package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/credentialstore"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/gateway"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/replay"
	"github.com/bkcarlos/remote_agent/internal/sandbox"
	"github.com/bkcarlos/remote_agent/internal/workspaceregistry"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "listen address")
	root := flag.String("workspace", "", "authorized single workspace")
	workspaceConfigPath := flag.String("workspace-config", "", "trusted multi-workspace registry JSON")
	allowHTTP := flag.Bool("allow-insecure-http", false, "allow HTTP on a private interface")
	cert := flag.String("tls-cert", "", "TLS certificate")
	key := flag.String("tls-key", "", "TLS private key")
	allowWrite := flag.Bool("allow-write", false, "enable workspace write tools")
	allowNetwork := flag.Bool("allow-network", false, "enable configured Network tools")
	allowRemote := flag.Bool("allow-remote", false, "enable configured Remote tools")
	allowExec := flag.Bool("allow-exec", false, "enable configured Exec tools")
	allowDebug := flag.Bool("allow-debug", false, "enable same-session managed-child Debug tools")
	allowMem := flag.Bool("allow-mem", false, "enable same-session managed-child memory scans")
	approvalMode := flag.String("approval-mode", gateway.ApprovalModeServerToken, "approval mode: server_token or client_managed")
	auditPath := flag.String("audit-log", "audit.jsonl", "audit log path")
	replayPath := flag.String("replay-db", "state/replay.db", "persistent HTTP and approval replay database")
	workerBin := flag.String("file-worker", siblingExecutable("file-worker"), "isolated file-worker executable")
	networkWorker := flag.String("network-worker", "", "optional isolated network-worker executable")
	networkPolicy := flag.String("network-policy", "", "strict v1 administrator Network profiles JSON")
	remoteWorker := flag.String("remote-worker", "", "optional isolated remote-worker executable")
	remoteProfiles := flag.String("remote-profiles", "", "strict administrator SSH/SFTP profiles JSON")
	execWorker := flag.String("exec-worker", "", "optional Linux exec-worker executable")
	execPolicy := flag.String("exec-policy", "", "strict v1 administrator task profiles JSON")
	execSocketDir := flag.String("exec-socket-dir", "", "absolute directory for per-workspace Exec runtime files")
	execCgroupRoot := flag.String("exec-cgroup-root", "", "delegated cgroup v2 directory for Exec children")
	execProduction := flag.Bool("exec-production", true, "require all Linux Exec isolation layers")
	workerTimeout := flag.Duration("worker-timeout", 30*time.Second, "per-job file/network worker timeout")
	maxConcurrency := flag.Int("max-concurrency", 64, "maximum concurrent gateway requests per workspace")
	rateLimit := flag.Float64("rate-limit", 20, "authenticated requests per second per principal/IP/workspace (0 disables)")
	rateBurst := flag.Int("rate-burst", 40, "per-principal/IP/workspace token bucket burst")
	cgroupRoot := flag.String("cgroup-root", "", "delegated cgroup v2 directory for mandatory per-worker limits")
	adminPolicy := flag.String("admin-policy", "", "administrator policy JSON (can only restrict)")
	deploymentPolicy := flag.String("deployment-policy", "", "deployment policy JSON (can only restrict)")
	projectPolicy := flag.String("project-policy", "", "project policy JSON (can only restrict)")
	clientID := flag.String("client-id", "", "trusted client identity recorded in audit events")
	userID := flag.String("user-id", "", "trusted user identity recorded in audit events")
	workspaceIDFlag := flag.String("workspace-id", "", "single-workspace opaque audit identity (random per startup by default)")
	policyVersion := flag.String("policy-version", "effective-v1", "effective policy version recorded in audit events")
	flag.Parse()

	if (*root == "") == (*workspaceConfigPath == "") {
		log.Fatal("exactly one of -workspace or -workspace-config is required")
	}
	if *workspaceConfigPath != "" && *workspaceIDFlag != "" {
		log.Fatal("-workspace-id is only valid with -workspace")
	}
	if strings.TrimSpace(*policyVersion) == "" {
		log.Fatal("-policy-version must not be empty")
	}
	instanceID, err := randomID("gateway-", 16)
	if err != nil {
		log.Fatal("could not generate gateway instance identity")
	}
	token := os.Getenv("REMOTE_AGENT_TOKEN")
	if len(token) < 32 {
		log.Fatal("REMOTE_AGENT_TOKEN must contain at least 32 characters")
	}

	if *approvalMode != gateway.ApprovalModeServerToken && *approvalMode != gateway.ApprovalModeClientManaged {
		log.Fatal("-approval-mode must be server_token or client_managed")
	}
	policyConfig := policy.Config{
		AllowWrite: *allowWrite, AllowNetwork: *allowNetwork, AllowRemote: *allowRemote,
		AllowExec: *allowExec, AllowDebug: *allowDebug, AllowMem: *allowMem,
	}
	for _, layer := range []struct {
		name string
		path string
	}{{"administrator", *adminPolicy}, {"deployment", *deploymentPolicy}, {"project", *projectPolicy}} {
		if layer.path == "" {
			continue
		}
		document, loadErr := policy.LoadFile(layer.path)
		if loadErr != nil {
			log.Fatalf("load %s policy failed", layer.name)
		}
		policyConfig = policy.Restrict(policyConfig, document)
		log.Printf("loaded %s policy version %s", layer.name, document.Version)
	}
	approvalKey := os.Getenv("REMOTE_AGENT_APPROVAL_KEY")
	if *approvalMode == gateway.ApprovalModeServerToken && policyConfig.AllowWrite && len(approvalKey) < 32 {
		log.Fatal("REMOTE_AGENT_APPROVAL_KEY must contain at least 32 characters when writes are enabled in server_token mode")
	}
	if *approvalMode == gateway.ApprovalModeClientManaged {
		approvalKey = ""
	}
	if *cert == "" || *key == "" {
		if !*allowHTTP {
			log.Fatal("TLS is required unless -allow-insecure-http is explicitly set")
		}
		if !privateListen(*addr) {
			log.Fatal("insecure HTTP may only listen on loopback or a private IP")
		}
	}

	var registryConfig workspaceregistry.Config
	if *workspaceConfigPath != "" {
		registryConfig, err = workspaceregistry.LoadFile(*workspaceConfigPath, time.Now().UTC())
		if err != nil {
			log.Fatal("load workspace config failed")
		}
	}
	if st, statErr := os.Stat(*workerBin); statErr != nil || st.IsDir() {
		log.Fatal("file worker is unavailable")
	}
	if (*networkWorker == "") != (*networkPolicy == "") {
		log.Fatal("-network-worker and -network-policy must be configured together")
	}
	var configuredNetworkProfiles map[string]networkworker.Profile
	if *networkWorker != "" {
		if st, statErr := os.Stat(*networkWorker); statErr != nil || st.IsDir() {
			log.Fatal("network worker is unavailable")
		}
		configuredNetworkProfiles, err = networkworker.LoadProfiles(*networkPolicy, time.Now().UTC())
		if err != nil {
			log.Fatal("load network profiles failed")
		}
	}
	if (*remoteWorker == "") != (*remoteProfiles == "") {
		log.Fatal("-remote-worker and -remote-profiles must be configured together")
	}
	if *remoteWorker != "" {
		if st, statErr := os.Stat(*remoteWorker); statErr != nil || st.IsDir() {
			log.Fatal("remote worker is unavailable")
		}
		if err := credentialstore.Validate(*remoteProfiles); err != nil {
			log.Fatal("remote profile configuration or credential store is invalid")
		}
	}
	if (*execWorker == "") != (*execPolicy == "") || (*execWorker == "") != (*execSocketDir == "") {
		log.Fatal("-exec-worker, -exec-policy, and -exec-socket-dir must be configured together")
	}
	var configuredExec execworker.AdministratorConfig
	if *execWorker != "" {
		if runtime.GOOS != "linux" {
			log.Fatal("Exec worker configuration is supported only on Linux")
		}
		if !filepath.IsAbs(*execSocketDir) {
			log.Fatal("-exec-socket-dir must be absolute")
		}
		if st, statErr := os.Stat(*execWorker); statErr != nil || st.IsDir() {
			log.Fatal("exec worker is unavailable")
		}
		configuredExec, err = execworker.LoadAdministratorConfig(*execPolicy)
		if err != nil {
			log.Fatal("load exec administrator policy failed")
		}
	}

	replayStore, err := replay.OpenBolt(*replayPath)
	if err != nil {
		log.Fatal("open replay database failed")
	}
	defer replayStore.Close()
	f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("open audit log failed")
	}
	defer f.Close()
	auditLogger := audit.New(f)

	var degradationFields []string
	var degradationReasons []string
	if runtime.GOOS == "linux" {
		if landlockErr := sandbox.Supported(); errors.Is(landlockErr, sandbox.ErrLandlockUnavailable) {
			log.Printf("WARNING: %v; continuing with openat2 workspace confinement and namespace/seccomp isolation", landlockErr)
			degradationFields = append(degradationFields, "landlock")
			degradationReasons = append(degradationReasons, "Landlock unavailable")
		} else if landlockErr != nil {
			log.Fatal("check Landlock support failed")
		}
		if *cgroupRoot == "" {
			log.Print("WARNING: -cgroup-root is not configured; rlimits remain active but cgroup memory controls are unavailable")
			degradationFields = append(degradationFields, "cgroup")
			degradationReasons = append(degradationReasons, "cgroup memory controls unavailable")
		}
	}

	factory := workspaceFactory{
		workerBinary: *workerBin, workerTimeout: *workerTimeout, cgroupRoot: *cgroupRoot,
		networkBinary: *networkWorker, networkProfiles: configuredNetworkProfiles,
		remoteBinary: *remoteWorker, remoteProfilesPath: *remoteProfiles,
		execBinary: *execWorker, execSocketDir: *execSocketDir, execCgroupRoot: *execCgroupRoot,
		execProduction: *execProduction, execAdministrator: configuredExec,
		policy: policyConfig,
		gateway: gateway.Config{
			AuthToken: token, ApprovalKey: []byte(approvalKey), ApprovalMode: *approvalMode, Transport: "streamable-http",
			VerifyOptionalRequestSignature: true, ReplayStore: replayStore,
			MaxConcurrency: *maxConcurrency, RateLimitPerSecond: *rateLimit, RateLimitBurst: *rateBurst,
			ClientID: *clientID, UserID: *userID, PolicyVersion: *policyVersion,
			SecurityDegraded:          len(degradationFields) > 0,
			SecurityDegradationReason: strings.Join(degradationReasons, "; "),
			SecurityDegradationFields: degradationFields,
		},
		audit: auditLogger,
	}

	var handler http.Handler
	if *root != "" {
		workspaceID := *workspaceIDFlag
		if workspaceID == "" {
			workspaceID, err = randomID("workspace-", 16)
			if err != nil {
				log.Fatal("could not generate workspace identity")
			}
		}
		if err := workspaceregistry.ValidateID(workspaceID); err != nil {
			log.Fatal("-workspace-id must be a valid opaque workspace identity")
		}
		server, buildErr := factory.build(workspaceregistry.WorkspaceConfig{ID: workspaceID, Root: *root})
		if buildErr != nil {
			log.Fatal("initialize workspace failed")
		}
		defer server.Close()
		handler = gatewayHandler(server)
		log.Printf("workspace id=%s endpoint=%s", workspaceID, gateway.DefaultEndpoint)
	} else {
		bindings, buildErr := buildWorkspaceBindings(registryConfig.Workspaces, factory.build)
		if buildErr != nil {
			log.Fatal("initialize configured workspaces failed")
		}
		router := gateway.NewWorkspaceRouter()
		if replaceErr := router.ReplaceAll(bindings); replaceErr != nil {
			closeWorkspaceBindings(bindings)
			log.Fatal("install workspace routes failed")
		}
		defer router.Close()
		handler = router
		logWorkspaceEndpoints(bindings)

		signals, stopSignals := workspaceReloadSignals()
		defer stopSignals()
		if signals != nil {
			go func() {
				for range signals {
					loaded, reloadErr := reloadWorkspaceConfig(*workspaceConfigPath, router, factory.build, time.Now)
					if reloadErr != nil {
						log.Print("workspace config reload rejected; previous configuration remains active")
						continue
					}
					log.Print("workspace config reload applied")
					logWorkspaceEndpoints(loaded)
				}
			}()
		}
	}

	h := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: gatewayWriteTimeout(*workerTimeout, configuredExec), IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("gateway listening on %s (%s), instance=%s", *addr, transport(*cert), instanceID)
	if *cert != "" && *key != "" {
		err = h.ListenAndServeTLS(*cert, *key)
	} else {
		err = h.ListenAndServe()
	}
	log.Fatal(err)
}
func gatewayWriteTimeout(workerTimeout time.Duration, execConfig execworker.AdministratorConfig) time.Duration {
	timeout := 30 * time.Second
	if workerTimeout > timeout {
		timeout = workerTimeout
	}
	for _, profile := range execConfig.Profiles {
		candidate := time.Duration(profile.Limits.TimeoutMillis) * time.Millisecond
		if candidate > timeout {
			timeout = candidate
		}
	}
	const responseGrace = 5 * time.Second
	if timeout > time.Duration(1<<63-1)-responseGrace {
		return timeout
	}
	return timeout + responseGrace
}

func gatewayHandler(handler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(gateway.DefaultEndpoint, handler)
	return mux
}

func logWorkspaceEndpoints(bindings []gateway.WorkspaceBinding) {
	for _, binding := range bindings {
		endpoint, err := workspaceregistry.WorkspacePath(binding.Workspace.ID)
		if err == nil {
			log.Printf("workspace id=%s endpoint=%s", binding.Workspace.ID, endpoint)
		}
	}
}

func transport(cert string) string {
	if cert != "" {
		return "https"
	}
	return "http"
}
func privateListen(addr string) bool {
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}
func randomID(prefix string, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}
func siblingExecutable(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	if strings.HasSuffix(strings.ToLower(exe), ".exe") {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}
