package main

import (
	"crypto/rand"
	"encoding/hex"
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
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/gateway"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/replay"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "listen address")
	root := flag.String("workspace", "", "authorized workspace")
	allowHTTP := flag.Bool("allow-insecure-http", false, "allow HTTP on a private interface")
	cert := flag.String("tls-cert", "", "TLS certificate")
	key := flag.String("tls-key", "", "TLS private key")
	allowWrite := flag.Bool("allow-write", false, "enable write tool (still requires approval)")
	auditPath := flag.String("audit-log", "audit.jsonl", "audit log path")
	replayPath := flag.String("replay-db", "state/replay.db", "persistent HTTP and approval replay database")
	workerBin := flag.String("file-worker", siblingExecutable("file-worker"), "isolated file-worker executable")
	workerTimeout := flag.Duration("worker-timeout", 30*time.Second, "per-job file worker timeout")
	cgroupRoot := flag.String("cgroup-root", "", "delegated cgroup v2 directory for mandatory per-worker limits")
	adminPolicy := flag.String("admin-policy", "", "administrator policy JSON (can only restrict)")
	deploymentPolicy := flag.String("deployment-policy", "", "deployment policy JSON (can only restrict)")
	projectPolicy := flag.String("project-policy", "", "project policy JSON (can only restrict)")
	flag.Parse()
	if *root == "" {
		log.Fatal("-workspace is required")
	}
	token := os.Getenv("REMOTE_AGENT_TOKEN")
	if len(token) < 32 {
		log.Fatal("REMOTE_AGENT_TOKEN must contain at least 32 characters")
	}
	policyConfig := policy.Config{AllowWrite: *allowWrite}
	for _, layer := range []struct {
		name string
		path string
	}{{"administrator", *adminPolicy}, {"deployment", *deploymentPolicy}, {"project", *projectPolicy}} {
		if layer.path == "" {
			continue
		}
		document, loadErr := policy.LoadFile(layer.path)
		if loadErr != nil {
			log.Fatalf("load %s policy: %v", layer.name, loadErr)
		}
		policyConfig = policy.Restrict(policyConfig, document)
		log.Printf("loaded %s policy version %s", layer.name, document.Version)
	}
	approvalKey := os.Getenv("REMOTE_AGENT_APPROVAL_KEY")
	if policyConfig.AllowWrite && len(approvalKey) < 32 {
		log.Fatal("REMOTE_AGENT_APPROVAL_KEY must contain at least 32 characters when writes are enabled")
	}
	if *cert == "" || *key == "" {
		if !*allowHTTP {
			log.Fatal("TLS is required unless -allow-insecure-http is explicitly set")
		}
		if !privateListen(*addr) {
			log.Fatal("insecure HTTP may only listen on loopback or a private IP")
		}
	}
	replayStore, err := replay.OpenBolt(*replayPath)
	if err != nil {
		log.Fatalf("open replay database: %v", err)
	}
	defer replayStore.Close()
	f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if st, statErr := os.Stat(*workerBin); statErr != nil || st.IsDir() {
		log.Fatalf("file worker is unavailable: %s", *workerBin)
	}
	workerKey := make([]byte, 32)
	if _, err := rand.Read(workerKey); err != nil {
		log.Fatal("could not generate worker capability key")
	}
	p := policy.New(policyConfig)
	files, err := fileworker.NewSecureProcessExecutor(*workerBin, *root, workerKey, *workerTimeout, p.DeniedNames(), *cgroupRoot)
	if err != nil {
		log.Fatal(err)
	}
	if *cgroupRoot == "" && runtime.GOOS == "linux" {
		log.Print("WARNING: -cgroup-root is not configured; rlimits remain active but cgroup memory controls are unavailable")
	}
	s, err := gateway.New(gateway.Config{AuthToken: token, ApprovalKey: []byte(approvalKey), Transport: transport(*cert), RequireRequestSignature: true, ReplayStore: replayStore}, files, p, audit.New(f))
	if err != nil {
		log.Fatal(err)
	}
	h := &http.Server{Addr: *addr, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("gateway listening on %s (%s), instance=%s", *addr, transport(*cert), id())
	if *cert != "" && *key != "" {
		err = h.ListenAndServeTLS(*cert, *key)
	} else {
		err = h.ListenAndServe()
	}
	log.Fatal(err)
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
func id() string { b := make([]byte, 6); rand.Read(b); return hex.EncodeToString(b) }
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
