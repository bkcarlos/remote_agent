package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bkcarlos/remote_agent/internal/installer"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(errOut)
	client := fs.String("client", "", "client JSON preset: claude, claude-code, cursor, or windsurf; codex/codex-json require --config")
	config := fs.String("config", "", "explicit mcpServers JSON configuration path (overrides the client preset path)")
	bridge := fs.String("bridge", "", "absolute or relative stdio-bridge executable path")
	endpoint := fs.String("endpoint", "", "remote Agent HTTP(S) endpoint")
	name := fs.String("name", installer.DefaultServerName, "MCP server name")
	allowHTTP := fs.Bool("allow-private-http", false, "allow an HTTP endpoint on localhost/private IP")
	apply := fs.Bool("apply", false, "write configuration; default is preview only")
	uninstall := fs.Bool("uninstall", false, "remove only this MCP server entry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	explicitConfig := *config != ""
	if !explicitConfig {
		var err error
		*config, err = installer.DefaultConfigPath(*client)
		if err != nil {
			return err
		}
	}
	if *uninstall {
		plan, err := installer.PlanUninstall(*config, *name, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "MCP uninstall plan\n  client config: %s\n  server name:   %s\n  backup:        %s\n", plan.ConfigPath, *name, plan.BackupPath)
		if err := printDiff(out, plan); err != nil {
			return err
		}
		if !*apply {
			fmt.Fprintln(out, "Preview only. Re-run with --uninstall --apply to write this change.")
			return nil
		}
		if err := installer.Apply(plan); err != nil {
			return err
		}
		fmt.Fprintln(out, "Uninstallation completed; a backup was created and other client settings were preserved.")
		return nil
	}
	if *endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if *bridge == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		*bridge = filepath.Join(filepath.Dir(exe), executableName("stdio-bridge"))
	}
	plan, err := installer.PlanInstall(installer.Options{
		ConfigPath:       *config,
		ServerName:       *name,
		BridgePath:       *bridge,
		Endpoint:         *endpoint,
		AllowPrivateHTTP: *allowHTTP,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "MCP installation plan\n  client preset: %s\n  client config: %s\n  config format: standard mcpServers JSON\n  server name:   %s\n  bridge:        %s\n  remote endpoint: %s\n  action:        %s\n", presetDescription(*client, explicitConfig), plan.ConfigPath, *name, *bridge, *endpoint, action(plan.Existed))
	if plan.BackupPath != "" {
		fmt.Fprintf(out, "  backup before apply: %s\n", plan.BackupPath)
	}
	fmt.Fprintf(out, "  authentication: %s must be injected into the MCP client startup environment (value is not read, displayed, or written)\n", installer.TokenEnvironment)
	if err := printDiff(out, plan); err != nil {
		return err
	}
	if !*apply {
		fmt.Fprintln(out, "Preview only. Re-run with --apply to write this change.")
		return nil
	}
	if err := installer.Apply(plan); err != nil {
		return err
	}
	if plan.Existed {
		fmt.Fprintln(out, "Installation completed; a backup was created and other client settings were preserved.")
	} else {
		fmt.Fprintln(out, "Installation completed.")
	}
	return nil
}

func printDiff(out io.Writer, plan installer.Plan) error {
	diff, err := json.Marshal(plan.Diff)
	if err != nil {
		return fmt.Errorf("encode configuration diff summary: %w", err)
	}
	fmt.Fprintf(out, "  config diff:   %s\n", diff)
	return nil
}

func presetDescription(client string, explicitConfig bool) string {
	if explicitConfig && client == "" {
		return "custom JSON (--config)"
	}
	switch strings.ToLower(client) {
	case "codex", "codex-json":
		if explicitConfig {
			return "Codex JSON (explicit --config)"
		}
		return "Codex (requires explicit --config)"
	case "":
		return "custom JSON (--config)"
	default:
		return client
	}
}

func executableName(name string) string {
	if filepath.Ext(os.Args[0]) == ".exe" {
		return name + ".exe"
	}
	return name
}

func action(existed bool) string {
	if existed {
		return "update existing configuration (preserve other entries)"
	}
	return "create configuration"
}
