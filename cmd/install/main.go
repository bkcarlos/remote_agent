package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bkcarlos/remote_agent/internal/installer"
)

func main() {
	client := flag.String("client", "", "client: claude, claude-code, cursor, or windsurf")
	config := flag.String("config", "", "explicit client JSON configuration path")
	bridge := flag.String("bridge", "", "absolute or relative stdio-bridge executable path")
	endpoint := flag.String("endpoint", "", "remote Agent HTTP(S) endpoint")
	name := flag.String("name", installer.DefaultServerName, "MCP server name")
	allowHTTP := flag.Bool("allow-private-http", false, "allow an HTTP endpoint on localhost/private IP")
	apply := flag.Bool("apply", false, "write configuration; default is preview only")
	uninstall := flag.Bool("uninstall", false, "remove only this MCP server entry")
	flag.Parse()

	if *config == "" {
		var err error
		*config, err = installer.DefaultConfigPath(*client)
		if err != nil {
			fatal(err.Error())
		}
	}
	if *uninstall {
		plan, err := installer.PlanUninstall(*config, *name, nil)
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("MCP uninstall plan\n  client config: %s\n  server name:   %s\n  backup:        %s\n", plan.ConfigPath, *name, plan.BackupPath)
		if !*apply {
			fmt.Println("Preview only. Re-run with --uninstall --apply to write this change.")
			return
		}
		if err := installer.Apply(plan); err != nil {
			fatal(err.Error())
		}
		fmt.Println("Uninstallation completed; other client settings were preserved.")
		return
	}
	if *endpoint == "" {
		fatal("--endpoint is required")
	}
	if *bridge == "" {
		exe, err := os.Executable()
		if err != nil {
			fatal(err.Error())
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
		fatal(err.Error())
	}
	fmt.Printf("MCP installation plan\n  client config: %s\n  server name:   %s\n  bridge:        %s\n  endpoint:      %s\n  action:        %s\n", plan.ConfigPath, *name, *bridge, *endpoint, action(plan.Existed))
	if plan.BackupPath != "" {
		fmt.Printf("  backup:        %s\n", plan.BackupPath)
	}
	fmt.Println("  credentials:   not written; bridge reads REMOTE_AGENT_TOKEN from its trusted environment")
	if !*apply {
		fmt.Println("Preview only. Re-run with --apply to write this change.")
		return
	}
	if err := installer.Apply(plan); err != nil {
		fatal(err.Error())
	}
	fmt.Println("Installation completed.")
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
func fatal(message string) {
	fmt.Fprintln(os.Stderr, "install:", message)
	os.Exit(1)
}
