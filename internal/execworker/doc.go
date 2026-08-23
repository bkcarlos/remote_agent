// Package execworker implements a Linux-only, capability-scoped execution
// supervisor for administrator-defined tasks.
//
// It is deliberately not an arbitrary host PID, shell, ptrace-attach, memory
// address read, memory write, or injection facility. Every process originates
// from a configured TaskProfile and is addressed thereafter only by an opaque
// handle bound to its creating principal, MCP session, workspace, and task.
package execworker
