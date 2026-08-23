package workspaceregistry

import (
	"net/url"
	"strings"
	"testing"
)

func TestRoutePaths(t *testing.T) {
	defaultRoute, err := ParsePath(DefaultPath)
	if err != nil || !defaultRoute.Default || defaultRoute.WorkspaceID != "" {
		t.Fatalf("default route = %+v, %v", defaultRoute, err)
	}

	ids := []string{
		"workspace-0123456789",
		"opaque!workspace*1234",
		"opaque+workspace&1234",
	}
	for _, id := range ids {
		path, err := WorkspacePath(id)
		if err != nil {
			t.Fatalf("WorkspacePath(%q): %v", id, err)
		}
		want := DefaultPath + "/" + url.PathEscape(id)
		if path != want {
			t.Fatalf("WorkspacePath(%q) = %q, want %q", id, path, want)
		}
		route, err := ParsePath(path)
		if err != nil || route.Default || route.WorkspaceID != id {
			t.Fatalf("ParsePath(%q) = %+v, %v", path, route, err)
		}
	}
}

func TestParsePathRejectsAmbiguousOrExtraSegments(t *testing.T) {
	validID := "workspace-0123456789"
	validPath, err := WorkspacePath(validID)
	if err != nil {
		t.Fatal(err)
	}
	escapedStarPath, err := WorkspacePath("opaque*workspace-1234")
	if err != nil {
		t.Fatal(err)
	}

	invalid := []string{
		"/",
		"/mcp/",
		"/mcp//" + validID,
		validPath + "/extra",
		validPath + "?query=true",
		validPath + "#fragment",
		"/mcp/%2Fworkspace-0123456789",
		"/mcp/%77orkspace-0123456789",
		"/mcp/%",
		"/mcp/short",
		strings.Replace(escapedStarPath, "%2A", "%2a", 1),
	}
	for _, path := range invalid {
		if _, err := ParsePath(path); err == nil {
			t.Errorf("accepted ambiguous path %q", path)
		}
	}
}

func TestWorkspacePathRejectsUnsafeOrWeakIDs(t *testing.T) {
	for _, id := range []string{
		"",
		"short",
		"workspace/0123456789",
		"workspace%0123456789",
		"workspace?0123456789",
		"workspace#0123456789",
		"workspace 0123456789",
		"workspace-你好-012345",
	} {
		if _, err := WorkspacePath(id); err == nil {
			t.Errorf("accepted unsafe ID %q", id)
		}
	}
}
