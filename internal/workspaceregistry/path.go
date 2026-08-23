package workspaceregistry

import (
	"errors"
	"net/url"
	"strings"
)

const DefaultPath = "/mcp"

// Route identifies either the default endpoint or one workspace endpoint.
type Route struct {
	Default     bool
	WorkspaceID string
}

// WorkspacePath returns the canonical route for an opaque workspace ID.
func WorkspacePath(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	return DefaultPath + "/" + url.PathEscape(id), nil
}

// ParsePath accepts only DefaultPath or one canonical escaped workspace
// segment. It rejects extra segments, encoded delimiters, malformed escapes,
// non-canonical encodings, query/fragment text, and weak IDs.
func ParsePath(path string) (Route, error) {
	if path == DefaultPath {
		return Route{Default: true}, nil
	}
	prefix := DefaultPath + "/"
	if !strings.HasPrefix(path, prefix) {
		return Route{}, errors.New("route path is outside the MCP endpoint")
	}
	segment := strings.TrimPrefix(path, prefix)
	if segment == "" || strings.ContainsAny(segment, "/?#") {
		return Route{}, errors.New("workspace route must contain exactly one escaped segment")
	}
	id, err := url.PathUnescape(segment)
	if err != nil {
		return Route{}, errors.New("workspace route contains an invalid escape")
	}
	canonical, err := WorkspacePath(id)
	if err != nil {
		return Route{}, err
	}
	if canonical != path {
		return Route{}, errors.New("workspace route is not canonically encoded")
	}
	return Route{WorkspaceID: id}, nil
}
