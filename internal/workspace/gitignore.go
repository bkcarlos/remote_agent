package workspace

import (
	"path"
	"strings"
)

const (
	// DefaultMaxTraversalDepth bounds existing Glob and Grep calls without
	// changing their API. Depth is measured from the requested traversal root;
	// direct children have depth one.
	DefaultMaxTraversalDepth = 64
	maxGitignoreBytes        = int64(1 << 20)
)

type ignoreRule struct {
	base          string
	pattern       string
	negated       bool
	directoryOnly bool
	hasSlash      bool
}

func parseGitignore(data []byte, base string) []ignoreRule {
	lines := strings.Split(string(data), "\n")
	rules := make([]ignoreRule, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		line = trimUnescapedTrailingSpaces(line)
		if line == "" || line[0] == '#' {
			continue
		}

		negated := false
		if line[0] == '!' {
			negated = true
			line = line[1:]
		} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
			line = line[1:]
		}
		if line == "" {
			continue
		}

		directoryOnly := strings.HasSuffix(line, "/") && !strings.HasSuffix(line, `\/`)
		if directoryOnly {
			line = strings.TrimSuffix(line, "/")
		}
		anchored := strings.HasPrefix(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		rules = append(rules, ignoreRule{
			base:          strings.Trim(base, "/"),
			pattern:       line,
			negated:       negated,
			directoryOnly: directoryOnly,
			hasSlash:      anchored || strings.Contains(line, "/"),
		})
	}
	return rules
}

func trimUnescapedTrailingSpaces(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		backslashes := 0
		for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			// A single escaping backslash makes the final space significant.
			return s[:len(s)-2] + s[len(s)-1:]
		}
		s = s[:len(s)-1]
	}
	return s
}

func ignoredByRules(rules []ignoreRule, name string, isDir bool) bool {
	ignored := false
	for _, rule := range rules {
		if rule.matches(name, isDir) {
			ignored = !rule.negated
		}
	}
	return ignored
}

func (r ignoreRule) matches(name string, isDir bool) bool {
	rel, ok := relativeToRuleBase(r.base, strings.Trim(name, "/"))
	if !ok || rel == "" {
		return false
	}

	if !r.directoryOnly {
		return r.matchesOne(rel)
	}

	parts := strings.Split(rel, "/")
	limit := len(parts)
	if !isDir {
		limit--
	}
	for i := 1; i <= limit; i++ {
		if r.matchesOne(strings.Join(parts[:i], "/")) {
			return true
		}
	}
	return false
}

func (r ignoreRule) matchesOne(rel string) bool {
	if !r.hasSlash {
		parts := strings.Split(rel, "/")
		matched, err := path.Match(r.pattern, parts[len(parts)-1])
		return err == nil && matched
	}
	return gitGlobMatch(r.pattern, rel)
}

func relativeToRuleBase(base, name string) (string, bool) {
	if base == "" {
		return name, true
	}
	if name == base {
		return "", true
	}
	prefix := base + "/"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	return strings.TrimPrefix(name, prefix), true
}

func gitGlobMatch(pattern, name string) bool {
	return gitGlobMatchParts(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func gitGlobMatchParts(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		for len(pattern) > 1 && pattern[1] == "**" {
			pattern = pattern[1:]
		}
		if len(pattern) == 1 {
			// A trailing /** matches contents below the preceding directory,
			// not the directory itself.
			return len(name) > 0
		}
		if gitGlobMatchParts(pattern[1:], name) {
			return true
		}
		return len(name) > 0 && gitGlobMatchParts(pattern, name[1:])
	}
	if len(name) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], name[0])
	return err == nil && matched && gitGlobMatchParts(pattern[1:], name[1:])
}
