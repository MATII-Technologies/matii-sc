package matii

import (
	"context"
	"regexp"
	"strings"
)

// Reference syntax (same as the console):
//
//	${KEY}  ${/path/KEY}             same environment
//	${env.KEY}                        another environment of the same app
//	${app::env.KEY}                   another app
var referencePattern = regexp.MustCompile(`\$\{([^{}]+)\}`)

const maxReferenceDepth = 25

type fetchFunc func(ctx context.Context, appName, envName string) ([]Secret, error)

// resolveReferences expands references in E2EE values locally (SSE values are
// resolved by the server). Unresolvable references are left as written.
func resolveReferences(ctx context.Context, secrets []Secret, app *appKeys, fetch fetchFunc) ([]Secret, error) {
	cache := map[string]map[string]string{"": index(secrets)}
	var resolve func(value string, depth int) string
	resolve = func(value string, depth int) string {
		if depth > maxReferenceDepth || !strings.Contains(value, "${") {
			return value
		}
		return referencePattern.ReplaceAllStringFunc(value, func(match string) string {
			ref := match[2 : len(match)-1]
			scope, name := "", ref
			appName, envName := "", ""
			if i := strings.Index(ref, "::"); i >= 0 {
				appName, ref = ref[:i], ref[i+2:]
				scope = appName + "::"
			}
			if i := strings.Index(ref, "."); i >= 0 && !strings.HasPrefix(ref, "/") {
				envName, name = ref[:i], ref[i+1:]
				scope += envName
			} else {
				name = ref
			}
			if appName != "" && envName == "" {
				return match
			}
			values, ok := cache[scope]
			if !ok {
				fetched, err := fetch(ctx, appName, envName)
				if err != nil {
					cache[scope] = nil
					return match
				}
				values = index(fetched)
				cache[scope] = values
			}
			if values == nil {
				return match
			}
			if v, ok := values[normalize(name)]; ok {
				return resolve(v, depth+1)
			}
			return match
		})
	}
	out := make([]Secret, len(secrets))
	for i, s := range secrets {
		s.Value = resolve(s.Value, 0)
		out[i] = s
	}
	return out, nil
}

func index(secrets []Secret) map[string]string {
	m := make(map[string]string, len(secrets)*2)
	for _, s := range secrets {
		m[normalize(s.Path+"/"+s.Key)] = s.Value
		if s.Path == "/" || s.Path == "" {
			m[normalize(s.Key)] = s.Value
		}
	}
	return m
}

func normalize(name string) string {
	name = strings.TrimSpace(name)
	for strings.Contains(name, "//") {
		name = strings.ReplaceAll(name, "//", "/")
	}
	return strings.TrimPrefix(name, "/")
}
