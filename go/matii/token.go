package matii

import (
	"errors"
	"fmt"
	"strings"
)

// Token is a parsed Secret Service API token. Its String() never reveals
// secret material.
type Token struct {
	kind     string // "ServiceAccount" or "User"
	value    string // bearer credential
	kxPublic string
	shareA   string
	wrapKey  string
}

// ParseToken accepts pss_service:v2:... and pss_user:v1/v2:... tokens (the
// console issues personal access tokens as pss_user:v1, which has the same layout).
func ParseToken(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ":")
	if len(parts) != 6 || !(parts[1] == "v2" || (parts[0] == "pss_user" && parts[1] == "v1")) {
		return nil, errors.New("matii: unsupported token format (expected pss_service:v2 or pss_user:v1/v2)")
	}
	t := &Token{value: parts[2], kxPublic: parts[3], shareA: parts[4], wrapKey: parts[5]}
	switch parts[0] {
	case "pss_service":
		t.kind = "ServiceAccount"
	case "pss_user":
		t.kind = "User"
	default:
		return nil, errors.New("matii: unknown token type")
	}
	for _, field := range []string{t.value, t.kxPublic, t.shareA, t.wrapKey} {
		if len(field) != 64 {
			return nil, errors.New("matii: malformed token")
		}
	}
	return t, nil
}

// Kind is "ServiceAccount" or "User".
func (t *Token) Kind() string { return t.kind }

// authorization is the HTTP Authorization header value.
func (t *Token) authorization() string { return fmt.Sprintf("Bearer %s %s", t.kind, t.value) }

func (t *Token) String() string { return fmt.Sprintf("%s token (redacted)", t.kind) }

// GoString keeps %#v from printing fields.
func (t *Token) GoString() string { return t.String() }
