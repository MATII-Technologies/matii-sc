package matii

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies the current service account token.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

type staticToken struct{ t *Token }

func (s staticToken) Token(context.Context) (*Token, error) { return s.t, nil }

// StaticToken uses a fixed token (from MATII_TOKEN, a file or a secret store).
func StaticToken(raw string) (TokenSource, error) {
	t, err := ParseToken(raw)
	if err != nil {
		return nil, err
	}
	return staticToken{t}, nil
}

// JWTSource returns the workload's current identity token.
type JWTSource func(ctx context.Context) (string, error)

// FileJWT reads a token file on every call (Kubernetes rotates projected tokens in place).
func FileJWT(path string) JWTSource {
	return func(context.Context) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// GitHubActionsJWT requests an ID token for audience from the Actions runtime
// (the job needs `permissions: id-token: write`).
func GitHubActionsJWT(audience string, hc *http.Client) JWTSource {
	return func(ctx context.Context) (string, error) {
		reqURL, reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if reqURL == "" || reqToken == "" {
			return "", errors.New("adera: not in a GitHub Actions job with id-token: write permission")
		}
		if hc == nil {
			hc = http.DefaultClient
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL+"&audience="+url.QueryEscape(audience), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+reqToken)
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || body.Value == "" {
			return "", fmt.Errorf("adera: GitHub did not return an ID token (HTTP %d)", resp.StatusCode)
		}
		return body.Value, nil
	}
}

// OIDCTokenSource exchanges a workload identity token for a short-lived
// service account token and refreshes it before it expires.
type OIDCTokenSource struct {
	APIBase          string // e.g. https://secrets.example.com/service
	ServiceAccountID string
	JWT              JWTSource
	TTL              time.Duration // requested token lifetime; 0 = identity default
	HTTPClient       *http.Client

	mu      sync.Mutex
	current *Token
	renewAt time.Time
}

func (s *OIDCTokenSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && time.Now().Before(s.renewAt) {
		return s.current, nil
	}
	jwt, err := s.JWT(ctx)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"account": map[string]string{"type": "service", "id": s.ServiceAccountID},
		"oidc":    map[string]string{"token": jwt},
	}
	if s.TTL > 0 {
		payload["tokenRequest"] = map[string]int{"ttl": int(s.TTL.Seconds())}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(s.APIBase, "/")+"/identities/external/v1/oidc/auth/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	hc := s.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Authentication struct {
			Token string `json:"token"`
			TTL   int    `json:"TTL"`
		} `json:"authentication"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Message: out.Error}
	}
	token, err := ParseToken(out.Authentication.Token)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(out.Authentication.TTL) * time.Second
	s.current, s.renewAt = token, time.Now().Add(ttl*4/5)
	return token, nil
}
