// Package matii is a client for the Matii Secret Service.
//
// It reads secrets from server-side encrypted (SSE) apps through the public
// API and from end-to-end encrypted (E2EE) apps by decrypting locally, using
// a service account token (static, or exchanged from a workload identity).
// Secret values are never logged; Secret.String() redacts them.
package matii

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const userAgent = "matii-go/0.1"

// Config configures a Client.
type Config struct {
	// Host is the console URL, e.g. https://secrets.example.com. The API is
	// served under <Host>/service unless APIBase is set.
	Host    string
	APIBase string
	// Tokens supplies the service account token; see StaticToken and OIDCTokenSource.
	Tokens     TokenSource
	HTTPClient *http.Client
}

// Client talks to the Secret Service. It is safe for concurrent use.
type Client struct {
	base   string
	tokens TokenSource
	http   *http.Client

	mu        sync.Mutex
	bootstrap map[string]*bootstrapInfo // by token value
}

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("adera: HTTP %d: %s", e.Status, e.Message) }

// Secret is one decrypted secret. String() never prints the value.
type Secret struct {
	Key      string
	Value    string
	Path     string
	Comment  string
	Tags     []string
	Type     string // "secret", "sealed" or "config"
	Redacted bool   // the caller may list but not reveal this value (Secrets:reveal)
	// Overridden is set when Value is the signed-in member's active personal override.
	Overridden bool
}

func (s Secret) String() string   { return fmt.Sprintf("%s%s=<redacted>", s.Path, s.Key) }
func (s Secret) GoString() string { return s.String() }

// Query selects an environment (and optionally a folder path).
type Query struct {
	AppID   string // or AppName
	AppName string
	Env     string // environment name, e.g. "production"
	Path    string // folder, e.g. "/" or "/backend"; empty = all paths
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Tokens == nil {
		return nil, errors.New("adera: Config.Tokens is required")
	}
	base := strings.TrimRight(cfg.APIBase, "/")
	if base == "" {
		if cfg.Host == "" {
			return nil, errors.New("adera: Config.Host is required")
		}
		base = strings.TrimRight(cfg.Host, "/") + "/service"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("adera: invalid Host/APIBase")
	}
	if parsed.Scheme != "https" && !isLocal(parsed.Hostname()) {
		return nil, errors.New("adera: the API must use https (plain http only for localhost)")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: base, tokens: cfg.Tokens, http: hc, bootstrap: map[string]*bootstrapInfo{}}, nil
}

func isLocal(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, headers map[string]string, out any) error {
	return c.send(ctx, method, path, query, headers, nil, out)
}

// send is do with an optional JSON request body.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, headers map[string]string, body any, out any) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return err
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", token.authorization())
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(respBody, &payload)
		msg := payload.Error
		if msg == "" {
			msg = payload.Detail
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(respBody, out)
}

// --- token bootstrap -----------------------------------------------------------

type envKey struct {
	Environment struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		EnvType string `json:"env_type"`
	} `json:"environment"`
	WrappedSeed string `json:"wrapped_seed"`
	WrappedSalt string `json:"wrapped_salt"`
	IdentityKey string `json:"identity_key"`
}

type appKeys struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Encryption      string   `json:"encryption"` // "SSE" or "E2E"
	EnvironmentKeys []envKey `json:"environment_keys"`
}

type bootstrapInfo struct {
	WrappedKeyShare string `json:"wrapped_key_share"`
	UserID          string `json:"user_id"`
	AccountID       string `json:"account_id"`
	Organisation    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"organisation"`
	Apps     []appKeys `json:"apps"`
	tokenKey KeyPair
	envKeys  map[string]envMaterial // environment id -> keys
}

type envMaterial struct {
	keys KeyPair
	salt string
}

func (c *Client) info(ctx context.Context) (*bootstrapInfo, *Token, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	cached := c.bootstrap[token.value]
	c.mu.Unlock()
	if cached != nil {
		return cached, token, nil
	}
	var info bootstrapInfo
	if err := c.do(ctx, http.MethodGet, "/secrets/tokens/", nil, nil, &info); err != nil {
		return nil, nil, err
	}
	info.tokenKey, err = recoverTokenKey(token, info.WrappedKeyShare)
	if err != nil {
		return nil, nil, err
	}
	info.envKeys = map[string]envMaterial{}
	c.mu.Lock()
	c.bootstrap = map[string]*bootstrapInfo{token.value: &info} // drop old tokens' material
	c.mu.Unlock()
	return &info, token, nil
}

// resolve finds the app and environment of q. Environment names match
// case-insensitively, and a unique prefix is accepted ("prod" → "Production").
func (info *bootstrapInfo) resolve(q Query) (*appKeys, *envKey, error) {
	for i := range info.Apps {
		app := &info.Apps[i]
		if (q.AppID != "" && app.ID == q.AppID) || (q.AppID == "" && strings.EqualFold(app.Name, q.AppName)) {
			var prefixed []int
			for j := range app.EnvironmentKeys {
				name := app.EnvironmentKeys[j].Environment.Name
				if strings.EqualFold(name, q.Env) {
					return app, &app.EnvironmentKeys[j], nil
				}
				if q.Env != "" && strings.HasPrefix(strings.ToLower(name), strings.ToLower(q.Env)) {
					prefixed = append(prefixed, j)
				}
			}
			if len(prefixed) == 1 {
				return app, &app.EnvironmentKeys[prefixed[0]], nil
			}
			if len(prefixed) > 1 {
				return nil, nil, fmt.Errorf("adera: environment %q of app %q is ambiguous", q.Env, app.Name)
			}
			return nil, nil, fmt.Errorf("adera: this token has no access to environment %q of app %q", q.Env, app.Name)
		}
	}
	return nil, nil, errors.New("adera: this token has no access to that app")
}

// App is an app the token can access, with its environments.
type App struct {
	ID           string
	Name         string
	Encryption   string // "SSE" or "E2E"
	Environments []Environment
}

// Environment is one environment of an App.
type Environment struct {
	ID   string
	Name string
	Type string // "dev", "staging", "prod" or "custom"
}

// Apps lists the apps and environments this token has access to.
func (c *Client) Apps(ctx context.Context) ([]App, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]App, 0, len(info.Apps))
	for _, a := range info.Apps {
		app := App{ID: a.ID, Name: a.Name, Encryption: a.Encryption}
		for _, k := range a.EnvironmentKeys {
			app.Environments = append(app.Environments, Environment{ID: k.Environment.ID, Name: k.Environment.Name, Type: k.Environment.EnvType})
		}
		out = append(out, app)
	}
	return out, nil
}

// Identity describes who a token belongs to.
type Identity struct {
	Kind             string // "User" or "ServiceAccount"
	AccountID        string // user or service account id
	OrganisationID   string
	OrganisationName string
}

// Whoami returns the identity behind the client's token.
func (c *Client) Whoami(ctx context.Context) (*Identity, error) {
	info, token, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	id := &Identity{Kind: token.kind, AccountID: info.AccountID, OrganisationID: info.Organisation.ID, OrganisationName: info.Organisation.Name}
	if id.AccountID == "" {
		id.AccountID = info.UserID
	}
	return id, nil
}

// EnvironmentOf returns the app and environment q selects.
func (c *Client) EnvironmentOf(ctx context.Context, q Query) (*App, *Environment, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, nil, err
	}
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, nil, err
	}
	return &App{ID: app.ID, Name: app.Name, Encryption: app.Encryption},
		&Environment{ID: key.Environment.ID, Name: key.Environment.Name, Type: key.Environment.EnvType}, nil
}

func (info *bootstrapInfo) material(key *envKey) (envMaterial, error) {
	if m, ok := info.envKeys[key.Environment.ID]; ok {
		return m, nil
	}
	seed, err := DecryptAsymmetric(key.WrappedSeed, info.tokenKey)
	if err != nil {
		return envMaterial{}, err
	}
	salt, err := DecryptAsymmetric(key.WrappedSalt, info.tokenKey)
	if err != nil {
		return envMaterial{}, err
	}
	seedBytes, err := hexDecode(seed)
	if err != nil {
		return envMaterial{}, err
	}
	kp, err := KXSeedKeyPair(seedBytes)
	if err != nil {
		return envMaterial{}, err
	}
	m := envMaterial{keys: kp, salt: salt}
	info.envKeys[key.Environment.ID] = m
	return m, nil
}

// --- fetching --------------------------------------------------------------------

type apiSecret struct {
	ID            string       `json:"id"`
	Key           string       `json:"key"`
	Value         *string      `json:"value"`
	Path          string       `json:"path"`
	Comment       string       `json:"comment"`
	Tags          []string     `json:"tags"`
	Type          string       `json:"type"`
	Override      *apiOverride `json:"override"`
	ValueRedacted bool         `json:"valueRedacted"`
}

// apiOverride is the signed-in member's personal value for a secret.
type apiOverride struct {
	Value    *string `json:"value"`
	IsActive bool    `json:"isActive"`
}

// Secrets returns the secrets of one environment, with references resolved.
func (c *Client) Secrets(ctx context.Context, q Query) ([]Secret, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	if app.Encryption == "SSE" {
		return c.sseSecrets(ctx, app, key, q.Path)
	}
	secrets, err := c.e2eeSecrets(ctx, info, key, q.Path)
	if err != nil {
		return nil, err
	}
	return resolveReferences(ctx, secrets, app, func(ctx context.Context, appName, envName string) ([]Secret, error) {
		query := Query{AppID: app.ID, Env: envName}
		if appName != "" {
			query = Query{AppName: appName, Env: envName}
		}
		return c.rawSecrets(ctx, info, query)
	})
}

// rawSecrets fetches without resolving references (used by the resolver).
func (c *Client) rawSecrets(ctx context.Context, info *bootstrapInfo, q Query) ([]Secret, error) {
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	if app.Encryption == "SSE" {
		return c.sseSecrets(ctx, app, key, "")
	}
	return c.e2eeSecrets(ctx, info, key, "")
}

func (c *Client) sseSecrets(ctx context.Context, app *appKeys, key *envKey, path string) ([]Secret, error) {
	query := url.Values{"app_id": {app.ID}, "env": {key.Environment.Name}}
	if path != "" {
		query.Set("path", path)
	}
	var items []apiSecret
	if err := c.do(ctx, http.MethodGet, "/v1/secrets/", query, nil, &items); err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(items))
	for _, item := range items {
		s := Secret{Key: item.Key, Path: item.Path, Comment: item.Comment, Tags: item.Tags, Type: item.Type, Redacted: item.ValueRedacted}
		if item.Value != nil {
			s.Value = *item.Value
		} else {
			s.Redacted = true
		}
		if o := item.Override; o != nil && o.IsActive && o.Value != nil && !s.Redacted {
			s.Value, s.Overridden = *o.Value, true
		}
		out = append(out, s)
	}
	return out, nil
}

func (c *Client) e2eeSecrets(ctx context.Context, info *bootstrapInfo, key *envKey, path string) ([]Secret, error) {
	material, err := info.material(key)
	if err != nil {
		return nil, err
	}
	// Ask for camelCase fields (e.g. override.isActive), as the SSE API returns.
	headers := map[string]string{"Environment": key.Environment.ID, "X-Use-Camel-Case": "true"}
	if path != "" {
		headers["Path"] = path
	}
	var items []apiSecret
	if err := c.do(ctx, http.MethodGet, "/secrets/", nil, headers, &items); err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(items))
	for _, item := range items {
		k, err := DecryptAsymmetric(item.Key, material.keys)
		if err != nil {
			return nil, err
		}
		s := Secret{Key: k, Path: item.Path, Tags: item.Tags, Type: item.Type}
		if item.Value != nil && *item.Value != "" {
			if s.Value, err = DecryptAsymmetric(*item.Value, material.keys); err != nil {
				return nil, err
			}
		}
		if item.Comment != "" {
			if s.Comment, err = DecryptAsymmetric(item.Comment, material.keys); err != nil {
				return nil, err
			}
		}
		if o := item.Override; o != nil && o.IsActive && o.Value != nil && *o.Value != "" {
			if s.Value, err = DecryptAsymmetric(*o.Value, material.keys); err != nil {
				return nil, err
			}
			s.Overridden = true
		}
		out = append(out, s)
	}
	return out, nil
}

func hexDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrDecrypt
	}
	return b, nil
}
