package matii

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ManagedSecret is a secret written through the API (server-side encrypted apps).
type ManagedSecret struct {
	ID      string
	Key     string
	Value   string
	Path    string
	Comment string
}

// ErrNotFound is returned when a secret does not exist (or is not visible).
var ErrNotFound = errors.New("adera: not found")

type apiManaged struct {
	ID      string  `json:"id"`
	Key     string  `json:"key"`
	Value   *string `json:"value"`
	Path    string  `json:"path"`
	Comment string  `json:"comment"`
}

func (c *Client) sseTarget(ctx context.Context, q Query) (url.Values, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	if app.Encryption != "SSE" {
		return nil, errors.New("adera: managing secrets through the API needs a server-side encrypted app")
	}
	return url.Values{"app_id": {app.ID}, "env": {key.Environment.Name}}, nil
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return "/" + strings.Trim(p, "/")
}

// FindSecret returns the secret named key in q's environment and folder.
func (c *Client) FindSecret(ctx context.Context, q Query, key string) (*ManagedSecret, error) {
	query, err := c.sseTarget(ctx, q)
	if err != nil {
		return nil, err
	}
	key = strings.ToUpper(key)
	query.Set("key", key)
	query.Set("path", normalizePath(q.Path))
	var items []apiManaged
	if err := c.do(ctx, http.MethodGet, "/v1/secrets/", query, nil, &items); err != nil {
		return nil, err
	}
	for _, i := range items {
		if i.Key == key && normalizePath(i.Path) == normalizePath(q.Path) {
			m := &ManagedSecret{ID: i.ID, Key: i.Key, Path: i.Path, Comment: i.Comment}
			if i.Value != nil {
				m.Value = *i.Value
			}
			return m, nil
		}
	}
	return nil, ErrNotFound
}

// CreateSecret creates a secret; keys are stored upper-case.
func (c *Client) CreateSecret(ctx context.Context, q Query, s ManagedSecret) (*ManagedSecret, error) {
	query, err := c.sseTarget(ctx, q)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"secrets": []map[string]any{{
		"key": s.Key, "value": s.Value, "comment": s.Comment, "path": normalizePath(q.Path),
	}}}
	if err := c.send(ctx, http.MethodPost, "/v1/secrets/", query, nil, body, nil); err != nil {
		return nil, err
	}
	return c.FindSecret(ctx, q, s.Key)
}

// UpdateSecret changes the value and comment of the secret with s.ID.
func (c *Client) UpdateSecret(ctx context.Context, q Query, s ManagedSecret) error {
	query, err := c.sseTarget(ctx, q)
	if err != nil {
		return err
	}
	body := map[string]any{"secrets": []map[string]any{{"id": s.ID, "value": s.Value, "comment": s.Comment}}}
	return c.send(ctx, http.MethodPut, "/v1/secrets/", query, nil, body, nil)
}

// DeleteSecret deletes the secret with the given id.
func (c *Client) DeleteSecret(ctx context.Context, q Query, id string) error {
	query, err := c.sseTarget(ctx, q)
	if err != nil {
		return err
	}
	return c.send(ctx, http.MethodDelete, "/v1/secrets/", query, nil, map[string]any{"secrets": []string{id}}, nil)
}

// --- batch management (server-side and end-to-end encrypted apps) ---------------

// StoredSecret is a secret as stored: values are not reference-resolved and
// personal overrides are reported separately.
type StoredSecret struct {
	ID       string
	Key      string
	Value    string
	Path     string
	Comment  string
	Tags     []string
	Type     string    // "secret" (default), "sealed" or "config"
	Override *Override // the signed-in member's personal value, if any
	Redacted bool      // listed without Secrets:reveal; Value is empty
}

// Override is a member's personal value for a secret. Only people (not
// service accounts) have overrides.
type Override struct {
	Value  string
	Active bool
}

// writeTarget is where secret writes for q go.
type writeTarget struct {
	sse     bool
	query   url.Values
	headers map[string]string
	keys    KeyPair // E2EE environment keys
	salt    string
}

func (c *Client) writeTarget(ctx context.Context, q Query) (*writeTarget, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	if app.Encryption == "SSE" {
		return &writeTarget{sse: true, query: url.Values{"app_id": {app.ID}, "env": {key.Environment.Name}}}, nil
	}
	material, err := info.material(key)
	if err != nil {
		return nil, err
	}
	return &writeTarget{headers: map[string]string{"Environment": key.Environment.ID}, keys: material.keys, salt: material.salt}, nil
}

func (t *writeTarget) endpoint() string {
	if t.sse {
		return "/v1/secrets/"
	}
	return "/secrets/"
}

func (t *writeTarget) encrypt(plaintext string) (string, error) {
	return EncryptAsymmetric(plaintext, t.keys.Public)
}

// ListSecrets returns the stored secrets of q's environment (all folders when
// q.Path is empty) with their IDs, for editing.
func (c *Client) ListSecrets(ctx context.Context, q Query) ([]StoredSecret, error) {
	t, err := c.writeTarget(ctx, q)
	if err != nil {
		return nil, err
	}
	var items []apiSecret
	if t.sse {
		query := url.Values{"app_id": t.query["app_id"], "env": t.query["env"]}
		if q.Path != "" {
			query.Set("path", normalizePath(q.Path))
		}
		err = c.do(ctx, http.MethodGet, "/v1/secrets/", query, nil, &items)
	} else {
		headers := map[string]string{"Environment": t.headers["Environment"], "X-Use-Camel-Case": "true"}
		if q.Path != "" {
			headers["Path"] = normalizePath(q.Path)
		}
		err = c.do(ctx, http.MethodGet, "/secrets/", nil, headers, &items)
	}
	if err != nil {
		return nil, err
	}
	out := make([]StoredSecret, 0, len(items))
	for _, item := range items {
		s := StoredSecret{ID: item.ID, Path: normalizePath(item.Path), Tags: item.Tags, Type: item.Type, Redacted: item.ValueRedacted}
		if s.Type == "" {
			s.Type = "secret"
		}
		open := func(v string) (string, error) {
			if t.sse || v == "" {
				return v, nil
			}
			return DecryptAsymmetric(v, t.keys)
		}
		if s.Key, err = open(item.Key); err != nil {
			return nil, err
		}
		if item.Value != nil {
			if s.Value, err = open(*item.Value); err != nil {
				return nil, err
			}
		} else if t.sse {
			s.Redacted = true
		}
		if s.Comment, err = open(item.Comment); err != nil {
			return nil, err
		}
		if o := item.Override; o != nil {
			s.Override = &Override{Active: o.IsActive}
			if o.Value != nil {
				if s.Override.Value, err = open(*o.Value); err != nil {
					return nil, err
				}
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// normalizeKey upper-cases a key and replaces spaces with underscores.
func normalizeKey(k string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), " ", "_"))
}

// CreateSecrets creates secrets in q's environment in one request. A secret's
// Path defaults to q.Path. An Override is stored only for people.
func (c *Client) CreateSecrets(ctx context.Context, q Query, secrets []StoredSecret) error {
	if len(secrets) == 0 {
		return nil
	}
	t, err := c.writeTarget(ctx, q)
	if err != nil {
		return err
	}
	body := make([]map[string]any, 0, len(secrets))
	for _, s := range secrets {
		key := normalizeKey(s.Key)
		if key == "" {
			return errors.New("adera: secret key is empty")
		}
		path := s.Path
		if path == "" {
			path = q.Path
		}
		item := map[string]any{"path": normalizePath(path), "tags": nonNil(s.Tags), "type": secretType(s.Type)}
		fields := map[string]string{"key": key, "value": s.Value, "comment": s.Comment}
		if s.Override != nil {
			fields["override"] = s.Override.Value
		}
		if !t.sse {
			if item["keyDigest"], err = KeyDigest(key, t.salt); err != nil {
				return err
			}
			for name, v := range fields {
				if fields[name], err = t.encrypt(v); err != nil {
					return err
				}
			}
		}
		item["key"], item["value"], item["comment"] = fields["key"], fields["value"], fields["comment"]
		if s.Override != nil {
			item["override"] = map[string]any{"value": fields["override"], "isActive": s.Override.Active}
		}
		body = append(body, item)
	}
	return c.send(ctx, http.MethodPost, t.endpoint(), t.query, t.headers, map[string]any{"secrets": body}, nil)
}

// UpdateSecrets writes back secrets previously returned by ListSecrets (and
// changed by the caller) in one request: value, comment, path, tags, type and
// override. The value of a Redacted secret is left unchanged; keys cannot be
// renamed.
func (c *Client) UpdateSecrets(ctx context.Context, q Query, secrets []StoredSecret) error {
	if len(secrets) == 0 {
		return nil
	}
	t, err := c.writeTarget(ctx, q)
	if err != nil {
		return err
	}
	body := make([]map[string]any, 0, len(secrets))
	for _, s := range secrets {
		if s.ID == "" {
			return errors.New("adera: UpdateSecrets needs secrets with IDs (from ListSecrets)")
		}
		item := map[string]any{"id": s.ID, "path": normalizePath(s.Path), "tags": nonNil(s.Tags), "type": secretType(s.Type)}
		fields := map[string]string{"comment": s.Comment}
		if !s.Redacted {
			fields["value"] = s.Value
		}
		if s.Override != nil {
			fields["override"] = s.Override.Value
		}
		if !t.sse {
			// The key and its digest let the server reject a move onto an existing key.
			fields["key"] = normalizeKey(s.Key)
			if item["keyDigest"], err = KeyDigest(normalizeKey(s.Key), t.salt); err != nil {
				return err
			}
			for name, v := range fields {
				if fields[name], err = t.encrypt(v); err != nil {
					return err
				}
			}
		}
		for _, name := range []string{"key", "value", "comment"} {
			if v, ok := fields[name]; ok {
				item[name] = v
			}
		}
		if s.Override != nil {
			item["override"] = map[string]any{"value": fields["override"], "isActive": s.Override.Active}
		}
		body = append(body, item)
	}
	return c.send(ctx, http.MethodPut, t.endpoint(), t.query, t.headers, map[string]any{"secrets": body}, nil)
}

// DeleteSecrets deletes secrets by ID in one request.
func (c *Client) DeleteSecrets(ctx context.Context, q Query, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	t, err := c.writeTarget(ctx, q)
	if err != nil {
		return err
	}
	return c.send(ctx, http.MethodDelete, t.endpoint(), t.query, t.headers, map[string]any{"secrets": ids}, nil)
}

func nonNil(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}

func secretType(t string) string {
	if t == "" {
		return "secret"
	}
	return t
}
