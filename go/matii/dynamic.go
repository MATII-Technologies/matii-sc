package matii

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// DynamicLease is a set of short-lived credentials issued by the service
// (for example AWS STS credentials). Values are secret; Lease.String() is not.
type DynamicLease struct {
	ID          string
	ExpiresAt   time.Time
	Credentials map[string]string
}

func (l *DynamicLease) String() string { return "dynamic lease " + l.ID + " (redacted)" }

// LeaseDynamic issues credentials from the dynamic secret `name` in the
// environment (and folder) of q. ttl 0 uses the definition's default.
func (c *Client) LeaseDynamic(ctx context.Context, q Query, name string, ttl time.Duration) (*DynamicLease, error) {
	if name == "" {
		return nil, errors.New("matii: dynamic secret name is required")
	}
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	app, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	path := q.Path
	if path == "" {
		path = "/"
	}
	body := map[string]any{"name": name, "path": path}
	if ttl > 0 {
		body["ttlSeconds"] = int(ttl / time.Second)
	}
	var out struct {
		LeaseID     string            `json:"leaseId"`
		ExpiresAt   time.Time         `json:"expiresAt"`
		Credentials map[string]string `json:"credentials"`
	}
	query := url.Values{"app_id": {app.ID}, "env": {key.Environment.Name}}
	if err := c.send(ctx, http.MethodPost, "/v1/dynamic-secrets/lease/", query, nil, body, &out); err != nil {
		return nil, err
	}
	return &DynamicLease{ID: out.LeaseID, ExpiresAt: out.ExpiresAt, Credentials: out.Credentials}, nil
}

// DynamicSecret is a dynamic secret definition (no credentials).
type DynamicSecret struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Path              string `json:"path"`
	Provider          string `json:"provider"`
	DefaultTTLSeconds int    `json:"defaultTtlSeconds"`
	MaxTTLSeconds     int    `json:"maxTtlSeconds"`
}

// DynamicLeaseInfo describes an issued lease (never its credentials).
type DynamicLeaseInfo struct {
	ID                 string    `json:"id"`
	MemberEmail        string    `json:"memberEmail"`
	ServiceAccountName string    `json:"serviceAccountName"`
	AccessKeyID        string    `json:"accessKeyId"`
	TTLSeconds         int       `json:"ttlSeconds"`
	ExpiresAt          time.Time `json:"expiresAt"`
	CreatedAt          time.Time `json:"createdAt"`
}

// ListDynamic lists the dynamic secrets of q's environment (q.Path filters by folder).
func (c *Client) ListDynamic(ctx context.Context, q Query) ([]DynamicSecret, error) {
	info, _, err := c.info(ctx)
	if err != nil {
		return nil, err
	}
	_, key, err := info.resolve(q)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data []DynamicSecret `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/dynamic-secrets/", url.Values{"environment_id": {key.Environment.ID}}, nil, &out); err != nil {
		return nil, err
	}
	if q.Path == "" {
		return out.Data, nil
	}
	filtered := out.Data[:0]
	for _, d := range out.Data {
		if normalizePath(d.Path) == normalizePath(q.Path) {
			filtered = append(filtered, d)
		}
	}
	return filtered, nil
}

// DynamicLeases lists the most recent leases of the dynamic secret `name` in
// q's environment and folder (default "/").
func (c *Client) DynamicLeases(ctx context.Context, q Query, name string) ([]DynamicLeaseInfo, error) {
	all, err := c.ListDynamic(ctx, Query{AppID: q.AppID, AppName: q.AppName, Env: q.Env})
	if err != nil {
		return nil, err
	}
	for _, d := range all {
		if d.Name == name && normalizePath(d.Path) == normalizePath(q.Path) {
			var out struct {
				Data []DynamicLeaseInfo `json:"data"`
			}
			if err := c.do(ctx, http.MethodGet, "/v1/dynamic-secrets/"+url.PathEscape(d.ID)+"/leases/", nil, nil, &out); err != nil {
				return nil, err
			}
			return out.Data, nil
		}
	}
	return nil, ErrNotFound
}
