package matii

import (
	"context"
	"sync"
	"time"
)

// CachedClient serves secrets from memory, refreshes them after TTL and keeps
// serving the last good values for up to MaxStale when the service is
// unreachable ("fail static"). Values live only in process memory.
type CachedClient struct {
	Client   *Client
	TTL      time.Duration // refresh interval (default 60s)
	MaxStale time.Duration // how long stale values may be served on errors (default 15m)

	mu      sync.Mutex
	entries map[Query]cacheEntry
}

type cacheEntry struct {
	secrets []Secret
	fetched time.Time
}

// Secrets returns cached values when fresh, refreshing as needed.
func (c *CachedClient) Secrets(ctx context.Context, q Query) ([]Secret, error) {
	ttl, maxStale := c.TTL, c.MaxStale
	if ttl <= 0 {
		ttl = time.Minute
	}
	if maxStale <= 0 {
		maxStale = 15 * time.Minute
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[Query]cacheEntry{}
	}
	entry, ok := c.entries[q]
	c.mu.Unlock()
	if ok && time.Since(entry.fetched) < ttl {
		return entry.secrets, nil
	}
	secrets, err := c.Client.Secrets(ctx, q)
	if err != nil {
		if ok && time.Since(entry.fetched) < maxStale {
			return entry.secrets, nil
		}
		return nil, err
	}
	c.mu.Lock()
	c.entries[q] = cacheEntry{secrets: secrets, fetched: time.Now()}
	c.mu.Unlock()
	return secrets, nil
}

// Get returns one value from a cached environment.
func (c *CachedClient) Get(ctx context.Context, q Query, key string) (string, bool, error) {
	secrets, err := c.Secrets(ctx, q)
	if err != nil {
		return "", false, err
	}
	for _, s := range secrets {
		if s.Key == key && !s.Redacted {
			return s.Value, true, nil
		}
	}
	return "", false, nil
}
