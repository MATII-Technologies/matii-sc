// Package operator reconciles MatiiSecret resources into Kubernetes Secrets.
//
//	apiVersion: secrets.matii.io/v1alpha1
//	kind: MatiiSecret
//	metadata: {name: payments, namespace: payments}
//	spec:
//	  serviceAccountId: <Matii service account id>     # with a Kubernetes OIDC identity
//	  kubernetesServiceAccount: payments-reader         # its token is exchanged (default "default")
//	  app: Payments
//	  env: production
//	  path: /                                          # optional
//	  secretName: payments-secrets                     # target Secret in the same namespace
//	  refreshSeconds: 60                               # optional (min 15)
//	  rolloutRestart: [{kind: Deployment, name: api}]  # optional, on change
//
// Authorization happens in the Secret Service: the operator obtains a token
// for the named ServiceAccount (TokenRequest API, audience below) and
// exchanges it; the Matii identity decides which namespaces/accounts may read
// what. The operator never overwrites a Secret it does not manage.
package operator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/internal/kube"
	"github.com/MATII-Technologies/matii-sc/go/matii"
)

const (
	Group          = "secrets.matii.io"
	Version        = "v1alpha1"
	FieldManager   = "matii-operator"
	ManagedByLabel = "app.kubernetes.io/managed-by"
	HashAnnotation = "secrets.matii.io/hash"
	restartKey     = "secrets.matii.io/restarted-for"
)

// MatiiSecret is the custom resource.
type MatiiSecret struct {
	Metadata struct {
		Name       string `json:"name"`
		Namespace  string `json:"namespace"`
		UID        string `json:"uid"`
		Generation int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountID         string `json:"serviceAccountId"`
		KubernetesServiceAccount string `json:"kubernetesServiceAccount"`
		App                      string `json:"app"`
		Env                      string `json:"env"`
		Path                     string `json:"path"`
		SecretName               string `json:"secretName"`
		RefreshSeconds           int    `json:"refreshSeconds"`
		RolloutRestart           []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"rolloutRestart"`
	} `json:"spec"`
	Status struct {
		SecretHash string `json:"secretHash"`
		LastSync   string `json:"lastSyncTime"`
	} `json:"status"`
}

// Config for the operator.
type Config struct {
	APIBase   string // Secret Service API, e.g. https://secrets.example.com/service
	Audience  string // audience of the exchanged Kubernetes tokens
	Namespace string // watch one namespace; empty = all
	Kube      *kube.Client
	Logger    *slog.Logger
	// NewClient builds a Secret Service client for a token source (tests override it).
	NewClient func(apiBase string, tokens matii.TokenSource) (secretsClient, error)
}

type secretsClient interface {
	Secrets(ctx context.Context, q matii.Query) ([]matii.Secret, error)
}

// Operator reconciles MatiiSecrets.
type Operator struct {
	cfg     Config
	mu      sync.Mutex
	clients map[string]secretsClient // per (namespace, k8s SA, matii SA)
	nextRun map[string]time.Time
}

func New(cfg Config) *Operator {
	if cfg.Audience == "" {
		cfg.Audience = "matii-secret-service"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NewClient == nil {
		cfg.NewClient = func(apiBase string, tokens matii.TokenSource) (secretsClient, error) {
			return matii.New(matii.Config{APIBase: apiBase, Tokens: tokens})
		}
	}
	return &Operator{cfg: cfg, clients: map[string]secretsClient{}, nextRun: map[string]time.Time{}}
}

func (o *Operator) listPath() string {
	if o.cfg.Namespace != "" {
		return fmt.Sprintf("/apis/%s/%s/namespaces/%s/matiisecrets", Group, Version, url.PathEscape(o.cfg.Namespace))
	}
	return fmt.Sprintf("/apis/%s/%s/matiisecrets", Group, Version)
}

// RunOnce reconciles every MatiiSecret that is due. Errors are reported in
// each resource's status; the returned error is for listing failures only.
func (o *Operator) RunOnce(ctx context.Context) error {
	var list struct {
		Items []MatiiSecret `json:"items"`
	}
	if err := o.cfg.Kube.Do(ctx, "GET", o.listPath(), "", nil, &list); err != nil {
		return err
	}
	now := time.Now()
	for i := range list.Items {
		ms := &list.Items[i]
		key := ms.Metadata.Namespace + "/" + ms.Metadata.Name + "@" + fmt.Sprint(ms.Metadata.Generation)
		o.mu.Lock()
		due := now.After(o.nextRun[key])
		o.mu.Unlock()
		if !due {
			continue
		}
		err := o.Reconcile(ctx, ms)
		interval := time.Duration(max(ms.Spec.RefreshSeconds, 15)) * time.Second
		if ms.Spec.RefreshSeconds == 0 {
			interval = time.Minute
		}
		if err != nil {
			o.cfg.Logger.Warn("reconcile failed", "matiisecret", ms.Metadata.Namespace+"/"+ms.Metadata.Name, "error", err.Error())
			interval = 30 * time.Second
		}
		o.mu.Lock()
		o.nextRun[key] = now.Add(interval)
		o.mu.Unlock()
	}
	return nil
}

func validate(ms *MatiiSecret) error {
	s := ms.Spec
	if s.ServiceAccountID == "" || s.App == "" || s.Env == "" || s.SecretName == "" {
		return errors.New("spec.serviceAccountId, app, env and secretName are required")
	}
	for _, r := range s.RolloutRestart {
		if r.Kind != "Deployment" && r.Kind != "StatefulSet" && r.Kind != "DaemonSet" {
			return fmt.Errorf("rolloutRestart kind %q is not supported", r.Kind)
		}
	}
	return nil
}

func (o *Operator) client(ms *MatiiSecret) (secretsClient, error) {
	sa := ms.Spec.KubernetesServiceAccount
	if sa == "" {
		sa = "default"
	}
	key := ms.Metadata.Namespace + "/" + sa + "/" + ms.Spec.ServiceAccountID
	o.mu.Lock()
	defer o.mu.Unlock()
	if c, ok := o.clients[key]; ok {
		return c, nil
	}
	namespace := ms.Metadata.Namespace
	tokens := &matii.OIDCTokenSource{
		APIBase:          o.cfg.APIBase,
		ServiceAccountID: ms.Spec.ServiceAccountID,
		JWT: func(ctx context.Context) (string, error) {
			return o.requestToken(ctx, namespace, sa)
		},
	}
	c, err := o.cfg.NewClient(o.cfg.APIBase, tokens)
	if err != nil {
		return nil, err
	}
	o.clients[key] = c
	return c, nil
}

// requestToken asks Kubernetes for a short-lived token of a ServiceAccount (TokenRequest API).
func (o *Operator) requestToken(ctx context.Context, namespace, serviceAccount string) (string, error) {
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       map[string]any{"audiences": []string{o.cfg.Audience}, "expirationSeconds": 600},
	}
	var out struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", url.PathEscape(namespace), url.PathEscape(serviceAccount))
	if err := o.cfg.Kube.Do(ctx, "POST", path, "", body, &out); err != nil {
		return "", err
	}
	return out.Status.Token, nil
}

// Hash is a stable digest of the secret data (keys sorted).
func Hash(data map[string]string) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s=%d:%s;", len(k), k, len(data[k]), data[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Reconcile syncs one MatiiSecret.
func (o *Operator) Reconcile(ctx context.Context, ms *MatiiSecret) error {
	err := o.reconcile(ctx, ms)
	status := map[string]any{"observedGeneration": ms.Metadata.Generation}
	if err != nil {
		status["ready"] = false
		status["message"] = err.Error()
	} else {
		status["ready"] = true
		status["message"] = "synced"
	}
	statusPath := fmt.Sprintf("/apis/%s/%s/namespaces/%s/matiisecrets/%s/status", Group, Version,
		url.PathEscape(ms.Metadata.Namespace), url.PathEscape(ms.Metadata.Name))
	if ms.Status.SecretHash != "" {
		status["secretHash"] = ms.Status.SecretHash
		status["lastSyncTime"] = ms.Status.LastSync
	}
	if serr := o.cfg.Kube.Do(ctx, "PATCH", statusPath, "application/merge-patch+json", map[string]any{"status": status}, nil); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (o *Operator) reconcile(ctx context.Context, ms *MatiiSecret) error {
	if err := validate(ms); err != nil {
		return err
	}
	client, err := o.client(ms)
	if err != nil {
		return err
	}
	secrets, err := client.Secrets(ctx, matii.Query{AppName: ms.Spec.App, Env: ms.Spec.Env, Path: ms.Spec.Path})
	if err != nil {
		return fmt.Errorf("fetching secrets: %w", err)
	}
	data := matii.Map(secrets)
	for key := range data {
		if !validSecretKey(key) {
			return fmt.Errorf("secret key %q is not a valid Kubernetes Secret key", key)
		}
	}
	hash := Hash(data)

	ns, name := url.PathEscape(ms.Metadata.Namespace), url.PathEscape(ms.Spec.SecretName)
	secretPath := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ns, name)
	var existing struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	switch err := o.cfg.Kube.Do(ctx, "GET", secretPath, "", nil, &existing); {
	case err == nil:
		if existing.Metadata.Labels[ManagedByLabel] != FieldManager {
			return fmt.Errorf("Secret %s exists and is not managed by %s; refusing to overwrite it", ms.Spec.SecretName, FieldManager)
		}
		if existing.Metadata.Annotations[HashAnnotation] == hash {
			ms.Status.SecretHash, ms.Status.LastSync = hash, time.Now().UTC().Format(time.RFC3339)
			return nil // unchanged
		}
	case kube.IsNotFound(err):
	default:
		return err
	}

	encoded := make(map[string]string, len(data))
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	apply := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "Opaque",
		"metadata": map[string]any{
			"name":        ms.Spec.SecretName,
			"namespace":   ms.Metadata.Namespace,
			"labels":      map[string]string{ManagedByLabel: FieldManager},
			"annotations": map[string]string{HashAnnotation: hash},
			"ownerReferences": []map[string]any{{
				"apiVersion": Group + "/" + Version, "kind": "MatiiSecret",
				"name": ms.Metadata.Name, "uid": ms.Metadata.UID, "controller": true,
			}},
		},
		"data": encoded,
	}
	if err := o.cfg.Kube.Do(ctx, "PATCH", secretPath+"?fieldManager="+FieldManager+"&force=true",
		"application/apply-patch+yaml", apply, nil); err != nil {
		return fmt.Errorf("applying Secret: %w", err)
	}
	for _, target := range ms.Spec.RolloutRestart {
		resource := strings.ToLower(target.Kind) + "s"
		path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s", ns, resource, url.PathEscape(target.Name))
		patch := map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
			"annotations": map[string]string{restartKey: hash},
		}}}}
		if err := o.cfg.Kube.Do(ctx, "PATCH", path, "application/strategic-merge-patch+json", patch, nil); err != nil {
			return fmt.Errorf("restarting %s/%s: %w", target.Kind, target.Name, err)
		}
	}
	ms.Status.SecretHash, ms.Status.LastSync = hash, time.Now().UTC().Format(time.RFC3339)
	o.cfg.Logger.Info("synced", "matiisecret", ms.Metadata.Namespace+"/"+ms.Metadata.Name, "keys", len(data))
	return nil
}

func validSecretKey(key string) bool {
	if key == "" || len(key) > 253 || key == "." || key == ".." {
		return false
	}
	for _, r := range key {
		if !(r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
