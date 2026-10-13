// Package csi implements a Secrets Store CSI Driver provider for the Matii
// Secret Service: secrets are mounted as files in the pod (tmpfs) and never
// stored as Kubernetes Secrets.
package csi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MATII-Technologies/matii-sc/go/matii"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

const (
	tokensAttribute = "csi.storage.k8s.io/serviceAccount.tokens"
	defaultAudience = "matii-secret-service"
	maxTotalBytes   = 1 << 20 // the driver's limit for syncing to Secrets
)

var fileName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Object maps one secret to a file. Without objects, every secret becomes a
// file named after its key.
type Object struct {
	Key  string `json:"key"`
	File string `json:"file"`
}

// Server answers the CSI driver's Mount and Version calls.
type Server struct {
	pb.UnimplementedCSIDriverProviderServer
	AllowedHosts []string // e.g. https://secrets.example.com; empty refuses every mount
	BuildVersion string
	// NewClient builds the Secret Service client (replaced in tests).
	NewClient  func(host string, tokens matii.TokenSource) (secretsClient, error)
	versionKey []byte
}

type secretsClient interface {
	Secrets(ctx context.Context, q matii.Query) ([]matii.Secret, error)
}

// NewServer returns a server with the real client.
func NewServer(allowed []string, version string) *Server {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &Server{
		AllowedHosts: allowed, BuildVersion: version, versionKey: key,
		NewClient: func(host string, tokens matii.TokenSource) (secretsClient, error) {
			return matii.New(matii.Config{Host: host, Tokens: tokens})
		},
	}
}

func (s *Server) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{Version: "v1alpha1", RuntimeName: "matii-csi-provider", RuntimeVersion: s.BuildVersion}, nil
}

type params struct {
	host, serviceAccountID, app, env, folder, audience, format, formatFile string
	objects                                                              []Object
}

func parseParams(attrs map[string]string) (*params, error) {
	p := &params{
		host: strings.TrimRight(attrs["host"], "/"), serviceAccountID: attrs["serviceAccountId"],
		app: attrs["app"], env: attrs["env"], folder: attrs["path"], audience: attrs["audience"],
		format: attrs["format"], formatFile: attrs["fileName"],
	}
	if p.audience == "" {
		p.audience = defaultAudience
	}
	if p.host == "" || p.serviceAccountID == "" || p.app == "" || p.env == "" {
		return nil, errors.New("parameters host, serviceAccountId, app and env are required")
	}
	if raw := attrs["objects"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &p.objects); err != nil {
			return nil, fmt.Errorf("objects must be a JSON list of {key, file}: %w", err)
		}
	}
	switch p.format {
	case "", "files":
	case "dotenv", "json":
		if p.formatFile == "" {
			p.formatFile = map[string]string{"dotenv": ".env", "json": "secrets.json"}[p.format]
		}
	default:
		return nil, errors.New("format must be files, dotenv or json")
	}
	return p, nil
}

func (s *Server) hostAllowed(host string) bool {
	u, err := url.Parse(host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return false
	}
	for _, allowed := range s.AllowedHosts {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), host) {
			return true
		}
	}
	return false
}

func podToken(attrs map[string]string, audience string) (string, error) {
	var tokens map[string]struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(attrs[tokensAttribute]), &tokens); err != nil || tokens[audience].Token == "" {
		return "", fmt.Errorf("no service account token for audience %q: add it to the CSIDriver's tokenRequests", audience)
	}
	return tokens[audience].Token, nil
}

func (s *Server) version(value string) string {
	mac := hmac.New(sha256.New, s.versionKey)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func (s *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	var attrs map[string]string
	if err := json.Unmarshal([]byte(req.GetAttributes()), &attrs); err != nil {
		return nil, fmt.Errorf("matii: invalid attributes: %w", err)
	}
	p, err := parseParams(attrs)
	if err != nil {
		return nil, fmt.Errorf("matii: %w", err)
	}
	if !s.hostAllowed(p.host) {
		return nil, fmt.Errorf("matii: host %q is not in the provider's --allowed-hosts", p.host)
	}
	jwt, err := podToken(attrs, p.audience)
	if err != nil {
		return nil, fmt.Errorf("matii: %w", err)
	}
	mode := int32(0o440)
	if req.GetPermission() != "" {
		if m, err := strconv.ParseInt(req.GetPermission(), 10, 32); err == nil && m >= 0 && m <= 0o777 {
			mode = int32(m)
		}
	}
	tokens := &matii.OIDCTokenSource{APIBase: p.host + "/service", ServiceAccountID: p.serviceAccountID,
		JWT: func(context.Context) (string, error) { return jwt, nil }}
	client, err := s.NewClient(p.host, tokens)
	if err != nil {
		return nil, fmt.Errorf("matii: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	secrets, err := client.Secrets(ctx, matii.Query{AppName: p.app, Env: p.env, Path: p.folder})
	if err != nil {
		return nil, fmt.Errorf("matii: reading secrets failed: %w", err)
	}
	values := matii.Map(secrets)
	resp := &pb.MountResponse{}
	add := func(file, id string, contents []byte) error {
		if !fileName.MatchString(file) || file == "." || file == ".." {
			return fmt.Errorf("matii: invalid file name %q", file)
		}
		resp.Files = append(resp.Files, &pb.File{Path: file, Mode: mode, Contents: contents})
		resp.ObjectVersion = append(resp.ObjectVersion, &pb.ObjectVersion{
			Id: path.Join("matii", p.app, p.env, id), Version: s.version(string(contents))})
		return nil
	}
	switch {
	case p.format == "dotenv" || p.format == "json":
		body := matii.Dotenv(secrets)
		if p.format == "json" {
			body = matii.JSON(secrets)
		}
		if err := add(p.formatFile, p.formatFile, []byte(body)); err != nil {
			return nil, err
		}
	case len(p.objects) > 0:
		for _, o := range p.objects {
			v, ok := values[o.Key]
			if !ok {
				return nil, fmt.Errorf("matii: secret %q not found (or not revealable) in %s/%s", o.Key, p.app, p.env)
			}
			file := o.File
			if file == "" {
				file = o.Key
			}
			if err := add(file, o.Key, []byte(v)); err != nil {
				return nil, err
			}
		}
	default:
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := add(k, k, []byte(values[k])); err != nil {
				return nil, err
			}
		}
	}
	total := 0
	for _, f := range resp.Files {
		total += len(f.Contents)
	}
	if total > maxTotalBytes {
		return nil, fmt.Errorf("matii: %d bytes exceed the 1 MiB mount limit; select objects or a folder", total)
	}
	return resp, nil
}
