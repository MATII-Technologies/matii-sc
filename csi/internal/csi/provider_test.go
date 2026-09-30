package csi

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/matii-org/matii-secret-clients/go/matii"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

type fakeClient struct {
	gotQuery matii.Query
	gotJWT   string
	tokens   matii.TokenSource
}

func (f *fakeClient) Secrets(ctx context.Context, q matii.Query) ([]matii.Secret, error) {
	f.gotQuery = q
	if src, ok := f.tokens.(*matii.OIDCTokenSource); ok {
		f.gotJWT, _ = src.JWT(ctx)
	}
	return []matii.Secret{
		{Key: "DB_URL", Value: "postgres://x", Path: "/"},
		{Key: "API_KEY", Value: "k", Path: "/"},
		{Key: "HIDDEN", Redacted: true, Path: "/"},
	}, nil
}

func serve(t *testing.T, s *Server) pb.CSIDriverProviderClient {
	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	pb.RegisterCSIDriverProviderServer(g, s)
	go g.Serve(ln)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewCSIDriverProviderClient(conn)
}

func attributes(extra map[string]string) string {
	tokens, _ := json.Marshal(map[string]map[string]string{"matii-secret-service": {"token": "pod-jwt"}})
	a := map[string]string{
		"host": "https://secrets.example.com", "serviceAccountId": "sa-1", "app": "Payments", "env": "production",
		tokensAttribute: string(tokens),
	}
	for k, v := range extra {
		a[k] = v
	}
	b, _ := json.Marshal(a)
	return string(b)
}

func newTestServer(fc *fakeClient) *Server {
	s := NewServer([]string{"https://secrets.example.com"}, "test")
	s.NewClient = func(host string, tokens matii.TokenSource) (secretsClient, error) {
		fc.tokens = tokens
		return fc, nil
	}
	return s
}

func TestMountWritesRevealableSecretsAsFiles(t *testing.T) {
	fc := &fakeClient{}
	client := serve(t, newTestServer(fc))
	resp, err := client.Mount(context.Background(), &pb.MountRequest{Attributes: attributes(map[string]string{"path": "/backend"}), Permission: "420"})
	if err != nil {
		t.Fatal(err)
	}
	if fc.gotJWT != "pod-jwt" || fc.gotQuery.AppName != "Payments" || fc.gotQuery.Path != "/backend" {
		t.Fatalf("query %+v jwt %q", fc.gotQuery, fc.gotJWT)
	}
	got := map[string]string{}
	for _, f := range resp.Files {
		got[f.Path] = string(f.Contents)
		if f.Mode != 420 {
			t.Fatalf("mode %d", f.Mode)
		}
	}
	if len(got) != 2 || got["DB_URL"] != "postgres://x" || got["API_KEY"] != "k" {
		t.Fatalf("files %v", got)
	}
	for _, v := range resp.ObjectVersion {
		if strings.Contains(v.Version, "postgres") || len(v.Version) != 16 {
			t.Fatalf("version leaks or malformed: %v", v)
		}
	}
	v, _ := client.Version(context.Background(), &pb.VersionRequest{})
	if v.RuntimeName != "matii-csi-provider" {
		t.Fatal(v)
	}
}

func TestMountObjectsAndFormats(t *testing.T) {
	client := serve(t, newTestServer(&fakeClient{}))
	resp, err := client.Mount(context.Background(), &pb.MountRequest{Attributes: attributes(map[string]string{
		"objects": `[{"key":"DB_URL","file":"database-url"}]`})})
	if err != nil || len(resp.Files) != 1 || resp.Files[0].Path != "database-url" {
		t.Fatalf("%v %v", resp, err)
	}
	resp, err = client.Mount(context.Background(), &pb.MountRequest{Attributes: attributes(map[string]string{"format": "dotenv"})})
	if err != nil || resp.Files[0].Path != ".env" || !strings.Contains(string(resp.Files[0].Contents), "DB_URL=") {
		t.Fatalf("%v %v", resp, err)
	}
	if _, err := client.Mount(context.Background(), &pb.MountRequest{Attributes: attributes(map[string]string{
		"objects": `[{"key":"HIDDEN"}]`})}); err == nil {
		t.Fatal("unrevealable secret mounted")
	}
}

func TestMountRefusals(t *testing.T) {
	client := serve(t, newTestServer(&fakeClient{}))
	cases := map[string]map[string]string{
		"host not allowed":  {"host": "https://evil.example.com"},
		"plain http":        {"host": "http://secrets.example.com"},
		"traversal":         {"objects": `[{"key":"DB_URL","file":"../etc/passwd"}]`},
		"missing parameter": {"app": ""},
		"no token":          {tokensAttribute: "{}"},
	}
	for name, extra := range cases {
		if _, err := client.Mount(context.Background(), &pb.MountRequest{Attributes: attributes(extra)}); err == nil {
			t.Errorf("%s: mount accepted", name)
		}
	}
}
