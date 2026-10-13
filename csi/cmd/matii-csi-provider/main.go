// Command matii-csi-provider is a Secrets Store CSI Driver provider for the
// Matii Secret Service. Run it as a DaemonSet next to the driver.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"

	"github.com/MATII-Technologies/matii-sc/csi/internal/csi"
)

var version = "dev"

func main() {
	endpoint := flag.String("endpoint", "/etc/kubernetes/secrets-store-csi-providers/matii.sock", "unix socket to listen on")
	allowed := flag.String("allowed-hosts", os.Getenv("MATII_ALLOWED_HOSTS"), "comma-separated https origins of Secret Services pods may use")
	flag.Parse()
	hosts := []string{}
	for _, h := range strings.Split(*allowed, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		log.Fatal("set --allowed-hosts (or MATII_ALLOWED_HOSTS)")
	}
	_ = os.Remove(*endpoint)
	ln, err := net.Listen("unix", *endpoint)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*endpoint, 0o600); err != nil {
		log.Fatal(err)
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(4 << 20))
	pb.RegisterCSIDriverProviderServer(srv, csi.NewServer(hosts, version))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; srv.GracefulStop() }()
	log.Printf("matii-csi-provider %s listening on %s (hosts: %s)", version, *endpoint, strings.Join(hosts, ", "))
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
}
