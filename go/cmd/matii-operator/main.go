// Command matii-operator syncs MatiiSecret resources into Kubernetes Secrets.
//
// Environment: MATII_HOST (or MATII_API_BASE), MATII_AUDIENCE (default
// matii-secret-service), WATCH_NAMESPACE (empty = all), POLL_SECONDS (default 10).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/matii-org/matii-secret-clients/go/internal/kube"
	"github.com/matii-org/matii-secret-clients/go/internal/operator"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	apiBase := os.Getenv("MATII_API_BASE")
	if apiBase == "" && os.Getenv("MATII_HOST") != "" {
		apiBase = strings.TrimRight(os.Getenv("MATII_HOST"), "/") + "/service"
	}
	if apiBase == "" {
		logger.Error("set MATII_HOST")
		os.Exit(2)
	}
	kc, err := kube.InCluster()
	if err != nil {
		logger.Error("kubernetes config", "error", err.Error())
		os.Exit(2)
	}
	poll := 10 * time.Second
	if v, err := strconv.Atoi(os.Getenv("POLL_SECONDS")); err == nil && v >= 5 {
		poll = time.Duration(v) * time.Second
	}
	op := operator.New(operator.Config{
		APIBase: apiBase, Audience: os.Getenv("MATII_AUDIENCE"),
		Namespace: os.Getenv("WATCH_NAMESPACE"), Kube: kc, Logger: logger,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("matii-operator started", "namespace", os.Getenv("WATCH_NAMESPACE"), "poll", poll.String())
	for {
		if err := op.RunOnce(ctx); err != nil {
			logger.Warn("listing MatiiSecrets failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}
