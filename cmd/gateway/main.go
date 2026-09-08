package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"switchboard/internal/gateway"
	"syscall"
	"time"
)

func main() {
	logs := gateway.NewAsyncLogWriter(os.Stdout)
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	config := flag.String("config", "/etc/switchboard/config.json", "config file")
	health := flag.Bool("healthcheck", false, "check readiness and exit")
	// Prepares the data volume and exits, for use as an init container. An ECS
	// volume mounts owned by root, and the gateway proper runs as 65532 with a
	// read-only root filesystem and every capability dropped, so it cannot take
	// ownership of its own mount. Doing this with the gateway's own image rather
	// than a general-purpose one means a deployment ships a single image.
	initDir := flag.String("init-data-dir", "", "take ownership of this directory and exit")
	flag.Parse()

	if *initDir != "" {
		if e := os.MkdirAll(*initDir, 0700); e != nil {
			slog.Error("init: cannot create data directory", "error", e)
			os.Exit(1)
		}
		if e := os.Chown(*initDir, 65532, 65532); e != nil {
			slog.Error("init: cannot take ownership; this must run as root", "error", e)
			os.Exit(1)
		}
		if e := os.Chmod(*initDir, 0700); e != nil {
			slog.Error("init: cannot set permissions", "error", e)
			os.Exit(1)
		}
		// Straight to stderr rather than through the async writer, which has no
		// flush and would be racing this process's exit.
		fmt.Fprintf(os.Stderr, "init: prepared %s for uid/gid 65532\n", *initDir)
		return
	}
	c, e := gateway.LoadConfig(*config)
	if e != nil {
		slog.Error("invalid configuration", "error", e)
		os.Exit(1)
	}
	if *health {
		os.Exit(gateway.Healthcheck(c.Listen))
	}
	if e = os.MkdirAll(c.DataDir, 0700); e != nil {
		slog.Error("data directory unavailable")
		os.Exit(1)
	}
	lock, e := os.OpenFile(filepath.Join(c.DataDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		slog.Error("data directory already in use or not writable")
		os.Exit(1)
	}
	defer lock.Close()
	p := c.Store()
	if b, e := os.ReadFile(p.Path); e == nil {
		if e = p.Restore(b); e != nil {
			slog.Error("cached policy invalid", "error", e)
			os.Exit(1)
		}
	} else if !os.IsNotExist(e) {
		slog.Error("cannot read policy cache")
		os.Exit(1)
	}
	if c.Marketplace != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		api, e := gateway.NewUsageRegistrar(ctx)
		if e == nil {
			e = gateway.RegisterUsage(ctx, c.Marketplace, api)
		}
		cancel()
		if e != nil {
			// Fails closed: no entitlement, no serving.
			slog.Error("marketplace registration failed", "error", e)
			os.Exit(1)
		}
		slog.Info("marketplace usage registered", "product_code", c.Marketplace.ProductCode)
	}
	// Resolved once at startup, and only when a bedrock provider is configured,
	// so a deployment without one never touches AWS credential resolution.
	var bedrock *gateway.BedrockSigner
	if p, ok := c.Providers["bedrock"]; ok {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		bedrock, e = gateway.NewBedrockSigner(ctx, p.Region)
		cancel()
		if e != nil {
			slog.Error("bedrock is configured but unusable", "error", e)
			os.Exit(1)
		}
		slog.Info("bedrock signer ready", "region", p.Region)
	}

	m := &gateway.Metrics{LogDropped: &logs.Dropped}
	t, e := gateway.NewTelemetry(c, m)
	if e != nil {
		slog.Error("telemetry initialization failed")
		os.Exit(1)
	}
	background, stop := context.WithCancel(context.Background())
	s := gateway.New(c, p, m, t)
	s.Bedrock = bedrock
	t.Start(background)
	go s.Sync(background)
	// Checks each provider the policy routes to, once the first signed policy is
	// live. A key that is present but wrong, or an account that cannot pay, is
	// otherwise only discovered by a customer's first request failing.
	go s.ProbeProviders(background)
	srv := &http.Server{Addr: c.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	signals, unregister := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer unregister()
	go func() {
		<-signals.Done()
		s.Draining.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 95*time.Second)
		defer cancel()
		if srv.Shutdown(ctx) != nil {
			srv.Close()
		}
		stop()
	}()
	if w := c.UncollectedMetricsWarning(); w != "" {
		slog.Warn(w)
	}
	slog.Info("gateway started", "tenant", c.Tenant, "listen", c.Listen)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		slog.Error("listener failed")
		stop()
		os.Exit(1)
	}
	<-background.Done()
	done := make(chan struct{})
	go func() { t.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("telemetry drain timed out")
	}
}
