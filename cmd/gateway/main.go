package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"switchboard/internal/gateway"
	"syscall"
	"time"
)

func main() {
	logs := gateway.NewAsyncLogWriter(os.Stdout)
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	// Every fatal path goes through here. slog.Error followed directly by
	// os.Exit raced the writer goroutine and lost the message about a third of
	// the time, so a misconfigured gateway would exit 1 saying nothing at all.
	fatal := func(msg string, args ...any) {
		slog.Error(msg, args...)
		logs.Close()
		os.Exit(1)
	}
	config := flag.String("config", "/etc/switchboard/config.json", "config file")
	health := flag.Bool("healthcheck", false, "check readiness and exit")
	// Prepares the data volume and exits, for use as an init container. An ECS
	// volume mounts owned by root, and the gateway proper runs as 65532 with a
	// read-only root filesystem and every capability dropped, so it cannot take
	// ownership of its own mount. Doing this with the gateway's own image rather
	// than a general-purpose one means a deployment ships a single image.
	initDir := flag.String("init-data-dir", "", "take ownership of this directory and exit")
	// Prints the base64 public key for a base64 signing seed and exits. Two
	// shipped documents told operators to obtain this from the control plane,
	// which serves no such endpoint, so the instruction could not be followed.
	// It lives here because the gateway binary ships wherever the sidecar does
	// and needs no Python. Deriving a public key is not signing: this binary
	// still cannot produce a policy it would accept.
	pubKey := flag.Bool("public-key", false, "read a base64 signing seed on stdin, print its base64 public key, and exit")
	flag.Parse()

	if *pubKey {
		if e := printPublicKey(os.Stdin, os.Stdout); e != nil {
			fmt.Fprintln(os.Stderr, "public-key:", e)
			os.Exit(1)
		}
		return
	}

	if *initDir != "" {
		if e := os.MkdirAll(*initDir, 0700); e != nil {
			fatal("init: cannot create data directory", "error", e)
		}
		if e := os.Chown(*initDir, 65532, 65532); e != nil {
			fatal("init: cannot take ownership; this must run as root", "error", e)
		}
		if e := os.Chmod(*initDir, 0700); e != nil {
			fatal("init: cannot set permissions", "error", e)
		}
		// Straight to stderr rather than through the async writer, which has no
		// flush and would be racing this process's exit.
		fmt.Fprintf(os.Stderr, "init: prepared %s for uid/gid 65532\n", *initDir)
		return
	}
	c, e := gateway.LoadConfig(*config)
	if e != nil {
		fatal("invalid configuration", "error", e)
	}
	if *health {
		os.Exit(gateway.Healthcheck(c.Listen))
	}
	if e = os.MkdirAll(c.DataDir, 0700); e != nil {
		fatal("data directory unavailable")
	}
	lock, e := os.OpenFile(filepath.Join(c.DataDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		fatal("data directory already in use or not writable")
	}
	defer lock.Close()
	p := c.Store()
	if b, e := os.ReadFile(p.Path); e == nil {
		if e = p.Restore(b); e != nil {
			fatal("cached policy invalid", "error", e)
		}
	} else if !os.IsNotExist(e) {
		fatal("cannot read policy cache")
	} else if c.ControlURL == "" {
		// File-only operation with nothing to serve. Failing here says so;
		// starting would leave /readyz at 503 forever with nothing to poll and
		// no explanation of what is missing.
		fatal("file-only operation, but no policy is present",
			"expected", p.Path,
			"remedy", "write a signed policy there, or set control_url to fetch one")
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
			fatal("marketplace registration failed", "error", e)
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
			fatal("bedrock is configured but unusable", "error", e)
		}
		slog.Info("bedrock signer ready", "region", p.Region)
	}

	m := &gateway.Metrics{LogDropped: &logs.Dropped}
	t, e := gateway.NewTelemetry(c, m)
	if e != nil {
		fatal("telemetry initialization failed")
	}
	background, stop := context.WithCancel(context.Background())
	s := gateway.New(c, p, m, t)
	s.Bedrock = bedrock
	t.Start(background)
	// Nothing to poll in file-only operation. Starting the poller would log a
	// failure every 15 seconds against a control plane the operator chose not to
	// run, and count each one in policy_errors_total.
	if c.ControlURL != "" {
		go s.Sync(background)
	} else {
		slog.Info("file-only policy; no control plane configured",
			"policy", p.Path, "expires_at", "rotate by replacing this file")
	}
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
		fatal("listener failed")
		stop()
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

// printPublicKey derives the pinnable half of a signing seed. The seed is read
// from stdin rather than taken as an argument so it does not land in the process
// table or a shell history file.
func printPublicKey(in io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(in, 4096))
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("seed is not valid base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed is %d bytes; an ed25519 seed is %d", len(seed), ed25519.SeedSize)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	_, err = fmt.Fprintln(out, base64.StdEncoding.EncodeToString(pub))
	return err
}
