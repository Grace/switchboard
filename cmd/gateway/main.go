package main

import (
	"context"
	"flag"
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
	flag.Parse()
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
	m := &gateway.Metrics{LogDropped: &logs.Dropped}
	t, e := gateway.NewTelemetry(c, m)
	if e != nil {
		slog.Error("telemetry initialization failed")
		os.Exit(1)
	}
	background, stop := context.WithCancel(context.Background())
	s := gateway.New(c, p, m, t)
	t.Start(background)
	go s.Sync(background)
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
