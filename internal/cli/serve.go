package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Grace/switchboard/internal/server"
)

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := configFlag(fs)
	listen := fs.String("listen", "", "address to bind (overrides config)")
	if err := parse(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath, os.Stderr)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	reg := buildRegistry(cfg)
	// Models outlive requests, so unloading is tied to server shutdown rather
	// than to any one caller hanging up.
	defer reg.Close()

	logger := log.New(os.Stderr, "switchboard: ", log.LstdFlags)
	models := reg.Models(ctx)
	logger.Printf("serving %d model(s) on http://%s", len(models), cfg.Listen)
	for _, m := range models {
		logger.Printf("  %-24s %s", m.Name, m.Backend)
	}
	if len(models) == 0 {
		logger.Printf("  (no models configured — see 'switchboard init')")
	}

	srv := server.New(reg, logger).WithAttribution(cfg.Teams, cfg.Attribution.RequireCaller)
	if err := srv.ListenAndServe(ctx, cfg.Listen); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	logger.Printf("shut down")
	return nil
}
