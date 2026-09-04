package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Grace/switchboard/internal/audit"
	"github.com/Grace/switchboard/internal/config"
	"github.com/Grace/switchboard/internal/server"
	"github.com/Grace/switchboard/internal/vault"
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

	if cfg.OIDC.Enabled {
		v, err := cfg.OIDC.Build()
		if err != nil {
			return fmt.Errorf("oidc: %w", err)
		}
		srv = srv.WithOIDC(v)
		logger.Printf("oidc: trusting %s (audience %q, team claim %q)",
			cfg.OIDC.Issuer, cfg.OIDC.Audience, teamClaimOr(cfg.OIDC.TeamClaim))
	}

	if cfg.Audit.Enabled {
		red, err := cfg.Redaction.Build()
		if err != nil {
			return fmt.Errorf("redaction: %w", err)
		}
		if cfg.Vault.Enabled {
			// Tokens are what a sealed value is recovered by, so they are the
			// prerequisite rather than an option alongside.
			red = red.WithTokens(audit.KeyFromEnv())
		}

		lg, err := audit.Open(config.ExpandPath(cfg.Audit.Path), red, cfg.Audit.LogContent)
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		defer lg.Close()

		if cfg.Vault.Enabled {
			pub, err := vault.LoadPublicKey(config.ExpandPath(cfg.Vault.PublicKey))
			if err != nil {
				return fmt.Errorf("vault: %w", err)
			}
			vw, err := vault.Open(config.ExpandPath(cfg.Vault.Path), pub)
			if err != nil {
				return fmt.Errorf("vault: %w", err)
			}
			defer vw.Close()
			lg = lg.WithVault(vw)
			logger.Printf("vault: sealing redacted values to %s (this process cannot read them back)",
				cfg.Vault.PublicKey)
		}

		what := "metadata only"
		if cfg.Audit.LogContent {
			what = "redacted content"
		}
		// "auditing" and "auditing in a way that survives someone editing the
		// file" are different claims, so the operator is told which they have.
		chain := "unsigned, set " + audit.KeyEnv + " to sign"
		if lg.Signed() {
			chain = "signed"
		}
		logger.Printf("audit log: %s (%s; %s; rules: %s)",
			cfg.Audit.Path, what, chain, strings.Join(red.Rules(), ", "))
		srv = srv.WithAudit(lg)
	}

	if err := srv.ListenAndServe(ctx, cfg.Listen); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	logger.Printf("shut down")
	return nil
}

func teamClaimOr(s string) string {
	if s == "" {
		return "groups"
	}
	return s
}
