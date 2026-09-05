package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

	if lim := cfg.Limiter(); lim != nil {
		srv = srv.WithLimits(lim)
		d := cfg.Limits.Default
		logger.Printf("limits: %d req/min, %d concurrent, %d tokens per %s (per team)",
			d.RequestsPerMinute, d.Concurrent, d.TokensPerWindow, time.Duration(cfg.Limits.Window))
	}

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
		lg = lg.WithRotation(audit.Rotation{
			MaxBytes:       cfg.Audit.MaxBytes,
			Retention:      time.Duration(cfg.Audit.Retention),
			ArchiveCommand: cfg.Audit.ArchiveCommand,
		})
		defer lg.Close()

		switch {
		case cfg.Audit.MaxBytes == 0:
			logger.Printf("warning: audit.max_bytes is unset, so %s will grow without "+
				"bound. Set it, with audit.archive_command to ship segments off this "+
				"host, or plan for the disk", cfg.Audit.Path)
		case cfg.Audit.ArchiveCommand == "":
			logger.Printf("note: no audit.archive_command, so this host is the archive. " +
				"Retention here deletes evidence rather than draining a buffer")
		}
		if !cfg.Audit.Required {
			logger.Printf("note: audit.required is off — a completion whose entry " +
				"cannot be written will still be served. Turn it on where the record is the point")
		}
		if r := time.Duration(cfg.Audit.Retention); r > 0 && r < config.Art26Minimum {
			logger.Printf("warning: audit.retention is %s. EU AI Act Article 26 asks "+
				"deployers of high-risk systems to keep logs at least six months; "+
				"check what applies to you before shortening it further", r)
		}

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
		srv = srv.WithAudit(lg, cfg.Audit.Required)
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
