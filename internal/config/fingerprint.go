package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// A record of what happened, without a record of the rules it happened under,
// cannot answer the question a security audit actually asks: was this allowed
// under the policy in force at the time?
//
// The fingerprint is a digest of the decision-affecting configuration. It goes
// on every audit entry, so a reader can tell which entries were made under
// which policy, and see that policy changed in the middle of a window they were
// looking at.
//
// Deliberately not a hash of the whole file. A changed listen address or log
// path is not a policy change, and a fingerprint that moves for those reasons
// trains people to ignore it. The fields below are exactly those that alter
// what the gateway will allow, redact, attribute or refuse — which means adding
// a field here is a decision to make, not a mechanical step.

type policyView struct {
	Profile     Profile     `json:"profile"`
	Models      []Line      `json:"models"`
	Default     string      `json:"default_model"`
	Attribution Attribution `json:"attribution"`
	Teams       []teamView  `json:"teams"`
	OIDC        OIDC        `json:"oidc"`
	Redaction   Redaction   `json:"redaction"`
	Audit       auditView   `json:"audit"`
	Vault       vaultView   `json:"vault"`
	Limits      Limits      `json:"limits"`
	MutualTLS   bool        `json:"mutual_tls"`
}

// teamView omits the keys themselves. A rotated key is not a policy change, and
// a fingerprint is not a place to put a digest of a secret.
type teamView struct {
	Name   string     `json:"name"`
	Keys   int        `json:"key_count"`
	Limits TeamLimits `json:"limits"`
}

// auditView omits paths: where the log is written does not change what is
// recorded, and moving it should not read as a policy change.
type auditView struct {
	Enabled        bool     `json:"enabled"`
	LogContent     bool     `json:"log_content"`
	Required       bool     `json:"required"`
	Retention      Duration `json:"retention"`
	MaxBytes       int64    `json:"max_bytes"`
	VerifyInterval Duration `json:"verify_interval"`
	Archived       bool     `json:"archived"`
}

// vaultView records that sealing is on, not where the key lives.
type vaultView struct {
	Enabled bool `json:"enabled"`
}

// PolicyFingerprint returns a short digest of the decision-affecting config.
func (c *Config) PolicyFingerprint() string {
	_, fp := c.PolicyDocument()
	return fp
}

// PolicyDocument returns the exact bytes the fingerprint is taken over, and
// that fingerprint.
//
// A digest on every entry says *that* the rules changed. It cannot say what
// they were, and an entry naming a policy nobody kept is a citation to a
// missing document. Handing out the bytes lets them be archived beside the log,
// so a decision questioned six months later can be read against the rules that
// produced it.
//
// The bytes are returned verbatim rather than re-marshalled anywhere else,
// because their whole value is that they hash to the fingerprint: an archived
// document can be checked against the entries citing it, by anyone, without
// trusting whoever stored it. Filtering a field here to make the output
// prettier would silently break that.
//
// Nothing here is a secret. Team keys are reduced to a count, the vault is
// reduced to a boolean, log paths are omitted, and OIDC carries no client
// secret — so this can go to an auditor as it stands. The one field to watch is
// a local model's Args, which is passed to llama-server unread; do not put a
// credential there.
func (c *Config) PolicyDocument() ([]byte, string) {
	teams := make([]teamView, 0, len(c.Teams))
	for _, t := range c.Teams {
		teams = append(teams, teamView{Name: t.Name, Keys: len(t.Keys), Limits: t.Limits})
	}

	v := policyView{
		Profile:     c.Profile,
		Models:      c.Models,
		Default:     c.DefaultModel,
		Attribution: c.Attribution,
		Teams:       teams,
		OIDC:        c.OIDC,
		Redaction:   c.Redaction,
		Audit: auditView{
			Enabled:        c.Audit.Enabled,
			LogContent:     c.Audit.LogContent,
			Required:       c.Audit.Required,
			Retention:      c.Audit.Retention,
			MaxBytes:       c.Audit.MaxBytes,
			VerifyInterval: c.Audit.VerifyInterval,
			Archived:       c.Audit.ArchiveCommand != "",
		},
		Vault:     vaultView{Enabled: c.Vault.Enabled},
		Limits:    c.Limits,
		MutualTLS: c.TLS.ClientCAFile != "",
	}

	// Go marshals struct fields in declaration order and map keys sorted, so
	// this is stable across processes and versions.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ""
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:6])
}

// VerifyPolicyDocument reports whether stored bytes are the document the
// fingerprint names.
//
// This is the property that makes an archived policy evidence rather than a
// claim: the digest is recomputed from the bytes, so a document that was edited
// after the fact no longer matches the entries citing it.
func VerifyPolicyDocument(doc []byte, fingerprint string) bool {
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:6]) == fingerprint
}
