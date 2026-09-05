// Package vanta delivers an evidence package to a Vanta document.
//
// This needs no partnership, no marketplace listing and no conversation with
// Vanta. A customer with a Vanta plan that includes API access mints a token
// against their own account and hands it to the tool; the upload lands on a
// document in their programme, is recorded in their Vanta audit log, and their
// auditor pulls the file from Vanta directly.
//
// Two API calls, both documented:
//
//	POST /v1/documents/{id}/uploads   multipart/form-data
//	POST /v1/documents/{id}/submit
//
// Required token scopes: vanta-api.all:read, vanta-api.all:write,
// vanta-api.documents:upload.
//
// The token comes from the environment and never from a flag. A flag lands in
// shell history and in the process table, and a credential that grants write
// access to a compliance programme is not one to leave there.
package vanta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/push"
)

// Credentials come from the environment. Two forms are accepted because Vanta
// supports two workflows and they suit different callers.
//
// TokenEnv is an access token minted by hand. Vanta's expire after one hour,
// so this is for a one-off run — a person packaging a quarter and uploading it
// once.
//
// ClientIDEnv and ClientSecretEnv are an OAuth application's client_credentials,
// which the tool exchanges for a short-lived token itself. This is the form to
// use on a schedule, because nothing has to be re-pasted every hour.
//
// One gotcha worth knowing before you automate: Vanta allows only one active
// access token per application, and requesting a new one immediately revokes
// the previous. Two schedulers sharing an application will revoke each other.
// Mint one application per caller.
const (
	TokenEnv        = "VANTA_API_TOKEN"
	ClientIDEnv     = "VANTA_CLIENT_ID"
	ClientSecretEnv = "VANTA_CLIENT_SECRET"
)

// tokenPath is the OAuth endpoint. Verify against Vanta's current developer
// docs before relying on the default — this is the detail most likely to have
// moved, and it is why the manual-token path exists as a fallback.
var tokenPath = "/oauth/token"

// DefaultBase is Vanta's API host. Overridable for testing and for any
// customer on a non-default region.
const DefaultBase = "https://api.vanta.com"

// Target uploads to one Vanta document.
type Target struct {
	// DocumentID is the Vanta document this evidence belongs against. The
	// customer creates it; the tool does not invent documents in somebody
	// else's compliance programme.
	DocumentID string
	// Base overrides the API host.
	Base string
	// Submit sends the document for review after upload. Off by default: a
	// tool that silently advances a control's status in a compliance
	// programme is doing something the operator should have asked for.
	Submit bool
	// HTTP is injectable for tests.
	HTTP *http.Client
	// Token overrides the environment, for tests only.
	Token string
}

func (t *Target) Name() string { return "vanta" }

// token returns a usable access token, exchanging client credentials when that
// is what was supplied. The result is cached for the life of the Target so one
// run does not mint two tokens and revoke its own.
func (t *Target) token(ctx context.Context) (string, error) {
	if t.Token != "" {
		return t.Token, nil
	}
	if v := os.Getenv(TokenEnv); v != "" {
		t.Token = v
		return v, nil
	}
	id, secret := os.Getenv(ClientIDEnv), os.Getenv(ClientSecretEnv)
	if id == "" || secret == "" {
		return "", t.credentialError()
	}
	tok, err := t.exchange(ctx, id, secret)
	if err != nil {
		return "", err
	}
	t.Token = tok
	return tok, nil
}

// staticToken is what scrub uses; it must never trigger an exchange.
func (t *Target) staticToken() string {
	if t.Token != "" {
		return t.Token
	}
	return os.Getenv(TokenEnv)
}

func (t *Target) credentialError() error {
	return fmt.Errorf("vanta: no credentials. Either export %s with a token minted in "+
		"Settings -> Developer Console (Vanta's expire after an hour, so this suits a "+
		"one-off run), or export %s and %s from a \"Manage Vanta\" application and the "+
		"tool will exchange them itself. Neither is accepted as a flag",
		TokenEnv, ClientIDEnv, ClientSecretEnv)
}

// exchange performs the client_credentials grant.
func (t *Target) exchange(ctx context.Context, id, secret string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {id},
		"client_secret": {secret},
		"scope":         {"vanta-api.all:read vanta-api.all:write vanta-api.documents:upload"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base()+tokenPath,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("vanta: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("vanta: token exchange failed with %s. Confirm the OAuth "+
			"endpoint and the application's scopes against developer.vanta.com; if it has "+
			"moved, mint a token by hand and export %s instead", resp.Status, TokenEnv)
	}
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.AccessToken == "" {
		return "", fmt.Errorf("vanta: token exchange returned no access_token")
	}
	return v.AccessToken, nil
}

func (t *Target) base() string {
	if t.Base != "" {
		return strings.TrimRight(t.Base, "/")
	}
	return DefaultBase
}

func (t *Target) client() *http.Client {
	if t.HTTP != nil {
		return t.HTTP
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// Check reports whether this target can be used, before anything is built.
func (t *Target) Check() error {
	if t.DocumentID == "" {
		return fmt.Errorf("vanta: -document is required (the Vanta document id this evidence belongs against)")
	}
	// Check must not perform an exchange — it runs before anything is built,
	// and minting a token would revoke whatever the caller already had.
	if t.Token == "" && os.Getenv(TokenEnv) == "" &&
		(os.Getenv(ClientIDEnv) == "" || os.Getenv(ClientSecretEnv) == "") {
		return t.credentialError()
	}
	return nil
}

// Send uploads the archive and optionally submits the document.
func (t *Target) Send(ctx context.Context, a push.Archive) (string, error) {
	if err := t.Check(); err != nil {
		return "", err
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	w, err := mw.CreateFormFile("file", a.Filename)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(a.Body); err != nil {
		return "", err
	}
	// The digest travels beside the file so it is legible in Vanta's own UI
	// without unzipping anything, and so it appears in their audit log entry.
	_ = mw.WriteField("description", fmt.Sprintf(
		"switchboard evidence · period %s · manifest sha256 %s", a.Period, a.Digest))
	if err := mw.Close(); err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/v1/documents/%s/uploads", t.base(), t.DocumentID)
	if err := t.do(ctx, url, mw.FormDataContentType(), body.Bytes()); err != nil {
		return "", err
	}

	receipt := fmt.Sprintf("uploaded %s to Vanta document %s\n  digest  %s",
		a.Filename, t.DocumentID, a.Digest)

	if t.Submit {
		url := fmt.Sprintf("%s/v1/documents/%s/submit", t.base(), t.DocumentID)
		if err := t.do(ctx, url, "application/json", []byte(`{}`)); err != nil {
			return receipt, fmt.Errorf("uploaded, but submit failed: %w", err)
		}
		receipt += "\n  submitted for review"
	} else {
		receipt += "\n  not submitted for review — pass -submit if that is what you want"
	}

	// Worth saying every time. The upload is a third party's dated record that
	// this digest existed, which is a real gain over an unanchored package —
	// and it is not a transparency log, so it should not be described as one.
	receipt += "\n\nVanta now holds a timestamped record of this digest in an audit log you\n" +
		"do not control. That is weaker than a transparency log and stronger than\n" +
		"nothing: it is a third party attesting the package existed on this date."
	return receipt, nil
}

func (t *Target) do(ctx context.Context, endpoint, contentType string, body []byte) error {
	tok, err := t.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	resp, err := t.client().Do(req)
	if err != nil {
		return fmt.Errorf("vanta: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Read a bounded amount: an error page is not a reason to buffer a
	// megabyte, and the token must never appear in what we print back.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(snippet))
	if m := apiMessage(snippet); m != "" {
		msg = m
	}
	// Never repeat the credential, whatever the far end sent back. An API that
	// reflects a token in an error is not hypothetical, and the tool printing
	// it would put a compliance-programme write credential into a terminal
	// scrollback and probably a CI log.
	msg = t.scrub(msg)
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("vanta: %s — check the token's scopes include "+
			"vanta-api.documents:upload, and that your plan includes API access", resp.Status)
	case http.StatusNotFound:
		return fmt.Errorf("vanta: document %s not found. Create the document in Vanta "+
			"first; this tool does not create documents in your compliance programme", t.DocumentID)
	default:
		return fmt.Errorf("vanta: %s: %s", resp.Status, msg)
	}
}

// scrub removes the credential from anything about to be printed.
func (t *Target) scrub(s string) string {
	tok := t.staticToken()
	if tok == "" {
		return s
	}
	return strings.ReplaceAll(s, tok, "[redacted]")
}

// apiMessage pulls a message out of a JSON error body when there is one.
func apiMessage(b []byte) string {
	var v struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	if v.Message != "" {
		return v.Message
	}
	return v.Error
}
