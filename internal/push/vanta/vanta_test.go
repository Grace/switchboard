package vanta

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Grace/switchboard/internal/push"
)

func archive() push.Archive {
	return push.Archive{
		Filename: "evidence-2026-09.zip",
		Body:     []byte("PK\x03\x04 not really a zip"),
		Digest:   "fdb0df639a6be5a406e76bfdd298c7ea4ca85ae9a44e882d774d7c8f39c48aac",
		Period:   "2026-09",
	}
}

// A credential that grants write access to a compliance programme must not be
// accepted anywhere it would land in shell history or the process table.
func TestCredentialsComeFromTheEnvironmentOnly(t *testing.T) {
	clearCreds(t)
	tgt := &Target{DocumentID: "doc-1"}
	err := tgt.Check()
	if err == nil || !strings.Contains(err.Error(), "accepted as a flag") {
		t.Fatalf("want an environment-only error, got %v", err)
	}

	t.Setenv(TokenEnv, "tok")
	if err := tgt.Check(); err != nil {
		t.Fatalf("a minted token should pass: %v", err)
	}
}

// Both credential forms are accepted, because they suit different callers: a
// pasted token for a one-off, client credentials for a schedule.
func TestClientCredentialsAlsoPassCheck(t *testing.T) {
	clearCreds(t)
	t.Setenv(ClientIDEnv, "id")
	t.Setenv(ClientSecretEnv, "secret")
	if err := (&Target{DocumentID: "d"}).Check(); err != nil {
		t.Fatalf("client credentials should pass Check: %v", err)
	}
}

// Check runs before the package is built. It must not mint a token, because
// Vanta revokes the previous one when you do — a preflight that silently
// invalidated the caller's existing token would be worse than no preflight.
func TestCheckDoesNotExchange(t *testing.T) {
	clearCreds(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv(ClientIDEnv, "id")
	t.Setenv(ClientSecretEnv, "secret")

	tgt := &Target{DocumentID: "d", Base: srv.URL, HTTP: srv.Client()}
	if err := tgt.Check(); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Errorf("Check made %d network calls; it should make none", hits)
	}
}

func TestExchangeIsCachedForTheRun(t *testing.T) {
	clearCreds(t)
	var exchanges int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			exchanges++
			_, _ = w.Write([]byte(`{"access_token":"minted"}`))
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer minted" {
			t.Errorf("auth = %q, want the exchanged token", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv(ClientIDEnv, "id")
	t.Setenv(ClientSecretEnv, "secret")

	tgt := &Target{DocumentID: "d", Base: srv.URL, HTTP: srv.Client(), Submit: true}
	if _, err := tgt.Send(context.Background(), archive()); err != nil {
		t.Fatal(err)
	}
	// Upload and submit are two calls; one token between them.
	if exchanges != 1 {
		t.Errorf("minted %d tokens for one run; Vanta revokes the previous each time", exchanges)
	}
}

func clearCreds(t *testing.T) {
	t.Helper()
	for _, k := range []string{TokenEnv, ClientIDEnv, ClientSecretEnv} {
		t.Setenv(k, "")
	}
}

func TestRequiresADocument(t *testing.T) {
	clearCreds(t)
	t.Setenv(TokenEnv, "tok")
	if err := (&Target{}).Check(); err == nil {
		t.Fatal("a document id is required")
	}
}

func TestUploadPostsMultipartAndBearer(t *testing.T) {
	var gotAuth, gotPath, gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotPath, gotType, gotBody = r.Header.Get("Authorization"), r.URL.Path, r.Header.Get("Content-Type"), string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tgt := &Target{DocumentID: "doc-1", Base: srv.URL, Token: "tok", HTTP: srv.Client()}
	receipt, err := tgt.Send(context.Background(), archive())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/v1/documents/doc-1/uploads" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.HasPrefix(gotType, "multipart/form-data") {
		t.Errorf("content-type = %q", gotType)
	}
	// The digest must travel beside the file so it is legible without unzipping.
	if !strings.Contains(gotBody, archive().Digest) {
		t.Error("the manifest digest should be sent in the description field")
	}
	if !strings.Contains(receipt, archive().Digest) {
		t.Error("the receipt should repeat the digest")
	}
}

// Advancing a control's status in someone's compliance programme is not a
// side effect; it has to be asked for.
func TestSubmitIsOptIn(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tgt := &Target{DocumentID: "d", Base: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, err := tgt.Send(context.Background(), archive()); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("without -submit only the upload should happen, got %v", paths)
	}

	paths = nil
	tgt.Submit = true
	if _, err := tgt.Send(context.Background(), archive()); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || !strings.HasSuffix(paths[1], "/submit") {
		t.Errorf("with -submit both calls should happen, got %v", paths)
	}
}

func TestErrorsAreActionable(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, "vanta-api.documents:upload"},
		{http.StatusForbidden, "plan includes API access"},
		{http.StatusNotFound, "does not create documents"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
		}))
		tgt := &Target{DocumentID: "d", Base: srv.URL, Token: "t", HTTP: srv.Client()}
		_, err := tgt.Send(context.Background(), archive())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d: want guidance containing %q, got %v", c.code, c.want, err)
		}
	}
}

// A failing token must never be echoed back in an error.
func TestTokenNeverAppearsInErrors(t *testing.T) {
	const secret = "super-secret-token-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// A hostile or careless API echoing the credential back must not
		// result in the tool printing it.
		_, _ = w.Write([]byte(`{"message":"bad request for token ` + secret + `"}`))
	}))
	defer srv.Close()

	tgt := &Target{DocumentID: "d", Base: srv.URL, Token: secret, HTTP: srv.Client()}
	_, err := tgt.Send(context.Background(), archive())
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the token leaked into the error: %v", err)
	}
}
