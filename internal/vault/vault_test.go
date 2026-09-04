package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keyPair(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	pubDER, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pubPath := filepath.Join(dir, "pub.pem")
	os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)

	privPath := filepath.Join(dir, "priv.pem")
	os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}), 0o600)

	return k, pubPath, privPath
}

// The whole point: a value is recoverable with the private key, and the file
// contains nothing readable without it.
func TestSealAndRecover(t *testing.T) {
	_, pubPath, privPath := keyPair(t)
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.jsonl")

	w, err := Open(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Seal("tok1", "email", "attacker@evil.com"); err != nil {
		t.Fatal(err)
	}
	if err := w.Seal("tok2", "credit_card", "4111111111111111"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	raw, _ := os.ReadFile(path)
	for _, secret := range []string{"attacker@evil.com", "4111111111111111"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("plaintext reached the vault file: %s", raw)
		}
	}

	priv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Recover(path, priv, "tok1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != "attacker@evil.com" || got[0].Rule != "email" {
		t.Fatalf("recovered = %+v", got)
	}

	all, err := Recover(path, priv)
	if err != nil || len(all) != 2 {
		t.Fatalf("recovering everything = %+v, %v", all, err)
	}
}

// Giving the gateway a private key is the mistake this design exists to
// prevent, so it fails at startup rather than quietly working.
func TestPrivateKeyIsRefusedAsThePublicKey(t *testing.T) {
	_, _, privPath := keyPair(t)
	_, err := LoadPublicKey(privPath)
	if err == nil {
		t.Fatal("a private key must not be accepted as the gateway's key")
	}
	if !strings.Contains(err.Error(), "public half") {
		t.Errorf("the error should explain why, got %v", err)
	}
}

func TestWrongKeyCannotRecover(t *testing.T) {
	_, pubPath, _ := keyPair(t)
	other, _, otherPriv := keyPair(t)
	_ = other

	pub, _ := LoadPublicKey(pubPath)
	path := filepath.Join(t.TempDir(), "v.jsonl")
	w, _ := Open(path, pub)
	w.Seal("tok", "email", "secret@example.com")
	w.Close()

	priv, _ := LoadPrivateKey(otherPriv)
	if _, err := Recover(path, priv, "tok"); err == nil {
		t.Fatal("the wrong private key must not decrypt")
	}
}

// An entry relabelled to point at a different token must not open: the token
// is authenticated alongside the value.
func TestRelabelledEntryDoesNotAuthenticate(t *testing.T) {
	_, pubPath, privPath := keyPair(t)
	pub, _ := LoadPublicKey(pubPath)
	path := filepath.Join(t.TempDir(), "v.jsonl")

	w, _ := Open(path, pub)
	w.Seal("real-token", "email", "a@b.com")
	w.Close()

	raw, _ := os.ReadFile(path)
	var e Entry
	json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &e)
	e.Token = "someone-elses-token"
	edited, _ := json.Marshal(e)
	os.WriteFile(path, append(edited, '\n'), 0o600)

	priv, _ := LoadPrivateKey(privPath)
	if _, err := Recover(path, priv, "someone-elses-token"); err == nil {
		t.Fatal("a relabelled entry must not authenticate")
	}
}

// The same value appearing a thousand times is one entry: the token already
// says it recurred.
func TestRepeatsAreSealedOnce(t *testing.T) {
	_, pubPath, _ := keyPair(t)
	pub, _ := LoadPublicKey(pubPath)
	path := filepath.Join(t.TempDir(), "v.jsonl")

	w, _ := Open(path, pub)
	for i := 0; i < 50; i++ {
		w.Seal("tok", "email", "a@b.com")
	}
	w.Close()

	raw, _ := os.ReadFile(path)
	if n := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; n != 1 {
		t.Errorf("wrote %d entries for one value, want 1", n)
	}
}

func TestNilWriterAndEmptyValuesAreSafe(t *testing.T) {
	var w *Writer
	if err := w.Seal("t", "r", "v"); err != nil {
		t.Errorf("nil writer should be a no-op, got %v", err)
	}
	if err := w.Close(); err != nil {
		t.Error(err)
	}

	_, pubPath, _ := keyPair(t)
	pub, _ := LoadPublicKey(pubPath)
	real, _ := Open(filepath.Join(t.TempDir(), "v.jsonl"), pub)
	defer real.Close()
	if err := real.Seal("", "email", ""); err != nil {
		t.Errorf("empty token or value should be skipped, got %v", err)
	}
}

func TestSmallKeysAreRefused(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p := filepath.Join(t.TempDir(), "small.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)

	if _, err := LoadPublicKey(p); err == nil {
		t.Fatal("a 1024-bit key must be refused")
	}
}
