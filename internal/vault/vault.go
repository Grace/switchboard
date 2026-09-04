// Package vault stores redacted values encrypted to a key this process does
// not have.
//
// Redaction exists so sensitive values are not written down. An investigation
// eventually wants some of them back — the address an injected instruction was
// exfiltrating to is the most incriminating token in the whole attack, and it
// is exactly what the email rule removes.
//
// The obvious resolution, a store the gateway can read, gives back the exposure
// redaction removed and attaches a lookup API to it. This does the other thing:
// the gateway is given only a public key, so it can write and cannot read. Not
// "does not expose an endpoint" — it does not hold the capability. Recovery
// needs the private half, which lives with whoever handles incidents and never
// on the gateway.
//
// Each value is sealed under its own AES-256-GCM key, and that key is wrapped
// with RSA-OAEP. Public-key operations happen once per newly seen value, not
// per request, so a busy gateway is not doing asymmetric crypto in a loop.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one sealed value. Nothing here is readable without the private key.
type Entry struct {
	Token string    `json:"token"`
	Rule  string    `json:"rule"`
	Time  time.Time `json:"time"`

	// Key is the AES key for this entry, wrapped with RSA-OAEP.
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`
	Cipher string `json:"cipher"`
}

// Writer seals values to a public key.
type Writer struct {
	pub *rsa.PublicKey

	mu   sync.Mutex
	w    io.WriteCloser
	enc  *json.Encoder
	seen map[string]struct{}
}

// seenCap bounds the dedupe set. Exceeding it costs a repeated entry for a
// value, never a missing one, so the failure mode is a slightly larger file.
const seenCap = 50000

// LoadPublicKey reads a PEM public key. It refuses a private key: handing the
// gateway a private key is the mistake this design exists to make impossible,
// and it should fail at startup rather than quietly work.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY":
		return nil, fmt.Errorf("%s contains a private key: the gateway must be "+
			"given only the public half, or it can read back what it sealed", path)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if pkcs1, err1 := x509.ParsePKCS1PublicKey(block.Bytes); err1 == nil {
			key = pkcs1
		} else {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an RSA public key, got %T", path, key)
	}
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%s: %d-bit key is too small", path, pub.N.BitLen())
	}
	return pub, nil
}

// Open creates or appends to a vault file.
func Open(path string, pub *rsa.PublicKey) (*Writer, error) {
	if pub == nil {
		return nil, fmt.Errorf("vault needs a public key")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{pub: pub, w: f, enc: json.NewEncoder(f), seen: map[string]struct{}{}}, nil
}

// Seal writes one value under its token, once.
//
// Repeats are skipped: the token already tells an investigator the value
// recurred, and re-sealing it would only grow the file.
func (w *Writer) Seal(token, rule, value string) error {
	if w == nil || token == "" || value == "" {
		return nil
	}
	w.mu.Lock()
	if _, done := w.seen[token]; done {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// The token is authenticated alongside the value, so an entry cannot be
	// relabelled to point at a different token without detection.
	sealed := gcm.Seal(nil, nonce, []byte(value), []byte(token))

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, w.pub, dek, []byte(rule))
	if err != nil {
		return err
	}

	entry := Entry{
		Token: token, Rule: rule, Time: time.Now().UTC(),
		Key:    base64.StdEncoding.EncodeToString(wrapped),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Cipher: base64.StdEncoding.EncodeToString(sealed),
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(entry); err != nil {
		return err
	}
	if len(w.seen) >= seenCap {
		w.seen = map[string]struct{}{}
	}
	w.seen[token] = struct{}{}
	return nil
}

func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Close()
}
