package vault

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// Recovery is deliberately in its own file, and deliberately not reachable from
// anything the server runs. The gateway is never handed a private key; this
// path exists for an operator holding one, out of band, during an incident.

// LoadPrivateKey reads a PEM private key for recovery.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("%s is a public key. Recovery needs the private "+
			"half, which the gateway is never given — it is held by whoever "+
			"handles incidents", path)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an RSA private key, got %T", path, parsed)
	}
	return key, nil
}

// Recovered is one value returned to an investigator.
type Recovered struct {
	Token string
	Rule  string
	Value string
}

// Recover opens a vault and decrypts the entries matching tokens.
//
// Passing no tokens recovers everything, which is occasionally what an
// investigation needs and always worth being deliberate about.
func Recover(path string, priv *rsa.PrivateKey, tokens ...string) ([]Recovered, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	want := map[string]bool{}
	for _, t := range tokens {
		want[t] = true
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var out []Recovered
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		if len(want) > 0 && !want[e.Token] {
			continue
		}
		value, err := open(e, priv)
		if err != nil {
			return nil, fmt.Errorf("token %s: %w", e.Token, err)
		}
		out = append(out, Recovered{Token: e.Token, Rule: e.Rule, Value: value})
	}
	return out, sc.Err()
}

func open(e Entry, priv *rsa.PrivateKey) (string, error) {
	wrapped, err := base64.StdEncoding.DecodeString(e.Key)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return "", err
	}
	sealed, err := base64.StdEncoding.DecodeString(e.Cipher)
	if err != nil {
		return "", err
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, wrapped, []byte(e.Rule))
	if err != nil {
		return "", fmt.Errorf("unwrapping the key failed: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, sealed, []byte(e.Token))
	if err != nil {
		return "", fmt.Errorf("entry does not authenticate: %w", err)
	}
	return string(plain), nil
}
