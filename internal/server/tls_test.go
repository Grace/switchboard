package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certFor writes a certificate and key, signed by parent (or self-signed when
// parent is nil), and returns their paths plus the parsed certificate.
func certFor(t *testing.T, dir, name string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)

	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certPath, keyPath, cert, key
}

func TestTLSConfigRequiresBothFiles(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, _ := certFor(t, dir, "server", true, nil, nil)

	if _, err := (TLS{CertFile: cert}).config(); err == nil {
		t.Error("a certificate without a key must be refused")
	}
	if _, err := (TLS{KeyFile: key}).config(); err == nil {
		t.Error("a key without a certificate must be refused")
	}
	if cfg, err := (TLS{CertFile: cert, KeyFile: key}).config(); err != nil || cfg == nil {
		t.Errorf("a complete pair should build: %v", err)
	}
}

func TestDisabledTLSProducesNoConfig(t *testing.T) {
	cfg, err := (TLS{}).config()
	if err != nil || cfg != nil {
		t.Errorf("no TLS configured should be nil, nil; got %v, %v", cfg, err)
	}
}

func TestFloorIsTLS12(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, _ := certFor(t, dir, "server", true, nil, nil)
	cfg, err := (TLS{CertFile: cert, KeyFile: key}).config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
}

// Mutual TLS must verify, not merely require. RequireAnyClientCert would accept
// a self-signed certificate from anyone, which is worse than not asking.
func TestMutualTLSVerifiesAgainstTheCA(t *testing.T) {
	dir := t.TempDir()
	caCert, _, ca, caKey := certFor(t, dir, "ca", true, nil, nil)
	srvCert, srvKey, _, _ := certFor(t, dir, "server", false, ca, caKey)

	cfg, err := (TLS{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: caCert}).config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("client CAs were not loaded")
	}
	_ = srvKey
}

func TestBadClientCAIsRefused(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, _ := certFor(t, dir, "server", true, nil, nil)

	junk := filepath.Join(dir, "junk.pem")
	os.WriteFile(junk, []byte("not a certificate"), 0o644)

	_, err := (TLS{CertFile: cert, KeyFile: key, ClientCAFile: junk}).config()
	if err == nil {
		t.Fatal("a CA file with no certificates must be refused")
	}
	if !strings.Contains(err.Error(), "no usable certificates") {
		t.Errorf("error should say what was wrong: %v", err)
	}

	if _, err := (TLS{CertFile: cert, KeyFile: key, ClientCAFile: filepath.Join(dir, "absent.pem")}).config(); err == nil {
		t.Error("a missing CA file must be refused")
	}
}

func TestEnabledAndMutualReporting(t *testing.T) {
	if (TLS{}).Enabled() {
		t.Error("empty TLS should not report enabled")
	}
	if !(TLS{CertFile: "c", KeyFile: "k"}).Enabled() {
		t.Error("a configured pair should report enabled")
	}
	if (TLS{CertFile: "c", KeyFile: "k"}).MutualTLS() {
		t.Error("no client CA is not mutual TLS")
	}
	if !(TLS{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}).MutualTLS() {
		t.Error("a client CA is mutual TLS")
	}
}
