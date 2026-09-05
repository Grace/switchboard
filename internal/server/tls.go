package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLS configures the listener's own transport security.
//
// Terminating TLS elsewhere — an ingress, a service mesh, a load balancer — is
// a perfectly good answer and remains the default. It stops being a good answer
// the moment the gateway is reached directly, which is most non-Kubernetes
// deployments and every laptop, and "assume something in front of it" is not
// something a security review accepts on trust.
type TLS struct {
	CertFile string
	KeyFile  string
	// ClientCAFile turns on mutual TLS: a caller must present a certificate
	// signed by this authority. It is authentication at the transport, which
	// composes with rather than replaces team keys and OIDC — a client
	// certificate says which machine, a token says which person.
	ClientCAFile string
}

// Enabled reports whether a certificate was configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// MutualTLS reports whether callers must present a certificate.
func (t TLS) MutualTLS() bool { return t.ClientCAFile != "" }

// config builds the tls.Config, refusing anything half-specified.
func (t TLS) config() (*tls.Config, error) {
	if !t.Enabled() {
		return nil, nil
	}
	if t.CertFile == "" || t.KeyFile == "" {
		return nil, fmt.Errorf("tls needs both cert_file and key_file")
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 1.2 is the floor every current client meets and every current
		// benchmark requires. Go picks the suites; its defaults for 1.3 are
		// the ones you would choose anyway.
		MinVersion: tls.VersionTLS12,
	}

	if t.ClientCAFile != "" {
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("loading the client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no usable certificates", t.ClientCAFile)
		}
		cfg.ClientCAs = pool
		// Require and verify: RequireAnyClientCert would accept a self-signed
		// certificate from anyone, which is worse than not asking.
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
