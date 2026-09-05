package config

import (
	"fmt"
	"os"
	"strings"
)

// TLS configures the listener's own transport security.
//
// Terminating TLS at an ingress is a good answer and stays the default. It
// stops being one when the gateway is reached directly, which is most
// non-Kubernetes deployments — and "assume something is in front of it" is not
// an assumption a security review takes on trust.
type TLS struct {
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// ClientCAFile requires callers to present a certificate signed by this
	// authority. A certificate says which machine; a token says which person.
	// They compose.
	ClientCAFile string `json:"client_ca_file,omitempty"`
}

func (t TLS) enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

func (t *TLS) validate(listen string) error {
	if !t.enabled() {
		if t.ClientCAFile != "" {
			return fmt.Errorf("tls.client_ca_file is set without a certificate: " +
				"mutual TLS needs the server to speak TLS first")
		}
		// Binding a plaintext listener to anything but loopback is a decision,
		// not a default, and worth naming at load rather than at incident.
		if !loopback(listen) {
			return fmt.Errorf("listen is %q and no TLS is configured: either set "+
				"tls.cert_file and tls.key_file, bind to loopback behind a "+
				"terminator, or say so deliberately by binding 127.0.0.1", listen)
		}
		return nil
	}
	if t.CertFile == "" || t.KeyFile == "" {
		return fmt.Errorf("tls needs both cert_file and key_file")
	}
	for _, f := range []string{t.CertFile, t.KeyFile, t.ClientCAFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(ExpandPath(f)); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}
	return nil
}

// loopback reports whether an address is bound to the local host only.
func loopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "localhost", "::1", "":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// Paths returns the expanded file paths. Building the server's own TLS value is
// the caller's job: config describing the server rather than importing it keeps
// the dependency pointing one way.
func (t TLS) Paths() (cert, key, clientCA string) {
	return ExpandPath(t.CertFile), ExpandPath(t.KeyFile), ExpandPath(t.ClientCAFile)
}
