// Package push delivers a built evidence package to where the auditor already
// looks.
//
// The package is designed to be verifiable without its author, which solves the
// trust problem and not the delivery one: a directory on your laptop is not
// evidence anybody can find. Compliance programmes already have a place
// auditors pull from — Vanta, Drata, Secureframe — and the whole value of
// arriving there is that the recipient never learns your name.
//
// There is a second effect worth being explicit about, because it changes what
// the paid tier is for. A package built by the same party that wrote the log is
// unanchored: nothing outside it attests that entries were not cut off the end.
// Uploading to a GRC platform records the digest, with a timestamp, in a log
// the uploader does not control. That is not a transparency log and should not
// be described as one — but it is a third party's dated record that this digest
// existed, which is most of what the anchor was for.
package push

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Target is somewhere an evidence package can be delivered.
type Target interface {
	// Name is what the CLI calls it.
	Name() string
	// Check reports whether the target is configured, without sending
	// anything. Credentials come from the environment; a target that needs
	// one it cannot find says so here rather than at upload time.
	Check() error
	// Send delivers the archive and returns a human-readable receipt.
	Send(ctx context.Context, a Archive) (string, error)
}

// Archive is one evidence package, zipped, with the digest that identifies it.
type Archive struct {
	// Filename is what the receiving system should call it.
	Filename string
	// Body is the zip.
	Body []byte
	// Digest is the SHA-256 of manifest.json — the value that identifies the
	// package, and the one worth recording somewhere the package is not.
	Digest string
	// Period labels the archive for a human scanning a document list.
	Period string
}

// Zip packs an evidence directory.
//
// The whole directory, because the files verify against each other: manifest
// digests the rest, and a manifest delivered without the entries it describes
// is an assertion rather than evidence. Entries are stored byte for byte —
// re-encoding JSON produces different bytes and verifies against nothing.
func Zip(dir, digest, period string) (Archive, error) {
	var names []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return Archive{}, err
	}
	if len(names) == 0 {
		return Archive{}, fmt.Errorf("%s: nothing to send", dir)
	}
	// Sorted so the same package produces the same archive: a receiving system
	// that dedupes by hash should see a re-upload as a re-upload.
	sort.Strings(names)

	var buf strings.Builder
	zw := zip.NewWriter(&stringWriter{&buf})
	for _, name := range names {
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return Archive{}, err
		}
		w, err := zw.Create(name)
		if err != nil {
			return Archive{}, err
		}
		if _, err := w.Write(src); err != nil {
			return Archive{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return Archive{}, err
	}
	body := []byte(buf.String())

	if digest == "" {
		sum := sha256.Sum256(body)
		digest = hex.EncodeToString(sum[:])
	}
	label := period
	if label == "" {
		label = filepath.Base(dir)
	}
	return Archive{
		Filename: "evidence-" + sanitise(label) + ".zip",
		Body:     body,
		Digest:   digest,
		Period:   period,
	}, nil
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Describe renders what would be sent, for a dry run. A tool that uploads
// evidence somewhere on a customer's behalf should be able to show its work
// before it does it.
func Describe(t Target, a Archive) string {
	var b strings.Builder
	fmt.Fprintf(&b, "would send to %s\n", t.Name())
	fmt.Fprintf(&b, "  file    %s (%d bytes)\n", a.Filename, len(a.Body))
	fmt.Fprintf(&b, "  period  %s\n", a.Period)
	fmt.Fprintf(&b, "  digest  %s\n", a.Digest)
	fmt.Fprintf(&b, "\nNothing was sent. Drop -dry-run to send it.\n")
	return b.String()
}

var _ io.Writer = (*stringWriter)(nil)
