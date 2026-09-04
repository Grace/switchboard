package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// The chain is what makes this a record rather than a file.
//
// Every entry carries the sequence number it was written at and the MAC of the
// entry before it, and its own MAC covers both. Change a field, drop a line, or
// reorder two entries and the recomputation stops matching at exactly the point
// where the edit happened.
//
// Keyed with SWITCHBOARD_AUDIT_KEY the MAC is an HMAC, so an edit requires the
// key as well as write access to the file. Without a key it is a plain digest,
// which still catches corruption and casual editing but not a determined one —
// and the verifier says which of the two you have rather than implying the
// stronger claim.
//
// Two limits worth stating rather than discovering. Truncation at the tail is
// undetectable from the file alone: an intact prefix is an intact chain, and
// only an external anchor of the head can prove entries once followed it.
// And anyone holding the key can rewrite history wholesale. This is
// tamper-evidence against an attacker without the key, which is most real
// exposure, not proof against one who has it.

const keyEnv = "SWITCHBOARD_AUDIT_KEY"

// signer computes the MAC over a record's canonical bytes.
type signer struct {
	key   []byte
	keyed bool
}

func newSigner(key []byte) signer {
	return signer{key: key, keyed: len(key) > 0}
}

// keyFromEnv reads the audit key, if one is set.
func keyFromEnv() []byte {
	if v := os.Getenv(keyEnv); v != "" {
		return []byte(v)
	}
	return nil
}

func (s signer) sum(canonical []byte) string {
	if s.keyed {
		m := hmac.New(sha256.New, s.key)
		m.Write(canonical)
		return "h:" + hex.EncodeToString(m.Sum(nil))
	}
	d := sha256.Sum256(canonical)
	return "s:" + hex.EncodeToString(d[:])
}

// canonical renders a record for MACing: the record exactly as it will be
// written, with the MAC field itself empty. Go marshals struct fields in
// declaration order and map keys sorted, so this is stable across processes
// and Go versions.
func canonical(r Record) ([]byte, error) {
	r.MAC = ""
	return json.Marshal(r)
}

// sign fills in Seq, Prev and MAC.
func (s signer) sign(r Record, seq uint64, prev string) (Record, error) {
	r.Seq = seq
	r.Prev = prev
	c, err := canonical(r)
	if err != nil {
		return r, err
	}
	r.MAC = s.sum(c)
	return r, nil
}

// Break describes the first place a log stops verifying.
type Break struct {
	Line   int
	Seq    uint64
	Reason string
}

func (b *Break) Error() string {
	return fmt.Sprintf("audit chain broken at line %d (seq %d): %s", b.Line, b.Seq, b.Reason)
}

// Report is the outcome of verifying a log.
type Report struct {
	Entries int
	Keyed   bool
	Head    string
	Break   *Break
}

// Verify walks a log and reports the first inconsistency.
//
// It returns a Report even when the chain is broken, because "the first 4,812
// entries verify and entry 4,813 was altered" is the useful answer — far more
// so than a bare failure.
func Verify(path string, key []byte) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return verify(f, key)
}

func verify(r io.Reader, key []byte) (*Report, error) {
	s := newSigner(key)
	rep := &Report{Keyed: s.keyed}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var prev string
	var expectSeq uint64 = 1

	for line := 1; sc.Scan(); line++ {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			rep.Break = &Break{Line: line, Reason: "not valid JSON: " + err.Error()}
			return rep, nil
		}

		switch {
		case rec.Seq != expectSeq:
			rep.Break = &Break{Line: line, Seq: rec.Seq, Reason: fmt.Sprintf(
				"sequence jumped: expected %d, found %d — an entry was removed or reordered",
				expectSeq, rec.Seq)}
			return rep, nil
		case rec.Prev != prev:
			rep.Break = &Break{Line: line, Seq: rec.Seq, Reason: "does not follow the previous entry"}
			return rep, nil
		}

		c, err := canonical(rec)
		if err != nil {
			return nil, err
		}
		if want := s.sum(c); !hmac.Equal([]byte(want), []byte(rec.MAC)) {
			reason := "contents do not match the recorded digest — this entry was altered"
			if s.keyed && len(rec.MAC) > 1 && rec.MAC[:2] == "s:" {
				reason = "entry was written unsigned but verified with a key"
			} else if !s.keyed && len(rec.MAC) > 1 && rec.MAC[:2] == "h:" {
				reason = "entry was signed; set " + keyEnv + " to verify it"
			}
			rep.Break = &Break{Line: line, Seq: rec.Seq, Reason: reason}
			return rep, nil
		}

		prev = rec.MAC
		expectSeq++
		rep.Entries++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rep.Head = prev
	return rep, nil
}

// tailState recovers the sequence and MAC to continue from, so a restart
// appends to the existing chain instead of starting a new one beside it.
func tailState(path string) (seq uint64, prev string, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			// A corrupt tail is not a reason to refuse to keep recording;
			// Verify is where that gets reported.
			continue
		}
		seq, prev = rec.Seq, rec.MAC
	}
	return seq, prev, sc.Err()
}

// Find returns every entry for one completion id.
//
// This is the reconstruction half: given a decision someone is asking about,
// produce what actually happened — which model answered, on whose behalf, with
// what token counts, and what was redacted on the way in.
func Find(path, id string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var out []Record
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		if rec.ID == id {
			out = append(out, rec)
		}
	}
	return out, sc.Err()
}

// KeyFromEnv exposes the configured audit key to callers outside the package.
func KeyFromEnv() []byte { return keyFromEnv() }

// KeyEnv names the environment variable holding the audit key.
const KeyEnv = keyEnv
