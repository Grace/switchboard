package evidence

import (
	"fmt"
	"strings"
)

// verifyDoc writes the instructions that make the package checkable by someone
// who has no reason to take the author's word for any of it.
//
// It is generated rather than shipped as a static file because half of it is
// facts about this particular package — whether the chain verified, whether the
// entries were signed or only digested, what the period was. A document that
// said "the chain is intact" beside a package whose chain was broken would be
// worse than no document.
func verifyDoc(o Options, m Manifest) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Verifying this package")
	w("")
	w("This covers **%s**.", o.Period)
	w("")
	w("It was produced by the same party that wrote the log. That is worth stating")
	w("first, because it determines what the rest of this document can honestly")
	w("claim. Everything below is checkable by you, with no software from that")
	w("party and no request to them — but the last section is about what none of it")
	w("proves, and that section is not a formality.")
	w("")

	w("## 1. The files are the files the manifest describes")
	w("")
	w("```")
	w("shasum -a 256 %s %s %s %s", fileEntries, fileReport, fileControls, fileVerify)
	w("```")
	w("")
	w("Compare each digest with the matching entry in `%s`. Any difference means", fileManifest)
	w("the file beside this one is not the file that was packaged.")
	w("")

	w("## 2. The manifest is the manifest you were told about")
	w("")
	w("```")
	w("shasum -a 256 %s", fileManifest)
	w("```")
	w("")
	w("Every other digest lives inside the manifest, so this one value covers the")
	w("package. Compare it with the digest you were given **through some other")
	w("channel** — a ticket, an email, a signed statement. Comparing it against a")
	w("number that travelled inside this directory proves nothing.")
	w("")

	w("## 3. The entries have not been altered")
	w("")
	w("`%s` holds the entries verbatim, in the bytes the writer emitted. Each is a", fileEntries)
	w("JSON object whose last field is `mac`, and the chain works like this:")
	w("")
	w("- `seq` counts from 1 and never skips.")
	w("- `prev` is the `mac` of the entry before it.")
	w("- `mac` covers the entry's own bytes **with the `mac` value emptied**.")
	w("  Because `mac` is written last, that is a textual substitution: replace")
	w("  `\"mac\":\"…\"` at the end of the line with `\"mac\":\"\"`.")
	if m.Chain.Signed {
		w("- The digest is `h:` followed by hex HMAC-SHA-256 of those bytes under the")
		w("  audit key. You need the key to check it, and the key is deliberately not")
		w("  in this package.")
	} else {
		w("- The digest is `s:` followed by hex SHA-256 of those bytes. **No key was")
		w("  used.** This catches corruption and casual editing. It does not stop")
		w("  anyone who can write to the file from rewriting history wholesale, since")
		w("  recomputing a plain digest needs no secret.")
	}
	w("")
	w("In Python, with no dependencies:")
	w("")
	w("```python")
	w("import hashlib, hmac, json, re, sys")
	w("key = b''  # the audit key, for h: entries")
	w("prev, seq = '', None")
	w("for line in open('%s', 'rb'):", fileEntries)
	w("    line = line.rstrip(b'\\n')")
	w("    rec = json.loads(line)")
	w("    canonical = re.sub(rb'\"mac\":\"[^\"]*\"\\}$', b'\"mac\":\"\"}', line)")
	w("    if rec['mac'].startswith('h:'):")
	w("        want = 'h:' + hmac.new(key, canonical, hashlib.sha256).hexdigest()")
	w("    else:")
	w("        want = 's:' + hashlib.sha256(canonical).hexdigest()")
	w("    assert want == rec['mac'], f\"entry {rec['seq']} was altered\"")
	w("    if seq is not None:")
	w("        assert rec['seq'] == seq + 1, 'an entry was removed or reordered'")
	w("        assert rec.get('prev', '') == prev, 'does not follow the previous entry'")
	w("    seq, prev = rec['seq'], rec['mac']")
	w("print('ok', seq, 'entries')")
	w("```")
	w("")

	w("## 4. What the producer's own check said")
	w("")
	if m.Chain.Break != "" {
		w("**The chain did not verify.** %s", m.Chain.Break)
		w("")
		w("Treat every figure in `%s` as coming from a file somebody may have", fileReport)
		w("edited. The break is over the whole log, not only this period: entries")
		w("after a break are downstream of it whether or not they fall inside the")
		w("window.")
	} else {
		w("At the time of packaging the whole log verified: %d entries across %d",
			m.Chain.Entries, m.Chain.Segments)
		w("segment(s), %s.", signedWord(m.Chain.Signed))
		w("")
		w("Verification covered the whole log rather than this period alone, because")
		w("a break anywhere puts everything after it in doubt.")
	}
	w("")
	w("This slice is entries %d through %d.", m.Extract.FirstSeq, m.Extract.LastSeq)
	if m.Extract.FirstPrev != "" {
		w("The entry immediately before it has MAC `%s`. Anyone holding the full log", m.Extract.FirstPrev)
		w("can find that entry and confirm this slice begins where it says it does.")
	}
	w("")

	w("## 5. Reproducing the producer's check")
	w("")
	w("`switchboard audit verify` performs section 3 for you. It is MIT-licensed and")
	w("its releases are signed with keyless cosign and carry SBOMs, so you can pin")
	w("the identity of the workflow that built the binary rather than trusting a")
	w("download — see `docs/verifying.md` in the source. That is the difference")
	w("between trusting the producer and trusting a public build.")
	w("")

	if len(m.PoliciesArchived) > 0 || len(m.PoliciesMissing) > 0 {
		w("## 5a. The rules each entry was served under")
		w("")
		w("Every entry names a policy fingerprint. That says *which* rules were in force,")
		w("and on its own it cannot say what they were — a digest citing a document")
		w("nobody kept is a reference to a missing source.")
		w("")
		if len(m.PoliciesArchived) > 0 {
			w("`policies/` holds the configuration behind %s cited here, byte for byte.",
				plural(len(m.PoliciesArchived), "the fingerprint", "each of the fingerprints"))
			w("")
			w("Each file is named by its own digest, so you can check it the same way you")
			w("checked everything else — and this one binds to the entries rather than to")
			w("this package:")
			w("")
			w("```sh")
			for _, fp := range m.PoliciesArchived {
				w("shasum -a 256 policies/%s.json   # first 12 hex digits are %s", fp, fp)
			}
			w("```")
			w("")
			w("That is what makes an archived policy evidence rather than an assertion. The")
			w("entries cite a name; the file answers to that name; neither depends on")
			w("trusting whoever assembled this directory.")
			w("")
		}
		if len(m.PoliciesMissing) > 0 {
			w("**Not every policy here is recoverable.** %s cited by these entries",
				plural(len(m.PoliciesMissing), "One fingerprint is", "Several fingerprints are"))
			w("and was never archived: %s.", join(m.PoliciesMissing))
			w("")
			w("Entries citing those were served under rules nobody captured. That is a real")
			w("gap in this package, it has a knowable start, and nothing done now recovers")
			w("it — archiving begins when it is switched on and is not retroactive. It is")
			w("stated here rather than left for you to notice.")
			w("")
		}
	}

	if m.Extract.Traced > 0 {
		w("## 6. Where the rest of the story is")
		w("")
		w("%d of these %d entries carry a W3C trace id.", m.Extract.Traced, m.Extract.Entries)
		w("")
		w("That is deliberate, and it is worth being explicit about what it means. This")
		w("package is the *record*: what was asked of which model, on whose behalf, under")
		w("which policy, and what it cost. It is complete as evidence and it is not the")
		w("whole story. Retries, intermediate steps, latencies and — where the deployment")
		w("uses them — the model's own reasoning traces live in the caller's tracing")
		w("system, under the same trace id.")
		w("")
		w("The two are complementary and are kept apart on purpose. A record has to be")
		w("complete, redacted before it was written, and retained for years; a trace is")
		w("sampled, raw, mutable and short-lived. Neither store can have both sets of")
		w("properties, so an investigation reads the entry here and pulls the trace from")
		w("wherever that deployment sends OTLP.")
		w("")
		w("A trace is not evidence. It is in a system that can be edited, is usually")
		w("expired by the time anyone asks, and was never redacted. Use it to understand")
		w("what happened; use this to establish it.")
		w("")
		w("## 7. What none of this proves")
	} else {
		w("## 6. What none of this proves")
	}
	w("")
	w("**Entries may have been removed from the end.** An intact prefix of a hash")
	w("chain is itself an intact chain, so nothing inside the file can show that")
	w("entries once followed the last one. This is the material limit, and it is not")
	w("closed by anything in this package. Closing it needs the head digest recorded,")
	w("at the time, somewhere the author of the log does not control.")
	w("")
	if m.Chain.Head != "" {
		w("The head at packaging time was `%s`.", m.Chain.Head)
		w("")
	}
	if !m.Chain.Signed {
		w("**These entries are unsigned.** Anyone who could write to the log could")
		w("also recompute the digests. Section 3 catches accident, not intent.")
		w("")
	}
	w("**The record is only as complete as the deployment made it.** The log records")
	w("what passed through the gateway. Traffic that went straight to a provider is")
	w("not here and cannot be — see `%s` for what the configuration in force did", fileControls)
	w("and did not enforce, including the obligations no configuration can evidence.")
	w("")
	if o.Report.Profile != "" {
		w("**A control assessment is not an audit opinion.** `%s` scores the", fileControls)
		w("configuration against %s. It is generated from live settings so it cannot",
			regimeOr(m.Controls.Regime, string(o.Report.Profile)))
		w("flatter the deployment, and it names what it could not determine — but it")
		w("is a description of a config file, not a judgement about your compliance.")
		w("")
	}
	w("**Content, where present, is redacted and partial.** Prompts and completions")
	w("appear only where content logging was deliberately enabled, and only after")
	w("pattern-based redaction. Values that were removed are not in this package.")

	return b.String()
}

func signedWord(signed bool) string {
	if signed {
		return "signed with a key"
	}
	return "digested but **not signed**"
}

func regimeOr(regime, profile string) string {
	if regime != "" {
		return regime
	}
	return profile
}

// plural picks a phrase by count, so the document reads as prose rather than
// as a template somebody forgot to finish.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// join lists names the way a sentence would.
func join(all []string) string {
	switch len(all) {
	case 0:
		return ""
	case 1:
		return all[0]
	case 2:
		return all[0] + " and " + all[1]
	default:
		return strings.Join(all[:len(all)-1], ", ") + " and " + all[len(all)-1]
	}
}
