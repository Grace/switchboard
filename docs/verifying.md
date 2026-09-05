# Verifying a release

*A signature is only worth having if someone checks it, so here is how.*

Releases are built by GitHub Actions from a tag, and the checksum file is signed
with [cosign](https://docs.sigstore.dev/) using keyless signing. There is no
private key: the certificate is issued to the workflow identity that ran the
build and recorded in a public transparency log. So a valid signature does not
say "someone with a key made this" — it says *this artifact came out of this
workflow, in this repository, at this commit*, and anyone can check that claim
against a log neither of us controls.

## Check the download

```sh
VERSION=v0.2.0
BASE=https://github.com/Grace/switchboard/releases/download/$VERSION

curl -LO $BASE/switchboard_${VERSION#v}_darwin_arm64.tar.gz
curl -LO $BASE/checksums.txt
curl -LO $BASE/checksums.txt.sig
curl -LO $BASE/checksums.txt.pem

cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/Grace/switchboard/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

shasum -a 256 -c checksums.txt --ignore-missing
```

The first command establishes that the checksum file is the one that workflow
produced. The second establishes that your download matches it. Skipping either
leaves the other proving nothing.

**The `--certificate-identity-regexp` is the part that matters.** Without it
`cosign` will happily verify that *somebody* signed the file. Pinning the
identity is what makes the signature mean this repository's release workflow
rather than any workflow anywhere.

## Check the container image

```sh
cosign verify ghcr.io/grace/switchboard:v0.2.0 \
  --certificate-identity-regexp 'https://github.com/Grace/switchboard/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## What is in the binary

Every archive ships an SPDX SBOM alongside it —
`switchboard_0.2.0_linux_amd64.tar.gz.sbom.spdx.json` — so a supply-chain
question can be answered by reading rather than by asking. The short version is
that the list is short: the standard library and the AWS SDK.

## What this does and does not prove

It proves the artifact came from this repository's release workflow at a
particular tag, and that it has not been altered since. That is the property
that matters for a mirror, a proxy, or a compromised download.

It does not prove the source is correct, that the workflow was not itself
subverted, or that a maintainer with push access acted honestly. Signing moves
trust from "the file I downloaded" to "the repository and its workflow"; it does
not remove the need to trust those.
