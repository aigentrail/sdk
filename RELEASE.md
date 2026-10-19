# SDK release preparation

This release adds decision-linked execution evidence and strict tool-call quota
admission across all SDKs. Existing tracing and enforcement defaults remain
unchanged. Strict admission requires explicit opt-in and an agent-bound key.

| Package | Version | Release tag |
| --- | --- | --- |
| Python `gentrail` | 0.8.0 | `v0.8.0` |
| JavaScript `@gentrail/ai` | 0.4.1 | `js-v0.4.1` |
| Go `github.com/aigentrail/sdk/go` | 0.6.0 | `go/v0.6.0` |

Versions follow each package's existing sequence. `release.json` records the
release set; CI rejects mismatched manifests, locks and release tags.

Python 0.8.0 and Go 0.6.0 have been released. JavaScript 0.4.0 bootstraps the
npm package; 0.4.1 validates GitHub trusted publishing and provenance with the
same runtime behavior. The npm trust connection permits `publish-npm.yml` in
`aigentrail/sdk` using the `npm` environment. Its first successful CI publish
must complete within two days of configuration to activate the connection.

## Behavior

- Opt in with Python `strict_admission=True`, Go `WithStrictAdmission()`, or
  JavaScript `strictAdmission: true`. Python supports sync and async clients.
  Python framework adapters and JavaScript `guardTools` preserve the setting.
- Human approval resolves before quota reservation and consumption. The server
  owns policy evaluation, quota windows and accounting.
- Strict enforcement blocks on decision outages, malformed or expired receipts,
  replay, quota exhaustion and lost consume replies. Consume is never retried.
- A consumed attempt stays charged after a crash, tool failure or host refusal.
  Reporting failure must never cause the tool to execute again.
- Decision references link execution evidence without granting permission.
  Argument hashes use the full original arguments before redaction or truncation.
- Constructors without strict opt-in retain fail-open decision transport behavior
  and fail-closed approval waits. A quota resource requires strict support.

Native usage is documented in [Python](python/README.md), [Go](go/README.md) and
[JavaScript](js/gentrail-ai/README.md). Framework availability remains specific
to each ecosystem; the [feature matrix](README.md#feature-parity) records it.

## Package verification

Run from the repository root with Go 1.25.7+, Python 3.13, uv, Node 24 and npm:

```console
go test scripts/releasecheck/main.go scripts/releasecheck/main_test.go
go run scripts/releasecheck/main.go python
go run scripts/releasecheck/main.go javascript
go run scripts/releasecheck/main.go go
```

The checks build a Python wheel and source distribution, rebuild the wheel from
the source distribution, and install each wheel in a clean environment. They
pack and install the npm tarball, and download a candidate Go module zip through
a temporary file-based module proxy. Existing native suites and shared vectors
then run against packaged code, with test fixtures supplied separately. Import
checks exercise public Python and JavaScript exports, bundled PII data and
explicit strict-mode defaults. JavaScript packing always rebuilds generated code.

Artifacts are saved under `dist/release/`. The release workflow runs these checks
on pull requests, main and release tags. Tag-triggered publishing consumes the
same verified artifacts instead of rebuilding them. Go is distributed by its
module tag; the candidate zip check does not prove public proxy availability.
The existing `publish.yml` and `publish-npm.yml` filenames and environment names
stay in place because trusted-publisher permissions bind to those identities.

The Gentrail CLI separately runs 30 real-pipeline scenarios against its pinned
SDK revision. Package checks cover client behavior and distribution contents;
they do not certify hosted providers or live AWS latency.

## Rollout

After this PR merges and its checks pass, create only `js-v0.4.1` on the merged
commit. The existing `v0.8.0` and `go/v0.6.0` tags remain on their original release
commit. Verify the npm publish job and install 0.4.1 from the public registry.
Then update Gentrail's Go dependency and cross-language conformance pin together;
version and pin verification must support the Go release tag rather than assuming
every dependency uses a pseudoversion.

This release PR prepares JavaScript 0.4.1; publication follows merge.
