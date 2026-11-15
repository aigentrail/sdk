# SDK release preparation

## D3 candidate release set

| Package | Version | Release tag |
| --- | --- | --- |
| Python `gentrail` | 0.9.0 | `v0.9.0` |
| JavaScript `@gentrail/ai` | 0.5.0 | `js-v0.5.0` |
| Go `github.com/aigentrail/sdk/go` | 0.7.0 | `go/v0.7.0` |

This is a breaking enforcement change. Configured enforcers require registered
identity and policy-bound `operation_v1` admission for every executable operation,
including those without quotas. Remove the old strict-admission options. Pass
Go `WithToolID`, JavaScript `toolId`/`guardTools` mappings or Python `tool_id`/
`tool_ids`. Python framework adapters retain mappings across sync/async conversion.

Missing admission, unavailable decisions and lost consumption replies deny
execution. Closed attempts and uncertain consumption have distinct recovery
states; neither permits automatic retry. Parent-request options link a fresh
attempt without inheriting approvals. Shared vectors and package checks cover
all three languages.

A D3-compatible server is required. Updating the SDK alone against an old server
keeps execution blocked. Coordinate server/client deployment and pending-work
handling; never replace an existing tag or package. Candidate metadata and local
package checks do not mean these versions are published. Application pin updates,
public registry/proxy verification and coordinated dev cutover remain pending.

## Previous release set

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

## Previous release behavior

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
enforcement defaults. JavaScript packing always rebuilds generated code.

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

After all candidate checks pass, merge the SDK candidate and publish only the
three tags in the D3 table on that exact commit. Existing tags remain immutable.
Python/npm tag workflows publish the verified artifacts; Go uses its module tag.
Verify every public package/module before updating application pins and locks.
Run the application pipeline against those installed published versions, then
perform the coordinated stopped-writer dev cutover. No older client may remain
an active enforcement path.
