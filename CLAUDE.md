# aikido-report — project conventions

Unofficial CLI: Aikido Security scan results → SARIF 2.1.0 + CI quality
gate. Companion to bb-insights (which publishes SARIF to Bitbucket Code
Insights). Not an Aikido SDK and must not grow into one.

## Architecture (dependency direction is enforced by review)

```
cli ──► gate ──► publicapi (transport: HTTP, OAuth, retry, pagination, DTOs)
 │        │
 │        └────► report (domain model — depends on NOTHING in this repo)
 └──► sarifgen ─► report
      imageref (parser, used by cli/gate)
```

- `internal/report` never imports other project packages.
- `internal/aikido/publicapi` makes no business decisions; DTOs stay inside
  gate/publicapi and never reach sarifgen.
- `internal/gate` owns target resolution, trigger-once, polling; interfaces
  are defined on the consumer side (gate), satisfied by `*publicapi.Client`.
- `internal/sarifgen` knows only `report.Report`; no HTTP, no credentials,
  no exit codes.
- `internal/cli` owns kong parsing, env fallbacks, pipe mode, signals, exit
  codes; no API or SARIF logic.

## Standing rules

- Every flag has an `AIKIDO_*` env fallback (Bitbucket pipe mode requires
  it); flags win over env. Bitbucket variables are configuration fallbacks
  only, never domain logic.
- Exit codes: 0 success, 1 technical/config error, 2 (configurable 2–255,
  never 1) failed quality gate. The SARIF report is always written before
  the gate is evaluated. Reports are written atomically.
- SARIF output is deterministic (sorted rules/results, no timestamps, no
  randomness) and golden-tested; refresh goldens with
  `go test ./internal/sarifgen -update` only for intentional changes.
- No fake locations in SARIF: findings without a file get no `locations`.
- Secrets never appear in logs/errors/reports — every new failure path
  needs a test asserting this.
- Retries: GET only (429/5xx/network, honoring Retry-After); POST scan
  triggers are never auto-retried. Polling is a separate mechanism with an
  injectable `SleepFunc` — no real sleeps in tests.
- Unknown Aikido severities/categories map to `unknown` and are kept, never
  dropped; the original type goes into finding properties.
- Ambiguous target matches are errors — never pick the first candidate.
- Documented Aikido API shapes live as fixtures in `testdata/api`; when the
  real API disagrees with docs, fix the DTO and the fixture together.
- Minimal dependencies: kong, go-sarif/v3, distribution/reference. Adding
  any dependency needs written justification in the PR.

## Checks

```bash
go test ./... && go test -race ./... && go vet ./... && golangci-lint run
```

Tests must never require Aikido credentials or network access.
