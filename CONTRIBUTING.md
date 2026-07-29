# Contributing

Thanks for considering a contribution!

## Before you start

- For anything non-trivial, open an issue first so we can discuss the
  approach.
- This tool intentionally implements only a small slice of the Aikido API.
  Contributions that grow it into a general-purpose SDK, add heavy
  dependencies, or introduce speculative abstractions will be declined.

## Development

Requirements: Go (version from `go.mod`).

```bash
go test ./...
go test -race ./...
go vet ./...
golangci-lint run
```

All tests must run without an Aikido account — API behavior is tested
against `httptest` servers with fixtures in `testdata/api`. SARIF output is
golden-tested; after an intentional output change run
`go test ./internal/sarifgen -update` and include the golden diff in the PR.

## Architecture ground rules

- `internal/report` (domain model) depends on nothing else in the project.
- `internal/aikido/publicapi` is transport only: HTTP, retry, pagination,
  DTOs. No business decisions.
- `internal/gate` holds the use cases and maps DTOs to the domain model.
- `internal/sarifgen` knows only the domain model — no HTTP, no credentials.
- `internal/cli` parses configuration and picks exit codes — no API logic.
- Every new flag needs an `AIKIDO_*` environment fallback (pipe mode) and
  documentation in the README.
- Secrets must never reach logs, errors, or reports; add a test proving it
  for any new failure path.
- SARIF output must stay deterministic; the golden tests enforce this.

## Commit and PR guidelines

- Keep PRs focused; separate refactors from behavior changes.
- Add or update tests for every behavior change.
- `go vet`, tests (including `-race`) and `golangci-lint` must pass in CI.
