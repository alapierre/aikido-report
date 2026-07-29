# aikido-report

[![CI](https://github.com/alapierre/aikido-report/actions/workflows/ci.yml/badge.svg)](https://github.com/alapierre/aikido-report/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Unofficial CLI that turns [Aikido Security](https://www.aikido.dev) scan
results into [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
reports and optionally acts as a CI quality gate. Built to work hand in hand
with [bb-insights](https://github.com/alapierre/bb-insights), which publishes
SARIF to Bitbucket Code Insights.

> **Disclaimer**
>
> This project is **not** an official Aikido Security product. It is not
> affiliated with, supported, or maintained by Aikido Security. It uses only
> a small, documented subset of the Aikido public API. The tool does **not**
> analyze code itself — it triggers or reads Aikido scans and exports their
> results as SARIF.

## What it does

Two use cases, two subcommands:

- **`aikido-report container`** — *container deployment gate*. After you
  build and push an image (and before you deploy or promote it), verify that
  Aikido has scanned exactly the tag you are about to ship, export the open
  findings as SARIF, and optionally fail the pipeline on findings at or above
  a severity threshold.
- **`aikido-report repository`** — *repository release gate*. Before a
  release or production deployment, verify the final state of the code and
  its dependencies on the branch Aikido scans, export all open findings
  (SCA, SAST, secrets, IaC, …) with file/line locations where available, and
  optionally gate on severity.

Both commands:

1. authenticate with OAuth client credentials,
2. resolve the exact scan target in Aikido (ambiguity is an error, never a guess),
3. optionally trigger one scan and poll until the result is available,
4. fetch **all** open findings (no severity filtering at fetch time),
5. write a deterministic SARIF 2.1.0 report (atomically — no partial files),
6. only then evaluate the quality gate and pick the exit code.

### What about pull requests?

Aikido has **native PR integrations** that comment on the diff, publish PR
statuses and distinguish new from pre-existing issues without any pipeline
step. If you want PR gating, use the native integration — it is almost always
the better tool. This CLI intentionally does not implement a PR mode; the
`repository` command is a *release* gate with a different purpose: producing
an auditable SARIF artifact of the full current state.

## Installation

**Release binary** (Linux/macOS, amd64/arm64):

```bash
curl -sSL -o aikido-report \
  https://github.com/alapierre/aikido-report/releases/latest/download/aikido-report_linux_amd64
chmod +x aikido-report
```

**Go:**

```bash
go install github.com/alapierre/aikido-report/cmd/aikido-report@latest
```

**Docker:**

```bash
docker run --rm -v "$PWD:/work" -w /work lapierre/aikido-report:latest --help
```

## Credentials

Both commands need **OAuth client credentials** created by a workspace admin
in Aikido under *Settings → Integrations* (scopes: `containers:read`,
`containers:write` for `--trigger-scan`, `repositories:read`,
`repositories:write`, `issues:read`).

```text
AIKIDO_CLIENT_ID
AIKIDO_CLIENT_SECRET
```

Store them as secured repository variables in your CI. They are only ever
held in memory, never written to disk, and never appear in logs, error
messages, or reports. If your workspace lives in a regional environment, set
`AIKIDO_BASE_URL` (e.g. `https://app.us.aikido.dev`).

## Usage

### Container deployment gate

```bash
aikido-report container \
  --image registry.example.com/team/application \
  --tag 1.2.3 \
  --output aikido-container.sarif \
  --wait \
  --trigger-scan \
  --fail-severity high
```

The image reference may carry the tag itself (`--image app:1.2.3`); if both
forms are used they must agree. Digest references are not supported (Aikido
matches scans by tag). When `--image` names no registry, the name must match
exactly one Aikido container repository across all registries — otherwise the
tool exits with an ambiguity error asking you to qualify the registry.

**Important Aikido API limitation:** the scan trigger accepts no tag; Aikido
scans whatever the repository's *tag filter* selects (or the latest image).
The tool therefore polls until `last_scanned_tag` equals your `--tag`. If
your registry integration scans pushed tags automatically, everything just
works; if the tag filter points elsewhere, the wait will time out with a
message showing which tags Aikido did scan.

### Repository release gate

```bash
aikido-report repository \
  --repository my-project \
  --branch master \
  --commit "$BITBUCKET_COMMIT" \
  --output aikido-code.sarif \
  --wait \
  --trigger-scan \
  --scan-types sast,iac,secrets \
  --fail-severity high
```

**Semantics you should know:**

- The Aikido public API scans the **branch configured in Aikido** for the
  repository. `--branch` is *verified* against that configuration — a
  mismatch is an error (the findings would describe a different branch).
- `--commit` is recorded in the SARIF report (`versionControlProvenance`)
  as metadata only; Aikido's public API has no per-commit scan results.
  Use `--trigger-scan --wait` to make sure findings are fresh.
- The dependency (SCA) scan always runs on trigger; `--scan-types` adds
  `sast`, `iac` and/or `secrets`.

### Flags and environment variables

Every flag has an environment fallback (flags win). Common flags:

| Flag                   | Env                    | Default                  | Description                                                               |
|------------------------|------------------------|--------------------------|---------------------------------------------------------------------------|
| `--output`             | `AIKIDO_OUTPUT`        | *(required)*             | SARIF path; `-` writes to stdout (logs go to stderr)                      |
| `--base-url`           | `AIKIDO_BASE_URL`      | `https://app.aikido.dev` | Aikido base URL                                                           |
| `--client-id`          | `AIKIDO_CLIENT_ID`     | *(required)*             | OAuth client ID                                                           |
| `--client-secret`      | `AIKIDO_CLIENT_SECRET` | *(required)*             | OAuth client secret                                                       |
| `--fail-severity`      | `AIKIDO_FAIL_SEVERITY` | *(empty = gate off)*     | `critical`\|`high`\|`medium`\|`low`                                       |
| `--exit-code`          | `AIKIDO_EXIT_CODE`     | `2`                      | Exit code on failed gate (2–255; 1 is reserved)                           |
| `--wait` / `--no-wait` | `AIKIDO_WAIT`          | `true`                   | Poll until the expected scan result exists                                |
| `--trigger-scan`       | `AIKIDO_TRIGGER_SCAN`  | `false`                  | Trigger one scan when the result is missing                               |
| `--poll-interval`      | `AIKIDO_POLL_INTERVAL` | `15s`                    | Delay between polls                                                       |
| `--timeout`            | `AIKIDO_TIMEOUT`       | `10m`                    | Overall operation budget                                                  |
| `--http-timeout`       | `AIKIDO_HTTP_TIMEOUT`  | `30s`                    | Single HTTP request timeout                                               |
| `--dry-run`            | `AIKIDO_DRY_RUN`       | `false`                  | Read-only: never trigger scans, still fetch findings and write the report |
| `--verbose`            | `AIKIDO_VERBOSE`       | `false`                  | Debug logging on stderr (never logs credentials)                          |

Container: `--image` (`AIKIDO_IMAGE`), `--tag` (`AIKIDO_TAG`).

Repository: `--repository` (`AIKIDO_REPOSITORY`, falls back to
`BITBUCKET_REPO_SLUG`), `--branch` (`AIKIDO_BRANCH` / `BITBUCKET_BRANCH`),
`--commit` (`AIKIDO_COMMIT` / `BITBUCKET_COMMIT`), `--scan-types`
(`AIKIDO_SCAN_TYPES`).

The Bitbucket fallbacks are just configuration defaults — the tool runs the
same everywhere: locally, GitHub Actions, GitLab CI, Jenkins.

## Exit codes

| Code                   | Meaning                                                                                                                   |
|------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `0`                    | Success — gate disabled, or no findings at/above the threshold                                                            |
| `1`                    | Technical or configuration error (auth failure, no matching repository, ambiguous match, scan wait timeout, cancellation) |
| `2` (or `--exit-code`) | Quality gate failed — open findings at/above `--fail-severity` exist                                                      |

The SARIF report is **always written before** the gate is evaluated, so a
red gate still leaves the full report for publication. The gate counts only
findings with a known severity; `unknown` never trips it (but is always in
the report).

## Quality gate: here or in bb-insights?

Both tools can gate; pick one place. Recommended split for Bitbucket:

- `aikido-report` runs **without** `AIKIDO_FAIL_SEVERITY` (gate off) and only
  produces the SARIF artifact,
- `bb-insights` publishes the report to Code Insights **and then** gates
  (`BB_INSIGHTS_FAIL_SEVERITY` + `BB_INSIGHTS_EXIT_CODE`).

This guarantees the report is visible in Bitbucket even when the pipeline is
stopped. Standalone (without bb-insights), let `aikido-report` gate directly.

## Use in Bitbucket Pipelines

Pipes in the same step share the build directory (`$BITBUCKET_CLONE_DIR` is
mounted into every pipe container as its working directory), so a file
written by one pipe is readable by the next — use relative paths.

```yaml
- step:
    name: Aikido container gate
    script:
      - pipe: docker://lapierre/aikido-report:latest
        variables:
          AIKIDO_REPORT_TYPE: container
          AIKIDO_CLIENT_ID: $AIKIDO_CLIENT_ID
          AIKIDO_CLIENT_SECRET: $AIKIDO_CLIENT_SECRET
          AIKIDO_IMAGE: $IMAGE
          AIKIDO_TAG: $VERSION
          AIKIDO_OUTPUT: aikido-container.sarif
          AIKIDO_WAIT: "true"
          AIKIDO_TRIGGER_SCAN: "true"
      - pipe: docker://lapierre/bb-insights:latest
        variables:
          BB_INSIGHTS_REPORT_TYPE: sarif
          BB_INSIGHTS_INPUT: aikido-container.sarif
          BB_INSIGHTS_TITLE: Aikido Container Security
          BB_INSIGHTS_REPORT_ID: bb-insights-aikido-container
          BB_INSIGHTS_FAIL_SEVERITY: high
          BB_INSIGHTS_EXIT_CODE: "2"
          BB_INSIGHTS_TOKEN: $BB_INSIGHTS_TOKEN
```

Repository release gate:

```yaml
- step:
    name: Aikido release gate
    script:
      - pipe: docker://lapierre/aikido-report:latest
        variables:
          AIKIDO_REPORT_TYPE: repository
          AIKIDO_CLIENT_ID: $AIKIDO_CLIENT_ID
          AIKIDO_CLIENT_SECRET: $AIKIDO_CLIENT_SECRET
          AIKIDO_REPOSITORY: $BITBUCKET_REPO_SLUG
          AIKIDO_BRANCH: $BITBUCKET_BRANCH
          AIKIDO_COMMIT: $BITBUCKET_COMMIT
          AIKIDO_OUTPUT: aikido-code.sarif
          AIKIDO_WAIT: "true"
          AIKIDO_TRIGGER_SCAN: "true"
          AIKIDO_SCAN_TYPES: sast,iac,secrets
      - pipe: docker://lapierre/bb-insights:latest
        variables:
          BB_INSIGHTS_REPORT_TYPE: sarif
          BB_INSIGHTS_INPUT: aikido-code.sarif
          BB_INSIGHTS_TITLE: Aikido Code Security
          BB_INSIGHTS_REPORT_ID: bb-insights-aikido-code
          BB_INSIGHTS_FAIL_SEVERITY: high
          BB_INSIGHTS_EXIT_CODE: "2"
          BB_INSIGHTS_TOKEN: $BB_INSIGHTS_TOKEN
```

Notes:

- With no arguments (how pipes start containers), the binary selects the
  subcommand from `AIKIDO_REPORT_TYPE` (`container` or `repository`); every
  flag resolves through its environment variable.
- `BITBUCKET_REPO_SLUG`, `BITBUCKET_BRANCH`, `BITBUCKET_COMMIT` are injected
  into pipe containers automatically; secrets must be passed explicitly in
  `variables:`.
- The image runs as root on purpose: Bitbucket mounts the clone directory
  with userns-remapped root ownership and a non-root pipe could not write
  the report into it. If the report must survive into a *later step*,
  declare it under `artifacts:`.
- If you prefer a single container, run both binaries in one `script:` step
  instead of two pipes — the same environment variables apply.

## SARIF output

- Valid SARIF 2.1.0 (`$schema` + `version` included), tool name
  `aikido-report`, tool version from the build.
- **Deterministic**: rules and results are sorted, no timestamps, no random
  IDs — identical input produces byte-identical output (golden-tested).
- **Rule IDs** in stable precedence: CVE (`CVE-2025-12345`) → Aikido rule id
  (`aik_sast_sqli_001`) → `aikido-<type>-<groupId>`.
- **Severity**: `critical/high → error`, `medium → warning`, `low/info/unknown
  → note`, with the exact severity preserved in rule tags (`CRITICAL`, …)
  and a CVSS-style `security-severity` rule property — this is exactly what
  bb-insights reads, so severities survive the round trip.
- **Locations** only when the finding has a real file (SAST, secrets, IaC).
  Container package findings carry no artificial `Dockerfile:1`-style
  locations; bb-insights still counts them in report metrics and publishes
  them as file-less annotations.
- Result properties carry the Aikido issue id/group id, category, CVE, CWE,
  package, installed/fixed versions, and a link back to the Aikido issue.
- Findings of Aikido types this tool doesn't chart map to category
  `unknown`, keeping the original type in properties — nothing is dropped.

## Limitations

- The container scan trigger cannot target a tag (public API limitation);
  see the container section above.
- No scan-status endpoint exists in the public API: a scan that fails
  inside Aikido is indistinguishable from one still running and surfaces
  here as a wait timeout.
- `--commit` on the repository gate is metadata, not verification.
- The issues export carries no long descriptions; report messages are
  composed from structured fields (rule, package, versions, CVE, CWE).
- Aikido rate-limits the public API to 20 requests/min per workspace. The
  client honors `Retry-After` and backs off, but heavily parallel pipelines
  in one workspace may slow each other down.

## Troubleshooting

- **`ambiguous match`** — the image name matches several Aikido container
  repositories; qualify the registry: `--image registry.example.com/team/app`.
- **`no matching Aikido repository`** — check the name Aikido uses (the
  error lists similarly named candidates and their registries).
- **`timed out waiting for scan`** — the expected tag was never scanned;
  the message shows which tag Aikido scanned last. Check the repository's
  tag filter in Aikido or raise `--timeout`.
- **`branch mismatch`** — Aikido is configured to scan a different branch;
  either run the gate on that branch or change the Aikido configuration.
- **HTTP 429** — workspace rate limit; the tool retries automatically.
- **Debugging the Docker image** — it has no shell (distroless). Run the
  binary locally with `--verbose`, or `docker run --rm lapierre/aikido-report --help`.

## Security

- Credentials live only in memory; no token cache is written.
- Secrets never appear in logs (including `--verbose`), error messages,
  SARIF output, or dry-run summaries — enforced by tests.
- The HTTP client refuses redirects to a different host, so the
  `Authorization` header cannot leak.
- Error bodies from the API are length-limited and stripped of control
  characters before they reach logs.
- Reports are written atomically (temp file + rename): no partial files.

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
golangci-lint run
govulncheck ./...
```

Tests run entirely against `httptest` servers — no Aikido account or
credentials are needed. SARIF output is golden-tested
(`go test ./internal/sarifgen -update` refreshes the goldens after
intentional changes).

Releases are built by GoReleaser: static binaries (linux/darwin,
amd64/arm64) with checksums, syft SBOMs, provenance attestations, and a
multi-arch Docker image.

## Related projects

- [bb-insights](https://github.com/alapierre/bb-insights) — publishes SARIF
  (and JUnit/coverage) reports to Bitbucket Code Insights.

## License

[Apache 2.0](LICENSE)
