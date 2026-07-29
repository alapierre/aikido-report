# AI Assistance Disclosure

This project is developed in collaboration with an AI coding agent (Claude
Code, by Anthropic), using models from the Claude Sonnet family, in
addition to human authorship and review.

## What AI is used for

- **Code review**: reviewing diffs for correctness, security, and
  consistency with the project's architecture before changes are merged.
- **Implementation**: drafting parts of the implementation (parsers, CLI
  commands, tests, documentation) from requirements set by the maintainer.

## What stays human-driven

- All architectural and design decisions (see [CLAUDE.md](CLAUDE.md)) are
  made and owned by the maintainer, not delegated to the AI.
- Every change is reviewed by the maintainer before merging, regardless of
  whether it was drafted by a human or an AI agent.
- Releases, dependency approvals, and security-sensitive decisions (see
  [SECURITY.md](SECURITY.md)) are made by the maintainer.
- The maintainer is responsible for the correctness, security, and quality
  of the released code, the same as for any other open source project.

## Why this disclosure exists

`bb-insights` is a security- and CI-adjacent tool: it runs inside build
pipelines and handles output from test, coverage, and vulnerability
scanners. Being transparent about how the code is produced - including
AI involvement - is part of giving users and contributors the context they
need to evaluate the project's trustworthiness, consistent with this
project's [Code of Conduct](CODE_OF_CONDUCT.md) commitment to an open,
transparent community.

This disclosure applies to the project's own development workflow; see
[CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions) for the
expectations placed on external contributions that use AI tools.
