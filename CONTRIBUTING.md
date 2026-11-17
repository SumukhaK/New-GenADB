# Contributing to New-GenADB

Thanks for your interest. Bug reports, fixes, documentation and new integrations are all welcome.

## Ground rules

- **Be kind.** Assume good intent and keep discussion about the work.
- **Security issues are private.** Report vulnerabilities through GitHub's "Report a vulnerability" on this repository, never in a public issue or pull request.
- **Licensing.** By contributing, you agree that your contribution is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). New dependencies must use a permissive licence (Apache-2.0, MIT, BSD or ISC). Copyleft licences such as GPL, LGPL and AGPL cannot be accepted. Test-only dependencies under EPL or MPL are acceptable.

## Development setup

| Part | Needs |
|---|---|
| Go core, SDK, daemon | Go 1.24+ |
| Evaluation harness | Python 3.10+ and Go |
| Kotlin SDK logic (`android/agent-protocol`) | JDK 17+ |
| Android library and app | Android SDK (API 35), JDK 17+ and Go (the build cross-compiles the agent) |

```bash
cd core
go vet ./...
go test -race ./...
go build ./cmd/...

cd ..
python3 eval.py           # must not regress (see below)

cd android
./gradlew :agent-protocol:test
./gradlew :genadb-android:assembleRelease :app:assembleDebug   # with ANDROID_HOME set
```

## Where things go

| Change | Location |
|---|---|
| Public Go API | `core/pkg/genadb`, plus docs in `API_SPEC.md` |
| Wire protocol, transport, tunnel, policy enforcement | `core/internal/engine`. Keep it unexported |
| Audit records, reports, webhook | `core/pkg/genadb/audit` |
| CLI commands | `core/cmd/genadb`; daemon methods in `core/internal/daemon` |
| Android public API | `android/genadb-android` (Android-specific) and `android/agent-protocol/src/main/kotlin/dev/genadb/sdk` (platform-neutral, JVM-tested) |

The Kotlin SDK is compiled in explicit-API mode. Anything not meant for SDK users must be `internal` or `private`.

## The evaluation harness is locked

`eval.py`, `harness/`, `program.md`, and everything under `docs/research/` (`remote_adb_research_findings.md`, `reports/` and `notes/`) are the fixed benchmark and research record. Do not modify them in pull requests. Improve the product, and record each experiment as a new line appended to `results.tsv`.

Changes that touch the connectivity core should report the `eval.py` score before and after. The score varies by about ±0.03 between runs, mostly from the throughput check.

## Security expectations

These hold for every change:

- The relay must never learn the pairing code, session keys or ADB contents.
- Tampering must never be delivered silently.
- Audit records must never contain tokens, pairing codes, passwords, command arguments or file contents. Add a test when you add a field.
- Do not weaken a security check to make a test pass. If a check is wrong, explain why in the pull request.
- Device tests must be non-destructive. Never reboot, wipe or uninstall anything you did not install, and restore any setting you toggle.

## Pull requests

1. Open an issue first for large changes, so the design can be discussed.
2. Keep each pull request to one logical change, with tests.
3. Make sure `go vet`, `go test -race ./...`, `gofmt -l` (no output) and the Kotlin tests pass.
4. Update `README.md` or `API_SPEC.md` when behaviour or API changes.
5. Describe what you tested, including on which hardware if you tested on devices.

## Commit messages

Use the imperative mood ("Add webhook retry"), with a short summary line and an explanation of why in the body.
