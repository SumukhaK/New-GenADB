# Autonomous Research Protocol (`program.md`)

## Objective
Solve the problem specified in **`remote_adb_research_findings.md` §16** (this replaces the separate `research_draft.md` originally referenced here). The deliverable is a secure, resilient remote-ADB connectivity core (`genadb`: relay, device agent, desktop connect agent/CLI) in `./core`. Iteratively improve it to maximise the `SCORE:` reported by `eval.py`. Higher is better, and the maximum is 100.

## Strict Rules & Safety Constraints
1. **Editable surface:** You may ONLY modify `solution.py` and files under `core/`, and append logs to `results.tsv`.
2. **Immutable harness:** You are strictly forbidden from modifying `eval.py`, anything under `harness/`, `program.md`, `remote_adb_research_findings.md`, `reports/` or `research_notes/`. Harness fixes were allowed only during Phase 1.
3. **No gaming:**
   - The solution must not read `eval.py` or `harness/`, inspect the test environment, or special-case canary strings, ports, process names or scenario names.
   - Security properties must be real. Use standard primitives (e.g. X25519/Ed25519, HKDF, ChaCha20-Poly1305/AES-GCM, or TLS 1.3/Noise) with no hard-coded keys.
   - End-to-end keys must not be derivable from anything the relay sees.
   - The pairing code must never reach the relay in any encoding. Use a PAKE or an equivalent design.
   - Never weaken the authorised path to make a denial pass.
4. **Workspace containment:** Never access, read, or modify files outside `./`. Exceptions: the Go module/build cache and the temporary directories that `eval.py` creates.
5. **Time budget:** Each execution of `python eval.py` must complete within 3 minutes (180 seconds). Kill or optimise any approach that exceeds this.
6. **No stopping:** Once Phase 2 begins, run the research loop continuously without pausing for human confirmation until the session ends or the time budget given at kickoff is used up.
7. **Git:** Commit only on the designated working branch. Push it after every `KEEP` (`git push -u origin <branch>`). Never force-push.

## Logging Format (`results.tsv`)
Maintain a tab-separated file `results.tsv` with these exact columns:
`commit_hash	iteration	score	status	hypothesis_summary`
* `status` must be `KEEP`, `DISCARD`, `CRASH`, or `BASELINE` (iteration 0 only).

## Autonomous Loop (Phase 2)
Repeat the following steps:
1. **Analyze:** Read `results.tsv`, `remote_adb_research_findings.md` §16, the code in `core/`, and the per-check `CHECK`/`NOTE` lines of the last `run.log`. Form a clear, non-trivial hypothesis about why the current best score is limited and how one specific change will raise it.
2. **Edit:** Implement that single focused change in `core/` (and `solution.py` if needed). Run `go vet ./...` in `core/` before evaluating.
3. **Commit:** `git add solution.py core && git commit -m "exp <N>: <short hypothesis>"`.
4. **Evaluate:** `python eval.py > run.log 2>&1`, then extract the final `SCORE:` value from `run.log`.
5. **Decide.** Measured noise is about ±0.05, so a change only counts if it beats the previous best by **≥ 0.10**:
   * **If `SCORE` improves by ≥ 0.10:** log `KEEP` in `results.tsv` and keep the commit as the new baseline.
   * **If `SCORE` is equal or worse, or the run crashes or times out:** log `DISCARD` or `CRASH` in `results.tsv`. Save `results.tsv` aside first, then revert with `git reset --hard HEAD~1`, then restore `results.tsv`.
   * Never `KEEP` a change that lowers any `C.*` or `T.tamper_never_silent` check, even if the total rises.
