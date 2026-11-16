# Autonomous Research Protocol (`program.md`)

## Objective
Solve the problem defined in `research_draft.md` by iteratively improving `solution.py` to maximize the primary score reported by `eval.py`.

## Strict Rules & Safety Constraints
1. **Single Editable File:** You may ONLY modify `solution.py` (and append logs to `results.tsv`).
2. **Immutable Harness:** You are strictly forbidden from modifying `eval.py`, `research_draft.md`, `program.md`, or any dataset files. If `eval.py` has a bug during Phase 1 setup, fix it ONLY before Phase 2 begins.
3. **Workspace Containment:** Never access, read, or modify files outside `./` (the current repository root).
4. **Time Budget:** Each execution of `python eval.py` must complete within 3 minutes (180 seconds). Kill or optimize any approach that exceeds this time limit.
5. **No Stopping:** Once Phase 2 begins, execute the research loop continuously without pausing to ask for human confirmation until the session ends.

## Logging Format (`results.tsv`)
Maintain a tab-separated file `results.tsv` with these exact columns:
`commit_hash	iteration	score	status	hypothesis_summary`
* `status` must be `KEEP`, `DISCARD`, or `CRASH`.

## Autonomous Loop (Phase 2)
Repeat the following steps endlessly:
1. **Analyze:** Read `results.tsv`, `research_draft.md`, and `solution.py`. Formulate a clear, non-trivial hypothesis for why the current best score is limited and how a specific change will improve it.
2. **Edit:** Implement the single focused change in `solution.py`.
3. **Commit:** Run `git add solution.py && git commit -m "exp <N>: <short hypothesis>"`.
4. **Evaluate:** Run `python eval.py > run.log 2>&1`. Extract the final `SCORE:` value from `run.log`.
5. **Decide:**
   * **If `SCORE` strictly improves** over the previous best score: Log `KEEP` in `results.tsv` and keep the commit as the new baseline.
   * **If `SCORE` is equal or worse, or the run crashes/times out:** Log `DISCARD` or `CRASH` in `results.tsv`, then revert `solution.py` immediately using `git reset --hard HEAD~1` (preserve `results.tsv` before resetting).
