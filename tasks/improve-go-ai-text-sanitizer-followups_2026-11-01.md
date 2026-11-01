# go-ai-text-sanitizer — Follow-ups after the improvement plan

- **Date:** 2026-11-01
- **Parent plan:** [`improve-go-ai-text-sanitizer_2026-11-01.md`](improve-go-ai-text-sanitizer_2026-11-01.md)
- **State of the work:** everything below the "Done" line is still open.
  - The implementation is in the working tree, **not committed**.
  - Verified locally (macOS/arm64, Go 1.25.1):
    - `go test -race ./...`, `go vet`, `gofmt` and `staticcheck` all clean;
    - about 5 minutes of fuzzing with no open failures;
    - every Unicode 18.0 fully-qualified emoji sequence round-trips.
  - CI has **not run on GitHub yet**.

## 1. What was done

Each phase of the plan was implemented. The decisions from §5 of the plan were taken as recommended:

| Decision | Taken |
|---|---|
| D1 | `rewrite` removed. `SanitizeWithRewrite`/`RewriteStrategy` are deprecated no-op shims; `--rewrite` errors unless `none`. |
| D2 | No real NFKC. `FoldCompatibility` uses generated tables; `Nfkc` is a deprecated alias. |
| D3 | Script-aware joiners are kept by default (`KeepScriptFormatting`). |
| D4 | JSON switched to snake_case. `Finding.Rule` added; `Finding.Category` is now the coarse group. |
| D5 | Boilerplate and Markdown rules exist, opt-in only. |
| D6 | Private-use characters are detect-only by default; ChatGPT's U+E200–E202 construct is removed as an artifact. |

Highlights:

- **Unicode tables.** Generated from Unicode 18.0.0 by `internal/ucdgen` (`go generate ./aisanitizer`).
- **Engine.** Rule registry plus a single-pass, copy-on-write character engine. Post-character stages repeat until the text is stable, which keeps `Sanitize` idempotent. Offset maps report findings against the original input.
- **Performance.**
  - Clean text runs at about 200–480 MB/s with 2 allocations per call (was 8.8 MB/s and 312 allocations).
  - Worst-case dirty text runs at about 69 MB/s.
  - The `plain` preset runs at about 75 MB/s.
- **Artifact rules.** All of the plan's artifact rules are implemented, plus tracking parameters and protected regions. Removal tidies the surrounding whitespace.
- **Hidden-payload decoders.** Tag characters, variation selectors, invisible operators, zero-width binary and trailing whitespace. Plus homoglyph detection and opt-in folding, and `Report.Risk`.
- **CLI.**
  - Flags may follow file names; multiple files and directories with `--include`/`--exclude`.
  - Modes: `--check`, `--diff`, and `--format text|json|sarif`.
  - Atomic in-place writes that keep file permissions, with `--no-backup`.
  - Strict UTF-8 handling (`--invalid-utf8`); `--preset`, `--rule`/`--no-rule`, `--list-rules`.
- **Tests.**
  - Unit, golden-corpus, emoji-test, script, CLI, fuzz (2 targets), benchmark and example tests.
  - A test that keeps the README rules table in sync.
  - A test that forbids literal invisible characters in `.go` sources.
- **CI and release.**
  - CI matrix (Linux/macOS/Windows) plus lint, fuzz-smoke and an informational benchstat job.
  - A nightly workflow for long fuzzing and checking that the Unicode tables are up to date.
  - GoReleaser (6 platforms, checksums, SBOM) wired into release-please.
  - A GitHub Action (`action.yml`) and pre-commit hooks.
- **Docs.** README, PRD and package docs updated.

### Deviations from the plan

| Plan item | What was done instead | Why |
|---|---|---|
| T1.2 option name `KeepScriptJoiners` | `KeepScriptFormatting` | It also covers Mongolian selectors, Hangul fillers and ideographic/standardized variation sequences, not just joiners. |
| T1.6 `SanitizeE` / `InvalidUTF8=Error` | `CheckUTF8(text) error` plus `InvalidUTF8Replace`/`Drop`. The CLI defaults to an error. | Keeps `Sanitize` error-free and its output always valid UTF-8. |
| §3.3 streaming `NewWriter`/`SanitizeReader` with chunking | `SanitizeReader` buffers the whole input; `SanitizeBytes` added | See W1: chunking interacts badly with document-level rules. |
| T1.10 `--check` "lists offending files" | `--check` lists files that **would change** (like `gofmt -l`). Detect-only findings, such as private use or homoglyphs, are reported by `--detect-only`. | Clean exit semantics for pre-commit and CI. |
| T2.2 separate ASCII fast path | No separate fast path. The engine's inner loop skips printable ASCII byte-wise, which reached 340 MB/s. | Simpler, and fast enough. |
| T2.5 benchmark gate (fail at >15% regression) | Informational benchstat summary on PRs | Shared runners are too noisy to gate reliably. See W3. |
| T3 `oai_citation` "keep URL" sub-option | The whole construct is removed | Pending decision OD4. |
| T4.1 detect-only findings for Egyptian format controls and Arabic prepended marks | Not implemented | See W5. |
| `MaxBlankLines` | `0` means 1 (so the zero value keeps paragraphs) and a negative value means no limit. "Remove all blank lines" can't be expressed. | Keeps a zero `Options` value safe. |
| `Detect` | `Report.Changes` is always zero; findings carry the would-be action | Avoids confusing "changes" in a read-only call. |

### Code-review fixes (2026-11-01)

A `/code-review medium` pass found 10 bugs. All are fixed, each with a regression test (`aisanitizer/review_fixes_test.go`, plus two CLI tests in `cli_test.go`):

- HTML entities inside inline code and fenced blocks are left alone.
- The GitHub Action writes SARIF to `$RUNNER_TEMP` by default, always excludes the report from the scan, and exposes the path as `outputs.sarif-file`.
- Files found by a directory walk that are not valid UTF-8 are skipped with a warning; files named explicitly still fail under `--invalid-utf8=error`.
- Directory walks skip `*.bak`, so `-i` no longer rewrites its own backups.
- Boilerplate removal never removes every line of the text.
- The Markdown heading rule keeps `C#`/`F#`: a closing `#` sequence needs whitespace before it.
- `KeepTabs`/`KeepNewlines = false` folds only while the `control` rule is on.
- With `KeepNewlines = false`, U+2028, U+2029 and NEL become spaces in one pass, so the result is idempotent.
- `DashComma` treats a run of dashes (`——`, `— —`) as one dash.
- `EXCESS BLANK LINE` counts lines, not bytes.

---

## 2. Open decisions (need the maintainer)

| ID | Question | Options / recommendation |
|---|---|---|
| OD1 | **When to delete the deprecated APIs?** These are `SanitizeWithRewrite`, `RewriteStrategy` and its constants, `ChangeStats.RewrittenSegments`, `Options.Nfkc`, `Options.NormalizeDashes`, `Options.KeepBidi`, and the `--nfkc`, `--normalize-dashes` and `--rewrite` flags. | Recommend: one minor release with the shims, then delete them before tagging v1.0.0. |
| OD2 | **Release and versioning.** This change set breaks the JSON field names, `Finding.Category` semantics and several CLI behaviours (see §4). What version should it ship as? | Recommend: ship as `v0.x` with `feat!:` commits so release-please bumps correctly, then freeze the API and tag `v1.0.0` after OD1. |
| OD3 | **Normalize NBSP (U+00A0) and IDEOGRAPHIC SPACE (U+3000) by default?** NBSP is common in legitimate web copy and U+3000 is standard CJK typesetting. Both are currently replaced with U+0020 by default; only U+202F has a reported watermark use. | (a) Keep as is. (b) Default to keeping U+3000 when it sits between CJK characters, like `KeepFrenchSpacing`. (c) Move NBSP to opt-in. Recommend (b). |
| OD4 | **What should removing `[oai_citation:N‡source](url)` leave behind?** Removing it can leave dangling words ("Source: and https://…"). | (a) Remove it, as now. (b) Replace it with the bare URL. (c) Add an option. Recommend (c), defaulting to (a). |
| OD5 | **Should `--detect-only` fail on any finding or on a risk level?** It currently exits 2 on any finding, including low-risk NBSP and detect-only source pills. | Recommend adding `--fail-on none\|low\|high` (default `low`) and the same input to the GitHub Action. |
| OD6 | **Real NFC/NFKC** (D2 was deferred). | Only if users ask: an optional sub-package `aisanitizer/norm` importing `golang.org/x/text/unicode/norm`, keeping the core zero-dependency. |
| OD7 | **Unicode upgrade policy.** The nightly job only checks that the committed tables match a fresh generation of the *pinned* version. | Recommend: bump `-unicode` in `tables.go` and `emoji-test` each September (new Unicode release) via a tracked issue. |
| OD8 | **Homebrew tap.** It needs a `homebrew-tap` repo and a token secret. | Create `iSerter/homebrew-tap`, then add a `brews:` section to `.goreleaser.yaml` and a `HOMEBREW_TAP_TOKEN` secret. |

---

## 3. Remaining work

### P0 — before merging

- [ ] **W0. Commit and open a PR.** Suggested split:
  1. `internal/ucdgen` + generated tables + `.gitattributes`;
  2. library rewrite + tests;
  3. CLI;
  4. CI/release/Action/pre-commit;
  5. docs.

  Use `feat!:` / `BREAKING CHANGE:` footers (see §4).
- [ ] **W0.1 First CI run.**
  - Watch for Windows-specific issues: paths in `--check` output and in-place temp files.
  - `.gitattributes` keeps golden files byte-exact; confirm it on a Windows checkout.
  - Confirm `staticcheck@2025.1.1` works with the Go version in `go.mod`, or bump it.
- [ ] **W0.2 Migration notes.** Add a "Breaking changes / migration" section to the release notes (see §4).

### P1

- [ ] **W1. True streaming.**
  - Implement `NewWriter` / chunked `SanitizeReader` for very large inputs.
  - Constraints:
    - split only at blank lines outside fenced code;
    - carry fence state, the blank-line count and RTL presence (BidiAuto currently scans the whole document) across chunks;
    - buffer trailing whitespace for `Trim`;
    - keep the fixpoint loop per chunk.
  - Add a property test: chunked output must equal whole-input output.
- [ ] **W2. Real-world samples.**
  - The golden corpus is synthetic, built from documented formats. Replace or augment it with captured outputs from ChatGPT (search, file search, canvas), Gemini, Perplexity, Grok, Copilot and Claude.
  - Verify the formats marked unverified in the plan's Appendix A:
    - the `navlist`/`fetch` variants of `turn…` tokens;
    - Grok card variants;
    - whether `utm_source=claude.ai`/`gemini` actually occur;
    - the primary source for the U+202F watermark claim.
- [ ] **W3. Benchmark gate.** Run benchmarks on a stable self-hosted runner, or compare with `benchstat` against a stored baseline, and fail on more than 15% regression. Today's job only reports.
- [ ] **W4. GitHub Action and pre-commit validation.**
  - Exercise `action.yml` in a sample repo, including SARIF upload to code scanning.
  - Make the default `version` follow the action ref (`github.action_ref`) instead of `latest`.
  - Publish to the Marketplace.
  - Run both pre-commit hooks in a real repo.
- [ ] **W5. Detect-only coverage gaps.**
  - Egyptian hieroglyph format controls U+13430–1343F.
  - Arabic/Kaithi prepended concatenation marks: U+0600–0605, U+06DD, U+070F, U+0890–0891, U+08E2, U+110BD, U+110CD.
  - Visible blanks U+13441–13442.

  Their names are already in the generated tables.
- [ ] **W6. Finding noise.** When a `stego.tag_payload` finding decodes a payload, the per-letter `tag_char` findings (one per distinct tag letter) clutter the text output. Collapse them into a single `tag_char` finding per run, or hide them in `Report.String()`.
- [ ] **W7. OD4 implementation:** `oai_citation` keep-URL option.
- [ ] **W8. OD5 implementation:** `--fail-on` risk threshold (CLI + Action).

### P2

- [ ] **W9. Homebrew tap** (OD8) and a `brew install` line in the README.
- [ ] **W10. WASM build and demo page** ("paste text → see highlighted invisible characters", using `Reveal`).
- [ ] **W11. Artifact regex performance.** Merge the citation regexes into one alternation with named groups. Dirty text is about 69 MB/s, dominated by `regexp` and per-match allocations.
- [ ] **W12. Markdown heuristics.** Markdown stripping is regex-based and heuristic. Known gaps:
  - setext headings (`===`/`---` underlines);
  - reference-style links;
  - tables;
  - nested emphasis such as `***x***` inside words.

  Consider a tiny line-oriented parser if users rely on it.
- [ ] **W13. Diff for huge rewrites.** `--diff` caps the Myers search at 4096 edits and then falls back to replacing the whole file. Consider patience/histogram diff for very large files.
- [ ] **W14. Godoc polish.** Document individual `ChangeStats` fields and the remaining exported constants. Consider `revive`/`staticcheck -checks ST1020,ST1021` in CI.
- [ ] **W15. Unicode bump automation** per OD7.

---

## 4. Breaking changes to announce (for W0.2)

**Library:**

- JSON field names are now snake_case (`modified`, `changes.removed_zero_width`, `findings[].rule`, …).
- `Finding.Category` is now the group (`invisible`, `artifact`, …). The fine-grained ID is `Finding.Rule`.
- `Detect` now honours `opts`, returns deterministic, sorted findings and includes detect-only rules.
- `Report.HasWatermarks` ignores typography/whitespace findings. Use `HasFindings` for "anything".
- Citation removal now tidies whitespace: `"text (oaicite:0){index=0} more"` → `"text more"`, no longer a double space.
- `Nfkc` now means the generated compatibility fold; `…` becomes `...` instead of `.`.
- `CollapseWhitespace` keeps paragraph breaks and leading indentation, preserves CRLF and strips trailing spaces.
- Smart-quote normalization maps `‹›` to `'`, no longer `<>`.
- Rewriting is gone; `SanitizeWithRewrite` ignores its strategy.

**CLI:**

- `--detect-only` no longer echoes the input. It exits 2 when there are findings, even without `--strict`.
- Invalid UTF-8 input is an error (exit 1) unless `--invalid-utf8=replace|drop`.
- `--rewrite` with any value except `none` is an error.
- `.bak` files keep the source file's permissions, and unchanged files are no longer rewritten.
- Directory walks skip `*.bak` files, and skip (with a warning) files that are not valid UTF-8.
- The Action's `sarif-file` input now defaults to `$RUNNER_TEMP/ai-text-sanitizer.sarif`; read the path from `outputs.sarif-file`.
