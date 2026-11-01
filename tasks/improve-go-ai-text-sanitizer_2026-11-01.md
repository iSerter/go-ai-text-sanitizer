# Improve go-ai-text-sanitizer — Plan

- **Date:** 2026-11-01
- **Status:** Implemented on 2026-11-01 (uncommitted working tree), with decisions D1–D6 taken as recommended. Deviations, open decisions and remaining work: [`improve-go-ai-text-sanitizer-followups_2026-11-01.md`](improve-go-ai-text-sanitizer-followups_2026-11-01.md)
- **Scope:** `aisanitizer/` library, `cmd/ai-text-sanitizer/` CLI, tests, CI/release, docs

## 1. Direction & guiding principles

This project is a **static, deterministic, programmatic sanitizer**: it detects and removes/replaces invisible
Unicode watermarks, steganographic payloads, and visible LLM transport artifacts ("footprints"). It is **not** a
humanizer.

1. **No LLM calls, no paraphrasing, no randomness.** Same input + same options ⇒ same output, always.
2. **Never break legitimate text.** Emoji sequences, Persian/Arabic/Indic joiners, RTL text, French typography, code
   and URLs must survive default settings. When a character is ambiguous, *detect* by default and *remove* only on
   opt-in.
3. **Zero runtime dependencies** in the core package. Generated tables (via `go:generate` from Unicode data files) are
   fine; importing `golang.org/x/text` is only acceptable in an optional sub-package (see Decision D2).
4. **Detect and Sanitize agree.** Both are driven by one rule registry, so every finding has a matching removal rule
   and vice versa.
5. **Every change is accounted for** in the report (per rule, with positions when requested).
6. **Fast.** Meet the PRD's own target of ≥ 50 MB/s with default options. Today it is ~9 MB/s (see §2.3).

### Explicitly out of scope

- LLM/API-based rewriting or paraphrasing (all four reference repos' core feature).
- Meaning-changing phrase/synonym substitution (e.g. StealthHumanizer's `leverage→use`, `in order to→to` lists,
  lynote's vocabulary map), random punctuation noise, sentence reordering, burstiness injection.
- Defeating statistical/token-level watermarks (SynthID, green-list) or neural AI detectors. That is already a non-goal in `PRD.md`.

---

## 2. Review findings (current state)

Everything below was reproduced against `main` @ `8a36890` with throwaway probe tests and the built CLI.

### 2.1 Correctness bugs (confirmed)

| # | Area | Problem | Evidence |
|---|------|---------|----------|
| B1 | Emoji protection | `findEmojiSequences` returns **rune** indices, `removeCategory` checks **byte** offsets (`for i, r := range s`). Protection also isn't recomputed after each removal pass shifts offsets. Result: emoji ZWJ sequences get broken with `KeepEmoji=true` (the default). | `👨\u200D👩\u200D👧` → `👨\u200D👩👧`; `héllo 👨\u200D👩\u200D👧` → `héllo 👨👩👧`; `🏳\uFE0F\u200D🌈` → `🏳🌈`; `❤\uFE0F` → `❤`; keycap `1\uFE0F\u20E3` → `1\u20E3` |
| B2 | Emoji protection | `KeepEmoji` VS filter tests whether the *selector itself* is an emoji (`isEmojiExtendedPictographic(r)` with `r` = VS), which is never true, so the filter has no effect. | `sanitizer.go:37-45` |
| B3 | Persian/Indic | ZWNJ/ZWJ are removed unconditionally. They are orthographically required in Persian, Urdu, Kurdish, and Indic scripts. | `می\u200Cخواهم` → `میخواهم` |
| B4 | CollapseWhitespace | `\r\n` becomes `\r`. Paragraph breaks `\n\n` collapse to `\n`. The PRD says "trim line-end spaces", but they are not trimmed. Dropped newlines aren't counted in the report. | `a\r\nb`→`a\rb`; `a\n\nb`→`a\nb`; `a   \nb`→`a \nb` |
| B5 | "NFKC" | This is a ~140-entry hand table, not NFKC. Problems: `…`→`.` (should be `...`), `‥`→`.`. Soft hyphen→`-` and Word Joiner→space when they should be removed. It runs **before** the invisible-char removal, so watermark chars get silently converted and never reported. Ligatures (`ﬁ`), circled digits, and superscripts are untouched. None of its changes are counted. | `wait…`→`wait.`; `a\u2060b`→`a b` (0 changes) |
| B6 | Citations | Only `(oaicite:N){index=N}` is matched. The common ChatGPT form `:contentReference[oaicite:0]{index=0}` is left intact, and so are all other artifact formats (§4.3). | `contentReference` probe: 0 changes |
| B7 | Model artifacts | `RemoveModelArtifacts` is a **no-op** (`sanitizer.go:82-83`) even though it is on by default, advertised, and counted. | — |
| B8 | Coverage gaps | Not detected or removed: U+FFF9–FFFB, U+1BCA0–1BCA3, U+2065, U+206A–206F, U+180F, U+FFF0–FFF8, U+E0080–E0FFF, PUA (ChatGPT's U+E200–E202 citation wrappers), noncharacters, U+0085 (NEL). | `missed invisibles` probe: 0 changes |
| B9 | Invalid UTF-8 | Invalid bytes are silently turned into U+FFFD and not reported. PRD promises exit code 1 for invalid UTF-8. | `a\xffb` → `a\uFFFDb`, 0 changes |
| B10 | Smart quotes | `‹ ›` are mapped to `< >`, which changes meaning and can fabricate HTML-like tags. They should map to `'`, or to `"` for guillemet consistency. | `‹y›` → `<y>` |
| B11 | Detect | `Detect` ignores `opts` entirely. It uses predicates that differ from Sanitize (e.g. reports NBSP as a "watermark"). Finding order is **non-deterministic** because it ranges over a map. | 3 runs → 2 different orders |
| B12 | Names | `variationSelectorName` is off by one (FE00 is VS1, not "VS-0"). For FE0A–FE0F it produces non-digits (`VARIATION SELECTOR-?`). | probe output |
| B13 | Report | `Trim` changes are not counted. `ChangeStats`/`Finding` have no JSON tags, so the JSON uses Go CamelCase. `Finding.Index` is a byte offset of the first hit only, and that isn't documented. | `-r` output |
| B14 | Duplication | `U+180E` is in both `isFormatChar` and `isExoticSpace`. `nfkcCompat` duplicates the quote/dash/space tables. `normalizeLineSeparators` has a dead `i` counter. `isLineSeparator` is unused. | — |
| B15 | Control strip | ESC (`\x1b`) is removed but the rest of an ANSI sequence stays (`[31m` debris). If `KeepNewlines=false`, newlines are deleted rather than replaced with a space, so words join. | — |

### 2.2 CLI bugs (confirmed)

| # | Problem | Evidence |
|---|---------|----------|
| C1 | Go's `flag` stops parsing at the first positional argument. The **README's own example** `ai-text-sanitizer draft.txt -o clean.txt` silently ignores `-o` and writes to stdout. | `clean.txt` not created, exit 0 |
| C2 | `--detect-only` echoes the whole input to stdout. Usage text says it exits 2 on findings, but it only does so with `--strict`. | exit 0 with findings |
| C3 | An invalid `--rewrite` value is silently accepted as `none`. | `--rewrite bogus` → exit 0 |
| C4 | `--in-place`: the `.bak` file is created `0644` regardless of the source mode, so a `0600` file's backup becomes world-readable. The write is not atomic (no temp + rename). | `-rw-------` source → `-rw-r--r--` backup |
| C5 | Rule toggles are one-directional (`--no-*` for defaults, enable-only for opt-ins). There's no `--[no-]` symmetry as in the PRD, no `--help` listing of all rules, and `--nfkc` + flags conflict silently. | — |
| C6 | Only one input file. No multi-file/glob/directory support and no `--check` mode for CI over many files. | — |

### 2.3 Performance (measured, Apple M4)

| Benchmark (≈2 MB input) | Throughput | Allocs/op |
|---|---|---|
| `CleanText` on clean text with some emoji/accents | **8.8 MB/s** | 312 (26 MB) |
| `CleanText` on dirty text (ZW, NBSP, citations) | **12.2 MB/s** | 20,086 (27 MB) |
| `Detect` | 85.8 MB/s | 160,033 |

Root causes:

- About 12 sequential passes, each re-encoding the whole string even when nothing matches.
- `[]rune(s)` conversion plus a `map[int]bool` lookup per rune for emoji protection.
- `fmt.Sprintf` per matched rune in Detect.
- Regex runs without a literal prefilter.

### 2.4 The `rewrite` feature contradicts the project's direction

`rewrite.go` (`RewriteLight`/`RewriteAggressive`) is a crude "humanizer":

- `RewriteLight` **converts straight quotes into curly quotes**, which re-introduces a typographic AI footprint, and it is buggy: `"hi"` → `“hi“` (two opening quotes).
- It splits the last sentence into a paragraph using byte slicing (`first[:1]`), which corrupts multi-byte first letters.
- `RewriteAggressive` swaps words *toward* stereotypical LLM vocabulary (`use→utilize`, `also→moreover`, `important→crucial`).
- It uses a fixed seed `42`, its tests assert nothing, and it changes meaning.

→ See Decision D1. Recommendation: **remove it**.

### 2.5 Engineering hygiene

- `gofmt -l` flags `options.go`, `report.go`, `cmd/ai-text-sanitizer/main.go`.
- No CI that runs tests, vet, or lint. The only workflow is release-please.
- The release builds a single **linux/amd64** binary, even though the PRD promises macOS/Linux/Windows × amd64/arm64. The Makefile references GoReleaser, but there is no `.goreleaser.yaml`, and `--rm-dist` is deprecated.
- Tests:
  - No CLI tests, fuzz tests, golden corpus, or benchmarks.
  - The emoji test only checks that the base emoji survives, so it misses B1.
  - The rewrite tests assert nothing.
  - The hand-rolled `contains` helpers duplicate `strings.Contains`.
- No godoc comments on exported identifiers. The PRD lists `MustSanitize` and `detect_test.go`, which don't exist.

---

## 3. Target architecture

### 3.1 Rule registry (single source of truth)

```go
type RuleID string // "zero_width", "tag_char", "artifact.oai_content_reference", ...

type Rule struct {
    ID          RuleID
    Category    string        // report grouping
    Description string        // for --list-rules / docs
    Default     bool
    Kind        RuleKind      // CharRule | PatternRule | LineRule
    // CharRule: classification via generated table + optional context predicate
    // PatternRule: literal prefilter + RE2 regex + replacement
}
```

- `Options` keeps its boolean fields for backward compatibility, but they map onto rule IDs. An additional
  `Options.Rules map[RuleID]bool` / `Enable(...)` / `Disable(...)` lets new rules land without new struct fields.
- `Detect` and `Sanitize` both iterate the same registry, so Detect honours `opts` (fixes B11).
- `--list-rules` and the README rules table are generated from the registry.

### 3.2 Single-pass character engine

- **Generated classification table.** `go:generate` reads `DerivedCoreProperties.txt`, `PropList.txt`, `UnicodeData.txt` and `emoji-data.txt` and emits `tables_gen.go`. That file holds a compact range table mapping rune → category bitset, plus character names. Unicode version is pinned and recorded in the file header. This also kills the hand-written name switches and B12.
- **ASCII fast path.** If the input has no byte ≥ 0x80 and no C0 controls other than `\t\n\r`, skip the char engine entirely and run only the pattern rules, behind literal prefilters.
- **Copy-on-write.** Scan without allocating, and allocate the output builder only at the first change.
- **Context-aware decisions in the same pass.** Keep a small window of prev/next runes and a grapheme-ish state machine to decide whether a ZWJ, ZWNJ or VS is legitimate (§4.2). No `[]rune` conversion and no maps.
- **Pass order.** Decode targeted HTML entities → char rules → pattern rules (artifacts, protected regions honoured) →
  typography → whitespace. Patterns run after invisible removal, so `oai\u200Bcite` can't evade the regex.
- **Validation.** Have one test assert that the composed pipeline is idempotent (`Sanitize(Sanitize(x)) == Sanitize(x)`).

### 3.3 Streaming API (large files / pipes)

- `NewWriter(w io.Writer, opts) *Writer` and `SanitizeReader(r io.Reader, w io.Writer, opts) (*Report, error)`. They process line-buffered chunks, carrying over a bounded tail so patterns and grapheme context don't split across chunks.
- Add `SanitizeBytes([]byte, *Options) ([]byte, *Report)` to avoid string↔[]byte copies in the CLI.

---

## 4. Work plan

Priorities: **P0** = correctness/trust, **P1** = core value, **P2** = nice to have.

### Phase 0 — Safety net first (P0)

Do this phase before touching behaviour, so regressions are visible.

- [ ] **T0.1** Run `gofmt` on everything. Add CI (`.github/workflows/ci.yml`) running `go vet`, `gofmt -l` check, `staticcheck`, and `go test -race ./...` on Linux/macOS/Windows.
- [ ] **T0.2** Add a golden corpus `aisanitizer/testdata/golden/*.txt` with matching `*.want.txt` and `*.report.json` files, plus a `-update` flag. Seed it with:
  - real-world samples of each artifact family (§4.3);
  - emoji torture text: ZWJ families, flags, subdivision flags 🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F, keycaps, skin tones, VS15/VS16;
  - Persian/Arabic/Hindi/Bengali text with ZWNJ/ZWJ;
  - Hebrew/Arabic with legitimate RLM;
  - French text with U+202F;
  - Mongolian text;
  - code blocks and URLs.
- [ ] **T0.3** Add benchmarks (`bench_test.go`) on fixed corpora covering ASCII, Latin-1-heavy, emoji-heavy, CJK, and dirty inputs. Record the baseline numbers from §2.3 in the PR description.
- [ ] **T0.4** Add native fuzz tests (`FuzzSanitize`) with these properties:
  - output is valid UTF-8;
  - idempotent;
  - with defaults, output contains no rune that a default-on rule would remove;
  - `Detect(x)` is non-empty ⇔ `Sanitize(x)` modified it (for char rules);
  - no panics.
- [ ] **T0.5** Add CLI tests (`cmd/.../main_test.go`) using `testscript` or plain `exec` against a built binary. Cover stdin/stdout, `-o`, `-r`, `-i`, exit codes, flags after positional args, and invalid UTF-8.

### Phase 1 — Fix confirmed bugs (P0)

- [ ] **T1.1** (B1, B2) Rewrite emoji protection on byte offsets inside the single-pass engine (or as an interim fix: recompute the protected set per pass using byte offsets). Use `emoji-data.txt` `Extended_Pictographic` + `Emoji_Modifier` + `Regional_Indicator` and the RGI emoji sequence grammar:
  - keep VS16/VS15 only directly after an emoji or keycap base;
  - keep ZWJ only between two emoji elements;
  - keep tag chars only in a valid `U+1F3F4 (E0061–E007A)+ E007F` subdivision flag sequence.

  Acceptance: every sample in `emoji-test.txt` (fully-qualified) round-trips unchanged.
- [ ] **T1.2** (B3) Make ZWNJ/ZWJ context-aware using the RFC 5892 Appendix A.1/A.2 (IDNA CONTEXTJ) rules. ZWNJ/ZWJ stays when it follows a virama, or when ZWNJ sits between joining-type letters (Arabic-script `L/D … R/D`). Make this behaviour the default as `KeepScriptJoiners: true`. A stray ZWJ/ZWNJ in Latin text is still removed.
- [ ] **T1.3** (B4) Rewrite `CollapseWhitespace`:
  - preserve `\r\n` as a unit;
  - cap blank lines at a configurable `MaxBlankLines` (default 1, which keeps paragraphs);
  - strip trailing spaces/tabs per line (this also defeats SNOW whitespace stego);
  - count every removed char.
- [ ] **T1.4** (B5) Replace the fake `Nfkc`:
  - Rename the concept to `FoldCompatibility`. Keep `Nfkc` as a deprecated alias for one minor version.
  - Back it with a generated table of `<compat>/<wide>/<narrow>/<font>/<super>/<sub>/<circle>/<fraction>` decompositions from `UnicodeData.txt`, restricted to targets that are ASCII or Latin-1. That covers ligatures, fullwidth, math alphanumerics `𝐀→A`, enclosed alphanumerics, superscripts, and so on.
  - Run it **after** invisible-char removal and count its changes.
  - Map `…` to `...`, not `.`.
  - Real NFC/NFKC: see D2.
- [ ] **T1.5** (B6, B7) Implement artifact rules (Phase 3) so `RemoveCitations`/`RemoveModelArtifacts` actually work. At minimum, fix `contentReference` now.
- [ ] **T1.6** (B9) Validate UTF-8. Library: add `Options.InvalidUTF8` with values `Replace` (current behaviour, but counted as `ReplacedInvalidUTF8`), `Drop`, or `Error`. Make `Sanitize` errors surface via a new `SanitizeE` or the existing `Detect`-style error return. CLI: exit 1 with byte offset, unless `--invalid-utf8=replace|drop`.
- [ ] **T1.7** (B10) Map `‹›` to `'`, keep `«»` → `"`, and add U+02BC, U+2032/2033 (primes, opt-in), U+FF02/FF07 to the quote table.
- [ ] **T1.8** (B11–B13) Detect fixes:
  - Detect honours options.
  - Findings are sorted (by first index, then code point).
  - Add JSON tags (`snake_case`) to `Report`, `ChangeStats` and `Finding`, and add `Finding.RuleID`.
  - Count Trim.
  - Document that `Index` is a byte offset.
  - Add optional `Positions []Position{Byte, Line, Col}` capped by `Options.MaxPositions`.
- [ ] **T1.9** (B14, B15) Remove duplicate and dead code. Strip full ANSI/VT escape sequences (`\x1b\[[0-9;?]*[ -/]*[@-~]`, OSC `\x1b\][^\x07\x1b]*(\x07|\x1b\\)`) as a `control.ansi` rule. When a newline is stripped, replace it with a space.
- [ ] **T1.10** (C1–C6) CLI fixes:
  - Interspersed flag parsing: reorder `os.Args` so flags may follow file args, or use a `flag.FlagSet` loop. Stay zero-dep.
  - `--detect-only` prints nothing to stdout unless `--echo`, and exits 2 when findings are present (documented). `--strict` keeps its meaning for sanitize mode.
  - Reject unknown `--rewrite`/enum values with exit 1. A `0600` source must produce a `0600` backup, and writes are atomic (temp file in the same dir + `os.Rename`).
  - `--no-backup`.
  - Symmetric `--rule=<id>` / `--no-rule=<id>` plus `--list-rules`.
  - Multiple files and directories with `--include`/`--exclude` globs; `--check` mode (like `gofmt -l`) that lists offending files and exits 2.
  - `--format=text|json|sarif` for the detect report. SARIF lets GitHub code scanning annotate PRs.
  - `--diff` to show a unified diff with invisible chars rendered as `⟨U+200B⟩`.

### Phase 2 — Performance (P1)

Target: ≥ 50 MB/s defaults on mixed text, ≥ 300 MB/s on pure ASCII, ≤ 2 allocs/op when the input is unchanged.

- [ ] **T2.1** Implement the generated classification table and single-pass engine (§3.2).
- [ ] **T2.2** ASCII fast path and copy-on-write (return the input string itself when unchanged).
- [ ] **T2.3** Literal prefilters for every pattern rule (`strings.Contains(s, "oaicite")`, `"【"`, `"turn0"`, `"\uE200"`, `"utm_source="`, …) before running a regex. Also consider merging the rules into one alternation regex with named groups.
- [ ] **T2.4** Detect: no `fmt.Sprintf` in the hot loop (use precomputed notation strings), and a fixed-size per-category counter array instead of maps.
- [ ] **T2.5** Benchmark gate in CI with `benchstat`: fail if throughput regresses more than 15%.

### Phase 3 — Visible LLM artifacts ("footprints") (P1)

Implement as `PatternRule`s under `RemoveModelArtifacts` / `RemoveCitations`, each individually toggleable. Patterns
must be RE2-compatible: Go has no lookaround, so use explicit groups and post-checks. Each pattern needs real-world
golden samples. Sources are listed in Appendix A.

| Rule ID | Pattern (sketch) | Action | Default |
|---|---|---|---|
| `artifact.oaicite` | `\(oaicite:\d+\)\{index=\d+\}` | remove | on (exists) |
| `artifact.content_reference` | `:{0,2}contentReference\[oaicite:\d+\]\{index=\d+\}` | remove | on |
| `artifact.oai_citation` | `\[oai_citation:\d+‡([^\]]*)\]\(([^)]*)\)` | keep URL as plain link text, or remove (sub-option) | on |
| `artifact.pua_cite` | `\x{E200}[^\x{E201}]*\x{E201}` (ChatGPT private-use citation wrappers U+E200/E201/E202) | remove | on |
| `artifact.turn_cite` | `\b(?:file)?(?:cite|navlist)?(?:turn\d+(?:search|news|file|image|view)\d+)+\b` (visible leaked form, e.g. `citeturn0search2turn0news1`) | remove | on |
| `artifact.lenticular` | `【\d+(?::\d+)?†[^】]{0,80}】` (`【4:0†source】`, `【85†L261-269】`) | remove | on |
| `artifact.attribution_json` | `\^\[([^\]]+)\]\(\{"attribution":\{[^}]*\}\}\)` → `$1` | unwrap | on |
| `artifact.gemini_cite` | `\[cite:\s*\d+(?:,\s*\d+)*\]` and `\[cite_start\]` | remove | on |
| `artifact.gemini_span` | `\[span_\d+\]\((?:start|end)_span\)` | remove | on |
| `artifact.grok_card` | `<grok-card[^>]*>(?:</grok-card>)?` and `\[\]\(grok_render_citation_card_json=\{[^)]*\}\)` | remove | on |
| `artifact.perplexity_tag` | `\[(?:web|attached_file):\d+\]` | remove | on |
| `artifact.writing_block` | `^:::[\p{L}]+\{[^}\n]*\}\s*$` … `^:::\s*$` | unwrap (keep inner text) | on |
| `artifact.tracking_params` | `utm_source=(chatgpt\.com|openai|copilot\.com|perplexity(\.ai)?|claude\.ai|gemini)`, `referrer=grok\.com` inside URLs | remove param, repair `?&`/trailing `?` | on |
| `artifact.html_invisible_entities` | `&#8203;` `&#x200B;` `&zwj;` `&zwnj;` `&nbsp;` `&shy;` `&#xFEFF;` … (only entities that decode to a rule-covered char) | decode, then the char rule handles it | on |
| `artifact.numeric_markers` | `\[\d+(?:[,–-]\s*\d+)*\]` (Perplexity-style `[1]`, `[2,3]`) | remove | **off** (ambiguous with real citations) |
| `artifact.source_pills` | `\b[A-Z][\w .]{1,40}\+\d+\b` (ChatGPT "Wikipedia+1") | **detect only** | on (detect) |
| `artifact.footnote_backlinks` | stray `↩\uFE0E`/`↩` | remove | off |

Also in this phase:

- [ ] **T3.1** **Protected regions.** Before pattern/typography rules, mask fenced code blocks, inline code, URLs and emails (as StealthHumanizer's `protect-regions.ts` does), then restore them. Char-level invisible removal still applies inside protected regions, since watermarks hide in code too, but typography normalization does not. This keeps `--normalize-dashes` from breaking `--flag` or `a—b` inside code, and keeps the tracking-param rule confined to URLs.
- [ ] **T3.2** **Cleanup after removal.** Collapse the gap left by a removed artifact: `"text  more"` → `"text more"`, `"text ."` → `"text."`. Only touch whitespace adjacent to a removal site, never globally (the current `TestRemoveCitations` expects the double space; update it).
- [ ] **T3.3** **Boilerplate lines, opt-in (`RemoveChatBoilerplate`, default off).** This is deterministic, anchored, line-level removal, not rewriting:
  - a leading line that matches an opener (`^(Sure|Certainly|Of course|Absolutely|Here(?:'s| is)…)\b.{0,100}:\s*$`);
  - trailing sign-offs (`^(I hope this helps|Let me know if|Feel free to)…$`);
  - knowledge-cutoff disclaimers (`As of my (?:last )?(?:knowledge|training) (?:cutoff|update)`);
  - `As an AI language model,` prefixes.

  Only whole lines or leading clauses are removed, and each removal is reported with its text.
- [ ] **T3.4** **Markdown leftovers, opt-in (`StripMarkdown`, default off).** For text pasted into plain-text targets:
  - `**bold**`/`__bold__` → `bold`;
  - `#{1,6} Heading` → `Heading`;
  - horizontal rules removed;
  - `[text](url)` → `text (url)` or `text`;
  - list bullets normalised.

  This is useful for email/CMS pipelines and must respect protected regions.

### Phase 4 — Invisible-char coverage & steganography detection (P1)

- [ ] **T4.1** **Coverage from Unicode data.** New default-on rules:
  - Full `Default_Ignorable_Code_Point`: adds U+180F, U+2065, U+206A–206F, U+FFF0–FFF8, U+1BCA0–1BCA3, U+E0080–E0FFF.
  - Interlinear annotation U+FFF9–FFFB.
  - Object replacement U+FFFC.
  - NEL U+0085 → `\n`.
  - Egyptian hieroglyph format controls (detect only).

  A catch-all `remove_other_default_ignorable` rule covers anything in the DI set that no named rule claims, so future Unicode versions are handled by regenerating the tables.
- [ ] **T4.2** **Private Use Area and noncharacters.**
  - PUA (U+E000–F8FF, planes 15–16): **detect by default; removal opt-in**, because PUA is legitimate for icon fonts (Font Awesome, Nerd Fonts). Exception: the ChatGPT U+E200–E202 citation construct, which Phase 3 removes.
  - Noncharacters (U+FDD0–FDEF, U+xFFFE/xFFFF): remove by default.
- [ ] **T4.3** **Script-aware exceptions.** Keep:
  - U+180B–180F inside Mongolian text;
  - Hangul fillers inside Hangul jamo sequences;
  - U+202F between French text and `;:!?»` when `KeepFrenchSpacing` is set (default off, so NNBSP still gets normalised; this is the reported o3/o4-mini watermark);
  - RLM/LRM/ALM in text that contains RTL letters, when `KeepBidi=auto`.

  Make `KeepBidi` a tri-state: `auto` (new default: keep marks in RTL context, always remove overrides U+202A–202E/U+2066–2069 = Trojan Source) | `keep` | `remove`.
- [ ] **T4.4** **Steganography payload detectors** (detect-only findings with decoded preview, `Finding.Payload string`):
  - **ASCII smuggling:** decode tag-char runs U+E0020–E007E → ASCII and show the hidden text. This is the highest-value finding, since it surfaces prompt-injection payloads.
  - **Emoji/VS smuggling:** two or more consecutive variation selectors, or a VS after a non-emoji base. Decode VS17–VS256 bytes (Paul Butler scheme).
  - **"Sneaky Bits":** runs of U+2062/U+2064 decoded as binary.
  - **Zero-width binary:** runs of 8 or more mixed ZW chars (ZWSP/ZWNJ/ZWJ/WJ), decoded as bits with the common mappings.
  - **Whitespace stego (SNOW-style):** trailing space/tab runs at line ends, and unusual space-variant patterns (e.g. NBSP vs space alternating at word boundaries).
  - **Summary:** add `Report.Risk` (`none|low|high`). `high` when a decodable payload or a bidi override is found.
- [ ] **T4.5** **Homoglyphs/confusables.**
  - **Detect** (default on): words that mix Latin with Cyrillic/Greek/Armenian lookalikes, using UTS #39 mixed-script detection with a generated `confusables.txt` subset. For example Cyrillic `а` U+0430 inside `pаypal`.
  - **Fold** (opt-in `FoldConfusables`): fold only *within mixed-script words* to the majority script's skeleton, so legitimate Russian/Greek text is never touched.
  - Also fold Mathematical Alphanumeric Symbols (`𝐇𝐞𝐥𝐥𝐨` → `Hello`) under `FoldCompatibility`.

### Phase 5 — Typographic footprint normalization (P1/P2)

All of these stay **opt-in**, are deterministic, and respect protected regions.

- [ ] **T5.1** **Dash policy.** Replace `NormalizeDashes bool` with `DashStyle`:
  - `keep`;
  - `hyphen` (current behaviour: everything → `-`);
  - `ascii` (em dash → `--`, en dash → `-`);
  - `comma` (em dash used as a parenthetical → `, `, since the em dash is the most-cited AI tell).

  In every style, keep numeric ranges (`1990–2000` → `1990-2000`) and never create `,,` or ` ,`.
- [ ] **T5.2** **Ellipsis and spacing.** `…` → `...`; space-before-punctuation cleanup (` ,` → `,`) only at sites we modified.
- [ ] **T5.3** **ASCII-fold profile.** Opt-in folding of bullets (`•◦▪` → `-`), arrows (`→` → `->`, `⇒` → `=>`), `×` → `x`, `≈` → `~`, `™®©` (keep by default), fraction slash, primes. This is table-driven and lives in the generated file.
- [ ] **T5.4** **Presets.** Library `Preset(name)` and CLI `--preset`:
  - `safe`: invisible chars plus artifacts, nothing visible changes except artifacts;
  - `default` (= `safe` + space normalization);
  - `plain`: `default` + quotes, dashes, ellipsis, compat folding, markdown strip, collapse whitespace;
  - `paranoid`: everything including PUA removal, confusable folding, and boilerplate lines.

### Phase 6 — Remove the rewrite feature (P0, pending D1)

- [ ] **T6.1** Mark `SanitizeWithRewrite`, `RewriteStrategy` and `RewriteLight/Aggressive` `// Deprecated:` in the next minor release. Have them behave as `RewriteNone` plus a deprecation note in the report, or keep them untouched for one release. Remove them in the following minor release (pre-v1, so this is allowed). Remove the `--rewrite` CLI flag, which errors with a pointer to the changelog.
- [ ] **T6.2** Remove `RewrittenSegments` from `ChangeStats`, or leave it as a deprecated always-zero field until v1.
- [ ] **T6.3** Update `PRD.md` §4.5 and the README, and add the non-goal "no rewriting/paraphrasing" explicitly.

### Phase 7 — API polish & docs (P1)

- [ ] **T7.1** Godoc on every exported identifier. Add `example_test.go` with runnable examples (`ExampleCleanText`, `ExampleDetect`, `ExampleSanitize_preset`).
- [ ] **T7.2** `Report` helpers:
  - `Report.Findings` grouped by `RuleID`;
  - `Report.Removed()` (total count of removed or changed runes);
  - `Report.String()` for pretty CLI output with a table;
  - `Report.Merge()` for multi-file runs.
- [ ] **T7.3** Make the `Detector` interface pluggable via `Options.ExtraDetectors []Detector`. This keeps the extension point the PRD promised, for example a user-supplied statistical scorer.
- [ ] **T7.4** README:
  - a rules table generated from the registry, with a test that fails if it's stale;
  - a "what this does / doesn't do" section;
  - a "safe for multilingual text" section;
  - performance numbers;
  - fixed CLI examples.

  Sync `PRD.md`: remove `MustSanitize`, which doesn't exist, or add it.
- [ ] **T7.5** `CHANGELOG.md` is managed by release-please. Use conventional commits. Each phase ships as its own PR.

### Phase 8 — Distribution (P2)

- [ ] **T8.1** Add `.goreleaser.yaml`: darwin/linux/windows × amd64/arm64, checksums, SBOM, `-trimpath`, `CGO_ENABLED=0`, version via ldflags. Wire it into the release-please workflow and fix the Makefile (`--clean`, not `--rm-dist`).
- [ ] **T8.2** Homebrew tap formula and `go install` instructions.
- [ ] **T8.3** **GitHub Action** (`action.yml`) that runs `ai-text-sanitizer --check --format=sarif` over changed files. This is the "CI gate" use case from the PRD.
- [ ] **T8.4** **WASM build** (`GOOS=js GOARCH=wasm` or TinyGo) plus a tiny static demo page for "paste text → see highlighted invisible chars".
- [ ] **T8.5** **pre-commit hook** definition (`.pre-commit-hooks.yaml`).

---

## 5. Decisions needed from the maintainer

| ID | Decision | Recommendation |
|----|----------|----------------|
| D1 | Keep, deprecate, or remove `rewrite.go` / `--rewrite`? | **Remove** (deprecate for one minor release first). It adds AI footprints, changes meaning, and contradicts the static-sanitizer direction. |
| D2 | True NFC/NFKC requires composition tables. Options: (a) generated tables in-repo (large, but zero-dep); (b) optional sub-package `aisanitizer/norm` importing `golang.org/x/text/unicode/norm`; (c) drop it and offer only the targeted `FoldCompatibility`. | **(c) now, (b) later if requested.** `FoldCompatibility` covers the watermark-relevant cases and keeps the core zero-dep. |
| D3 | Default for ZWNJ/ZWJ in scripts (B3): context-aware keep (new) vs. always remove (current). | **Context-aware keep by default.** Stray joiners in Latin text are still removed. |
| D4 | Breaking JSON field names (CamelCase → snake_case) and `Index` semantics. | **Do it now**, pre-v1, in one release with a clear changelog. |
| D5 | Should the opt-in boilerplate-line (T3.3) and markdown-strip (T3.4) rules live here? They are deterministic, but closer to content editing. | **Yes, opt-in only and reported line by line.** Deterministic phrase *substitution* stays out (§1). |
| D6 | PUA default: detect-only vs remove. | **Detect-only** (icon fonts), except the known ChatGPT U+E200–E202 construct. |

## 6. Suggested sequencing

1. **PR 1:** Phase 0, the safety net (CI, golden corpus, fuzz, benchmarks, CLI tests). Expect several tests to fail initially and mark them `t.Skip("B1")` etc.
2. **PR 2:** Phase 1 bug fixes B1–B15 and C1–C6. Un-skip the tests. Remove or deprecate rewrite (Phase 6, per D1).
3. **PR 3:** Phase 2, the rule registry, generated tables and single-pass engine. Benchmarks must hit the targets.
4. **PR 4:** Phase 3 artifacts plus protected regions.
5. **PR 5:** Phase 4 coverage, stego detectors and confusables.
6. **PR 6:** Phase 5 typography presets, then Phase 7 docs.
7. **PR 7:** Phase 8 distribution. Tag `v1.0.0` once the API is frozen.

## 7. Definition of done

- All B*/C* issues have a regression test.
- The golden corpus passes. `emoji-test.txt` fully-qualified sequences, and the Persian/Hindi/Arabic/Hebrew/French/Mongolian samples, survive defaults byte-for-byte.
- The fuzz targets run for at least 5 minutes in CI nightly with no failures.
- Defaults reach ≥ 50 MB/s on the mixed corpus and ≥ 300 MB/s on ASCII, with ≤ 2 allocs/op on unchanged input.
- `Detect` and `Sanitize` agree for every char rule (fuzz property).
- The README rules table is generated and verified in CI. No rewriting code remains (per D1).

---

## Appendix A — References

**Competitor repos reviewed.** Only their static, deterministic parts were considered.

- **rudra496/StealthHumanizer.** Borrowable: `lib/protect-regions.ts` (mask code/URLs/emails before processing), and the `lib/postprocess.ts` em-dash handling with numeric-range protection plus post-removal punctuation tidy-up. Its preamble/sign-off stripping regexes inform T3.3. Not borrowed: phrase/word substitution lists, random noise, and the LLM providers.
- **AhmadHassan-BTed/Turnitout-Humanizer.** Docs/marketing only; no engine code is published. Borrowable ideas are protected-term/LaTeX masking and DOCX run-level processing (possible future input format). Its claims of ZW and C2PA removal couldn't be verified.
- **lynote-ai/humanize-text.** LLM rewriting chains. Nothing borrowable beyond confirming that vocabulary maps are out of scope. Its post-processor actually *adds* em dashes.
- **harshaneel/humanize.** Prompt "skills", not code. Borrowable: its banned-phrase list for openers, sign-offs and knowledge-cutoff lines (T3.3), and the mechanical heuristics (em-dash density, curly quotes) as possible detect-only stats.

**Artifact formats.**

- Wikipedia: *Signs of AI writing / Markup*. https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing/Markup
- OpenAI community, contentReference: https://community.openai.com/t/why-is-chatgpt-adding-content-references/1076836
- OpenAI community, PUA citation markers: https://community.openai.com/t/streamed-web-search-citations-leaking-citation-markers-into-text-output/1390157
- OpenAI community, `citeturn…` leakage: https://community.openai.com/t/unexpected-citation-markers-appearing-in-text-output-when-using-file-search/1362380
- `openai/gpt-oss` `simple_browser_tool.py`: the `【cursor†Lstart-Lend】` format.

**Unicode & steganography.**

- Unicode `DerivedCoreProperties.txt` (Default_Ignorable_Code_Point), `PropList.txt`, `UnicodeData.txt`, `emoji-data.txt`, `emoji-test.txt`, UTS #39 `confusables.txt`.
- RFC 5892 Appendix A (CONTEXTJ rules for ZWNJ/ZWJ).
- ASCII smuggling / Sneaky Bits: https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler
- Emoji/variation-selector smuggling: https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/
- Trojan Source (CVE-2021-42574): bidi override attacks.
- SilverSpeak homoglyph attacks on AI detectors: https://arxiv.org/abs/2406.11239
- o3/o4-mini U+202F reports (secondhand only; primary source not found): https://www.indiehackers.com/post/what-is-the-narrow-no-break-space-in-chatgpt-KyFE9bkiCLENinayEno8
- ftfy (`chardata.py`) for its control-char, ligature, fullwidth, line-break and quote tables.

**Unverified items** (verify before shipping a rule):

- The `navlist`/`fetch` variants of `turn…` citation tokens.
- Exact Grok card syntax variants.
- Whether `utm_source=claude.ai`/`gemini` appear in the wild.
- The primary source for the U+202F watermark claim.
