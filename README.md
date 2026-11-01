# go-ai-text-sanitizer

[![CI](https://github.com/iSerter/go-ai-text-sanitizer/actions/workflows/ci.yml/badge.svg)](https://github.com/iSerter/go-ai-text-sanitizer/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/iSerter/go-ai-text-sanitizer/aisanitizer.svg)](https://pkg.go.dev/github.com/iSerter/go-ai-text-sanitizer/aisanitizer)

**Zero-dependency Go library and CLI** that detects and removes invisible Unicode watermarks, hidden payloads and visible LLM artifacts ("footprints") from text.

- **Invisible characters:** zero-width characters, bidi controls, tag characters, variation selectors, invisible operators, every Unicode *Default_Ignorable_Code_Point*, noncharacters, control characters and ANSI escapes.
- **LLM artifacts:**
  - ChatGPT `:contentReference[oaicite:0]{index=0}`, `[oai_citation:…]`, `citeturn0search0`, `【4:0†source】` and private-use citation markers;
  - Gemini `[cite: 1]` and `[span_1](start_span)`, Grok cards, Perplexity `[web:1]`;
  - `utm_source=chatgpt.com`-style tracking parameters, and more.
- **Hidden payloads:** decodes "ASCII smuggling" (tag characters), emoji/variation-selector smuggling, invisible-operator binary, zero-width binary, trailing-whitespace steganography and homoglyph words.
- **Never breaks legitimate text:** emoji ZWJ sequences, Persian/Arabic/Indic joiners, RTL marks, Mongolian selectors, CJK variation sequences, French spacing (opt-in), code blocks and URLs all survive.
- **Deterministic and fast:** no LLM calls, no randomness, about 200–480 MB/s on clean text and 2 allocations when nothing changes.

> **What it does not do.** This is a static sanitizer, not a "humanizer". It never paraphrases, never swaps words and never calls a model. It cannot remove statistical/token-level watermarks such as SynthID or green-list schemes, and it will not make text pass an AI detector. It removes what is *in the bytes*.

## Install

```bash
go install github.com/iSerter/go-ai-text-sanitizer/cmd/ai-text-sanitizer@latest
```

Prebuilt binaries for Linux, macOS and Windows (amd64/arm64) are attached to each [GitHub release](https://github.com/iSerter/go-ai-text-sanitizer/releases).

## CLI

```bash
# Sanitize a file (flags may come before or after file names)
ai-text-sanitizer draft.txt -o clean.txt

# Pipe, with a JSON report
cat draft.txt | ai-text-sanitizer --report report.json > clean.txt

# Show what would change, with invisible characters made visible
ai-text-sanitizer --diff draft.txt

# Detect only: list findings (decoded hidden payloads included), exit 2 if any
ai-text-sanitizer --detect-only draft.txt

# CI gate over a directory: list files that would change, exit 2 if any
ai-text-sanitizer --check docs/ --include '*.md'

# Rewrite many files in place (atomic, keeps permissions, writes .bak backups)
ai-text-sanitizer --in-place docs/ --exclude 'vendor'

# Plain-text output: also straighten quotes, dashes, ellipses, strip Markdown, collapse whitespace
ai-text-sanitizer --preset plain draft.md

# Fine-grained control
ai-text-sanitizer --normalize-smart-quotes --dash-style comma --rule artifact.numeric_citation --no-rule exotic_space draft.txt

# SARIF for GitHub code scanning
ai-text-sanitizer --detect-only --format sarif docs/ > results.sarif

# List every rule
ai-text-sanitizer --list-rules
```

| Mode | Behaviour | Exit code 2 when |
|---|---|---|
| *(default)* | sanitized text to stdout or `-o` | `--strict` and the text changed or had findings |
| `-i, --in-place` | rewrite files atomically, keep `FILE.bak` (unless `--no-backup`) | `--strict` and anything changed |
| `-d, --detect-only` | print findings (`--format text\|json\|sarif`); never modifies | any finding |
| `--check` | list files that would change | any file would change |
| `--diff` | unified diff, invisible characters shown as `⟨U+200B⟩` | `--strict` and anything changed |

Exit code 1 means an error. Invalid UTF-8 input is an error by default; use `--invalid-utf8=replace` or `--invalid-utf8=drop` to process it anyway. Directories are walked recursively, skipping hidden entries, binary files and `*.bak` backups; walked files that are not valid UTF-8 are skipped with a warning instead of failing the run.

### Presets

| Preset | What it does |
|---|---|
| `safe` | Invisible characters and model artifacts only. Nothing visible changes except the artifacts. |
| `default` | `safe` plus unusual spaces → U+0020 and U+2028/2029 → newlines. Same as `Defaults()`. |
| `plain` | `default` plus straight quotes, `-` dashes, `...`, ASCII bullets/arrows, compatibility folding (ﬁ → fi, Ａ → A), Markdown stripping, whitespace collapsing and trimming. |
| `paranoid` | `plain` plus private-use removal, homoglyph folding, chat-boilerplate removal and removal of every bidi control. |

Flags given after `--preset` override it, e.g. `--preset plain --normalize-smart-quotes=false`.

## HTTP API

`ai-text-sanitizer serve` runs a small HTTP server (standard library only) for non-Go clients and shared deployments.

```bash
# Listens on :8080 (or :$PORT). Setting a key protects /sanitize.
AI_TEXT_SANITIZER_API_KEY=secret ai-text-sanitizer serve --addr :8080

curl localhost:8080/health
# {"status":"ok","unicode":"18.0.0","version":"v1.2.3"}

# JSON in, JSON out
curl -H 'Authorization: Bearer secret' -H 'Content-Type: application/json' \
  -d '{"text":"hi​there","preset":"plain"}' localhost:8080/sanitize
# {"text":"hithere","report":{"modified":true,"risk":"low",...}}

# Raw text body, options as query parameters
curl -H 'X-API-Key: secret' --data-binary @draft.txt 'localhost:8080/sanitize?detect_only=1'
```

| Endpoint | Auth | Description |
|---|---|---|
| `GET /health` | never | Liveness probe with the version and Unicode version. |
| `POST /sanitize` | when a key is set | Returns `{"text": ..., "report": ...}`; `text` is omitted for `detect_only`. |

`POST /sanitize` accepts a JSON body (`Content-Type: application/json`) or any other body as the raw text:

| JSON field | Query parameter | Meaning |
|---|---|---|
| `text` | *(the body)* | Text to sanitize (required). |
| `preset` | `preset` | `safe`, `default`, `plain` or `paranoid`. |
| `rules` | `rule` | Rule IDs to enable (see `--list-rules`); repeatable or comma-separated. |
| `disable_rules` | `no_rule` | Rule IDs to disable. |
| `detect_only` | `detect_only` | Report findings without modifying the text. |
| `positions` | `positions` | Record up to n positions per finding. |
| `invalid_utf8` | `invalid_utf8` | `error` (default, returns 400), `replace` or `drop`. |

Authentication uses `Authorization: Bearer KEY` or `X-API-Key: KEY`, from `--api-key` or (preferably, so it stays out of `ps`) `$AI_TEXT_SANITIZER_API_KEY`. Without a key `/sanitize` is open and the server logs a warning. Errors are `{"error": "..."}` with status 400, 401, 405 or 413 (bodies over `--max-body`, default 10 MiB). The server applies read/write timeouts and shuts down gracefully on SIGINT/SIGTERM. Go programs can mount the same handler with `httpapi.New(httpapi.Config{...})`.

## Library

```go
import "github.com/iSerter/go-ai-text-sanitizer/aisanitizer"

// One call with safe defaults.
clean, report := aisanitizer.CleanText(aiOutput)
fmt.Println(report.Changes.Total, report.Risk)

// Presets and individual switches.
opts, _ := aisanitizer.Preset(aisanitizer.PresetPlain)
opts.DashStyle = aisanitizer.DashComma        // "a — b — c" → "a, b, c"
_ = opts.SetRule(aisanitizer.RuleNumericCitation, true)
clean, report = aisanitizer.Sanitize(aiOutput, opts)

// Detect only: findings, decoded hidden payloads and positions.
opts = aisanitizer.Defaults()
opts.MaxPositions = 10
report, _ = aisanitizer.Detect(aiOutput, opts)
for _, f := range report.Findings {
    fmt.Println(f.Rule, f.Name, f.Count, f.Payload, f.Positions)
}

// Make invisible characters visible for logs and diffs.
fmt.Println(aisanitizer.Reveal("a\u200Bb")) // a⟨U+200B⟩b
```

- **`Sanitize`**
  - Returns the input string itself, with no copy, when nothing changes.
  - Its output is always valid UTF-8 and idempotent: sanitizing twice gives the same result.
- **`Report`**
  - Holds per-group `Changes` and aggregated `Findings` (rule, category, action, code point, first byte offset, count, optional positions and payload).
  - Holds an overall `Risk`:
    - `high` for decodable hidden payloads, bidi overrides, tag characters or homoglyph words;
    - `low` for anything else.
- **`Detect`**
  - Reports exactly what `Sanitize` would change, plus detect-only findings.
- **Other entry points**
  - `SanitizeBytes`, `SanitizeReader` and `CheckUTF8` cover byte slices, readers and UTF-8 validation.
  - `Options.ExtraDetectors` plugs in custom `Detector`s.

## Rules

Every rule has a stable ID used in reports, in `Options.Rules`/`SetRule` and in `--rule`/`--no-rule`.

<!-- rules:start (generated by `go test ./aisanitizer -run TestReadmeRules -update`) -->

| Rule | Category | Action | Default | Option | Description |
|---|---|---|---|---|---|
| `zero_width` | invisible | remove | **on** | `RemoveZeroWidth` | Zero-width space/non-joiner/joiner, word joiner and BOM (U+200B–200D, U+2060, U+FEFF). Joiners inside emoji and scripts that need them are kept. |
| `bidi` | invisible | remove | **on** | `RemoveBidi` | Bidirectional marks, embeddings, overrides and isolates (U+061C, U+200E/200F, U+202A–202E, U+2066–2069). See BidiMode. |
| `invisible_math` | invisible | remove | **on** | `RemoveInvisibleMath` | Invisible math operators (U+2061–2064). |
| `variation_selector` | invisible | remove | **on** | `RemoveVariationSelectors` | Variation selectors (U+FE00–FE0F, U+E0100–E01EF). Registered emoji/standardized/ideographic variation sequences are kept. |
| `tag_char` | invisible | remove | **on** | `RemoveTagChars` | Unicode tag characters (U+E0000–E007F), the carrier for "ASCII smuggling". Valid emoji subdivision flags are kept. |
| `format_char` | invisible | remove | **on** | `RemoveFormatChars` | Other default-ignorable and invisible format characters: soft hyphen, CGJ, Hangul fillers, Khmer inherent vowels, Mongolian selectors, deprecated format controls, interlinear annotation, shorthand format controls, object replacement character, musical invisibles. |
| `braille_blank` | invisible | remove | **on** | `RemoveBrailleBlank` | Braille pattern blank (U+2800), a visible-blank character used to fake whitespace. |
| `noncharacter` | invisible | remove | **on** | `RemoveNoncharacters` | Noncharacters (U+FDD0–FDEF and U+xFFFE/xFFFF). |
| `private_use` | invisible | remove | off | `RemovePrivateUse` | Private-use characters (U+E000–F8FF, planes 15–16). Off by default because icon fonts use them; always reported by Detect. |
| `control` | invisible | remove | **on** | `StripControl` | C0/C1 control characters except TAB, LF and CR (see KeepTabs/KeepNewlines). |
| `ansi_escape` | invisible | remove | **on** | `StripControl` | Complete ANSI/VT escape sequences (CSI, OSC and two-byte escapes), not just the ESC byte. |
| `html_entity` | invisible | remove | **on** | `DecodeInvisibleEntities` | HTML entities that encode invisible characters (e.g. &#8203;, &#x200B;, &ZeroWidthSpace;). Entities for characters with legitimate HTML uses (&nbsp;, &shy;, &zwj;, &zwnj;, &lrm;, &rlm;) are left alone. |
| `invalid_utf8` | encoding | replace | **on** | `InvalidUTF8` | Invalid UTF-8 byte sequences are replaced with U+FFFD or dropped (see InvalidUTF8). |
| `replacement_char` | encoding | detect | **on** |  | U+FFFD REPLACEMENT CHARACTER in the input, a sign of earlier decoding damage. |
| `exotic_space` | whitespace | replace | **on** | `NormalizeSpaces` | Unusual spaces (NBSP, en/em/thin/hair spaces, narrow NBSP, ideographic space, …) become U+0020. |
| `line_separator` | whitespace | replace | **on** | `NormalizeLineSeparators` | U+2028 and U+0085 become \n, U+2029 becomes \n\n. |
| `collapse_whitespace` | whitespace | remove | off | `CollapseWhitespace` | Collapses runs of spaces/tabs inside lines, strips trailing whitespace per line and limits blank lines (MaxBlankLines). Leading indentation and fenced code are preserved. |
| `trim` | whitespace | remove | off | `Trim` | Trims leading and trailing whitespace from the whole text. |
| `artifact.content_reference` | artifact | remove | **on** | `RemoveCitations` | ChatGPT content references: :contentReference[oaicite:N]{index=N}. |
| `artifact.oaicite` | artifact | remove | **on** | `RemoveCitations` | ChatGPT citation placeholders: (oaicite:N){index=N}. |
| `artifact.oai_citation` | artifact | remove | **on** | `RemoveCitations` | ChatGPT citation links: [oai_citation:N‡source](url). |
| `artifact.pua_citation` | artifact | remove | **on** | `RemoveCitations` | ChatGPT citation markers wrapped in private-use characters U+E200…U+E201 (e.g. \uE200cite\uE202turn0search0\uE201). |
| `artifact.turn_citation` | artifact | remove | **on** | `RemoveCitations` | Leaked ChatGPT search/file citation tokens: citeturn0search0, turn0news1, filecite turn0file2, iturn0image0, … |
| `artifact.lenticular_citation` | artifact | remove | **on** | `RemoveCitations` | Lenticular-bracket citations: 【4:0†source】, 【85†L261-269】. |
| `artifact.attribution_json` | artifact | replace | **on** | `RemoveCitations` | ChatGPT attribution wrappers ^[text]({"attribution":{…}}); the text is kept. |
| `artifact.gemini_citation` | artifact | remove | **on** | `RemoveCitations` | Gemini citation markers: [cite: 1, 2], [cite_start], [cite_end]. |
| `artifact.gemini_span` | artifact | remove | **on** | `RemoveCitations` | Gemini span markers: [span_1](start_span), [span_1](end_span). |
| `artifact.grok_card` | artifact | remove | **on** | `RemoveCitations` | Grok citation cards: <grok-card …></grok-card> and [](grok_render_citation_card_json={…}). |
| `artifact.perplexity_tag` | artifact | remove | **on** | `RemoveCitations` | Perplexity source tags: [web:1], [attached_file:1]. |
| `artifact.numeric_citation` | artifact | remove | off | `RemoveNumericCitations` | Bare numeric citation markers such as [1] or [2, 3]. Off by default: ambiguous with legitimate references. |
| `artifact.writing_block` | artifact | remove | **on** | `RemoveModelArtifacts` | ChatGPT canvas wrappers: lines like :::writing{variant="document" id="1"} and the closing :::. The inner text is kept. |
| `artifact.footnote_backlink` | artifact | remove | off |  | Footnote back-link arrows (↩, optionally followed by VS15) left over from rendered Markdown. Enable via Options.Rules. |
| `artifact.source_pill` | artifact | detect | **on** |  | ChatGPT source "pills" pasted as text (e.g. "Wikipedia+1"). Detect only. |
| `artifact.tracking_param` | artifact | remove | **on** | `RemoveTrackingParams` | AI referral parameters in URLs: utm_source=chatgpt.com/openai/copilot.com/perplexity/claude.ai/gemini, referrer=grok.com. |
| `artifact.chat_boilerplate` | artifact | remove | off | `RemoveChatBoilerplate` | Chat boilerplate: a leading "Sure! Here's …:" line, trailing "I hope this helps"-style sign-offs, "As an AI language model," and knowledge-cutoff preambles. |
| `smart_quote` | typography | replace | off | `NormalizeSmartQuotes` | Curly quotes, guillemets, primes-as-apostrophes and fullwidth quotes become ' and ". |
| `dash` | typography | replace | off | `DashStyle` | Dashes and minus signs are rewritten according to DashStyle (hyphen, ascii or comma). |
| `ellipsis` | typography | replace | off | `NormalizeEllipsis` | Horizontal ellipsis (U+2026) becomes "...". |
| `punctuation` | typography | replace | off | `NormalizePunctuation` | Bullets, arrows and math symbols become ASCII (• → -, → → ->, ≤ → <=, × → x, …). |
| `compat_fold` | typography | replace | off | `FoldCompatibility` | Compatibility characters fold to their plain form: ligatures (ﬁ → fi), fullwidth (Ａ → A), math alphanumerics (𝐀 → A), superscripts, circled/parenthesized numbers, fractions. |
| `markdown` | typography | replace | off | `StripMarkdown` | Markdown leftovers in plain text: **bold**, headings, horizontal rules, [links](url), images, blockquotes, bullet styles. |
| `confusable` | homoglyph | replace | off | `FoldConfusables` | Folds Cyrillic/Greek/Armenian/Cherokee look-alike letters to Latin inside mixed-script words (e.g. Cyrillic а in "pаypal"). |
| `mixed_script` | homoglyph | detect | **on** |  | Words mixing Latin with look-alike letters from other scripts, and look-alike-only words in Latin text. Detect only. |
| `stego.tag_payload` | steganography | detect | **on** |  | Decodes text hidden in Unicode tag characters ("ASCII smuggling"). |
| `stego.variation_selector_payload` | steganography | detect | **on** |  | Decodes bytes hidden in runs of variation selectors ("emoji smuggling"). |
| `stego.invisible_math_payload` | steganography | detect | **on** |  | Decodes binary payloads encoded with invisible math operators ("Sneaky Bits"). |
| `stego.zero_width_payload` | steganography | detect | **on** |  | Long runs of zero-width characters, decoded as binary when possible. |
| `stego.trailing_whitespace` | steganography | detect | **on** |  | Trailing space/tab patterns at line ends (SNOW-style whitespace steganography). Remove with CollapseWhitespace. |

<!-- rules:end -->

## Safe for multilingual text

Default settings are tested byte-for-byte against:

- every fully-qualified sequence in Unicode's `emoji-test.txt`;
- Persian, Kurdish, Hindi, Bengali, Malayalam and Sinhala joiners (ZWJ/ZWNJ under the RFC 5892 CONTEXTJ rules);
- Hebrew and Arabic with bidi marks;
- Mongolian variation selectors, Hangul jamo fillers, and Japanese ideographic and standardized variation sequences.

Stray joiners in Latin text, and any selector that isn't part of a registered sequence, are still removed. `KeepFrenchSpacing` keeps narrow no-break spaces in French typography.

Character data comes from the Unicode Character Database (currently Unicode `UnicodeVersion` = 18.0.0). The tables are generated by `internal/ucdgen`; run `go generate ./aisanitizer` to update them. A test ensures every `Default_Ignorable_Code_Point` is covered.

## Performance

Apple M4, `go test -bench . ./aisanitizer`, default options:

| Input (≈2 MB) | Throughput | Allocations |
|---|---|---|
| ASCII prose | 338 MB/s | 2 |
| Latin-1 prose | 410 MB/s | 2 |
| Mixed (quotes, dashes, emoji) | 208 MB/s | 2 |
| Emoji ZWJ sequences | 283 MB/s | 2 |
| CJK | 479 MB/s | 2 |
| Persian (ZWNJ) | 249 MB/s | 2 |
| Dirty (watermark + citation on every line) | 69 MB/s | — |
| Mixed, `plain` preset | 75 MB/s | — |

## CI integration

**GitHub Action:** the repository ships an `action.yml` that runs `--check`/`--detect-only` and writes SARIF:

```yaml
- uses: iSerter/go-ai-text-sanitizer@v1
  id: sanitizer
  with:
    paths: docs/
    args: --include '*.md'
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.sanitizer.outputs.sarif-file }}
```

The SARIF report goes to `$RUNNER_TEMP` unless `sarif-file` is set, and is never scanned itself.

**pre-commit:**

```yaml
- repo: https://github.com/iSerter/go-ai-text-sanitizer
  rev: v1.0.0
  hooks:
    - id: ai-text-sanitizer        # fails on files that would change
    # - id: ai-text-sanitizer-fix  # rewrites them instead
```

## Development

```bash
make test       # go test ./...
make lint       # gofmt check, go vet, staticcheck
make bench      # benchmarks
make fuzz       # run each fuzz target for FUZZTIME (default 60s)
make generate   # regenerate Unicode tables (network access)
go test ./aisanitizer -update   # accept golden-file and README changes
```

Golden samples live in `aisanitizer/testdata/golden`: inputs, expected outputs and expected `Detect` reports.

## Inspired by

- [php-ai-text-sanitizer](https://github.com/iSerter/php-ai-text-sanitizer)
- [ai-text-sanitizer](https://github.com/BeMoreDifferent/ai-text-sanitizer)
- [Text-Stealth-Watermark-Cleaner-Detector](https://github.com/cronos3k/Text-Stealth-Watermark-Cleaner-Detector)
- The artifact catalogue at [Wikipedia: Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing/Markup)
- Research on [ASCII smuggling](https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler) and [emoji smuggling](https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/)

## License

See [LICENSE](LICENSE).
