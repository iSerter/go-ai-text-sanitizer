# go-ai-text-sanitizer — Product Requirements Document

## 1. Motivation

Large language models routinely embed **invisible Unicode watermark characters** in their output — zero-width spaces (ZWSP/ZWNJ/ZWJ), Unicode tag characters (`U+E0000–E007F`), variation selectors (`U+FE00–FE0F`, `U+E0100–E01EF`), bidirectional controls, soft hyphens, and other default-ignorable code points. Some providers also insert visible model/source annotation envelopes (e.g. `&#8203;` markers or citation placeholders like `(oaicite:0){index=0}`) or use non-standard whitespace patterns for steganographic watermarking.

Inspired by:

- [php-ai-text-sanitizer](https://github.com/iSerter/php-ai-text-sanitizer) — zero-dependency PHP library
- [ai-text-sanitizer](https://github.com/BeMoreDifferent/ai-text-sanitizer) — TypeScript ES module with detectors and rewrite strategies
- [Text-Stealth-Watermark-Cleaner-Detector](https://github.com/cronos3k/Text-Stealth-Watermark-Cleaner-Detector) — Python script with detailed reporting

**go-ai-text-sanitizer** brings the same capabilities to Go: a **zero-dependency** library that can be used as a CLI tool or integrated directly into other Go programs.

## 2. Goals

1. Detect and remove invisible Unicode watermarks and formatting characters from LLM-generated text.
2. Normalize "fancy" typography (smart quotes, dashes, ellipsis) to ASCII equivalents.
3. Strip visible model transport artifacts (citation placeholders, annotation envelopes).
4. Provide detailed per-rule change statistics (audit trail).
5. Offer heuristic and extensible watermark detection (read-only, no mutation).
6. Ship as both a reusable Go library (`import`) and a standalone CLI binary.
7. Zero external dependencies — standard library only (`unicode`, `strings`, `regexp`, `bufio`, `flag`).

## 3. Non-Goals

- **Rewriting, paraphrasing or "humanizing".** The sanitizer never calls a model, never substitutes words or phrases, and never randomizes output. Same input + same options ⇒ same output.
- Defeating SynthID, green-list statistical watermarks, or neural AI detectors (these operate on token-level statistics, not string-level artifacts).
- Parsing HTML/XML structure (operates on raw text; Markdown code spans and URLs are recognized only so they can be protected).
- Handling C2PA or file-metadata content credentials.
- Running as a service/daemon (CLI + library only).

## 4. Library API

The authoritative reference is the package documentation (`go doc ./aisanitizer`). Summary:

### 4.1 Options, presets and rules

- `Options` holds boolean switches per rule group (`RemoveZeroWidth`, `RemoveCitations`, `NormalizeSmartQuotes`, `FoldCompatibility`, `StripMarkdown`, …), the policy knobs (`DashStyle`, `BidiMode`, `InvalidUTF8`, `MaxBlankLines`, `MaxPositions`), the preservation switches (`KeepEmoji`, `KeepScriptFormatting`, `KeepTabs`, `KeepNewlines`, `KeepFrenchSpacing`) and a `Rules map[RuleID]bool` override.
- `Defaults()` removes invisible characters and model artifacts without changing visible typography. `Preset(name)` returns `safe`, `default`, `plain` or `paranoid`.
- Every rule has a stable `RuleID` (`Rules()`, `LookupRule()`, `Options.SetRule()`), a category (`invisible`, `whitespace`, `artifact`, `typography`, `homoglyph`, `steganography`, `encoding`) and an action (`remove`, `replace`, `detect`).
- Deprecated aliases kept for compatibility: `Nfkc` (→ `FoldCompatibility`), `NormalizeDashes` (→ `DashStyle=DashHyphen`), `KeepBidi` (→ `BidiMode=BidiKeep`).

### 4.2 Sanitize

```go
func Sanitize(text string, opts *Options) (string, *Report)
func CleanText(text string) (string, *Report)                 // Defaults()
func SanitizeBytes(b []byte, opts *Options) ([]byte, *Report)
func SanitizeReader(r io.Reader, w io.Writer, opts *Options) (*Report, error)
func CheckUTF8(text string) error                              // *InvalidUTF8Error
func Reveal(text string) string                                // "a⟨U+200B⟩b"
```

Guarantees: output is valid UTF-8; `Sanitize` is idempotent; unchanged input is returned without copying.

### 4.3 Detect Only (Read-Only)

```go
func Detect(text string, opts *Options) (*Report, error)
```

Reports exactly what `Sanitize` would change, plus detect-only findings: decoded steganographic payloads (tag characters, variation selectors, invisible operators, zero-width runs, trailing whitespace), mixed-script/homoglyph words, private-use and replacement characters, and ChatGPT "source pills".

### 4.4 Report

`Report{Modified, Risk, Changes ChangeStats, Findings []Finding}`; JSON field names are snake_case. A `Finding` carries `Rule`, `Category`, `Action`, `Name`, `Notation`, `CodePoint`, `Index` (byte offset of the first occurrence in the original input), `Count`, `Payload` and optional `Positions` (offset/line/column). Helpers: `HasFindings`, `HasWatermarks`, `Count(rule)`, `Summary`, `String`, `Merge`.

### 4.5 Detectors

`Detector` (`Name()`, `Detect(text) ([]Finding, error)`) is the extension point; register custom detectors via `Options.ExtraDetectors`. `HeuristicDetector` exposes the built-in rules as a `Detector`.

### 4.6 Rewrite strategies (removed)

`SanitizeWithRewrite` and `RewriteStrategy` remain only as deprecated no-op shims and will be deleted. Rewriting changed meaning and *added* typographic AI footprints (curly quotes, "utilize", "moreover").

## 5. CLI Usage

```
ai-text-sanitizer [flags] [file|dir ...]     # flags may appear anywhere

Modes:      (default) stdout or -o FILE | -i/--in-place | -d/--detect-only | --check | --diff
Reporting:  -r/--report FILE, --format text|json|sarif, --pretty, --positions N, -s/--strict
Rules:      --preset safe|default|plain|paranoid, --rule ID, --no-rule ID, --list-rules,
            --normalize-smart-quotes, --dash-style keep|hyphen|ascii|comma, --normalize-ellipsis,
            --normalize-punctuation, --fold-compat, --fold-confusables, --strip-markdown,
            --remove-boilerplate, --remove-numeric-citations, --remove-private-use,
            --collapse-whitespace, --max-blank-lines N, --trim, --keep-french-spacing,
            --bidi auto|keep|remove, --no-keep-emoji, --no-keep-script-formatting, --no-* (defaults)
Input:      --invalid-utf8 error|replace|drop, --include GLOB, --exclude GLOB
```

See README.md for examples.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Error (file not found, invalid UTF-8 with the default policy, bad flags, …) |
| 2    | Findings (`--detect-only`), files that would change (`--check`), or changes/findings with `--strict` |

## 6. Architecture

```
go-ai-text-sanitizer/
├── cmd/ai-text-sanitizer/   # CLI: flags.go, cli.go (modes, files, atomic writes), diff.go, sarif.go
├── aisanitizer/
│   ├── rules.go             # rule registry (IDs, categories, defaults, option bindings)
│   ├── options.go           # Options, presets, enums
│   ├── sanitizer.go         # public API + stage pipeline
│   ├── engine.go            # single-pass character engine (+ context rules)
│   ├── artifacts.go         # LLM artifact patterns, tracking parameters
│   ├── boilerplate.go, markdown.go, typography.go, whitespace.go
│   ├── stego.go             # payload decoders (detect-only)
│   ├── regions.go           # protected regions (code spans, URLs, e-mails)
│   ├── rewriter.go          # copy-on-write builder with offset maps
│   ├── report.go, names.go, reveal.go, detect.go
│   ├── tables_gen.go        # generated from the Unicode Character Database
│   └── testdata/            # golden corpus, emoji-test sequences, fuzz regressions
└── internal/ucdgen/         # table generator (go generate ./aisanitizer)
```

### Processing Pipeline

```
Input Text
  │
  ├─ 1. Character engine (single pass, copy-on-write)
  │    ├── invalid UTF-8 → U+FFFD or dropped
  │    ├── HTML entities that encode invisible characters
  │    ├── ANSI escape sequences, C0/C1 controls
  │    ├── zero-width, bidi, invisible math, variation selectors, tags,
  │    │   other default-ignorables, braille blank, noncharacters, private use (opt-in)
  │    │   — with context rules for emoji, Indic/Arabic joiners, Mongolian,
  │    │     Hangul, standardized/ideographic variation sequences, RTL marks
  │    └── unusual spaces → U+0020, line/paragraph separators → \n
  │
  ├─ 2. Post-character stages, repeated until stable (code spans protected)
  │    ├── LLM artifacts (citations, canvas wrappers, tracking parameters)
  │    ├── chat boilerplate (opt-in), Markdown stripping (opt-in)
  │    ├── typography: quotes, dashes, ellipsis, punctuation, compatibility folding (opt-in; URLs protected)
  │    ├── homoglyph folding (opt-in) / mixed-script detection
  │    └── whitespace collapsing and trimming (opt-in)
  │
  ├─ 3. Steganography analyzers on the original input (detect-only findings)
  │
  └─ 4. Cleaned text + Report (offsets mapped back to the original input)
```

## 7. Unicode Coverage

Tables are generated from Unicode 18.0.0 (`UnicodeVersion`). Every `Default_Ignorable_Code_Point` is handled by an invisible-character rule (enforced by a test).

| Category | Code Points | Example |
|----------|------------|---------|
| Zero-width | U+200B–200D, U+2060, U+FEFF | ZWSP, ZWNJ, ZWJ, Word Joiner, BOM |
| Bidi controls | U+061C, U+200E/200F, U+202A–202E, U+2066–2069 | ALM, LRM, RLM, LRE…RLO, LRI…PDI |
| Variation selectors | U+FE00–FE0F, U+E0100–E01EF | VS1–VS256 |
| Tags block | U+E0000–E007F | ASCII smuggling payloads |
| Invisible math | U+2061–2064 | FUNCTION APPLICATION, INVISIBLE TIMES/SEPARATOR/PLUS |
| Other format/default-ignorable | U+00AD, U+034F, U+115F–1160, U+17B4–17B5, U+180B–180F, U+2065, U+206A–206F, U+3164, U+FFA0, U+FFF0–FFFC, U+1BCA0–1BCA3, U+1D159, U+1D173–1D17A, U+E0080–E0FFF | Soft hyphen, CGJ, Hangul fillers, Mongolian selectors, deprecated format controls, interlinear annotation, object replacement, shorthand format controls |
| Braille blank | U+2800 | BRAILLE PATTERN BLANK |
| Noncharacters | U+FDD0–FDEF, U+xFFFE/xFFFF | — |
| Private use (opt-in) | U+E000–F8FF, planes 15–16 | ChatGPT U+E200–E202 citation wrappers are removed as artifacts |
| Control chars | U+0000–001F (excl. 09/0A/0D), U+007F–009F (excl. U+0085), ANSI escapes | C0/C1 controls |
| Exotic spaces | U+00A0, U+1680, U+2000–200A, U+202F, U+205F, U+3000 | NBSP, en/em/thin/hair spaces, NNBSP, ideographic |
| Line separators | U+2028, U+2029, U+0085 | LINE/PARAGRAPH SEPARATOR, NEL |
| Smart quotes (opt-in) | U+2018–201F, U+2039–203A, U+00AB, U+00BB, U+02BC, U+FF02, U+FF07 | Curly quotes, guillemets |
| Dashes (opt-in) | U+2010–2015, U+2212, U+FE58, U+FE63, U+FF0D | Hyphen, en/em dash, minus |
| Compatibility (opt-in) | `<compat>`, `<font>`, `<wide>`, `<super>`, `<circle>`, `<fraction>`, … decompositions | ﬁ, Ａ, 𝐀, ², ①, ½ |
| Confusables (opt-in fold, detect by default) | Cyrillic/Greek/Armenian/Cherokee/Coptic/Lisu → Latin (UTS #39) | Cyrillic а in "pаypal" |

## 8. Testing Strategy

- **Unit tests** for each sanitization rule (individual Unicode categories)
- **Golden tests** (`aisanitizer/testdata/golden`) with realistic LLM output samples (ChatGPT, Gemini, Perplexity, Grok, etc.), expected outputs and expected reports
- **Fuzz tests** (idempotency, valid UTF-8 output, Detect/Sanitize agreement, offsets in range)
- **Regression tests** for known watermark patterns from major providers
- **Emoji handling tests** (ensure ZWJ sequences like 👨‍👩‍👧‍👦 survive with `KeepEmoji`)
- **Script tests** (Persian/Kurdish/Indic joiners, Arabic/Hebrew bidi marks, Mongolian, Hangul, CJK variation sequences, French spacing) with default options
- **CLI tests** — pipe/stdin, file I/O, exit codes, `--strict` behavior
- **Benchmarks** for throughput (MB/s)

## 9. Performance Targets

- **Throughput:** ≥ 50 MB/s for default options on mixed text (currently ~200–480 MB/s on clean text, ~70 MB/s on worst-case dirty text)
- **Memory:** O(n) relative to input size; 2 allocations per call when the input is unchanged
- **Startup time:** Sub-millisecond (no external dependencies, no heavy init)

## 10. Releases & Versioning

- **Semantic Versioning** (v1.0.0+)
- **Binary releases** via GoReleaser for macOS, Linux and Windows (amd64/arm64), with checksums and SBOMs
- **Homebrew tap** (optional)

## 11. Future Considerations (Post-v1)

- Token-based statistical watermark detector interface (user-provided scoring)
- SynthID bridging adapter
- Integration with `chardet`-like encoding detection for non-UTF-8 inputs
- WASM build for browser use
- (Done) GitHub Action and pre-commit hooks for CI gates
