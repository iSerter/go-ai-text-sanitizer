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

- Defeating SynthID, green-list statistical watermarks, or neural AI detectors (these operate on token-level statistics, not string-level artifacts).
- Parsing HTML/XML structure (operates on raw text).
- Handling C2PA or file-metadata content credentials.
- Running as a service/daemon (CLI + library only).

## 4. Library API

### 4.1 Core Function

```go
package aisanitizer

type Options struct {
    RemoveZeroWidth        bool  // ZWSP, ZWNJ, ZWJ, Word Joiner, BOM
    RemoveBidi             bool  // Bidirectional marks/controls
    RemoveInvisibleMath    bool  // Invisible operators (U+2061–2064)
    RemoveVariationSelectors bool // U+FE00–FE0F, U+E0100–E01EF
    RemoveTagChars         bool  // Unicode tags block U+E0000–E007F
    RemoveFormatChars      bool  // Soft hyphen, CGJ, Hangul fillers, interlinear, musical
    RemoveBrailleBlank     bool  // U+2800 BRAILLE PATTERN BLANK
    StripControl           bool  // C0/C1 controls (keeps TAB, LF, CR)
    RemoveCitations        bool  // (oaicite:N){index=N} placeholders
    RemoveModelArtifacts   bool  // Visible model annotation envelopes
    NormalizeSpaces        bool  // Unusual spaces → U+0020
    NormalizeLineSeparators bool // U+2028 → \n, U+2029 → \n\n
    NormalizeSmartQuotes   bool  // Curly/angle quotes → straight ' "
    NormalizeDashes        bool  // En/em dashes, minus → -
    NormalizeEllipsis      bool  // U+2026 → ...
    CollapseWhitespace     bool  // Runs of spaces → one, trim line-end spaces
    Trim                  bool  // Trim leading/trailing whitespace
    KeepEmoji              bool  // Preserve ZWJ/Variation selectors in emoji sequences
    KeepBidi               bool  // Override: allow bidi marks to survive
    KeepTabs               bool  // Preserve horizontal tabs
    KeepNewlines           bool  // Preserve \n/\r
    Nfkc                   bool  // Apply NFKC normalization (default: NFC)
}

type Report struct {
    Modified bool
    Changes  ChangeStats
    Findings []Finding
}

type ChangeStats struct {
    RemovedZeroWidth        int
    RemovedBidi             int
    RemovedInvisibleMath    int
    RemovedVariationSelectors int
    RemovedTagChars         int
    RemovedFormatChars      int
    RemovedBrailleBlank     int
    RemovedControl          int
    RemovedCitations        int
    RemovedModelArtifacts   int
    NormalizedSpaces        int
    NormalizedLineSeparators int
    NormalizedSmartQuotes   int
    NormalizedDashes        int
    NormalizedEllipsis      int
    CollapsedSpaces         int
    RewrittenSegments       int
    Total                   int
}

type Finding struct {
    Category string // e.g. "zero_width", "tag_char", "bidi"
    Name     string // e.g. "ZERO WIDTH SPACE"
    Notation string // e.g. "U+200B"
    CodePoint rune
    Index    int
    Count    int
}
```

### 4.2 Sanitize

```go
// Sanitize cleans text and returns the result with a change report.
func Sanitize(text string, opts *Options) (string, *Report)

// MustSanitize is like Sanitize but panics on error (never in practice).
func MustSanitize(text string, opts *Options) (string, *Report)

// Defaults returns an Options with all safe defaults pre-set.
func Defaults() *Options
```

### 4.3 Detect Only (Read-Only)

```go
// Detect runs detectors without mutating text, returns findings.
func Detect(text string, opts *Options) (*Report, error)
```

### 4.4 Detectors

Built-in detectors (read-only heuristic scans):

- **HeuristicDetector** — counts zero-width marks, exotic spaces, tag payloads, variation selectors, model artifacts.
- Extensible via `Detector` interface:

```go
type Detector interface {
    Name() string
    Detect(text string) ([]Finding, error)
}
```

### 4.5 Rewrite Strategies (Opt-In)

```go
type RewriteStrategy int

const (
    RewriteNone       RewriteStrategy = iota
    RewriteLight      // Flip quotes, re-chunk sentences
    RewriteAggressive // Light + synonym substitution
)
```

```go
// SanitizeWithRewrite cleans text and applies optional deterministic rewrites.
func SanitizeWithRewrite(text string, opts *Options, strategy RewriteStrategy) (string, *Report, error)
```

### 4.6 Convenience

```go
// CleanText applies default sanitization in one call (equivalent to the PHP library's static method).
func CleanText(text string) (string, *Report)
```

## 5. CLI Usage

```
Usage: ai-text-sanitizer [flags] [input-file]

Flags:
  -o, --out string       Output file (default: stdout)
  -r, --report string    Write JSON report to file
  -d, --detect-only      Only detect, don't modify (exit code 2 if findings)
  -s, --strict           Exit code 2 if text was modified or findings detected
  -i, --in-place         Modify file in-place (creates .bak backup)
      --pretty           Human-readable report to stderr
      --rewrite string   Rewrite strategy: none, light, aggressive (default: none)

  # Toggle individual sanitization rules
      --[no-]remove-zero-width
      --[no-]remove-bidi
      --[no-]remove-variation-selectors
      --[no-]remove-tag-chars
      --[no-]remove-citations
      --[no-]normalize-smart-quotes
      --[no-]normalize-dashes
      --[no-]collapse-whitespace
      --nfkc
      --trim

  -h, --help             Show help
  -v, --version          Show version
```

### Examples

```bash
# Sanitize a file, write cleaned result
ai-text-sanitizer draft.txt -o draft_clean.txt

# Detect only, exit 2 if watermarks found (CI gate)
ai-text-sanitizer draft.txt --detect-only --strict

# Pipe support
cat draft.txt | ai-text-sanitizer --report report.json > clean.txt

# In-place cleaning with backup
ai-text-sanitizer --in-place draft.txt

# Full normalization
ai-text-sanitizer --normalize-smart-quotes --normalize-dashes --nfkc --trim input.txt
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success, no changes |
| 1    | Error (file not found, invalid UTF-8, etc.) |
| 2    | Changes made or findings detected (with `--strict`) |

## 6. Architecture

```
go-ai-text-sanitizer/
├── cmd/
│   └── ai-text-sanitizer/
│       └── main.go           # CLI entry point
├── aisanitizer/
│   ├── sanitizer.go          # Core Sanitize/Detect logic
│   ├── options.go            # Options struct + Defaults()
│   ├── report.go             # Report, ChangeStats, Finding types
│   ├── unicode.go            # Unicode category tables & helpers
│   ├── patterns.go           # Regex patterns for citations, artifacts
│   ├── normalize.go          # Typography normalization (quotes, dashes, etc.)
│   ├── spaces.go             # Whitespace folding & collapsing
│   ├── rewrite.go            # Deterministic rewrite strategies
│   ├── detect.go             # Heuristic detector implementation
│   └── detect_test.go        # Tests
├── go.mod
├── go.sum
├── Makefile
├── PRD.md
├── README.md
└── LICENSE
```

### Processing Pipeline

```
Input Text
  │
  ├─ 1. Detect-only pass (if requested) → collect Findings
  │
  ├─ 2. NFKC/NF normalization (optional)
  │
  ├─ 3. Remove invisible characters
  │    ├── Zero-width chars (U+200B–200D, U+2060, U+FEFF)
  │    ├── Bidi controls (U+200E/200F, U+202A–202E, U+2066–2069, U+061C)
  │    ├── Variation selectors (U+FE00–FE0F, U+E0100–E01EF)
  │    ├── Tags block (U+E0000–E007F)
  │    ├── Invisible math operators (U+2061–2064)
  │    ├── Other format chars (soft hyphen, CGJ, fillers, musical, shorthand)
  │    ├── Braille blank (U+2800)
  │    └── Stray C0/C1 controls (optional, keeps TAB/LF/CR)
  │
  ├─ 4. Strip visible model artifacts
  │    ├── Citation placeholders (oaicite, etc.)
  │    └── Model annotation envelopes
  │
  ├─ 5. Normalize typography
  │    ├── Smart quotes → straight
  │    ├── Dashes/minus → -
  │    └── Ellipsis → ...
  │
  ├─ 6. Normalize whitespace
  │    ├── Unusual spaces → U+0020
  │    ├── Line/paragraph separators → \n
  │    └── Collapse runs (optional)
  │
  ├─ 7. Apply rewrite strategy (optional)
  │
  └─ 8. Return cleaned text + Report
```

## 7. Unicode Coverage

| Category | Code Points | Example |
|----------|------------|---------|
| Zero-width | U+200B–200D, U+2060, U+FEFF | ZWSP, ZWNJ, ZWJ, Word Joiner, BOM |
| Bidi controls | U+200E/200F, U+202A–202E, U+2066–2069, U+061C | LRM, RLM, LRE, RLE, PDF, LRI, RLI, FSI, ALM |
| Variation selectors | U+FE00–FE0F, U+E0100–E01EF | VS1–VS16, VS17–VS256 |
| Tags block | U+E0000–E007F | Language tags (steganographic payload) |
| Invisible math | U+2061–2064 | FUNCTION APPLICATION, INVISIBLE TIMES/SEPARATOR/PLUS |
| Format chars | U+00AD, U+034F, U+115F–1160, U+17B4–17B5, U+180B–180D, U+200F, U+3164, U+FFA0, U+FE00–FE0F, U+1D159, U+1D173–1D17A, U+1FFFE–1FFFF, U+E0001, U+E0020–E007F, U+E0100–E01EF | Soft hyphen, CGJ, Hangul fillers, Khmer/Kayah Li, Mongolian, interlinear, musical |
| Braille blank | U+2800 | BRAILLE PATTERN BLANK |
| Control chars | U+0000–001F (excl. 09/0A/0D), U+007F–009F | C0/C1 controls |
| Exotic spaces | U+00A0, U+1680, U+2000–200A, U+202F, U+205F, U+3000, U+180E | NBSP, Ogham, en/em/thin/hair spaces, NNBSP, MPS, ideographic, Mongolian vowel |
| Smart quotes | U+2018–201F, U+2039–203A, U+00AB, U+00BB | Curly single/double, guillemets |
| Dashes | U+2010–2015, U+2212 | Hyphen, en-dash, em-dash, horizontal bar, minus |
| Ellipsis | U+2026 | HORIZONTAL ELLIPSIS |
| Line/paragraph separators | U+2028, U+2029 | LINE SEPARATOR, PARAGRAPH SEPARATOR |

## 8. Testing Strategy

- **Unit tests** for each sanitization rule (individual Unicode categories)
- **Integration tests** with realistic LLM output samples (ChatGPT, Claude, Gemini, etc.)
- **Regression tests** for known watermark patterns from major providers
- **Emoji handling tests** (ensure ZWJ sequences like 👨‍👩‍👧‍👦 survive with `KeepEmoji`)
- **RTL/Bidi tests** (Persian, Arabic, Hebrew with `KeepBidi` enabled)
- **CLI tests** — pipe/stdin, file I/O, exit codes, `--strict` behavior
- **Benchmarks** for throughput (MB/s)

## 9. Performance Targets

- **Throughput:** ≥ 50 MB/s for default options on modern hardware
- **Memory:** O(n) relative to input size; minimize allocations in hot paths
- **Startup time:** Sub-millisecond (no external dependencies, no heavy init)

## 10. Releases & Versioning

- **Semantic Versioning** (v1.0.0+)
- **Binary releases** via GoReleaser for macOS (amd64/arm64), Linux (amd64/arm64), Windows (amd64)
- **Homebrew tap** (optional)

## 11. Future Considerations (Post-v1)

- Token-based statistical watermark detector interface (user-provided scoring)
- SynthID bridging adapter
- Integration with `chardet`-like encoding detection for non-UTF-8 inputs
- WASM build for browser use
- GitHub Action for CI gates
