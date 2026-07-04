# go-ai-text-sanitizer

**Zero-dependency Go library and CLI** for detecting and removing invisible Unicode watermarks, formatting characters, and model transport artifacts from LLM-generated text.

Inspired by [php-ai-text-sanitizer](https://github.com/iSerter/php-ai-text-sanitizer), [ai-text-sanitizer](https://github.com/BeMoreDifferent/ai-text-sanitizer), and [Text-Stealth-Watermark-Cleaner-Detector](https://github.com/cronos3k/Text-Stealth-Watermark-Cleaner-Detector).

## Library

```go
import "github.com/iSerter/go-ai-text-sanitizer/aisanitizer"

// One-liner with defaults
clean, report := aisanitizer.CleanText(aiOutput)

// Configure options
opts := aisanitizer.Defaults()
opts.NormalizeSmartQuotes = true
opts.NormalizeDashes = true
clean, report = aisanitizer.Sanitize(aiOutput, opts)

// Detect only (no mutation)
report, _ = aisanitizer.Detect(aiOutput, nil)
if report.HasWatermarks() { ... }

// With rewrite strategy
clean, report, _ = aisanitizer.SanitizeWithRewrite(text, opts, aisanitizer.RewriteLight)
```

## CLI

```bash
# Sanitize a file
ai-text-sanitizer draft.txt -o clean.txt

# Pipe
cat draft.txt | ai-text-sanitizer --report report.json > clean.txt

# Detect only (CI gate)
ai-text-sanitizer --detect-only --strict input.txt

# In-place with backup
ai-text-sanitizer --in-place draft.txt

# Full normalization
ai-text-sanitizer --normalize-smart-quotes --normalize-dashes --nfkc --trim input.txt
```

## Build

```bash
make build   # builds bin/ai-text-sanitizer
make test    # runs all tests
make install # go install
```
