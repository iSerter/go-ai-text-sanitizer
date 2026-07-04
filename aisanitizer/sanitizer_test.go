package aisanitizer

import (
	"encoding/json"
	"testing"
)

func TestCleanTextPreservesNormalText(t *testing.T) {
	input := "Hello, world! This is normal text with numbers 123 and symbols @#$%."
	cleaned, report := CleanText(input)
	if cleaned != input {
		t.Errorf("CleanText modified normal text:\n  got:  %q\n  want: %q", cleaned, input)
	}
	if report.WasModified() {
		t.Errorf("expected no modifications, got changes: %+v", report.Changes)
	}
}

func TestRemoveZeroWidth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ZWSP", "a\u200Bb", "ab"},
		{"ZWNJ", "a\u200Cb", "ab"},
		{"ZWJ", "a\u200Db", "ab"},
		{"WordJoiner", "a\u2060b", "ab"},
		{"BOM", "a\uFEFFb", "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned, report := CleanText(tt.input)
			if cleaned != tt.expected {
				t.Errorf("got %q, want %q", cleaned, tt.expected)
			}
			if !report.WasModified() {
				t.Error("expected modification")
			}
			if report.Changes.RemovedZeroWidth != 1 {
				t.Errorf("expected 1 zero-width removal, got %d", report.Changes.RemovedZeroWidth)
			}
		})
	}
}

func TestRemoveBidi(t *testing.T) {
	input := "a\u200Eb"
	cleaned, report := CleanText(input)
	if cleaned != "ab" {
		t.Errorf("got %q, want %q", cleaned, "ab")
	}
	if report.Changes.RemovedBidi != 1 {
		t.Errorf("expected 1 bidi removal, got %d", report.Changes.RemovedBidi)
	}
}

func TestKeepBidi(t *testing.T) {
	input := "a\u200Eb"
	opts := Defaults()
	opts.KeepBidi = true
	cleaned, _ := Sanitize(input, opts)
	if cleaned != input {
		t.Errorf("expected bidi preserved, got %q", cleaned)
	}
}

func TestRemoveInvisibleMath(t *testing.T) {
	for _, r := range []rune{0x2061, 0x2062, 0x2063, 0x2064} {
		input := "a" + string(r) + "b"
		cleaned, report := CleanText(input)
		if cleaned != "ab" {
			t.Errorf("U+%04X: got %q, want %q", r, cleaned, "ab")
		}
		if report.Changes.RemovedInvisibleMath != 1 {
			t.Errorf("U+%04X: expected 1 removal, got %d", r, report.Changes.RemovedInvisibleMath)
		}
	}
}

func TestRemoveVariationSelectors(t *testing.T) {
	input := "a\uFE00b\uFE0Fc"
	cleaned, report := CleanText(input)
	if cleaned != "abc" {
		t.Errorf("got %q, want %q", cleaned, "abc")
	}
	if report.Changes.RemovedVariationSelectors != 2 {
		t.Errorf("expected 2 vs removals, got %d", report.Changes.RemovedVariationSelectors)
	}
}

func TestRemoveTagChars(t *testing.T) {
	input := "a\U000E0001b\U000E0020c"
	cleaned, report := CleanText(input)
	if cleaned != "abc" {
		t.Errorf("got %q, want %q", cleaned, "abc")
	}
	if report.Changes.RemovedTagChars != 2 {
		t.Errorf("expected 2 tag removals, got %d", report.Changes.RemovedTagChars)
	}
}

func TestRemoveFormatChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		r     rune
	}{
		{"SoftHyphen", "\u00AD", 0x00AD},
		{"CGJ", "\u034F", 0x034F},
		{"HangulFiller", "\u3164", 0x3164},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "a" + string(tt.r) + "b"
			cleaned, report := CleanText(input)
			if cleaned != "ab" {
				t.Errorf("got %q, want %q", cleaned, "ab")
			}
			if report.Changes.RemovedFormatChars != 1 {
				t.Errorf("expected 1 format char removal, got %d", report.Changes.RemovedFormatChars)
			}
		})
	}
}

func TestRemoveBrailleBlank(t *testing.T) {
	input := "a\u2800b"
	cleaned, report := CleanText(input)
	if cleaned != "ab" {
		t.Errorf("got %q, want %q", cleaned, "ab")
	}
	if report.Changes.RemovedBrailleBlank != 1 {
		t.Errorf("expected 1 braille blank removal, got %d", report.Changes.RemovedBrailleBlank)
	}
}

func TestStripControl(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Null", "a\x00b", "ab"},
		{"Bell", "a\x07b", "ab"},
		{"ESC", "a\x1Bb", "ab"},
		{"DEL", "a\x7Fb", "ab"},
		{"KeepTab", "a\tb", "a\tb"},
		{"KeepLF", "a\nb", "a\nb"},
		{"KeepCR", "a\rb", "a\rb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned, _ := CleanText(tt.input)
			if cleaned != tt.expected {
				t.Errorf("got %q, want %q", cleaned, tt.expected)
			}
		})
	}
}

func TestRemoveCitations(t *testing.T) {
	input := "Some text (oaicite:5){index=5} more text"
	cleaned, report := CleanText(input)
	expected := "Some text  more text"
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.RemovedCitations != 1 {
		t.Errorf("expected 1 citation removal, got %d", report.Changes.RemovedCitations)
	}
}

func TestNormalizeSmartQuotes(t *testing.T) {
	opts := Defaults()
	opts.NormalizeSmartQuotes = true

	input := "\u201CHello\u201D \u2018world\u2019"
	expected := "\"Hello\" 'world'"
	cleaned, report := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.NormalizedSmartQuotes != 4 {
		t.Errorf("expected 4 quote normalizations, got %d", report.Changes.NormalizedSmartQuotes)
	}
}

func TestNormalizeDashes(t *testing.T) {
	opts := Defaults()
	opts.NormalizeDashes = true

	input := "hello\u2014world\u2013test"
	expected := "hello-world-test"
	cleaned, report := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.NormalizedDashes != 2 {
		t.Errorf("expected 2 dash normalizations, got %d", report.Changes.NormalizedDashes)
	}
}

func TestNormalizeEllipsis(t *testing.T) {
	opts := Defaults()
	opts.NormalizeEllipsis = true

	input := "hello\u2026world"
	expected := "hello...world"
	cleaned, report := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.NormalizedEllipsis != 1 {
		t.Errorf("expected 1 ellipsis normalization, got %d", report.Changes.NormalizedEllipsis)
	}
}

func TestNormalizeSpaces(t *testing.T) {
	input := "a\u00A0b\u2003c"
	expected := "a b c"
	cleaned, report := CleanText(input)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.NormalizedSpaces != 2 {
		t.Errorf("expected 2 space normalizations, got %d", report.Changes.NormalizedSpaces)
	}
}

func TestNormalizeLineSeparators(t *testing.T) {
	input := "a\u2028b\u2029c"
	expected := "a\nb\n\nc"
	cleaned, _ := CleanText(input)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
}

func TestCollapseWhitespace(t *testing.T) {
	opts := Defaults()
	opts.CollapseWhitespace = true

	input := "a    b   c"
	expected := "a b c"
	cleaned, report := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	if report.Changes.CollapsedSpaces == 0 {
		t.Error("expected some spaces collapsed")
	}
}

func TestTrim(t *testing.T) {
	opts := Defaults()
	opts.Trim = true

	input := "  hello world  "
	expected := "hello world"
	cleaned, _ := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
}

func TestKeepEmoji(t *testing.T) {
	input := "\U0001F600\u200D\U0001F600" + "\u200B" + "test"
	cleaned, report := CleanText(input)
	if !containsRune(cleaned, '\U0001F600') {
		t.Errorf("expected emoji base preserved, got %q", cleaned)
	}
	if report.Changes.RemovedZeroWidth == 0 {
		t.Error("expected some zero-width removals")
	}
}

func TestDetectOnly(t *testing.T) {
	input := "a\u200Bb\u200Cc"
	report, err := Detect(input, Defaults())
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if !report.HasWatermarks() {
		t.Error("expected watermarks to be detected")
	}
	if report.WasModified() {
		t.Error("Detect should not report modifications")
	}
	if len(report.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(report.Findings))
	}
}

func TestSanitizeWithRewrite(t *testing.T) {
	opts := Defaults()

	cleaned, report, err := SanitizeWithRewrite("hello world", opts, RewriteLight)
	if err != nil {
		t.Fatalf("SanitizeWithRewrite error: %v", err)
	}
	if report.Changes.RewrittenSegments == 0 {
		t.Log("no rewrite applied (expected for short text)")
	}
	_ = cleaned
}

func TestSanitizeWithRewriteAggressive(t *testing.T) {
	opts := Defaults()

	cleaned, report, err := SanitizeWithRewrite(
		"hello world, this is very important. however, we need to also consider the use.",
		opts, RewriteAggressive,
	)
	if err != nil {
		t.Fatalf("SanitizeWithRewrite error: %v", err)
	}
	_ = cleaned
	_ = report
}

func TestSanitizeNilOptions(t *testing.T) {
	cleaned, report := Sanitize("hello\u200Bworld", nil)
	if cleaned != "helloworld" {
		t.Errorf("got %q, want %q", cleaned, "helloworld")
	}
	if !report.WasModified() {
		t.Error("expected modification")
	}
}

func TestReportJSON(t *testing.T) {
	input := "a\u200Bb\u200Cc"
	_, report := CleanText(input)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	var decoded Report
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if decoded.Changes.Total != report.Changes.Total {
		t.Errorf("JSON round-trip: got total %d, want %d", decoded.Changes.Total, report.Changes.Total)
	}
}

func TestRealWorldLlmOutput(t *testing.T) {
	llmOutput := "\u201CHere is your answer\u201D\u200B\n\n(oaicite:0){index=0}\n\nSome\u00A0text\u2003with\u00A0weird\u00A0spaces."
	opts := Defaults()
	opts.NormalizeSmartQuotes = true
	opts.CollapseWhitespace = true
	opts.Trim = true

	cleaned, report := Sanitize(llmOutput, opts)

	if report.Changes.RemovedZeroWidth == 0 {
		t.Error("expected zero-width removal")
	}
	if report.Changes.RemovedCitations == 0 {
		t.Error("expected citation removal")
	}
	if report.Changes.NormalizedSmartQuotes == 0 {
		t.Error("expected quote normalization")
	}
	if report.Changes.NormalizedSpaces == 0 {
		t.Error("expected space normalization")
	}

	if !contains(cleaned, "\"Here is your answer\"") {
		t.Errorf("expected normalized quotes in output: %q", cleaned)
	}
}

func TestHeuristicDetector(t *testing.T) {
	detector := NewHeuristicDetector()
	if detector.Name() != "heuristic" {
		t.Errorf("got name %q, want %q", detector.Name(), "heuristic")
	}

	findings, err := detector.Detect("hello\u200Bworld\u200Ctest")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestNFKC(t *testing.T) {
	opts := Defaults()
	opts.Nfkc = true
	opts.RemoveZeroWidth = false
	opts.RemoveVariationSelectors = false

	input := "hello\uFF21world"
	expected := "helloAworld"
	cleaned, _ := Sanitize(input, opts)
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
}

func TestDetectorInterface(t *testing.T) {
	var d Detector = NewHeuristicDetector()
	findings, err := d.Detect("test\u200B")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestMultipleZWRemovals(t *testing.T) {
	input := "\u200B\u200C\u200D\u2060\uFEFF"
	cleaned, report := CleanText(input)
	if cleaned != "" {
		t.Errorf("got %q, want empty string", cleaned)
	}
	if report.Changes.RemovedZeroWidth != 5 {
		t.Errorf("expected 5 removals, got %d", report.Changes.RemovedZeroWidth)
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{
		Category:  "zero_width",
		Name:      "ZERO WIDTH SPACE",
		Notation:  "U+200B",
		CodePoint: 0x200B,
		Index:     3,
		Count:     2,
	}
	s := f.String()
	if s != "U+200B ZERO WIDTH SPACE [zero_width] x2" {
		t.Errorf("got %q, want %q", s, "U+200B ZERO WIDTH SPACE [zero_width] x2")
	}
}

func TestReportSummary(t *testing.T) {
	r := &Report{}
	if r.Summary() != "No changes made." {
		t.Errorf("got %q", r.Summary())
	}

	r.Modified = true
	r.Changes.Total = 5
	if r.Summary() == "No changes made." {
		t.Errorf("expected modified summary")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
