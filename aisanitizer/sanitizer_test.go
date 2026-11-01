package aisanitizer

import (
	"encoding/json"
	"strings"
	"testing"
	"unsafe"
)

// check runs Sanitize and compares the output.
func check(t *testing.T, opts *Options, in, want string) *Report {
	t.Helper()
	got, report := Sanitize(in, opts)
	if got != want {
		t.Errorf("Sanitize(%+q)\n  got:  %+q\n  want: %+q", in, got, want)
	}
	if report.Modified != (got != in) {
		t.Errorf("Modified=%v but output changed=%v", report.Modified, got != in)
	}
	return report
}

func withOpts(fn func(o *Options)) *Options {
	o := Defaults()
	fn(o)
	return o
}

func TestCleanTextPreservesNormalText(t *testing.T) {
	for _, in := range []string{
		"Hello, world! This is normal text with numbers 123 and symbols @#$%.",
		"\u00DCn\u00EFc\u00F6d\u00E9 caf\u00E9 \u2014 \u201Cquotes\u201D and\u2026 ellipsis stay by default.",
		"\u65E5\u672C\u8A9E\u306E\u30C6\u30AD\u30B9\u30C8\u3068\u4E2D\u6587\u6587\u672C\u3002\uD55C\uAD6D\uC5B4 \uD14D\uC2A4\uD2B8.",
		"Tabs\tand\nnewlines\r\nstay.",
		"",
	} {
		r := check(t, nil, in, in)
		if r.WasModified() || r.HasFindings() || r.Risk != RiskNone {
			t.Errorf("%q: unexpected report %+v", in, r)
		}
	}
}

func TestCleanTextReturnsInputWithoutCopy(t *testing.T) {
	in := strings.Repeat("plain ascii text ", 10)
	out, _ := CleanText(in)
	if unsafe.StringData(out) != unsafe.StringData(in) {
		t.Fatal("unchanged input was copied")
	}
}

func TestRemoveZeroWidth(t *testing.T) {
	for name, r := range map[string]string{"ZWSP": "\u200B", "ZWNJ": "\u200C", "ZWJ": "\u200D", "WJ": "\u2060", "BOM": "\uFEFF"} {
		t.Run(name, func(t *testing.T) {
			rep := check(t, nil, "a"+r+"b", "ab")
			if rep.Changes.RemovedZeroWidth != 1 || rep.Changes.Total != 1 {
				t.Errorf("changes = %+v", rep.Changes)
			}
		})
	}
	rep := check(t, nil, "\u200B\u200C\u200D\u2060\uFEFF", "")
	if rep.Changes.RemovedZeroWidth != 5 {
		t.Errorf("removed %d, want 5", rep.Changes.RemovedZeroWidth)
	}
}

func TestRemoveInvisibleMath(t *testing.T) {
	for _, r := range []rune{0x2061, 0x2062, 0x2063, 0x2064} {
		rep := check(t, nil, "a"+string(r)+"b", "ab")
		if rep.Changes.RemovedInvisibleMath != 1 {
			t.Errorf("U+%04X: %+v", r, rep.Changes)
		}
	}
}

func TestRemoveVariationSelectors(t *testing.T) {
	rep := check(t, nil, "a\uFE00b\uFE0Fc", "abc")
	if rep.Changes.RemovedVariationSelectors != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestRemoveTagChars(t *testing.T) {
	rep := check(t, nil, "a\U000E0001b\U000E0020c", "abc")
	if rep.Changes.RemovedTagChars != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestRemoveFormatChars(t *testing.T) {
	for _, r := range []rune{
		0x00AD, 0x034F, 0x3164, 0xFFA0, 0x115F, 0x17B4, 0x180E, 0x2065, 0x206A, 0x206F,
		0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0x1BCA0, 0x1BCA3, 0x1D159, 0x1D173, 0xE0080, 0xE0FFF,
	} {
		rep := check(t, nil, "a"+string(r)+"b", "ab")
		if rep.Changes.RemovedFormatChars != 1 {
			t.Errorf("U+%04X: %+v", r, rep.Changes)
		}
	}
	// Visible musical symbols next to U+1D159 must not be touched.
	check(t, nil, "\U0001D15A\U0001D15F", "\U0001D15A\U0001D15F")
}

func TestRemoveBrailleBlankAndNoncharacters(t *testing.T) {
	rep := check(t, nil, "a\u2800b\uFDD0c\uFFFEd\U0001FFFFe", "abcde")
	if rep.Changes.RemovedBrailleBlank != 1 || rep.Changes.RemovedNoncharacters != 3 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestPrivateUse(t *testing.T) {
	in := "icon \uF101 here"
	check(t, nil, in, in)
	rep, _ := Detect(in, nil)
	if rep.Count(RulePrivateUse) != 1 || rep.Findings[0].Action != ActionDetect {
		t.Errorf("detect findings = %+v", rep.Findings)
	}
	check(t, withOpts(func(o *Options) { o.RemovePrivateUse = true }), in, "icon  here")
}

func TestStripControl(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"Null", "a\x00b", "ab"},
		{"Bell", "a\x07b", "ab"},
		{"ESC", "a\x1Bb", "ab"},
		{"DEL", "a\x7Fb", "ab"},
		{"C1", "a\u0090b", "ab"},
		{"KeepTab", "a\tb", "a\tb"},
		{"KeepLF", "a\nb", "a\nb"},
		{"KeepCR", "a\rb", "a\rb"},
		{"ANSI CSI", "\x1b[1;31mred\x1b[0m!", "red!"},
		{"ANSI OSC", "\x1b]0;title\x07text", "text"},
		{"ANSI two-byte", "a\x1bMb", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { check(t, nil, tt.in, tt.want) })
	}
	rep := check(t, nil, "\x1b[31mx", "x")
	if rep.Changes.RemovedANSIEscapes != 1 || rep.Changes.RemovedControl != 0 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestKeepTabsAndNewlinesOff(t *testing.T) {
	o := withOpts(func(o *Options) { o.KeepTabs, o.KeepNewlines = false, false })
	check(t, o, "a\tb\nc\r\nd\re", "a b c d e")
}

func TestNormalizeSpaces(t *testing.T) {
	rep := check(t, nil, "a\u00A0b\u2003c\u202Fd\u3000e\u1680f", "a b c d e f")
	if rep.Changes.NormalizedSpaces != 5 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	check(t, withOpts(func(o *Options) { o.NormalizeSpaces = false }), "a\u00A0b", "a\u00A0b")
}

func TestNormalizeLineSeparators(t *testing.T) {
	rep := check(t, nil, "a\u2028b\u2029c\u0085d", "a\nb\n\nc\nd")
	if rep.Changes.NormalizedLineSeparators != 3 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestInvalidUTF8(t *testing.T) {
	rep := check(t, nil, "a\xffb\xc3", "a\uFFFDb\uFFFD")
	if rep.Changes.ReplacedInvalidUTF8 != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	check(t, withOpts(func(o *Options) { o.InvalidUTF8 = InvalidUTF8Drop }), "a\xffb", "ab")

	err := CheckUTF8("ok\xff")
	if e, ok := err.(*InvalidUTF8Error); !ok || e.Offset != 2 || e.Byte != 0xFF {
		t.Errorf("CheckUTF8 = %v", err)
	}
	if CheckUTF8("fine \u2713") != nil {
		t.Error("valid input reported invalid")
	}
}

func TestHTMLEntities(t *testing.T) {
	rep := check(t, nil, "a&#8203;b&#x200b;c&ZeroWidthSpace;d&#xE0041;e", "abcde")
	if rep.Changes.RemovedHTMLEntities != 4 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	// Entities with legitimate HTML uses are untouched.
	for _, in := range []string{"&nbsp;", "&shy;", "&zwj;", "&#8205;", "&lrm;", "&#xFE0F;", "&amp;", "&#65;", "AT&T", "&#;"} {
		check(t, nil, in, in)
	}
	check(t, withOpts(func(o *Options) { o.RemoveZeroWidth = false }), "a&#8203;b", "a&#8203;b")
}

func TestNilOptionsUseDefaults(t *testing.T) {
	got, rep := Sanitize("hello\u200Bworld", nil)
	if got != "helloworld" || !rep.WasModified() {
		t.Errorf("got %q, %+v", got, rep)
	}
}

func TestDeprecatedRewriteIsNoOp(t *testing.T) {
	in := "He said \"this is very important\". Also use it."
	for _, s := range []RewriteStrategy{RewriteNone, RewriteLight, RewriteAggressive} {
		got, rep, err := SanitizeWithRewrite(in, nil, s)
		if err != nil || got != in || rep.Changes.RewrittenSegments != 0 {
			t.Errorf("strategy %d: got %q (%v)", s, got, err)
		}
	}
}

func TestDeprecatedAliases(t *testing.T) {
	check(t, withOpts(func(o *Options) { o.Nfkc = true }), "hello\uFF21world", "helloAworld")
	check(t, withOpts(func(o *Options) { o.NormalizeDashes = true }), "a\u2014b", "a-b")
	check(t, withOpts(func(o *Options) { o.KeepBidi = true }), "a\u202Eb", "a\u202Eb")
}

func TestReportJSON(t *testing.T) {
	_, report := CleanText("a\u200Bb\u200Cc")
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"modified":true`, `"risk":"low"`, `"removed_zero_width":2`, `"rule":"zero_width"`, `"category":"invisible"`, `"notation":"U+200B"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("JSON missing %s: %s", key, data)
		}
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Changes.Total != report.Changes.Total || len(decoded.Findings) != 2 {
		t.Errorf("round trip mismatch: %+v", decoded)
	}
}

func TestFindingString(t *testing.T) {
	f := Finding{Rule: RuleZeroWidth, Name: "ZERO WIDTH SPACE", Notation: "U+200B", Count: 2}
	if got, want := f.String(), "U+200B ZERO WIDTH SPACE [zero_width] x2"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	f.Payload = "hi"
	if !strings.HasSuffix(f.String(), `payload="hi"`) {
		t.Errorf("got %q", f.String())
	}
}

func TestReportSummaryAndHelpers(t *testing.T) {
	r := &Report{}
	if r.Summary() != "No changes made." {
		t.Errorf("got %q", r.Summary())
	}
	_, r = Sanitize("x\u201Cy\u201D\u200B", withOpts(func(o *Options) { o.NormalizeSmartQuotes = true }))
	if !r.HasWatermarks() || r.Count(RuleSmartQuote) != 2 || r.Count(RuleZeroWidth) != 1 {
		t.Errorf("report = %+v", r)
	}
	if !strings.Contains(r.String(), "[smart_quote] x1") {
		t.Errorf("String() = %q", r.String())
	}
	_, typoOnly := Sanitize("\u201Cy\u201D", withOpts(func(o *Options) { o.NormalizeSmartQuotes = true }))
	if typoOnly.HasWatermarks() {
		t.Error("typography alone should not count as a watermark")
	}

	merged := &Report{}
	merged.Merge(r)
	merged.Merge(typoOnly)
	if merged.Changes.Total != r.Changes.Total+typoOnly.Changes.Total || len(merged.Findings) != len(r.Findings)+len(typoOnly.Findings) || merged.Risk != RiskLow {
		t.Errorf("merged = %+v", merged)
	}
}

func TestFindingsAreDeterministicAndOrdered(t *testing.T) {
	in := "a\u200Bb\u200Cc\u00A0d\u2060 e\u200B"
	first, _ := Detect(in, nil)
	for i := 0; i < 20; i++ {
		again, _ := Detect(in, nil)
		if len(again.Findings) != len(first.Findings) {
			t.Fatal("finding count changed")
		}
		for j := range again.Findings {
			if again.Findings[j].Notation != first.Findings[j].Notation {
				t.Fatalf("order changed: %v vs %v", again.Findings, first.Findings)
			}
		}
	}
	for j := 1; j < len(first.Findings); j++ {
		if first.Findings[j-1].Index > first.Findings[j].Index {
			t.Errorf("findings not sorted by index: %v", first.Findings)
		}
	}
}

func TestPositions(t *testing.T) {
	o := withOpts(func(o *Options) { o.MaxPositions = 2 })
	in := "line one\nl\u00E9\u200Bx (oaicite:1){index=1}\n\u200Bend\u200B"
	_, rep := Sanitize(in, o)
	var zw, cite *Finding
	for i := range rep.Findings {
		switch rep.Findings[i].Rule {
		case RuleZeroWidth:
			zw = &rep.Findings[i]
		case RuleOaicite:
			cite = &rep.Findings[i]
		}
	}
	if zw == nil || cite == nil {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	if zw.Count != 3 || len(zw.Positions) != 2 {
		t.Fatalf("zw = %+v", zw)
	}
	if p := zw.Positions[0]; p.Line != 2 || p.Column != 3 || p.Offset != strings.Index(in, "\u200B") {
		t.Errorf("first ZW position = %+v", p)
	}
	if p := zw.Positions[1]; p.Line != 3 || p.Column != 1 {
		t.Errorf("second ZW position = %+v", p)
	}
	// The citation is matched after the ZWSP was removed; its index must
	// still point into the original input.
	if cite.Index != strings.Index(in, "(oaicite") || cite.Positions[0].Line != 2 || cite.Positions[0].Column != 6 {
		t.Errorf("citation = %+v", cite)
	}
}

func TestDetectMatchesSanitize(t *testing.T) {
	in := "x\u200By \u202Ez (oaicite:0){index=0} \u00A0"
	rep, err := Detect(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Modified || rep.Changes.Total != 0 {
		t.Errorf("Detect reported changes: %+v", rep)
	}
	_, srep := CleanText(in)
	if len(rep.Findings) != len(srep.Findings) {
		t.Errorf("Detect found %d, Sanitize %d", len(rep.Findings), len(srep.Findings))
	}
	if rep.Risk != RiskHigh {
		t.Errorf("bidi override should be high risk, got %s", rep.Risk)
	}
	// Detect honours options.
	rep, _ = Detect(in, withOpts(func(o *Options) { o.RemoveZeroWidth = false }))
	if rep.Count(RuleZeroWidth) != 0 {
		t.Error("disabled rule reported")
	}
}

type fakeDetector struct{}

func (fakeDetector) Name() string { return "fake" }
func (fakeDetector) Detect(text string) ([]Finding, error) {
	return []Finding{{Name: "FAKE", Count: 1}}, nil
}

func TestExtraDetectors(t *testing.T) {
	o := withOpts(func(o *Options) { o.ExtraDetectors = []Detector{fakeDetector{}} })
	rep, err := Detect("plain", o)
	if err != nil || len(rep.Findings) != 1 || rep.Findings[0].Rule != "fake" || rep.Findings[0].Action != ActionDetect {
		t.Errorf("findings = %+v, err = %v", rep.Findings, err)
	}
	var d Detector = NewHeuristicDetector()
	fs, err := d.Detect("test\u200B")
	if err != nil || len(fs) != 1 || d.Name() != "heuristic" {
		t.Errorf("heuristic detector: %+v %v", fs, err)
	}
}

func TestSanitizeBytesAndReader(t *testing.T) {
	out, rep := SanitizeBytes([]byte("a\u200Bb"), nil)
	if string(out) != "ab" || !rep.Modified {
		t.Errorf("SanitizeBytes = %q", out)
	}
	var sb strings.Builder
	rep, err := SanitizeReader(strings.NewReader("c\u200Bd"), &sb, nil)
	if err != nil || sb.String() != "cd" || rep.Changes.Total != 1 {
		t.Errorf("SanitizeReader = %q, %v", sb.String(), err)
	}
}

func TestRealWorldLLMOutput(t *testing.T) {
	in := "\u201CHere is your answer\u201D\u200B\n\n(oaicite:0){index=0}\n\nSome\u00A0text\u2003with\u00A0weird\u00A0spaces."
	o := withOpts(func(o *Options) { o.NormalizeSmartQuotes, o.CollapseWhitespace, o.Trim = true, true, true })
	got, rep := Sanitize(in, o)
	want := "\"Here is your answer\"\n\nSome text with weird spaces."
	if got != want {
		t.Errorf("got %+q\nwant %+q", got, want)
	}
	for name, n := range map[string]int{
		"zero width": rep.Changes.RemovedZeroWidth, "citations": rep.Changes.RemovedCitations,
		"quotes": rep.Changes.NormalizedSmartQuotes, "spaces": rep.Changes.NormalizedSpaces,
	} {
		if n == 0 {
			t.Errorf("expected %s changes", name)
		}
	}
}

func TestReveal(t *testing.T) {
	got := Reveal("a\u200Bb\u00A0c\x1bd\te\n\xff\U0001F600")
	want := "a\u27E8U+200B\u27E9b\u27E8U+00A0\u27E9c\u27E8U+001B\u27E9d\te\n\u27E8invalid 0xFF\u27E9\U0001F600"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}
