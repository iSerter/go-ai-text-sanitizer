package aisanitizer

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"unicode"
)

// Every Default_Ignorable_Code_Point must be handled by an invisible-char
// rule, so regenerating the tables for a new Unicode version cannot silently
// leave new invisibles behind.
func TestDefaultIgnorableCoverage(t *testing.T) {
	invisible := map[charClass]bool{
		clsZeroWidth: true, clsBidi: true, clsInvisibleMath: true,
		clsVariationSelector: true, clsTag: true, clsFormat: true,
	}
	for _, rng := range tblDefaultIgnorable.R16 {
		for r := rune(rng.Lo); r <= rune(rng.Hi); r++ {
			if !invisible[classify(r)] {
				t.Errorf("U+%04X is default-ignorable but classified as %d", r, classify(r))
			}
		}
	}
	for _, rng := range tblDefaultIgnorable.R32 {
		for r := rune(rng.Lo); r <= rune(rng.Hi); r++ {
			if !invisible[classify(r)] {
				t.Errorf("U+%04X is default-ignorable but classified as %d", r, classify(r))
			}
		}
	}
}

func TestClassifyLeavesOrdinaryTextAlone(t *testing.T) {
	for _, r := range "a\u00E9\u00DF\u03A9\u0416\u05D0\uD55C\u4E2D\U0001F600\u2018\u2019\u201C\u201D\u2014\u2013\u2026\u20AC\u2122\u00A9\u00AE\u00B0\u00B1\u00A7\u00B6\u2022\u2192" {
		if c := classify(r); c != clsNone {
			t.Errorf("%q (U+%04X) classified as %d", r, r, c)
		}
	}
}

func TestCharacterNames(t *testing.T) {
	for r, want := range map[rune]string{
		0x200B: "ZERO WIDTH SPACE", 0xFE0F: "VARIATION SELECTOR-16", 0xFE00: "VARIATION SELECTOR-1",
		0xE0100: "VARIATION SELECTOR-17", 0xE0041: "TAG LATIN CAPITAL LETTER A", 0xE007F: "CANCEL TAG",
		0x1B: "ESCAPE", 0x202F: "NARROW NO-BREAK SPACE", 0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
		0xFDD0: "NONCHARACTER", 0xE000: "PRIVATE USE CHARACTER", 0x0085: "NEXT LINE (NEL)",
	} {
		if got := runeName(r); got != want {
			t.Errorf("runeName(U+%04X) = %q, want %q", r, got, want)
		}
	}
}

// Every fully-qualified emoji sequence from emoji-test.txt must survive the
// default options untouched, on its own and between letters.
func TestEmojiSequencesSurvive(t *testing.T) {
	f, err := os.Open("testdata/emoji-fully-qualified.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		seq := sc.Text()
		if strings.HasPrefix(seq, "#") || seq == "" {
			continue
		}
		n++
		for _, in := range []string{seq, "a" + seq + "b", seq + seq} {
			if got, _ := CleanText(in); got != in {
				t.Errorf("emoji %+q changed to %+q", in, got)
			}
		}
	}
	if n < 3000 {
		t.Fatalf("only %d emoji sequences loaded", n)
	}
}

func TestEmojiContextIsStrict(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"ZWJ between letters", "a\u200Db", "ab"},
		{"ZWJ after emoji before letter", "\U0001F600\u200Da", "\U0001F600a"},
		{"VS16 after letter", "a\uFE0F", "a"},
		{"double VS16", "\u2764\uFE0F\uFE0F", "\u2764\uFE0F"},
		{"VS16 after digit without keycap", "1\uFE0F", "1"},
		{"VS17 after emoji", "\U0001F600\U000E0100", "\U0001F600"},
		{"tags without black flag", "x\U000E0067\U000E0062\U000E007F", "x"},
		{"tag payload after black flag", "\U0001F3F4\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065\U000E0061\U000E006C\U000E007F", "\U0001F3F4"},
		{"ZWSP inside family", "\U0001F468\u200B\u200D\U0001F469", "\U0001F468\U0001F469"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { check(t, nil, tt.in, tt.want) })
	}
	noEmoji := withOpts(func(o *Options) { o.KeepEmoji, o.KeepScriptFormatting = false, false })
	check(t, noEmoji, "\U0001F468\u200D\U0001F469 \u2764\uFE0F", "\U0001F468\U0001F469 \u2764")
}

func TestScriptJoinersArePreserved(t *testing.T) {
	keep := []struct{ name, text string }{
		{"Persian ZWNJ", "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645"},
		{"Persian plural", "\u06A9\u062A\u0627\u0628\u200C\u0647\u0627"},
		{"Kurdish ZWNJ", "\u062F\u0647\u200C\u06A9\u06D5\u0645"},
		{"Hindi half form ZWJ", "\u0915\u094D\u200D\u0937"},
		{"Hindi explicit virama ZWNJ", "\u0915\u094D\u200C\u0937"},
		{"Bengali ZWJ", "\u09B0\u09CD\u200D\u09AF"},
		{"Malayalam chillu ZWJ", "\u0D28\u0D4D\u200D"},
		{"Sinhala ZWJ", "\u0DC1\u0DCA\u200D\u0DBB"},
		{"Mongolian FVS", "\u1820\u180B\u1821"},
		{"Mongolian MVS", "\u1828\u180E\u1820"},
		{"Hangul jamo filler", "\u115F\u1161"},
		{"Ideographic variation sequence", "\u845B\U000E0100"},
		{"Standardized variant", "0\uFE00"},
	}
	for _, tt := range keep {
		t.Run(tt.name, func(t *testing.T) {
			check(t, nil, tt.text, tt.text)
			check(t, nil, "Latin "+tt.text+" text", "Latin "+tt.text+" text")
		})
	}
	off := withOpts(func(o *Options) { o.KeepScriptFormatting = false })
	check(t, off, "\u0645\u06CC\u200C\u062E", "\u0645\u06CC\u062E")
	check(t, off, "\u845B\U000E0100", "\u845B")
	// Joiners in Latin text, or ZWNJ next to non-joining letters, still go.
	check(t, nil, "auf\u200Clage", "auflage")
	check(t, nil, "\u0627\u200C\u0628", "\u0627\u0628") // ALEF is right-joining only
	check(t, nil, "\u845B\U000E0100\U000E0101", "\u845B\U000E0100")
	check(t, nil, "a\u180Bb", "ab")
	check(t, nil, "a\u3164b", "ab")
}

func TestBidiModes(t *testing.T) {
	hebrew := "\u05E9\u05DC\u05D5\u05DD \u200Fabc\u200E"
	check(t, nil, hebrew, hebrew)
	check(t, nil, "abc\u200F def\u061C", "abc def")
	// Overrides and isolates are removed even in RTL text (Trojan Source).
	check(t, nil, "\u05D0\u202Ex\u202C\u2066y\u2069", "\u05D0xy")
	check(t, withOpts(func(o *Options) { o.BidiMode = BidiRemove }), hebrew, "\u05E9\u05DC\u05D5\u05DD abc")
	check(t, withOpts(func(o *Options) { o.BidiMode = BidiKeep }), "a\u202Eb", "a\u202Eb")
	check(t, withOpts(func(o *Options) { o.RemoveBidi = false }), "a\u202Eb", "a\u202Eb")
}

func TestFrenchSpacing(t *testing.T) {
	in := "Bonjour\u202F! \u00AB\u00A0Oui\u00A0\u00BB co\u00FBte 1\u202F000\u00A0\u20AC et a\u00A0b"
	want := "Bonjour\u202F! \u00AB\u00A0Oui\u00A0\u00BB co\u00FBte 1\u202F000\u00A0\u20AC et a b"
	check(t, withOpts(func(o *Options) { o.KeepFrenchSpacing = true }), in, want)
	got, _ := CleanText(in)
	if strings.ContainsAny(got, "\u202F\u00A0") {
		t.Errorf("default options kept French spaces: %+q", got)
	}
}

func TestRuleOverrides(t *testing.T) {
	o := Defaults()
	if err := o.SetRule(RuleZeroWidth, false); err != nil {
		t.Fatal(err)
	}
	check(t, o, "a\u200Bb", "a\u200Bb")
	if err := o.SetRule("nope", true); err == nil {
		t.Error("unknown rule accepted")
	}
	o = Defaults()
	_ = o.SetRule(RuleFootnoteBacklink, true)
	check(t, o, "text \u21A9\uFE0E", "text")
	if !o.Enabled(RuleFootnoteBacklink) || o.Enabled(RuleSmartQuote) || o.Enabled("nope") {
		t.Error("Enabled() mismatch")
	}
	// Forcing the dash rule on without a style uses DashHyphen.
	o = Defaults()
	_ = o.SetRule(RuleDash, true)
	check(t, o, "a\u2014b", "a-b")
}

func TestUnicodeVersion(t *testing.T) {
	if UnicodeVersion == "" || !unicode.Is(tblExtPict, 0x1F600) {
		t.Error("generated tables missing")
	}
}
