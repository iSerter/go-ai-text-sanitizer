package aisanitizer

import (
	"strings"
	"testing"
	"unicode/utf8"
)

var fuzzSeeds = []string{
	"",
	"plain text",
	"a\u200Bb\u200C\u200D\u2060\uFEFF",
	"\U0001F468\u200D\U0001F469\u200D\U0001F467 \u2764\uFE0F 1\uFE0F\u20E3",
	"\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F",
	"\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645 \u0915\u094D\u200D\u0937",
	"x (oaicite:1){index=1} :contentReference[oaicite:0]{index=0}",
	"\uE200cite\uE202turn0search0\uE201 citeturn0news1 \u30104:0\u2020source\u3011",
	"https://x.io/?a=1&utm_source=chatgpt.com#f [web:1] [cite: 1, 2]",
	"&#8203;&ZeroWidthSpace;&#xE0041;\x1b[31m\x1b]0;t\x07",
	"\u201Cq\u201D \u2014 a\u2026 \uFB01 \uFF21 p\u0430yp\u0430l",
	"```\ncode  \n```\n# H\n**b** _i_ [l](u)\n\n\n\n",
	"Sure! Here's it:\nbody\nI hope this helps!",
	"a\xffb\xc3",
	"\u202Eevil\u202C \u2066x\u2069",
}

func FuzzSanitize(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	paranoid, _ := Preset(PresetParanoid)
	f.Fuzz(func(t *testing.T, in string) {
		for _, o := range []*Options{Defaults(), paranoid} {
			out, rep := Sanitize(in, o)
			if !utf8.ValidString(out) {
				t.Fatalf("invalid UTF-8 output %+q", out)
			}
			if rep.Modified != (out != in) {
				t.Fatalf("Modified=%v for %+q -> %+q", rep.Modified, in, out)
			}
			again, rep2 := Sanitize(out, o)
			if again != out {
				t.Fatalf("not idempotent:\n in     %+q\n first  %+q\n second %+q (%v)", in, out, again, rep2.Findings)
			}
			for _, fd := range rep.Findings {
				if fd.Index < 0 || fd.Index > len(in) {
					t.Fatalf("finding index %d out of range for %+q", fd.Index, in)
				}
			}
		}
		// With defaults, no tag/BOM/word-joiner/invisible-math/noncharacter
		// survives regardless of context.
		out, _ := CleanText(in)
		for _, r := range out {
			if (r >= 0xE0000 && r <= 0xE001F) || r == 0xFEFF || r == 0x2060 || (r >= 0x2061 && r <= 0x2064) || isNoncharacter(r) || r == 0x200B {
				t.Fatalf("default output kept U+%04X: %+q", r, out)
			}
		}
		// Detect reports something exactly when default sanitizing changes
		// the (valid UTF-8) text through character rules.
		if utf8.ValidString(in) && !strings.ContainsAny(in, "&\x1b") {
			rep, err := Detect(in, nil)
			if err != nil {
				t.Fatal(err)
			}
			if out != in && !rep.HasFindings() {
				t.Fatalf("Sanitize changed %+q but Detect found nothing", in)
			}
		}
	})
}

func FuzzOffsets(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		o := withOpts(func(o *Options) { o.MaxPositions = 4 })
		_, rep := Sanitize(in, o)
		for _, fd := range rep.Findings {
			for _, p := range fd.Positions {
				if p.Offset < 0 || p.Offset > len(in) || p.Line < 1 || p.Column < 1 {
					t.Fatalf("bad position %+v for %+q", p, in)
				}
			}
		}
	})
}
