package aisanitizer

import "testing"

func TestSmartQuotes(t *testing.T) {
	o := withOpts(func(o *Options) { o.NormalizeSmartQuotes = true })
	rep := check(t, o, "\u201CHello\u201D \u2018world\u2019 \u00ABoui\u00BB \u2039x\u203A it\u02BCs \uFF02y\uFF02", "\"Hello\" 'world' \"oui\" 'x' it's \"y\"")
	if rep.Changes.NormalizedSmartQuotes != 11 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	// Code and URLs are left alone.
	check(t, o, "`\u201Cq\u201D` \u201Cq\u201D", "`\u201Cq\u201D` \"q\"")
}

func TestDashStyles(t *testing.T) {
	in := "a\u2014b c \u2013 d 1990\u20132000 x\u2212y e\u2010f"
	for _, tt := range []struct {
		style DashStyle
		want  string
	}{
		{DashKeep, in},
		{DashHyphen, "a-b c - d 1990-2000 x-y e-f"},
		{DashASCII, "a--b c - d 1990-2000 x-y e-f"},
	} {
		check(t, withOpts(func(o *Options) { o.DashStyle = tt.style }), in, tt.want)
	}
}

func TestDashComma(t *testing.T) {
	o := withOpts(func(o *Options) { o.DashStyle = DashComma })
	tests := []struct{ in, want string }{
		{"The plan \u2014 bold as it was \u2014 failed.", "The plan, bold as it was, failed."},
		{"The plan\u2014bold\u2014failed.", "The plan, bold, failed."},
		{"It worked \u2014.", "It worked."},
		{"It worked \u2014\nNext", "It worked\nNext"},
		{"\u2014 Quote author", "- Quote author"},
		{"  \u2014 indented", "  - indented"},
		{"pages 10 \u2014 20", "pages 10-20"},
		{"1990\u20132000", "1990-2000"},
		{"Paris\u2013London", "Paris-London"},
		{"Wait, \u2014 really", "Wait, really"},
		{"a \u2013 b", "a, b"},
		{"see `a\u2014b` and https://x.io/a\u2014b", "see `a\u2014b` and https://x.io/a\u2014b"},
		{"x\u2212y", "x-y"},
	}
	for _, tt := range tests {
		check(t, o, tt.in, tt.want)
	}
}

func TestEllipsisAndPunctuation(t *testing.T) {
	check(t, withOpts(func(o *Options) { o.NormalizeEllipsis = true }), "wait\u2026 what", "wait... what")
	o := withOpts(func(o *Options) { o.NormalizePunctuation = true })
	check(t, o, "\u2022 item \u2192 next \u21D2 done, 3\u00D74 \u2264 12 \u2260 13, 5\u2032", "- item -> next => done, 3x4 <= 12 != 13, 5'")
	check(t, o, "keep \u00A9 \u00AE \u2122 \u00B0 \u00A7", "keep \u00A9 \u00AE \u2122 \u00B0 \u00A7")
}

func TestFoldCompatibility(t *testing.T) {
	o := withOpts(func(o *Options) { o.FoldCompatibility = true })
	tests := []struct{ in, want string }{
		{"\uFB01ne \uFB02ow \uFB00", "fine flow ff"},
		{"\uFF28\uFF45\uFF4C\uFF4C\uFF4F\uFF01", "Hello!"},
		{"\U0001D407\U0001D41E\U0001D425\U0001D425\U0001D428", "Hello"},
		{"\u2460 \u2474 \u00B2 x\u2082", "1 (1) 2 x2"},
		{"\u00BD cup", "1/2 cup"},
		{"\u2026", "..."},
		{"\u3131\u314F", "\u3131\u314F"}, // Hangul compatibility jamo are not folded
		{"\u00E9\u00F1\u00FC", "\u00E9\u00F1\u00FC"},
	}
	for _, tt := range tests {
		check(t, o, tt.in, tt.want)
	}
	rep := check(t, o, "\uFB01", "fi")
	if rep.Changes.FoldedCompatibility != 1 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestConfusables(t *testing.T) {
	in := "Log in to p\u0430yp\u0430l now. \u041C\u043E\u0441\u043A\u0432\u0430 is fine."
	check(t, nil, in, in)

	rep, _ := Detect(in, nil)
	if rep.Count(RuleMixedScript) != 1 || rep.Risk != RiskHigh {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.Payload != "paypal" || f.Index != 10 || f.Notation != "p\u0430yp\u0430l" {
		t.Errorf("finding = %+v", f)
	}

	o := withOpts(func(o *Options) { o.FoldConfusables = true })
	rep = check(t, o, in, "Log in to paypal now. \u041C\u043E\u0441\u043A\u0432\u0430 is fine.")
	if rep.Changes.FoldedConfusables != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	// Words with non-confusable foreign letters are reported but not folded.
	check(t, o, "abc\u0436", "abc\u0436")
	// URLs are never rewritten.
	check(t, o, "https://p\u0430ypal.com", "https://p\u0430ypal.com")

	rep, _ = Detect("Please visit \u0440\u0430\u0443\u0440\u0430\u04CF today and pay your bill online.", nil)
	if rep.Count(RuleMixedScript) != 1 || rep.Findings[0].Name != "WHOLE-SCRIPT CONFUSABLE WORD" {
		t.Errorf("whole-script findings = %+v", rep.Findings)
	}
	rep, _ = Detect("\u041F\u0440\u0438\u0432\u0435\u0442, \u043A\u0430\u043A \u0434\u0435\u043B\u0430?", nil)
	if rep.Count(RuleMixedScript) != 0 {
		t.Errorf("Russian text flagged: %+v", rep.Findings)
	}
}

func TestStripMarkdown(t *testing.T) {
	o := withOpts(func(o *Options) { o.StripMarkdown = true })
	tests := []struct{ in, want string }{
		{"## Heading ##\nText", "Heading\nText"},
		{"This is **bold** and __strong__.", "This is bold and strong."},
		{"An *italic* and _emphasis_ word.", "An italic and emphasis word."},
		{"snake_case_name and 2*3*4 stay", "snake_case_name and 2*3*4 stay"},
		{"See [docs](https://go.dev) or [https://x.io](https://x.io).", "See docs (https://go.dev) or https://x.io."},
		{"![alt text](img.png)", "alt text"},
		{"a\n---\nb\n* * *\nc", "a\n\nb\n\nc"},
		{"> quoted\n> more", "quoted\nmore"},
		{"* one\n+ two\n  \u2022 three\n- four", "- one\n- two\n  - three\n- four"},
		{"```md\n# not a heading **x**\n```", "```md\n# not a heading **x**\n```"},
		{"Use `**raw**` here", "Use `**raw**` here"},
	}
	for _, tt := range tests {
		check(t, o, tt.in, tt.want)
	}
}

func TestPresets(t *testing.T) {
	for _, name := range PresetNames() {
		if _, err := Preset(name); err != nil {
			t.Errorf("Preset(%q): %v", name, err)
		}
	}
	if _, err := Preset("nope"); err == nil {
		t.Error("unknown preset accepted")
	}
	safe, _ := Preset(PresetSafe)
	check(t, safe, "a\u00A0b\u200B", "a\u00A0b")

	plain, _ := Preset(PresetPlain)
	in := "  ## Title\n\n\u201CSmart\u201D \u2014 text\u2026 with \uFB01x  \n\n\n\n**bold**\u200B  "
	check(t, plain, in, "Title\n\n\"Smart\" - text... with fix\n\nbold")

	paranoid, _ := Preset(PresetParanoid)
	if !paranoid.RemovePrivateUse || !paranoid.FoldConfusables || !paranoid.RemoveChatBoilerplate || paranoid.BidiMode != BidiRemove {
		t.Errorf("paranoid = %+v", paranoid)
	}
	if def, _ := Preset(""); def.NormalizeSmartQuotes {
		t.Error("default preset changed typography")
	}
}

func TestOptionsHelpers(t *testing.T) {
	o := Defaults()
	_ = o.SetRule(RuleSmartQuote, true)
	c := o.Clone()
	c.Rules[RuleSmartQuote] = false
	if !o.Enabled(RuleSmartQuote) {
		t.Error("Clone shares the Rules map")
	}
	rules := o.EnabledRules()
	for i := 1; i < len(rules); i++ {
		if rules[i-1] > rules[i] {
			t.Fatal("EnabledRules not sorted")
		}
	}
	if len(Rules()) != numRules {
		t.Error("Rules() incomplete")
	}
	if info, ok := LookupRule(RuleZeroWidth); !ok || info.Category != CategoryInvisible || !info.Default {
		t.Errorf("LookupRule = %+v", info)
	}
	if _, ok := LookupRule("nope"); ok {
		t.Error("unknown rule found")
	}
	// Defaults() must agree with each rule's documented default.
	d := Defaults()
	for _, r := range Rules() {
		if r.Action == ActionDetect {
			continue
		}
		if d.Enabled(r.ID) != r.Default {
			t.Errorf("rule %s: Defaults() enables=%v, registry default=%v", r.ID, d.Enabled(r.ID), r.Default)
		}
	}
}
