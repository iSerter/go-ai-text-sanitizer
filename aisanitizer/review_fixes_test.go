package aisanitizer

import "testing"

// Regression tests for issues found in code review.

func TestHTMLEntitiesInCodeAreKept(t *testing.T) {
	for _, in := range []string{
		"Use `&#8203;` for ZWSP",
		"```\n&ZeroWidthSpace;\n```\n",
		"    text ``&#x200B;`` text",
	} {
		check(t, nil, in, in)
	}
	check(t, nil, "a&#8203;b `&#8203;`", "ab `&#8203;`")
}

func TestTabAndNewlineFoldingFollowsControlRule(t *testing.T) {
	o := withOpts(func(o *Options) { o.KeepTabs, o.KeepNewlines, o.StripControl = false, false, false })
	check(t, o, "a\tb\nc", "a\tb\nc")
	o = withOpts(func(o *Options) { o.KeepTabs = false })
	o.SetRule(RuleControl, false)
	check(t, o, "a\tb", "a\tb")
}

func TestLineSeparatorsFoldWithoutNewlines(t *testing.T) {
	o := withOpts(func(o *Options) { o.KeepNewlines = false })
	for in, want := range map[string]string{
		"x\u2028y\nz":     "x y z",
		"x\u2029y\u0085z": "x y z",
		"x\u2028y & z":    "x y & z",
	} {
		check(t, o, in, want)
		if again, _ := Sanitize(want, o); again != want {
			t.Errorf("not idempotent: %q -> %q", want, again)
		}
	}
}

func TestExcessBlankLinesCountLines(t *testing.T) {
	o := withOpts(func(o *Options) { o.CollapseWhitespace = true })
	for _, in := range []string{"a\r\n\r\n\r\n\r\nb", "a\n\n\n\nb"} {
		_, rep := Sanitize(in, o)
		f := findRule(rep, RuleCollapseWhitespace)
		if f == nil || f.Count != 2 {
			t.Errorf("%q: finding = %+v", in, f)
		}
	}
}

func TestHeadingKeepsTrailingHashInWord(t *testing.T) {
	o := withOpts(func(o *Options) { o.StripMarkdown = true })
	check(t, o, "# Learn C#", "Learn C#")
	check(t, o, "## F# and C# ##", "F# and C#")
	check(t, o, "### Title ###\n", "Title\n")
}

func TestBoilerplateNeverEmptiesText(t *testing.T) {
	o := withOpts(func(o *Options) { o.RemoveChatBoilerplate = true })
	for _, in := range []string{
		"Hope this helps!",
		"Let me know if the contract terms change.\n",
		"Sure!\n\nHope this helps!\n",
	} {
		check(t, o, in, in)
	}
	check(t, o, "Answer.\n\nHope this helps!", "Answer.")
}

func TestDashCommaCollapsesDashRuns(t *testing.T) {
	o := withOpts(func(o *Options) { o.DashStyle = DashComma })
	check(t, o, "x \u2014\u2014 y", "x, y")
	check(t, o, "x \u2014 \u2014 y", "x, y")
	check(t, o, "x\u2014\u2014y", "x, y")
	rep := check(t, o, "1\u2013\u20132", "1-2")
	if rep.Changes.NormalizedDashes != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}
