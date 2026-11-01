package aisanitizer

import "testing"

func TestCollapseWhitespace(t *testing.T) {
	o := withOpts(func(o *Options) { o.CollapseWhitespace = true })
	tests := []struct{ name, in, want string }{
		{"runs", "a    b   c", "a b c"},
		{"tab runs", "a\t \tb", "a b"},
		{"single tab kept", "a\tb", "a\tb"},
		{"CRLF kept", "a\r\nb", "a\r\nb"},
		{"paragraph kept", "a\n\nb", "a\n\nb"},
		{"excess blank lines", "a\n\n\n\nb", "a\n\nb"},
		{"CRLF blank lines", "a\r\n\r\n\r\n\r\nb", "a\r\n\r\nb"},
		{"trailing spaces", "a   \nb\t\n", "a\nb\n"},
		{"whitespace-only lines", "a\n   \n\t\nb", "a\n\nb"},
		{"indentation kept", "    code  line\n\tx  y", "    code line\n\tx y"},
		{"fenced code untouched", "```\na    b   \n\n\n\n```\nc  d", "```\na    b   \n\n\n\n```\nc d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { check(t, o, tt.in, tt.want) })
	}
	rep := check(t, o, "a   b  \n\n\n\nc", "a b\n\nc")
	if rep.Changes.CollapsedSpaces != 6 {
		t.Errorf("collapsed = %d, want 6", rep.Changes.CollapsedSpaces)
	}

	check(t, withOpts(func(o *Options) { o.CollapseWhitespace, o.MaxBlankLines = true, -1 }), "a\n\n\n\nb", "a\n\n\n\nb")
	check(t, withOpts(func(o *Options) { o.CollapseWhitespace, o.MaxBlankLines = true, 2 }), "a\n\n\n\nb", "a\n\n\nb")
}

func TestTrim(t *testing.T) {
	o := withOpts(func(o *Options) { o.Trim = true })
	rep := check(t, o, " \n hello world \t\n", "hello world")
	if rep.Changes.TrimmedWhitespace != 6 {
		t.Errorf("trimmed = %d", rep.Changes.TrimmedWhitespace)
	}
	check(t, o, "   ", "")
	check(t, o, "x", "x")
}
