package aisanitizer

import "strings"

type quoteReplacement struct {
	old string
	new string
}

var quoteReplacements = []quoteReplacement{
	{"\u2018", "'"},
	{"\u2019", "'"},
	{"\u201A", "'"},
	{"\u201B", "'"},
	{"\u201C", "\""},
	{"\u201D", "\""},
	{"\u201E", "\""},
	{"\u201F", "\""},
	{"\u2039", "<"},
	{"\u203A", ">"},
	{"\u00AB", "\""},
	{"\u00BB", "\""},
}

var dashReplacements = []quoteReplacement{
	{"\u2010", "-"},
	{"\u2011", "-"},
	{"\u2012", "-"},
	{"\u2013", "-"},
	{"\u2014", "-"},
	{"\u2015", "-"},
	{"\u2212", "-"},
}

func makeReplacer(replacements []quoteReplacement) *strings.Replacer {
	args := make([]string, 0, len(replacements)*2)
	for _, r := range replacements {
		args = append(args, r.old, r.new)
	}
	return strings.NewReplacer(args...)
}

var (
	quoteReplacer = makeReplacer(quoteReplacements)
	dashReplacer  = makeReplacer(dashReplacements)
)

func normalizeSmartQuotes(s string) (string, int) {
	before := countRunesIn(s, isQuote)
	if before == 0 {
		return s, 0
	}
	result := quoteReplacer.Replace(s)
	return result, before
}

func normalizeDashes(s string) (string, int) {
	before := countRunesIn(s, isDash)
	if before == 0 {
		return s, 0
	}
	result := dashReplacer.Replace(s)
	return result, before
}

func normalizeEllipsis(s string) (string, int) {
	count := strings.Count(s, "\u2026")
	if count == 0 {
		return s, 0
	}
	result := strings.ReplaceAll(s, "\u2026", "...")
	return result, count
}

func countRunesIn(s string, fn func(rune) bool) int {
	count := 0
	for _, r := range s {
		if fn(r) {
			count++
		}
	}
	return count
}
