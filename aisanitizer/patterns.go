package aisanitizer

import "regexp"

var (
	citationPattern = regexp.MustCompile(`\(oaicite:[0-9]+\)\{index=[0-9]+\}`)
)

func countCitations(s string) int {
	matches := citationPattern.FindAllString(s, -1)
	return len(matches)
}

func removeCitations(s string) (string, int) {
	before := countCitations(s)
	if before == 0 {
		return s, 0
	}
	result := citationPattern.ReplaceAllString(s, "")
	return result, before
}
