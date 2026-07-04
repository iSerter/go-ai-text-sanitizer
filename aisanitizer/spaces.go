package aisanitizer

import "strings"

func normalizeSpaces(s string) (string, int) {
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if isExoticSpace(r) {
			b.WriteRune(' ')
			count++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), count
}

func normalizeLineSeparators(s string) (string, int) {
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	i := 0
	for _, r := range s {
		if r == 0x2028 {
			b.WriteRune('\n')
			count++
		} else if r == 0x2029 {
			b.WriteString("\n\n")
			count++
		} else {
			b.WriteRune(r)
		}
		i++
	}
	return b.String(), count
}

func collapseWhitespace(s string) (string, int) {
	var b strings.Builder
	b.Grow(len(s))
	collapsed := 0
	spaceRun := false
	lastWasNewline := false
	newlineRun := 0

	for _, r := range s {
		if r == '\n' || r == '\r' {
			if lastWasNewline {
				if r == '\n' && newlineRun >= 2 {
					spaceRun = false
					continue
				}
				if r == '\n' {
					newlineRun++
				}
			}
			if newlineRun == 0 {
				spaceRun = false
				b.WriteRune(r)
				lastWasNewline = true
				if r == '\n' {
					newlineRun = 1
				}
				continue
			}
			continue
		}
		lastWasNewline = false
		newlineRun = 0

		if r == ' ' || r == '\t' {
			if spaceRun {
				collapsed++
				continue
			}
			spaceRun = true
			b.WriteRune(r)
		} else {
			spaceRun = false
			b.WriteRune(r)
		}
	}
	return b.String(), collapsed
}

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}
