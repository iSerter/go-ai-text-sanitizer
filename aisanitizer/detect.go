package aisanitizer

import "fmt"

type Detector interface {
	Name() string
	Detect(text string) ([]Finding, error)
}

type HeuristicDetector struct{}

func NewHeuristicDetector() *HeuristicDetector {
	return &HeuristicDetector{}
}

func (d *HeuristicDetector) Name() string {
	return "heuristic"
}

func (d *HeuristicDetector) Detect(text string) ([]Finding, error) {
	var findings []Finding
	seen := make(map[string]int)
	firstIdx := make(map[string]int)
	firstRune := make(map[string]rune)
	categories := make(map[string]string)
	names := make(map[string]string)
	notations := make(map[string]string)

	for i, r := range text {
		var cat, name, notation string
		var matched bool

		switch {
		case isZeroWidth(r):
			cat, name, notation = "zero_width", zeroWidthName(r), zeroWidthNotation(r)
			matched = true
		case isBidi(r):
			cat, name, notation = "bidi", bidiName(r), bidiNotation(r)
			matched = true
		case isInvisibleMath(r):
			cat, name, notation = "invisible_math", invisibleMathName(r), invisibleMathNotation(r)
			matched = true
		case isVariationSelector(r):
			cat, name, notation = "variation_selector", variationSelectorName(r), variationSelectorNotation(r)
			matched = true
		case isTagChar(r):
			cat, name, notation = "tag_char", tagCharName(r), tagCharNotation(r)
			matched = true
		case isFormatChar(r):
			cat, name, notation = "format_char", formatCharName(r), formatCharNotation(r)
			matched = true
		case isBrailleBlank(r):
			cat, name, notation = "braille_blank", "BRAILLE PATTERN BLANK", "U+2800"
			matched = true
		case isControl(r):
			cat, name, notation = "control", controlName(r), controlNotation(r)
			matched = true
		case isExoticSpace(r):
			cat, name, notation = "exotic_space", exoticSpaceName(r), exoticSpaceNotation(r)
			matched = true
		}

		if matched {
			key := notation
			seen[key]++
			if _, ok := firstIdx[key]; !ok {
				firstIdx[key] = i
				firstRune[key] = r
				categories[key] = cat
				names[key] = name
				notations[key] = notation
			}
		}
	}

	for key, count := range seen {
		findings = append(findings, Finding{
			Category:  categories[key],
			Name:      names[key],
			Notation:  notations[key],
			CodePoint: firstRune[key],
			Index:     firstIdx[key],
			Count:     count,
		})
	}

	citationCount := countCitations(text)
	if citationCount > 0 {
		findings = append(findings, Finding{
			Category: "citation",
			Name:     "Citation placeholder (oaicite)",
			Notation: "(oaicite:N){index=N}",
			Index:    0,
			Count:    citationCount,
		})
	}

	return findings, nil
}

func zeroWidthName(r rune) string {
	switch r {
	case 0x200B:
		return "ZERO WIDTH SPACE"
	case 0x200C:
		return "ZERO WIDTH NON-JOINER"
	case 0x200D:
		return "ZERO WIDTH JOINER"
	case 0x2060:
		return "WORD JOINER"
	case 0xFEFF:
		return "BYTE ORDER MARK"
	}
	return "ZERO WIDTH"
}

func zeroWidthNotation(r rune) string {
	return runeNotation(r)
}

func bidiName(r rune) string {
	switch r {
	case 0x200E:
		return "LEFT-TO-RIGHT MARK"
	case 0x200F:
		return "RIGHT-TO-LEFT MARK"
	case 0x202A:
		return "LEFT-TO-RIGHT EMBEDDING"
	case 0x202B:
		return "RIGHT-TO-LEFT EMBEDDING"
	case 0x202C:
		return "POP DIRECTIONAL FORMATTING"
	case 0x202D:
		return "LEFT-TO-RIGHT OVERRIDE"
	case 0x202E:
		return "RIGHT-TO-LEFT OVERRIDE"
	case 0x2066:
		return "LEFT-TO-RIGHT ISOLATE"
	case 0x2067:
		return "RIGHT-TO-LEFT ISOLATE"
	case 0x2068:
		return "FIRST STRONG ISOLATE"
	case 0x2069:
		return "POP DIRECTIONAL ISOLATE"
	case 0x061C:
		return "ARABIC LETTER MARK"
	}
	return "BIDI"
}

func bidiNotation(r rune) string {
	return runeNotation(r)
}

func invisibleMathName(r rune) string {
	switch r {
	case 0x2061:
		return "FUNCTION APPLICATION"
	case 0x2062:
		return "INVISIBLE TIMES"
	case 0x2063:
		return "INVISIBLE SEPARATOR"
	case 0x2064:
		return "INVISIBLE PLUS"
	}
	return "INVISIBLE MATH"
}

func invisibleMathNotation(r rune) string {
	return runeNotation(r)
}

func variationSelectorName(r rune) string {
	if r >= 0xFE00 && r <= 0xFE0F {
		return "VARIATION SELECTOR-" + string(rune('0'+r-0xFE00))
	}
	return "VARIATION SELECTOR SUPPLEMENT"
}

func variationSelectorNotation(r rune) string {
	return runeNotation(r)
}

func tagCharName(r rune) string {
	if r == 0xE0001 {
		return "LANGUAGE TAG"
	}
	if r >= 0xE0020 && r <= 0xE007E {
		return "TAG " + string(rune(r-0xE0020+' '))
	}
	if r == 0xE007F {
		return "CANCEL TAG"
	}
	return "TAG CHARACTER"
}

func tagCharNotation(r rune) string {
	return runeNotation(r)
}

func formatCharName(r rune) string {
	switch r {
	case 0x00AD:
		return "SOFT HYPHEN"
	case 0x034F:
		return "COMBINING GRAPHEME JOINER"
	case 0x115F:
		return "HANGUL CHOSEONG FILLER"
	case 0x1160:
		return "HANGUL JUNGSEONG FILLER"
	case 0x17B4:
		return "KHMER VOWEL INHERENT AQ"
	case 0x17B5:
		return "KHMER VOWEL INHERENT AA"
	case 0x180B:
		return "MONGOLIAN FREE VARIATION SELECTOR ONE"
	case 0x180C:
		return "MONGOLIAN FREE VARIATION SELECTOR TWO"
	case 0x180D:
		return "MONGOLIAN FREE VARIATION SELECTOR THREE"
	case 0x180E:
		return "MONGOLIAN VOWEL SEPARATOR"
	case 0x3164:
		return "HANGUL FILLER"
	case 0xFFA0:
		return "HALFWIDTH HANGUL FILLER"
	}
	return "FORMAT CHARACTER"
}

func formatCharNotation(r rune) string {
	return runeNotation(r)
}

func controlName(r rune) string {
	if r < 0x20 {
		names := []string{
			"NULL", "START OF HEADING", "START OF TEXT", "END OF TEXT",
			"END OF TRANSMISSION", "ENQUIRY", "ACKNOWLEDGE", "BELL",
			"BACKSPACE", "CHARACTER TABULATION", "LINE FEED", "VERTICAL TABULATION",
			"FORM FEED", "CARRIAGE RETURN", "SHIFT OUT", "SHIFT IN",
			"DATA LINK ESCAPE", "DEVICE CONTROL ONE", "DEVICE CONTROL TWO",
			"DEVICE CONTROL THREE", "DEVICE CONTROL FOUR", "NEGATIVE ACKNOWLEDGE",
			"SYNCHRONOUS IDLE", "END OF TRANSMISSION BLOCK", "CANCEL",
			"END OF MEDIUM", "SUBSTITUTE", "ESCAPE", "FILE SEPARATOR",
			"GROUP SEPARATOR", "RECORD SEPARATOR", "UNIT SEPARATOR",
		}
		if int(r) < len(names) {
			return names[r]
		}
	}
	if r >= 0x7F && r <= 0x9F {
		return "C1 CONTROL CHARACTER"
	}
	return "CONTROL"
}

func controlNotation(r rune) string {
	return runeNotation(r)
}

func exoticSpaceName(r rune) string {
	switch r {
	case 0x00A0:
		return "NO-BREAK SPACE"
	case 0x1680:
		return "OGHAM SPACE MARK"
	case 0x2000:
		return "EN QUAD"
	case 0x2001:
		return "EM QUAD"
	case 0x2002:
		return "EN SPACE"
	case 0x2003:
		return "EM SPACE"
	case 0x2004:
		return "THREE-PER-EM SPACE"
	case 0x2005:
		return "FOUR-PER-EM SPACE"
	case 0x2006:
		return "SIX-PER-EM SPACE"
	case 0x2007:
		return "FIGURE SPACE"
	case 0x2008:
		return "PUNCTUATION SPACE"
	case 0x2009:
		return "THIN SPACE"
	case 0x200A:
		return "HAIR SPACE"
	case 0x202F:
		return "NARROW NO-BREAK SPACE"
	case 0x205F:
		return "MEDIUM MATHEMATICAL SPACE"
	case 0x3000:
		return "IDEOGRAPHIC SPACE"
	case 0x180E:
		return "MONGOLIAN VOWEL SEPARATOR"
	}
	return "EXOTIC SPACE"
}

func exoticSpaceNotation(r rune) string {
	return runeNotation(r)
}

func runeNotation(r rune) string {
	return fmt.Sprintf("U+%04X", r)
}
