package aisanitizer

import (
	"fmt"
	"strconv"
	"unicode"
)

var c0Names = [...]string{
	"NULL", "START OF HEADING", "START OF TEXT", "END OF TEXT",
	"END OF TRANSMISSION", "ENQUIRY", "ACKNOWLEDGE", "BELL",
	"BACKSPACE", "CHARACTER TABULATION", "LINE FEED", "LINE TABULATION",
	"FORM FEED", "CARRIAGE RETURN", "SHIFT OUT", "SHIFT IN",
	"DATA LINK ESCAPE", "DEVICE CONTROL ONE", "DEVICE CONTROL TWO",
	"DEVICE CONTROL THREE", "DEVICE CONTROL FOUR", "NEGATIVE ACKNOWLEDGE",
	"SYNCHRONOUS IDLE", "END OF TRANSMISSION BLOCK", "CANCEL",
	"END OF MEDIUM", "SUBSTITUTE", "ESCAPE", "INFORMATION SEPARATOR FOUR",
	"INFORMATION SEPARATOR THREE", "INFORMATION SEPARATOR TWO", "INFORMATION SEPARATOR ONE",
}

// runeName returns the Unicode name (or a descriptive label) for r.
func runeName(r rune) string {
	switch {
	case r < 0x20:
		return c0Names[r]
	case r == 0x7F:
		return "DELETE"
	case r == 0x85:
		return "NEXT LINE (NEL)"
	case r >= 0x80 && r <= 0x9F:
		return "C1 CONTROL CHARACTER"
	case r >= 0xFE00 && r <= 0xFE0F:
		return "VARIATION SELECTOR-" + strconv.Itoa(int(r-0xFE00)+1)
	case r >= 0xE0100 && r <= 0xE01EF:
		return "VARIATION SELECTOR-" + strconv.Itoa(int(r-0xE0100)+17)
	case r == 0xE0001:
		return "LANGUAGE TAG"
	case r == 0xE007F:
		return "CANCEL TAG"
	case r >= 0xE0020 && r <= 0xE007E:
		return "TAG " + tagLabel(r)
	}
	if n, ok := lookupString(charNameTable[:], r); ok {
		return n
	}
	switch {
	case isNoncharacter(r):
		return "NONCHARACTER"
	case isPrivateUse(r):
		return "PRIVATE USE CHARACTER"
	case unicode.Is(tblDefaultIgnorable, r):
		return "UNASSIGNED DEFAULT IGNORABLE"
	}
	return ""
}

func tagLabel(r rune) string {
	c := r - 0xE0000
	switch {
	case c == ' ':
		return "SPACE"
	case c >= 'a' && c <= 'z':
		return "LATIN SMALL LETTER " + string(c-'a'+'A')
	case c >= 'A' && c <= 'Z':
		return "LATIN CAPITAL LETTER " + string(c)
	case c >= '0' && c <= '9':
		return "DIGIT " + string(c)
	}
	return "CHARACTER " + string(c)
}

func runeNotation(r rune) string {
	return fmt.Sprintf("U+%04X", r)
}

func isNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || (r&0xFFFE == 0xFFFE && r <= unicode.MaxRune)
}

func isPrivateUse(r rune) bool {
	return (r >= 0xE000 && r <= 0xF8FF) || (r >= 0xF0000 && r <= 0xFFFFD) || (r >= 0x100000 && r <= 0x10FFFD)
}
