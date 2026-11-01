package aisanitizer

import (
	"strings"
	"unicode/utf8"
)

// Reveal returns text with every invisible, control, unusual-space and
// private-use character replaced by a visible "⟨U+XXXX⟩" marker (TAB and LF
// are kept). It is meant for diffs and debugging output.
func Reveal(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		c := text[i]
		if c < utf8.RuneSelf {
			if (c < 0x20 && c != '\t' && c != '\n') || c == 0x7F {
				b.WriteString("\u27E8" + runeNotation(rune(c)) + "\u27E9")
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString("\u27E8invalid 0x" + strings.ToUpper(hexByte(c)) + "\u27E9")
		case classify(r) != clsNone && classify(r) != clsReplacement:
			b.WriteString("\u27E8" + runeNotation(r) + "\u27E9")
		default:
			b.WriteString(text[i : i+size])
		}
		i += size
	}
	return b.String()
}

func hexByte(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[c>>4], digits[c&15]})
}
