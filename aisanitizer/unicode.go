package aisanitizer

import (
	"strings"
)

func inRange(r rune, lo, hi rune) bool {
	return r >= lo && r <= hi
}

func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF:
		return true
	}
	return false
}

func isBidi(r rune) bool {
	switch r {
	case 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069, 0x061C:
		return true
	}
	return false
}

func isInvisibleMath(r rune) bool {
	return inRange(r, 0x2061, 0x2064)
}

func isVariationSelector(r rune) bool {
	return inRange(r, 0xFE00, 0xFE0F) || inRange(r, 0xE0100, 0xE01EF)
}

func isTagChar(r rune) bool {
	return inRange(r, 0xE0000, 0xE007F)
}

func isFormatChar(r rune) bool {
	switch r {
	case 0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5,
		0x180B, 0x180C, 0x180D, 0x180E, 0x3164, 0xFFA0:
		return true
	}
	if inRange(r, 0x1D159, 0x1D15F) {
		return true
	}
	if inRange(r, 0x1D173, 0x1D17A) {
		return true
	}
	return false
}

func isBrailleBlank(r rune) bool {
	return r == 0x2800
}

func isControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r < 0x20 || inRange(r, 0x7F, 0x9F)
}

func isExoticSpace(r rune) bool {
	switch r {
	case 0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003,
		0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
		0x202F, 0x205F, 0x3000, 0x180E:
		return true
	}
	return false
}

func isQuote(r rune) bool {
	switch r {
	case '\u2018', '\u2019', '\u201A', '\u201B', '\u201C', '\u201D',
		'\u201E', '\u201F', '\u2039', '\u203A', '\u00AB', '\u00BB':
		return true
	}
	return false
}

func isDash(r rune) bool {
	switch r {
	case '\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2015', '\u2212':
		return true
	}
	return false
}

func isLineSeparator(r rune) bool {
	return r == 0x2028 || r == 0x2029
}

func isEmojiExtendedPictographic(r rune) bool {
	if r == 0x00A9 || r == 0x00AE || r == 0x203C || r == 0x2049 ||
		r == 0x2122 || r == 0x2139 || r == 0x2194 || r == 0x2195 ||
		r == 0x2196 || r == 0x2197 || r == 0x2198 || r == 0x2199 ||
		r == 0x21A9 || r == 0x21AA || r == 0x231A || r == 0x231B ||
		r == 0x2328 || r == 0x23CF || r == 0x23E9 || r == 0x23EA ||
		r == 0x23EB || r == 0x23EC || r == 0x23ED || r == 0x23EE ||
		r == 0x23EF || r == 0x23F0 || r == 0x23F1 || r == 0x23F2 ||
		r == 0x23F3 || r == 0x23F8 || r == 0x23F9 || r == 0x23FA ||
		r == 0x24C2 || r == 0x25AA || r == 0x25AB || r == 0x25B6 ||
		r == 0x25C0 || r == 0x25FB || r == 0x25FC || r == 0x25FD ||
		r == 0x25FE || r == 0x2600 || r == 0x2601 || r == 0x2602 ||
		r == 0x2603 || r == 0x2604 || r == 0x260E || r == 0x2611 ||
		r == 0x2614 || r == 0x2615 || r == 0x2618 || r == 0x261D ||
		r == 0x2620 || r == 0x2622 || r == 0x2623 || r == 0x2626 ||
		r == 0x262A || r == 0x262E || r == 0x262F || r == 0x2638 ||
		r == 0x2639 || r == 0x263A || r == 0x2640 || r == 0x2642 ||
		r == 0x2648 || r == 0x2649 || r == 0x264A || r == 0x264B ||
		r == 0x264C || r == 0x264D || r == 0x264E || r == 0x264F ||
		r == 0x2650 || r == 0x2651 || r == 0x2652 || r == 0x2653 ||
		r == 0x265F || r == 0x2660 || r == 0x2663 || r == 0x2665 ||
		r == 0x2666 || r == 0x2668 || r == 0x267B || r == 0x267E ||
		r == 0x267F || r == 0x2692 || r == 0x2693 || r == 0x2694 ||
		r == 0x2695 || r == 0x2696 || r == 0x2697 || r == 0x2699 ||
		r == 0x269B || r == 0x269C || r == 0x26A0 || r == 0x26A1 ||
		r == 0x26AA || r == 0x26AB || r == 0x26B0 || r == 0x26B1 ||
		r == 0x26BD || r == 0x26BE || r == 0x26C4 || r == 0x26C5 ||
		r == 0x26C8 || r == 0x26CE || r == 0x26CF || r == 0x26D1 ||
		r == 0x26D3 || r == 0x26D4 || r == 0x26E9 || r == 0x26EA ||
		r == 0x26F0 || r == 0x26F1 || r == 0x26F2 || r == 0x26F3 ||
		r == 0x26F4 || r == 0x26F5 || r == 0x26F7 || r == 0x26F8 ||
		r == 0x26F9 || r == 0x26FA || r == 0x26FD || r == 0x2702 ||
		r == 0x2705 || r == 0x2708 || r == 0x2709 || r == 0x270A ||
		r == 0x270B || r == 0x270C || r == 0x270D || r == 0x270F ||
		r == 0x2712 || r == 0x2714 || r == 0x2716 || r == 0x271D ||
		r == 0x2721 || r == 0x2728 || r == 0x2733 || r == 0x2734 ||
		r == 0x2744 || r == 0x2747 || r == 0x274C || r == 0x274E ||
		r == 0x2753 || r == 0x2754 || r == 0x2755 || r == 0x2757 ||
		r == 0x2763 || r == 0x2764 || r == 0x2795 || r == 0x2796 ||
		r == 0x2797 || r == 0x27A1 || r == 0x27B0 || r == 0x27BF ||
		r == 0x2934 || r == 0x2935 || r == 0x2B05 || r == 0x2B06 ||
		r == 0x2B07 || r == 0x2B1B || r == 0x2B1C || r == 0x2B50 ||
		r == 0x2B55 || r == 0x3030 || r == 0x303D || r == 0x3297 ||
		r == 0x3299 {
		return true
	}
	return inRange(r, 0x1F000, 0x1FFFF)
}

func findEmojiSequences(s string) []int {
	protected := make(map[int]bool)
	runes := []rune(s)

	for i := 0; i < len(runes); i++ {
		if isEmojiExtendedPictographic(runes[i]) {
			protected[i] = true
			j := i + 1
			for j < len(runes) {
				if runes[j] == 0x200D {
					protected[j] = true
					j++
					if j < len(runes) && isEmojiExtendedPictographic(runes[j]) {
						protected[j] = true
						j++
						for j < len(runes) && runes[j] == 0xFE0F {
							protected[j] = true
							j++
						}
						continue
					}
					break
				}
				if runes[j] == 0xFE0F {
					protected[j] = true
					j++
					continue
				}
				if runes[j] >= 0x1F3FB && runes[j] <= 0x1F3FF {
					protected[j] = true
					j++
					continue
				}
				if inRange(runes[j], 0xFE00, 0xFE0F) {
					protected[j] = true
					j++
					continue
				}
				if inRange(runes[j], 0xE0100, 0xE01EF) {
					protected[j] = true
					j++
					continue
				}
				break
			}
		}
	}

	result := make([]int, 0, len(protected))
	for idx := range protected {
		result = append(result, idx)
	}
	return result
}

func emojiProtectedSet(s string, opts *Options) map[int]bool {
	protected := make(map[int]bool)
	if !opts.KeepEmoji {
		return protected
	}

	emojiSeq := findEmojiSequences(s)
	for _, idx := range emojiSeq {
		protected[idx] = true
	}
	return protected
}

func removeCategory(s string, fn func(rune) bool, protected map[int]bool) (string, int) {
	var b strings.Builder
	b.Grow(len(s))
	removed := 0
	for i, r := range s {
		if protected[i] {
			b.WriteRune(r)
			continue
		}
		if fn(r) {
			removed++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), removed
}
