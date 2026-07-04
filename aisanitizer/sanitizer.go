package aisanitizer

import (
	"strings"
)

func Sanitize(text string, opts *Options) (string, *Report) {
	if opts == nil {
		opts = Defaults()
	}

	report := &Report{}
	original := text
	current := text

	if opts.Nfkc {
		current = nfkcNormalize(current)
	}

	protected := emojiProtectedSet(current, opts)

	var n int

	if opts.RemoveZeroWidth {
		current, n = removeCategory(current, isZeroWidth, protected)
		report.Changes.RemovedZeroWidth += n
	}
	if opts.RemoveBidi && !opts.KeepBidi {
		current, n = removeCategory(current, isBidi, protected)
		report.Changes.RemovedBidi += n
	}
	if opts.RemoveInvisibleMath {
		current, n = removeCategory(current, isInvisibleMath, protected)
		report.Changes.RemovedInvisibleMath += n
	}
	if opts.RemoveVariationSelectors {
		vsFn := isVariationSelector
		if opts.KeepEmoji {
			vsFn = func(r rune) bool {
				if isEmojiExtendedPictographic(r) {
					return false
				}
				return isVariationSelector(r)
			}
		}
		current, n = removeCategory(current, vsFn, protected)
		report.Changes.RemovedVariationSelectors += n
	}
	if opts.RemoveTagChars {
		current, n = removeCategory(current, isTagChar, protected)
		report.Changes.RemovedTagChars += n
	}
	if opts.RemoveFormatChars {
		current, n = removeCategory(current, isFormatChar, protected)
		report.Changes.RemovedFormatChars += n
	}
	if opts.RemoveBrailleBlank {
		current, n = removeCategory(current, isBrailleBlank, protected)
		report.Changes.RemovedBrailleBlank += n
	}
	if opts.StripControl {
		ctrlFn := isControl
		if !opts.KeepTabs || !opts.KeepNewlines {
			ctrlFn = func(r rune) bool {
				if r == '\t' && opts.KeepTabs {
					return false
				}
				if (r == '\n' || r == '\r') && opts.KeepNewlines {
					return false
				}
				return isControl(r)
			}
		}
		current, n = removeCategory(current, ctrlFn, protected)
		report.Changes.RemovedControl += n
	}

	if opts.RemoveCitations {
		current, n = removeCitations(current)
		report.Changes.RemovedCitations += n
	}
	if opts.RemoveModelArtifacts {
	}

	if opts.NormalizeSmartQuotes {
		current, n = normalizeSmartQuotes(current)
		report.Changes.NormalizedSmartQuotes += n
	}
	if opts.NormalizeDashes {
		current, n = normalizeDashes(current)
		report.Changes.NormalizedDashes += n
	}
	if opts.NormalizeEllipsis {
		current, n = normalizeEllipsis(current)
		report.Changes.NormalizedEllipsis += n
	}

	if opts.NormalizeSpaces {
		current, n = normalizeSpaces(current)
		report.Changes.NormalizedSpaces += n
	}
	if opts.NormalizeLineSeparators {
		current, n = normalizeLineSeparators(current)
		report.Changes.NormalizedLineSeparators += n
	}
	if opts.CollapseWhitespace {
		current, n = collapseWhitespace(current)
		report.Changes.CollapsedSpaces += n
	}
	if opts.Trim {
		current = trimSpace(current)
	}

	report.Changes.Total = report.Changes.RemovedZeroWidth +
		report.Changes.RemovedBidi +
		report.Changes.RemovedInvisibleMath +
		report.Changes.RemovedVariationSelectors +
		report.Changes.RemovedTagChars +
		report.Changes.RemovedFormatChars +
		report.Changes.RemovedBrailleBlank +
		report.Changes.RemovedControl +
		report.Changes.RemovedCitations +
		report.Changes.RemovedModelArtifacts +
		report.Changes.NormalizedSpaces +
		report.Changes.NormalizedLineSeparators +
		report.Changes.NormalizedSmartQuotes +
		report.Changes.NormalizedDashes +
		report.Changes.NormalizedEllipsis +
		report.Changes.CollapsedSpaces +
		report.Changes.RewrittenSegments

	report.Modified = report.Changes.Total > 0 || current != original

	return current, report
}

func SanitizeWithRewrite(text string, opts *Options, strategy RewriteStrategy) (string, *Report, error) {
	cleaned, report := Sanitize(text, opts)
	if strategy != RewriteNone {
		rewritten, n := applyRewrite(cleaned, strategy)
		report.Changes.RewrittenSegments += n
		report.Changes.Total += n
		report.Modified = true
		cleaned = rewritten
	}
	return cleaned, report, nil
}

func Detect(text string, opts *Options) (*Report, error) {
	detector := NewHeuristicDetector()
	findings, err := detector.Detect(text)
	if err != nil {
		return nil, err
	}
	return &Report{
		Findings: findings,
		Modified: false,
	}, nil
}

func CleanText(text string) (string, *Report) {
	return Sanitize(text, Defaults())
}

func nfkcNormalize(s string) string {
	return strings.Map(func(r rune) rune {
		if compat, ok := nfkcCompat[r]; ok {
			return compat
		}
		if nfkcDrop[r] {
			return -1
		}
		return r
	}, s)
}

var nfkcDrop = map[rune]bool{
	0xFE00: true, 0xFE01: true, 0xFE02: true, 0xFE03: true,
	0xFE04: true, 0xFE05: true, 0xFE06: true, 0xFE07: true,
	0xFE08: true, 0xFE09: true, 0xFE0A: true, 0xFE0B: true,
	0xFE0C: true, 0xFE0D: true, 0xFE0E: true, 0xFE0F: true,
}

var nfkcCompat = map[rune]rune{
	0x00A0: ' ',
	0x00AD: '-',
	0x2000: ' ',
	0x2001: ' ',
	0x2002: ' ',
	0x2003: ' ',
	0x2004: ' ',
	0x2005: ' ',
	0x2006: ' ',
	0x2007: ' ',
	0x2008: ' ',
	0x2009: ' ',
	0x200A: ' ',
	0x2010: '-',
	0x2011: '-',
	0x2012: '-',
	0x2013: '-',
	0x2014: '-',
	0x2015: '-',
	0x2018: '\'',
	0x2019: '\'',
	0x201A: '\'',
	0x201B: '\'',
	0x201C: '"',
	0x201D: '"',
	0x201E: '"',
	0x201F: '"',
	0x2024: '.',
	0x2025: '.',
	0x2026: '.',
	0x202F: ' ',
	0x2039: '<',
	0x203A: '>',
	0x2044: '/',
	0x205F: ' ',
	0x2060: ' ',
	0x2212: '-',
	0x3000: ' ',
	0xFF01: '!',
	0xFF02: '"',
	0xFF03: '#',
	0xFF04: '$',
	0xFF05: '%',
	0xFF06: '&',
	0xFF07: '\'',
	0xFF08: '(',
	0xFF09: ')',
	0xFF0A: '*',
	0xFF0B: '+',
	0xFF0C: ',',
	0xFF0D: '-',
	0xFF0E: '.',
	0xFF0F: '/',
	0xFF10: '0',
	0xFF11: '1',
	0xFF12: '2',
	0xFF13: '3',
	0xFF14: '4',
	0xFF15: '5',
	0xFF16: '6',
	0xFF17: '7',
	0xFF18: '8',
	0xFF19: '9',
	0xFF1A: ':',
	0xFF1B: ';',
	0xFF1C: '<',
	0xFF1D: '=',
	0xFF1E: '>',
	0xFF1F: '?',
	0xFF20: '@',
	0xFF21: 'A',
	0xFF22: 'B',
	0xFF23: 'C',
	0xFF24: 'D',
	0xFF25: 'E',
	0xFF26: 'F',
	0xFF27: 'G',
	0xFF28: 'H',
	0xFF29: 'I',
	0xFF2A: 'J',
	0xFF2B: 'K',
	0xFF2C: 'L',
	0xFF2D: 'M',
	0xFF2E: 'N',
	0xFF2F: 'O',
	0xFF30: 'P',
	0xFF31: 'Q',
	0xFF32: 'R',
	0xFF33: 'S',
	0xFF34: 'T',
	0xFF35: 'U',
	0xFF36: 'V',
	0xFF37: 'W',
	0xFF38: 'X',
	0xFF39: 'Y',
	0xFF3A: 'Z',
	0xFF3B: '[',
	0xFF3C: '\\',
	0xFF3D: ']',
	0xFF3E: '^',
	0xFF3F: '_',
	0xFF40: '`',
	0xFF41: 'a',
	0xFF42: 'b',
	0xFF43: 'c',
	0xFF44: 'd',
	0xFF45: 'e',
	0xFF46: 'f',
	0xFF47: 'g',
	0xFF48: 'h',
	0xFF49: 'i',
	0xFF4A: 'j',
	0xFF4B: 'k',
	0xFF4C: 'l',
	0xFF4D: 'm',
	0xFF4E: 'n',
	0xFF4F: 'o',
	0xFF50: 'p',
	0xFF51: 'q',
	0xFF52: 'r',
	0xFF53: 's',
	0xFF54: 't',
	0xFF55: 'u',
	0xFF56: 'v',
	0xFF57: 'w',
	0xFF58: 'x',
	0xFF59: 'y',
	0xFF5A: 'z',
	0xFF5B: '{',
	0xFF5C: '|',
	0xFF5D: '}',
	0xFF5E: '~',
	0xFFE0: '¢',
	0xFFE1: '£',
	0xFFE2: '¬',
	0xFFE3: '¯',
	0xFFE5: '¥',
	0xFFE6: '₩',
}
