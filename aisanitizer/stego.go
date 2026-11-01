package aisanitizer

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// analyzeStego looks for runs of invisible characters in the original input
// that encode data, and decodes them where possible. Findings are
// detect-only and reported against original offsets.
func (p *pipeline) analyzeStego() {
	src := p.src
	tagOn := p.en[ruleIndex[RuleTagPayload]]
	vsOn := p.en[ruleIndex[RuleVariationSelectorStego]]
	mathOn := p.en[ruleIndex[RuleInvisibleMathStego]]
	zwOn := p.en[ruleIndex[RuleZeroWidthStego]]
	for i := 0; i < len(src); {
		r, size := utf8.DecodeRuneInString(src[i:])
		switch {
		case tagOn && r >= 0xE0000 && r <= 0xE007F:
			i = p.tagRun(i)
		case vsOn && isVS(r):
			i = p.vsRun(i)
		case mathOn && r >= 0x2061 && r <= 0x2064:
			i = p.mathRun(i)
		case zwOn && isZeroWidthRune(r):
			i = p.zwRun(i)
		default:
			i += size
		}
	}
}

// runEnd returns the end of the run of runes satisfying fn starting at i
// and the number of runes in it.
func runEnd(s string, i int, fn func(rune) bool) (end, n int) {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !fn(r) {
			break
		}
		i += size
		n++
	}
	return i, n
}

// runes decodes s[i:end].
func runes(s string, i, end int) []rune { return []rune(s[i:end]) }

func (p *pipeline) tagRun(i int) int {
	end, _ := runEnd(p.src, i, func(r rune) bool { return r >= 0xE0000 && r <= 0xE007F })
	if validTagSequence(p.src, i) {
		return end
	}
	rs := runes(p.src, i, end)
	var b strings.Builder
	for _, r := range rs {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	payload := b.String()
	name := "HIDDEN TEXT IN TAG CHARACTERS"
	if payload == "" {
		name = "TAG CHARACTER RUN"
	}
	f := p.col.add(ruleIndex[RuleTagPayload], 0, name, fmt.Sprintf("%d tag characters", len(rs)), i, len(rs), ActionDetect)
	f.Payload = truncatePayload(payload)
	return end
}

func (p *pipeline) vsRun(i int) int {
	end, n := runEnd(p.src, i, isVS)
	prev, _ := utf8.DecodeLastRuneInString(p.src[:i])
	if first, _ := utf8.DecodeRuneInString(p.src[i:]); n < 2 && (first < 0xE0100 || unicode.Is(tblIdeographic, prev)) {
		return end
	}
	rs := runes(p.src, i, end)
	data := make([]byte, 0, len(rs))
	for _, r := range rs {
		if r >= 0xE0100 {
			data = append(data, byte(r-0xE0100+16))
		} else {
			data = append(data, byte(r-0xFE00))
		}
	}
	f := p.col.add(ruleIndex[RuleVariationSelectorStego], 0, "HIDDEN BYTES IN VARIATION SELECTORS",
		fmt.Sprintf("%d variation selectors", len(rs)), i, len(rs), ActionDetect)
	f.Payload = describeBytes(data)
	return end
}

func (p *pipeline) mathRun(i int) int {
	end, n := runEnd(p.src, i, func(r rune) bool { return r >= 0x2061 && r <= 0x2064 })
	if n < 8 {
		return end
	}
	rs := runes(p.src, i, end)
	var bits []bool
	for _, r := range rs {
		switch r {
		case 0x2062:
			bits = append(bits, false)
		case 0x2064:
			bits = append(bits, true)
		}
	}
	f := p.col.add(ruleIndex[RuleInvisibleMathStego], 0, "BINARY DATA IN INVISIBLE MATH OPERATORS",
		fmt.Sprintf("%d invisible operators", len(rs)), i, len(rs), ActionDetect)
	if s, ok := printable(bitsToBytes(bits)); ok {
		f.Payload = s
	}
	return end
}

func isZeroWidthRune(r rune) bool {
	return r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF
}

func (p *pipeline) zwRun(i int) int {
	end, n := runEnd(p.src, i, isZeroWidthRune)
	if n < 8 {
		return end
	}
	rs := runes(p.src, i, end)
	f := p.col.add(ruleIndex[RuleZeroWidthStego], 0, "ZERO-WIDTH CHARACTER RUN",
		fmt.Sprintf("%d zero-width characters", len(rs)), i, len(rs), ActionDetect)
	distinct := map[rune]bool{}
	for _, r := range rs {
		distinct[r] = true
	}
	if len(distinct) == 2 {
		var syms []rune
		for r := range distinct {
			syms = append(syms, r)
		}
		if syms[0] > syms[1] {
			syms[0], syms[1] = syms[1], syms[0]
		}
		for _, one := range syms {
			bits := make([]bool, len(rs))
			for k, r := range rs {
				bits[k] = r == one
			}
			if s, ok := printable(bitsToBytes(bits)); ok {
				f.Payload = s
				break
			}
		}
	}
	return end
}

// analyzeTrailingWhitespace flags SNOW-style whitespace steganography:
// several lines whose trailing whitespace contains tabs or is unusually long.
func (p *pipeline) analyzeTrailingWhitespace() {
	src := p.src
	first, n := -1, 0
	for pos := 0; pos < len(src); {
		nl := strings.IndexByte(src[pos:], '\n')
		next, end := len(src), len(src)
		if nl >= 0 {
			next, end = pos+nl+1, pos+nl
		}
		if end > pos && src[end-1] == '\r' {
			end--
		}
		line := src[pos:end]
		content := strings.TrimRight(line, " \t")
		trail := line[len(content):]
		if content != "" && (strings.IndexByte(trail, '\t') >= 0 || len(trail) >= 3) {
			if first < 0 {
				first = pos + len(content)
			}
			n++
		}
		pos = next
	}
	if n >= 3 {
		p.col.add(ruleIndex[RuleTrailingWhitespaceStego], 0, "TRAILING WHITESPACE PATTERN",
			fmt.Sprintf("%d lines", n), first, n, ActionDetect)
	}
}

func bitsToBytes(bits []bool) []byte {
	out := make([]byte, 0, len(bits)/8)
	for k := 0; k+8 <= len(bits); k += 8 {
		var b byte
		for _, bit := range bits[k : k+8] {
			b <<= 1
			if bit {
				b |= 1
			}
		}
		out = append(out, b)
	}
	return out
}

// printable returns data as a string if it is valid UTF-8 and at least 80%
// of its runes are printable.
func printable(data []byte) (string, bool) {
	if len(data) == 0 || !utf8.Valid(data) {
		return "", false
	}
	s := string(data)
	total, ok := 0, 0
	for _, r := range s {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			ok++
		}
	}
	if ok*5 < total*4 {
		return "", false
	}
	return truncatePayload(s), true
}

func describeBytes(data []byte) string {
	if s, ok := printable(data); ok {
		return s
	}
	if len(data) > 64 {
		return "hex:" + hex.EncodeToString(data[:64]) + "\u2026"
	}
	return "hex:" + hex.EncodeToString(data)
}

func truncatePayload(s string) string {
	const max = 200
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "\u2026"
}
