package aisanitizer

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// charClass groups the code points the character engine acts on.
type charClass uint8

const (
	clsNone charClass = iota
	clsZeroWidth
	clsBidi
	clsInvisibleMath
	clsVariationSelector
	clsTag
	clsFormat
	clsBraille
	clsNoncharacter
	clsPrivateUse
	clsControl
	clsSpace
	clsLineSeparator
	clsReplacement
)

// classify returns the class of a non-ASCII rune (C1 controls included).
// Every Default_Ignorable_Code_Point maps to one of the invisible classes;
// see TestDefaultIgnorableCoverage.
func classify(r rune) charClass {
	switch {
	case r < 0xA0:
		if r == 0x85 {
			return clsLineSeparator
		}
		if r >= 0x7F {
			return clsControl
		}
		return clsNone
	case r == 0xA0:
		return clsSpace
	case r < 0x2000:
		switch {
		case r == 0xAD, r == 0x034F, r == 0x115F, r == 0x1160, r == 0x17B4, r == 0x17B5,
			r >= 0x180B && r <= 0x180F:
			return clsFormat
		case r == 0x061C:
			return clsBidi
		case r == 0x1680:
			return clsSpace
		}
		return clsNone
	case r <= 0x206F:
		switch {
		case r <= 0x200A, r == 0x202F, r == 0x205F:
			return clsSpace
		case r <= 0x200D, r == 0x2060:
			return clsZeroWidth
		case r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			return clsBidi
		case r == 0x2028, r == 0x2029:
			return clsLineSeparator
		case r >= 0x2061 && r <= 0x2064:
			return clsInvisibleMath
		case r == 0x2065, r >= 0x206A:
			return clsFormat
		}
		return clsNone
	case r == 0x2800:
		return clsBraille
	case r == 0x3000:
		return clsSpace
	case r == 0x3164:
		return clsFormat
	case r < 0xE000:
		return clsNone
	case r <= 0xF8FF:
		return clsPrivateUse
	case r < 0xFDD0:
		return clsNone
	case r <= 0xFDEF:
		return clsNoncharacter
	case r >= 0xFE00 && r <= 0xFE0F:
		return clsVariationSelector
	case r == 0xFEFF:
		return clsZeroWidth
	case r == 0xFFA0, r >= 0xFFF0 && r <= 0xFFFC:
		return clsFormat
	case r == 0xFFFD:
		return clsReplacement
	case r == 0xFFFE, r == 0xFFFF:
		return clsNoncharacter
	case r < 0x10000:
		return clsNone
	case r&0xFFFE == 0xFFFE:
		return clsNoncharacter
	case r >= 0x1BCA0 && r <= 0x1BCA3, r == 0x1D159, r >= 0x1D173 && r <= 0x1D17A:
		return clsFormat
	case r < 0xE0000:
		return clsNone
	case r <= 0xE007F:
		return clsTag
	case r >= 0xE0100 && r <= 0xE01EF:
		return clsVariationSelector
	case r <= 0xE0FFF:
		return clsFormat
	case r >= 0xF0000:
		return clsPrivateUse
	}
	return clsNone
}

var classRule = [...]ruleIdx{
	clsZeroWidth:         iZeroWidth,
	clsBidi:              iBidi,
	clsInvisibleMath:     iInvisibleMath,
	clsVariationSelector: iVariationSelector,
	clsTag:               iTagChar,
	clsFormat:            iFormatChar,
	clsBraille:           iBrailleBlank,
	clsNoncharacter:      iNoncharacter,
	clsPrivateUse:        iPrivateUse,
	clsControl:           iControl,
	clsSpace:             iExoticSpace,
	clsLineSeparator:     iLineSeparator,
	clsReplacement:       iReplacementChar,
}

// engine is the single-pass character stage.
type engine struct {
	p   *pipeline
	src string
	w   *rewriter
	en  *[maxRules]bool

	keepEmoji, keepScript, keepFrench bool
	foldTabs, foldNewlines            bool // TAB / line breaks become spaces (control rule on, Keep* off)
	bidi                              BidiMode
	dropInvalid                       bool

	code      spans // code spans, computed on the first entity candidate
	codeKnown bool

	rtlKnown, rtl bool
	tagRunEnd     int
	tagRunKeep    bool

	// Triggers for the steganography analyzers.
	sawTags, sawVS, sawMath, sawZW bool
}

func (p *pipeline) charStage(src string, w *rewriter) {
	o := p.opts
	e := &engine{
		p: p, src: src, w: w, en: &p.en,
		keepEmoji: o.KeepEmoji, keepScript: o.KeepScriptFormatting,
		keepFrench: o.KeepFrenchSpacing,
		foldTabs:   !o.KeepTabs && p.en[iControl], foldNewlines: !o.KeepNewlines && p.en[iControl],
		bidi: o.bidiMode(), dropInvalid: o.InvalidUTF8 == InvalidUTF8Drop,
		tagRunEnd: -1,
	}
	e.run()
	p.sawTags, p.sawVS, p.sawMath, p.sawZW = e.sawTags, e.sawVS, e.sawMath, e.sawZW
}

func (e *engine) run() {
	s := e.src
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != 0x7F && c != '&' {
				i++
				continue
			}
			i = e.ascii(i, c)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			e.invalid(i)
			i++
			continue
		}
		cls := classify(r)
		if cls == clsNone {
			i += size
			continue
		}
		e.rune(i, r, size, cls)
		i += size
	}
}

func (e *engine) remove(i, size int, idx ruleIdx, r rune) {
	e.w.replace(i, i+size, "")
	e.p.addRune(idx, r, i, ActionRemove)
}

func (e *engine) substitute(i, size int, repl string, idx ruleIdx, r rune) {
	e.w.replace(i, i+size, repl)
	e.p.addRune(idx, r, i, ActionReplace)
}

// ascii handles ASCII controls and '&'; it returns the next index.
func (e *engine) ascii(i int, c byte) int {
	s := e.src
	switch {
	case c == '&':
		if e.en[iHTMLEntity] {
			if n := e.entity(i); n > 0 {
				return i + n
			}
		}
		return i + 1
	case c == '\t':
		if e.foldTabs {
			e.substitute(i, 1, " ", iControl, '\t')
		}
		return i + 1
	case c == '\n' || c == '\r':
		if e.foldNewlines {
			n := 1
			if c == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				n = 2
			}
			e.substitute(i, n, " ", iControl, rune(c))
			return i + n
		}
		return i + 1
	case c == 0x1B && e.en[iANSIEscape]:
		if n := ansiSequenceLen(s[i:]); n > 0 {
			e.w.replace(i, i+n, "")
			e.p.add(iANSIEscape, 0, "ANSI ESCAPE SEQUENCE", sample(s[i:i+n]), i, 1, ActionRemove)
			return i + n
		}
	}
	if e.en[iControl] {
		e.remove(i, 1, iControl, rune(c))
	}
	return i + 1
}

func (e *engine) invalid(i int) {
	if e.dropInvalid {
		e.w.replace(i, i+1, "")
	} else {
		e.w.replace(i, i+1, "\uFFFD")
	}
	e.p.add(iInvalidUTF8, 0, "INVALID UTF-8 BYTE", "0x"+strings.ToUpper(strconv.FormatUint(uint64(e.src[i]), 16)), i, 1, ActionReplace)
}

func (e *engine) rune(i int, r rune, size int, cls charClass) {
	idx := classRule[cls]
	switch cls {
	case clsReplacement:
		if e.p.detect {
			e.p.addRune(idx, r, i, ActionDetect)
		}
		return
	case clsPrivateUse:
		if !e.en[idx] {
			if e.p.detect {
				e.p.addRune(idx, r, i, ActionDetect)
			}
			return
		}
	}
	if !e.en[idx] || e.keep(i, r, size, cls) {
		return
	}
	switch cls {
	case clsTag:
		e.sawTags = true
	case clsVariationSelector:
		e.sawVS = true
	case clsInvisibleMath:
		e.sawMath = true
	case clsZeroWidth:
		e.sawZW = true
	}
	switch cls {
	case clsSpace:
		e.substitute(i, size, " ", idx, r)
	case clsLineSeparator:
		repl := "\n"
		if e.foldNewlines {
			repl = " " // the newline it would become is folded too
		} else if r == 0x2029 {
			repl = "\n\n"
		}
		e.substitute(i, size, repl, idx, r)
	default:
		e.remove(i, size, idx, r)
	}
}

// keep reports whether a character that its rule would act on is a
// legitimate part of the surrounding text.
func (e *engine) keep(i int, r rune, size int, cls charClass) bool {
	s := e.src
	switch cls {
	case clsZeroWidth:
		switch r {
		case 0x200D: // ZWJ
			return (e.keepEmoji && emojiJoiner(s, i, size)) || (e.keepScript && afterVirama(s, i))
		case 0x200C: // ZWNJ
			return e.keepScript && (afterVirama(s, i) || joiningContext(s, i, size))
		}
	case clsBidi:
		switch e.bidi {
		case BidiKeep:
			return true
		case BidiAuto:
			if r == 0x200E || r == 0x200F || r == 0x061C {
				return e.hasRTL()
			}
		}
	case clsVariationSelector:
		prev, _ := utf8.DecodeLastRuneInString(s[:i])
		if (r == 0xFE0E || r == 0xFE0F) && e.keepEmoji && emojiVariation(s, i, size, prev) {
			return true
		}
		// Non-emoji variation sequences (VS1–VS14 standardized variants and
		// ideographic variation sequences). VS15/VS16 are emoji-only above.
		if e.keepScript && !isVS(prev) && r != 0xFE0E && r != 0xFE0F {
			if r >= 0xE0100 {
				return unicode.Is(tblIdeographic, prev)
			}
			return isStandardizedVariant(prev, r)
		}
	case clsTag:
		if !e.keepEmoji {
			return false
		}
		if i != e.tagRunEnd {
			e.tagRunKeep = validTagSequence(s, i)
		}
		e.tagRunEnd = i + size
		return e.tagRunKeep
	case clsFormat:
		if !e.keepScript {
			return false
		}
		switch {
		case r >= 0x180B && r <= 0x180F:
			prev, _ := utf8.DecodeLastRuneInString(s[:i])
			return unicode.Is(unicode.Mongolian, prev)
		case r == 0x115F:
			next, _ := utf8.DecodeRuneInString(s[i+size:])
			return next >= 0x1160 && next <= 0x11A7
		case r == 0x1160:
			prev, _ := utf8.DecodeLastRuneInString(s[:i])
			return prev >= 0x1100 && prev <= 0x115F
		}
	case clsSpace:
		if e.keepFrench && (r == 0x202F || r == 0x00A0 || r == 0x2009) {
			return frenchSpace(s, i, size)
		}
	}
	return false
}

func (e *engine) hasRTL() bool {
	if !e.rtlKnown {
		e.rtlKnown = true
		for _, r := range e.src {
			if r >= 0x0590 && unicode.IsLetter(r) && unicode.Is(tblRTL, r) {
				e.rtl = true
				break
			}
		}
	}
	return e.rtl
}

func isVS(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func isEmojiElement(r rune) bool {
	return r >= 0x80 && (unicode.Is(tblExtPict, r) || unicode.Is(tblEmoji, r))
}

// emojiJoiner reports whether the ZWJ at s[i:i+size] joins two emoji.
func emojiJoiner(s string, i, size int) bool {
	j := i
	for j > 0 {
		r, n := utf8.DecodeLastRuneInString(s[:j])
		if r == 0xFE0F || r == 0xFE0E || r == 0x20E3 || (r >= 0x1F3FB && r <= 0x1F3FF) || (r >= 0xE0020 && r <= 0xE007F) {
			j -= n
			continue
		}
		if !isEmojiElement(r) {
			return false
		}
		break
	}
	if j == 0 {
		return false
	}
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	return isEmojiElement(next)
}

// emojiVariation reports whether VS15/VS16 at s[i:] follows an emoji base.
func emojiVariation(s string, i, size int, prev rune) bool {
	if !unicode.Is(tblEmoji, prev) || isVS(prev) {
		return false
	}
	if prev < utf8.RuneSelf { // keycap bases: 0-9 # * need U+20E3 to follow
		next, _ := utf8.DecodeRuneInString(s[i+size:])
		return next == 0x20E3
	}
	return true
}

// validTagSequence reports whether the tag run starting at s[i] is the tag
// spec of an emoji subdivision flag: U+1F3F4, then 2 letters plus 1–4
// letters/digits as tag characters, then CANCEL TAG.
func validTagSequence(s string, i int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	if prev != 0x1F3F4 {
		return false
	}
	n := 0
	for j := i; j < len(s); {
		r, size := utf8.DecodeRuneInString(s[j:])
		switch {
		case r == 0xE007F:
			return n >= 3 && n <= 6
		case r >= 0xE0061 && r <= 0xE007A, n >= 2 && r >= 0xE0030 && r <= 0xE0039:
			n++
		default:
			return false
		}
		j += size
	}
	return false
}

func afterVirama(s string, i int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	return prev >= 0x0900 && unicode.Is(tblVirama, prev)
}

// joiningContext implements the RFC 5892 Appendix A.1 rule for ZWNJ:
// (Joining_Type:{L,D})(Joining_Type:T)* ZWNJ (Joining_Type:T)*(Joining_Type:{R,D}).
func joiningContext(s string, i, size int) bool {
	j := i
	var prev rune
	for j > 0 {
		r, n := utf8.DecodeLastRuneInString(s[:j])
		if !unicode.Is(tblJoinT, r) {
			prev = r
			break
		}
		j -= n
	}
	// Neighbours must be letters: ZWJ itself is Join_Causing but is not a
	// legitimate partner (and may be removed), which would break idempotency.
	if !unicode.IsLetter(prev) || !(unicode.Is(tblJoinL, prev) || unicode.Is(tblJoinD, prev)) {
		return false
	}
	for j = i + size; j < len(s); {
		r, n := utf8.DecodeRuneInString(s[j:])
		if !unicode.Is(tblJoinT, r) {
			return unicode.IsLetter(r) && (unicode.Is(tblJoinR, r) || unicode.Is(tblJoinD, r))
		}
		j += n
	}
	return false
}

// frenchSpace reports whether a narrow/no-break space follows French
// typographic conventions: before ; : ! ? » › %, after « ‹, as a digit
// group separator, or between an amount and its currency symbol.
func frenchSpace(s string, i, size int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	switch next {
	case ';', ':', '!', '?', '\u00BB', '\u203A', '%':
		return true
	}
	switch prev {
	case '\u00AB', '\u2039':
		return true
	}
	return isDigit(prev) && (isDigit(next) || unicode.Is(unicode.Sc, next))
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// ansiSequenceLen returns the length of the ANSI escape sequence at the start
// of s (which begins with ESC), or 0 if there is none.
func ansiSequenceLen(s string) int {
	if len(s) < 2 {
		return 0
	}
	switch c := s[1]; {
	case c == '[': // CSI: parameters, intermediates, final byte
		j := 2
		for j < len(s) && s[j] >= 0x30 && s[j] <= 0x3F {
			j++
		}
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2F {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7E {
			return j + 1
		}
		return 0
	case c == ']': // OSC, terminated by BEL or ST (ESC \)
		for j := 2; j < len(s) && j < 4096; j++ {
			if s[j] == 0x07 {
				return j + 1
			}
			if s[j] == 0x1B && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2
			}
		}
		return 0
	case c >= 0x40 && c <= 0x5F: // two-byte Fe escape
		return 2
	}
	return 0
}

var namedInvisibleEntities = map[string]rune{
	"ZeroWidthSpace":        0x200B,
	"NegativeVeryThinSpace": 0x200B,
	"NegativeThinSpace":     0x200B,
	"NegativeMediumSpace":   0x200B,
	"NegativeThickSpace":    0x200B,
	"NoBreak":               0x2060,
	"af":                    0x2061,
	"ApplyFunction":         0x2061,
	"it":                    0x2062,
	"InvisibleTimes":        0x2062,
	"ic":                    0x2063,
	"InvisibleComma":        0x2063,
}

// entity removes an HTML entity at s[i] that encodes an invisible character
// whose own rule is enabled, returning its length (0 if none).
func (e *engine) entity(i int) int {
	s := e.src
	end := strings.IndexByte(s[i:min(len(s), i+32)], ';')
	if end < 3 {
		return 0
	}
	body := s[i+1 : i+end]
	var r rune
	if body[0] == '#' {
		var v uint64
		var err error
		if body[1] == 'x' || body[1] == 'X' {
			v, err = strconv.ParseUint(body[2:], 16, 32)
		} else {
			v, err = strconv.ParseUint(body[1:], 10, 32)
		}
		if err != nil || v > unicode.MaxRune {
			return 0
		}
		r = rune(v)
	} else {
		var ok bool
		if r, ok = namedInvisibleEntities[body]; !ok {
			return 0
		}
	}
	if !entityRemovable(r) {
		return 0
	}
	var cls charClass
	if r < 0x20 || r == 0x7F {
		cls = clsControl
	} else {
		cls = classify(r)
	}
	if !e.en[classRule[cls]] {
		return 0
	}
	// Entities inside Markdown code are visible, intentional text.
	if !e.codeKnown {
		e.code, e.codeKnown = codeSpans(s), true
	}
	if e.code.contains(i) {
		return 0
	}
	n := end + 1
	e.w.replace(i, i+n, "")
	e.p.add(iHTMLEntity, r, runeName(r)+" (HTML entity)", s[i:i+n], i, 1, ActionRemove)
	return n
}

// entityRemovable reports whether an entity-encoded rune has no legitimate
// use in HTML text. NBSP, soft hyphen, ZWJ/ZWNJ, bidi marks and variation
// selectors (emoji) are deliberately excluded.
func entityRemovable(r rune) bool {
	if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || (r >= 0x7F && r <= 0x9F && r != 0x85) {
		return true
	}
	switch classify(r) {
	case clsZeroWidth:
		return r == 0x200B || r == 0x2060 || r == 0xFEFF
	case clsInvisibleMath, clsTag, clsNoncharacter:
		return true
	case clsFormat:
		return r != 0xAD
	}
	return false
}

func sample(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\u2026"
}
