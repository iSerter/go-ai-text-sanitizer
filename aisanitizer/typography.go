package aisanitizer

import (
	"unicode"
	"unicode/utf8"
)

var quoteMap = map[rune]string{
	'\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
	'\u2039': "'", '\u203A': "'", '\u02BC': "'", '\uFF07': "'",
	'\u201C': `"`, '\u201D': `"`, '\u201E': `"`, '\u201F': `"`,
	'\u00AB': `"`, '\u00BB': `"`, '\uFF02': `"`,
}

// hyphenLike are dash characters that always become "-".
var hyphenLike = map[rune]bool{
	'\u2010': true, '\u2011': true, '\u2012': true, '\u2212': true,
	'\uFE58': true, '\uFE63': true, '\uFF0D': true,
}

var punctuationMap = map[rune]string{
	'\u2022': "-", '\u2023': "-", '\u2043': "-", '\u25E6': "-", '\u25AA': "-",
	'\u2190': "<-", '\u2192': "->", '\u2194': "<->",
	'\u21D0': "<=", '\u21D2': "=>", '\u21D4': "<=>",
	'\u00D7': "x", '\u2248': "~", '\u2260': "!=", '\u2264': "<=", '\u2265': ">=",
	'\u2032': "'", '\u2033': `"`, '\u2044': "/",
}

// typographyStage applies the per-character typography rules outside code
// spans and URLs.
func (p *pipeline) typographyStage(t string, w *rewriter) {
	style := p.opts.dashStyle()
	if style == DashKeep {
		style = DashHyphen // dash rule forced on through Options.Rules
	}
	quotes, dashes, ellipsis, punct, compat := p.en[iSmartQuote], p.en[iDash], p.en[iEllipsis], p.en[iPunctuation], p.en[iCompatFold]
	if !hasNonASCII(t) {
		return
	}
	protectedSpans(t, true).gaps(len(t), func(a, b int) {
		for i := a; i < b; {
			c := t[i]
			if c < utf8.RuneSelf {
				i++
				continue
			}
			r, size := utf8.DecodeRuneInString(t[i:])
			var repl string
			var idx ruleIdx = -1
			switch {
			case quotes && quoteMap[r] != "":
				repl, idx = quoteMap[r], iSmartQuote
			case dashes && hyphenLike[r]:
				repl, idx = "-", iDash
			case dashes && style != DashComma && (r == '\u2013' || r == '\u2014' || r == '\u2015'):
				repl, idx = "-", iDash
				if style == DashASCII && r != '\u2013' {
					repl = "--"
				}
			case ellipsis && r == '\u2026':
				repl, idx = "...", iEllipsis
			case punct && punctuationMap[r] != "":
				repl, idx = punctuationMap[r], iPunctuation
			case compat:
				if s, ok := compatFold(r); ok {
					repl, idx = s, iCompatFold
				}
			}
			if idx >= 0 {
				w.replace(i, i+size, repl)
				p.addRune(idx, r, i, ActionReplace)
			}
			i += size
		}
	})
}

// dashCommaStage implements DashComma: parenthetical em dashes become
// commas, dashes before punctuation or at line end are dropped, numeric
// ranges become "1-2" and dashes opening a line become "- ".
func (p *pipeline) dashCommaStage(t string, w *rewriter) {
	if !hasNonASCII(t) {
		return
	}
	protectedSpans(t, true).gaps(len(t), func(a, b int) {
		for i := a; i < b; {
			r, size := utf8.DecodeRuneInString(t[i:])
			if !isDashRune(r) {
				i += size
				continue
			}
			// A run of dashes ("\u2014\u2014", "\u2014 \u2014") is one dash.
			runEnd, dashes := i+size, 1
			for k := runEnd; k < b; {
				for k < b && (t[k] == ' ' || t[k] == '\t') {
					k++
				}
				r2, n := utf8.DecodeRuneInString(t[k:])
				if k == b || !isDashRune(r2) {
					break
				}
				runEnd, k = k+n, k+n
				dashes++
			}
			size = runEnd - i
			s, e := i, i+size
			for s > a && (t[s-1] == ' ' || t[s-1] == '\t') {
				s--
			}
			for e < b && (t[e] == ' ' || t[e] == '\t') {
				e++
			}
			if s < w.last {
				s = w.last
			}
			spaced := s < i && e > i+size
			prev, _ := utf8.DecodeLastRuneInString(t[:s])
			next, _ := utf8.DecodeRuneInString(t[e:])
			var repl string
			switch {
			case r == '\u2013' && dashes == 1 && !spaced:
				s, e, repl = i, i+size, "-"
			case isDigit(prev) && isDigit(next):
				repl = "-"
			case s == 0 || prev == '\n':
				s, repl = i, "- "
			case e >= len(t) || next == '\n' || next == '\r' || (next < utf8.RuneSelf && isClosingPunct(byte(next))):
				repl = ""
			case prev == ',' || prev == ';' || prev == ':' || prev == '(':
				repl = " "
			default:
				repl = ", "
			}
			w.replace(s, e, repl)
			for k := i; k < i+size; {
				r2, n := utf8.DecodeRuneInString(t[k:])
				if isDashRune(r2) {
					p.addRune(iDash, r2, k, ActionReplace)
				}
				k += n
			}
			i = e
		}
	})
}

// confusableStage reports mixed-script (homoglyph) words and, when
// FoldConfusables is on, folds look-alike letters to Latin inside them.
func (p *pipeline) confusableStage(t string, w *rewriter) {
	if !hasNonASCII(t) {
		return
	}
	fold := p.en[iConfusable]
	detect := p.en[iMixedScript] && p.iter == 0
	code := codeSpans(t)
	var links spans
	if fold {
		links = linkSpans(t)
	}
	latinText := -1 // lazily computed: 1 if the text is predominantly Latin
	code.gaps(len(t), func(a, b int) {
		for i := a; i < b; {
			r, size := utf8.DecodeRuneInString(t[i:])
			if !isWordRune(r) {
				i += size
				continue
			}
			start := i
			latin, conf, other := 0, 0, 0
			for i < b {
				r, size = utf8.DecodeRuneInString(t[i:])
				if !isWordRune(r) {
					break
				}
				switch {
				case unicode.IsMark(r):
				case unicode.Is(unicode.Latin, r):
					latin++
				case isConfusableScript(r):
					if _, ok := confusableTarget(r); ok {
						conf++
					} else {
						other++
					}
				default:
					other++
				}
				i += size
			}
			if conf == 0 {
				continue
			}
			word := t[start:i]
			switch {
			case latin > 0:
				skel := skeleton(word)
				if detect {
					f := p.col.addKeyed(iMixedScript, 0, word, "MIXED-SCRIPT WORD", word, p.origin(start), 1, ActionDetect)
					f.Payload = skel
				}
				if fold && other == 0 && !links.overlaps(start, i) {
					p.foldWord(t, w, start, i)
				}
			case other == 0 && detect && conf >= 2:
				if latinText < 0 {
					latinText = 0
					if predominantlyLatin(t) {
						latinText = 1
					}
				}
				if latinText == 1 {
					f := p.col.addKeyed(iMixedScript, 0, word, "WHOLE-SCRIPT CONFUSABLE WORD", word, p.origin(start), 1, ActionDetect)
					f.Payload = skeleton(word)
				}
			}
		}
	})
}

func (p *pipeline) foldWord(t string, w *rewriter, a, b int) {
	for i := a; i < b; {
		r, size := utf8.DecodeRuneInString(t[i:])
		if l, ok := confusableTarget(r); ok && !unicode.Is(unicode.Latin, r) {
			w.replace(i, i+size, string(l))
			p.addRune(iConfusable, r, i, ActionReplace)
		}
		i += size
	}
}

func skeleton(word string) string {
	out := make([]rune, 0, len(word))
	for _, r := range word {
		if l, ok := confusableTarget(r); ok && !unicode.Is(unicode.Latin, r) {
			r = l
		}
		out = append(out, r)
	}
	return string(out)
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsMark(r) }

var confusableScriptTables = []*unicode.RangeTable{
	unicode.Cyrillic, unicode.Greek, unicode.Armenian, unicode.Cherokee, unicode.Coptic, unicode.Lisu,
}

func isConfusableScript(r rune) bool { return unicode.IsOneOf(confusableScriptTables, r) }

func predominantlyLatin(t string) bool {
	latin, other := 0, 0
	for _, r := range t {
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.Is(unicode.Latin, r) {
			latin++
		} else {
			other++
		}
	}
	return latin > 2*other
}

func hasNonASCII(t string) bool {
	for i := 0; i < len(t); i++ {
		if t[i] >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

func isDashRune(r rune) bool { return r == '\u2013' || r == '\u2014' || r == '\u2015' }
