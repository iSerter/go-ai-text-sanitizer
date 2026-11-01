package aisanitizer

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	boilerplateOpener  = regexp.MustCompile(`(?i)^\s*(?:(?:sure|certainly|of course|absolutely|okay|ok|alright|great question|good question)[!,.]?\s*)?(?:here(?:'s|’s| is| are)|below (?:is|are))\b[^\n]{0,150}:\s*$`)
	boilerplateAck     = regexp.MustCompile(`(?i)^\s*(?:sure|certainly|of course|absolutely|great question|good question)[!.]?\s*$`)
	boilerplateSignoff = regexp.MustCompile(`(?i)^\s*(?:i hope (?:this|that) helps|hope (?:this|that) helps|let me know if|feel free to|if you have any (?:other |further |more |additional )?questions|is there anything else|happy (?:writing|to help)|good luck with)\b[^\n]*$`)
	boilerplateInline  = regexp.MustCompile(`(?i)\b(?:as an ai(?: language)? model(?: developed by [a-z][\w-]*)?|(?:as of|based on) my (?:last |latest )?(?:knowledge|training)(?: data)?(?: cut-?off| update)(?: (?:date|in|of) [^,.\n]{1,30})?),\s*`)
)

// boilerplateStage removes chat boilerplate: an opening acknowledgement or
// "Here's …:" line, closing sign-off lines, and "As an AI language model,"
// or knowledge-cutoff lead-in clauses.
func (p *pipeline) boilerplateStage(t string, w *rewriter) {
	code := codeSpans(t)
	type line struct{ a, b, next int }
	var ls []line
	for pos := 0; pos < len(t); {
		nl := strings.IndexByte(t[pos:], '\n')
		next := len(t)
		if nl >= 0 {
			next = pos + nl + 1
		}
		end := next
		for end > pos && (t[end-1] == '\n' || t[end-1] == '\r') {
			end--
		}
		ls = append(ls, line{pos, end, next})
		pos = next
	}
	isBlank := func(l line) bool { return strings.TrimSpace(t[l.a:l.b]) == "" }
	removeLine := func(k int) {
		l := ls[k]
		// Also drop one following blank line so no gap is left behind.
		end := l.next
		if k+1 < len(ls) && isBlank(ls[k+1]) && k+1 != len(ls)-1 {
			end = ls[k+1].next
		}
		w.replace(l.a, end, "")
		p.add(iChatBoilerplate, 0, "CHAT BOILERPLATE LINE", sample(strings.TrimSpace(t[l.a:l.b])), l.a, 1, ActionRemove)
	}

	// Leading opener (at most two lines, e.g. "Sure!" then "Here's …:").
	first := 0
	for first < len(ls) && isBlank(ls[first]) {
		first++
	}
	removedHead := map[int]bool{}
	for k := first; k < len(ls) && k < first+2; k++ {
		l := ls[k]
		if isBlank(l) || code.overlaps(l.a, l.b) {
			break
		}
		txt := t[l.a:l.b]
		if boilerplateAck.MatchString(txt) || boilerplateOpener.MatchString(txt) {
			removedHead[k] = true
			continue
		}
		break
	}

	// Trailing sign-offs (up to three lines).
	removedTail := map[int]bool{}
	last := len(ls) - 1
	for last >= 0 && isBlank(ls[last]) {
		last--
	}
	for k, n := last, 0; k >= 0 && n < 3; k-- {
		l := ls[k]
		if isBlank(l) {
			continue
		}
		if removedHead[k] || code.overlaps(l.a, l.b) || !boilerplateSignoff.MatchString(t[l.a:l.b]) {
			break
		}
		removedTail[k] = true
		n++
	}
	// Never remove every line: text that is nothing but boilerplate-like
	// lines ("Hope this helps!") is the content itself.
	if len(removedHead)+len(removedTail) > 0 {
		kept := false
		for k, l := range ls {
			if !removedHead[k] && !removedTail[k] && !isBlank(l) {
				kept = true
				break
			}
		}
		if !kept {
			clear(removedHead)
			clear(removedTail)
		}
	}

	inline := boilerplateInline.FindAllStringIndex(t, -1)
	mi := 0
	for k := range ls {
		if removedHead[k] {
			removeLine(k)
			continue
		}
		if removedTail[k] {
			// The sign-offs and the blank lines around them run to the end
			// of the text: remove them as one block.
			a := ls[k].a
			for j := k - 1; j >= 0 && isBlank(ls[j]) && ls[j].a >= w.last; j-- {
				a = ls[j].a
			}
			if !strings.HasSuffix(t, "\n") {
				// The text had no final newline; don't leave one behind.
				for a > w.last && (t[a-1] == '\n' || t[a-1] == '\r') {
					a--
				}
			}
			for j := k; j < len(ls); j++ {
				if removedTail[j] {
					l := ls[j]
					p.add(iChatBoilerplate, 0, "CHAT BOILERPLATE LINE", sample(strings.TrimSpace(t[l.a:l.b])), l.a, 1, ActionRemove)
				}
			}
			w.replace(a, len(t), "")
			break
		}
		for ; mi < len(inline) && inline[mi][0] < ls[k].next; mi++ {
			m := inline[mi]
			if m[0] < w.last || code.overlaps(m[0], m[1]) {
				continue
			}
			p.add(iChatBoilerplate, 0, "CHAT BOILERPLATE CLAUSE", sample(t[m[0]:m[1]]), m[0], 1, ActionRemove)
			// Capitalize the next letter when the clause opened a sentence.
			r, size := utf8.DecodeRuneInString(t[m[1]:])
			if atSentenceStart(t, m[0]) && unicode.IsLower(r) {
				w.replace(m[0], m[1]+size, string(unicode.ToUpper(r)))
			} else {
				w.replace(m[0], m[1], "")
			}
		}
	}
}

func atSentenceStart(t string, i int) bool {
	for i > 0 {
		r, size := utf8.DecodeLastRuneInString(t[:i])
		switch {
		case r == ' ' || r == '\t':
			i -= size
			continue
		case r == '\n' || r == '.' || r == '!' || r == '?' || r == '"' || r == '(':
			return true
		}
		return false
	}
	return true
}
