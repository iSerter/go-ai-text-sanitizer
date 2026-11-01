package aisanitizer

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// collapseStage collapses runs of spaces/tabs inside lines, strips trailing
// whitespace and limits consecutive blank lines. Leading indentation, line
// endings (including CRLF) and fenced code blocks are preserved.
func (p *pipeline) collapseStage(t string, w *rewriter) {
	maxBlank := p.opts.maxBlankLines()
	fences := fencedBlocks(t)
	blank := 0
	for pos := 0; pos < len(t); {
		nl := strings.IndexByte(t[pos:], '\n')
		next, lineEnd := len(t), len(t)
		if nl >= 0 {
			next = pos + nl + 1
			lineEnd = pos + nl
		}
		if lineEnd > pos && t[lineEnd-1] == '\r' {
			lineEnd--
		}
		if fences.contains(pos) {
			blank = 0
			pos = next
			continue
		}
		line := t[pos:lineEnd]
		if strings.TrimLeft(line, " \t") == "" {
			blank++
			if maxBlank >= 0 && blank > maxBlank {
				// Drop the whole line, including its line ending.
				w.replace(pos, next, "")
				p.add(iCollapseWhitespace, 0, "EXCESS BLANK LINE", "", pos, 1, ActionRemove)
			} else if len(line) > 0 {
				w.replace(pos, lineEnd, "")
				p.add(iCollapseWhitespace, 0, "TRAILING WHITESPACE", "", pos, len(line), ActionRemove)
			}
			pos = next
			continue
		}
		blank = 0
		// Skip leading indentation.
		i := pos
		for i < lineEnd && (t[i] == ' ' || t[i] == '\t') {
			i++
		}
		for i < lineEnd {
			if t[i] != ' ' && t[i] != '\t' {
				i++
				continue
			}
			j := i
			for j < lineEnd && (t[j] == ' ' || t[j] == '\t') {
				j++
			}
			switch {
			case j == lineEnd:
				w.replace(i, j, "")
				p.add(iCollapseWhitespace, 0, "TRAILING WHITESPACE", "", i, j-i, ActionRemove)
			case j-i > 1:
				w.replace(i, j, " ")
				p.add(iCollapseWhitespace, 0, "WHITESPACE RUN", "", i, j-i-1, ActionRemove)
			}
			i = j
		}
		pos = next
	}
}

func (p *pipeline) trimStage(t string, w *rewriter) {
	start := len(t) - len(strings.TrimLeftFunc(t, unicode.IsSpace))
	end := len(strings.TrimRightFunc(t, unicode.IsSpace))
	if start == len(t) {
		end = start
	}
	if start > 0 {
		w.replace(0, start, "")
		p.add(iTrim, 0, "LEADING WHITESPACE", "", 0, utf8.RuneCountInString(t[:start]), ActionRemove)
	}
	if end < len(t) && end >= start {
		w.replace(end, len(t), "")
		p.add(iTrim, 0, "TRAILING WHITESPACE", "", end, utf8.RuneCountInString(t[end:]), ActionRemove)
	}
}
