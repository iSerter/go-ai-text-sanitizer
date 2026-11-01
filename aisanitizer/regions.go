package aisanitizer

import (
	"regexp"
	"sort"
	"strings"
)

// span is a half-open byte range [a, b).
type span struct{ a, b int }

// spans is a sorted, non-overlapping list of protected ranges.
type spans []span

// overlaps reports whether [a, b) intersects any span.
func (ss spans) overlaps(a, b int) bool {
	k := sort.Search(len(ss), func(i int) bool { return ss[i].b > a })
	return k < len(ss) && ss[k].a < b
}

// contains reports whether offset i lies inside a span.
func (ss spans) contains(i int) bool { return ss.overlaps(i, i+1) }

// gaps calls fn for each maximal range of [0, n) outside the spans.
func (ss spans) gaps(n int, fn func(a, b int)) {
	pos := 0
	for _, s := range ss {
		if s.a > pos {
			fn(pos, s.a)
		}
		if s.b > pos {
			pos = s.b
		}
	}
	if pos < n {
		fn(pos, n)
	}
}

func mergeSpans(lists ...spans) spans {
	var all spans
	for _, l := range lists {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].a < all[j].a })
	var out spans
	for _, s := range all {
		if n := len(out); n > 0 && s.a <= out[n-1].b {
			if s.b > out[n-1].b {
				out[n-1].b = s.b
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// codeSpans finds Markdown fenced code blocks and inline code spans.
func codeSpans(t string) spans {
	if !strings.ContainsAny(t, "`~") {
		return nil
	}
	fences := fencedBlocks(t)
	var inline spans
	fences.gaps(len(t), func(a, b int) {
		inline = append(inline, inlineCode(t, a, b)...)
	})
	return mergeSpans(fences, inline)
}

// inlineCode finds backtick code spans in t[a:b]: a run of N backticks
// closed by the next run of exactly N backticks in the same paragraph.
// It runs in linear time.
func inlineCode(t string, a, b int) spans {
	type run struct{ start, end, para int }
	var runs []run
	para := 0
	for i := a; i < b; {
		switch {
		case t[i] == '`':
			j := i
			for j < b && t[j] == '`' {
				j++
			}
			runs = append(runs, run{i, j, para})
			i = j
		case t[i] == '\n' && i+1 < b && t[i+1] == '\n':
			para++
			i += 2
		default:
			i++
		}
	}
	if len(runs) < 2 {
		return nil
	}
	// next[k] is the index of the next run with the same length, or -1.
	next := make([]int, len(runs))
	last := map[int]int{}
	for k := len(runs) - 1; k >= 0; k-- {
		n := runs[k].end - runs[k].start
		if j, ok := last[n]; ok {
			next[k] = j
		} else {
			next[k] = -1
		}
		last[n] = k
	}
	var out spans
	for k := 0; k < len(runs); {
		j := next[k]
		if j < 0 || runs[j].para != runs[k].para {
			k++
			continue
		}
		out = append(out, span{runs[k].start, runs[j].end})
		k = j + 1
	}
	return out
}

// fencedBlocks finds ``` and ~~~ fenced code blocks (an unclosed fence runs
// to the end of the text).
func fencedBlocks(t string) spans {
	var out spans
	open := -1
	var fenceChar byte
	fenceLen := 0
	for pos := 0; pos < len(t); {
		end := strings.IndexByte(t[pos:], '\n')
		next := len(t)
		if end >= 0 {
			next = pos + end + 1
		}
		line := strings.TrimRight(t[pos:next], "\r\n")
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if indent <= 3 && len(trimmed) >= 3 && (trimmed[0] == '`' || trimmed[0] == '~') {
			c := trimmed[0]
			n := 0
			for n < len(trimmed) && trimmed[n] == c {
				n++
			}
			switch {
			case open < 0 && n >= 3:
				open, fenceChar, fenceLen = pos, c, n
			case open >= 0 && c == fenceChar && n >= fenceLen && strings.TrimSpace(trimmed[n:]) == "":
				out = append(out, span{open, next})
				open = -1
			}
		}
		pos = next
	}
	if open >= 0 {
		out = append(out, span{open, len(t)})
	}
	return out
}

var (
	urlPattern   = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'\x60\x{3010}\x{3011}]+`)
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// linkSpans finds URLs and e-mail addresses.
func linkSpans(t string) spans {
	var out spans
	if strings.Contains(t, "://") || strings.Contains(t, "www.") {
		for _, m := range urlPattern.FindAllStringIndex(t, -1) {
			out = append(out, span{m[0], m[0] + len(trimURL(t[m[0]:m[1]]))})
		}
	}
	if strings.IndexByte(t, '@') >= 0 {
		for _, m := range emailPattern.FindAllStringIndex(t, -1) {
			out = append(out, span{m[0], m[1]})
		}
	}
	return mergeSpans(out)
}

// trimURL drops trailing punctuation that is almost never part of a URL, and
// a closing parenthesis/bracket that has no opening partner in the URL.
func trimURL(u string) string {
	for len(u) > 0 {
		c := u[len(u)-1]
		switch {
		case strings.IndexByte(".,;:!?'\"*_", c) >= 0:
		case c == ')' && strings.Count(u, "(") < strings.Count(u, ")"):
		case c == ']' && strings.Count(u, "[") < strings.Count(u, "]"):
		default:
			return u
		}
		u = u[:len(u)-1]
	}
	return u
}

// protectedSpans returns code spans, plus links when withLinks is set.
func protectedSpans(t string, withLinks bool) spans {
	if withLinks {
		return mergeSpans(codeSpans(t), linkSpans(t))
	}
	return codeSpans(t)
}
