package aisanitizer

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// markdownRule is one Markdown-to-plain-text rewrite. Each runs as its own
// pipeline stage so that later rules see the output of earlier ones.
type markdownRule struct {
	name string
	// needles are literal prefilters: the regex only runs if one occurs.
	needles []string
	re      *regexp.Regexp
	// repl builds the replacement from the submatch indexes; ok=false skips
	// the match.
	repl func(t string, m []int) (string, bool)
}

func group(t string, m []int, g int) string {
	if m[2*g] < 0 {
		return ""
	}
	return t[m[2*g]:m[2*g+1]]
}

func expand(tmpl ...int) func(t string, m []int) (string, bool) {
	return func(t string, m []int) (string, bool) {
		s := ""
		for _, g := range tmpl {
			s += group(t, m, g)
		}
		return s, true
	}
}

var markdownRules = []markdownRule{
	{"IMAGE", []string{"!["}, regexp.MustCompile(`!\[([^\]\n]*)\]\([^)\n]+\)`), expand(1)},
	{"LINK", []string{"]("}, regexp.MustCompile(`\[([^\]\n]+)\]\(([^)\s]+)\)`), func(t string, m []int) (string, bool) {
		label, url := group(t, m, 1), group(t, m, 2)
		if label == url {
			return url, true
		}
		return label + " (" + url + ")", true
	}},
	// A closing # sequence needs whitespace before it, so "C#" keeps its '#'.
	{"HEADING", []string{"#"}, regexp.MustCompile(`(?m)^[ \t]{0,3}(?:#{1,6}[ \t]+)+([^\n]*?)(?:[ \t]+#+)?[ \t]*$`), expand(1)},
	{"BOLD", []string{"**", "__"}, regexp.MustCompile(`\*{2,}([^*\n]+?)\*{2,}|_{2,}([^_\n]+?)_{2,}`), expand(1, 2)},
	{"ITALIC", []string{"*", "_"}, regexp.MustCompile(`(^|[^*\w])\*([^*\s](?:[^*\n]*[^*\s])?)\*|(^|[\s(])_([^_\s](?:[^_\n]*[^_\s])?)_`),
		func(t string, m []int) (string, bool) {
			if end := m[1]; end < len(t) {
				r, _ := utf8.DecodeRuneInString(t[end:])
				if unicode.IsLetter(r) || unicode.IsDigit(r) {
					return "", false
				}
			}
			return group(t, m, 1) + group(t, m, 2) + group(t, m, 3) + group(t, m, 4), true
		}},
	{"HORIZONTAL RULE", []string{"---", "- -", "**", "* *", "__", "_ _"}, regexp.MustCompile(`(?m)^[ \t]{0,3}(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})$`), expand()},
	{"BLOCKQUOTE", []string{">"}, regexp.MustCompile(`(?m)^[ \t]{0,3}(?:>[ \t]?)+`), expand()},
	{"BULLET", []string{"* ", "*\t", "+ ", "+\t", "\u2022"}, regexp.MustCompile(`(?m)^([ \t]*)[*+•][ \t]+`), func(t string, m []int) (string, bool) {
		return group(t, m, 1) + "- ", true
	}},
}

func (m markdownRule) apply(p *pipeline) func(string, *rewriter) {
	return func(t string, w *rewriter) {
		if !containsAny(t, m.needles) {
			return
		}
		matches := m.re.FindAllStringSubmatchIndex(t, -1)
		if len(matches) == 0 {
			return
		}
		code := codeSpans(t)
		for _, sm := range matches {
			if sm[0] < w.last || code.overlaps(sm[0], max(sm[1], sm[0]+1)) {
				continue
			}
			repl, ok := m.repl(t, sm)
			if !ok || repl == t[sm[0]:sm[1]] {
				continue
			}
			w.replace(sm[0], sm[1], repl)
			p.add(iMarkdown, 0, "MARKDOWN "+m.name, sample(t[sm[0]:sm[1]]), sm[0], 1, ActionReplace)
		}
	}
}
