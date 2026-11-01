package aisanitizer

import (
	"regexp"
	"sort"
	"strings"
)

// artifactPattern is a regex-based artifact rule. Needles are cheap literal
// prefilters: the regex only runs if one of them occurs in the text.
type artifactPattern struct {
	rule    RuleID
	name    string
	needles []string
	re      *regexp.Regexp
	// repl is an Expand template; empty means remove (with whitespace
	// tidying).
	repl string
	// accept optionally vetoes a match given the text and match indexes.
	accept func(t string, m []int) bool
}

var artifactPatterns = []artifactPattern{
	{rule: RuleContentReference, name: "CHATGPT CONTENT REFERENCE", needles: []string{"contentReference"},
		re: regexp.MustCompile(`:{0,2}contentReference\[oaicite:\d+\]\{index=\d+\}`)},
	{rule: RuleOaicite, name: "CHATGPT OAICITE PLACEHOLDER", needles: []string{"oaicite"},
		re: regexp.MustCompile(`\(oaicite:\d+\)\{index=\d+\}`)},
	{rule: RuleOaiCitation, name: "CHATGPT OAI_CITATION LINK", needles: []string{"oai_citation"},
		re: regexp.MustCompile(`\[oai_citation(?:_attribution)?:\d+‡[^\]\n]*\]\([^)\s]*\)`)},
	{rule: RulePUACitation, name: "CHATGPT PRIVATE-USE CITATION", needles: []string{"\uE200"},
		re: regexp.MustCompile(`\x{E200}[^\x{E201}\n]{0,300}\x{E201}`)},
	{rule: RuleTurnCitation, name: "CHATGPT TURN CITATION TOKEN", needles: []string{"turn"},
		re: regexp.MustCompile(`(?:filecite|cite|navlist|i)?(?:turn\d+(?:search|news|file|image|view)\d+)+`)},
	{rule: RuleLenticularCitation, name: "LENTICULAR CITATION", needles: []string{"\u3010"},
		re: regexp.MustCompile(`【\d+(?::\d+)?†[^】\n]{0,80}】`)},
	{rule: RuleAttributionJSON, name: "CHATGPT ATTRIBUTION WRAPPER", needles: []string{"attribution"},
		re: regexp.MustCompile(`\^\[([^\]\n]+)\]\(\{["“”]attribution["“”]:\s*\{[^}\n]*\}\}\)`), repl: "$1"},
	{rule: RuleGeminiCitation, name: "GEMINI CITATION", needles: []string{"[cite"},
		re: regexp.MustCompile(`\[cite:\s*\d+(?:\s*,\s*\d+)*\]|\[cite_(?:start|end)\]`)},
	{rule: RuleGeminiSpan, name: "GEMINI SPAN MARKER", needles: []string{"[span_"},
		re: regexp.MustCompile(`\[span_\d+\]\((?:start|end)_span\)`)},
	{rule: RuleGrokCard, name: "GROK CITATION CARD", needles: []string{"grok"},
		re: regexp.MustCompile(`<grok-card\b[^>]*>(?:[^<]{0,200}</grok-card>)?|\[\]\(grok_render_citation_card_json=\{[^)\n]*\}\)`)},
	{rule: RulePerplexityTag, name: "PERPLEXITY SOURCE TAG", needles: []string{"[web:", "[attached_file:"},
		re: regexp.MustCompile(`\[(?:web|attached_file):\d+(?:\s*,\s*\d+)*\]`)},
	{rule: RuleNumericCitation, name: "NUMERIC CITATION MARKER", needles: []string{"["},
		re:     regexp.MustCompile(`\[\d{1,3}(?:\s*[,–-]\s*\d{1,3})*\]`),
		accept: notLinkLabel},
	{rule: RuleFootnoteBacklink, name: "FOOTNOTE BACKLINK", needles: []string{"\u21A9"},
		re: regexp.MustCompile(`[ \t]*↩\x{FE0E}?`)},
	{rule: RuleSourcePill, name: "CHATGPT SOURCE PILL", needles: []string{"+"},
		re: regexp.MustCompile(`\b[A-Z][A-Za-z.&-]{2,}(?: [A-Z][A-Za-z.&-]*){0,3}\+\d{1,2}(?:[A-Z][A-Za-z.&-]{2,}(?: [A-Z][A-Za-z.&-]*){0,3}\+\d{1,2})*\b`)},
}

var (
	writingOpen  = regexp.MustCompile(`(?m)^[ \t]*:::[\p{L}_-]+\{[^}\n]*\}[ \t]*(?:\r?\n|$)`)
	writingClose = regexp.MustCompile(`(?m)^[ \t]*:::[ \t]*(?:\r?\n|$)`)
)

// artifactRuleIdx lists the rules handled by the artifact stage.
var artifactRuleIdx = func() []ruleIdx {
	out := []ruleIdx{ruleIndex[RuleWritingBlock], ruleIndex[RuleTrackingParam]}
	for _, ap := range artifactPatterns {
		out = append(out, ruleIndex[ap.rule])
	}
	return out
}()

// notLinkLabel rejects "[1](url)" and "[1]: url" (Markdown link syntax).
func notLinkLabel(t string, m []int) bool {
	if m[1] < len(t) && (t[m[1]] == '(' || t[m[1]] == ':') {
		return false
	}
	return m[0] == 0 || t[m[0]-1] != ']'
}

type artifactMatch struct {
	a, b   int
	idx    ruleIdx
	name   string
	repl   string
	remove bool
	detect bool
	count  int
}

func (p *pipeline) artifactStage(t string, w *rewriter) {
	var ms []artifactMatch
	for _, ap := range artifactPatterns {
		i := ruleIndex[ap.rule]
		if !p.en[i] || (registry[i].Action == ActionDetect && !p.detect) || !containsAny(t, ap.needles) {
			continue
		}
		for _, m := range ap.re.FindAllStringSubmatchIndex(t, -1) {
			if ap.accept != nil && !ap.accept(t, m) {
				continue
			}
			am := artifactMatch{a: m[0], b: m[1], idx: i, name: ap.name, count: 1}
			switch {
			case registry[i].Action == ActionDetect:
				am.detect = true
			case ap.repl != "":
				am.repl = string(ap.re.ExpandString(nil, ap.repl, t, m))
			default:
				am.remove = true
			}
			ms = append(ms, am)
		}
	}
	if p.en[ruleIndex[RuleWritingBlock]] && strings.Contains(t, ":::") {
		ms = append(ms, writingBlockMatches(t)...)
	}
	if p.en[iTrackingParam] && (strings.Contains(t, "utm_source=") || strings.Contains(t, "referrer=")) {
		ms = append(ms, trackingParamMatches(t)...)
	}
	if len(ms) == 0 {
		return
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].a != ms[j].a {
			return ms[i].a < ms[j].a
		}
		return ms[i].b > ms[j].b
	})
	code := codeSpans(t)
	end := 0
	for _, m := range ms {
		if code.overlaps(m.a, m.b) {
			continue
		}
		if m.detect {
			if p.iter == 0 {
				p.add(m.idx, 0, m.name, sample(t[m.a:m.b]), m.a, 1, ActionDetect)
			}
			continue
		}
		if m.a < end || m.a < w.last {
			continue
		}
		end = m.b
		action := ActionReplace
		if m.remove {
			action = ActionRemove
		}
		p.add(m.idx, 0, m.name, sample(t[m.a:m.b]), m.a, m.count, action)
		if m.remove {
			w.removeTidy(m.a, m.b)
		} else {
			w.replace(m.a, m.b, m.repl)
		}
	}
}

func containsAny(t string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(t, n) {
			return true
		}
	}
	return false
}

// writingBlockMatches removes ":::writing{...}" opener lines and the next
// ":::" closer after each, keeping the content in between.
func writingBlockMatches(t string) []artifactMatch {
	i := ruleIndex[RuleWritingBlock]
	var out []artifactMatch
	for _, m := range writingOpen.FindAllStringIndex(t, -1) {
		out = append(out, artifactMatch{a: m[0], b: m[1], idx: i, name: "CANVAS WRAPPER", count: 1})
		if c := writingClose.FindStringIndex(t[m[1]:]); c != nil {
			out = append(out, artifactMatch{a: m[1] + c[0], b: m[1] + c[1], idx: i, name: "CANVAS WRAPPER", count: 1})
		}
	}
	return out
}

var trackingPattern = regexp.MustCompile(`https?://[^\s<>"'\x60)\]]+`)

var aiReferrers = map[string]map[string]bool{
	"utm_source": {
		"chatgpt.com": true, "chat.openai.com": true, "openai": true, "openai.com": true,
		"copilot.com": true, "copilot.microsoft.com": true, "perplexity": true, "perplexity.ai": true,
		"claude.ai": true, "claude": true, "gemini": true, "gemini.google.com": true,
	},
	"referrer": {"grok.com": true},
}

// trackingParamMatches rewrites URLs whose query contains AI referral
// parameters, dropping just those parameters.
func trackingParamMatches(t string) []artifactMatch {
	i := ruleIndex[RuleTrackingParam]
	var out []artifactMatch
	for _, m := range trackingPattern.FindAllStringIndex(t, -1) {
		u := trimURL(t[m[0]:m[1]])
		q := strings.IndexByte(u, '?')
		if q < 0 {
			continue
		}
		base, query, frag := u[:q], u[q+1:], ""
		if h := strings.IndexByte(query, '#'); h >= 0 {
			query, frag = query[:h], query[h:]
		}
		parts := strings.Split(query, "&")
		kept := parts[:0:0]
		removed := 0
		for _, part := range parts {
			key, val, _ := strings.Cut(strings.TrimPrefix(part, "amp;"), "=")
			if aiReferrers[strings.ToLower(key)][strings.ToLower(val)] {
				removed++
				continue
			}
			kept = append(kept, part)
		}
		if removed == 0 {
			continue
		}
		if len(kept) > 0 {
			kept[0] = strings.TrimPrefix(kept[0], "amp;")
		}
		repl := base
		if len(kept) > 0 {
			repl += "?" + strings.Join(kept, "&")
		}
		repl += frag
		out = append(out, artifactMatch{a: m[0], b: m[0] + len(u), idx: i, name: "AI REFERRAL PARAMETER", repl: repl, count: removed})
	}
	return out
}
