package aisanitizer

import "testing"

func TestCitationArtifacts(t *testing.T) {
	tests := []struct {
		name, in, want string
		rule           RuleID
	}{
		{"oaicite", "Some text (oaicite:5){index=5} more text", "Some text more text", RuleOaicite},
		{"oaicite before period", "Fact (oaicite:0){index=0}.", "Fact.", RuleOaicite},
		{"content reference", "Text :contentReference[oaicite:0]{index=0} end", "Text end", RuleContentReference},
		{"content reference double colon", "Text.::contentReference[oaicite:12]{index=12}", "Text.", RuleContentReference},
		{"oai_citation", "Rates rose [oai_citation:0\u2021reuters.com](https://www.reuters.com/x?utm_source=chatgpt.com) today.", "Rates rose today.", RuleOaiCitation},
		{"oai_citation_attribution", "See [oai_citation_attribution:1\u2021Wikipedia](https://en.wikipedia.org/wiki/Go).", "See.", RuleOaiCitation},
		{"pua citation", "Fact \uE200cite\uE202turn0search0\uE202turn0news3\uE201.", "Fact.", RulePUACitation},
		{"turn citation", "Inflation rose.citeturn0search2turn0news1 Next", "Inflation rose. Next", RuleTurnCitation},
		{"filecite", "As noted filecite turn0file2turn0file6 above", "As noted filecite above", RuleTurnCitation},
		{"filecite glued", "As noted fileciteturn0file2turn0file6 above", "As noted above", RuleTurnCitation},
		{"image group", "Pictures iturn0image0turn0image1 here", "Pictures here", RuleTurnCitation},
		{"lenticular", "Answer \u30104:0\u2020source\u3011.", "Answer.", RuleLenticularCitation},
		{"lenticular lines", "Text \u301085\u2020L261-269\u3011 more", "Text more", RuleLenticularCitation},
		{"attribution json", "^[The sky is blue.]({\"attribution\":{\"attributableIndex\":\"1009-1\"}}) Next.", "The sky is blue. Next.", RuleAttributionJSON},
		{"attribution curly", "^[Fact]({\u201Cattribution\u201D:{\u201CattributableIndex\u201D:\u201C3-1\u201D}})", "Fact", RuleAttributionJSON},
		{"gemini cite", "Growth was 3% [cite: 2, 6].", "Growth was 3%.", RuleGeminiCitation},
		{"gemini cite_start", "[cite_start]Growth was 3%.", "Growth was 3%.", RuleGeminiCitation},
		{"gemini span", "[span_1](start_span)Claim[span_1](end_span) here", "Claim here", RuleGeminiSpan},
		{"grok card", "Fact <grok-card data-id=\"e8ff4f\" data-type=\"citation_card\"></grok-card> ok", "Fact ok", RuleGrokCard},
		{"grok render", "Fact [](grok_render_citation_card_json={\"cardIds\":[\"3bb883\"]}) ok", "Fact ok", RuleGrokCard},
		{"perplexity web", "Paris is the capital[web:1][web:3].", "Paris is the capital.", RulePerplexityTag},
		{"perplexity file", "Per the report [attached_file:1], sales grew.", "Per the report, sales grew.", RulePerplexityTag},
		{"adjacent citations", "x (oaicite:0){index=0}(oaicite:1){index=1}.", "x.", RuleOaicite},
		{"line of only citations", "a\n(oaicite:0){index=0}\nb", "a\n\nb", RuleOaicite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := check(t, nil, tt.in, tt.want)
			if rep.Count(tt.rule) == 0 {
				t.Errorf("no %s finding: %+v", tt.rule, rep.Findings)
			}
			if rep.Changes.RemovedCitations == 0 {
				t.Errorf("RemovedCitations not counted: %+v", rep.Changes)
			}
		})
	}
	check(t, withOpts(func(o *Options) { o.RemoveCitations = false }), "a (oaicite:0){index=0}", "a (oaicite:0){index=0}")
}

func TestArtifactsInvisibleEvasion(t *testing.T) {
	// Watermark characters inside an artifact must not hide it.
	check(t, nil, "x (oai\u200Bcite:1){index=1} y", "x y")
}

func TestArtifactsInCodeAreKept(t *testing.T) {
	for _, in := range []string{
		"Use `(oaicite:0){index=0}` in docs",
		"```\nprint(\"\u30104\u2020source\u3011\")\n[web:1]\n```\n",
		"~~~go\nx := \"citeturn0search0\"\n~~~",
	} {
		check(t, nil, in, in)
	}
}

func TestNumericCitations(t *testing.T) {
	in := "Proven [1], again [2, 3] and [4\u20136]. See [1](http://x.y) and\n[2]: http://ref"
	check(t, nil, in, in)
	o := withOpts(func(o *Options) { o.RemoveNumericCitations = true })
	check(t, o, in, "Proven, again and. See [1](http://x.y) and\n[2]: http://ref")
}

func TestWritingBlock(t *testing.T) {
	in := "Intro\n:::writing{variant=\"document\" id=\"68427\"}\nDraft body.\n:::\nOutro"
	rep := check(t, nil, in, "Intro\nDraft body.\nOutro")
	if rep.Changes.RemovedModelArtifacts != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
	check(t, nil, ":::\nnot a block\n:::", ":::\nnot a block\n:::")
	check(t, withOpts(func(o *Options) { o.RemoveModelArtifacts = false }), in, in)
}

func TestTrackingParams(t *testing.T) {
	tests := []struct{ in, want string }{
		{"See https://example.com/a?utm_source=chatgpt.com.", "See https://example.com/a."},
		{"https://x.io/p?a=1&utm_source=openai#frag", "https://x.io/p?a=1#frag"},
		{"https://x.io/p?utm_source=chatgpt.com&b=2", "https://x.io/p?b=2"},
		{"[link](https://x.io/?utm_source=copilot.com)", "[link](https://x.io/)"},
		{"<a href=\"https://x.io/?a=1&amp;utm_source=chatgpt.com\">", "<a href=\"https://x.io/?a=1\">"},
		{"https://x.io/?utm_source=chatgpt.com&amp;b=2", "https://x.io/?b=2"},
		{"https://grok.com/x?referrer=grok.com", "https://grok.com/x"},
		{"https://x.io/?utm_source=newsletter", "https://x.io/?utm_source=newsletter"},
		{"utm_source=chatgpt.com without URL", "utm_source=chatgpt.com without URL"},
	}
	for _, tt := range tests {
		check(t, nil, tt.in, tt.want)
	}
	_, rep := CleanText("https://a.b/?utm_source=chatgpt.com https://c.d/?utm_source=openai")
	if rep.Changes.RemovedTrackingParams != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestSourcePillsAreDetectOnly(t *testing.T) {
	in := "Coverage was good Wikipedia+1 and IT Governance+3ISO+3 too."
	check(t, nil, in, in)
	rep, _ := Detect(in, nil)
	if rep.Count(RuleSourcePill) != 2 {
		t.Errorf("findings = %+v", rep.Findings)
	}
	rep, _ = Detect("C++ and A+1 grades", nil)
	if rep.Count(RuleSourcePill) != 0 {
		t.Errorf("false positive: %+v", rep.Findings)
	}
}

func TestBoilerplate(t *testing.T) {
	o := withOpts(func(o *Options) { o.RemoveChatBoilerplate = true })
	tests := []struct{ name, in, want string }{
		{"opener and signoff",
			"Sure! Here's the rewritten paragraph:\n\nThe report is due Friday.\n\nI hope this helps! Let me know if you need anything else.\n",
			"The report is due Friday.\n"},
		{"two-line opener", "Certainly!\nHere is a summary:\nBody text.", "Body text."},
		{"ai model clause", "As an AI language model, i cannot browse. Fine.", "I cannot browse. Fine."},
		{"knowledge cutoff mid-text", "Prices vary. As of my last knowledge update in 2023, prices rose.", "Prices vary. Prices rose."},
		{"signoff lines", "Answer.\n\nFeel free to ask more.\nHappy writing!", "Answer."},
		{"no colon keeps line", "Sure, here's a thought experiment worth having.\nBody.", "Sure, here's a thought experiment worth having.\nBody."},
		{"mid-text here is kept", "Intro.\nHere is the data:\n1, 2, 3", "Intro.\nHere is the data:\n1, 2, 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { check(t, o, tt.in, tt.want) })
	}
	check(t, nil, "Sure! Here's the text:\nBody", "Sure! Here's the text:\nBody")
}
