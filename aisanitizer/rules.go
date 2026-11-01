package aisanitizer

// RuleID identifies a single sanitization or detection rule. Rule IDs are
// stable and appear in reports (Finding.Rule), in Options.Rules overrides and
// in the CLI's --rule/--no-rule flags.
type RuleID string

// Character rules.
const (
	RuleZeroWidth         RuleID = "zero_width"
	RuleBidi              RuleID = "bidi"
	RuleInvisibleMath     RuleID = "invisible_math"
	RuleVariationSelector RuleID = "variation_selector"
	RuleTagChar           RuleID = "tag_char"
	RuleFormatChar        RuleID = "format_char"
	RuleBrailleBlank      RuleID = "braille_blank"
	RuleNoncharacter      RuleID = "noncharacter"
	RulePrivateUse        RuleID = "private_use"
	RuleControl           RuleID = "control"
	RuleANSIEscape        RuleID = "ansi_escape"
	RuleHTMLEntity        RuleID = "html_entity"
	RuleInvalidUTF8       RuleID = "invalid_utf8"
	RuleReplacementChar   RuleID = "replacement_char"
)

// Whitespace rules.
const (
	RuleExoticSpace        RuleID = "exotic_space"
	RuleLineSeparator      RuleID = "line_separator"
	RuleCollapseWhitespace RuleID = "collapse_whitespace"
	RuleTrim               RuleID = "trim"
)

// Visible LLM artifact rules.
const (
	RuleOaicite            RuleID = "artifact.oaicite"
	RuleContentReference   RuleID = "artifact.content_reference"
	RuleOaiCitation        RuleID = "artifact.oai_citation"
	RulePUACitation        RuleID = "artifact.pua_citation"
	RuleTurnCitation       RuleID = "artifact.turn_citation"
	RuleLenticularCitation RuleID = "artifact.lenticular_citation"
	RuleAttributionJSON    RuleID = "artifact.attribution_json"
	RuleGeminiCitation     RuleID = "artifact.gemini_citation"
	RuleGeminiSpan         RuleID = "artifact.gemini_span"
	RuleGrokCard           RuleID = "artifact.grok_card"
	RulePerplexityTag      RuleID = "artifact.perplexity_tag"
	RuleWritingBlock       RuleID = "artifact.writing_block"
	RuleNumericCitation    RuleID = "artifact.numeric_citation"
	RuleFootnoteBacklink   RuleID = "artifact.footnote_backlink"
	RuleSourcePill         RuleID = "artifact.source_pill"
	RuleTrackingParam      RuleID = "artifact.tracking_param"
	RuleChatBoilerplate    RuleID = "artifact.chat_boilerplate"
)

// Typography and formatting rules.
const (
	RuleSmartQuote  RuleID = "smart_quote"
	RuleDash        RuleID = "dash"
	RuleEllipsis    RuleID = "ellipsis"
	RulePunctuation RuleID = "punctuation"
	RuleCompatFold  RuleID = "compat_fold"
	RuleMarkdown    RuleID = "markdown"
)

// Homoglyph and steganography rules.
const (
	RuleConfusable              RuleID = "confusable"
	RuleMixedScript             RuleID = "mixed_script"
	RuleTagPayload              RuleID = "stego.tag_payload"
	RuleVariationSelectorStego  RuleID = "stego.variation_selector_payload"
	RuleInvisibleMathStego      RuleID = "stego.invisible_math_payload"
	RuleZeroWidthStego          RuleID = "stego.zero_width_payload"
	RuleTrailingWhitespaceStego RuleID = "stego.trailing_whitespace"
)

// Rule categories, used to group findings.
const (
	CategoryInvisible     = "invisible"
	CategoryWhitespace    = "whitespace"
	CategoryArtifact      = "artifact"
	CategoryTypography    = "typography"
	CategoryHomoglyph     = "homoglyph"
	CategorySteganography = "steganography"
	CategoryEncoding      = "encoding"
)

// Action describes what a rule does with what it matches.
type Action string

const (
	ActionRemove  Action = "remove"
	ActionReplace Action = "replace"
	ActionDetect  Action = "detect"
)

// RuleInfo describes a registered rule.
type RuleInfo struct {
	ID          RuleID `json:"id"`
	Category    string `json:"category"`
	Action      Action `json:"action"`
	Default     bool   `json:"default"`
	Option      string `json:"option,omitempty"`
	Description string `json:"description"`
}

type ruleIdx int

// maxRules bounds the registry size so per-rule state fits in fixed arrays.
const maxRules = 64

// ruleDef is the internal registry entry. enabled reports whether the rule is
// on for a given Options value before Options.Rules overrides apply.
type ruleDef struct {
	RuleInfo
	enabled func(o *Options) bool
	stat    func(c *ChangeStats) *int
}

func always(*Options) bool { return true }

var registry = []ruleDef{
	// Invisible characters.
	{RuleInfo{RuleZeroWidth, CategoryInvisible, ActionRemove, true, "RemoveZeroWidth",
		"Zero-width space/non-joiner/joiner, word joiner and BOM (U+200B\u2013200D, U+2060, U+FEFF). Joiners inside emoji and scripts that need them are kept."},
		func(o *Options) bool { return o.RemoveZeroWidth }, func(c *ChangeStats) *int { return &c.RemovedZeroWidth }},
	{RuleInfo{RuleBidi, CategoryInvisible, ActionRemove, true, "RemoveBidi",
		"Bidirectional marks, embeddings, overrides and isolates (U+061C, U+200E/200F, U+202A\u2013202E, U+2066\u20132069). See BidiMode."},
		func(o *Options) bool { return o.RemoveBidi }, func(c *ChangeStats) *int { return &c.RemovedBidi }},
	{RuleInfo{RuleInvisibleMath, CategoryInvisible, ActionRemove, true, "RemoveInvisibleMath",
		"Invisible math operators (U+2061\u20132064)."},
		func(o *Options) bool { return o.RemoveInvisibleMath }, func(c *ChangeStats) *int { return &c.RemovedInvisibleMath }},
	{RuleInfo{RuleVariationSelector, CategoryInvisible, ActionRemove, true, "RemoveVariationSelectors",
		"Variation selectors (U+FE00\u2013FE0F, U+E0100\u2013E01EF). Registered emoji/standardized/ideographic variation sequences are kept."},
		func(o *Options) bool { return o.RemoveVariationSelectors }, func(c *ChangeStats) *int { return &c.RemovedVariationSelectors }},
	{RuleInfo{RuleTagChar, CategoryInvisible, ActionRemove, true, "RemoveTagChars",
		"Unicode tag characters (U+E0000\u2013E007F), the carrier for \"ASCII smuggling\". Valid emoji subdivision flags are kept."},
		func(o *Options) bool { return o.RemoveTagChars }, func(c *ChangeStats) *int { return &c.RemovedTagChars }},
	{RuleInfo{RuleFormatChar, CategoryInvisible, ActionRemove, true, "RemoveFormatChars",
		"Other default-ignorable and invisible format characters: soft hyphen, CGJ, Hangul fillers, Khmer inherent vowels, Mongolian selectors, deprecated format controls, interlinear annotation, shorthand format controls, object replacement character, musical invisibles."},
		func(o *Options) bool { return o.RemoveFormatChars }, func(c *ChangeStats) *int { return &c.RemovedFormatChars }},
	{RuleInfo{RuleBrailleBlank, CategoryInvisible, ActionRemove, true, "RemoveBrailleBlank",
		"Braille pattern blank (U+2800), a visible-blank character used to fake whitespace."},
		func(o *Options) bool { return o.RemoveBrailleBlank }, func(c *ChangeStats) *int { return &c.RemovedBrailleBlank }},
	{RuleInfo{RuleNoncharacter, CategoryInvisible, ActionRemove, true, "RemoveNoncharacters",
		"Noncharacters (U+FDD0\u2013FDEF and U+xFFFE/xFFFF)."},
		func(o *Options) bool { return o.RemoveNoncharacters }, func(c *ChangeStats) *int { return &c.RemovedNoncharacters }},
	{RuleInfo{RulePrivateUse, CategoryInvisible, ActionRemove, false, "RemovePrivateUse",
		"Private-use characters (U+E000\u2013F8FF, planes 15\u201316). Off by default because icon fonts use them; always reported by Detect."},
		func(o *Options) bool { return o.RemovePrivateUse }, func(c *ChangeStats) *int { return &c.RemovedPrivateUse }},
	{RuleInfo{RuleControl, CategoryInvisible, ActionRemove, true, "StripControl",
		"C0/C1 control characters except TAB, LF and CR (see KeepTabs/KeepNewlines)."},
		func(o *Options) bool { return o.StripControl }, func(c *ChangeStats) *int { return &c.RemovedControl }},
	{RuleInfo{RuleANSIEscape, CategoryInvisible, ActionRemove, true, "StripControl",
		"Complete ANSI/VT escape sequences (CSI, OSC and two-byte escapes), not just the ESC byte."},
		func(o *Options) bool { return o.StripControl }, func(c *ChangeStats) *int { return &c.RemovedANSIEscapes }},
	{RuleInfo{RuleHTMLEntity, CategoryInvisible, ActionRemove, true, "DecodeInvisibleEntities",
		"HTML entities that encode invisible characters (e.g. &#8203;, &#x200B;, &ZeroWidthSpace;). Entities for characters with legitimate HTML uses (&nbsp;, &shy;, &zwj;, &zwnj;, &lrm;, &rlm;) are left alone."},
		func(o *Options) bool { return o.DecodeInvisibleEntities }, func(c *ChangeStats) *int { return &c.RemovedHTMLEntities }},
	{RuleInfo{RuleInvalidUTF8, CategoryEncoding, ActionReplace, true, "InvalidUTF8",
		"Invalid UTF-8 byte sequences are replaced with U+FFFD or dropped (see InvalidUTF8)."},
		always, func(c *ChangeStats) *int { return &c.ReplacedInvalidUTF8 }},
	{RuleInfo{RuleReplacementChar, CategoryEncoding, ActionDetect, true, "",
		"U+FFFD REPLACEMENT CHARACTER in the input, a sign of earlier decoding damage."},
		always, nil},

	// Whitespace.
	{RuleInfo{RuleExoticSpace, CategoryWhitespace, ActionReplace, true, "NormalizeSpaces",
		"Unusual spaces (NBSP, en/em/thin/hair spaces, narrow NBSP, ideographic space, \u2026) become U+0020."},
		func(o *Options) bool { return o.NormalizeSpaces }, func(c *ChangeStats) *int { return &c.NormalizedSpaces }},
	{RuleInfo{RuleLineSeparator, CategoryWhitespace, ActionReplace, true, "NormalizeLineSeparators",
		"U+2028 and U+0085 become \\n, U+2029 becomes \\n\\n."},
		func(o *Options) bool { return o.NormalizeLineSeparators }, func(c *ChangeStats) *int { return &c.NormalizedLineSeparators }},
	{RuleInfo{RuleCollapseWhitespace, CategoryWhitespace, ActionRemove, false, "CollapseWhitespace",
		"Collapses runs of spaces/tabs inside lines, strips trailing whitespace per line and limits blank lines (MaxBlankLines). Leading indentation and fenced code are preserved."},
		func(o *Options) bool { return o.CollapseWhitespace }, func(c *ChangeStats) *int { return &c.CollapsedSpaces }},
	{RuleInfo{RuleTrim, CategoryWhitespace, ActionRemove, false, "Trim",
		"Trims leading and trailing whitespace from the whole text."},
		func(o *Options) bool { return o.Trim }, func(c *ChangeStats) *int { return &c.TrimmedWhitespace }},

	// Artifacts.
	{RuleInfo{RuleContentReference, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"ChatGPT content references: :contentReference[oaicite:N]{index=N}."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleOaicite, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"ChatGPT citation placeholders: (oaicite:N){index=N}."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleOaiCitation, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"ChatGPT citation links: [oai_citation:N\u2021source](url)."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RulePUACitation, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"ChatGPT citation markers wrapped in private-use characters U+E200\u2026U+E201 (e.g. \\uE200cite\\uE202turn0search0\\uE201)."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleTurnCitation, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Leaked ChatGPT search/file citation tokens: citeturn0search0, turn0news1, filecite turn0file2, iturn0image0, \u2026"},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleLenticularCitation, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Lenticular-bracket citations: \u30104:0\u2020source\u3011, \u301085\u2020L261-269\u3011."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleAttributionJSON, CategoryArtifact, ActionReplace, true, "RemoveCitations",
		"ChatGPT attribution wrappers ^[text]({\"attribution\":{\u2026}}); the text is kept."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleGeminiCitation, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Gemini citation markers: [cite: 1, 2], [cite_start], [cite_end]."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleGeminiSpan, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Gemini span markers: [span_1](start_span), [span_1](end_span)."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleGrokCard, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Grok citation cards: <grok-card \u2026></grok-card> and [](grok_render_citation_card_json={\u2026})."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RulePerplexityTag, CategoryArtifact, ActionRemove, true, "RemoveCitations",
		"Perplexity source tags: [web:1], [attached_file:1]."},
		func(o *Options) bool { return o.RemoveCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleNumericCitation, CategoryArtifact, ActionRemove, false, "RemoveNumericCitations",
		"Bare numeric citation markers such as [1] or [2, 3]. Off by default: ambiguous with legitimate references."},
		func(o *Options) bool { return o.RemoveNumericCitations }, func(c *ChangeStats) *int { return &c.RemovedCitations }},
	{RuleInfo{RuleWritingBlock, CategoryArtifact, ActionRemove, true, "RemoveModelArtifacts",
		"ChatGPT canvas wrappers: lines like :::writing{variant=\"document\" id=\"1\"} and the closing :::. The inner text is kept."},
		func(o *Options) bool { return o.RemoveModelArtifacts }, func(c *ChangeStats) *int { return &c.RemovedModelArtifacts }},
	{RuleInfo{RuleFootnoteBacklink, CategoryArtifact, ActionRemove, false, "",
		"Footnote back-link arrows (\u21A9, optionally followed by VS15) left over from rendered Markdown. Enable via Options.Rules."},
		func(o *Options) bool { return false }, func(c *ChangeStats) *int { return &c.RemovedModelArtifacts }},
	{RuleInfo{RuleSourcePill, CategoryArtifact, ActionDetect, true, "",
		"ChatGPT source \"pills\" pasted as text (e.g. \"Wikipedia+1\"). Detect only."},
		always, nil},
	{RuleInfo{RuleTrackingParam, CategoryArtifact, ActionRemove, true, "RemoveTrackingParams",
		"AI referral parameters in URLs: utm_source=chatgpt.com/openai/copilot.com/perplexity/claude.ai/gemini, referrer=grok.com."},
		func(o *Options) bool { return o.RemoveTrackingParams }, func(c *ChangeStats) *int { return &c.RemovedTrackingParams }},
	{RuleInfo{RuleChatBoilerplate, CategoryArtifact, ActionRemove, false, "RemoveChatBoilerplate",
		"Chat boilerplate: a leading \"Sure! Here's \u2026:\" line, trailing \"I hope this helps\"-style sign-offs, \"As an AI language model,\" and knowledge-cutoff preambles."},
		func(o *Options) bool { return o.RemoveChatBoilerplate }, func(c *ChangeStats) *int { return &c.RemovedBoilerplate }},

	// Typography.
	{RuleInfo{RuleSmartQuote, CategoryTypography, ActionReplace, false, "NormalizeSmartQuotes",
		"Curly quotes, guillemets, primes-as-apostrophes and fullwidth quotes become ' and \"."},
		func(o *Options) bool { return o.NormalizeSmartQuotes }, func(c *ChangeStats) *int { return &c.NormalizedSmartQuotes }},
	{RuleInfo{RuleDash, CategoryTypography, ActionReplace, false, "DashStyle",
		"Dashes and minus signs are rewritten according to DashStyle (hyphen, ascii or comma)."},
		func(o *Options) bool { return o.dashStyle() != DashKeep }, func(c *ChangeStats) *int { return &c.NormalizedDashes }},
	{RuleInfo{RuleEllipsis, CategoryTypography, ActionReplace, false, "NormalizeEllipsis",
		"Horizontal ellipsis (U+2026) becomes \"...\"."},
		func(o *Options) bool { return o.NormalizeEllipsis }, func(c *ChangeStats) *int { return &c.NormalizedEllipsis }},
	{RuleInfo{RulePunctuation, CategoryTypography, ActionReplace, false, "NormalizePunctuation",
		"Bullets, arrows and math symbols become ASCII (\u2022 \u2192 -, \u2192 \u2192 ->, \u2264 \u2192 <=, \u00D7 \u2192 x, \u2026)."},
		func(o *Options) bool { return o.NormalizePunctuation }, func(c *ChangeStats) *int { return &c.NormalizedPunctuation }},
	{RuleInfo{RuleCompatFold, CategoryTypography, ActionReplace, false, "FoldCompatibility",
		"Compatibility characters fold to their plain form: ligatures (\uFB01 \u2192 fi), fullwidth (\uFF21 \u2192 A), math alphanumerics (\U0001D400 \u2192 A), superscripts, circled/parenthesized numbers, fractions."},
		func(o *Options) bool { return o.FoldCompatibility || o.Nfkc }, func(c *ChangeStats) *int { return &c.FoldedCompatibility }},
	{RuleInfo{RuleMarkdown, CategoryTypography, ActionReplace, false, "StripMarkdown",
		"Markdown leftovers in plain text: **bold**, headings, horizontal rules, [links](url), images, blockquotes, bullet styles."},
		func(o *Options) bool { return o.StripMarkdown }, func(c *ChangeStats) *int { return &c.StrippedMarkdown }},

	// Homoglyphs.
	{RuleInfo{RuleConfusable, CategoryHomoglyph, ActionReplace, false, "FoldConfusables",
		"Folds Cyrillic/Greek/Armenian/Cherokee look-alike letters to Latin inside mixed-script words (e.g. Cyrillic \u0430 in \"p\u0430ypal\")."},
		func(o *Options) bool { return o.FoldConfusables }, func(c *ChangeStats) *int { return &c.FoldedConfusables }},
	{RuleInfo{RuleMixedScript, CategoryHomoglyph, ActionDetect, true, "",
		"Words mixing Latin with look-alike letters from other scripts, and look-alike-only words in Latin text. Detect only."},
		always, nil},

	// Steganography (detect only).
	{RuleInfo{RuleTagPayload, CategorySteganography, ActionDetect, true, "",
		"Decodes text hidden in Unicode tag characters (\"ASCII smuggling\")."},
		always, nil},
	{RuleInfo{RuleVariationSelectorStego, CategorySteganography, ActionDetect, true, "",
		"Decodes bytes hidden in runs of variation selectors (\"emoji smuggling\")."},
		always, nil},
	{RuleInfo{RuleInvisibleMathStego, CategorySteganography, ActionDetect, true, "",
		"Decodes binary payloads encoded with invisible math operators (\"Sneaky Bits\")."},
		always, nil},
	{RuleInfo{RuleZeroWidthStego, CategorySteganography, ActionDetect, true, "",
		"Long runs of zero-width characters, decoded as binary when possible."},
		always, nil},
	{RuleInfo{RuleTrailingWhitespaceStego, CategorySteganography, ActionDetect, true, "",
		"Trailing space/tab patterns at line ends (SNOW-style whitespace steganography). Remove with CollapseWhitespace."},
		always, nil},
}

var (
	ruleIndex = func() map[RuleID]ruleIdx {
		m := make(map[RuleID]ruleIdx, len(registry))
		for i, r := range registry {
			m[r.ID] = ruleIdx(i)
		}
		return m
	}()
	numRules = func() int {
		if len(registry) > maxRules {
			panic("aisanitizer: raise maxRules")
		}
		return len(registry)
	}()

	// Hot-path indices.
	iZeroWidth          = ruleIndex[RuleZeroWidth]
	iBidi               = ruleIndex[RuleBidi]
	iInvisibleMath      = ruleIndex[RuleInvisibleMath]
	iVariationSelector  = ruleIndex[RuleVariationSelector]
	iTagChar            = ruleIndex[RuleTagChar]
	iFormatChar         = ruleIndex[RuleFormatChar]
	iBrailleBlank       = ruleIndex[RuleBrailleBlank]
	iNoncharacter       = ruleIndex[RuleNoncharacter]
	iPrivateUse         = ruleIndex[RulePrivateUse]
	iControl            = ruleIndex[RuleControl]
	iANSIEscape         = ruleIndex[RuleANSIEscape]
	iHTMLEntity         = ruleIndex[RuleHTMLEntity]
	iInvalidUTF8        = ruleIndex[RuleInvalidUTF8]
	iReplacementChar    = ruleIndex[RuleReplacementChar]
	iExoticSpace        = ruleIndex[RuleExoticSpace]
	iLineSeparator      = ruleIndex[RuleLineSeparator]
	iCollapseWhitespace = ruleIndex[RuleCollapseWhitespace]
	iTrim               = ruleIndex[RuleTrim]
	iSmartQuote         = ruleIndex[RuleSmartQuote]
	iDash               = ruleIndex[RuleDash]
	iEllipsis           = ruleIndex[RuleEllipsis]
	iPunctuation        = ruleIndex[RulePunctuation]
	iCompatFold         = ruleIndex[RuleCompatFold]
	iMarkdown           = ruleIndex[RuleMarkdown]
	iConfusable         = ruleIndex[RuleConfusable]
	iMixedScript        = ruleIndex[RuleMixedScript]
	iTrackingParam      = ruleIndex[RuleTrackingParam]
	iChatBoilerplate    = ruleIndex[RuleChatBoilerplate]
)

// Rules returns information about every registered rule, in pipeline order.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(registry))
	for i, r := range registry {
		out[i] = r.RuleInfo
	}
	return out
}

// LookupRule returns the RuleInfo for id.
func LookupRule(id RuleID) (RuleInfo, bool) {
	i, ok := ruleIndex[id]
	if !ok {
		return RuleInfo{}, false
	}
	return registry[i].RuleInfo, true
}
