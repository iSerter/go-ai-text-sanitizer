package aisanitizer

import (
	"fmt"
	"sort"
	"strings"
)

// ChangeStats counts the changes made by each group of rules.
type ChangeStats struct {
	RemovedZeroWidth          int `json:"removed_zero_width"`
	RemovedBidi               int `json:"removed_bidi"`
	RemovedInvisibleMath      int `json:"removed_invisible_math"`
	RemovedVariationSelectors int `json:"removed_variation_selectors"`
	RemovedTagChars           int `json:"removed_tag_chars"`
	RemovedFormatChars        int `json:"removed_format_chars"`
	RemovedBrailleBlank       int `json:"removed_braille_blank"`
	RemovedNoncharacters      int `json:"removed_noncharacters"`
	RemovedPrivateUse         int `json:"removed_private_use"`
	RemovedControl            int `json:"removed_control"`
	RemovedANSIEscapes        int `json:"removed_ansi_escapes"`
	RemovedHTMLEntities       int `json:"removed_html_entities"`
	RemovedCitations          int `json:"removed_citations"`
	RemovedModelArtifacts     int `json:"removed_model_artifacts"`
	RemovedTrackingParams     int `json:"removed_tracking_params"`
	RemovedBoilerplate        int `json:"removed_boilerplate"`
	StrippedMarkdown          int `json:"stripped_markdown"`
	NormalizedSpaces          int `json:"normalized_spaces"`
	NormalizedLineSeparators  int `json:"normalized_line_separators"`
	NormalizedSmartQuotes     int `json:"normalized_smart_quotes"`
	NormalizedDashes          int `json:"normalized_dashes"`
	NormalizedEllipsis        int `json:"normalized_ellipsis"`
	NormalizedPunctuation     int `json:"normalized_punctuation"`
	FoldedCompatibility       int `json:"folded_compatibility"`
	FoldedConfusables         int `json:"folded_confusables"`
	CollapsedSpaces           int `json:"collapsed_spaces"`
	TrimmedWhitespace         int `json:"trimmed_whitespace"`
	ReplacedInvalidUTF8       int `json:"replaced_invalid_utf8"`
	// Deprecated: rewriting was removed; always zero.
	RewrittenSegments int `json:"rewritten_segments,omitempty"`
	Total             int `json:"total"`
}

// Position locates one occurrence of a finding in the original input.
type Position struct {
	Offset int `json:"offset"` // byte offset
	Line   int `json:"line"`   // 1-based
	Column int `json:"column"` // 1-based, in runes
}

// Finding describes one kind of character or pattern a rule matched,
// aggregated over all its occurrences.
type Finding struct {
	Rule     RuleID `json:"rule"`
	Category string `json:"category"`
	Action   Action `json:"action"`
	Name     string `json:"name"`
	// Notation is "U+XXXX" for character findings and a (truncated) sample
	// of the matched text for pattern findings.
	Notation  string `json:"notation"`
	CodePoint rune   `json:"code_point,omitempty"`
	// Index is the byte offset of the first occurrence in the original input.
	Index int `json:"index"`
	Count int `json:"count"`
	// Payload holds decoded hidden content for steganography findings.
	Payload   string     `json:"payload,omitempty"`
	Positions []Position `json:"positions,omitempty"`
}

// String formats the finding as "U+200B ZERO WIDTH SPACE [zero_width] x2".
func (f *Finding) String() string {
	s := fmt.Sprintf("%s %s [%s] x%d", f.Notation, f.Name, f.Rule, f.Count)
	if f.Payload != "" {
		s += fmt.Sprintf(" payload=%q", f.Payload)
	}
	return s
}

// Risk summarizes how suspicious the findings are.
type Risk string

const (
	RiskNone Risk = "none"
	// RiskLow means invisible characters, artifacts or typography were found.
	RiskLow Risk = "low"
	// RiskHigh means a decodable hidden payload, bidi overrides, tag
	// characters or homoglyph words were found.
	RiskHigh Risk = "high"
)

// Report describes what Sanitize changed or what Detect found.
type Report struct {
	Modified bool        `json:"modified"`
	Risk     Risk        `json:"risk"`
	Changes  ChangeStats `json:"changes"`
	Findings []Finding   `json:"findings,omitempty"`
}

// WasModified reports whether the text was changed.
func (r *Report) WasModified() bool { return r.Modified }

// HasFindings reports whether any rule matched.
func (r *Report) HasFindings() bool { return len(r.Findings) > 0 }

// HasWatermarks reports whether any invisible character, model artifact,
// homoglyph or steganographic payload was found. Typography, whitespace and
// encoding findings do not count.
func (r *Report) HasWatermarks() bool {
	for _, f := range r.Findings {
		switch f.Category {
		case CategoryInvisible, CategoryArtifact, CategoryHomoglyph, CategorySteganography:
			return true
		}
	}
	return false
}

// Count returns the total number of occurrences found for a rule.
func (r *Report) Count(id RuleID) int {
	n := 0
	for _, f := range r.Findings {
		if f.Rule == id {
			n += f.Count
		}
	}
	return n
}

// Summary returns a one-line summary.
func (r *Report) Summary() string {
	if !r.Modified && !r.HasFindings() {
		return "No changes made."
	}
	return fmt.Sprintf("Modified: %v, Changes: %d, Findings: %d, Risk: %s",
		r.Modified, r.Changes.Total, len(r.Findings), r.Risk)
}

// String returns a human-readable multi-line report.
func (r *Report) String() string {
	var b strings.Builder
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	for i := range r.Findings {
		f := &r.Findings[i]
		fmt.Fprintf(&b, "  %-8s %s", f.Action, f.String())
		if len(f.Positions) > 0 {
			b.WriteString(" at")
			for _, p := range f.Positions {
				fmt.Fprintf(&b, " %d:%d", p.Line, p.Column)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Merge adds other's changes and findings to r (e.g. when processing several
// files). Finding indexes and positions stay relative to their own inputs.
func (r *Report) Merge(other *Report) {
	if other == nil {
		return
	}
	r.Modified = r.Modified || other.Modified
	r.Risk = maxRisk(r.Risk, other.Risk)
	a, b := statFields(&r.Changes), statFields(&other.Changes)
	for i := range a {
		*a[i] += *b[i]
	}
	r.Findings = append(r.Findings, other.Findings...)
}

func statFields(c *ChangeStats) []*int {
	return []*int{
		&c.RemovedZeroWidth, &c.RemovedBidi, &c.RemovedInvisibleMath, &c.RemovedVariationSelectors,
		&c.RemovedTagChars, &c.RemovedFormatChars, &c.RemovedBrailleBlank, &c.RemovedNoncharacters,
		&c.RemovedPrivateUse, &c.RemovedControl, &c.RemovedANSIEscapes, &c.RemovedHTMLEntities,
		&c.RemovedCitations, &c.RemovedModelArtifacts, &c.RemovedTrackingParams, &c.RemovedBoilerplate,
		&c.StrippedMarkdown, &c.NormalizedSpaces, &c.NormalizedLineSeparators, &c.NormalizedSmartQuotes,
		&c.NormalizedDashes, &c.NormalizedEllipsis, &c.NormalizedPunctuation, &c.FoldedCompatibility,
		&c.FoldedConfusables, &c.CollapsedSpaces, &c.TrimmedWhitespace, &c.ReplacedInvalidUTF8,
		&c.RewrittenSegments, &c.Total,
	}
}

func maxRisk(a, b Risk) Risk {
	rank := func(r Risk) int {
		switch r {
		case RiskHigh:
			return 2
		case RiskLow:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	if a == "" {
		return RiskNone
	}
	return a
}

// findingKey aggregates occurrences of the same rule and character/pattern.
type findingKey struct {
	rule ruleIdx
	cp   rune
	name string
}

type findingAgg struct {
	f       *Finding
	offsets []int
}

// collector accumulates findings and per-rule change counts.
type collector struct {
	maxPositions int
	counts       [maxRules]int
	order        []findingKey
	byKey        map[findingKey]*findingAgg
}

// add records n occurrences (n > 0) at original byte offset off. Findings
// with the same rule, code point and name are aggregated.
func (c *collector) add(i ruleIdx, cp rune, name, notation string, off, n int, action Action) *Finding {
	return c.addKeyed(i, cp, name, name, notation, off, n, action)
}

// addKeyed is add with an explicit aggregation key.
func (c *collector) addKeyed(i ruleIdx, cp rune, key, name, notation string, off, n int, action Action) *Finding {
	if c.byKey == nil {
		c.byKey = make(map[findingKey]*findingAgg)
	}
	if action != ActionDetect {
		c.counts[i] += n
	}
	k := findingKey{i, cp, key}
	a := c.byKey[k]
	if a == nil {
		def := &registry[i]
		a = &findingAgg{f: &Finding{
			Rule: def.ID, Category: def.Category, Action: action,
			Name: name, Notation: notation, CodePoint: cp, Index: off,
		}}
		c.byKey[k] = a
		c.order = append(c.order, k)
	}
	a.f.Count += n
	if len(a.offsets) < c.maxPositions {
		a.offsets = append(a.offsets, off)
	}
	return a.f
}

// addRune records a character finding.
func (c *collector) addRune(i ruleIdx, r rune, off int, action Action) {
	if a := c.byKey[findingKey{i, r, ""}]; a != nil {
		// Fast path: avoid formatting the name and notation again.
		if action != ActionDetect {
			c.counts[i]++
		}
		a.f.Count++
		if len(a.offsets) < c.maxPositions {
			a.offsets = append(a.offsets, off)
		}
		return
	}
	c.addKeyed(i, r, "", runeName(r), runeNotation(r), off, 1, action)
}

func (c *collector) build(src string, report *Report) {
	for i, n := range c.counts {
		if n == 0 {
			continue
		}
		if st := registry[i].stat; st != nil {
			*st(&report.Changes) += n
			report.Changes.Total += n
		}
	}
	if len(c.order) == 0 {
		return
	}
	var allOffsets []int
	report.Findings = make([]Finding, 0, len(c.order))
	for _, k := range c.order {
		a := c.byKey[k]
		report.Findings = append(report.Findings, *a.f)
		allOffsets = append(allOffsets, a.offsets...)
	}
	if len(allOffsets) > 0 {
		pos := lineColumns(src, allOffsets)
		for idx, k := range c.order {
			a := c.byKey[k]
			if len(a.offsets) == 0 {
				continue
			}
			ps := make([]Position, len(a.offsets))
			for x, off := range a.offsets {
				ps[x] = pos[off]
			}
			report.Findings[idx].Positions = ps
		}
	}
	sortFindings(report.Findings)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Index != fs[j].Index {
			return fs[i].Index < fs[j].Index
		}
		if fs[i].Rule != fs[j].Rule {
			return fs[i].Rule < fs[j].Rule
		}
		return fs[i].CodePoint < fs[j].CodePoint
	})
}

// lineColumns maps byte offsets to line/column positions in one pass.
func lineColumns(src string, offsets []int) map[int]Position {
	sorted := append([]int(nil), offsets...)
	sort.Ints(sorted)
	out := make(map[int]Position, len(sorted))
	line, col, k := 1, 1, 0
	for i, r := range src {
		for k < len(sorted) && sorted[k] <= i {
			out[sorted[k]] = Position{Offset: sorted[k], Line: line, Column: col}
			k++
		}
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	for ; k < len(sorted); k++ {
		out[sorted[k]] = Position{Offset: sorted[k], Line: line, Column: col}
	}
	return out
}
