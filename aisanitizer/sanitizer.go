package aisanitizer

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Sanitize cleans text according to opts (Defaults() when nil) and returns
// the result with a report of every change. Unchanged input is returned
// without copying. The result is always valid UTF-8.
func Sanitize(text string, opts *Options) (string, *Report) {
	if opts == nil {
		opts = Defaults()
	}
	p := newPipeline(text, opts, false)
	out := p.run()
	if p.sawTags || p.sawVS || p.sawMath || p.sawZW {
		p.analyzeStego()
	}
	report := &Report{Modified: out != text}
	p.col.build(text, report)
	report.Risk = assessRisk(report.Findings)
	return out, report
}

// CleanText sanitizes text with Defaults().
func CleanText(text string) (string, *Report) {
	return Sanitize(text, Defaults())
}

// SanitizeBytes is Sanitize for byte slices.
func SanitizeBytes(b []byte, opts *Options) ([]byte, *Report) {
	out, report := Sanitize(string(b), opts)
	return []byte(out), report
}

// SanitizeReader reads all of r, sanitizes it and writes the result to w.
// The whole input is buffered in memory.
func SanitizeReader(r io.Reader, w io.Writer, opts *Options) (*Report, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out, report := Sanitize(string(data), opts)
	if _, err := io.WriteString(w, out); err != nil {
		return report, err
	}
	return report, nil
}

// Detect reports what Sanitize would change, plus detect-only findings
// (steganographic payloads, homoglyph words, private-use and replacement
// characters, source pills), without modifying text. Report.Changes is
// always zero and Report.Modified is always false.
func Detect(text string, opts *Options) (*Report, error) {
	if opts == nil {
		opts = Defaults()
	}
	p := newPipeline(text, opts, true)
	p.run()
	p.analyzeStego()
	if p.en[ruleIndex[RuleTrailingWhitespaceStego]] {
		p.analyzeTrailingWhitespace()
	}
	report := &Report{}
	p.col.build(text, report)
	report.Changes = ChangeStats{}

	var errs []error
	for _, d := range opts.ExtraDetectors {
		fs, err := d.Detect(text)
		if err != nil {
			errs = append(errs, fmt.Errorf("detector %s: %w", d.Name(), err))
			continue
		}
		for _, f := range fs {
			if f.Rule == "" {
				f.Rule = RuleID(d.Name())
			}
			if f.Action == "" {
				f.Action = ActionDetect
			}
			report.Findings = append(report.Findings, f)
		}
	}
	sortFindings(report.Findings)
	report.Risk = assessRisk(report.Findings)
	return report, errors.Join(errs...)
}

// InvalidUTF8Error reports the first invalid UTF-8 byte in an input.
type InvalidUTF8Error struct {
	Offset int
	Byte   byte
}

func (e *InvalidUTF8Error) Error() string {
	return fmt.Sprintf("invalid UTF-8 byte 0x%02X at offset %d", e.Byte, e.Offset)
}

// CheckUTF8 returns an *InvalidUTF8Error if text is not valid UTF-8.
func CheckUTF8(text string) error {
	if utf8.ValidString(text) {
		return nil
	}
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			return &InvalidUTF8Error{Offset: i, Byte: text[i]}
		}
		i += size
	}
	return nil
}

// pipeline runs the sanitization stages in order. Each stage rewrites the
// previous stage's output; offset maps translate finding positions back to
// the original input.
type pipeline struct {
	opts   *Options
	en     [maxRules]bool
	detect bool
	src    string
	maps   []*offsetMap
	col    collector
	w      rewriter
	iter   int // current pass of the post-character stages

	mapsBuf [16]*offsetMap

	sawTags, sawVS, sawMath, sawZW bool
}

func newPipeline(src string, opts *Options, detect bool) *pipeline {
	p := &pipeline{opts: opts, detect: detect, src: src}
	p.col.maxPositions = opts.MaxPositions
	p.maps = p.mapsBuf[:0]
	for i := range registry {
		p.en[i] = opts.enabled(ruleIdx(i))
	}
	return p
}

func (p *pipeline) run() string {
	t := p.stage(p.src, p.charStage)
	// Removing characters can assemble a new HTML entity ("&\x1b#0;" ->
	// "&#0;", "&ZeroWidth\aSpace;"); repeat the character stage until the
	// text is stable.
	for n := 0; n < 3 && p.en[iHTMLEntity] && p.maps[len(p.maps)-1] != nil && strings.Contains(t, "&"); n++ {
		t = p.stage(t, p.charStage)
	}
	// Removing an artifact or Markdown marker can expose another one
	// ("# # x", nested citations), so the remaining stages repeat until a
	// pass changes nothing. Unchanged input costs a single pass.
	for p.iter = 0; p.iter < maxPasses; p.iter++ {
		first := len(p.maps)
		t = p.postStages(t)
		changed := false
		for _, m := range p.maps[first:] {
			changed = changed || m != nil
		}
		if !changed {
			break
		}
	}
	return t
}

// maxPasses bounds the fixpoint loop in run.
const maxPasses = 8

func (p *pipeline) postStages(t string) string {
	if p.anyEnabled(artifactRuleIdx) || p.detect {
		t = p.stage(t, p.artifactStage)
	}
	if p.en[iChatBoilerplate] {
		t = p.stage(t, p.boilerplateStage)
	}
	if p.en[iMarkdown] {
		for _, m := range markdownRules {
			t = p.stage(t, m.apply(p))
		}
	}
	if p.en[iDash] && p.opts.dashStyle() == DashComma {
		t = p.stage(t, p.dashCommaStage)
	}
	if p.en[iSmartQuote] || p.en[iDash] || p.en[iEllipsis] || p.en[iPunctuation] || p.en[iCompatFold] {
		t = p.stage(t, p.typographyStage)
	}
	if p.en[iConfusable] || (p.detect && p.en[iMixedScript]) {
		t = p.stage(t, p.confusableStage)
	}
	if p.en[iCollapseWhitespace] {
		t = p.stage(t, p.collapseStage)
	}
	if p.en[iTrim] {
		t = p.stage(t, p.trimStage)
	}
	return t
}

func (p *pipeline) stage(t string, fn func(string, *rewriter)) string {
	w := &p.w
	*w = rewriter{src: t}
	fn(t, w)
	out := w.String() // finalizes the offset map
	p.maps = append(p.maps, w.offsetMap())
	return out
}

func (p *pipeline) anyEnabled(idx []ruleIdx) bool {
	for _, i := range idx {
		if p.en[i] {
			return true
		}
	}
	return false
}

// origin maps an offset in the current stage's input to the original input.
func (p *pipeline) origin(off int) int {
	for j := len(p.maps) - 1; j >= 0; j-- {
		off = p.maps[j].toSource(off)
	}
	return off
}

func (p *pipeline) action(i ruleIdx, a Action) Action {
	if registry[i].Action == ActionDetect {
		return ActionDetect
	}
	return a
}

// add records a finding at an offset in the current stage's input.
func (p *pipeline) add(i ruleIdx, cp rune, name, notation string, off, n int, a Action) *Finding {
	return p.col.add(i, cp, name, notation, p.origin(off), n, p.action(i, a))
}

func (p *pipeline) addRune(i ruleIdx, r rune, off int, a Action) {
	p.col.addRune(i, r, p.origin(off), p.action(i, a))
}

func assessRisk(fs []Finding) Risk {
	if len(fs) == 0 {
		return RiskNone
	}
	for _, f := range fs {
		switch {
		case f.Category == CategorySteganography && f.Rule != RuleTrailingWhitespaceStego,
			f.Category == CategoryHomoglyph,
			f.Rule == RuleTagChar,
			f.Rule == RuleBidi && isBidiOverride(f.CodePoint):
			return RiskHigh
		}
	}
	return RiskLow
}

func isBidiOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// Deprecated: rewriting was removed because it changed meaning and added
// typographic AI footprints. RewriteStrategy values are ignored.
type RewriteStrategy int

// Deprecated: see RewriteStrategy.
const (
	RewriteNone RewriteStrategy = iota
	RewriteLight
	RewriteAggressive
)

// Deprecated: use Sanitize. The strategy is ignored and no rewriting is
// performed; this function will be removed in a future release.
func SanitizeWithRewrite(text string, opts *Options, strategy RewriteStrategy) (string, *Report, error) {
	out, report := Sanitize(text, opts)
	return out, report, nil
}
