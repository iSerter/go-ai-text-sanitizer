package aisanitizer

import (
	"fmt"
	"sort"
	"strings"
)

// Options controls which rules run. Start from Defaults() or Preset() rather
// than a zero Options value: the zero value disables every rule.
//
// Every boolean switch maps onto one or more rules (see Rules()). Individual
// rules can additionally be forced on or off through Rules, which takes
// precedence over the switches.
type Options struct {
	// Invisible characters.
	RemoveZeroWidth          bool
	RemoveBidi               bool
	RemoveInvisibleMath      bool
	RemoveVariationSelectors bool
	RemoveTagChars           bool
	RemoveFormatChars        bool
	RemoveBrailleBlank       bool
	RemoveNoncharacters      bool
	RemovePrivateUse         bool
	StripControl             bool
	DecodeInvisibleEntities  bool

	// Visible LLM artifacts.
	RemoveCitations        bool
	RemoveNumericCitations bool
	RemoveModelArtifacts   bool
	RemoveTrackingParams   bool
	RemoveChatBoilerplate  bool

	// Whitespace.
	NormalizeSpaces         bool
	NormalizeLineSeparators bool
	CollapseWhitespace      bool
	// MaxBlankLines limits consecutive blank lines when CollapseWhitespace is
	// on. Zero means 1 (paragraph breaks are preserved); negative means no
	// limit.
	MaxBlankLines int
	Trim          bool

	// Typography and formatting.
	NormalizeSmartQuotes bool
	DashStyle            DashStyle
	NormalizeEllipsis    bool
	NormalizePunctuation bool
	FoldCompatibility    bool
	FoldConfusables      bool
	StripMarkdown        bool

	// Preservation of legitimate uses of otherwise-removed characters.
	KeepEmoji            bool // ZWJ, VS15/VS16, keycaps and tag flags inside emoji sequences
	KeepScriptFormatting bool // ZWJ/ZWNJ in Indic/Arabic-script words, Mongolian selectors, Hangul fillers in jamo, registered variation sequences
	KeepTabs             bool // when false (and the control rule is on), TAB becomes a space
	KeepNewlines         bool // when false (and the control rule is on), line breaks and U+2028/U+2029/NEL become spaces
	KeepFrenchSpacing    bool // narrow/no-break spaces before ;:!?» and between digits
	BidiMode             BidiMode

	// InvalidUTF8 selects how invalid UTF-8 input bytes are handled.
	InvalidUTF8 InvalidUTF8Policy

	// MaxPositions, when positive, records up to that many positions
	// (offset/line/column) per finding.
	MaxPositions int

	// Rules forces individual rules on (true) or off (false), overriding the
	// switches above.
	Rules map[RuleID]bool

	// ExtraDetectors run in addition to the built-in rules in Detect.
	ExtraDetectors []Detector

	// Deprecated: use DashStyle. NormalizeDashes=true is equivalent to
	// DashStyle=DashHyphen when DashStyle is DashKeep.
	NormalizeDashes bool
	// Deprecated: use FoldCompatibility. The previous implementation was not
	// real NFKC; Nfkc=true now enables FoldCompatibility.
	Nfkc bool
	// Deprecated: use BidiMode=BidiKeep.
	KeepBidi bool
}

// DashStyle selects how dashes are normalized.
type DashStyle int

const (
	// DashKeep leaves dashes untouched.
	DashKeep DashStyle = iota
	// DashHyphen turns every dash and minus sign into "-".
	DashHyphen
	// DashASCII turns em dashes and horizontal bars into "--" and every
	// other dash into "-".
	DashASCII
	// DashComma rewrites parenthetical em dashes as commas (and drops them
	// before punctuation), keeps numeric ranges as "1-2", and turns hyphen
	// variants into "-".
	DashComma
)

// BidiMode selects how bidirectional control characters are handled when
// RemoveBidi is on.
type BidiMode int

const (
	// BidiAuto removes embeddings, overrides and isolates (Trojan Source
	// vectors) everywhere, and removes LRM/RLM/ALM marks only when the text
	// contains no right-to-left letters.
	BidiAuto BidiMode = iota
	// BidiRemove removes every bidi control character.
	BidiRemove
	// BidiKeep keeps every bidi control character.
	BidiKeep
)

// InvalidUTF8Policy selects how invalid UTF-8 is handled.
type InvalidUTF8Policy int

const (
	// InvalidUTF8Replace replaces each invalid byte with U+FFFD.
	InvalidUTF8Replace InvalidUTF8Policy = iota
	// InvalidUTF8Drop removes invalid bytes.
	InvalidUTF8Drop
)

// Defaults returns options that remove invisible characters and model
// artifacts without changing visible typography.
func Defaults() *Options {
	return &Options{
		RemoveZeroWidth:          true,
		RemoveBidi:               true,
		RemoveInvisibleMath:      true,
		RemoveVariationSelectors: true,
		RemoveTagChars:           true,
		RemoveFormatChars:        true,
		RemoveBrailleBlank:       true,
		RemoveNoncharacters:      true,
		StripControl:             true,
		DecodeInvisibleEntities:  true,
		RemoveCitations:          true,
		RemoveModelArtifacts:     true,
		RemoveTrackingParams:     true,
		NormalizeSpaces:          true,
		NormalizeLineSeparators:  true,
		KeepEmoji:                true,
		KeepScriptFormatting:     true,
		KeepTabs:                 true,
		KeepNewlines:             true,
	}
}

// Preset names accepted by Preset.
const (
	// PresetSafe removes invisible characters and model artifacts only;
	// spaces are not normalized.
	PresetSafe = "safe"
	// PresetDefault is Defaults().
	PresetDefault = "default"
	// PresetPlain additionally converts typography to plain ASCII-style text
	// and strips Markdown.
	PresetPlain = "plain"
	// PresetParanoid enables everything, including private-use removal,
	// confusable folding and chat boilerplate removal.
	PresetParanoid = "paranoid"
)

// PresetNames lists the presets accepted by Preset.
func PresetNames() []string {
	return []string{PresetSafe, PresetDefault, PresetPlain, PresetParanoid}
}

// Preset returns the options for a named preset.
func Preset(name string) (*Options, error) {
	o := Defaults()
	switch strings.ToLower(name) {
	case PresetSafe:
		o.NormalizeSpaces = false
	case PresetDefault, "":
	case PresetParanoid:
		o.RemovePrivateUse = true
		o.FoldConfusables = true
		o.RemoveChatBoilerplate = true
		o.BidiMode = BidiRemove
		fallthrough
	case PresetPlain:
		o.NormalizeSmartQuotes = true
		o.DashStyle = DashHyphen
		o.NormalizeEllipsis = true
		o.NormalizePunctuation = true
		o.FoldCompatibility = true
		o.StripMarkdown = true
		o.CollapseWhitespace = true
		o.Trim = true
	default:
		return nil, fmt.Errorf("aisanitizer: unknown preset %q (want one of %s)", name, strings.Join(PresetNames(), ", "))
	}
	return o, nil
}

// SetRule forces a rule on or off. It returns an error for unknown rule IDs.
func (o *Options) SetRule(id RuleID, enabled bool) error {
	if _, ok := ruleIndex[id]; !ok {
		return fmt.Errorf("aisanitizer: unknown rule %q", id)
	}
	if o.Rules == nil {
		o.Rules = make(map[RuleID]bool)
	}
	o.Rules[id] = enabled
	return nil
}

// Enabled reports whether the rule is on for these options.
func (o *Options) Enabled(id RuleID) bool {
	i, ok := ruleIndex[id]
	if !ok {
		return false
	}
	return o.enabled(i)
}

// EnabledRules returns the IDs of all rules that are on, sorted.
func (o *Options) EnabledRules() []RuleID {
	var out []RuleID
	for i := range registry {
		if o.enabled(ruleIdx(i)) {
			out = append(out, registry[i].ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Clone returns a deep copy of o.
func (o *Options) Clone() *Options {
	c := *o
	if o.Rules != nil {
		c.Rules = make(map[RuleID]bool, len(o.Rules))
		for k, v := range o.Rules {
			c.Rules[k] = v
		}
	}
	c.ExtraDetectors = append([]Detector(nil), o.ExtraDetectors...)
	return &c
}

func (o *Options) enabled(i ruleIdx) bool {
	if v, ok := o.Rules[registry[i].ID]; ok {
		return v
	}
	return registry[i].enabled(o)
}

func (o *Options) dashStyle() DashStyle {
	if o.DashStyle == DashKeep && o.NormalizeDashes {
		return DashHyphen
	}
	return o.DashStyle
}

func (o *Options) bidiMode() BidiMode {
	if o.KeepBidi {
		return BidiKeep
	}
	return o.BidiMode
}

func (o *Options) maxBlankLines() int {
	switch {
	case o.MaxBlankLines == 0:
		return 1
	case o.MaxBlankLines < 0:
		return -1
	}
	return o.MaxBlankLines
}
