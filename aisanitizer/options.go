package aisanitizer

type Options struct {
	RemoveZeroWidth           bool
	RemoveBidi                bool
	RemoveInvisibleMath       bool
	RemoveVariationSelectors  bool
	RemoveTagChars            bool
	RemoveFormatChars         bool
	RemoveBrailleBlank        bool
	StripControl              bool
	RemoveCitations           bool
	RemoveModelArtifacts      bool
	NormalizeSpaces           bool
	NormalizeLineSeparators   bool
	NormalizeSmartQuotes      bool
	NormalizeDashes           bool
	NormalizeEllipsis         bool
	CollapseWhitespace        bool
	Trim                      bool
	KeepEmoji                 bool
	KeepBidi                  bool
	KeepTabs                  bool
	KeepNewlines              bool
	Nfkc                      bool
}

type RewriteStrategy int

const (
	RewriteNone       RewriteStrategy = iota
	RewriteLight
	RewriteAggressive
)

func Defaults() *Options {
	return &Options{
		RemoveZeroWidth:          true,
		RemoveBidi:               true,
		RemoveInvisibleMath:      true,
		RemoveVariationSelectors: true,
		RemoveTagChars:           true,
		RemoveFormatChars:        true,
		RemoveBrailleBlank:       true,
		StripControl:             true,
		RemoveCitations:          true,
		RemoveModelArtifacts:     true,
		NormalizeSpaces:          true,
		NormalizeLineSeparators:  true,
		NormalizeSmartQuotes:     false,
		NormalizeDashes:          false,
		NormalizeEllipsis:        false,
		CollapseWhitespace:       false,
		Trim:                     false,
		KeepEmoji:                true,
		KeepBidi:                 false,
		KeepTabs:                 true,
		KeepNewlines:             true,
		Nfkc:                     false,
	}
}
