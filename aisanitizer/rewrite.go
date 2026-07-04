package aisanitizer

import (
	"math/rand"
	"strings"
)

var lightReplacements = [][2]string{
	{"...", " …"},
	{"...", "…"},
	{"\"", "\u201C"},
	{"\"", "\u201D"},
}

var aggressiveSynonyms = [][2]string{
	{" therefore ", " hence "},
	{" therefore ", " thus "},
	{" however ", " nevertheless "},
	{" however ", " nonetheless "},
	{" also ", " furthermore "},
	{" also ", " moreover "},
	{" very ", " extremely "},
	{" very ", " particularly "},
	{" important ", " significant "},
	{" important ", " crucial "},
	{" use ", " utilize "},
	{" use ", " employ "},
	{" show ", " demonstrate "},
	{" show ", " indicate "},
	{" make ", " create "},
	{" make ", " produce "},
	{" change ", " modify "},
	{" change ", " alter "},
	{" help ", " assist "},
	{" help ", " aid "},
}

func rewriteLight(s string, rng *rand.Rand) (string, int) {
	count := 0
	result := s

	if rng.Intn(2) == 0 {
		result = strings.ReplaceAll(result, "\u201C", "\"")
		result = strings.ReplaceAll(result, "\u201D", "\"")
		count++
	} else {
		result = strings.ReplaceAll(result, "\"", "\u201C")
		count++
	}

	periodPos := strings.LastIndex(result, ". ")
	if periodPos > 0 && rng.Intn(2) == 0 {
		first := result[periodPos+2:]
		replacement := ".\n\n" + strings.ToUpper(first[:1]) + first[1:]
		result = result[:periodPos] + replacement
		count++
	}

	return result, count
}

func rewriteAggressive(s string, rng *rand.Rand) (string, int) {
	result, count := rewriteLight(s, rng)

	for i := 0; i < 5; i++ {
		for _, pair := range aggressiveSynonyms {
			if strings.Contains(result, pair[0]) {
				if rng.Intn(3) == 0 {
					result = strings.Replace(result, pair[0], pair[1], 1)
					count++
				}
			}
		}
	}

	return result, count
}

func applyRewrite(s string, strategy RewriteStrategy) (string, int) {
	if strategy == RewriteNone {
		return s, 0
	}

	rng := rand.New(rand.NewSource(42))

	switch strategy {
	case RewriteLight:
		return rewriteLight(s, rng)
	case RewriteAggressive:
		return rewriteAggressive(s, rng)
	default:
		return s, 0
	}
}
