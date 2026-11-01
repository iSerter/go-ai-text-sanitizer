package aisanitizer

import (
	"strings"
	"testing"
)

var benchCorpora = map[string]string{
	"ascii":   strings.Repeat("The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.\n", 20000),
	"latin":   strings.Repeat("Caf\u00E9 na\u00EFve r\u00E9sum\u00E9 \u00FCber \u00E0 la fa\u00E7on de Gr\u00FC\u00DFe aus M\u00FCnchen.\n", 25000),
	"mixed":   strings.Repeat("The quick brown fox \u201Cjumps\u201D over the lazy dog\u2014again. Caf\u00E9 \U0001F600 r\u00E9sum\u00E9.\n", 20000),
	"emoji":   strings.Repeat("\U0001F468\u200D\U0001F469\u200D\U0001F467 \u2764\uFE0F \U0001F44B\U0001F3FD \U0001F3F3\uFE0F\u200D\U0001F308 ok\n", 25000),
	"cjk":     strings.Repeat("\u65E5\u672C\u8A9E\u306E\u30C6\u30AD\u30B9\u30C8\u3068\u4E2D\u6587\u6587\u672C\u3002\uD55C\uAD6D\uC5B4 \uD14D\uC2A4\uD2B8.\n", 25000),
	"persian": strings.Repeat("\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645 \u06A9\u062A\u0627\u0628\u200C\u0647\u0627 \u0631\u0627 \u0628\u062E\u0648\u0627\u0646\u0645.\n", 25000),
	"dirty":   strings.Repeat("The quick\u200B brown fox\u00A0jumps (oaicite:1){index=1} over\u202Fthe lazy dog\u2060.\n", 20000),
}

func benchmarkSanitize(b *testing.B, corpus string, opts *Options) {
	in := benchCorpora[corpus]
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sanitize(in, opts)
	}
}

func BenchmarkSanitizeASCII(b *testing.B)   { benchmarkSanitize(b, "ascii", Defaults()) }
func BenchmarkSanitizeLatin(b *testing.B)   { benchmarkSanitize(b, "latin", Defaults()) }
func BenchmarkSanitizeMixed(b *testing.B)   { benchmarkSanitize(b, "mixed", Defaults()) }
func BenchmarkSanitizeEmoji(b *testing.B)   { benchmarkSanitize(b, "emoji", Defaults()) }
func BenchmarkSanitizeCJK(b *testing.B)     { benchmarkSanitize(b, "cjk", Defaults()) }
func BenchmarkSanitizePersian(b *testing.B) { benchmarkSanitize(b, "persian", Defaults()) }
func BenchmarkSanitizeDirty(b *testing.B)   { benchmarkSanitize(b, "dirty", Defaults()) }

func BenchmarkSanitizeMixedPlain(b *testing.B) {
	o, _ := Preset(PresetPlain)
	benchmarkSanitize(b, "mixed", o)
}

func BenchmarkDetectMixed(b *testing.B) {
	in := benchCorpora["mixed"]
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Detect(in, nil)
	}
}

func BenchmarkDetectDirty(b *testing.B) {
	in := benchCorpora["dirty"]
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Detect(in, nil)
	}
}
