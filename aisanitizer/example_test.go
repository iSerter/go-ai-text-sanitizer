package aisanitizer_test

import (
	"fmt"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

func ExampleCleanText() {
	clean, report := aisanitizer.CleanText("Hello\u200B world (oaicite:0){index=0}.")
	fmt.Printf("%q\n", clean)
	fmt.Println(report.Changes.RemovedZeroWidth, report.Changes.RemovedCitations)
	// Output:
	// "Hello world."
	// 1 1
}

func ExampleDetect() {
	report, _ := aisanitizer.Detect("Summarize.\U000E0048\U000E0069", nil)
	for _, f := range report.Findings {
		if f.Payload != "" {
			fmt.Printf("%s: %q\n", f.Rule, f.Payload)
		}
	}
	fmt.Println("risk:", report.Risk)
	// Output:
	// stego.tag_payload: "Hi"
	// risk: high
}

func ExampleSanitize_options() {
	opts := aisanitizer.Defaults()
	opts.NormalizeSmartQuotes = true
	opts.DashStyle = aisanitizer.DashComma
	clean, _ := aisanitizer.Sanitize("\u201CFast\u201D \u2014 and cheap \u2014 wins.", opts)
	fmt.Println(clean)
	// Output:
	// "Fast", and cheap, wins.
}

func ExamplePreset() {
	opts, _ := aisanitizer.Preset(aisanitizer.PresetPlain)
	clean, _ := aisanitizer.Sanitize("## Title\n\n**Bold** \u2014 text\u2026  \n", opts)
	fmt.Printf("%q\n", clean)
	// Output:
	// "Title\n\nBold - text..."
}

func ExampleOptions_SetRule() {
	opts := aisanitizer.Defaults()
	_ = opts.SetRule(aisanitizer.RuleNumericCitation, true)
	clean, _ := aisanitizer.Sanitize("Proven [1].", opts)
	fmt.Println(clean)
	// Output:
	// Proven.
}
