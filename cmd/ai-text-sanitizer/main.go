package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

var version = "dev"

func main() {
	opts := aisanitizer.Defaults()

	var (
		outFile       string
		reportFile    string
		detectOnly    bool
		strict        bool
		inPlace       bool
		pretty        bool
		rewriteStr    string
		showVersion   bool

		noZeroWidth           bool
		noBidi                bool
		noInvisibleMath       bool
		noVariationSelectors  bool
		noTagChars            bool
		noFormatChars         bool
		noBrailleBlank        bool
		noStripControl        bool
		noCitations           bool
		noModelArtifacts      bool
		noNormalizeSpaces     bool
		noNormalizeLineSep    bool

		enableSmartQuotes  bool
		enableDashes       bool
		enableEllipsis     bool
		enableCollapse     bool
		enableTrim         bool

		nfkc bool
	)

	flag.StringVar(&outFile, "out", "", "Output file (default: stdout)")
	flag.StringVar(&outFile, "o", "", "Output file (default: stdout)")
	flag.StringVar(&reportFile, "report", "", "Write JSON report to file")
	flag.StringVar(&reportFile, "r", "", "Write JSON report to file")
	flag.BoolVar(&detectOnly, "detect-only", false, "Only detect, don't modify")
	flag.BoolVar(&detectOnly, "d", false, "Only detect, don't modify")
	flag.BoolVar(&strict, "strict", false, "Exit code 2 if text was modified or findings detected")
	flag.BoolVar(&strict, "s", false, "Exit code 2 if text was modified or findings detected")
	flag.BoolVar(&inPlace, "in-place", false, "Modify file in-place (creates .bak backup)")
	flag.BoolVar(&inPlace, "i", false, "Modify file in-place (creates .bak backup)")
	flag.BoolVar(&pretty, "pretty", false, "Human-readable report to stderr")
	flag.StringVar(&rewriteStr, "rewrite", "none", "Rewrite strategy: none, light, aggressive")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showVersion, "v", false, "Show version")

	flag.BoolVar(&noZeroWidth, "no-remove-zero-width", false, "Keep zero-width characters")
	flag.BoolVar(&noBidi, "no-remove-bidi", false, "Keep bidi controls")
	flag.BoolVar(&noInvisibleMath, "no-remove-invisible-math", false, "Keep invisible math operators")
	flag.BoolVar(&noVariationSelectors, "no-remove-variation-selectors", false, "Keep variation selectors")
	flag.BoolVar(&noTagChars, "no-remove-tag-chars", false, "Keep Unicode tag characters")
	flag.BoolVar(&noFormatChars, "no-remove-format-chars", false, "Keep format characters")
	flag.BoolVar(&noBrailleBlank, "no-remove-braille-blank", false, "Keep braille pattern blank")
	flag.BoolVar(&noStripControl, "no-strip-control", false, "Keep control characters")
	flag.BoolVar(&noCitations, "no-remove-citations", false, "Keep citation placeholders")
	flag.BoolVar(&noModelArtifacts, "no-remove-model-artifacts", false, "Keep model artifacts")
	flag.BoolVar(&noNormalizeSpaces, "no-normalize-spaces", false, "Keep exotic spaces")
	flag.BoolVar(&noNormalizeLineSep, "no-normalize-line-separators", false, "Keep line/paragraph separators")
	flag.BoolVar(&enableSmartQuotes, "normalize-smart-quotes", false, "Normalize smart quotes")
	flag.BoolVar(&enableDashes, "normalize-dashes", false, "Normalize dashes")
	flag.BoolVar(&enableEllipsis, "normalize-ellipsis", false, "Normalize ellipsis")
	flag.BoolVar(&enableCollapse, "collapse-whitespace", false, "Collapse whitespace runs")
	flag.BoolVar(&enableTrim, "trim", false, "Trim leading/trailing whitespace")
	flag.BoolVar(&nfkc, "nfkc", false, "Apply NFKC normalization")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ai-text-sanitizer v%s - Sanitize AI-generated text

Usage: ai-text-sanitizer [flags] [input-file]

If no input file is given, reads from stdin.

Flags:
  -o, --out string       Output file (default: stdout)
  -r, --report string    Write JSON report to file
  -d, --detect-only      Only detect, don't modify (exit code 2 if findings)
  -s, --strict           Exit code 2 if text was modified or findings detected
  -i, --in-place         Modify file in-place (creates .bak backup)
      --pretty           Human-readable report to stderr
      --rewrite string   Rewrite strategy: none, light, aggressive (default: none)
  -v, --version          Show version
      --nfkc             Apply NFKC normalization
      --trim             Trim leading/trailing whitespace
      --collapse-whitespace  Collapse runs of whitespace
      --normalize-smart-quotes  Normalize smart quotes to straight
      --normalize-dashes      Normalize dashes to -
      --normalize-ellipsis    Normalize ellipsis to ...

Disable default sanitization rules:
      --no-remove-zero-width
      --no-remove-bidi
      --no-remove-variation-selectors
      --no-remove-tag-chars
      --no-remove-citations
      --no-normalize-spaces
      (and more --no-* flags for each default rule)
`, version)
	}

	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	if noZeroWidth {
		opts.RemoveZeroWidth = false
	}
	if noBidi {
		opts.RemoveBidi = false
	}
	if noInvisibleMath {
		opts.RemoveInvisibleMath = false
	}
	if noVariationSelectors {
		opts.RemoveVariationSelectors = false
	}
	if noTagChars {
		opts.RemoveTagChars = false
	}
	if noFormatChars {
		opts.RemoveFormatChars = false
	}
	if noBrailleBlank {
		opts.RemoveBrailleBlank = false
	}
	if noStripControl {
		opts.StripControl = false
	}
	if noCitations {
		opts.RemoveCitations = false
	}
	if noModelArtifacts {
		opts.RemoveModelArtifacts = false
	}
	if noNormalizeSpaces {
		opts.NormalizeSpaces = false
	}
	if noNormalizeLineSep {
		opts.NormalizeLineSeparators = false
	}

	opts.NormalizeSmartQuotes = enableSmartQuotes
	opts.NormalizeDashes = enableDashes
	opts.NormalizeEllipsis = enableEllipsis
	opts.CollapseWhitespace = enableCollapse
	opts.Trim = enableTrim
	opts.Nfkc = nfkc

	var rewriteStrategy aisanitizer.RewriteStrategy
	switch strings.ToLower(rewriteStr) {
	case "light":
		rewriteStrategy = aisanitizer.RewriteLight
	case "aggressive":
		rewriteStrategy = aisanitizer.RewriteAggressive
	default:
		rewriteStrategy = aisanitizer.RewriteNone
	}

	args := flag.Args()

	var inputReader io.Reader
	var inputPath string

	if len(args) > 0 {
		inputPath = args[0]
		f, err := os.Open(inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		inputReader = f
	} else {
		inputReader = os.Stdin
	}

	inputBytes, err := io.ReadAll(inputReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
	input := string(inputBytes)

	var output string
	var report *aisanitizer.Report

	if detectOnly {
		report, err = aisanitizer.Detect(input, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Detection error: %v\n", err)
			os.Exit(1)
		}
		output = input
	} else if rewriteStrategy != aisanitizer.RewriteNone {
		output, report, err = aisanitizer.SanitizeWithRewrite(input, opts, rewriteStrategy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		output, report = aisanitizer.Sanitize(input, opts)
	}

	if inPlace && inputPath != "" {
		err := os.WriteFile(inputPath+".bak", []byte(input), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating backup: %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(inputPath, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
	} else if outFile != "" {
		err := os.WriteFile(outFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(output)
	}

	if reportFile != "" {
		reportJSON, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling report: %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(reportFile, reportJSON, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
			os.Exit(1)
		}
	}

	if pretty {
		fmt.Fprintf(os.Stderr, "Report: %s\n", report.Summary())
		if report.HasWatermarks() {
			fmt.Fprintf(os.Stderr, "Findings:\n")
			for _, f := range report.Findings {
				fmt.Fprintf(os.Stderr, "  %s\n", f.String())
			}
		}
	}

	if strict && (report.WasModified() || report.HasWatermarks()) {
		os.Exit(2)
	}
}
