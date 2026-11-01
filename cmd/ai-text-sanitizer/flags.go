package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

// config holds everything parsed from the command line.
type config struct {
	out, report, format, preset string
	invalidUTF8                 string
	detectOnly, check, diff     bool
	strict, inPlace, noBackup   bool
	pretty, listRules, version  bool
	positions                   int
	includes, excludes          []string
	// setters apply option flags in command-line order on top of the preset.
	setters []func(*aisanitizer.Options) error
}

// optBool is a boolean flag that records an Options setter when given.
type optBool struct {
	c   *config
	set func(o *aisanitizer.Options, v bool)
}

func (f *optBool) String() string   { return "" }
func (f *optBool) IsBoolFlag() bool { return true }
func (f *optBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	f.c.setters = append(f.c.setters, func(o *aisanitizer.Options) error { f.set(o, v); return nil })
	return nil
}

// optValue is a valued flag that records an Options setter when given.
type optValue struct {
	c   *config
	set func(o *aisanitizer.Options, v string) error
}

func (f *optValue) String() string { return "" }
func (f *optValue) Set(s string) error {
	f.c.setters = append(f.c.setters, func(o *aisanitizer.Options) error { return f.set(o, s) })
	return nil
}

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func newFlagSet(c *config) *flag.FlagSet {
	fs := flag.NewFlagSet("ai-text-sanitizer", flag.ContinueOnError)

	str := func(p *string, def, usage string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, def, usage)
		}
	}
	boolean := func(p *bool, usage string, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, usage)
		}
	}
	str(&c.out, "", "write output to `file` (single input only)", "o", "out")
	str(&c.report, "", "write the JSON report to `file`", "r", "report")
	str(&c.format, "text", "report `format` for --detect-only/--check: text, json, sarif", "format")
	str(&c.preset, "default", "rule `preset`: safe, default, plain, paranoid", "preset")
	str(&c.invalidUTF8, "error", "invalid UTF-8 `policy`: error, replace, drop", "invalid-utf8")
	boolean(&c.detectOnly, "only detect; print findings and exit 2 if any", "d", "detect-only")
	boolean(&c.check, "list inputs that would change; exit 2 if any", "check")
	boolean(&c.diff, "print a unified diff of the changes instead of the output", "diff")
	boolean(&c.strict, "exit 2 if text was modified or findings were detected", "s", "strict")
	boolean(&c.inPlace, "rewrite files in place (atomically, keeping a .bak)", "i", "in-place")
	boolean(&c.noBackup, "with --in-place, do not keep a .bak backup", "no-backup")
	boolean(&c.pretty, "print a human-readable report to stderr", "pretty")
	boolean(&c.listRules, "list all rules and exit", "list-rules")
	boolean(&c.version, "print the version and exit", "v", "version")
	fs.IntVar(&c.positions, "positions", 0, "record up to `n` positions per finding")
	fs.Var((*stringList)(&c.includes), "include", "when walking directories, only process files matching `glob` (repeatable)")
	fs.Var((*stringList)(&c.excludes), "exclude", "skip files and directories matching `glob` (repeatable)")

	ruleFlag := func(on bool) func(o *aisanitizer.Options, v string) error {
		return func(o *aisanitizer.Options, v string) error {
			for _, id := range strings.Split(v, ",") {
				if id = strings.TrimSpace(id); id == "" {
					continue
				}
				if err := o.SetRule(aisanitizer.RuleID(id), on); err != nil {
					return err
				}
			}
			return nil
		}
	}
	fs.Var(&optValue{c, ruleFlag(true)}, "rule", "enable rule `ids` (comma-separated, repeatable; see --list-rules)")
	fs.Var(&optValue{c, ruleFlag(false)}, "no-rule", "disable rule `ids` (comma-separated, repeatable)")

	optB := func(name, usage string, set func(o *aisanitizer.Options, v bool)) {
		fs.Var(&optBool{c, set}, name, usage)
	}
	optV := func(name, usage string, set func(o *aisanitizer.Options, v string) error) {
		fs.Var(&optValue{c, set}, name, usage)
	}

	// Typography and opt-in rules.
	optB("normalize-smart-quotes", "convert curly quotes to straight quotes", func(o *aisanitizer.Options, v bool) { o.NormalizeSmartQuotes = v })
	optB("normalize-dashes", "convert all dashes to - (same as --dash-style=hyphen)", func(o *aisanitizer.Options, v bool) {
		if v {
			o.DashStyle = aisanitizer.DashHyphen
		} else {
			o.DashStyle = aisanitizer.DashKeep
		}
	})
	optV("dash-style", "dash `style`: keep, hyphen, ascii, comma", func(o *aisanitizer.Options, v string) error {
		styles := map[string]aisanitizer.DashStyle{"keep": aisanitizer.DashKeep, "hyphen": aisanitizer.DashHyphen, "ascii": aisanitizer.DashASCII, "comma": aisanitizer.DashComma}
		s, ok := styles[strings.ToLower(v)]
		if !ok {
			return fmt.Errorf("invalid --dash-style %q (want keep, hyphen, ascii or comma)", v)
		}
		o.DashStyle = s
		return nil
	})
	optB("normalize-ellipsis", "convert \u2026 to ...", func(o *aisanitizer.Options, v bool) { o.NormalizeEllipsis = v })
	optB("normalize-punctuation", "convert bullets, arrows and math symbols to ASCII", func(o *aisanitizer.Options, v bool) { o.NormalizePunctuation = v })
	optB("fold-compat", "fold compatibility characters (ligatures, fullwidth, math letters, superscripts)", func(o *aisanitizer.Options, v bool) { o.FoldCompatibility = v })
	optB("nfkc", "deprecated alias for --fold-compat", func(o *aisanitizer.Options, v bool) { o.FoldCompatibility = v })
	optB("fold-confusables", "fold look-alike Cyrillic/Greek letters in mixed-script words to Latin", func(o *aisanitizer.Options, v bool) { o.FoldConfusables = v })
	optB("strip-markdown", "strip Markdown formatting", func(o *aisanitizer.Options, v bool) { o.StripMarkdown = v })
	optB("remove-boilerplate", "remove chat boilerplate (openers, sign-offs, \"As an AI language model\")", func(o *aisanitizer.Options, v bool) { o.RemoveChatBoilerplate = v })
	optB("remove-numeric-citations", "remove bare [1]-style citation markers", func(o *aisanitizer.Options, v bool) { o.RemoveNumericCitations = v })
	optB("remove-private-use", "remove private-use characters", func(o *aisanitizer.Options, v bool) { o.RemovePrivateUse = v })
	optB("collapse-whitespace", "collapse whitespace runs, strip trailing spaces, limit blank lines", func(o *aisanitizer.Options, v bool) { o.CollapseWhitespace = v })
	optV("max-blank-lines", "with --collapse-whitespace, keep at most `n` consecutive blank lines (n >= 1, or -1 for no limit)", func(o *aisanitizer.Options, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n == 0 || n < -1 {
			return fmt.Errorf("invalid --max-blank-lines %q (want n >= 1, or -1 for no limit)", v)
		}
		o.MaxBlankLines = n
		return nil
	})
	optB("trim", "trim leading and trailing whitespace", func(o *aisanitizer.Options, v bool) { o.Trim = v })
	optB("keep-french-spacing", "keep narrow/no-break spaces used by French typography", func(o *aisanitizer.Options, v bool) { o.KeepFrenchSpacing = v })
	optV("bidi", "bidi control `mode`: auto, keep, remove", func(o *aisanitizer.Options, v string) error {
		modes := map[string]aisanitizer.BidiMode{"auto": aisanitizer.BidiAuto, "keep": aisanitizer.BidiKeep, "remove": aisanitizer.BidiRemove}
		m, ok := modes[strings.ToLower(v)]
		if !ok {
			return fmt.Errorf("invalid --bidi %q (want auto, keep or remove)", v)
		}
		o.BidiMode = m
		return nil
	})
	optB("no-keep-emoji", "do not preserve joiners/selectors inside emoji sequences", func(o *aisanitizer.Options, v bool) { o.KeepEmoji = !v })
	optB("no-keep-script-formatting", "do not preserve joiners/selectors required by Indic, Arabic, Mongolian and CJK text", func(o *aisanitizer.Options, v bool) { o.KeepScriptFormatting = !v })

	// Disable default rules (legacy flags).
	for _, d := range []struct {
		name string
		set  func(o *aisanitizer.Options)
	}{
		{"no-remove-zero-width", func(o *aisanitizer.Options) { o.RemoveZeroWidth = false }},
		{"no-remove-bidi", func(o *aisanitizer.Options) { o.RemoveBidi = false }},
		{"no-remove-invisible-math", func(o *aisanitizer.Options) { o.RemoveInvisibleMath = false }},
		{"no-remove-variation-selectors", func(o *aisanitizer.Options) { o.RemoveVariationSelectors = false }},
		{"no-remove-tag-chars", func(o *aisanitizer.Options) { o.RemoveTagChars = false }},
		{"no-remove-format-chars", func(o *aisanitizer.Options) { o.RemoveFormatChars = false }},
		{"no-remove-braille-blank", func(o *aisanitizer.Options) { o.RemoveBrailleBlank = false }},
		{"no-remove-noncharacters", func(o *aisanitizer.Options) { o.RemoveNoncharacters = false }},
		{"no-strip-control", func(o *aisanitizer.Options) { o.StripControl = false }},
		{"no-decode-entities", func(o *aisanitizer.Options) { o.DecodeInvisibleEntities = false }},
		{"no-remove-citations", func(o *aisanitizer.Options) { o.RemoveCitations = false }},
		{"no-remove-model-artifacts", func(o *aisanitizer.Options) { o.RemoveModelArtifacts = false }},
		{"no-remove-tracking-params", func(o *aisanitizer.Options) { o.RemoveTrackingParams = false }},
		{"no-normalize-spaces", func(o *aisanitizer.Options) { o.NormalizeSpaces = false }},
		{"no-normalize-line-separators", func(o *aisanitizer.Options) { o.NormalizeLineSeparators = false }},
	} {
		d := d
		optB(d.name, "disable a default rule group", func(o *aisanitizer.Options, v bool) {
			if v {
				d.set(o)
			}
		})
	}

	// Removed feature, kept so old invocations fail with a clear message.
	optV("rewrite", "removed; only \"none\" is accepted", func(o *aisanitizer.Options, v string) error {
		if strings.EqualFold(v, "none") {
			return nil
		}
		return fmt.Errorf("--rewrite %s is no longer supported: rewriting was removed because it changed meaning and added AI footprints (see CHANGELOG)", v)
	})
	return fs
}

// splitArgs separates flags from positional arguments so flags may follow
// file names (Go's flag package stops at the first positional argument).
func splitArgs(fs *flag.FlagSet, args []string) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positional
}

func (c *config) options() (*aisanitizer.Options, error) {
	o, err := aisanitizer.Preset(c.preset)
	if err != nil {
		return nil, err
	}
	for _, set := range c.setters {
		if err := set(o); err != nil {
			return nil, err
		}
	}
	switch strings.ToLower(c.invalidUTF8) {
	case "error", "replace":
		o.InvalidUTF8 = aisanitizer.InvalidUTF8Replace
	case "drop":
		o.InvalidUTF8 = aisanitizer.InvalidUTF8Drop
	default:
		return nil, fmt.Errorf("invalid --invalid-utf8 %q (want error, replace or drop)", c.invalidUTF8)
	}
	o.MaxPositions = c.positions
	return o, nil
}
