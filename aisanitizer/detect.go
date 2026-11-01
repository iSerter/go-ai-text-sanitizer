package aisanitizer

// Detector is an extension point for additional read-only detectors (for
// example a statistical scorer). Register them via Options.ExtraDetectors;
// Detect appends their findings to the report.
type Detector interface {
	Name() string
	Detect(text string) ([]Finding, error)
}

// HeuristicDetector exposes the built-in rules as a Detector.
type HeuristicDetector struct {
	// Options selects the rules to run; nil means Defaults().
	Options *Options
}

// NewHeuristicDetector returns a detector using Defaults().
func NewHeuristicDetector() *HeuristicDetector {
	return &HeuristicDetector{}
}

// Name returns "heuristic".
func (d *HeuristicDetector) Name() string {
	return "heuristic"
}

// Detect returns the findings Detect reports for text.
func (d *HeuristicDetector) Detect(text string) ([]Finding, error) {
	opts := d.Options
	if opts == nil {
		opts = Defaults()
	} else {
		opts = opts.Clone()
	}
	opts.ExtraDetectors = nil
	report, err := Detect(text, opts)
	if err != nil {
		return nil, err
	}
	return report.Findings, nil
}
