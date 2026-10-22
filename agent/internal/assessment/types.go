package assessment

type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusError         Status = "ERROR"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	StatusUnknown       Status = "UNKNOWN"
)

type Applicability string

const (
	ApplicabilityApplicable    Applicability = "APPLICABLE"
	ApplicabilityNotApplicable Applicability = "NOT_APPLICABLE"
)

// Assessment is the shared response envelope used by platform evaluators.
// Existing clients continue to receive the same platform/findings structure.
type Assessment struct {
	Platform string    `json:"platform"`
	Findings []Finding `json:"findings"`
}

type Evidence struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type NormalizedError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Source  string `json:"source"`
}

type Finding struct {
	ControlID     string           `json:"control_id"`
	Title         string           `json:"title"`
	Status        Status           `json:"status"`
	Applicability Applicability    `json:"applicability,omitempty"`
	Severity      string           `json:"severity"`
	CurrentValue  string           `json:"current_value"`
	ExpectedValue string           `json:"expected_value"`
	Message       string           `json:"message"`
	Source        string           `json:"source,omitempty"`
	Evidence      []Evidence       `json:"evidence,omitempty"`
	Error         *NormalizedError `json:"error,omitempty"`
}

// NotApplicableFinding represents a known control that does not apply to a target.
func NotApplicableFinding(controlID, title, severity, reason, source string) Finding {
	return Finding{
		ControlID:     controlID,
		Title:         title,
		Status:        StatusNotApplicable,
		Applicability: ApplicabilityNotApplicable,
		Severity:      severity,
		Message:       reason,
		Source:        source,
	}
}
