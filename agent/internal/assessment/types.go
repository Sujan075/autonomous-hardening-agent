package assessment

type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusError         Status = "ERROR"
	StatusNotApplicable Status = "NOT_APPLICABLE"
)

type Finding struct {
	ControlID     string `json:"control_id"`
	Title         string `json:"title"`
	Status        Status `json:"status"`
	Severity      string `json:"severity"`
	CurrentValue  string `json:"current_value"`
	ExpectedValue string `json:"expected_value"`
	Message       string `json:"message"`
}
