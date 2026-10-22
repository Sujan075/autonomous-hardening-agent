package planner

type ExecutionMode string

const (
	ExecutionAuto     ExecutionMode = "AUTO"
	ExecutionApproval ExecutionMode = "APPROVAL"
	ExecutionSandbox  ExecutionMode = "SANDBOX"
	ExecutionManual   ExecutionMode = "MANUAL"
	ExecutionBlocked  ExecutionMode = "BLOCKED"
)

type PlanStatus string

const (
	PlanStatusReady   PlanStatus = "READY"
	PlanStatusBlocked PlanStatus = "BLOCKED"
)

type Action struct {
	ActionID      string        `json:"action_id"`
	ControlID     string        `json:"control_id"`
	Title         string        `json:"title"`
	ActionType    string        `json:"action_type"`
	CurrentValue  string        `json:"current_value"`
	DesiredValue  string        `json:"desired_value"`
	RiskScore     float64       `json:"risk_score"`
	ExecutionMode ExecutionMode `json:"execution_mode"`
	Reason        string        `json:"reason"`
}

type Plan struct {
	Status   PlanStatus `json:"status"`
	Platform string     `json:"platform"`
	Actions  []Action   `json:"actions"`
}
