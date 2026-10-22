package planner

import (
	"fmt"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

func BuildSSHPlan(findings []assessment.Finding) Plan {
	plan := Plan{
		Status:   PlanStatusReady,
		Platform: "ubuntu",
		Actions:  make([]Action, 0),
	}

	for _, finding := range findings {
		if finding.Status == assessment.StatusError {
			plan.Status = PlanStatusBlocked
			return plan
		}
	}

	for _, finding := range findings {
		if finding.Status != assessment.StatusFail {
			continue
		}

		switch finding.ControlID {
		case "5.1.20":
			plan.Actions = append(plan.Actions, Action{
				ActionID:      "ACT-SSH-5.1.20",
				ControlID:     finding.ControlID,
				Title:         "Disable SSH root login",
				ActionType:    "SET_SSH_DIRECTIVE",
				CurrentValue:  finding.CurrentValue,
				DesiredValue:  finding.ExpectedValue,
				RiskScore:     3.8,
				ExecutionMode: ExecutionApproval,
				Reason: fmt.Sprintf(
					"High-impact SSH authentication change: %s -> %s",
					finding.CurrentValue,
					finding.ExpectedValue,
				),
			})
		}
	}

	return plan
}
