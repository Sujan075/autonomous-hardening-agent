package planner

import (
	"fmt"
	"strings"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

var requiredUbuntuSSHControls = []string{"5.1.19", "5.1.20", "5.1.21", "5.1.22"}

func BuildSSHPlan(findings []assessment.Finding) Plan {
	return buildUbuntuSSHPlan(findings)
}

func BuildAssessmentPlan(result assessment.Assessment) Plan {
	if !strings.EqualFold(result.Platform, assessment.PlatformUbuntu) {
		return blockedPlan(result.Platform)
	}
	return buildUbuntuSSHPlan(result.Findings)
}

func buildUbuntuSSHPlan(findings []assessment.Finding) Plan {
	plan := Plan{
		Status:   PlanStatusReady,
		Platform: assessment.PlatformUbuntu,
		Actions:  make([]Action, 0),
	}
	block := func() Plan {
		plan.Status = PlanStatusBlocked
		plan.Actions = make([]Action, 0)
		return plan
	}
	if len(findings) == 0 {
		return block()
	}

	required := make(map[string]struct{}, len(requiredUbuntuSSHControls))
	for _, controlID := range requiredUbuntuSSHControls {
		required[controlID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(findings))
	byControl := make(map[string]assessment.Finding, len(findings))

	for _, finding := range findings {
		if _, duplicate := seen[finding.ControlID]; duplicate || finding.ControlID == "" {
			return block()
		}
		seen[finding.ControlID] = struct{}{}
		if _, known := required[finding.ControlID]; !known {
			return block()
		}
		if finding.Error != nil || finding.Status == assessment.StatusError || finding.Status == assessment.StatusUnknown {
			return block()
		}
		if finding.Applicability != assessment.ApplicabilityApplicable {
			return block()
		}
		if finding.CurrentValue == "" || finding.ExpectedValue == "" || finding.Severity == "" {
			return block()
		}
		switch finding.Status {
		case assessment.StatusPass:
			if finding.CurrentValue != finding.ExpectedValue {
				return block()
			}
		case assessment.StatusFail:
			if finding.CurrentValue == finding.ExpectedValue {
				return block()
			}
		default:
			return block()
		}
		byControl[finding.ControlID] = finding
	}

	if len(byControl) != len(requiredUbuntuSSHControls) {
		return block()
	}
	for _, controlID := range requiredUbuntuSSHControls {
		if _, exists := byControl[controlID]; !exists {
			return block()
		}
	}

	for _, finding := range findings {
		if finding.Status != assessment.StatusFail {
			continue
		}

		switch finding.ControlID {
		case "5.1.20":
			if finding.ExpectedValue != "no" {
				return block()
			}
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
		default:
			// No approved remediation is defined for this failing control.
			return block()
		}
	}

	return plan
}

func blockedPlan(platform string) Plan {
	return Plan{
		Status:   PlanStatusBlocked,
		Platform: platform,
		Actions:  make([]Action, 0),
	}
}
