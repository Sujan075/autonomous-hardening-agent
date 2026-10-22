package planner

import (
	"fmt"
	"strings"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
)

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
	return buildUbuntuSSHPlanWithCatalog(findings, catalog.Controls(catalog.PlatformUbuntu))
}

func buildUbuntuSSHPlanWithCatalog(findings []assessment.Finding, controls []catalog.Control) Plan {
	plan := Plan{
		Status:   PlanStatusReady,
		Platform: string(catalog.PlatformUbuntu),
		Actions:  make([]Action, 0),
	}
	block := func() Plan {
		plan.Status = PlanStatusBlocked
		plan.Actions = make([]Action, 0)
		return plan
	}
	if len(findings) == 0 || len(controls) == 0 || catalog.Validate(controls) != nil {
		return block()
	}

	required := make(map[string]catalog.Control, len(controls))
	for _, control := range controls {
		if control.Scope.Platform != catalog.PlatformUbuntu {
			return block()
		}
		required[control.ID] = control
	}
	seen := make(map[string]struct{}, len(findings))
	byControl := make(map[string]assessment.Finding, len(findings))

	for _, finding := range findings {
		if _, duplicate := seen[finding.ControlID]; duplicate || finding.ControlID == "" {
			return block()
		}
		seen[finding.ControlID] = struct{}{}
		control, known := required[finding.ControlID]
		if !known {
			return block()
		}
		if finding.Error != nil || finding.Status == assessment.StatusError || finding.Status == assessment.StatusUnknown {
			return block()
		}
		if finding.Applicability != assessment.ApplicabilityApplicable {
			return block()
		}
		if finding.Title != control.Title || finding.Severity != control.Severity || finding.ExpectedValue != control.ExpectedValue {
			return block()
		}
		if finding.CurrentValue == "" || finding.ExpectedValue == "" || !hasExpectedEvidence(finding, control) {
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

	if len(byControl) != len(controls) {
		return block()
	}
	for controlID := range required {
		if _, exists := byControl[controlID]; !exists {
			return block()
		}
	}

	for _, finding := range findings {
		if finding.Status != assessment.StatusFail {
			continue
		}

		control := required[finding.ControlID]
		remediation := control.Remediation
		if !remediation.Supported || !remediation.RequiresApproval || finding.ExpectedValue != remediation.DesiredValue {
			// No approved remediation is defined for this failing control.
			return block()
		}
		plan.Actions = append(plan.Actions, Action{
			ActionID:      remediation.ActionID,
			ControlID:     finding.ControlID,
			Title:         remediation.ActionTitle,
			ActionType:    remediation.ActionType,
			CurrentValue:  finding.CurrentValue,
			DesiredValue:  remediation.DesiredValue,
			RiskScore:     remediation.RiskScore,
			ExecutionMode: ExecutionApproval,
			Reason: fmt.Sprintf(
				"High-impact SSH authentication change: %s -> %s",
				finding.CurrentValue,
				remediation.DesiredValue,
			),
		})
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

func hasExpectedEvidence(finding assessment.Finding, control catalog.Control) bool {
	if finding.Source == "" || len(finding.Evidence) < len(control.Evidence) {
		return false
	}
	for _, expected := range control.Evidence {
		if finding.Source != expected.Source {
			return false
		}
		found := false
		for _, evidence := range finding.Evidence {
			if evidence.Name == expected.SettingKey && evidence.Source == expected.Source && evidence.Value != "" {
				if evidence.Name == control.EffectiveSettingKey && evidence.Value != finding.CurrentValue {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
