package planner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

func TestBuildAssessmentPlanCompleteCompliantUbuntuIsReady(t *testing.T) {
	plan := BuildAssessmentPlan(assessment.Assessment{
		Platform: assessment.PlatformUbuntu,
		Findings: completeUbuntuFindings(),
	})

	if plan.Status != PlanStatusReady {
		t.Fatalf("status = %q, want %q", plan.Status, PlanStatusReady)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("got %d actions, want none", len(plan.Actions))
	}
}

func TestBuildAssessmentPlanCompleteFailingSSHRootLoginRequiresApproval(t *testing.T) {
	findings := completeUbuntuFindings()
	findings[1].Status = assessment.StatusFail
	findings[1].CurrentValue = "yes"

	plan := BuildAssessmentPlan(assessment.Assessment{
		Platform: assessment.PlatformUbuntu,
		Findings: findings,
	})

	if plan.Status != PlanStatusReady || len(plan.Actions) != 1 {
		t.Fatalf("plan = %#v, want READY with one approval action", plan)
	}
	action := plan.Actions[0]
	if action.ActionID != "ACT-SSH-5.1.20" || action.ControlID != "5.1.20" {
		t.Errorf("unexpected action identity: %#v", action)
	}
	if action.ActionType != "SET_SSH_DIRECTIVE" || action.DesiredValue != "no" {
		t.Errorf("unexpected action: %#v", action)
	}
	if action.RiskScore != 3.8 || action.ExecutionMode != ExecutionApproval {
		t.Errorf("action must remain approval-required: %#v", action)
	}
}

func TestBuildAssessmentPlanFailsClosedForIncompleteOrUncertainAssessments(t *testing.T) {
	tests := []struct {
		name    string
		prepare func() assessment.Assessment
	}{
		{
			name: "empty assessment",
			prepare: func() assessment.Assessment {
				return assessment.Assessment{Platform: assessment.PlatformUbuntu}
			},
		},
		{
			name: "missing required control",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings[:3]}
			},
		},
		{
			name: "assessment error",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Status = assessment.StatusError
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "normalized error attached to non-error status",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Error = &assessment.NormalizedError{Code: "ASSESSMENT_EVALUATION_FAILED"}
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "unknown status",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Status = assessment.StatusUnknown
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "unresolved applicability",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Applicability = ""
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "not applicable without policy rule",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0] = assessment.NotApplicableFinding(
					findings[0].ControlID,
					findings[0].Title,
					findings[0].Severity,
					"not applicable",
					"test",
				)
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "duplicate control IDs",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[3].ControlID = findings[0].ControlID
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "unknown control ID",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].ControlID = "future.control.id"
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "inconsistent PASS values",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].CurrentValue = "yes"
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "unsupported failing control has no remediation",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Status = assessment.StatusFail
				findings[0].CurrentValue = "yes"
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "wrong platform",
			prepare: func() assessment.Assessment {
				return assessment.Assessment{Platform: "centos", Findings: completeUbuntuFindings()}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := BuildAssessmentPlan(tt.prepare())
			assertBlockedWithoutActions(t, plan)
		})
	}
}

func TestBuildSSHPlanRequiresAllUbuntuControls(t *testing.T) {
	plan := BuildSSHPlan([]assessment.Finding{completeUbuntuFindings()[1]})
	assertBlockedWithoutActions(t, plan)
}

func TestBuildAssessmentPlanBlocksEveryMissingRequiredControl(t *testing.T) {
	for missingIndex, controlID := range requiredUbuntuSSHControls {
		t.Run(controlID, func(t *testing.T) {
			findings := completeUbuntuFindings()
			findings = append(findings[:missingIndex], findings[missingIndex+1:]...)
			plan := BuildAssessmentPlan(assessment.Assessment{
				Platform: assessment.PlatformUbuntu,
				Findings: findings,
			})
			assertBlockedWithoutActions(t, plan)
		})
	}
}

func TestPlanStatusIsSerializedAsJSON(t *testing.T) {
	data, err := json.Marshal(Plan{Status: PlanStatusBlocked})
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if !strings.Contains(string(data), `"status":"BLOCKED"`) {
		t.Errorf("JSON = %s, want a BLOCKED status field", data)
	}
}

func completeUbuntuFindings() []assessment.Finding {
	return []assessment.Finding{
		compliantSSHControl("5.1.19", "no", "MEDIUM"),
		compliantSSHControl("5.1.20", "no", "HIGH"),
		compliantSSHControl("5.1.21", "no", "MEDIUM"),
		compliantSSHControl("5.1.22", "yes", "MEDIUM"),
	}
}

func compliantSSHControl(controlID, value, severity string) assessment.Finding {
	return assessment.Finding{
		ControlID:     controlID,
		Status:        assessment.StatusPass,
		Applicability: assessment.ApplicabilityApplicable,
		Severity:      severity,
		CurrentValue:  value,
		ExpectedValue: value,
	}
}

func assertBlockedWithoutActions(t *testing.T, plan Plan) {
	t.Helper()
	if plan.Status != PlanStatusBlocked {
		t.Errorf("status = %q, want %q", plan.Status, PlanStatusBlocked)
	}
	if len(plan.Actions) != 0 {
		t.Errorf("got %d actions, want none", len(plan.Actions))
	}
}
