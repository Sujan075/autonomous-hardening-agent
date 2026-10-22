package planner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

func TestBuildSSHPlanAssessmentErrorBlocksPlan(t *testing.T) {
	findings := []assessment.Finding{
		{ControlID: "5.1.1", Status: assessment.StatusError},
	}

	plan := BuildSSHPlan(findings)
	assertBlockedWithoutActions(t, plan)
}

func TestBuildSSHPlanFailedControlAndAssessmentErrorBlocksPlan(t *testing.T) {
	findings := []assessment.Finding{
		failingSSHControl(),
		{ControlID: "5.1.1", Status: assessment.StatusError},
	}

	plan := BuildSSHPlan(findings)
	assertBlockedWithoutActions(t, plan)
}

func TestBuildSSHPlanMixedFindingsBlockRegardlessOfOrder(t *testing.T) {
	failedControl := failingSSHControl()
	errorFinding := assessment.Finding{ControlID: "5.1.1", Status: assessment.StatusError}

	tests := []struct {
		name     string
		findings []assessment.Finding
	}{
		{name: "failure then error", findings: []assessment.Finding{failedControl, errorFinding}},
		{name: "error then failure", findings: []assessment.Finding{errorFinding, failedControl}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := BuildSSHPlan(tt.findings)
			assertBlockedWithoutActions(t, plan)
		})
	}
}

func TestBuildSSHPlanValidFailingControlCreatesRemediationAction(t *testing.T) {
	finding := failingSSHControl()

	plan := BuildSSHPlan([]assessment.Finding{finding})

	if plan.Status != PlanStatusReady {
		t.Fatalf("status = %q, want %q", plan.Status, PlanStatusReady)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("got %d actions, want 1", len(plan.Actions))
	}
	action := plan.Actions[0]
	if action.ActionID != "ACT-SSH-5.1.20" {
		t.Errorf("action ID = %q, want %q", action.ActionID, "ACT-SSH-5.1.20")
	}
	if action.ControlID != "5.1.20" {
		t.Errorf("control ID = %q, want %q", action.ControlID, "5.1.20")
	}
	if action.ActionType != "SET_SSH_DIRECTIVE" {
		t.Errorf("action type = %q, want %q", action.ActionType, "SET_SSH_DIRECTIVE")
	}
	if action.DesiredValue != "no" {
		t.Errorf("desired value = %q, want %q", action.DesiredValue, "no")
	}
	if action.RiskScore != 3.8 {
		t.Errorf("risk score = %v, want 3.8", action.RiskScore)
	}
	if action.ExecutionMode != ExecutionApproval {
		t.Errorf("execution mode = %q, want %q", action.ExecutionMode, ExecutionApproval)
	}
}

func TestBuildSSHPlanPassingAssessmentIsReadyWithoutActions(t *testing.T) {
	findings := []assessment.Finding{
		{ControlID: "5.1.20", Status: assessment.StatusPass},
		{ControlID: "5.1.1", Status: assessment.StatusPass},
	}

	plan := BuildSSHPlan(findings)

	if plan.Status != PlanStatusReady {
		t.Fatalf("status = %q, want %q", plan.Status, PlanStatusReady)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("got %d actions, want none", len(plan.Actions))
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

func failingSSHControl() assessment.Finding {
	return assessment.Finding{
		ControlID:     "5.1.20",
		Status:        assessment.StatusFail,
		CurrentValue:  "yes",
		ExpectedValue: "no",
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
