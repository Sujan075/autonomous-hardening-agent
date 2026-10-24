package planner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/catalog"
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
	setCurrentValue(&findings[1], "yes")

	plan := BuildAssessmentPlan(assessment.Assessment{
		Platform: assessment.PlatformUbuntu,
		Findings: findings,
	})

	if plan.Status != PlanStatusReady || len(plan.Actions) != 1 {
		t.Fatalf("plan = %#v, want READY with one approval action", plan)
	}
	action := plan.Actions[0]
	control, ok := catalog.Lookup(catalog.PlatformUbuntu, "5.1.20")
	if !ok {
		t.Fatal("catalog missing 5.1.20")
	}
	remediation := control.Remediation
	if action.ActionID != remediation.ActionID || action.ControlID != control.ID {
		t.Errorf("unexpected action identity: %#v", action)
	}
	if action.ActionType != remediation.ActionType || action.DesiredValue != remediation.DesiredValue || action.Title != remediation.ActionTitle {
		t.Errorf("unexpected action: %#v", action)
	}
	if action.RiskScore != remediation.RiskScore || !remediation.RequiresApproval || action.ExecutionMode != ExecutionApproval {
		t.Errorf("action must remain approval-required: %#v", action)
	}
}

func TestBuildAssessmentPlanBlocksUnsupportedCentOSStreamAssessment(t *testing.T) {
	plan := BuildAssessmentPlan(assessment.Assessment{
		Platform: "centos-stream",
		Findings: []assessment.Finding{{
			ControlID: "PLATFORM-ASSESSMENT-UNSUPPORTED",
			Status:    assessment.StatusUnknown,
			Error: &assessment.NormalizedError{
				Code: "PLATFORM_OR_CONTROL_SET_UNSUPPORTED",
			},
		}},
	})
	if plan.Status != PlanStatusBlocked || plan.Platform != "centos-stream" || len(plan.Actions) != 0 {
		t.Fatalf("unsupported CentOS Stream plan = %#v, want blocked with no actions", plan)
	}
}

func TestBuildAssessmentPlanAlwaysBlocksCentOSBaseline(t *testing.T) {
	findings := make([]assessment.Finding, 0)
	for _, control := range catalog.Controls(catalog.PlatformCentOSStream) {
		finding := assessment.Finding{ControlID: control.ID, Title: control.Title, Status: assessment.StatusPass, Applicability: assessment.ApplicabilityApplicable, Severity: control.Severity, CurrentValue: control.ExpectedValue, ExpectedValue: control.ExpectedValue}
		for _, ev := range control.Evidence {
			finding.Source = ev.Source
			finding.Evidence = append(finding.Evidence, assessment.Evidence{Name: ev.SettingKey, Value: control.ExpectedValue, Source: ev.Source})
		}
		findings = append(findings, finding)
	}
	for _, item := range []struct {
		name     string
		findings []assessment.Finding
	}{
		{"complete passing", findings},
		{"complete failing", func() []assessment.Finding {
			copy := append([]assessment.Finding(nil), findings...)
			copy[1].Status = assessment.StatusFail
			setCurrentValue(&copy[1], "without-password")
			return copy
		}()},
		{"incomplete", findings[:3]},
		{"uncertain", func() []assessment.Finding {
			copy := append([]assessment.Finding(nil), findings...)
			copy[0].Status = assessment.StatusUnknown
			return copy
		}()},
	} {
		t.Run(item.name, func(t *testing.T) {
			plan := BuildAssessmentPlan(assessment.Assessment{Platform: assessment.PlatformCentOSStream, Findings: item.findings})
			if plan.Platform != assessment.PlatformCentOSStream {
				t.Errorf("platform=%s", plan.Platform)
			}
			assertBlockedWithoutActions(t, plan)
		})
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
			name: "missing required evidence",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Evidence = nil
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "evidence does not match current value",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Evidence[0].Value = "yes"
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
				setCurrentValue(&findings[0], "yes")
				return assessment.Assessment{Platform: assessment.PlatformUbuntu, Findings: findings}
			},
		},
		{
			name: "unsupported failing control has no remediation",
			prepare: func() assessment.Assessment {
				findings := completeUbuntuFindings()
				findings[0].Status = assessment.StatusFail
				setCurrentValue(&findings[0], "yes")
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

func TestBuildAssessmentPlanBlocksInvalidCatalogDefinitions(t *testing.T) {
	controls := catalog.Controls(catalog.PlatformUbuntu)
	controls[1].ExpectedValue = "yes"
	plan := buildUbuntuSSHPlanWithCatalog(completeUbuntuFindings(), controls)
	assertBlockedWithoutActions(t, plan)
}

func TestBuildAssessmentPlanBlocksEveryMissingRequiredControl(t *testing.T) {
	for missingIndex, control := range catalog.Controls(catalog.PlatformUbuntu) {
		t.Run(control.ID, func(t *testing.T) {
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
	controls := catalog.Controls(catalog.PlatformUbuntu)
	findings := make([]assessment.Finding, 0, len(controls))
	for _, control := range controls {
		finding := assessment.Finding{
			ControlID:     control.ID,
			Title:         control.Title,
			Status:        assessment.StatusPass,
			Applicability: assessment.ApplicabilityApplicable,
			Severity:      control.Severity,
			CurrentValue:  control.ExpectedValue,
			ExpectedValue: control.ExpectedValue,
		}
		for _, expected := range control.Evidence {
			finding.Source = expected.Source
			finding.Evidence = append(finding.Evidence, assessment.Evidence{
				Name:   expected.SettingKey,
				Value:  control.ExpectedValue,
				Source: expected.Source,
			})
		}
		findings = append(findings, finding)
	}
	return findings
}

func setCurrentValue(finding *assessment.Finding, value string) {
	finding.CurrentValue = value
	for i := range finding.Evidence {
		finding.Evidence[i].Value = value
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
