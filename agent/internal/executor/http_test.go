package executor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testExecutionToken = "test-only-execution-token"

func TestExecuteHandlerRejectsRequestsBeforeExecution(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		token         string
		authorization string
		body          string
		wantStatus    int
	}{
		{name: "unsupported method", method: http.MethodGet, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, body: `{"action_id":"` + ActionSSHRootLogin + `","approved":true}`, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing bearer token", method: http.MethodPost, token: testExecutionToken, body: `{"action_id":"` + ActionSSHRootLogin + `","approved":true}`, wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer token", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer wrong-token", body: `{"action_id":"` + ActionSSHRootLogin + `","approved":true}`, wantStatus: http.StatusUnauthorized},
		{name: "missing approval", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, body: `{"action_id":"` + ActionSSHRootLogin + `"}`, wantStatus: http.StatusForbidden},
		{name: "unsupported action ID", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, body: `{"action_id":"ACT-UNSUPPORTED","approved":true}`, wantStatus: http.StatusForbidden},
		{name: "malformed JSON", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, body: `{"action_id":`, wantStatus: http.StatusBadRequest},
		{name: "trailing JSON value", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, body: `{"action_id":"` + ActionSSHRootLogin + `","approved":true} {"approved":true}`, wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			request := httptest.NewRequest(tt.method, "/execute", strings.NewReader(tt.body))
			if tt.authorization != "" {
				request.Header.Set("Authorization", tt.authorization)
			}
			recorder := httptest.NewRecorder()

			executeHandler(recorder, request, tt.token, func() (ExecutionResult, error) {
				calls++
				return ExecutionResult{}, nil
			})

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			if calls != 0 {
				t.Fatalf("executor calls = %d, want 0", calls)
			}
			if strings.Contains(recorder.Body.String(), testExecutionToken) {
				t.Fatal("response exposed the execution token")
			}
		})
	}
}

func TestExecuteHandlerDisablesExecutionWhenTokenIsUnset(t *testing.T) {
	t.Setenv("AGENT_EXECUTION_TOKEN", "")
	request := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"action_id":"`+ActionSSHRootLogin+`","approved":true}`))
	request.Header.Set("Authorization", "Bearer "+testExecutionToken)
	recorder := httptest.NewRecorder()

	ExecuteHandler(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(recorder.Body.String(), testExecutionToken) {
		t.Fatal("response exposed the execution token")
	}
}

func TestRollbackHandlerRejectsRequestsBeforeRollback(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		token         string
		authorization string
		wantStatus    int
	}{
		{name: "unsupported method", method: http.MethodGet, token: testExecutionToken, authorization: "Bearer " + testExecutionToken, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing bearer token", method: http.MethodPost, token: testExecutionToken, wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer token", method: http.MethodPost, token: testExecutionToken, authorization: "Bearer wrong-token", wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			request := httptest.NewRequest(tt.method, "/rollback", nil)
			if tt.authorization != "" {
				request.Header.Set("Authorization", tt.authorization)
			}
			recorder := httptest.NewRecorder()

			rollbackHandler(recorder, request, tt.token, func() (ExecutionResult, error) {
				calls++
				return ExecutionResult{}, nil
			})

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			if calls != 0 {
				t.Fatalf("rollback calls = %d, want 0", calls)
			}
			if strings.Contains(recorder.Body.String(), testExecutionToken) {
				t.Fatal("response exposed the execution token")
			}
		})
	}
}

func TestRollbackHandlerDisablesExecutionWhenTokenIsUnset(t *testing.T) {
	t.Setenv("AGENT_EXECUTION_TOKEN", "")
	request := httptest.NewRequest(http.MethodPost, "/rollback", nil)
	request.Header.Set("Authorization", "Bearer "+testExecutionToken)
	recorder := httptest.NewRecorder()

	RollbackHandler(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(recorder.Body.String(), testExecutionToken) {
		t.Fatal("response exposed the execution token")
	}
}
