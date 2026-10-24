package executor

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecuteAndRollbackHandlersRemainUnavailableEvenWithCallerApproval(t *testing.T) {
	// This regression keeps an arbitrary environment token from enabling the
	// legacy approved-boolean API. The authenticated approval path is not wired.
	t.Setenv("AGENT_EXECUTION_TOKEN", "arbitrary-demo-token")
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{path: "/execute", handler: ExecuteHandler},
		{path: "/rollback", handler: RollbackHandler},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, endpoint.path, nil)
			request.Header.Set("Authorization", "Bearer arbitrary-demo-token")
			request.Header.Set("Content-Type", "application/json")
			request.Body = http.NoBody
			response := httptest.NewRecorder()
			endpoint.handler(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d, want 404", response.Code)
			}
		})
	}
}
