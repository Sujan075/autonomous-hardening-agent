package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentHandlerExposesNoOperationalMutationRoutes(t *testing.T) {
	t.Setenv("AGENT_EXECUTION_TOKEN", "arbitrary-demo-token")
	handler := newHandler("agent-test")
	for _, path := range []string{"/execute", "/rollback"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, nil)
			request.Header.Set("Authorization", "Bearer arbitrary-demo-token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d, want 404", response.Code)
			}
		})
	}
}
