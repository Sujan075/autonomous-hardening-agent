package executor

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type ExecuteRequest struct {
	ActionID string `json:"action_id"`
	Approved bool   `json:"approved"`
}

func ExecuteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := requireExecutionAuthorization(r); err != nil {
		http.Error(w, err.Error(), err.status)
		return
	}

	var request ExecuteRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if !request.Approved {
		http.Error(w, "explicit approval required", http.StatusForbidden)
		return
	}

	if request.ActionID != ActionSSHRootLogin {
		http.Error(w, "action is not allowed", http.StatusForbidden)
		return
	}

	result, err := ApplySSHRootLoginDisable()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(result)
}

func RollbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := requireExecutionAuthorization(r); err != nil {
		http.Error(w, err.Error(), err.status)
		return
	}

	result, err := RollbackSSHRootLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(result)
}

type authorizationError struct {
	status  int
	message string
}

func (e *authorizationError) Error() string {
	return e.message
}

func requireExecutionAuthorization(r *http.Request) *authorizationError {
	expected := os.Getenv("AGENT_EXECUTION_TOKEN")

	if expected == "" {
		return &authorizationError{
			status:  http.StatusServiceUnavailable,
			message: "privileged execution is disabled: AGENT_EXECUTION_TOKEN is not configured",
		}
	}

	const prefix = "Bearer "

	header := r.Header.Get("Authorization")

	if !strings.HasPrefix(header, prefix) {
		return &authorizationError{
			status:  http.StatusUnauthorized,
			message: "valid execution authorization required",
		}
	}

	presented := strings.TrimPrefix(header, prefix)

	if len(presented) != len(expected) ||
		subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) != 1 {
		return &authorizationError{
			status:  http.StatusUnauthorized,
			message: "invalid execution authorization",
		}
	}

	return nil
}
