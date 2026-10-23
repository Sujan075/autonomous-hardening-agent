package executor

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

type ExecuteRequest struct {
	ActionID string `json:"action_id"`
	Approved bool   `json:"approved"`
}

func ExecuteHandler(w http.ResponseWriter, r *http.Request) {
	executeHandler(w, r, os.Getenv("AGENT_EXECUTION_TOKEN"), ApplySSHRootLoginDisable)
}

func executeHandler(w http.ResponseWriter, r *http.Request, expectedToken string, execute func() (ExecutionResult, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := requireExecutionAuthorization(r, expectedToken); err != nil {
		http.Error(w, err.Error(), err.status)
		return
	}

	var request ExecuteRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := requireJSONEnd(decoder); err != nil {
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

	result, err := execute()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(result)
}

func RollbackHandler(w http.ResponseWriter, r *http.Request) {
	rollbackHandler(w, r, os.Getenv("AGENT_EXECUTION_TOKEN"), RollbackSSHRootLogin)
}

func rollbackHandler(w http.ResponseWriter, r *http.Request, expectedToken string, rollback func() (ExecutionResult, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := requireExecutionAuthorization(r, expectedToken); err != nil {
		http.Error(w, err.Error(), err.status)
		return
	}

	result, err := rollback()
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

func requireExecutionAuthorization(r *http.Request, expected string) *authorizationError {
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

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("unexpected trailing JSON value")
	} else if err != io.EOF {
		return err
	}
	return nil
}
