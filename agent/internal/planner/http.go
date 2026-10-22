package planner

import (
	"encoding/json"
	"net/http"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findings := assessment.AssessSSHControls()
	plan := BuildSSHPlan(findings)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"platform": "ubuntu",
		"findings": findings,
		"plan":     plan,
	})
}
