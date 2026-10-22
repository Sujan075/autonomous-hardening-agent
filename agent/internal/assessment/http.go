package assessment

import (
	"encoding/json"
	"net/http"
)

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	assessment := Assessment{
		Platform: PlatformUbuntu,
		Findings: AssessSSHControls(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(assessment)
}
