package executor

import "net/http"

// ExecuteHandler is intentionally disabled. The production agent has no
// operational approval issuer/context provider or deployed privilege boundary;
// a bearer token and caller-supplied approved flag are not sufficient proof.
func ExecuteHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// RollbackHandler is intentionally disabled until recovery is dispatched only
// from a separately authorized and verified recovery manifest.
func RollbackHandler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
