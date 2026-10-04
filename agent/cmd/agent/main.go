package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		agentID = "agent-dev"
	}

	host := os.Getenv("AGENT_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	port := os.Getenv("AGENT_PORT")
	if port == "" {
		port = "9000"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": agentID,
			"status":   "online",
		})
	})

	addr := host + ":" + port

	log.Printf("agent_id=%s listening=%s", agentID, addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
