package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/assessment"
)

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	PrimaryIP    string `json:"primary_ip"`
}

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

	http.HandleFunc("/assessment", assessment.HTTPHandler)

	http.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		hostname, err := os.Hostname()
		if err != nil {
			http.Error(w, "failed to read hostname", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SystemInfo{
			Hostname:     hostname,
			OS:           runtime.GOOS,
			OSVersion:    readOSVersion(),
			Kernel:       readKernel(),
			Architecture: runtime.GOARCH,
			PrimaryIP:    detectPrimaryIP(),
		})
	})

	addr := host + ":" + port

	log.Printf("agent_id=%s listening=%s", agentID, addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

func readOSVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return "unknown"
}

func readKernel() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func detectPrimaryIP() string {
	conn, err := net.Dial("udp", "192.168.64.1:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "unknown"
	}

	return localAddr.IP.String()
}
