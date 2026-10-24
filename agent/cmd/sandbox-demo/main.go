package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Sujan075/autonomous-hardening-agent/agent/internal/sandbox"
)

func main() {
	scenario := flag.String("scenario", "roundtrip", "fixed local fixture: roundtrip, compliant, or precedence-conflict")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sandbox-demo does not accept positional commands")
		os.Exit(2)
	}
	result, err := sandbox.Run(*scenario)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode sandbox result:", err)
		os.Exit(1)
	}
	if result.Status == "RECOVERY_FAILED" {
		os.Exit(1)
	}
}
