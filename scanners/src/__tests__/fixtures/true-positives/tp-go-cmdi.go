// tp-go-cmdi.go: Command injection via os/exec with user input
package main

import (
	"net/http"
	"os/exec"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// VULNERABLE: user input passed to shell via exec.Command
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	cmd.Run()
}
