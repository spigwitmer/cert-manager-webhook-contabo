package main

import (
	"os"

	cmd "github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	"cert-manager-webhook-contabo/pkg/solver"
)

func main() {
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		groupName = "acme.contabo.com"
	}

	cmd.RunWebhookServer(groupName, solver.NewSolver())
}
