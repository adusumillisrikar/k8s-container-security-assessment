// Known-good sample for org-go-shell-command-built-from-input: the corrected
// health-check handler from 06-remediation/remediation-advisory.md (item 3).
// The org Semgrep rules must report nothing on this file.
package main

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func pingHandler(c *fiber.Ctx) error {
	endpoint := strings.TrimSpace(c.FormValue("endpoint"))

	if net.ParseIP(endpoint) == nil && !hostnamePattern.MatchString(endpoint) {
		return c.Status(fiber.StatusBadRequest).Render("index", fiber.Map{
			"Title":  "Ping Your Servers",
			"Output": "Please enter a valid hostname or IP address.",
		})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ping", "-c", "2", "--", endpoint).CombinedOutput()

	result := string(output)
	if err != nil && result == "" {
		result = "Ping failed."
	}
	return c.Render("index", fiber.Map{"Title": "Ping Your Servers", "Output": result})
}
