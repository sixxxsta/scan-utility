package notify_test

import (
	"strings"
	"testing"

	"github.com/scan-utility/scanner/internal/models"
	"github.com/scan-utility/scanner/internal/notify"
)

func TestFormatFinding(t *testing.T) {
	text := notify.FormatFinding(models.Finding{
		IP: "203.0.113.1", Port: 80, Proto: "tcp", State: "open",
		Diff: models.DiffNew, Service: "http", Product: "nginx", Version: "1.24",
		CVEs: []models.CVE{{CVEID: "CVE-2023-44487", CVSS: 7.5, Summary: "HTTP/2 Rapid Reset"}},
	})
	if !strings.Contains(text, "203.0.113.1:80/tcp") {
		t.Fatalf("missing host: %s", text)
	}
	if !strings.Contains(text, "CVE-2023-44487") {
		t.Fatalf("missing cve: %s", text)
	}
}
