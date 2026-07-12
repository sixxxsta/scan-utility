package masscan_test

import (
	"testing"

	"github.com/scan-utility/scanner/internal/masscan"
)

func TestParseJSONArray(t *testing.T) {
	data := []byte(`[
  {"ip":"203.0.113.10","timestamp":"123","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64,"service":{"name":"http","banner":"nginx/1.24.0"}}]},
  {"ip":"203.0.113.11","timestamp":"124","ports":[{"port":22,"proto":"tcp","status":"open","service":{"name":"ssh","banner":"SSH-2.0-OpenSSH_8.9"}}]}
]`)
	findings, err := masscan.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
	if findings[0].IP != "203.0.113.10" || findings[0].Port != 80 {
		t.Fatalf("unexpected first finding: %+v", findings[0])
	}
	if findings[0].Product != "nginx" || findings[0].Version != "1.24.0" {
		t.Fatalf("banner normalize failed: %+v", findings[0])
	}
	if findings[1].Service != "ssh" {
		t.Fatalf("expected ssh, got %q", findings[1].Service)
	}
}

func TestParseList(t *testing.T) {
	data := []byte(`#masscan
open tcp 443 198.51.100.5 1710000000
open tcp 22 198.51.100.5 1710000001
`)
	findings, err := masscan.ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2, got %d", len(findings))
	}
	if findings[0].Port != 443 || findings[0].IP != "198.51.100.5" {
		t.Fatalf("unexpected: %+v", findings[0])
	}
}
