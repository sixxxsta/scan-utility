package cve_test

import (
	"context"
	"os"
	"testing"

	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/cve"
)

func TestLookupApacheLive(t *testing.T) {
	key := os.Getenv("VULNERS_API_KEY")
	if key == "" {
		t.Skip("VULNERS_API_KEY not set")
	}
	client := cve.New(config.VulnersConfig{BaseURL: "https://vulners.com/api/v3"}, key)
	got, err := client.Lookup(context.Background(), "Apache httpd", "2.4.49")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected CVE hits for Apache httpd 2.4.49")
	}
	found := false
	for _, c := range got {
		if c.CVEID == "CVE-2021-41773" {
			found = true
			break
		}
	}
	if !found {
		t.Logf("got %d CVEs, first=%s", len(got), got[0].CVEID)
	}
}
