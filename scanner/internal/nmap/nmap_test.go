package nmap_test

import (
	"testing"

	"github.com/scan-utility/scanner/internal/models"
	"github.com/scan-utility/scanner/internal/nmap"
)

func TestApplyXML(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
</nmaprun>`)
	f, err := nmap.ApplyXML(models.Finding{IP: "203.0.113.9", Port: 443, Proto: "tcp"}, xml)
	if err != nil {
		t.Fatal(err)
	}
	if f.Service != "https" || f.Product != "nginx" || f.Version != "1.24.0" {
		t.Fatalf("bad result: %+v", f)
	}
}
