package nmap_test

import (
	"testing"

	"github.com/scan-utility/scanner/internal/config"
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

func TestApplyNSEXMLValidated(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <script id="ssl-heartbleed" output="VULNERABLE:&#xa;The SSL service seems vulnerable"/>
      </port>
    </ports>
  </host>
</nmaprun>`)
	f, err := nmap.ApplyNSEXML(models.Finding{Port: 443}, xml)
	if err != nil {
		t.Fatal(err)
	}
	if f.ValidationStatus != models.ValidationValidated {
		t.Fatalf("want validated, got %s (%s)", f.ValidationStatus, f.NSEOutput)
	}
}

func TestApplyNSEXMLNotConfirmed(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <script id="ssh2-enum-algos" output="kex_algorithms: (4)"/>
      </port>
    </ports>
  </host>
</nmaprun>`)
	f, err := nmap.ApplyNSEXML(models.Finding{Port: 22}, xml)
	if err != nil {
		t.Fatal(err)
	}
	if f.ValidationStatus != models.ValidationNotConfirmed {
		t.Fatalf("want not_confirmed, got %s", f.ValidationStatus)
	}
}

func TestSelectScripts(t *testing.T) {
	auto := true
	got := nmap.SelectScripts(config.NSEConfig{Enabled: true, Auto: &auto}, models.Finding{Port: 80, Service: "http"})
	if len(got) == 0 {
		t.Fatal("auto mode should pick http scripts")
	}
	found := false
	for _, s := range got {
		if s == "http-vuln*" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want http-vuln* in %v", got)
	}

	got = nmap.SelectScripts(config.NSEConfig{Enabled: true, Auto: &auto}, models.Finding{Port: 22})
	if len(got) == 0 {
		t.Fatal("port 22 should map to ssh profile")
	}

	off := false
	got = nmap.SelectScripts(config.NSEConfig{
		Enabled: true,
		Auto:    &off,
		Scripts: map[string][]string{"80": {"http-methods"}},
	}, models.Finding{Port: 80})
	if len(got) != 1 || got[0] != "http-methods" {
		t.Fatalf("custom only => %v", got)
	}
}
