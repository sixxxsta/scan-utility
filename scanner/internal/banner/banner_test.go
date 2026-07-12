package banner_test

import (
	"testing"

	"github.com/scan-utility/scanner/internal/banner"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		svc, raw, wantSvc, wantProd, wantVer string
	}{
		{"", "nginx/1.18.0", "http", "nginx", "1.18.0"},
		{"", "Apache/2.4.57 (Unix)", "http", "Apache", "2.4.57"},
		{"ssh", "SSH-2.0-OpenSSH_9.2p1", "ssh", "OpenSSH", "9.2p1"},
	}
	for _, tc := range cases {
		svc, prod, ver := banner.Normalize(tc.svc, tc.raw)
		if svc != tc.wantSvc || prod != tc.wantProd || ver != tc.wantVer {
			t.Fatalf("%q => (%q,%q,%q) want (%q,%q,%q)", tc.raw, svc, prod, ver, tc.wantSvc, tc.wantProd, tc.wantVer)
		}
	}
}
