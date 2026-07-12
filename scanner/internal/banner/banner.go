package banner

import (
	"regexp"
	"strings"
)

var (
	reProductVersion = regexp.MustCompile(`(?i)([a-z0-9._+-]+)/([0-9]+(?:\.[0-9A-Za-z._+-]+)*)`)
	reSSH            = regexp.MustCompile(`(?i)SSH-2\.0-([^\s]+)`)
	reApache         = regexp.MustCompile(`(?i)Apache[/\s]([0-9.]+)`)
	reNginx          = regexp.MustCompile(`(?i)nginx[/\s]([0-9.]+)`)
	reOpenSSH        = regexp.MustCompile(`(?i)OpenSSH[_\s-]?([0-9.p]+)`)
)

func Normalize(service, raw string) (svc, product, version string) {
	svc = strings.TrimSpace(service)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return svc, "", ""
	}

	if m := reSSH.FindStringSubmatch(raw); len(m) == 2 {
		if svc == "" {
			svc = "ssh"
		}
		product = "OpenSSH"
		if om := reOpenSSH.FindStringSubmatch(m[1]); len(om) == 2 {
			version = om[1]
		} else {
			version = m[1]
		}
		return svc, product, version
	}
	if m := reApache.FindStringSubmatch(raw); len(m) == 2 {
		if svc == "" {
			svc = "http"
		}
		return svc, "Apache", m[1]
	}
	if m := reNginx.FindStringSubmatch(raw); len(m) == 2 {
		if svc == "" {
			svc = "http"
		}
		return svc, "nginx", m[1]
	}
	if m := reProductVersion.FindStringSubmatch(raw); len(m) == 3 {
		if svc == "" {
			svc = strings.ToLower(m[1])
		}
		return svc, m[1], m[2]
	}

	fields := strings.Fields(raw)
	if len(fields) > 0 && product == "" {
		product = fields[0]
	}
	return svc, product, version
}
