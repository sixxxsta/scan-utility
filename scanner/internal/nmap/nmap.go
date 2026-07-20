package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/scan-utility/scanner/internal/banner"
	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/models"
)

type Runner struct {
	Cfg config.NmapConfig
	NSE config.NSEConfig
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports struct {
		Port []nmapPort `xml:"port"`
	} `xml:"ports"`
	HostScript []nmapScript `xml:"hostscript>script"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
		Extra   string `xml:"extrainfo,attr"`
		Banner  string `xml:"banner,attr"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func (r *Runner) Enrich(ctx context.Context, f models.Finding) (models.Finding, error) {
	if !r.Cfg.Enabled {
		return f, nil
	}
	args := append([]string{}, r.Cfg.Args...)
	args = append(args, "-p", strconv.Itoa(f.Port), "-oX", "-", f.IP)

	cmd := exec.CommandContext(ctx, r.Cfg.Path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return f, fmt.Errorf("nmap: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return ApplyXML(f, stdout.Bytes())
}

func (r *Runner) Validate(ctx context.Context, f models.Finding) (models.Finding, error) {
	if !r.NSE.Enabled {
		f.ValidationStatus = models.ValidationNone
		return f, nil
	}
	scripts := SelectScripts(r.NSE, f)
	if len(scripts) == 0 {
		f.ValidationStatus = models.ValidationSkipped
		f.NSEScripts = ""
		f.NSEOutput = ""
		return f, nil
	}
	f.NSEScripts = strings.Join(scripts, ",")

	args := []string{
		"-Pn",
		"--script", strings.Join(scripts, ","),
		"-p", strconv.Itoa(f.Port),
		"-oX", "-",
		f.IP,
	}
	cmd := exec.CommandContext(ctx, r.Cfg.Path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		f.ValidationStatus = models.ValidationError
		f.NSEOutput = truncate(strings.TrimSpace(stderr.String()), 2000)
		return f, fmt.Errorf("nmap nse: %w (%s)", err, f.NSEOutput)
	}
	return ApplyNSEXML(f, stdout.Bytes())
}

func DefaultProfiles() map[string][]string {
	return map[string][]string{
		"http":  {"http-vuln*", "http-slowloris-check"},
		"https": {"http-vuln*", "ssl-*"},
		"ssl":   {"ssl-*"},
		"ssh":   {"ssh2-enum-algos", "ssh-auth-methods", "ssh-*"},
		"ftp":   {"ftp-*"},
		"smtp":  {"smtp-*"},
		"mysql": {"mysql-*"},
		"redis": {"redis-*"},
		"rdp":   {"rdp-*"},
		"smb":   {"smb-vuln*", "smb-*"},
	}
}

func SelectScripts(cfg config.NSEConfig, f models.Finding) []string {
	rules := map[string][]string{}
	if cfg.AutoEnabled() {
		for k, v := range DefaultProfiles() {
			rules[k] = append([]string{}, v...)
		}
	}
	for k, v := range cfg.Scripts {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		rules[key] = append(rules[key], v...)
	}
	if len(rules) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	var out []string
	addKey := func(key string) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		for _, s := range rules[key] {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	addKey(strconv.Itoa(f.Port))
	for _, key := range serviceFamilies(f) {
		addKey(key)
	}
	return out
}

func serviceFamilies(f models.Finding) []string {
	var keys []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return
		}
		keys = append(keys, s)
	}

	add(f.Service)
	add(f.Product)

	blob := strings.ToLower(f.Service + " " + f.Product + " " + f.Banner)
	switch {
	case f.Port == 22 || strings.Contains(blob, "ssh"):
		add("ssh")
	case f.Port == 21 || strings.Contains(blob, "ftp"):
		add("ftp")
	case f.Port == 25 || f.Port == 587 || strings.Contains(blob, "smtp"):
		add("smtp")
	case f.Port == 3306 || strings.Contains(blob, "mysql"):
		add("mysql")
	case f.Port == 6379 || strings.Contains(blob, "redis"):
		add("redis")
	case f.Port == 3389 || strings.Contains(blob, "rdp") || strings.Contains(blob, "ms-wbt"):
		add("rdp")
	case f.Port == 445 || f.Port == 139 || strings.Contains(blob, "smb") || strings.Contains(blob, "microsoft-ds"):
		add("smb")
	}

	switch f.Port {
	case 80, 8080, 8000, 8008, 8888:
		add("http")
	case 443, 8443, 9443:
		add("https")
		add("ssl")
		add("http")
	}

	if strings.Contains(blob, "https") || strings.Contains(blob, "ssl") || strings.Contains(blob, "tls") {
		add("https")
		add("ssl")
	}
	if strings.Contains(blob, "http") {
		add("http")
	}
	return keys
}

func ApplyXML(f models.Finding, data []byte) (models.Finding, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return f, err
	}
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			port, _ := strconv.Atoi(p.PortID)
			if port != f.Port {
				continue
			}
			if p.State.State != "" {
				f.State = p.State.State
				f.IsOpen = p.State.State == "open"
			}
			if p.Protocol != "" {
				f.Proto = p.Protocol
			}
			svc := p.Service.Name
			product := p.Service.Product
			version := p.Service.Version
			ban := strings.TrimSpace(strings.Join([]string{p.Service.Product, p.Service.Version, p.Service.Extra, p.Service.Banner}, " "))
			if ban != "" {
				f.Banner = ban
			}
			if product == "" || version == "" {
				ns, np, nv := banner.Normalize(svc, ban)
				if svc == "" {
					svc = ns
				}
				if product == "" {
					product = np
				}
				if version == "" {
					version = nv
				}
			}
			if svc != "" {
				f.Service = svc
			}
			if product != "" {
				f.Product = product
			}
			if version != "" {
				f.Version = version
			}
			return f, nil
		}
	}
	return f, nil
}

func ApplyNSEXML(f models.Finding, data []byte) (models.Finding, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		f.ValidationStatus = models.ValidationError
		return f, err
	}
	var parts []string
	vulnerable := false
	for _, h := range run.Hosts {
		for _, sc := range h.HostScript {
			line := formatScript(sc)
			if line != "" {
				parts = append(parts, line)
			}
			if scriptVulnerable(sc) {
				vulnerable = true
			}
		}
		for _, p := range h.Ports.Port {
			port, _ := strconv.Atoi(p.PortID)
			if f.Port != 0 && port != f.Port {
				continue
			}
			for _, sc := range p.Scripts {
				line := formatScript(sc)
				if line != "" {
					parts = append(parts, line)
				}
				if scriptVulnerable(sc) {
					vulnerable = true
				}
			}
		}
	}
	f.NSEOutput = truncate(strings.Join(parts, "\n"), 4000)
	if vulnerable {
		f.ValidationStatus = models.ValidationValidated
	} else {
		f.ValidationStatus = models.ValidationNotConfirmed
	}
	return f, nil
}

func formatScript(sc nmapScript) string {
	id := strings.TrimSpace(sc.ID)
	out := strings.TrimSpace(sc.Output)
	if id == "" && out == "" {
		return ""
	}
	if out == "" {
		return id
	}
	return id + ": " + out
}

func scriptVulnerable(sc nmapScript) bool {
	blob := strings.ToUpper(sc.ID + " " + sc.Output)
	if strings.Contains(blob, "NOT VULNERABLE") || strings.Contains(blob, "NOTVULNERABLE") {
		return false
	}
	return strings.Contains(blob, "VULNERABLE")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
