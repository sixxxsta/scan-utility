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
