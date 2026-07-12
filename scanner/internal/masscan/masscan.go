package masscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/scan-utility/scanner/internal/banner"
	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/models"
)

type Runner struct {
	Cfg config.MasscanConfig
}

type jsonRecord struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
		Service struct {
			Name   string `json:"name"`
			Banner string `json:"banner"`
		} `json:"service"`
	} `json:"ports"`
}

func (r *Runner) Scan(ctx context.Context, targets []string, ports string) ([]models.Finding, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	tmpDir, err := os.MkdirTemp("", "masscan-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	outFile := filepath.Join(tmpDir, "out.json")

	args := []string{
		"-p", ports,
		"--rate", strconv.Itoa(r.Cfg.Rate),
		"-oJ", outFile,
		"--wait", strconv.Itoa(max(r.Cfg.Wait, 1)),
	}
	if r.Cfg.Banners {
		args = append(args, "--banners")
	}
	args = append(args, targets...)

	cmd := exec.CommandContext(ctx, r.Cfg.Path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr

	if err := cmd.Run(); err != nil {
		if _, statErr := os.Stat(outFile); statErr != nil {
			return nil, fmt.Errorf("masscan failed: %w; stderr: %s", err, stderr.String())
		}
	}

	return ParseJSONFile(outFile)
}

func ParseJSONFile(path string) ([]models.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseJSON(data)
}

func ParseJSON(data []byte) ([]models.Finding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	var records []jsonRecord
	if err := json.Unmarshal(data, &records); err == nil {
		return recordsToFindings(records), nil
	}

	var findings []models.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimSuffix(line, ",")
		if line == "" || line == "[" || line == "]" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec jsonRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		findings = append(findings, recordsToFindings([]jsonRecord{rec})...)
	}
	return findings, sc.Err()
}

func ParseList(data []byte) ([]models.Finding, error) {
	var findings []models.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		if parts[0] != "open" {
			continue
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		findings = append(findings, models.Finding{
			IP:    parts[3],
			Port:  port,
			Proto: parts[1],
			State: "open",
			IsOpen: true,
		})
	}
	return findings, sc.Err()
}

func recordsToFindings(records []jsonRecord) []models.Finding {
	var out []models.Finding
	for _, rec := range records {
		for _, p := range rec.Ports {
			state := p.Status
			if state == "" {
				state = "open"
			}
			svc := p.Service.Name
			ban := p.Service.Banner
			svc, product, version := banner.Normalize(svc, ban)
			out = append(out, models.Finding{
				IP:      rec.IP,
				Port:    p.Port,
				Proto:   defaultProto(p.Proto),
				State:   state,
				Service: svc,
				Banner:  ban,
				Product: product,
				Version: version,
				IsOpen:  state == "open",
			})
		}
	}
	return out
}

func defaultProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
