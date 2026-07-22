package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/models"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(cfg config.VulnersConfig, apiKey string) *Client {
	base := cfg.BaseURL
	if base == "" {
		base = "https://vulners.com/api/v3"
	}
	return &Client{
		BaseURL: strings.TrimRight(base, "/"),
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

type searchResponse struct {
	Result string `json:"result"`
	Data   struct {
		Search []searchHit `json:"search"`
	} `json:"data"`
}

type searchHit struct {
	ID     string `json:"_id"`
	Source struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Type        string `json:"type"`
		CVSS        any    `json:"cvss"`
	} `json:"_source"`
	FlatDescription string `json:"flatDescription"`
}

var versionRe = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

func (c *Client) Lookup(ctx context.Context, product, version string) ([]models.CVE, error) {
	product = strings.TrimSpace(product)
	version = strings.TrimSpace(version)
	if product == "" {
		return nil, nil
	}
	if m := versionRe.FindString(version); m != "" {
		version = m
	}
	query := product
	if version != "" {
		query = product + " " + version
	}
	query += " type:cve"

	body, err := json.Marshal(map[string]any{
		"query": query,
		"size":  10,
	})
	if err != nil {
		return nil, err
	}

	endpoint := c.BaseURL + "/search/lucene/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vulners status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed searchResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	if parsed.Result != "" && !strings.EqualFold(parsed.Result, "OK") {
		return nil, fmt.Errorf("vulners result %s", parsed.Result)
	}

	var out []models.CVE
	for _, item := range parsed.Data.Search {
		id := item.Source.ID
		if id == "" {
			id = item.ID
		}
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		summary := item.Source.Description
		if summary == "" {
			summary = item.FlatDescription
		}
		if summary == "" {
			summary = item.Source.Title
		}
		out = append(out, models.CVE{
			CVEID:   id,
			CVSS:    cvssScore(item.Source.CVSS),
			Summary: summary,
			Source:  "vulners",
		})
	}
	return out, nil
}

func cvssScore(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case map[string]any:
		if s, ok := t["score"].(float64); ok {
			return s
		}
	}
	return 0
}
