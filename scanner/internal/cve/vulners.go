package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		Search []struct {
			ID      string  `json:"id"`
			Title   string  `json:"title"`
			CVSS    float64 `json:"cvss"`
			Type    string  `json:"type"`
			Description string `json:"description"`
		} `json:"search"`
	} `json:"data"`
}

func (c *Client) Lookup(ctx context.Context, product, version string) ([]models.CVE, error) {
	product = strings.TrimSpace(product)
	version = strings.TrimSpace(version)
	if product == "" {
		return nil, nil
	}
	query := product
	if version != "" {
		query = product + " " + version
	}
	endpoint := c.BaseURL + "/search/lucene/"
	form := url.Values{}
	form.Set("query", query+" type:cve")
	form.Set("size", "10")
	if c.APIKey != "" {
		form.Set("apiKey", c.APIKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vulners status %d", resp.StatusCode)
	}
	var parsed searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []models.CVE
	for _, item := range parsed.Data.Search {
		id := item.ID
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		summary := item.Title
		if summary == "" {
			summary = item.Description
		}
		out = append(out, models.CVE{
			CVEID:   id,
			CVSS:    item.CVSS,
			Summary: summary,
			Source:  "vulners",
		})
	}
	return out, nil
}
