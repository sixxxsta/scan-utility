package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Resolver struct {
	HTTP *http.Client
}

func New() *Resolver {
	return &Resolver{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type bgpViewResponse struct {
	Status string `json:"status"`
	Data   struct {
		IPv4Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
		IPv6Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
}

func (r *Resolver) Resolve(ctx context.Context, asn int) ([]string, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "scanutil/1.0")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bgpview status %d for AS%d", resp.StatusCode, asn)
	}
	var parsed bgpViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range parsed.Data.IPv4Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

func (r *Resolver) ResolveMany(ctx context.Context, asns []int) ([]string, error) {
	var all []string
	seen := map[string]struct{}{}
	for _, asn := range asns {
		prefixes, err := r.Resolve(ctx, asn)
		if err != nil {
			return nil, err
		}
		for _, p := range prefixes {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			all = append(all, p)
		}
	}
	return all, nil
}
