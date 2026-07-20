package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/scan-utility/scanner/internal/asn"
	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/cve"
	"github.com/scan-utility/scanner/internal/exploitdb"
	"github.com/scan-utility/scanner/internal/masscan"
	"github.com/scan-utility/scanner/internal/models"
	"github.com/scan-utility/scanner/internal/nmap"
	"github.com/scan-utility/scanner/internal/notify"
	"github.com/scan-utility/scanner/internal/store"
)

type Orchestrator struct {
	Cfg      *config.Config
	Store    *store.Store
	Masscan  *masscan.Runner
	Nmap     *nmap.Runner
	CVE      *cve.Client
	Exploit  *exploitdb.Client
	ASN      *asn.Resolver
	Notify   *notify.Fanout

	mu      sync.Mutex
	running bool
	current *models.ScanRun
	message string
}

func New(cfg *config.Config, st *store.Store) (*Orchestrator, error) {
	o := &Orchestrator{
		Cfg:     cfg,
		Store:   st,
		Masscan: &masscan.Runner{Cfg: cfg.Masscan},
		Nmap:    &nmap.Runner{Cfg: cfg.Nmap, NSE: cfg.NSE},
		ASN:     asn.New(),
		Notify:  notify.NewFanout(cfg, st),
	}
	if cfg.Vulners.Enabled {
		o.CVE = cve.New(cfg.Vulners, cfg.Env(cfg.Vulners.APIKeyEnv))
	}
	if cfg.ExploitDB.Enabled {
		o.Exploit = exploitdb.New(cfg.ExploitDB)
	}
	return o, nil
}

func (o *Orchestrator) Status() models.ScanStatusInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	info := models.ScanStatusInfo{Running: o.running, Message: o.message}
	if o.current != nil {
		cp := *o.current
		info.CurrentRun = &cp
	}
	return info
}

func (o *Orchestrator) Run(ctx context.Context) (*models.ScanRun, error) {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return nil, fmt.Errorf("scan already running")
	}
	o.running = true
	o.message = "resolving targets"
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.running = false
		o.message = ""
		o.mu.Unlock()
	}()

	targets, err := o.resolveTargets(ctx)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets resolved")
	}

	run, err := o.Store.CreateRun(ctx, strings.Join(targets, ","), o.Cfg.Ports)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.current = run
	o.message = "masscan"
	o.mu.Unlock()

	var findings []models.Finding
	if o.Cfg.DryRun {
		log.Printf("dry_run: skipping masscan for targets=%v ports=%s", targets, o.Cfg.Ports)
		findings = nil
	} else {
		findings, err = o.Masscan.Scan(ctx, targets, o.Cfg.Ports)
		if err != nil {
			run.Status = models.ScanStatusFailed
			run.ErrorMsg = err.Error()
			_ = o.Store.FinishRun(ctx, run)
			return run, err
		}
	}

	o.setMessage("diff")
	diffed, err := o.Store.DiffAndUpsert(ctx, findings)
	if err != nil {
		run.Status = models.ScanStatusFailed
		run.ErrorMsg = err.Error()
		_ = o.Store.FinishRun(ctx, run)
		return run, err
	}

	var toEnrich []models.Finding
	for _, f := range diffed {
		if f.Diff == models.DiffNew || f.Diff == models.DiffChanged {
			toEnrich = append(toEnrich, f)
		}
		if f.IsOpen {
			run.OpenCount++
		}
		switch f.Diff {
		case models.DiffNew:
			run.NewCount++
		case models.DiffClosed:
			run.ClosedCount++
		}
	}

	o.setMessage("enrich")
	enriched, err := o.enrichAll(ctx, toEnrich)
	if err != nil {
		log.Printf("enrich: %v", err)
	}

	o.setMessage("notify")
	for _, f := range enriched {
		if err := o.Notify.Send(ctx, f, o.Cfg.NotifyClosed); err != nil {
			log.Printf("notify: %v", err)
		}
	}
	if o.Cfg.NotifyClosed {
		for _, f := range diffed {
			if f.Diff == models.DiffClosed {
				if err := o.Notify.Send(ctx, f, true); err != nil {
					log.Printf("notify closed: %v", err)
				}
			}
		}
	}

	run.Status = models.ScanStatusCompleted
	if err := o.Store.FinishRun(ctx, run); err != nil {
		return run, err
	}
	o.mu.Lock()
	o.current = run
	o.mu.Unlock()
	return run, nil
}

func (o *Orchestrator) resolveTargets(ctx context.Context) ([]string, error) {
	var targets []string
	targets = append(targets, o.Cfg.Targets.Ranges...)
	if len(o.Cfg.Targets.ASNs) > 0 {
		prefixes, err := o.ASN.ResolveMany(ctx, o.Cfg.Targets.ASNs)
		if err != nil {
			return nil, fmt.Errorf("asn resolve: %w", err)
		}
		targets = append(targets, prefixes...)
	}
	return targets, nil
}

func (o *Orchestrator) enrichAll(ctx context.Context, items []models.Finding) ([]models.Finding, error) {
	if len(items) == 0 {
		return nil, nil
	}
	workers := o.Cfg.Workers
	if workers <= 0 {
		workers = 8
	}
	out := make([]models.Finding, len(items))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	var mu sync.Mutex
	var errs []string

	for i := range items {
		i := i
		g.Go(func() error {
			f := items[i]
			var enrichErr error
			if o.Nmap != nil && o.Cfg.Nmap.Enabled {
				nf, err := o.Nmap.Enrich(ctx, f)
				if err != nil {
					enrichErr = err
				} else {
					f = nf
				}
			}
			if o.Nmap != nil && o.Cfg.NSE.Enabled {
				vf, err := o.Nmap.Validate(ctx, f)
				if err != nil {
					enrichErr = joinErr(enrichErr, err)
					f = vf
				} else {
					f = vf
				}
			} else if f.ValidationStatus == "" {
				f.ValidationStatus = models.ValidationNone
			}
			if o.CVE != nil && o.Cfg.Vulners.Enabled {
				cves, err := o.CVE.Lookup(ctx, f.Product, f.Version)
				if err != nil {
					enrichErr = joinErr(enrichErr, err)
				} else {
					f.CVEs = cves
					_ = o.Store.SaveCVEs(ctx, f.ID, cves)
				}
			}
			if o.Exploit != nil && o.Cfg.ExploitDB.Enabled {
				exps, err := o.Exploit.Match(ctx, f)
				if err != nil {
					enrichErr = joinErr(enrichErr, err)
				} else {
					f.Exploits = exps
					_ = o.Store.SaveExploits(ctx, f.ID, exps)
				}
			}
			f.LastSeen = time.Now().UTC()
			_ = o.Store.UpdateFindingEnrichment(ctx, f)
			out[i] = f
			if enrichErr != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", f.Key(), enrichErr))
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	if len(errs) > 0 {
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func (o *Orchestrator) setMessage(msg string) {
	o.mu.Lock()
	o.message = msg
	o.mu.Unlock()
}

func joinErr(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return fmt.Errorf("%v; %v", a, b)
}
