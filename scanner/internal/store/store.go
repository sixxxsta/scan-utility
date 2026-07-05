package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scan-utility/scanner/internal/models"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) Migrate(ctx context.Context) error {
	schema := `
CREATE TABLE IF NOT EXISTS scan_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	targets TEXT NOT NULL,
	ports TEXT NOT NULL,
	status TEXT NOT NULL,
	error_msg TEXT DEFAULT '',
	open_count INTEGER DEFAULT 0,
	new_count INTEGER DEFAULT 0,
	closed_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	proto TEXT NOT NULL,
	state TEXT NOT NULL,
	service TEXT DEFAULT '',
	banner TEXT DEFAULT '',
	product TEXT DEFAULT '',
	version TEXT DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	is_open INTEGER NOT NULL DEFAULT 1,
	UNIQUE(ip, port, proto)
);

CREATE TABLE IF NOT EXISTS cves (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id INTEGER NOT NULL,
	cve_id TEXT NOT NULL,
	cvss REAL DEFAULT 0,
	summary TEXT DEFAULT '',
	source TEXT DEFAULT 'vulners',
	UNIQUE(finding_id, cve_id),
	FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exploits (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id INTEGER NOT NULL,
	edb_id TEXT NOT NULL,
	title TEXT DEFAULT '',
	url TEXT DEFAULT '',
	UNIQUE(finding_id, edb_id),
	FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	finding_id INTEGER NOT NULL,
	channel TEXT NOT NULL,
	sent_at TEXT NOT NULL,
	status TEXT NOT NULL,
	message TEXT DEFAULT '',
	dedupe_key TEXT NOT NULL,
	UNIQUE(dedupe_key),
	FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(is_open);
CREATE INDEX IF NOT EXISTS idx_findings_ip ON findings(ip);
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) CreateRun(ctx context.Context, targets, ports string) (*models.ScanRun, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scan_runs(started_at, targets, ports, status) VALUES(?,?,?,?)`,
		now.Format(time.RFC3339Nano), targets, ports, models.ScanStatusRunning,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.ScanRun{
		ID:        id,
		StartedAt: now,
		Targets:   targets,
		Ports:     ports,
		Status:    models.ScanStatusRunning,
	}, nil
}

func (s *Store) FinishRun(ctx context.Context, run *models.ScanRun) error {
	now := time.Now().UTC()
	run.FinishedAt = &now
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET finished_at=?, status=?, error_msg=?, open_count=?, new_count=?, closed_count=? WHERE id=?`,
		now.Format(time.RFC3339Nano), run.Status, run.ErrorMsg, run.OpenCount, run.NewCount, run.ClosedCount, run.ID,
	)
	return err
}

func (s *Store) ListRuns(ctx context.Context, limit int) ([]models.ScanRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, started_at, finished_at, targets, ports, status, error_msg, open_count, new_count, closed_count
		 FROM scan_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ScanRun
	for rows.Next() {
		var r models.ScanRun
		var started, finished sql.NullString
		if err := rows.Scan(&r.ID, &started, &finished, &r.Targets, &r.Ports, &r.Status, &r.ErrorMsg, &r.OpenCount, &r.NewCount, &r.ClosedCount); err != nil {
			return nil, err
		}
		r.StartedAt, _ = time.Parse(time.RFC3339Nano, started.String)
		if finished.Valid && finished.String != "" {
			t, _ := time.Parse(time.RFC3339Nano, finished.String)
			r.FinishedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRun(ctx context.Context, id int64) (*models.ScanRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, started_at, finished_at, targets, ports, status, error_msg, open_count, new_count, closed_count
		 FROM scan_runs WHERE id=?`, id)
	var r models.ScanRun
	var started, finished sql.NullString
	if err := row.Scan(&r.ID, &started, &finished, &r.Targets, &r.Ports, &r.Status, &r.ErrorMsg, &r.OpenCount, &r.NewCount, &r.ClosedCount); err != nil {
		return nil, err
	}
	r.StartedAt, _ = time.Parse(time.RFC3339Nano, started.String)
	if finished.Valid && finished.String != "" {
		t, _ := time.Parse(time.RFC3339Nano, finished.String)
		r.FinishedAt = &t
	}
	return &r, nil
}

func (s *Store) DiffAndUpsert(ctx context.Context, current []models.Finding) ([]models.Finding, error) {
	prev, err := s.ListOpenFindings(ctx)
	if err != nil {
		return nil, err
	}
	prevMap := map[string]models.Finding{}
	for _, f := range prev {
		prevMap[f.Key()] = f
	}

	now := time.Now().UTC()
	seen := map[string]struct{}{}
	var result []models.Finding

	for _, f := range current {
		if f.Proto == "" {
			f.Proto = "tcp"
		}
		if f.State == "" {
			f.State = "open"
		}
		f.IsOpen = true
		f.LastSeen = now
		key := f.Key()
		seen[key] = struct{}{}

		if old, ok := prevMap[key]; ok {
			f.ID = old.ID
			f.FirstSeen = old.FirstSeen
			changed := old.Service != f.Service || old.Banner != f.Banner || old.Product != f.Product || old.Version != f.Version
			if changed {
				f.Diff = models.DiffChanged
			} else {
				f.Diff = models.DiffUnchanged
				if f.Service == "" {
					f.Service = old.Service
				}
				if f.Banner == "" {
					f.Banner = old.Banner
				}
				if f.Product == "" {
					f.Product = old.Product
				}
				if f.Version == "" {
					f.Version = old.Version
				}
			}
		} else {
			f.FirstSeen = now
			f.Diff = models.DiffNew
		}

		id, err := s.upsertFinding(ctx, f)
		if err != nil {
			return nil, err
		}
		f.ID = id
		result = append(result, f)
	}

	for key, old := range prevMap {
		if _, ok := seen[key]; ok {
			continue
		}
		old.IsOpen = false
		old.State = "closed"
		old.Diff = models.DiffClosed
		old.LastSeen = now
		if _, err := s.upsertFinding(ctx, old); err != nil {
			return nil, err
		}
		result = append(result, old)
	}

	return result, nil
}

func (s *Store) upsertFinding(ctx context.Context, f models.Finding) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO findings(ip, port, proto, state, service, banner, product, version, first_seen, last_seen, is_open)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(ip, port, proto) DO UPDATE SET
	state=excluded.state,
	service=CASE WHEN excluded.service='' THEN findings.service ELSE excluded.service END,
	banner=CASE WHEN excluded.banner='' THEN findings.banner ELSE excluded.banner END,
	product=CASE WHEN excluded.product='' THEN findings.product ELSE excluded.product END,
	version=CASE WHEN excluded.version='' THEN findings.version ELSE excluded.version END,
	last_seen=excluded.last_seen,
	is_open=excluded.is_open
`, f.IP, f.Port, f.Proto, f.State, f.Service, f.Banner, f.Product, f.Version,
		f.FirstSeen.Format(time.RFC3339Nano), f.LastSeen.Format(time.RFC3339Nano), boolToInt(f.IsOpen))
	if err != nil {
		return 0, err
	}
	if f.ID > 0 {
		return f.ID, nil
	}
	id, err := res.LastInsertId()
	if err != nil || id == 0 {
		row := s.db.QueryRowContext(ctx, `SELECT id FROM findings WHERE ip=? AND port=? AND proto=?`, f.IP, f.Port, f.Proto)
		if err := row.Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (s *Store) UpdateFindingEnrichment(ctx context.Context, f models.Finding) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET service=?, banner=?, product=?, version=?, last_seen=? WHERE id=?`,
		f.Service, f.Banner, f.Product, f.Version, f.LastSeen.Format(time.RFC3339Nano), f.ID,
	)
	return err
}

func (s *Store) ListOpenFindings(ctx context.Context) ([]models.Finding, error) {
	return s.queryFindings(ctx, `SELECT id, ip, port, proto, state, service, banner, product, version, first_seen, last_seen, is_open FROM findings WHERE is_open=1`)
}

func (s *Store) ListFindings(ctx context.Context, filter FindingFilter) ([]models.Finding, error) {
	var clauses []string
	var args []any
	if filter.OnlyOpen {
		clauses = append(clauses, "is_open=1")
	}
	if filter.OnlyNew {
		clauses = append(clauses, "first_seen = last_seen")
	}
	if filter.IP != "" {
		clauses = append(clauses, "ip=?")
		args = append(args, filter.IP)
	}
	q := `SELECT id, ip, port, proto, state, service, banner, product, version, first_seen, last_seen, is_open FROM findings`
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY last_seen DESC"
	if filter.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	findings, err := s.queryFindings(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	for i := range findings {
		cves, _ := s.ListCVEs(ctx, findings[i].ID)
		exps, _ := s.ListExploits(ctx, findings[i].ID)
		findings[i].CVEs = cves
		findings[i].Exploits = exps
		if filter.HasCVE && len(cves) == 0 {
			continue
		}
		if filter.HasExploit && len(exps) == 0 {
			continue
		}
	}
	if filter.HasCVE || filter.HasExploit {
		var filtered []models.Finding
		for _, f := range findings {
			if filter.HasCVE && len(f.CVEs) == 0 {
				continue
			}
			if filter.HasExploit && len(f.Exploits) == 0 {
				continue
			}
			filtered = append(filtered, f)
		}
		return filtered, nil
	}
	return findings, nil
}

type FindingFilter struct {
	OnlyOpen   bool
	OnlyNew    bool
	HasCVE     bool
	HasExploit bool
	IP         string
	Limit      int
}

func (s *Store) queryFindings(ctx context.Context, q string, args ...any) ([]models.Finding, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Finding
	for rows.Next() {
		var f models.Finding
		var first, last string
		var open int
		if err := rows.Scan(&f.ID, &f.IP, &f.Port, &f.Proto, &f.State, &f.Service, &f.Banner, &f.Product, &f.Version, &first, &last, &open); err != nil {
			return nil, err
		}
		f.FirstSeen, _ = time.Parse(time.RFC3339Nano, first)
		f.LastSeen, _ = time.Parse(time.RFC3339Nano, last)
		f.IsOpen = open == 1
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) SaveCVEs(ctx context.Context, findingID int64, cves []models.CVE) error {
	for _, c := range cves {
		_, err := s.db.ExecContext(ctx, `
INSERT INTO cves(finding_id, cve_id, cvss, summary, source) VALUES(?,?,?,?,?)
ON CONFLICT(finding_id, cve_id) DO UPDATE SET cvss=excluded.cvss, summary=excluded.summary
`, findingID, c.CVEID, c.CVSS, c.Summary, c.Source)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListCVEs(ctx context.Context, findingID int64) ([]models.CVE, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, finding_id, cve_id, cvss, summary, source FROM cves WHERE finding_id=?`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CVE
	for rows.Next() {
		var c models.CVE
		if err := rows.Scan(&c.ID, &c.FindingID, &c.CVEID, &c.CVSS, &c.Summary, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SaveExploits(ctx context.Context, findingID int64, exps []models.Exploit) error {
	for _, e := range exps {
		_, err := s.db.ExecContext(ctx, `
INSERT INTO exploits(finding_id, edb_id, title, url) VALUES(?,?,?,?)
ON CONFLICT(finding_id, edb_id) DO UPDATE SET title=excluded.title, url=excluded.url
`, findingID, e.EDBID, e.Title, e.URL)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListExploits(ctx context.Context, findingID int64) ([]models.Exploit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, finding_id, edb_id, title, url FROM exploits WHERE finding_id=?`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Exploit
	for rows.Next() {
		var e models.Exploit
		if err := rows.Scan(&e.ID, &e.FindingID, &e.EDBID, &e.Title, &e.URL); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) WasNotified(ctx context.Context, dedupeKey string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM notifications WHERE dedupe_key=?`, dedupeKey).Scan(&n)
	return n > 0, err
}

func (s *Store) RecordNotification(ctx context.Context, findingID int64, channel, status, message, dedupeKey string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO notifications(finding_id, channel, sent_at, status, message, dedupe_key)
VALUES(?,?,?,?,?,?)
`, findingID, channel, time.Now().UTC().Format(time.RFC3339Nano), status, message, dedupeKey)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
