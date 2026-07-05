package models

import (
	"strconv"
	"time"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

type DiffKind string

const (
	DiffNew       DiffKind = "new"
	DiffChanged   DiffKind = "changed"
	DiffClosed    DiffKind = "closed"
	DiffUnchanged DiffKind = "unchanged"
)

type ScanRun struct {
	ID          int64      `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Targets     string     `json:"targets"`
	Ports       string     `json:"ports"`
	Status      ScanStatus `json:"status"`
	ErrorMsg    string     `json:"error_msg,omitempty"`
	OpenCount   int        `json:"open_count"`
	NewCount    int        `json:"new_count"`
	ClosedCount int        `json:"closed_count"`
}

type Finding struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	State     string    `json:"state"`
	Service   string    `json:"service"`
	Banner    string    `json:"banner"`
	Product   string    `json:"product"`
	Version   string    `json:"version"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	IsOpen    bool      `json:"is_open"`
	Diff      DiffKind  `json:"diff,omitempty"`
	CVEs      []CVE     `json:"cves,omitempty"`
	Exploits  []Exploit `json:"exploits,omitempty"`
}

func (f Finding) Key() string {
	return f.IP + ":" + strconv.Itoa(f.Port) + "/" + f.Proto
}

type CVE struct {
	ID        int64   `json:"id"`
	FindingID int64   `json:"finding_id"`
	CVEID     string  `json:"cve_id"`
	CVSS      float64 `json:"cvss"`
	Summary   string  `json:"summary"`
	Source    string  `json:"source"`
}

type Exploit struct {
	ID        int64  `json:"id"`
	FindingID int64  `json:"finding_id"`
	EDBID     string `json:"edb_id"`
	Title     string `json:"title"`
	URL       string `json:"url"`
}

type Notification struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	Channel   string    `json:"channel"`
	SentAt    time.Time `json:"sent_at"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

type ScanStatusInfo struct {
	Running    bool     `json:"running"`
	CurrentRun *ScanRun `json:"current_run,omitempty"`
	Message    string   `json:"message,omitempty"`
}
