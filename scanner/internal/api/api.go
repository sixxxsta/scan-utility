package api

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/scan-utility/scanner/internal/orchestrator"
	"github.com/scan-utility/scanner/internal/store"
)

type Server struct {
	Orch      *orchestrator.Orchestrator
	Store     *store.Store
	WebDir    string
	templates *template.Template
}

func New(orch *orchestrator.Orchestrator, st *store.Store, webDir string) (*Server, error) {
	s := &Server{Orch: orch, Store: st, WebDir: webDir}
	tmpl, err := template.ParseGlob(webDir + "/*.html")
	if err != nil {
		return nil, err
	}
	s.templates = tmpl
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/findings", s.handleFindingsPage)
	mux.HandleFunc("/hosts/", s.handleHostPage)
	mux.HandleFunc("/api/runs", s.handleRuns)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(s.WebDir+"/static"))))
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	runs, _ := s.Store.ListRuns(r.Context(), 20)
	status := s.Orch.Status()
	_ = s.templates.ExecuteTemplate(w, "index.html", map[string]any{
		"Runs":   runs,
		"Status": status,
	})
}

func (s *Server) handleFindingsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.FindingFilter{
		OnlyOpen:   q.Get("open") != "0",
		OnlyNew:    q.Get("new") == "1",
		HasCVE:     q.Get("cve") == "1",
		HasExploit: q.Get("exploit") == "1",
		IP:         q.Get("ip"),
		Limit:      200,
	}
	findings, _ := s.Store.ListFindings(r.Context(), filter)
	_ = s.templates.ExecuteTemplate(w, "findings.html", map[string]any{
		"Findings": findings,
		"Filter":   filter,
	})
}

func (s *Server) handleHostPage(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/hosts/")
	ip = strings.Trim(ip, "/")
	if ip == "" {
		http.NotFound(w, r)
		return
	}
	findings, _ := s.Store.ListFindings(r.Context(), store.FindingFilter{IP: ip, Limit: 500})
	_ = s.templates.ExecuteTemplate(w, "host.html", map[string]any{
		"IP":       ip,
		"Findings": findings,
	})
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.Store.ListRuns(r.Context(), 50)
	if err != nil {
		writeErr(w, err, 500)
		return
	}
	writeJSON(w, runs)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := store.FindingFilter{
		OnlyOpen:   q.Get("open") != "0",
		OnlyNew:    q.Get("new") == "1",
		HasCVE:     q.Get("cve") == "1",
		HasExploit: q.Get("exploit") == "1",
		IP:         q.Get("ip"),
		Limit:      limit,
	}
	findings, err := s.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeErr(w, err, 500)
		return
	}
	writeJSON(w, findings)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Orch.Status())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		if _, err := s.Orch.Run(context.Background()); err != nil {
			log.Printf("manual scan: %v", err)
		}
	}()
	writeJSON(w, map[string]string{"status": "started"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error, code int) {
	http.Error(w, err.Error(), code)
}
