package notify

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/models"
	"github.com/scan-utility/scanner/internal/store"
)

type Notifier interface {
	Name() string
	Notify(ctx context.Context, finding models.Finding, text string) error
}

type Fanout struct {
	notifiers []Notifier
	store     *store.Store
}

func NewFanout(cfg *config.Config, st *store.Store) *Fanout {
	var ns []Notifier
	if cfg.Notifications.Telegram.Enabled {
		token := cfg.Env(cfg.Notifications.Telegram.BotTokenEnv)
		chat := cfg.Env(cfg.Notifications.Telegram.ChatIDEnv)
		if token != "" && chat != "" {
			ns = append(ns, &Telegram{Token: token, ChatID: chat, Client: &http.Client{Timeout: 15 * time.Second}})
		} else {
			log.Printf("telegram enabled but %s/%s empty", cfg.Notifications.Telegram.BotTokenEnv, cfg.Notifications.Telegram.ChatIDEnv)
		}
	}
	if cfg.Notifications.Email.Enabled {
		pass := cfg.Env(cfg.Notifications.Email.PasswordEnv)
		ns = append(ns, &Email{
			Host:     cfg.Notifications.Email.SMTPHost,
			Port:     cfg.Notifications.Email.SMTPPort,
			Username: cfg.Notifications.Email.Username,
			Password: pass,
			From:     cfg.Notifications.Email.From,
			To:       cfg.Notifications.Email.To,
		})
	}
	log.Printf("notifiers ready: %d", len(ns))
	return &Fanout{notifiers: ns, store: st}
}

func (f *Fanout) Send(ctx context.Context, finding models.Finding, notifyClosed bool) error {
	if finding.Diff == models.DiffUnchanged {
		return nil
	}
	if finding.Diff == models.DiffClosed && !notifyClosed {
		return nil
	}
	text := FormatFinding(finding)
	var errs []string
	for _, n := range f.notifiers {
		dedupe := fmt.Sprintf("%s|%s|%s|%s", n.Name(), finding.Key(), finding.Diff, finding.LastSeen.Format("2006-01-02"))
		if f.store != nil {
			ok, err := f.store.WasNotified(ctx, dedupe)
			if err == nil && ok {
				continue
			}
		}
		err := n.Notify(ctx, finding, text)
		status := "ok"
		if err != nil {
			status = "error"
			errs = append(errs, n.Name()+": "+err.Error())
		}
		if f.store != nil {
			_ = f.store.RecordNotification(ctx, finding.ID, n.Name(), status, text, dedupe)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func FormatFinding(f models.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s:%d/%s state=%s\n", strings.ToUpper(string(f.Diff)), f.IP, f.Port, f.Proto, f.State)
	if f.Service != "" {
		fmt.Fprintf(&b, "service: %s\n", f.Service)
	}
	if f.Product != "" || f.Version != "" {
		fmt.Fprintf(&b, "product: %s %s\n", f.Product, f.Version)
	}
	if f.ValidationStatus != "" && f.ValidationStatus != models.ValidationNone {
		fmt.Fprintf(&b, "validation: %s\n", f.ValidationStatus)
		if f.NSEScripts != "" {
			fmt.Fprintf(&b, "nse: %s\n", f.NSEScripts)
		}
	}
	if f.Banner != "" {
		fmt.Fprintf(&b, "banner: %s\n", truncate(f.Banner, 200))
	}
	if len(f.CVEs) > 0 {
		b.WriteString("CVEs:\n")
		for i, c := range f.CVEs {
			if i >= 5 {
				fmt.Fprintf(&b, "  ... +%d more\n", len(f.CVEs)-5)
				break
			}
			fmt.Fprintf(&b, "  %s (cvss %.1f) %s\n", c.CVEID, c.CVSS, truncate(c.Summary, 80))
		}
	}
	if len(f.Exploits) > 0 {
		b.WriteString("Exploits:\n")
		for i, e := range f.Exploits {
			if i >= 5 {
				fmt.Fprintf(&b, "  ... +%d more\n", len(f.Exploits)-5)
				break
			}
			fmt.Fprintf(&b, "  EDB-%s %s\n", e.EDBID, e.Title)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type Telegram struct {
	Token  string
	ChatID string
	Client *http.Client
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Notify(ctx context.Context, _ models.Finding, text string) error {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)
	form := url.Values{}
	form.Set("chat_id", t.ChatID)
	form.Set("text", text)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

type Email struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

func (e *Email) Name() string { return "email" }

func (e *Email) Notify(_ context.Context, f models.Finding, text string) error {
	if e.Host == "" || len(e.To) == 0 || e.From == "" {
		return fmt.Errorf("email not configured")
	}
	port := e.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", e.Host, port)
	subject := fmt.Sprintf("Scan alert: %s %s:%d/%s", f.Diff, f.IP, f.Port, f.Proto)
	msg := strings.Join([]string{
		"From: " + e.From,
		"To: " + strings.Join(e.To, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		text,
	}, "\r\n")

	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.Host)
	}
	return smtp.SendMail(addr, auth, e.From, e.To, []byte(msg))
}
