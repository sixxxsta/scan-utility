package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Targets       TargetsConfig       `yaml:"targets"`
	Ports         string              `yaml:"ports"`
	Masscan       MasscanConfig       `yaml:"masscan"`
	Nmap          NmapConfig          `yaml:"nmap"`
	NSE           NSEConfig           `yaml:"nse"`
	Persistence   PersistenceConfig   `yaml:"persistence"`
	Notifications NotificationsConfig `yaml:"notifications"`
	Vulners       VulnersConfig       `yaml:"vulners"`
	ExploitDB     ExploitDBConfig     `yaml:"exploitdb"`
	Schedule      ScheduleConfig      `yaml:"schedule"`
	Server        ServerConfig        `yaml:"server"`
	Workers       int                 `yaml:"workers"`
	NotifyClosed  bool                `yaml:"notify_closed"`
	DryRun        bool                `yaml:"dry_run"`
}

type TargetsConfig struct {
	Ranges []string `yaml:"ranges"`
	ASNs   []int    `yaml:"asns"`
}

type MasscanConfig struct {
	Path         string `yaml:"path"`
	Rate         int    `yaml:"rate"`
	Banners      bool   `yaml:"banners"`
	Wait         int    `yaml:"wait"`
	FallbackNmap bool   `yaml:"fallback_nmap"`
}

type NmapConfig struct {
	Enabled bool     `yaml:"enabled"`
	Path    string   `yaml:"path"`
	Args    []string `yaml:"args"`
}

type NSEConfig struct {
	Enabled bool `yaml:"enabled"`
	Auto    *bool `yaml:"auto"`
	Scripts map[string][]string `yaml:"scripts"`
}

func (n NSEConfig) AutoEnabled() bool {
	if n.Auto == nil {
		return true
	}
	return *n.Auto
}

type PersistenceConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type NotificationsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Email    EmailConfig    `yaml:"email"`
}

type TelegramConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"`
	ChatIDEnv   string `yaml:"chat_id_env"`
}

type EmailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	Username string   `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type VulnersConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url"`
}

type ExploitDBConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"path"`
	MaxResults int    `yaml:"max_results"`
}

type ScheduleConfig struct {
	Cron string `yaml:"cron"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	return &Config{
		Ports: "22,80,443,3306,8080",
		Masscan: MasscanConfig{
			Path:         "masscan",
			Rate:         1000,
			Banners:      true,
			Wait:         10,
			FallbackNmap: true,
		},
		Nmap: NmapConfig{
			Enabled: true,
			Path:    "nmap",
			Args:    []string{"-sV", "-Pn", "--version-light"},
		},
		NSE: NSEConfig{
			Enabled: true,
		},
		Persistence: PersistenceConfig{
			SQLitePath: "data/scan.db",
		},
		Notifications: NotificationsConfig{
			Telegram: TelegramConfig{
				BotTokenEnv: "TELEGRAM_BOT_TOKEN",
				ChatIDEnv:   "TELEGRAM_CHAT_ID",
			},
			Email: EmailConfig{
				SMTPPort:    587,
				PasswordEnv: "SMTP_PASSWORD",
			},
		},
		Vulners: VulnersConfig{
			APIKeyEnv: "VULNERS_API_KEY",
			BaseURL:   "https://vulners.com/api/v3",
		},
		ExploitDB: ExploitDBConfig{
			Path:       "searchsploit",
			MaxResults: 5,
		},
		Schedule: ScheduleConfig{},
		Server: ServerConfig{
			Listen: ":8080",
		},
		Workers:      8,
		NotifyClosed: false,
	}
}

func (c *Config) Validate() error {
	if len(c.Targets.Ranges) == 0 && len(c.Targets.ASNs) == 0 {
		return fmt.Errorf("targets.ranges or targets.asns must be set")
	}
	if strings.TrimSpace(c.Ports) == "" {
		return fmt.Errorf("ports must be set")
	}
	if c.Masscan.Path == "" {
		c.Masscan.Path = "masscan"
	}
	if c.Masscan.Rate <= 0 {
		c.Masscan.Rate = 1000
	}
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.Persistence.SQLitePath == "" {
		c.Persistence.SQLitePath = "data/scan.db"
	}
	if c.Nmap.Path == "" {
		c.Nmap.Path = "nmap"
	}
	if c.Vulners.BaseURL == "" {
		c.Vulners.BaseURL = "https://vulners.com/api/v3"
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	return nil
}

func (c *Config) Env(name string) string {
	if name == "" {
		return ""
	}
	return os.Getenv(name)
}
