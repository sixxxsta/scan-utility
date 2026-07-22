package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/scan-utility/scanner/internal/api"
	"github.com/scan-utility/scanner/internal/config"
	"github.com/scan-utility/scanner/internal/orchestrator"
	"github.com/scan-utility/scanner/internal/scheduler"
	"github.com/scan-utility/scanner/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("scanutil: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan":
		runScan(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "migrate":
		runMigrate(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `scanutil — masscan wrapper

Usage:
  scanutil scan    -c config.yaml [-env .env]
  scanutil serve   -c config.yaml [-env .env] [-web web]
  scanutil migrate -c config.yaml [-env .env]
`)
}

func loadStore(cfgPath, envPath string) (*config.Config, *store.Store, error) {
	if err := config.LoadDotEnv(envPath); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(cfg.Persistence.SQLitePath)
	if err != nil {
		return nil, nil, err
	}
	return cfg, st, nil
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "path to config file")
	envPath := fs.String("env", ".env", "path to dotenv file")
	_ = fs.Parse(args)

	cfg, st, err := loadStore(*cfgPath, *envPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	orch, err := orchestrator.New(cfg, st)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	run, err := orch.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("scan #%d completed: open=%d new=%d closed=%d", run.ID, run.OpenCount, run.NewCount, run.ClosedCount)
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "path to config file")
	envPath := fs.String("env", ".env", "path to dotenv file")
	_ = fs.Parse(args)

	if err := config.LoadDotEnv(*envPath); err != nil {
		log.Fatal(err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cfg = config.Default()
		if *cfgPath != "" {
			if c2, e2 := config.Load(*cfgPath); e2 == nil {
				cfg = c2
			} else {
				log.Printf("using defaults (%v)", e2)
			}
		}
	}
	st, err := store.Open(cfg.Persistence.SQLitePath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	log.Printf("schema ready at %s", cfg.Persistence.SQLitePath)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "path to config file")
	envPath := fs.String("env", ".env", "path to dotenv file")
	webDir := fs.String("web", "web", "path to web templates/static")
	_ = fs.Parse(args)

	cfg, st, err := loadStore(*cfgPath, *envPath)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	orch, err := orchestrator.New(cfg, st)
	if err != nil {
		log.Fatal(err)
	}

	absWeb, err := filepath.Abs(*webDir)
	if err != nil {
		log.Fatal(err)
	}
	srvAPI, err := api.New(orch, st, absWeb)
	if err != nil {
		log.Fatal(err)
	}

	sched := scheduler.New(orch)
	if err := sched.Start(cfg.Schedule.Cron); err != nil {
		log.Fatal(err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("dashboard listening on %s", cfg.Server.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	<-sched.Stop().Done()
	log.Printf("shutdown complete")
}
