package scheduler

import (
	"context"
	"log"
	"sync"

	"github.com/robfig/cron/v3"

	"github.com/scan-utility/scanner/internal/orchestrator"
)

type Scheduler struct {
	cron *cron.Cron
	orch *orchestrator.Orchestrator
	mu   sync.Mutex
}

func New(orch *orchestrator.Orchestrator) *Scheduler {
	return &Scheduler{
		cron: cron.New(),
		orch: orch,
	}
}

func (s *Scheduler) Start(expr string) error {
	if expr == "" {
		return nil
	}
	_, err := s.cron.AddFunc(expr, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		log.Printf("scheduler: starting scan")
		if _, err := s.orch.Run(context.Background()); err != nil {
			log.Printf("scheduler scan error: %v", err)
		}
	})
	if err != nil {
		return err
	}
	s.cron.Start()
	log.Printf("scheduler started: %s", expr)
	return nil
}

func (s *Scheduler) Stop() context.Context {
	return s.cron.Stop()
}
