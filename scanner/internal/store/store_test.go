package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/scan-utility/scanner/internal/models"
	"github.com/scan-utility/scanner/internal/store"
)

func TestDiffAndUpsert(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	first := []models.Finding{{
		IP: "203.0.113.1", Port: 80, Proto: "tcp", State: "open", Service: "http",
	}}
	out, err := st.DiffAndUpsert(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Diff != models.DiffNew {
		t.Fatalf("expected new, got %+v", out)
	}

	second := []models.Finding{{
		IP: "203.0.113.1", Port: 80, Proto: "tcp", State: "open", Service: "http", Banner: "nginx",
	}}
	out, err = st.DiffAndUpsert(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Diff != models.DiffChanged {
		t.Fatalf("expected changed, got %s", out[0].Diff)
	}

	out, err = st.DiffAndUpsert(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Diff != models.DiffClosed {
		t.Fatalf("expected closed, got %+v", out)
	}
}
