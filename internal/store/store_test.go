package store_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Prateeks16/vexel/internal/store"
	"github.com/Prateeks16/vexel/internal/store/storetest"
)

func TestMemory(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return store.NewMemory() })
}

// TestPostgres runs the suite against a real database when
// VEXEL_TEST_DATABASE_URL is set. Each subtest gets a throwaway schema.
func TestPostgres(t *testing.T) {
	url := os.Getenv("VEXEL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("VEXEL_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()

	storetest.Run(t, func(t *testing.T) store.Store {
		schema := fmt.Sprintf("vexel_test_%s", store.NewID()[:8])
		admin, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			admin.Close(context.Background())
		})

		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = schema
		pg, err := store.OpenPostgresConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := pg.Migrate(ctx); err != nil {
			pg.Close()
			t.Fatal(err)
		}
		return pg
	})
}
