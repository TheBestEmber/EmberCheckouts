package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/emberaio/embercheckouts/internal/crypto"
	"github.com/emberaio/embercheckouts/internal/domain"
)

func TestReusableCheckoutExpiryAndAnalyticsRetention(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	database, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	migration, err := os.ReadFile("../../migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"+string(migration)); err != nil {
		t.Fatal(err)
	}

	createdAt := time.Now().UTC()
	id := "123e4567-e89b-42d3-a456-426614174000"
	err = database.CreateCheckout(ctx,
		domain.Identity{
			Subject: "mem_1", MembershipID: "mem_1",
			InstallationID: "installation_1", SessionID: "session_1",
		},
		domain.CheckoutMetadata{
			ID: id, Module: "skiddle", Site: "skiddle", Title: "Final Release",
			Quantity: 2, Price: "55.00", Currency: "GBP", ProducerVersion: "0.1.0",
			TargetHost: "www.skiddle.com", CreatedAt: createdAt,
			ExpiresAt: createdAt.Add(domain.CheckoutTTL),
		},
		crypto.Envelope{Version: 1, KeyID: "test", Nonce: []byte("nonce"), Ciphertext: []byte("ciphertext")},
	)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if _, err := database.GetCheckout(ctx, id); err != nil {
			t.Fatalf("reusable retrieval failed: %v", err)
		}
	}
	if err := database.AddEvent(ctx, id, "import_succeeded"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(ctx, `UPDATE checkouts SET
		created_at = now() - interval '11 minutes',
		expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetCheckout(ctx, id); !errors.Is(err, ErrGone) {
		t.Fatalf("expired retrieval error = %v", err)
	}
	result, err := database.Cleanup(ctx)
	if err != nil || result.Erased != 1 {
		t.Fatalf("cleanup = %+v, %v", result, err)
	}

	var ciphertext []byte
	var retrievals int
	var events int
	if err := database.pool.QueryRow(ctx, `SELECT ciphertext, retrieval_count, event_count
		FROM checkouts WHERE id = $1`, id).Scan(&ciphertext, &retrievals, &events); err != nil {
		t.Fatal(err)
	}
	if ciphertext != nil || retrievals != 2 || events != 1 {
		t.Fatalf("analytics not retained safely: ciphertext=%v retrievals=%d events=%d", ciphertext, retrievals, events)
	}
}
