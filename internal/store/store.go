package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/emberaio/embercheckouts/internal/crypto"
	"github.com/emberaio/embercheckouts/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrGone     = errors.New("checkout expired")
	ErrEventCap = errors.New("checkout event limit reached")
)

type Store struct {
	pool *pgxpool.Pool
}

type CleanupResult struct {
	Erased int64
}

type Checkout struct {
	OwnerSubject string
	ExpiresAt    time.Time
	Envelope     crypto.Envelope
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Ready(ctx context.Context) error {
	var ready bool
	err := s.pool.QueryRow(ctx, `
		SELECT to_regclass('public.checkouts') IS NOT NULL
		   AND to_regclass('public.checkout_events') IS NOT NULL
	`).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("database migrations are not applied")
	}
	return nil
}

func (s *Store) CreateCheckout(
	ctx context.Context,
	identity domain.Identity,
	metadata domain.CheckoutMetadata,
	envelope crypto.Envelope,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO checkouts (
			id, owner_subject, membership_id, installation_id, session_id,
			module, site, title, quantity, price, currency, producer_version,
			target_host, proxy_used, created_at, expires_at,
			envelope_version, encryption_key_id, nonce, ciphertext
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20
		)
	`, metadata.ID, identity.Subject, identity.MembershipID, identity.InstallationID, identity.SessionID,
		metadata.Module, metadata.Site, metadata.Title, metadata.Quantity, metadata.Price, metadata.Currency,
		metadata.ProducerVersion, metadata.TargetHost, metadata.ProxyUsed, metadata.CreatedAt, metadata.ExpiresAt,
		envelope.Version, envelope.KeyID, envelope.Nonce, envelope.Ciphertext)
	return err
}

func (s *Store) GetCheckout(ctx context.Context, checkoutID string) (Checkout, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Checkout{}, err
	}
	defer tx.Rollback(ctx)

	var checkout Checkout
	err = tx.QueryRow(ctx, `
		SELECT owner_subject, expires_at, COALESCE(envelope_version, 0),
		       COALESCE(encryption_key_id, ''), nonce, ciphertext
		FROM checkouts
		WHERE id = $1
		FOR UPDATE
	`, checkoutID).Scan(&checkout.OwnerSubject, &checkout.ExpiresAt, &checkout.Envelope.Version,
		&checkout.Envelope.KeyID, &checkout.Envelope.Nonce, &checkout.Envelope.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return Checkout{}, ErrNotFound
	}
	if err != nil {
		return Checkout{}, err
	}
	now := time.Now().UTC()
	if !checkout.ExpiresAt.After(now) || checkout.Envelope.Ciphertext == nil {
		return Checkout{}, ErrGone
	}
	if _, err := tx.Exec(ctx, `
		UPDATE checkouts SET retrieval_count = retrieval_count + 1 WHERE id = $1
	`, checkoutID); err != nil {
		return Checkout{}, err
	}
	return checkout, tx.Commit(ctx)
}

func (s *Store) AddEvent(ctx context.Context, checkoutID, outcome string) error {
	tag, err := s.pool.Exec(ctx, `
		WITH accepted AS (
			UPDATE checkouts
			SET event_count = event_count + 1
			WHERE id = $1 AND expires_at > now() AND event_count < 20
			RETURNING id
		)
		INSERT INTO checkout_events (checkout_id, outcome)
		SELECT id, $2 FROM accepted
	`, checkoutID, outcome)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	var exists, expired bool
	if err := s.pool.QueryRow(ctx, `
		SELECT true, expires_at <= now() FROM checkouts WHERE id = $1
	`, checkoutID).Scan(&exists, &expired); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if expired {
		return ErrGone
	}
	return ErrEventCap
}

func (s *Store) Cleanup(ctx context.Context) (CleanupResult, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE checkouts
		SET ciphertext = NULL, nonce = NULL, encryption_key_id = NULL, envelope_version = NULL
		WHERE expires_at <= now() AND ciphertext IS NOT NULL
	`)
	if err != nil {
		return CleanupResult{}, err
	}
	return CleanupResult{Erased: tag.RowsAffected()}, nil
}
