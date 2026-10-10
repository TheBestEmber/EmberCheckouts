package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emberaio/embercheckouts/internal/auth"
	"github.com/emberaio/embercheckouts/internal/config"
	"github.com/emberaio/embercheckouts/internal/httpapi"
	"github.com/emberaio/embercheckouts/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	verifier, err := auth.NewJWKSVerifierAt(cfg.EmberAuthURL, cfg.EmberAuthJWKSURL, nil)
	if err != nil {
		logger.Error("authentication initialization failed", "error", err)
		os.Exit(1)
	}
	api := httpapi.New(httpapi.Config{
		Store: db, Verifier: verifier, Keyring: cfg.Keyring, Logger: logger,
		PublicBaseURL: cfg.PublicBaseURL, AllowLocalhostHTTP: cfg.AllowLocalhostHTTP,
		RateLimitPerMinute: cfg.RateLimitPerMinute, TrustedProxies: cfg.TrustedProxies,
	})
	server := &http.Server{
		Addr: cfg.Addr, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	go cleanup(ctx, logger, db, cfg.CleanupInterval)
	errs := make(chan error, 1)
	go func() {
		logger.Info("API listening", "address", cfg.Addr)
		errs <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server failed", "error", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

func cleanup(ctx context.Context, logger *slog.Logger, db *store.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			result, err := db.Cleanup(runCtx)
			cancel()
			if err != nil {
				logger.Error("cleanup failed", "error", err)
				continue
			}
			if result.Erased > 0 {
				logger.Info("cleanup completed", "erased_payloads", result.Erased)
			}
		}
	}
}
