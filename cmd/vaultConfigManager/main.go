package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lein3000zzz/the-watchers/pkg/observability/logging"
	"github.com/lein3000zzz/the-watchers/pkg/observability/logging/slogging"
	"github.com/lein3000zzz/vault-config-manager/pkg/manager"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger, err := slogging.NewSlogLoggerWithConfig(slogging.Config{
		Level:    logging.LevelInfo,
		Format:   logging.FormatJSON,
		ToStdout: true,
	})
	if err != nil {
		log.Fatalf("Error initializing logger: %v", err)
	}
	defer func() {
		if errClose := logger.Close(); errClose != nil {
			log.Printf("Error closing logger: %v", errClose)
		}
	}()

	sm, err := manager.NewSecretManager(
		os.Getenv("VAULT_ADDRESS"),
		os.Getenv("VAULT_TOKEN"),
		manager.DefaultBasePathData,
		manager.DefaultBasePathMetaData,
		logger,
	)
	if err != nil {
		logger.Error(ctx, "creating secret manager failed", logging.KeyError, err)

		return
	}

	sm.StartConfigUpdater(ctx, manager.DefaultConfigUpdateInterval)
}
