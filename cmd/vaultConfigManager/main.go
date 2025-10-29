package main

import (
	"log"
	"os"
	"vaultConfigManager/pkg/manager"

	"go.uber.org/zap"
)

func main() {
	logger := initLogger()

	sm, err := manager.NewSecretManager(os.Getenv("VAULT_ADDRESS"), os.Getenv("VAULT_TOKEN"), manager.DefaultBasePathData, manager.DefaultBasePathMetaData, logger)
	if err != nil {
		logger.Fatal("Error creating secret manager", zap.Error(err))
	}

	sm.StartConfigUpdater(manager.DefaultConfigUpdateInterval)
}

func initLogger() *zap.SugaredLogger {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Error initializing zap logger: %v", err)
		return nil
	}

	defer func(zapLogger *zap.Logger) {
		err := zapLogger.Sync()
		if err != nil {
			log.Fatalf("Error syncing zap logger: %v", err)
		}
	}(zapLogger)

	logger := zapLogger.Sugar()
	return logger
}
