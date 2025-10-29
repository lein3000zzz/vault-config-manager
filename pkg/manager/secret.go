package manager

import (
	"time"
)

type config map[string]any

const (
	DefaultConfigUpdateInterval = 5 * time.Minute
)

// TODO (OPTIONAL): ADD StopConfigUpdater

type SecretManager interface {
	UpdateSpecificSecret(path, varName string) (any, error)
	ResetConfig() error
	ReloadConfig() error
	UpdateConfigByPath(path string) error
	GetSecretStringFromConfig(key string) (string, error)
	GetSecretBoolFromConfig(key string) (bool, error)
	GetSecretIntFromConfig(key string) (int, error)
	GetSecretFloat64FromConfig(key string) (float64, error)
	StartConfigUpdater(updateInterval time.Duration)
	GetNotifierChannel() <-chan struct{}
}
