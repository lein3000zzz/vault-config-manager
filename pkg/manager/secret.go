package manager

import (
	"time"
)

type config map[string]any

const (
	DefaultConfigUpdateInterval = 5 * time.Minute
)

const (
	// DefaultBasePathData - дефолтный путь до самих секретов в папке.
	DefaultBasePathData = "kv/data/"

	// DefaultBasePathMetaData - дефолтный путь до подпапок с секретами в папке.
	DefaultBasePathMetaData = "kv/metadata/"
)

type logger interface {
	Errorf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

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
	UnsealVault(unsealKeys []string)
	StopUpdater() error
}
