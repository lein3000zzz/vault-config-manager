package manager

import (
	"context"
	"time"
)

type SecretManager interface {
	UpdateSpecificSecret(ctx context.Context, path, varName string) (any, error)
	UpdateConfig(ctx context.Context) error
	ResetConfig(ctx context.Context) error
	ReloadConfig(ctx context.Context) error
	PurgeConfig()
	UpdateConfigByPath(ctx context.Context, path string) error
	GetSecretStringFromConfig(ctx context.Context, key string) (string, error)
	GetSecretBoolFromConfig(ctx context.Context, key string) (bool, error)
	GetSecretIntFromConfig(ctx context.Context, key string) (int, error)
	GetSecretFloat64FromConfig(ctx context.Context, key string) (float64, error)
	StartConfigUpdater(ctx context.Context, updateInterval time.Duration)
	GetNotifierChannel() <-chan struct{}
	UnsealVault(ctx context.Context, unsealKeys []string) error
	StopUpdater() error
}

type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

func NoopLogger() Logger {
	return noopLogger{}
}

type noopLogger struct{}

func (noopLogger) Debug(context.Context, string, ...any) {}
func (noopLogger) Info(context.Context, string, ...any)  {}
func (noopLogger) Warn(context.Context, string, ...any)  {}
func (noopLogger) Error(context.Context, string, ...any) {}
