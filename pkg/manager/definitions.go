package manager

import "time"

const (
	DefaultConfigUpdateInterval = 5 * time.Minute
)

const (
	// DefaultBasePathData - default secret path
	DefaultBasePathData = "kv/data/"

	// DefaultBasePathMetaData - default secrets folders path
	DefaultBasePathMetaData = "kv/metadata/"
)

const keyError = "error"

type config map[string]any
