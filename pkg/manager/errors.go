package manager

import "errors"

var (
	ErrKeyNotFound             = errors.New("keyToLookup not found in the config")
	ErrNotMapInterface         = errors.New("not map interface")
	ErrWhileConvertingToString = errors.New("error converting folderKeyValues to string")
	ErrWhileConvertingToBool   = errors.New("error converting folderKeyValues to bool")
	ErrWhileConvertingToInt    = errors.New("error converting folderKeyValues to int")
	ErrWhileConvertingToFloat  = errors.New("error converting folderKeyValues to float64")
	ErrEmptyVaultResponse      = errors.New("empty vault response")
	ErrAlreadyClosed           = errors.New("already closed")
	ErrNoKeysList              = errors.New("vault response has no keys list")
	ErrStillSealed             = errors.New("vault is still sealed after trying every key")
)
