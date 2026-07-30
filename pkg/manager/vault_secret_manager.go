package manager

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

var _ SecretManager = (*SecretManagerVault)(nil)

type SecretManagerVault struct {
	vaultClient *vaultapi.Client
	config      config
	logger      Logger
	notifier    chan struct{}
	stopChan    chan struct{}

	basePath     string
	baseMetaPath string

	updaterStarted atomic.Bool
	stopOnce       sync.Once

	mu sync.RWMutex
}

func NewSecretManager(
	vaultAddr,
	token,
	basePath string,
	baseMetaPath string,
	logger Logger,
) (*SecretManagerVault, error) {
	vaultConfig := vaultapi.DefaultConfig()
	if vaultAddr != "" {
		vaultConfig.Address = vaultAddr
	}

	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	if !strings.HasSuffix(baseMetaPath, "/") {
		baseMetaPath += "/"
	}

	if logger == nil {
		logger = NoopLogger()
	}

	client.SetToken(token)

	smConfig := config(make(map[string]any))

	return &SecretManagerVault{
		vaultClient:  client,
		config:       smConfig,
		logger:       logger,
		notifier:     make(chan struct{}, 1),
		stopChan:     make(chan struct{}),
		basePath:     basePath,
		baseMetaPath: baseMetaPath,
	}, nil
}

func (sm *SecretManagerVault) UnsealVault(ctx context.Context, unsealKeys []string) error {
	status, err := sm.vaultClient.Sys().SealStatusWithContext(ctx)
	if err != nil {
		sm.logger.Error(ctx, "getting seal status failed", keyError, err)
		return err
	}

	if !status.Sealed {
		return nil
	}

	var errToReturn error

	for _, key := range unsealKeys {
		resp, errUnseal := sm.vaultClient.Sys().UnsealWithContext(ctx, strings.TrimSpace(key))
		if errUnseal != nil {
			sm.logger.Error(ctx, "unsealing vault with key failed", keyError, errUnseal)
			errToReturn = errors.Join(errToReturn, errUnseal)

			continue
		}

		if !resp.Sealed {
			sm.logger.Info(ctx, "vault unsealed successfully")

			return nil
		}
	}

	status, err = sm.vaultClient.Sys().SealStatusWithContext(ctx)
	if err != nil {
		sm.logger.Error(ctx, "getting seal status failed", keyError, err)

		return errors.Join(errToReturn, err)
	}

	if status.Sealed {
		sm.logger.Error(ctx, "failed to unseal vault", "keysTried", len(unsealKeys))

		return errors.Join(errToReturn, ErrStillSealed)
	}

	return nil
}

func (sm *SecretManagerVault) UpdateSpecificSecret(ctx context.Context, folder, key string) (any, error) {
	vaultResponse, err := sm.vaultClient.Logical().ReadWithContext(ctx, sm.basePath+folder)
	if err != nil {
		sm.logger.Error(ctx, "reading secret failed", "folder", folder, keyError, err)
		return "", err
	}

	if vaultResponse == nil || vaultResponse.Data == nil {
		sm.logger.Debug(ctx, "got nil while reading secret", "folder", folder, "keyToLookup", key)
		return "", ErrEmptyVaultResponse
	}

	secretData, okConversionToMapInterface := vaultResponse.Data["data"].(map[string]interface{})
	if !okConversionToMapInterface {
		sm.logger.Error(ctx, "reading secret failed: not a map[string]interface{}", "folder", folder)
		return "", ErrNotMapInterface
	}

	secretVal := secretData[key]

	sm.putSingleSecretStringIntoTheConfig(ctx, key, secretVal)

	return secretVal, nil
}

func (sm *SecretManagerVault) putSingleSecretStringIntoTheConfig(ctx context.Context, key string, secretString any) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.config[key] = secretString
	sm.logger.Debug(ctx, "updated secret in the config", "keyToLookup", key)
}

func (sm *SecretManagerVault) UpdateConfig(ctx context.Context) error {
	cfg, err := sm.getFullConfigFromVault(ctx)
	if err != nil {
		sm.logger.Error(ctx, "getting config from vault failed", keyError, err)
		return err
	}

	sm.applyUpdatesToConfig(ctx, cfg)

	return nil
}

func (sm *SecretManagerVault) ResetConfig(ctx context.Context) error {
	cfg, err := sm.getFullConfigFromVault(ctx)
	if err != nil {
		sm.logger.Error(ctx, "getting config from vault failed", keyError, err)
		return err
	}

	sm.setConfig(ctx, cfg)

	return nil
}

func (sm *SecretManagerVault) setConfig(ctx context.Context, cfg config) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.logger.Info(ctx, "setting new config", "keys", len(cfg))
	sm.config = cfg
}

func (sm *SecretManagerVault) getFullConfigFromVault(ctx context.Context) (config, error) {
	folderStack := make([]string, 0, 4)
	folderStack = append(folderStack, "") // мы смотрим на базовый путь

	cumulativeConfig := config(make(map[string]any))

	var errToReturn error = nil
	var currCheckedFolder string

	for len(folderStack) > 0 {
		currCheckedFolder = folderStack[len(folderStack)-1]
		currCheckedPath := sm.baseMetaPath + currCheckedFolder
		folderStack = folderStack[:len(folderStack)-1]

		vaultResponseList, errList := sm.vaultClient.Logical().ListWithContext(ctx, currCheckedPath)

		if errList != nil {
			sm.logger.Error(ctx, "listing secrets folders failed", "path", currCheckedPath, keyError, errList)
			errToReturn = errors.Join(errToReturn, errList)

			continue
		}

		if vaultResponseList == nil || vaultResponseList.Data == nil {
			sm.logger.Debug(ctx, "got nil while listing secrets folders", "path", currCheckedPath)
			continue
		}

		keys, okConversionToSlice := vaultResponseList.Data["keys"].([]interface{})
		if !okConversionToSlice {
			sm.logger.Error(ctx, "listing secrets folders failed: no keys list in response", "path", currCheckedPath)
			errToReturn = errors.Join(errToReturn, ErrNoKeysList)

			continue
		}

		var currInnerFolder string
		for _, folder := range keys {
			folderString, okConversionToString := folder.(string)

			if !okConversionToString {
				sm.logger.Error(ctx, "reading secret failed: folder is not a string", "folder", folder)
				errToReturn = errors.Join(errToReturn, ErrWhileConvertingToString)

				continue
			}

			currInnerFolder = currCheckedFolder + folderString
			folderConfigUpdates, err := sm.getConfigFromVaultByPath(ctx, currInnerFolder)
			if err != nil && !errors.Is(err, ErrEmptyVaultResponse) {
				errToReturn = errors.Join(errToReturn, err)
			}

			mergeConfigs(cumulativeConfig, folderConfigUpdates)

			folderStack = append(folderStack, currInnerFolder)
		}
	}

	return cumulativeConfig, errToReturn
}

func (sm *SecretManagerVault) UpdateConfigByPath(ctx context.Context, path string) error {
	cfg, err := sm.getConfigFromVaultByPath(ctx, path)
	if err != nil {
		sm.logger.Error(ctx, "getting config from vault failed", "path", path, keyError, err)
		return err
	}

	sm.applyUpdatesToConfig(ctx, cfg)

	return nil
}

func (sm *SecretManagerVault) getConfigFromVaultByPath(ctx context.Context, path string) (config, error) {
	vaultResponse, err := sm.vaultClient.Logical().ReadWithContext(ctx, sm.basePath+path)

	freshConfigByPath := config(make(map[string]any))

	if err != nil {
		sm.logger.Error(ctx, "reading secrets failed", "path", path, keyError, err)
		return freshConfigByPath, err
	}

	if vaultResponse == nil || vaultResponse.Data == nil {
		return freshConfigByPath, ErrEmptyVaultResponse
	}

	secretData, okConversionToMapInterface := vaultResponse.Data["data"].(map[string]interface{})
	if !okConversionToMapInterface {
		sm.logger.Error(ctx, "reading secrets failed: not a map[string]interface{}", "path", path)
		return freshConfigByPath, ErrNotMapInterface
	}

	for k, v := range secretData {

		switch typed := v.(type) {
		case json.Number:
			freshConfigByPath[k], err = typed.Float64()

			if err != nil {
				sm.logger.Error(ctx, "reading secret failed", "path", path, keyError, err)
				return freshConfigByPath, err
			}
		default:
			freshConfigByPath[k] = v
			sm.logger.Debug(ctx, "reading secret which is not json.Number", "path", path, "type", reflect.TypeOf(v))
		}
	}

	return freshConfigByPath, nil
}

func (sm *SecretManagerVault) applyUpdatesToConfig(ctx context.Context, configUpdates config) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.logger.Debug(ctx, "applying updates to config", "keys", len(configUpdates))
	for k, v := range configUpdates {
		sm.config[k] = v
	}
}

func (sm *SecretManagerVault) GetSecretStringFromConfig(ctx context.Context, key string) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if value, exists := sm.config[key]; exists {
		valueStr, ok := value.(string)

		if !ok {
			sm.logger.Error(ctx, "reading secret failed: not a string", "keyToLookup", key)
			return "", ErrWhileConvertingToString
		}

		return valueStr, nil
	}
	return "", ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretBoolFromConfig(ctx context.Context, key string) (bool, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if value, exists := sm.config[key]; exists {
		boolVal, ok := value.(bool)
		if !ok {
			sm.logger.Error(ctx, "reading secret failed: not a bool", "keyToLookup", key)
			return false, ErrWhileConvertingToBool
		}
		return boolVal, nil
	}
	return false, ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretIntFromConfig(ctx context.Context, key string) (int, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if value, exists := sm.config[key]; exists {

		var intVal int
		switch typed := value.(type) {
		case float64:
			intVal = int(typed)
		case int:
			intVal = typed
		default:
			sm.logger.Error(ctx, "reading secret failed: not an int", "keyToLookup", key)
			return 0, ErrWhileConvertingToInt
		}

		return intVal, nil
	}
	return 0, ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretFloat64FromConfig(ctx context.Context, key string) (float64, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if value, exists := sm.config[key]; exists {
		floatVal, ok := value.(float64)
		if !ok {
			sm.logger.Error(ctx, "reading secret failed: not a float64", "keyToLookup", key)
			return 0, ErrWhileConvertingToFloat
		}
		return floatVal, nil
	}
	return 0, ErrKeyNotFound
}

func (sm *SecretManagerVault) ReloadConfig(ctx context.Context) error {
	sm.PurgeConfig()
	return sm.ResetConfig(ctx)
}

func (sm *SecretManagerVault) PurgeConfig() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.config = make(map[string]any)
}

func (sm *SecretManagerVault) getConfigCopy() config {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return maps.Clone(sm.config)
}

func (sm *SecretManagerVault) StartConfigUpdater(ctx context.Context, updateInterval time.Duration) {
	if !sm.updaterStarted.CompareAndSwap(false, true) {
		sm.logger.Warn(ctx, "configUpdater already started")

		return
	}

	defer close(sm.notifier)

	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	configCopy := sm.getConfigCopy()

	for {
		select {
		case <-ctx.Done():
			sm.logger.Info(ctx, "configUpdater stopping", keyError, ctx.Err())

			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			freshConfig, err := sm.getFullConfigFromVault(ctx)

			if err != nil || freshConfig == nil {
				sm.logger.Error(ctx, "getFullConfigFromVault failed in configUpdater or freshConfig is nil",
					keyError, err, "freshConfigIsNil", freshConfig == nil)

				continue
			}

			if !areConfigsDifferent(freshConfig, configCopy) {
				continue
			}

			sm.setConfig(ctx, freshConfig)
			configCopy = sm.getConfigCopy()

			select {
			case sm.notifier <- struct{}{}:
			case <-ctx.Done():
				return
			case <-sm.stopChan:
				return
			default:
				sm.logger.Warn(ctx, "configUpdater notifier blocked, cant send notification")
			}
		}
	}
}

func (sm *SecretManagerVault) GetNotifierChannel() <-chan struct{} {
	return sm.notifier
}

func (sm *SecretManagerVault) StopUpdater() error {
	err := ErrAlreadyClosed

	sm.stopOnce.Do(func() {
		close(sm.stopChan)
		err = nil
	})

	return err
}
