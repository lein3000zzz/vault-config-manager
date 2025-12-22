package manager

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

const (
	// DefaultBasePathData - дефолтный путь до самих секретов в папке.
	DefaultBasePathData = "kv/data/"

	// DefaultBasePathMetaData - дефолтный путь до подпапок с секретами в папке.
	DefaultBasePathMetaData = "kv/metadata/"
)

var (
	// Проверки делать через errors.Is(errToCheck, errToCompareWith)

	ErrKeyNotFound             = errors.New("keyToLookup not found in the config")
	ErrNotMapInterface         = errors.New("not map interface")
	ErrWhileConvertingToString = errors.New("error converting folderKeyValues to string")
	ErrWhileConvertingToBool   = errors.New("error converting folderKeyValues to bool")
	ErrWhileConvertingToInt    = errors.New("error converting folderKeyValues to int")
	ErrWhileConvertingToFloat  = errors.New("error converting folderKeyValues to float64")
	ErrEmptyVaultResponse      = errors.New("empty vault response")
)

type SecretManagerVault struct {
	vaultClient *vaultapi.Client
	config      config
	logger      logger
	notifier    chan struct{}

	basePath     string
	baseMetaPath string

	*sync.RWMutex
}

func NewSecretManager(
	vaultAddr,
	token,
	basePath string,
	baseMetaPath string,
	logger *zap.SugaredLogger,
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

	client.SetToken(token)

	smConfig := config(make(map[string]any))

	return &SecretManagerVault{
		vaultClient:  client,
		config:       smConfig,
		logger:       logger,
		notifier:     make(chan struct{}),
		RWMutex:      &sync.RWMutex{},
		basePath:     basePath,
		baseMetaPath: baseMetaPath,
	}, nil
}

// UnsealVault пытается распечатать хранилище и ФАТАЛИТ, если у него не получается
func (sm *SecretManagerVault) UnsealVault(unsealKeys []string) {
	status, err := sm.vaultClient.Sys().SealStatus()
	if err != nil {
		sm.logger.Fatalf("Error getting seal status: %v", err)
	}

	if status.Sealed {
		for _, key := range unsealKeys {
			resp, err := sm.vaultClient.Sys().Unseal(strings.TrimSpace(key))
			if err != nil {
				sm.logger.Fatalf("Error unsealing Vault with key: %v", err)
			}
			if !resp.Sealed {
				sm.logger.Infof("Vault unsealed successfully")
				break
			}
		}

		status, err = sm.vaultClient.Sys().SealStatus()
		if err != nil || status.Sealed {
			sm.logger.Fatalf("Failed to unseal Vault")
		}
	}
}

// UpdateSpecificSecret обновляет секрет СРАЗУ В ТЕКУЩЕМ КОНФИГЕ и возвращает секрет. Начинаем без слэша, в конце - опционально,
// поскольку мы обращаемся относительно базового пути, который находится в константах BaseDataPath и BaseMetaDataPath
// пример - UpdateSpecificSecretString("test/", "test")
func (sm *SecretManagerVault) UpdateSpecificSecret(folder, key string) (any, error) {
	vaultResponse, err := sm.vaultClient.Logical().Read(sm.basePath + folder)
	if err != nil {
		sm.logger.Errorf("Error reading secret at folder '%s': %s", folder, err.Error())
		return "", err
	}

	if vaultResponse == nil || vaultResponse.Data == nil {
		sm.logger.Infof("Got nil while reading secret at folder '%s': keyToLookup %s", folder, key)
		return "", ErrEmptyVaultResponse
	}

	secretData, okConversionToMapInterface := vaultResponse.Data["data"].(map[string]interface{})
	if !okConversionToMapInterface {
		sm.logger.Errorf("Error reading secret at folder '%s': failed to convert to map[string]interface{}", folder)
		return "", ErrNotMapInterface
	}

	secretVal := secretData[key]

	sm.putSingleSecretStringIntoTheConfig(key, secretVal)

	return secretVal, nil
}

// Добавить в конфиг по определенному ключу определенное значение
func (sm *SecretManagerVault) putSingleSecretStringIntoTheConfig(key string, secretString any) {
	sm.Lock()
	defer sm.Unlock()

	sm.config[key] = secretString
	sm.logger.Infof("Updated secret in the config with keyToLookup %s to data '%s'", key, secretString)
}

// UpdateConfig берет полный конфиг из vault'a, и обновления вносит в текущий
func (sm *SecretManagerVault) UpdateConfig() error {
	cfg, err := sm.getFullConfigFromVault()
	if err != nil {
		sm.logger.Errorf("Error getting config from Vault: %s", err.Error())
		return err
	}

	sm.applyUpdatesToConfig(cfg)

	return nil
}

// ResetConfig берет полный конфиг из vault'a и старый конфиг заменяет на новый
func (sm *SecretManagerVault) ResetConfig() error {
	cfg, err := sm.getFullConfigFromVault()
	if err != nil {
		sm.logger.Errorf("Error getting config from Vault: %s", err.Error())
		return err
	}

	sm.setConfig(cfg)

	return nil
}

// Сетит предоставленный конфиг
func (sm *SecretManagerVault) setConfig(cfg config) {
	sm.Lock()
	defer sm.Unlock()

	sm.logger.Infof("setting new config")
	sm.config = cfg
}

// getFullConfigFromVault целиком собирает конфиг, проходясь по каждой папке, и считывает секреты с помощью getConfigFromVaultByPath,
// то есть сохраняются все те же правила - если в папке произошла ошибка, никакие данные из этой папки не будут обновлены.
// СБОР ВСЕГО КОНФИГА НЕ БЛОКИРУЕТСЯ НИ НА КАКОЙ СТАДИИ, ТО ЕСТЬ У НАС ПРОВЕРЯТСЯ ВСЕ ПАПКИ, ДАЖЕ ЕСЛИ ВО ВРЕМЯ
// ВЫПОЛНЕНИЯ БУДУТ ОШИБКИ. На выходе мы получаем СОВОКУПНУЮ ошибку, состоящую из нескольких ошибок.
// Дальнейшие действия зависят от более высокой абстракции
func (sm *SecretManagerVault) getFullConfigFromVault() (config, error) {
	folderStack := make([]string, 0, 4)
	folderStack = append(folderStack, "") // мы смотрим на базовый путь

	cumulativeConfig := config(make(map[string]any))

	var errToReturn error = nil
	var currCheckedFolder string

	for len(folderStack) > 0 {
		currCheckedFolder = folderStack[len(folderStack)-1]
		currCheckedPath := sm.baseMetaPath + currCheckedFolder
		folderStack = folderStack[:len(folderStack)-1]

		vaultResponseList, errList := sm.vaultClient.Logical().List(currCheckedPath)

		if errList != nil {
			sm.logger.Errorf("Error listing secrets folders at path '%s': %s", currCheckedPath, errList.Error())
			errToReturn = errors.Join(errToReturn, errList)
			continue
		}

		if vaultResponseList == nil || vaultResponseList.Data == nil {
			sm.logger.Infof("Got nil while listing secrets folders at path '%s'", currCheckedPath)
			continue
		}

		var currInnerFolder string
		for _, folder := range vaultResponseList.Data["keys"].([]interface{}) {
			folderString, okConversionToString := folder.(string)

			if !okConversionToString {
				sm.logger.Errorf("Error reading secret at folder '%s': failed to convert folder to string %s", folder, folderString)
				errToReturn = errors.Join(errToReturn, ErrWhileConvertingToString)
				continue
			}

			currInnerFolder = currCheckedFolder + folderString
			folderConfigUpdates, err := sm.getConfigFromVaultByPath(currInnerFolder)
			if err != nil && !errors.Is(err, ErrEmptyVaultResponse) {
				errToReturn = errors.Join(errToReturn, err)
			}

			mergeConfigs(cumulativeConfig, folderConfigUpdates)

			folderStack = append(folderStack, currInnerFolder)
		}
	}

	return cumulativeConfig, errToReturn
}

// UpdateConfigByPath Собирает обновления по пути, а далее вносит обновления в текущий конфиг
func (sm *SecretManagerVault) UpdateConfigByPath(path string) error {
	cfg, err := sm.getConfigFromVaultByPath(path)
	if err != nil {
		sm.logger.Errorf("Error getting config from Vault: %s", err.Error())
		return err
	}

	sm.applyUpdatesToConfig(cfg)

	return nil
}

// getConfigFromVaultByPath собирает конфиг по пути, который укажем, относительно базового пути. Если во время обновления произошла
// хотя бы одна ошибка, изменения останавливаются, и возвращается тот конфиг, который был на момент ошибки.
// Оставил глобальной для юзкейсов, когда мы точно ничего не удалили, а лишь обновили старые или добавили новые
func (sm *SecretManagerVault) getConfigFromVaultByPath(path string) (config, error) {
	vaultResponse, err := sm.vaultClient.Logical().Read(sm.basePath + path)

	freshConfigByPath := config(make(map[string]any))

	if err != nil {
		sm.logger.Errorf("Error reading secrets at path '%s': %s", path, err.Error())
		return freshConfigByPath, err
	}

	if vaultResponse == nil || vaultResponse.Data == nil {
		return freshConfigByPath, ErrEmptyVaultResponse
	}

	secretData, okConversionToMapInterface := vaultResponse.Data["data"].(map[string]interface{})
	if !okConversionToMapInterface {
		sm.logger.Errorf("Error reading secrets at path '%s': failed to convert to map[string]interface{}", path)
		return freshConfigByPath, ErrNotMapInterface
	}

	for k, v := range secretData {

		switch v.(type) {
		case json.Number:
			freshConfigByPath[k], err = v.(json.Number).Float64()

			if err != nil {
				sm.logger.Errorf("Error reading secret at path '%s': %s", path, err.Error())
				return freshConfigByPath, err
			}
		default:
			freshConfigByPath[k] = v
			sm.logger.Debugf("Reading secret, which is not json.Number at path '%s', type %v", path, reflect.TypeOf(v))
		}
	}

	return freshConfigByPath, nil
}

func (sm *SecretManagerVault) applyUpdatesToConfig(configUpdates config) {
	sm.Lock()
	defer sm.Unlock()

	sm.logger.Infof("applying updates to config: %v", configUpdates)
	for k, v := range configUpdates {
		sm.config[k] = v
	}
}

func (sm *SecretManagerVault) GetSecretStringFromConfig(key string) (string, error) {
	sm.RLock()
	defer sm.RUnlock()
	if value, exists := sm.config[key]; exists {
		valueStr, ok := value.(string)

		if !ok {
			sm.logger.Errorf("Error reading secret at path '%s': failed to convert to string", key)
			return "", ErrWhileConvertingToString
		}

		return valueStr, nil
	}
	return "", ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretBoolFromConfig(key string) (bool, error) {
	sm.RLock()
	defer sm.RUnlock()
	if value, exists := sm.config[key]; exists {
		boolVal, ok := value.(bool)
		if !ok {
			sm.logger.Errorf("Error reading secret at path '%s': failed to convert to bool", key)
			return false, ErrWhileConvertingToBool
		}
		return boolVal, nil
	}
	return false, ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretIntFromConfig(key string) (int, error) {
	sm.RLock()
	defer sm.RUnlock()
	if value, exists := sm.config[key]; exists {

		var intVal int
		switch value.(type) {
		case float64:
			intVal = int(value.(float64))
		case int:
			intVal = value.(int)
		default:
			sm.logger.Errorf("Error reading secret for key %s from config: failed to convert to int", key)
			return 0, ErrWhileConvertingToInt
		}

		return intVal, nil
	}
	return 0, ErrKeyNotFound
}

func (sm *SecretManagerVault) GetSecretFloat64FromConfig(key string) (float64, error) {
	sm.RLock()
	defer sm.RUnlock()
	if value, exists := sm.config[key]; exists {
		floatVal, ok := value.(float64)
		if !ok {
			sm.logger.Errorf("Error reading secret at path '%s': failed to convert to float64", key)
			return 0, ErrWhileConvertingToFloat
		}
		return floatVal, nil
	}
	return 0, ErrKeyNotFound
}

func (sm *SecretManagerVault) ReloadConfig() error {
	sm.PurgeConfig()
	return sm.ResetConfig()
}

func (sm *SecretManagerVault) PurgeConfig() {
	sm.Lock()
	defer sm.Unlock()

	sm.config = make(map[string]any)
}

func (sm *SecretManagerVault) getConfigCopy() config {
	sm.RLock()
	defer sm.RUnlock()

	configCopy := config{}
	for k, v := range sm.config {
		configCopy[k] = v
	}

	return configCopy
}

func (sm *SecretManagerVault) StartConfigUpdater(updateInterval time.Duration) {
	ticker := time.NewTicker(updateInterval)
	configCopy := sm.getConfigCopy()

	for {
		<-ticker.C

		freshConfig, err := sm.getFullConfigFromVault()

		if err != nil || freshConfig == nil {
			sm.logger.Errorf("getFullConfigFromVault failed in configUpdater or freshConfig is nil, err = %v, freshConfig = %v", err, freshConfig)
			continue
		}

		if !areConfigsDifferent(freshConfig, configCopy) {
			continue
		}

		sm.setConfig(freshConfig)
		configCopy = sm.getConfigCopy()

		sm.notifier <- struct{}{}
	}
}

func (sm *SecretManagerVault) GetNotifierChannel() <-chan struct{} {
	return sm.notifier
}

// mergeConfigs - берет ключи из src и пишет в destination. Если в destination такое уже есть, то не пишет!
func mergeConfigs(destination, src config) {
	for k, v := range src {
		if _, ok := destination[k]; !ok {
			destination[k] = v
		}
	}
}

func areConfigsDifferent(config1, config2 config) bool {
	if len(config1) != len(config2) {
		return true
	}

	for k, v1 := range config1 {
		if v2, ok := config2[k]; !ok || !reflect.DeepEqual(v1, v2) {
			return true
		}
	}

	return false
}
