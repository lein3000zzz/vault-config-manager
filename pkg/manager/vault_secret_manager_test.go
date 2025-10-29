package manager

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/vault"
	"go.uber.org/zap"
)

const (
	testVaultToken       = "token"
	testBasePathData     = DefaultBasePathData + "main/"
	testBasePathMetadata = DefaultBasePathMetaData + "main/"
)

var (
	nilLogger = zap.NewNop().Sugar()
)

var newManagerTests = []struct {
	address     string
	token       string
	expectedErr error
}{
	{"https://127.0.0.1:8200", testVaultToken, nil},
	{"http://127.0.0.1:8300", testVaultToken + "123", nil},
	{"http://127.0.0.1:8400", testVaultToken + "bebe", nil},
}

func TestNewSecretManager(t *testing.T) {
	var sm *SecretManagerVault
	var err error
	for _, test := range newManagerTests {
		sm, err = NewSecretManager(test.address, test.token, testBasePathData, testBasePathMetadata, nilLogger)
		assert.Equal(t, test.expectedErr, err)
		if test.expectedErr == nil {
			assert.NotNil(t, sm)
			assert.Equal(t, test.address, sm.vaultClient.Address())
			assert.Equal(t, test.token, sm.vaultClient.Token())
		}
	}
}

func skipCI(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping testing in CI environment")
	}
}

var updateSpecificSecretTests = []struct {
	name         string
	key          string
	value        string
	secretFolder string
	expectedErr  error
}{
	{
		"single put and retrieve",
		"keyToLookup",
		"folderKeyValues",
		"",
		nil,
	},
	{
		"empty keyToLookup",
		"",
		"folderKeyValues",
		"",
		nil,
	},
}

var updateByPathTests = []struct {
	name         string
	keyValues    map[string]interface{}
	secretFolder string
	expectedErr  error
}{
	{
		"bibaboba",
		map[string]interface{}{
			"fuck": "this",
			"shit": "i`m out",
		},
		"main",
		nil,
	},
}

var updateConfigFully = []struct {
	name            string
	folderKeyValues map[string]map[string]interface{}
	expectedOutput  config
	expectedErr     error
}{
	{
		"bibaboba",
		map[string]map[string]interface{}{
			"main/": {
				"fuck": "this",
				"shit": "i`m out",
			},
			"test1/": {
				"shitty": "this",
				"fucky":  "i`m out",
			},
			"test1/test2": {
				"shittiest": "this",
				"fuck":      "this",
			},
		},
		config{
			"fuck":      "this",
			"shit":      "i`m out",
			"shitty":    "this",
			"fucky":     "i`m out",
			"shittiest": "this",
		},
		nil,
	},
}

// SET THE ENV VARIABLE IN CI/CD TO SKIP THIS INTEGRITY TEST
//

func TestIntegrityWithVaultContainer(t *testing.T) {
	skipCI(t)

	ctx := context.Background()

	vaultContainer, errVaultInit := vault.Run(context.Background(),
		"hashicorp/vault",
		vault.WithToken(testVaultToken),
		vault.WithInitCommand("secrets enable -path=kv kv-v2"),
	)
	require.NoError(t, errVaultInit)

	endpoint, err := vaultContainer.HttpHostAddress(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		vaultContainer.Terminate(ctx)
	})

	sm, errSmInit := NewSecretManager(endpoint, testVaultToken, testBasePathData, testBasePathMetadata, nilLogger)
	require.NoError(t, errSmInit)

	var retrievedString string
	for _, test := range updateSpecificSecretTests {
		t.Run(test.name, func(t *testing.T) {
			_, writeErr := sm.vaultClient.Logical().Write(
				testBasePathData+test.secretFolder,
				map[string]interface{}{
					"data": map[string]interface{}{test.key: test.value},
				})
			require.NoError(t, writeErr)

			_, err = sm.UpdateSpecificSecret(test.secretFolder, test.key)
			retrievedString, err = sm.GetSecretStringFromConfig(test.key)
			assert.Equal(t, test.expectedErr, err)
			assert.Equal(t, test.value, retrievedString)
			assert.Equal(t, sm.config[test.key], retrievedString)

			_, deleteErr := sm.vaultClient.Logical().Delete(testBasePathData + test.secretFolder)
			require.NoError(t, deleteErr)
		})
	}

	for _, test := range updateByPathTests {
		t.Run(test.name, func(t *testing.T) {
			_, writeErr := sm.vaultClient.Logical().Write(
				testBasePathData+test.secretFolder,
				map[string]interface{}{
					"data": test.keyValues,
				})
			require.NoError(t, writeErr)

			err = sm.UpdateConfigByPath(test.secretFolder)
			assert.Equal(t, test.expectedErr, err)

			for k, v := range test.keyValues {
				val, exists := sm.config[k]
				assert.True(t, exists)
				assert.Equal(t, v, val)
			}

			_, deleteErr := sm.vaultClient.Logical().Delete(testBasePathData + test.secretFolder)
			require.NoError(t, deleteErr)
		})
	}

	for _, test := range updateConfigFully {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range test.folderKeyValues {
				_, writeErr := sm.vaultClient.Logical().Write(
					testBasePathData+k,
					map[string]interface{}{
						"data": v,
					})
				require.NoError(t, writeErr)
			}

			err = sm.ReloadConfig()
			assert.Equal(t, test.expectedErr, err)
			assert.Equal(t, test.expectedOutput, sm.config)

			for k, _ := range test.folderKeyValues {
				_, deleteErr := sm.vaultClient.Logical().Delete(testBasePathData + k)
				require.NoError(t, deleteErr)
			}
		})
	}
}

var putSingleSecretStringTests = []struct {
	key   string
	value string
}{
	{
		"biba",
		"boba",
	},
	{
		"boba",
		"biba",
	},
}

func TestPutSecretString(t *testing.T) {
	sm, _ := NewSecretManager("", testVaultToken, testBasePathData, testBasePathMetadata, nilLogger)

	for _, test := range putSingleSecretStringTests {
		sm.putSingleSecretStringIntoTheConfig(test.key, test.value)
		assert.Equal(t, test.value, sm.config[test.key])
	}
}

var applyUpdatesToConfigTests = []struct {
	configUpdates config
}{
	{
		configUpdates: config(map[string]any{
			"biba": "boba",
			"ping": "pong",
		}),
	},
	{
		configUpdates: config(map[string]any{
			"boba": "biba",
			"pong": "ping",
		}),
	},
}

func TestApplyUpdatesToConfigAndPurge(t *testing.T) {
	sm, _ := NewSecretManager("", testVaultToken, testBasePathData, testBasePathMetadata, nilLogger)

	for _, test := range applyUpdatesToConfigTests {
		sm.applyUpdatesToConfig(test.configUpdates)
		assert.Equal(t, test.configUpdates, sm.config)
		sm.PurgeConfig()
		assert.Equal(t, config{}, sm.config)
	}
}

var getSecretValuesTests = []struct {
	name        string
	keyToLookup string
	keyValues   config
	testCase    int // 0 - string, 1 - bool
	expectedErr error
}{
	{
		name:        "successful string retrieval",
		keyToLookup: "biba",
		keyValues:   config{"biba": "boba"},
		testCase:    0,
		expectedErr: nil,
	},
	{
		name:        "successful string retrieval",
		keyToLookup: "boba",
		keyValues:   config{"biba": "boba"},
		testCase:    0,
		expectedErr: ErrKeyNotFound,
	},
	{
		name:        "successful bool retrieval",
		keyToLookup: "biba",
		keyValues:   config{"biba": true},
		testCase:    1,
		expectedErr: nil,
	},
	{
		name:        "failed bool retrieval",
		keyToLookup: "biba",
		keyValues:   config{"boba": "boba"},
		testCase:    1,
		expectedErr: ErrKeyNotFound,
	},
	{
		name:        "err on bool conversion",
		keyToLookup: "biba",
		keyValues:   config{"biba": "boba"},
		testCase:    1,
		expectedErr: ErrWhileConvertingToBool,
	},
}

func TestGetFromConfig(t *testing.T) {
	sm, _ := NewSecretManager("", testVaultToken, testBasePathData, testBasePathMetadata, nilLogger)

	for _, test := range getSecretValuesTests {
		t.Run(test.name, func(t *testing.T) {
			sm.config = test.keyValues
			switch test.testCase {
			case 0:
				val, err := sm.GetSecretStringFromConfig(test.keyToLookup)
				assert.True(t, errors.Is(err, test.expectedErr))
				if test.expectedErr == nil {
					assert.Equal(t, test.keyValues[test.keyToLookup], val)
				}
			case 1:
				val, err := sm.GetSecretBoolFromConfig(test.keyToLookup)
				assert.True(t, errors.Is(err, test.expectedErr))
				if test.expectedErr == nil {
					booleanFromConfig, _ := sm.config[test.keyToLookup].(bool)
					assert.Equal(t, booleanFromConfig, val)
				}
			}
		})
	}
}
