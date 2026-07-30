package manager

import (
	"maps"
	"reflect"
)

func mergeConfigs(destination, src config) {
	for k, v := range src {
		if _, ok := destination[k]; !ok {
			destination[k] = v
		}
	}
}

func areConfigsDifferent(config1, config2 config) bool {
	return !maps.EqualFunc(config1, config2, func(v1, v2 any) bool {
		return reflect.DeepEqual(v1, v2)
	})
}
