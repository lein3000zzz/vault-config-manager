package manager

import "reflect"

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
