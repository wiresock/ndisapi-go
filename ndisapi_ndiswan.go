//go:build windows

package ndisapi

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

type ndiswanRegistryKey interface {
	ReadSubKeyNames(int) ([]string, error)
	GetStringValue(string) (string, uint32, error)
	GetStringsValue(string) ([]string, uint32, error)
	Close() error
}

var openNdiswanRegistryKey = func(path string) (ndiswanRegistryKey, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
}

// IsNdiswanInterfaces checks the network class ComponentId and Linkage exports,
// as in the native SDK. Registry access is read-only; missing entries are skipped.
func (a *NdisApi) IsNdiswanInterfaces(adapterName, ndiswanName string) bool {
	if adapterName == "" || ndiswanName == "" {
		return false
	}
	classKey, err := openNdiswanRegistryKey(REGSTR_NETWORK_CONTROL_CLASS)
	if err != nil {
		return false
	}
	defer classKey.Close()
	names, err := classKey.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, name := range names {
		if matchesNdiswanRegistryEntry(REGSTR_NETWORK_CONTROL_CLASS+`\`+name, adapterName, ndiswanName) {
			return true
		}
	}
	return false
}

func matchesNdiswanRegistryEntry(path, adapterName, ndiswanName string) bool {
	entry, err := openNdiswanRegistryKey(path)
	if err != nil {
		return false
	}
	defer entry.Close()
	component, _, err := entry.GetStringValue("ComponentId")
	if err != nil || !strings.EqualFold(component, ndiswanName) {
		return false
	}
	linkage, err := openNdiswanRegistryKey(path + `\Linkage`)
	if err != nil {
		return false
	}
	defer linkage.Close()
	exports, _, err := linkage.GetStringsValue("Export")
	if err == registry.ErrUnexpectedType {
		var export string
		export, _, err = linkage.GetStringValue("Export")
		exports = []string{export}
	}
	if err != nil {
		return false
	}
	for _, export := range exports {
		if strings.EqualFold(export, adapterName) {
			return true
		}
	}
	return false
}
