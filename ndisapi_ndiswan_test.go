//go:build windows

package ndisapi

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type ndiswanTestKey struct {
	names        []string
	strings      map[string]string
	multiStrings map[string][]string
	err          error
	closed       int
}

func (k *ndiswanTestKey) ReadSubKeyNames(_ int) ([]string, error) { return k.names, k.err }
func (k *ndiswanTestKey) GetStringValue(name string) (string, uint32, error) {
	if k.err != nil {
		return "", 0, k.err
	}
	if value, ok := k.strings[name]; ok {
		return value, registry.SZ, nil
	}
	if _, ok := k.multiStrings[name]; ok {
		return "", registry.MULTI_SZ, registry.ErrUnexpectedType
	}
	return "", 0, windows.ERROR_FILE_NOT_FOUND
}
func (k *ndiswanTestKey) GetStringsValue(name string) ([]string, uint32, error) {
	if k.err != nil {
		return nil, 0, k.err
	}
	if value, ok := k.multiStrings[name]; ok {
		return value, registry.MULTI_SZ, nil
	}
	if _, ok := k.strings[name]; ok {
		return nil, registry.SZ, registry.ErrUnexpectedType
	}
	return nil, 0, windows.ERROR_FILE_NOT_FOUND
}
func (k *ndiswanTestKey) Close() error { k.closed++; return nil }

func mockNdiswanRegistry(t *testing.T, keys map[string]*ndiswanTestKey) {
	t.Helper()
	previous := openNdiswanRegistryKey
	openNdiswanRegistryKey = func(path string) (ndiswanRegistryKey, error) {
		if key, ok := keys[path]; ok {
			return key, nil
		}
		return nil, windows.ERROR_FILE_NOT_FOUND
	}
	t.Cleanup(func() { openNdiswanRegistryKey = previous })
}

func TestIsNdiswanInterfacesMatchesRegistryComponentAndExport(t *testing.T) {
	for _, component := range []string{REGSTR_COMPONENTID_NDISWANIP, REGSTR_COMPONENTID_NDISWANIPV6, REGSTR_COMPONENTID_NDISWANBH} {
		for _, multi := range []bool{false, true} {
			name := component + "/string"
			if multi {
				name = component + "/multi_string"
			}
			t.Run(name, func(t *testing.T) {
				root := &ndiswanTestKey{names: []string{"0000", "0001", "0002"}}
				unrelated := &ndiswanTestKey{strings: map[string]string{"ComponentId": "ethernet"}}
				entry := &ndiswanTestKey{strings: map[string]string{"ComponentId": component}}
				exports := &ndiswanTestKey{strings: map[string]string{"Export": `\DEVICE\{wan-guid}`}}
				if multi {
					exports.strings = nil
					exports.multiStrings = map[string][]string{"Export": {`\DEVICE\{other-guid}`, `\DEVICE\{wan-guid}`}}
				}
				mockNdiswanRegistry(t, map[string]*ndiswanTestKey{
					REGSTR_NETWORK_CONTROL_CLASS:                   root,
					REGSTR_NETWORK_CONTROL_CLASS + `\0001`:         unrelated,
					REGSTR_NETWORK_CONTROL_CLASS + `\0002`:         entry,
					REGSTR_NETWORK_CONTROL_CLASS + `\0002\Linkage`: exports,
				})
				api := &NdisApi{}
				if !api.IsNdiswanInterfaces(`\device\{WAN-GUID}`, component) {
					t.Fatal("registered NDISWAN export was not identified (case-insensitive match)")
				}
				for name, key := range map[string]*ndiswanTestKey{"root": root, "unrelated": unrelated, "entry": entry, "exports": exports} {
					if key.closed != 1 {
						t.Errorf("%s closed %d times, want 1", name, key.closed)
					}
				}
			})
		}
	}
}

func TestIsNdiswanInterfacesMatchesComponentCaseInsensitively(t *testing.T) {
	mockNdiswanRegistry(t, map[string]*ndiswanTestKey{
		REGSTR_NETWORK_CONTROL_CLASS:                   {names: []string{"0001"}},
		REGSTR_NETWORK_CONTROL_CLASS + `\0001`:         {strings: map[string]string{"ComponentId": "MS_NDISWANIP"}},
		REGSTR_NETWORK_CONTROL_CLASS + `\0001\Linkage`: {strings: map[string]string{"Export": `\DEVICE\{wan-guid}`}},
	})
	if !(&NdisApi{}).IsNdiswanInterfaces(`\DEVICE\{wan-guid}`, REGSTR_COMPONENTID_NDISWANIP) {
		t.Fatal("component ID case prevented an NDISWAN match")
	}
}

func TestIsNdiswanInterfacesRejectsNonMatchingOrUnreadableRegistry(t *testing.T) {
	cases := []struct {
		name, component, adapter, export                                                     string
		rootMissing, enumerationError, componentUnreadable, linkageMissing, exportUnreadable bool
	}{
		{name: "different_component", component: "ethernet", adapter: `\DEVICE\{wan-guid}`, export: `\DEVICE\{wan-guid}`},
		{name: "different_export", component: REGSTR_COMPONENTID_NDISWANIP, adapter: `\DEVICE\{other-guid}`, export: `\DEVICE\{wan-guid}`},
		{name: "partial_export", component: REGSTR_COMPONENTID_NDISWANIP, adapter: `{wan-guid}`, export: `\DEVICE\{wan-guid}`},
		{name: "missing_root", rootMissing: true},
		{name: "enumeration_error", enumerationError: true},
		{name: "component_error", componentUnreadable: true},
		{name: "missing_linkage", component: REGSTR_COMPONENTID_NDISWANIP, linkageMissing: true},
		{name: "export_error", component: REGSTR_COMPONENTID_NDISWANIP, exportUnreadable: true},
		{name: "empty_name", component: REGSTR_COMPONENTID_NDISWANIP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "empty_name" && tc.adapter == "" {
				tc.adapter = `\DEVICE\{wan-guid}`
			}
			if tc.component == "" {
				tc.component = REGSTR_COMPONENTID_NDISWANIP
			}
			if tc.export == "" && tc.name != "empty_name" {
				tc.export = `\DEVICE\{wan-guid}`
			}
			root := &ndiswanTestKey{names: []string{"0001"}}
			entry := &ndiswanTestKey{strings: map[string]string{"ComponentId": tc.component}}
			linkage := &ndiswanTestKey{strings: map[string]string{"Export": tc.export}}
			keys := map[string]*ndiswanTestKey{
				REGSTR_NETWORK_CONTROL_CLASS:                   root,
				REGSTR_NETWORK_CONTROL_CLASS + `\0001`:         entry,
				REGSTR_NETWORK_CONTROL_CLASS + `\0001\Linkage`: linkage,
			}
			if tc.rootMissing {
				delete(keys, REGSTR_NETWORK_CONTROL_CLASS)
			}
			if tc.enumerationError {
				root.err = windows.ERROR_ACCESS_DENIED
			}
			if tc.componentUnreadable {
				entry.err = windows.ERROR_ACCESS_DENIED
			}
			if tc.linkageMissing {
				delete(keys, REGSTR_NETWORK_CONTROL_CLASS+`\0001\Linkage`)
			}
			if tc.exportUnreadable {
				linkage.err = windows.ERROR_ACCESS_DENIED
			}
			mockNdiswanRegistry(t, keys)
			if (&NdisApi{}).IsNdiswanInterfaces(tc.adapter, REGSTR_COMPONENTID_NDISWANIP) {
				t.Fatal("non-matching or unreadable registry was identified as NDISWAN")
			}
		})
	}
}

func TestNdiswanWindowsFastPathsDoNotReadRegistry(t *testing.T) {
	api := &NdisApi{}
	if !api.IsWindows10OrGreater() {
		t.Skip("existing fast paths require Windows 10 or greater")
	}
	previous := openNdiswanRegistryKey
	openNdiswanRegistryKey = func(string) (ndiswanRegistryKey, error) {
		t.Fatal("fast path accessed registry")
		return nil, windows.ERROR_ACCESS_DENIED
	}
	t.Cleanup(func() { openNdiswanRegistryKey = previous })
	if !api.IsNdiswanIP(DEVICE_NDISWANIP) || !api.IsNdiswanIPv6(DEVICE_NDISWANIPV6) || !api.IsNdiswanBh(DEVICE_NDISWANBH) {
		t.Fatal("existing NDISWAN device-name fast path was lost")
	}
}
