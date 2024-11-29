//go:build windows

package netlib

import (
	"net"
	"sync"
	"syscall"
	"unsafe"

	A "github.com/wiresock/ndisapi-go"

	"golang.org/x/sys/windows"
)

// NetworkProcess represents a networking application.
type NetworkProcess struct {
	ID       uint32
	Name     string
	PathName string
}

// NewNetworkProcess constructs an object instance from provided process ID, name, and path.
func NewNetworkProcess(id uint32, name, path string) *NetworkProcess {
	return &NetworkProcess{
		ID:       id,
		Name:     name,
		PathName: path,
	}
}

// ProcessLookup utilizes IP Helper API to match TCP network packets to local processes.
type ProcessLookup struct {
	tcpToApp       sync.Map
	defaultProcess *NetworkProcess
}

// NewProcessLookup initializes the current state of TCP connections.
func NewProcessLookup() (*ProcessLookup, error) {
	instance := &ProcessLookup{
		tcpToApp:       sync.Map{},
		defaultProcess: NewNetworkProcess(0, "System", "System"),
	}
	instance.tcpToApp.Store(0, instance.defaultProcess)

	err := instance.initializeTcpTable()
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// LookupProcessForTcp searches for a process by provided TCP session information.
func (pl *ProcessLookup) LookupProcessForTcp(session IPSession) (*NetworkProcess, error) {
	sessionHash, err := session.Hash()
	if err != nil {
		return pl.defaultProcess, err
	}

	if value, ok := pl.tcpToApp.Load(sessionHash); ok {
		return value.(*NetworkProcess), nil
	}

	return pl.defaultProcess, nil
}

// Actualize updates the TCP hash table.
func (pl *ProcessLookup) Actualize(tcp, udp bool) error {
	if tcp {
		err := pl.initializeTcpTable()
		if err != nil {
			return err
		}
	}

	return nil
}

// ResolveProcessForTcp resolves the process for a given TCP session.
func (pl *ProcessLookup) ResolveProcessForTcp(ipHeader *A.IPHeader, tcpHeader *A.TCPHeader) (*NetworkProcess, error) {
	session := IPSession{
		LocalAddr:  net.IP(ipHeader.SourceAddr[:]),
		RemoteAddr: net.IP(ipHeader.DestinationAddr[:]),
		LocalPort:  A.Ntohs(tcpHeader.SourcePort),
		RemotePort: A.Ntohs(tcpHeader.DestPort),
	}

	process, err := pl.LookupProcessForTcp(session)
	if err != nil {
		return nil, err
	}

	if process != nil && process.ID != 0 {
		return process, nil
	}

	if err := pl.Actualize(true, false); err != nil {
		return nil, err
	}

	process, err = pl.LookupProcessForTcp(session)
	if err != nil {
		return nil, err
	}

	return process, nil
}

// initializeTcpTable initializes or updates the TCP hashtable.
func (pl *ProcessLookup) initializeTcpTable() error {
	var (
		table PMIB_TCPTABLE_OWNER_MODULE
		buf   []byte
		size  uint32
	)

	for {
		if len(buf) > 0 {
			table = (PMIB_TCPTABLE_OWNER_MODULE)(unsafe.Pointer(&buf[0]))
		}

		err := GetExtendedTcpTable(uintptr(unsafe.Pointer(table)),
			&size,
			false,
			syscall.AF_INET,
			TCP_TABLE_OWNER_MODULE_CONNECTIONS,
			0,
		)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return err
		}
		buf = make([]byte, size)
	}

	if int(table.DwNumEntries) == 0 {
		return nil
	}

	pl.tcpToApp.Clear()
	index := int(unsafe.Sizeof(table.DwNumEntries)) + 4
	step := int(unsafe.Sizeof(table.Table))
	for i := 0; i < int(table.DwNumEntries); i++ {
		entry := (*MIB_TCPROW_OWNER_MODULE)(unsafe.Pointer(&buf[index]))

		process := processTcpEntryV4(entry)
		if process != nil {
			ipSession := IPSession{
				LocalAddr:  parseIPv4(entry.DwLocalAddr),
				LocalPort:  A.Ntohs(uint16(entry.DwLocalPort)),
				RemoteAddr: parseIPv4(entry.DwRemoteAddr),
				RemotePort: A.Ntohs(uint16(entry.DwRemotePort)),
			}

			hash, err := ipSession.Hash()
			if err == nil {
				pl.tcpToApp.Store(hash, process)
			}
		}
		index += step
	}

	return nil
}

// processTcpEntryV4 processes a TCP table entry for IPv4 and retrieves the owner module information.
func processTcpEntryV4(tableEntry *MIB_TCPROW_OWNER_MODULE) *NetworkProcess {
	var (
		size       uint32
		processPtr *NetworkProcess
	)

	size = 0

	err := GetOwnerModuleFromTcpEntry(
		uintptr(unsafe.Pointer(tableEntry)),
		TCPIP_OWNER_MODULE_INFO_BASIC,
		0,
		&size,
	)

	if err == windows.ERROR_INSUFFICIENT_BUFFER {
		var buf []byte = make([]byte, size)
		info := (*TCPIP_OWNER_MODULE_BASIC_INFO)(unsafe.Pointer(&buf[0]))

		err := GetOwnerModuleFromTcpEntry(
			uintptr(unsafe.Pointer(tableEntry)),
			TCPIP_OWNER_MODULE_INFO_BASIC,
			uintptr(unsafe.Pointer(info)),
			&size,
		)

		if err == nil && info.ModuleName != nil && info.ModulePath != nil {
			processPtr = &NetworkProcess{
				ID:       tableEntry.DwOwningPid,
				Name:     syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(info.ModuleName))[:]),
				PathName: syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(info.ModulePath))[:]),
			}
		}
	}

	return processPtr
}

// parseIPv4 converts a uint32 IP address to net.IP.
func parseIPv4(addr uint32) net.IP {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// parseIPv6 converts a 16-byte array IP address to net.IP.
func parseIPv6(addr [16]byte) net.IP {
	var ret [16]byte
	for i := 0; i < 16; i++ {
		ret[i] = uint8(addr[i])
	}

	ip := net.IP(ret[:])
	return ip
}
