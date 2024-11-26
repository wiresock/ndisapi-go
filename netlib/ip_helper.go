//go:build windows

package netlib

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetExtendedTCPTable        = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetOwnerModuleFromTcpEntry = modIphlpapi.NewProc("GetOwnerModuleFromTcpEntry")
)

func getUintptrFromBool(value bool) uintptr {
	if value {
		return 1
	}
	return 0
}

func GetExtendedTcpTable(tcpTable uintptr, size *uint32, order bool, addressFamily uint32, tableClass TCP_TABLE_CLASS, reserved uint32) error {
	r1, _, _ := syscall.Syscall6(procGetExtendedTCPTable.Addr(), 6, tcpTable, uintptr(unsafe.Pointer(size)), getUintptrFromBool(order), uintptr(addressFamily), uintptr(tableClass), uintptr(reserved))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func GetOwnerModuleFromTcpEntry(tcpEntry uintptr, infoClass TCPIP_OWNER_MODULE_INFO_CLASS, buffer uintptr, bufferSize *uint32) error {
	r1, _, _ := syscall.Syscall6(procGetOwnerModuleFromTcpEntry.Addr(), 4, tcpEntry, uintptr(infoClass), buffer, uintptr(unsafe.Pointer(bufferSize)), 0, 0)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}
