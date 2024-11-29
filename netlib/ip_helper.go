//go:build windows

package netlib

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procNotifyIpInterfaceChange    = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2     = modIphlpapi.NewProc("CancelMibChangeNotify2")
	procGetExtendedTCPTable        = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetOwnerModuleFromTcpEntry = modIphlpapi.NewProc("GetOwnerModuleFromTcpEntry")
)

type MibNotificationType uint32

const (
	MibAddInstance         MibNotificationType = 0
	MibDeleteInstance      MibNotificationType = 1
	MibInitialNotification MibNotificationType = 2
)

type IPInterfaceChangeCallback func(callerContext uintptr, row *windows.MibIpInterfaceRow, notificationType MibNotificationType) uintptr

func getUintptrFromBool(value bool) uintptr {
	if value {
		return 1
	}
	return 0
}

func GetOwnerModuleFromTcpEntry(tcpEntry uintptr, infoClass TCPIP_OWNER_MODULE_INFO_CLASS, buffer uintptr, bufferSize *uint32) error {
	r1, _, _ := syscall.SyscallN(procGetOwnerModuleFromTcpEntry.Addr(), tcpEntry, uintptr(infoClass), buffer, uintptr(unsafe.Pointer(bufferSize)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// NotifyIpInterfaceChange registers for network interface change notifications.
func NotifyIpInterfaceChange(callback IPInterfaceChangeCallback, callerContext uintptr, initialNotification bool) (windows.Handle, error) {
	var handle windows.Handle
	ret, _, err := procNotifyIpInterfaceChange.Call(
		uintptr(windows.AF_UNSPEC),
		syscall.NewCallback(callback),
		callerContext,
		getUintptrFromBool(initialNotification),
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, err
	}
	return handle, nil
}

// CancelMibChangeNotify2 cancels the network interface change notifications.
func CancelMibChangeNotify2(handle windows.Handle) error {
	ret, _, err := procCancelMibChangeNotify2.Call(uintptr(handle))
	if ret != 0 {
		return err
	}
	return nil
}

func GetExtendedTcpTable(tcpTable uintptr, size *uint32, order bool, addressFamily uint32, tableClass TCP_TABLE_CLASS, reserved uint32) error {
	r1, _, _ := syscall.SyscallN(procGetExtendedTCPTable.Addr(), tcpTable, uintptr(unsafe.Pointer(size)), getUintptrFromBool(order), uintptr(addressFamily), uintptr(tableClass), uintptr(reserved))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}
