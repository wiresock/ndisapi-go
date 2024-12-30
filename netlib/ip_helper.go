//go:build windows

package netlib

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procNotifyIpInterfaceChange    = modIphlpapi.NewProc("NotifyIpInterfaceChange")
	procCancelMibChangeNotify2     = modIphlpapi.NewProc("CancelMibChangeNotify2")
	procGetBestInterfaceEx         = modIphlpapi.NewProc("GetBestInterfaceEx")
	procGetExtendedTcpTable        = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable        = modIphlpapi.NewProc("GetExtendedUdpTable")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
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

func getBestInterfaceEx(destAddr []byte, bestIfIndex *uint32) error {
	if len(destAddr) < 64 {
		return fmt.Errorf("destAddr must be at least 64 bytes")
	}

	r1, _, _ := procGetBestInterfaceEx.Call(
		uintptr(unsafe.Pointer(&destAddr[0])),
		uintptr(unsafe.Pointer(bestIfIndex)),
	)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}