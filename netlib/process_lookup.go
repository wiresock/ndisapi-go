//go:build windows

package netlib

import (
	"context"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessInfo struct {
	ID       uint32
	PathName string
}

type ProcessLookup struct{}

func (s *ProcessLookup) FindProcessInfo(ctx context.Context, isUDP bool, source netip.AddrPort, destination netip.AddrPort, establishedOnly bool) (*ProcessInfo, error) {
	processName, pid, err := findProcessName(isUDP, source.Addr(), int(source.Port()), establishedOnly)
	if err != nil {
		return nil, err
	}
	return &ProcessInfo{PathName: processName, ID: pid}, nil
}

func findProcessName(isUDP bool, ip netip.Addr, srcPort int, establishedOnly bool) (string, uint32, error) {
	family := windows.AF_INET
	if ip.Is6() {
		family = windows.AF_INET6
	}

	const (
		tcpTablePidConn = 4
		udpTablePid     = 1
	)

	var class int
	var fn uintptr
	switch isUDP {
	case false:
		fn = procGetExtendedTcpTable.Addr()
		class = tcpTablePidConn
	case true:
		fn = procGetExtendedUdpTable.Addr()
		class = udpTablePid
	}

	buf, err := getTransportTable(fn, family, class)
	if err != nil {
		return "", 0, err
	}

	s := newSearcher(family == windows.AF_INET, !isUDP)

	pid, err := s.search(buf, ip, uint16(srcPort), establishedOnly)
	if err != nil {
		return "", 0, err
	}
	return getExecPathFromPID(pid)
}

type searcher struct {
	itemSize int
	port     int
	ip       int
	ipSize   int
	pid      int
	tcpState int
}

func (s *searcher) search(b []byte, ip netip.Addr, port uint16, establishedOnly bool) (uint32, error) {
	n := int(readNativeUint32(b[:4]))
	itemSize := s.itemSize
	for i := 0; i < n; i++ {
		row := b[4+itemSize*i : 4+itemSize*(i+1)]

		if establishedOnly && s.tcpState >= 0 {
			fmt.Println(s.tcpState, ip.String())
			tcpState := readNativeUint32(row[s.tcpState : s.tcpState+4])
			// MIB_TCP_STATE_ESTAB, only check established connections for TCP
			if tcpState != 5 {
				continue
			}
		}

		srcPort := syscall.Ntohs(uint16(readNativeUint32(row[s.port : s.port+4])))
		if srcPort != port {
			continue
		}

		srcIP, _ := netip.AddrFromSlice(row[s.ip : s.ip+s.ipSize])
		if ip != srcIP && (!srcIP.IsUnspecified() || s.tcpState != -1) {
			continue
		}

		pid := readNativeUint32(row[s.pid : s.pid+4])
		return pid, nil
	}
	return 0, fmt.Errorf("process not found")
}

func newSearcher(isV4, isTCP bool) *searcher {
	var itemSize, port, ip, ipSize, pid int
	tcpState := -1
	switch {
	case isV4 && isTCP:
		itemSize, port, ip, ipSize, pid, tcpState = 24, 8, 4, 4, 20, 0
	case isV4 && !isTCP:
		itemSize, port, ip, ipSize, pid = 12, 4, 0, 4, 8
	case !isV4 && isTCP:
		itemSize, port, ip, ipSize, pid, tcpState = 56, 20, 0, 16, 52, 48
	case !isV4 && !isTCP:
		itemSize, port, ip, ipSize, pid = 28, 20, 0, 16, 24
	}

	return &searcher{
		itemSize: itemSize,
		port:     port,
		ip:       ip,
		ipSize:   ipSize,
		pid:      pid,
		tcpState: tcpState,
	}
}

func getTransportTable(fn uintptr, family int, class int) ([]byte, error) {
	for size, buf := uint32(8), make([]byte, 8); ; {
		ptr := unsafe.Pointer(&buf[0])
		err, _, _ := syscall.SyscallN(fn, uintptr(ptr), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)

		switch err {
		case 0:
			return buf, nil
		case uintptr(syscall.ERROR_INSUFFICIENT_BUFFER):
			buf = make([]byte, size)
		default:
			return nil, fmt.Errorf("syscall error: %d", err)
		}
	}
}

func readNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func getExecPathFromPID(pid uint32) (string, uint32, error) {
	switch pid {
	case 0:
		return ":System Idle Process", pid, nil
	case 4:
		return ":System", pid, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", pid, err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	r1, _, err := syscall.SyscallN(
		procQueryFullProcessImageNameW.Addr(),
		uintptr(h),
		uintptr(0),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return "", pid, err
	}
	return syscall.UTF16ToString(buf[:size]), pid, nil
}
