//go:build !go1.18 && windows
// +build !go1.18,windows

package netlib

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessInfo struct {
	ID       uint32
	PathName string
}

type ProcessLookup struct{}

func (s *ProcessLookup) FindProcessInfo(ctx context.Context, isUDP bool, source net.Addr, destination net.Addr, establishedOnly bool) (*ProcessInfo, error) {
	srcAddr, srcPort, err := net.SplitHostPort(source.String())
	if err != nil {
		return nil, err
	}
	dstAddr, dstPort, err := net.SplitHostPort(destination.String())
	if err != nil {
		return nil, err
	}

	srcIP := net.ParseIP(srcAddr)
	srcPortInt, err := strconv.Atoi(srcPort)
	if err != nil {
		return nil, err
	}

	processName, pid, err := findProcessName(isUDP, srcIP, srcPortInt, establishedOnly)
	if err != nil {
		return nil, err
	}
	return &ProcessInfo{PathName: processName, ID: pid}, nil
}

func findProcessName(isUDP bool, ip net.IP, srcPort int, establishedOnly bool) (string, uint32, error) {
	family := windows.AF_INET
	if ip.To4() == nil {
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

func (s *searcher) search(b []byte, ip net.IP, port uint16, establishedOnly bool) (uint32, error) {
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

		srcIP := net.IP(row[s.ip : s.ip+s.ipSize])
		if !ip.Equal(srcIP) && (!srcIP.IsUnspecified() || s.tcpState != -1) {
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
		itemSize, port, ip, ipSize, pid = 16, 8, 4, 4, 12
	case !isV4 && isTCP:
		itemSize, port, ip, ipSize, pid, tcpState = 56, 16, 8, 16, 48, 0
	case !isV4 && !isTCP:
		itemSize, port, ip, ipSize, pid = 24, 8, 8, 16, 16
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

func readNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func getTransportTable(fn uintptr, family, class int) ([]byte, error) {
	var size uint32
	ret, _, _ := syscall.Syscall6(fn, 6, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&size)), uintptr(family), uintptr(class), 0)
	if ret != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, syscall.Errno(ret)
	}

	buf := make([]byte, size)
	ret, _, _ = syscall.Syscall6(fn, 6, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&size)), uintptr(family), uintptr(class), 0)
	if ret != 0 {
		return nil, syscall.Errno(ret)
	}
	return buf, nil
}

func getExecPathFromPID(pid uint32) (string, uint32, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", 0, err
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", 0, err
	}
	return windows.UTF16ToString(buf[:]), pid, nil
}
