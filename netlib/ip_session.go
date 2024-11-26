//go:build windows

package netlib

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

type IPSession struct {
	LocalAddr  net.IP
	LocalPort  uint16
	RemoteAddr net.IP
	RemotePort uint16
}

func NewIPSession(localAddr net.IP, remoteAddr net.IP, localPort uint16, remotePort uint16) IPSession {
	return IPSession{
		LocalAddr:  localAddr,
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
	}
}

func (s IPSession) Equal(other IPSession) bool {
	return s.LocalAddr.Equal(other.LocalAddr) &&
		s.LocalPort == other.LocalPort &&
		s.RemoteAddr.Equal(other.RemoteAddr) &&
		s.RemotePort == other.RemotePort
}

func (s IPSession) Hash() (uint64, error) {
	h := fnv.New64a()

	_, err := h.Write(s.LocalAddr.To4())
	if err != nil {
		return 0, err
	}

	err = binary.Write(h, binary.LittleEndian, s.LocalPort)
	if err != nil {
		return 0, err
	}

	_, err = h.Write(s.RemoteAddr.To4())
	if err != nil {
		return 0, err
	}

	err = binary.Write(h, binary.LittleEndian, s.RemotePort)
	if err != nil {
		return 0, err
	}

	return h.Sum64(), nil
}