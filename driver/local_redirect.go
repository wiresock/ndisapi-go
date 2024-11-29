//go:build windows

package driver

import (
	"net"
	"strconv"
)

type localRedirect struct {
    originalDestIP  net.IP
    originalSrcPort uint16
}

func newLocalRedirect(originalDestIP net.IP, originalSrcPort uint16) localRedirect {
    return localRedirect{
        originalDestIP: originalDestIP,
        originalSrcPort: originalSrcPort,
    }
}

func (k localRedirect) String() string {
    return k.originalDestIP.String() + ":" + strconv.Itoa(int(k.originalSrcPort))
}

func (k localRedirect) Equal(other localRedirect) bool {
    return k.originalDestIP.Equal(other.originalDestIP) && k.originalSrcPort == other.originalSrcPort
}