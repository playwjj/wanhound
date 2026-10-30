package scan

import (
	"errors"
	"syscall"
)

// Winsock error codes. Go's syscall.ECONNREFUSED on Windows is a
// synthetic value that real socket errors never match.
const (
	wsaEMFILE        syscall.Errno = 10024
	wsaEADDRNOTAVAIL syscall.Errno = 10049
	wsaECONNRESET    syscall.Errno = 10054 // UDP: ICMP port-unreachable
	wsaENOBUFS       syscall.Errno = 10055
	wsaECONNREFUSED  syscall.Errno = 10061
)

func isRefused(err error) bool {
	return errors.Is(err, wsaECONNREFUSED) || errors.Is(err, wsaECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)
}

var localTransient = []syscall.Errno{wsaEMFILE, wsaENOBUFS, wsaEADDRNOTAVAIL}
