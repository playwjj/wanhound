//go:build !windows

package scan

import (
	"errors"
	"syscall"
)

// isRefused: the peer actively refused (TCP RST, or for a connected UDP
// socket an ICMP port-unreachable).
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

var localTransient = []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EADDRNOTAVAIL, syscall.EAGAIN}
