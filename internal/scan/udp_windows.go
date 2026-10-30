package scan

import (
	"net"
	"syscall"
	"unsafe"
)

// sioUDPConnReset is SIO_UDP_CONNRESET (_WSAIOW(IOC_VENDOR, 12)).
const sioUDPConnReset = syscall.IOC_IN | syscall.IOC_VENDOR | 12

// enableICMPErrors turns SIO_UDP_CONNRESET back on for a probe socket.
// Go disables it on every Windows UDP socket so servers are not tripped
// up by stray ICMP, but for a probe the ICMP port-unreachable is exactly
// the "closed" signal (it then surfaces as WSAECONNRESET on read).
func enableICMPErrors(c net.Conn) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) {
		on := uint32(1)
		var n uint32
		syscall.WSAIoctl(syscall.Handle(fd), sioUDPConnReset, (*byte)(unsafe.Pointer(&on)), 4, nil, 0, &n, nil, 0)
	})
}
