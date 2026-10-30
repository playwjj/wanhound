//go:build !windows

package scan

import "net"

// enableICMPErrors is a no-op where connected UDP sockets already report
// ICMP port-unreachable as ECONNREFUSED.
func enableICMPErrors(net.Conn) {}
