// Package intel classifies a target IP address before any scanning
// happens: is it public, private, loopback, link-local, or inside the
// carrier-grade NAT range (100.64.0.0/10)? The classification decides
// whether a scan is meaningful at all — scanning a CGNAT address audits
// the carrier's NAT, not your home.
package intel

import (
	"fmt"
	"net"
)

// Class is the address classification of a target IP.
type Class int

const (
	ClassInvalid Class = iota
	ClassPublic
	ClassPrivate
	ClassLoopback
	ClassLinkLocal
	ClassCGNAT // 100.64.0.0/10 — carrier-grade NAT shared address space
	ClassULA   // fc00::/7 — IPv6 unique local
	ClassUnspecified
)

func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassPrivate:
		return "private"
	case ClassLoopback:
		return "loopback"
	case ClassLinkLocal:
		return "link-local"
	case ClassCGNAT:
		return "cgnat"
	case ClassULA:
		return "ula"
	case ClassUnspecified:
		return "unspecified"
	default:
		return "invalid"
	}
}

var cgnatRange = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// Classify parses and classifies an IP literal. Hostnames are rejected:
// WanHound audits address literals so a report always names the exact
// address that was probed.
func Classify(s string) (net.IP, Class, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, ClassInvalid, fmt.Errorf("%q is not a valid IP address literal", s)
	}
	switch {
	case ip.IsUnspecified():
		return ip, ClassUnspecified, nil
	case ip.IsLoopback():
		return ip, ClassLoopback, nil
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return ip, ClassLinkLocal, nil
	case cgnatRange.Contains(ip):
		return ip, ClassCGNAT, nil
	case ip.IsPrivate():
		// net.IP.IsPrivate covers RFC1918 and fc00::/7; split ULA out
		// for a clearer report.
		if ip.To4() == nil && (ip[0]&0xfe) == 0xfc {
			return ip, ClassULA, nil
		}
		return ip, ClassPrivate, nil
	default:
		return ip, ClassPublic, nil
	}
}

// Scannable reports whether probing this class of address is meaningful,
// with a human-readable explanation when it is not.
func Scannable(c Class) (bool, string) {
	switch c {
	case ClassPublic:
		return true, ""
	case ClassCGNAT:
		return false, "this address is in 100.64.0.0/10 (carrier-grade NAT): inbound connections terminate at the carrier's NAT, not at your home, so scanning it audits the carrier — not your network. Find the address your router shows on its WAN interface instead; if that is also in this range, your connection has no public IPv4 exposure to audit."
	case ClassPrivate, ClassULA:
		return false, "this is a private/LAN address. WanHound audits your public address from the outside; a private address can only be reached from inside the network (see LanHound for the inside view)."
	case ClassLoopback:
		return false, "this is a loopback address; it exists only on the machine running the tool."
	case ClassLinkLocal:
		return false, "this is a link-local address; it is not routed beyond the local segment."
	case ClassUnspecified:
		return false, "this is the unspecified address (0.0.0.0 / ::); it names no host."
	default:
		return false, "unrecognized address class."
	}
}

// PTR returns the reverse-DNS names for ip (best effort, may be empty).
func PTR(ip net.IP) []string {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return nil
	}
	return names
}
