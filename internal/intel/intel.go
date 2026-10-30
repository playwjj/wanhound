// Package intel classifies a target IP address before any scanning
// happens: is it public, private, loopback, link-local, or inside the
// carrier-grade NAT range (100.64.0.0/10)? The classification decides
// whether a scan is meaningful at all — scanning a CGNAT address audits
// the carrier's NAT, not your home.
package intel

import (
	"fmt"
	"net"

	"github.com/playwjj/wanhound/internal/i18n"
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
	// ClassReserved: documentation, benchmarking (198.18.0.0/15 — also
	// what fake-IP proxies hand out), multicast and other special-purpose
	// ranges that never identify a home line.
	ClassReserved
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
	case ClassReserved:
		return "reserved"
	default:
		return "invalid"
	}
}

var cgnatRange = mustCIDR("100.64.0.0/10")

var reservedRanges = []*net.IPNet{
	mustCIDR("192.0.0.0/24"), mustCIDR("192.0.2.0/24"), mustCIDR("198.18.0.0/15"),
	mustCIDR("198.51.100.0/24"), mustCIDR("203.0.113.0/24"), mustCIDR("240.0.0.0/4"),
	mustCIDR("255.255.255.255/32"), mustCIDR("2001:db8::/32"), mustCIDR("100::/64"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

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
	case ip.IsMulticast() || isReserved(ip):
		return ip, ClassReserved, nil
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

func isReserved(ip net.IP) bool {
	for _, n := range reservedRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Scannable reports whether probing this class of address is meaningful,
// with an explanation when it is not.
func Scannable(c Class) (bool, i18n.Msg) {
	if c == ClassPublic {
		return true, i18n.Msg{}
	}
	key := c.String()
	if c == ClassULA {
		key = "private"
	}
	return false, i18n.M("err.class." + key)
}
