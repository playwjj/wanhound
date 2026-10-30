package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UDPState is the outcome of a UDP probe. UDP has no handshake: only a
// reply proves "open" and only an ICMP port-unreachable proves
// "closed"; silence cannot tell an idle service from a firewall.
type UDPState int

const (
	UDPOpen UDPState = iota
	UDPClosed
	UDPOpenFiltered
)

func (s UDPState) String() string {
	switch s {
	case UDPOpen:
		return "open"
	case UDPClosed:
		return "closed"
	default:
		return "open|filtered"
	}
}

func (s UDPState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *UDPState) UnmarshalText(b []byte) error {
	switch string(b) {
	case "open":
		*s = UDPOpen
	case "closed":
		*s = UDPClosed
	case "open|filtered":
		*s = UDPOpenFiltered
	default:
		return fmt.Errorf("unknown udp state %q", b)
	}
	return nil
}

// UDPResult is one probed UDP port.
type UDPResult struct {
	Port    int      `json:"port"`
	Service string   `json:"service"`
	State   UDPState `json:"state"`
	// Detail summarizes the reply (e.g. "recursion available").
	Detail string `json:"detail,omitempty"`
}

// udpProbe is a protocol-correct, harmless request: the same packet a
// normal client sends first. No amplification queries (no NTP monlist,
// no DNS ANY), no credentials (no SNMP community guessing).
type udpProbe struct {
	port    int
	service string
	payload func() []byte
	parse   func([]byte) string
}

// udpProbes is the home-relevant UDP set: DNS, NTP, IKE/IPsec, OpenVPN,
// SSDP/UPnP, mDNS, WireGuard.
var udpProbes = []udpProbe{
	{53, "DNS", dnsQuery, dnsDetail},
	{123, "NTP", ntpRequest, func([]byte) string { return "answers NTP client requests" }},
	{500, "IKE (IPsec VPN)", ikeInit, nil},
	{1194, "OpenVPN", openvpnReset, func([]byte) string { return "OpenVPN server answered a session reset (no tls-auth/tls-crypt)" }},
	{1900, "SSDP (UPnP discovery)", ssdpSearch, ssdpDetail},
	{4500, "IPsec NAT-T", ikeInit, nil},
	{5353, "mDNS", mdnsQuery, func([]byte) string { return "answers multicast-DNS service discovery" }},
	{51820, "WireGuard", func() []byte { return []byte{0} }, nil},
}

// UDPPorts lists the probed UDP ports (for reports and coverage).
func UDPPorts() []int {
	ps := make([]int, len(udpProbes))
	for i, p := range udpProbes {
		ps[i] = p.port
	}
	return ps
}

// UDPServiceName returns the service name WanHound associates with a
// probed UDP port.
func UDPServiceName(port int) string {
	for _, p := range udpProbes {
		if p.port == port {
			return p.service
		}
	}
	return ""
}

// ScanUDP probes the UDP set against ip. Each port gets two attempts.
func ScanUDP(ctx context.Context, ip string, timeout time.Duration) []UDPResult {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	out := make([]UDPResult, len(udpProbes))
	var wg sync.WaitGroup
	for i, p := range udpProbes {
		wg.Add(1)
		go func(i int, p udpProbe) {
			defer wg.Done()
			out[i] = probeUDP(ctx, ip, p, timeout)
		}(i, p)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func probeUDP(ctx context.Context, ip string, p udpProbe, timeout time.Duration) UDPResult {
	r := UDPResult{Port: p.port, Service: p.service, State: UDPOpenFiltered}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, fmt.Sprint(p.port)))
	if err != nil {
		return r
	}
	defer conn.Close()
	buf := make([]byte, 2048)
	for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
		if _, err := conn.Write(p.payload()); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				r.State = UDPClosed
				return r
			}
			continue
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			r.State = UDPOpen
			if p.parse != nil {
				r.Detail = p.parse(buf[:n])
			}
			return r
		}
		// A connected UDP socket surfaces ICMP port-unreachable as
		// ECONNREFUSED on the next read.
		if errors.Is(err, syscall.ECONNREFUSED) {
			r.State = UDPClosed
			return r
		}
	}
	return r
}

// dnsQuery is a standard recursive query for example.com/A.
func dnsQuery() []byte {
	q := []byte{0x57, 0x48, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func dnsDetail(b []byte) string {
	if len(b) < 12 {
		return "answered"
	}
	ra := b[3]&0x80 != 0
	rcode := b[3] & 0x0f
	answers := binary.BigEndian.Uint16(b[6:8])
	if ra && rcode == 0 && answers > 0 {
		return "open resolver: resolves arbitrary names for anyone (recursion available)"
	}
	if ra {
		return "recursion advertised but the query was not answered"
	}
	return "answers DNS but does not recurse"
}

// ntpRequest is an NTPv4 client-mode packet (LI=0, VN=4, Mode=3).
func ntpRequest() []byte {
	b := make([]byte, 48)
	b[0] = 0x23
	return b
}

// ikeInit is a bare IKEv2 header (IKE_SA_INIT, initiator). Responders
// that answer at all typically return INVALID_SYNTAX — enough to show
// the daemon is there.
func ikeInit() []byte {
	b := make([]byte, 28)
	copy(b[0:8], "WanHound")
	b[17] = 0x20 // version 2.0
	b[18] = 34   // IKE_SA_INIT
	b[19] = 0x08 // initiator
	binary.BigEndian.PutUint32(b[24:28], 28)
	return b
}

// openvpnReset is P_CONTROL_HARD_RESET_CLIENT_V2 with an empty ACK set.
func openvpnReset() []byte {
	b := []byte{0x38}
	b = append(b, "WanHound"...)
	return append(b, 0, 0, 0, 0, 0)
}

func ssdpSearch() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n")
}

func ssdpDetail(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			return "UPnP answers from the internet; server=" + strings.TrimSpace(line[7:])
		}
	}
	return "UPnP answers from the internet"
}

// mdnsQuery asks for the DNS-SD service list (unicast-response bit set).
func mdnsQuery() []byte {
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"_services", "_dns-sd", "_udp", "local"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 12, 0x80, 1)
}
