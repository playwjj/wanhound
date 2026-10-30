package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/playwjj/wanhound/internal/i18n"
)

// Profile is passive context about a target address: who announces it
// and what its reverse DNS says. Gathering it never touches the target,
// but it does show the address to a third-party lookup service — the
// report says so, and --offline skips it entirely.
type Profile struct {
	ASN     string     `json:"asn,omitempty"`
	Org     string     `json:"org,omitempty"`
	Country string     `json:"country,omitempty"`
	PTR     []string   `json:"ptr,omitempty"`
	Source  string     `json:"source,omitempty"` // lookup service used
	Hints   []i18n.Msg `json:"hints,omitempty"`
	Error   string     `json:"error,omitempty"`
}

var client = &http.Client{Timeout: 6 * time.Second}

// mobileOrg flags operators that commonly put customers behind
// carrier-grade NAT, where an "IP echo" site shows a shared exit.
var mobileOrg = regexp.MustCompile(`(?i)(mobile|cellular|wireless|lte|\b5g\b|cmnet|移动)`)

var natPTR = regexp.MustCompile(`(?i)(cgn|cgnat|nat\d*\.|pool)`)

// Lookup fetches the ASN/ISP profile and PTR names for ip. Failures
// degrade to a partial profile with Error set; they never stop an audit.
func Lookup(ctx context.Context, ip net.IP) Profile {
	var p Profile
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip.String()); err == nil {
		for _, n := range names {
			p.PTR = append(p.PTR, strings.TrimSuffix(n, "."))
		}
	}
	if err := ipinfo(ctx, ip, &p); err != nil {
		if err2 := ipsb(ctx, ip, &p); err2 != nil {
			p.Error = fmt.Sprintf("ASN lookup failed (%v; %v)", err, err2)
		}
	}
	if mobileOrg.MatchString(p.Org) {
		p.Hints = append(p.Hints, i18n.M("hint.mobile"))
	}
	for _, n := range p.PTR {
		if natPTR.MatchString(n) {
			p.Hints = append(p.Hints, i18n.M("hint.ptr", n))
			break
		}
	}
	return p
}

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "WanHound")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(v)
}

func ipinfo(ctx context.Context, ip net.IP, p *Profile) error {
	var r struct {
		Org     string `json:"org"` // "AS4134 CHINANET-BACKBONE"
		Country string `json:"country"`
		Bogon   bool   `json:"bogon"`
	}
	if err := getJSON(ctx, "https://ipinfo.io/"+ip.String()+"/json", &r); err != nil {
		return err
	}
	if r.Org == "" {
		return fmt.Errorf("ipinfo.io: no org data")
	}
	p.Source = "ipinfo.io"
	p.Country = r.Country
	if asn, org, ok := strings.Cut(r.Org, " "); ok && strings.HasPrefix(asn, "AS") {
		p.ASN, p.Org = asn, org
	} else {
		p.Org = r.Org
	}
	return nil
}

func ipsb(ctx context.Context, ip net.IP, p *Profile) error {
	var r struct {
		ASN     int    `json:"asn"`
		ASNOrg  string `json:"asn_organization"`
		ISP     string `json:"isp"`
		Country string `json:"country_code"`
	}
	if err := getJSON(ctx, "https://api.ip.sb/geoip/"+ip.String(), &r); err != nil {
		return err
	}
	p.Source = "ip.sb"
	if r.ASN > 0 {
		p.ASN = "AS" + strconv.Itoa(r.ASN)
	}
	p.Org = r.ASNOrg
	if p.Org == "" {
		p.Org = r.ISP
	}
	p.Country = r.Country
	return nil
}

// echoURLs return the caller's public address as plain text.
var echoURLs = []string{"https://api64.ipify.org", "https://ifconfig.co/ip", "https://icanhazip.com"}

// Egress returns this machine's public address for the given family
// ("v4" or "v6"), asking echo services over a socket forced to that
// family. Empty when the family has no egress or all services fail.
func Egress(ctx context.Context, family string) string {
	network := "tcp4"
	if family == "v6" {
		network = "tcp6"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 6 * time.Second}
	for _, u := range echoURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/8 (WanHound)")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// IsLocal reports whether ip is assigned to one of this machine's
// interfaces — common with IPv6, where the host's own global address is
// the "public IP". Scanning yourself goes over loopback and says
// nothing about what the internet sees.
func IsLocal(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// Family returns "v4" or "v6" for an address literal.
func Family(ip net.IP) string {
	if ip.To4() != nil {
		return "v4"
	}
	return "v6"
}
