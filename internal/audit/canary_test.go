package audit

import (
	"context"
	"net"
	"testing"
)

// A host where every canary port accepts (a TUN proxy answering for
// everything) must be refused unless the user overrides it.
func TestInterceptionCanaryRefuses(t *testing.T) {
	saved := canaryPorts
	defer func() { canaryPorts = saved }()
	canaryPorts = nil
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		canaryPorts = append(canaryPorts, ln.Addr().(*net.TCPAddr).Port)
	}
	if n := interceptionCanary(context.Background(), "127.0.0.1"); n != 3 {
		t.Fatalf("canary = %d, want 3", n)
	}
	canaryPorts = append(canaryPorts[:2:2], 1) // one canary refuses → no alarm
	if n := interceptionCanary(context.Background(), "127.0.0.1"); n != 0 {
		t.Errorf("canary with a refusing port = %d, want 0", n)
	}
}
