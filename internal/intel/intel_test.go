package intel

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want Class
	}{
		{"8.8.8.8", ClassPublic},
		{"1.1.1.1", ClassPublic},
		{"192.168.2.1", ClassPrivate},
		{"10.0.0.5", ClassPrivate},
		{"172.16.0.2", ClassPrivate},
		{"100.64.0.1", ClassCGNAT},
		{"100.127.255.254", ClassCGNAT},
		{"100.128.0.1", ClassPublic}, // just outside the /10
		{"127.0.0.1", ClassLoopback},
		{"169.254.1.1", ClassLinkLocal},
		{"2400:3200::1", ClassPublic},
		{"fd00::1", ClassULA},
		{"fe80::1", ClassLinkLocal},
		{"::1", ClassLoopback},
		{"0.0.0.0", ClassUnspecified},
	}
	for _, tc := range cases {
		_, got, err := Classify(tc.in)
		if err != nil {
			t.Errorf("Classify(%s): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Classify(%s) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, _, err := Classify("not-an-ip"); err == nil {
		t.Error("Classify(not-an-ip): expected error")
	}
	if _, _, err := Classify("example.com"); err == nil {
		t.Error("Classify(example.com): hostnames must be rejected")
	}
}

func TestScannable(t *testing.T) {
	if ok, _ := Scannable(ClassPublic); !ok {
		t.Error("public addresses must be scannable")
	}
	for _, c := range []Class{ClassPrivate, ClassCGNAT, ClassLoopback, ClassLinkLocal, ClassULA, ClassUnspecified} {
		if ok, why := Scannable(c); ok || why == "" {
			t.Errorf("Scannable(%v) = %v, want false with explanation", c, ok)
		}
	}
}
