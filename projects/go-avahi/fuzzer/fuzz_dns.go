//go:build linux || freebsd

package fuzzer

import (
	"testing"

	avahi "github.com/OpenPrinting/go-avahi"
)

func FuzzDecodeDNSA(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = avahi.DNSDecodeA(data)
	})
}

func FuzzDNSAAAA(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = avahi.DNSDecodeAAAA(data)
	})
}

func FuzzDNSTXT(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = avahi.DNSDecodeTXT(data)
	})
}
