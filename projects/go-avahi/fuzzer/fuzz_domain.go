/*
 * Fuzz target for go-avahi's DomainNormalize function.
 */

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzDomainNormalize(f *testing.F) {
	f.Add("example.local")
	f.Add("printer._ipp._tcp.local")
	f.Add("My\\.Printer._ipp._tcp.local")
	f.Fuzz(func(t *testing.T, data string) {
		_ = avahi.DomainNormalize(data)
	})
}
