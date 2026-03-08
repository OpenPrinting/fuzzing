/*
 * Fuzz target for go-avahi's DomainNormalize function.
 */

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzDomainNormalize(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_ = avahi.DomainNormalize(data)
	})
}
