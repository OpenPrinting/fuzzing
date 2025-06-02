/*
 * Fuzz target for goipp's DecodeBytes function.
 */


package fuzzer

import (
	"testing"
	"github.com/OpenPrinting/goipp"
)

func FuzzDecBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var m goipp.Message
		if err := m.DecodeBytes(data); err != nil {
			t.Skip()
		}
	})
}