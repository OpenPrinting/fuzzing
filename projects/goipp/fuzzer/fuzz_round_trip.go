/*
 * Fuzz target for goipp's EncodeBytes + DecodeBytes round-trip consistency.
 */
package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/goipp"
)

func FuzzRoundTrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var m goipp.Message
		if err := m.DecodeBytes(data); err != nil {
			t.Skip()
		}

		encoded, err := m.EncodeBytes()
		if err != nil {
			t.Errorf("Failed to encode: %v", err)
			return
		}

		var m2 goipp.Message
		if err := m2.DecodeBytes(encoded); err != nil {
			t.Errorf("Failed to decode re-encoded: %v", err)
		}
	})
}
