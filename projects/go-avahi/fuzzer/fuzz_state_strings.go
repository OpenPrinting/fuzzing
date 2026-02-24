/*
 * Fuzz target for go-avahi's enum .String() methods.
 *
 * Tests BrowserEvent, ClientState, EntryGroupState, and ResolverEvent
 * String() methods with arbitrary integer values to ensure they never
 * panic and always return non-empty strings.
 */

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzStateStrings(f *testing.F) {
	// Seed corpus: boundary values
	f.Add(int32(0))
	f.Add(int32(1))
	f.Add(int32(-1))
	f.Add(int32(4))
	f.Add(int32(999))
	f.Add(int32(2147483647))  // MaxInt32
	f.Add(int32(-2147483648)) // MinInt32

	f.Fuzz(func(t *testing.T, val int32) {
		n := int(val)

		// BrowserEvent.String()
		bs := avahi.BrowserEvent(n).String()
		if bs == "" {
			t.Errorf("BrowserEvent(%d).String() returned empty", n)
		}

		// ClientState.String()
		cs := avahi.ClientState(n).String()
		if cs == "" {
			t.Errorf("ClientState(%d).String() returned empty", n)
		}

		// EntryGroupState.String()
		es := avahi.EntryGroupState(n).String()
		if es == "" {
			t.Errorf("EntryGroupState(%d).String() returned empty", n)
		}

		// ResolverEvent.String()
		rs := avahi.ResolverEvent(n).String()
		if rs == "" {
			t.Errorf("ResolverEvent(%d).String() returned empty", n)
		}
	})
}
