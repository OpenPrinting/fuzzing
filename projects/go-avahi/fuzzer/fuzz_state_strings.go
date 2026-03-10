// CGo binding for Avahi
//
// Copyright (C) 2024 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Fuzz target for go-avahi's Domain round-trip consistency
//
//go:build linux || freebsd

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzStateStrings(f *testing.F) {
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
