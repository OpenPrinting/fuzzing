// CGo binding for Avahi
//
// Copyright (C) 2024 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Fuzz target for go-avahi's string list CGo conversion path
//
//go:build linux || freebsd

package fuzzer

import (
	"strings"
	"testing"
	"unicode/utf8"

	avahi "github.com/OpenPrinting/go-avahi"
)

func FuzzStringArray(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		// Only valid UTF-8: Avahi TXT records are byte strings but
		// the Go layer uses string, and invalid UTF-8 would not
		// represent real-world TXT record inputs.
		if !utf8.ValidString(data) {
			return
		}

		// Split fuzz data into TXT record entries using newline as
		// delimiter, simulating key=value pairs in mDNS TXT records.
		raw := strings.Split(data, "\n")

		var txt []string
		for _, e := range raw {
			if len(e) > 0 && len(e) <= 255 {
				// TXT record strings are limited to 255 bytes
				// per the DNS spec; enforce the limit.
				txt = append(txt, e)
			}
		}

		if len(txt) == 0 {
			return
		}

		// Create a client to exercise the full EntryGroup path that
		// calls makeAvahiStringList internally. Skip if no daemon.
		clnt, err := avahi.NewClient(0)
		if err != nil {
			t.Skip("avahi-daemon not available")
			return
		}
		defer clnt.Close()

		egrp, err := avahi.NewEntryGroup(clnt)
		if err != nil {
			return
		}
		defer egrp.Close()

		// AddService calls makeAvahiStringList on the txt slice.
		// We do not assert success — we assert no panic and no crash.
		_ = egrp.AddService(&avahi.EntryGroupService{
			IfIdx:        avahi.IfIndexUnspec,
			Proto:        avahi.ProtocolUnspec,
			InstanceName: "fuzz-test",
			SvcType:      "_fuzz._tcp",
			Domain:       "",
			Port:         9999,
			Txt:          txt,
		}, 0)
	})
}
