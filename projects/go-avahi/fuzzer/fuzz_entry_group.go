// CGo binding for Avahi
//
// Copyright (C) 2024 and up by Alexander Pevzner (pzz@apevzner.com)
// See LICENSE for license terms and conditions
//
// Fuzz target for go-avahi's EntryGroup lifecycle
//
//go:build linux || freebsd

package fuzzer

import (
	"context"
	"testing"
	"time"

	avahi "github.com/OpenPrinting/go-avahi"
)

func FuzzEntryGroupLifecycle(f *testing.F) {
	f.Fuzz(func(t *testing.T, count uint8, svcName string, svcType string) {
		if count == 0 {
			count = 1
		}
		if count > 5 {
			count = 5
		}

		clnt, err := avahi.NewClient(0)
		if err != nil {
			t.Skip("avahi-daemon not available")
			return
		}
		defer clnt.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		clnt.Get(ctx) //nolint:errcheck
		cancel()

		egrp, err := avahi.NewEntryGroup(clnt)
		if err != nil {
			return
		}
		defer egrp.Close()

		for i := 0; i < int(count); i++ {
			_ = egrp.AddService(&avahi.EntryGroupService{
				IfIdx:        avahi.IfIndexUnspec,
				Proto:        avahi.ProtocolUnspec,
				InstanceName: svcName,
				SvcType:      svcType,
				Domain:       "local",
				Port:         8080,
				Txt:          []string{"key=value"},
			}, 0)

			_ = egrp.Commit()
			_ = egrp.Reset()

			// Optional intermediate commits
			_ = egrp.Commit()
		}
	})
}
