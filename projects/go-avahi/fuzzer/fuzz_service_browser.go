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

func FuzzServiceBrowserLifecycle(f *testing.F) {
	f.Fuzz(func(t *testing.T, count uint8, svcType string, domain string) {
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

		for i := 0; i < int(count); i++ {
			browser, err := avahi.NewServiceBrowser(clnt, avahi.IfIndexUnspec, avahi.ProtocolUnspec, svcType, domain, 0)
			if err != nil {
				continue
			}

			// Optional: try to fetch an event rapidly before tearing down
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
			browser.Get(ctx2) //nolint:errcheck
			cancel2()

			browser.Close()
		}
	})
}
