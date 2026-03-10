/*
 * Fuzz target for go-avahi's Client lifecycle.
 *
 * Tests rapid creation and tear-down of Clients to detect race
 * conditions, resource leaks, and panics in the CGo initialization
 * path. Requires a running avahi-daemon; skips if unavailable.
 *
 * Also exercises GetVersionString, GetHostName, GetDomainName, and
 * GetHostFQDN with fuzz-driven repetition to stress the threaded poll
 * lock/unlock cycle.
 */

package fuzzer

import (
	"context"
	"testing"
	"time"

	avahi "github.com/OpenPrinting/go-avahi"
)

func FuzzClientLifecycle(f *testing.F) {
	f.Fuzz(func(t *testing.T, iterations uint8) {
		// Clamp to a sane range to avoid exhausting file descriptors
		if iterations == 0 {
			iterations = 1
		}
		if iterations > 16 {
			iterations = 16
		}

		for i := 0; i < int(iterations); i++ {
			clnt, err := avahi.NewClient(0)
			if err != nil {
				// avahi-daemon not running; skip gracefully
				t.Skip("avahi-daemon not available")
				return
			}

			// Give the client a short window to connect and
			// report its initial state via the event channel.
			ctx, cancel := context.WithTimeout(
				context.Background(), 200*time.Millisecond)

			// Drain the first event (connecting / running)
			clnt.Get(ctx) //nolint:errcheck
			cancel()

			// Exercise the query methods that call into CGo
			// under the threaded poll lock, verifying no panics
			// and no empty return values.
			version := clnt.GetVersionString()
			if version == "" {
				t.Error("GetVersionString returned empty string")
			}

			host := clnt.GetHostName()
			if host == "" {
				t.Error("GetHostName returned empty string")
			}

			domain := clnt.GetDomainName()
			if domain == "" {
				t.Error("GetDomainName returned empty string")
			}

			fqdn := clnt.GetHostFQDN()
			if fqdn == "" {
				t.Error("GetHostFQDN returned empty string")
			}

			// Close must be idempotent — call twice to verify
			clnt.Close()
			clnt.Close()
		}
	})
}
