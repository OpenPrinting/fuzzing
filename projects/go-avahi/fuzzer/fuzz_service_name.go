/*
 * Fuzz target for go-avahi's DomainServiceNameSplit / Join consistency.
 *
 * Tests that splitting a service name and re-joining it produces a
 * name that splits back to the same components.
 */

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzServiceName(f *testing.F) {
	// Seed corpus: realistic mDNS service names
	f.Add("Kyocera ECOSYS M2040dn._ipp._tcp.local")
	f.Add("HP LaserJet._ipps._tcp.local")
	f.Add("My\\.Printer._ipp._tcp.example.com")
	f.Add("_http._tcp.local")
	f.Add("")

	f.Fuzz(func(t *testing.T, data string) {
		// Split the input into components
		instance, svctype, domain := avahi.DomainServiceNameSplit(data)

		if instance == "" && svctype == "" && domain == "" {
			// Invalid service name, nothing more to check
			return
		}

		// Re-join the components
		joined := avahi.DomainServiceNameJoin(instance, svctype, domain)
		if joined == "" {
			t.Errorf("DomainServiceNameJoin(%q, %q, %q) returned empty; "+
				"input=%q", instance, svctype, domain, data)
			return
		}

		// Split the re-joined name and verify consistency
		instance2, svctype2, domain2 := avahi.DomainServiceNameSplit(joined)

		if instance != instance2 {
			t.Errorf("Instance mismatch: %q vs %q; "+
				"input=%q joined=%q",
				instance, instance2, data, joined)
		}

		if svctype != svctype2 {
			t.Errorf("Svctype mismatch: %q vs %q; "+
				"input=%q joined=%q",
				svctype, svctype2, data, joined)
		}

		if domain != domain2 {
			t.Errorf("Domain mismatch: %q vs %q; "+
				"input=%q joined=%q",
				domain, domain2, data, joined)
		}
	})
}
