/*
 * Fuzz target for go-avahi's Domain round-trip consistency.
 *
 * Tests that DomainFrom and DomainSlice are inverse operations,
 * DomainEqual is reflexive for valid domains, and DomainToLower /
 * DomainToUpper are idempotent.
 */

package fuzzer

import (
	"testing"

	"github.com/OpenPrinting/go-avahi"
)

func FuzzDomainRoundTrip(f *testing.F) {
	// Seed corpus: representative domain name strings
	f.Add("example.local")
	f.Add("printer._ipp._tcp.local")
	f.Add("My\\.Printer._ipp._tcp.local")
	f.Add("Kyocera ECOSYS M2040dn._ipp._tcp.local")
	f.Add("")

	f.Fuzz(func(t *testing.T, data string) {
		// 1. Round-trip: DomainSlice → DomainFrom → DomainSlice
		labels := avahi.DomainSlice(data)
		if labels == nil {
			// Invalid domain, skip further checks
			return
		}

		// Reconstruct the domain from parsed labels
		reconstructed := avahi.DomainFrom(labels)

		// Re-parse the reconstructed domain
		labels2 := avahi.DomainSlice(reconstructed)
		if labels2 == nil {
			t.Errorf("DomainSlice(DomainFrom(%q)) returned nil; "+
				"labels=%q reconstructed=%q",
				data, labels, reconstructed)
			return
		}

		// Labels must be identical after round-trip
		if len(labels) != len(labels2) {
			t.Errorf("Round-trip label count mismatch: %d vs %d; "+
				"input=%q labels=%q reconstructed=%q labels2=%q",
				len(labels), len(labels2),
				data, labels, reconstructed, labels2)
			return
		}

		for i := range labels {
			if labels[i] != labels2[i] {
				t.Errorf("Round-trip label mismatch at %d: %q vs %q; "+
					"input=%q",
					i, labels[i], labels2[i], data)
			}
		}

		// 2. DomainNormalize must equal DomainFrom(DomainSlice(data))
		normalized := avahi.DomainNormalize(data)
		if normalized != reconstructed {
			t.Errorf("DomainNormalize(%q) = %q != DomainFrom(DomainSlice(%q)) = %q",
				data, normalized, data, reconstructed)
		}

		// 3. DomainEqual: valid domain must equal itself
		if !avahi.DomainEqual(data, data) {
			t.Errorf("DomainEqual(%q, %q) = false; expected true",
				data, data)
		}

		// 4. DomainToLower / DomainToUpper idempotency
		lower := avahi.DomainToLower(data)
		lowerLower := avahi.DomainToLower(lower)
		if lower != lowerLower {
			t.Errorf("DomainToLower not idempotent: %q → %q → %q",
				data, lower, lowerLower)
		}

		upper := avahi.DomainToUpper(data)
		upperUpper := avahi.DomainToUpper(upper)
		if upper != upperUpper {
			t.Errorf("DomainToUpper not idempotent: %q → %q → %q",
				data, upper, upperUpper)
		}

		// 5. Case-insensitive equality
		if !avahi.DomainEqual(lower, upper) {
			t.Errorf("DomainEqual(lower=%q, upper=%q) = false",
				lower, upper)
		}
	})
}
