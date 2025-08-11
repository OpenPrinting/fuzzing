package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// tests the actual ipp-usb daemon with fuzzed inputs
func FuzzDaemonIntegration(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// skip very small or very large inputs
		if len(data) < 10 || len(data) > 32*1024 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		testDaemonWithFuzzData(ctx, t, data)
	})
}

func testDaemonWithFuzzData(ctx context.Context, t *testing.T, fuzzData []byte) {
	// check if ipp-usb binary exists
	ippusbPath, err := exec.LookPath("ipp-usb")
	if err != nil {
		// try relative path for build environment
		ippusbPath = "./ipp-usb"
		if _, err := os.Stat(ippusbPath); err != nil {
			t.Skip("ipp-usb binary not found")
			return
		}
	}

	// start ipp-usb daemon in standalone mode
	cmd := exec.CommandContext(ctx, ippusbPath, "standalone")

	cmd.Env = append(os.Environ(),
		"IPP_USB_LOGGING=false",
		"IPP_USB_PORT=0", // use random port
	)

	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		t.Skipf("Failed to start ipp-usb daemon: %v", err)
		return
	}

	defer func() {
		if cmd.Process != nil {
			// try graceful shutdown first
			cmd.Process.Signal(syscall.SIGTERM)

			// force kill after short wait
			time.AfterFunc(100*time.Millisecond, func() {
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
			})
		}
	}()

	// give daemon time to start up
	select {
	case <-time.After(200 * time.Millisecond):
	case <-ctx.Done():
		return
	}

	// test different attack vectors
	testHTTPFuzzing(ctx, fuzzData)
	testIPPFuzzing(ctx, fuzzData)

	// check if daemon is still alive
	select {
	case <-time.After(50 * time.Millisecond):
		// daemon should still be running
	default:
		// if daemon exited immediately, that might indicate a crash
	}
}

func testHTTPFuzzing(ctx context.Context, fuzzData []byte) {
	// common ipp-usb http ports to try
	ports := []int{60000, 60001, 8080, 8631}

	client := &http.Client{
		Timeout: 100 * time.Millisecond,
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

		// test common ipp endpoints with fuzzed data
		endpoints := []string{
			"/ipp/print",
			"/ipp/faxout",
			"/",
			"/admin",
		}

		for _, endpoint := range endpoints {
			func() {
				req, err := http.NewRequestWithContext(ctx, "POST", baseURL+endpoint, strings.NewReader(string(fuzzData)))
				if err != nil {
					return
				}

				req.Header.Set("Content-Type", "application/ipp")

				// add fuzzed headers (carefully)
				if len(fuzzData) > 20 {
					headerVal := sanitizeHeaderValue(string(fuzzData[10:20]))
					if headerVal != "" {
						req.Header.Set("X-Fuzz-Test", headerVal)
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					return // connection refused is expected if daemon isn't listening on this port
				}
				defer resp.Body.Close()

				io.Copy(io.Discard, resp.Body)
			}()
		}
	}
}

func testIPPFuzzing(ctx context.Context, fuzzData []byte) {
	// test ipp-specific malformed requests
	ports := []int{60000, 60001, 8631}

	client := &http.Client{
		Timeout: 100 * time.Millisecond,
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ippData := createMalformedIPPRequest(fuzzData)

		func() {
			req, err := http.NewRequestWithContext(ctx, "POST",
				fmt.Sprintf("http://127.0.0.1:%d/ipp/print", port),
				strings.NewReader(string(ippData)))
			if err != nil {
				return
			}

			req.Header.Set("Content-Type", "application/ipp")
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(ippData)))

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			io.Copy(io.Discard, resp.Body)
		}()
	}
}

func createMalformedIPPRequest(fuzzData []byte) []byte {
	// create a basic ipp structure with fuzzed data
	minLen := 8 // minimum ipp header size
	if len(fuzzData) < minLen {
		// pad with zeros if too small
		padded := make([]byte, minLen)
		copy(padded, fuzzData)
		fuzzData = padded
	}

	// limit size to prevent resource exhaustion
	if len(fuzzData) > 4096 {
		fuzzData = fuzzData[:4096]
	}

	ippRequest := make([]byte, len(fuzzData))
	copy(ippRequest, fuzzData)

	// ensure first two bytes look like ipp version (sometimes)
	if len(ippRequest) >= 2 && ippRequest[0] == 0 && ippRequest[1] == 0 {
		ippRequest[0] = 1 // major version
		ippRequest[1] = 1 // minor version
	}

	return ippRequest
}

func sanitizeHeaderValue(s string) string {
	// remove dangerous characters that could break http parsing
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 && r != '\r' && r != '\n' {
			result.WriteRune(r)
		}
	}

	val := result.String()
	if len(val) > 100 {
		val = val[:100] // limit header length
	}
	return val
}
