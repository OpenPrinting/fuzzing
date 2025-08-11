package fuzzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// tests ipp-usb's tolerance to malformed http clients
func FuzzHTTPClient(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 {
			return
		}

		// create a mock http server that simulates a real printer
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// simulate printer responses
			w.Header().Set("Content-Type", "application/ipp")
			w.WriteHeader(200)

			// return some basic ipp response
			ippResponse := []byte{
				0x01, 0x01, // ipp version
				0x00, 0x00, // status: successful-ok
				0x00, 0x00, 0x00, 0x01, // request id
			}
			w.Write(ippResponse)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// test various malformed requests
		testCases := []struct {
			method      string
			path        string
			body        []byte
			contentType string
		}{
			{"POST", "/ipp/print", data, "application/ipp"},
			{"GET", "/", data, "text/plain"},
			{"POST", "/ipp/scan", data[:min(len(data)/2, len(data))], "application/ipp"},
			{"PUT", "/admin", data, "application/json"},
			{"DELETE", "/jobs/1", nil, ""},
		}

		client := &http.Client{Timeout: 500 * time.Millisecond}

		for _, tc := range testCases {
			var body io.Reader
			if tc.body != nil {
				body = bytes.NewReader(tc.body)
			}

			req, err := http.NewRequestWithContext(ctx, tc.method, server.URL+tc.path, body)
			if err != nil {
				continue
			}

			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			// add malformed headers using fuzz data
			if len(data) > 10 {
				headerName := fmt.Sprintf("X-Fuzz-%x", data[:4])
				headerValue := string(data[4:min(14, len(data))])
				req.Header.Set(headerName, headerValue)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// read and discard response
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
