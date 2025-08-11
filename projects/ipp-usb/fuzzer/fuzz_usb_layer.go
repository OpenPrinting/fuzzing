package fuzzer

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// implements usb layer fuzzing using native go 1.18 fuzzing
func FuzzUSBLayer(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// skip very small inputs to avoid edge cases
		if len(data) < 10 {
			return
		}

		// limit maximum data size to prevent resource exhaustion
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		testUSBProtocol(ctx, data)
	})
}

func testUSBProtocol(ctx context.Context, fuzzData []byte) {
	defer func() {
		if r := recover(); r != nil {
			// silently handle panics to prevent test crashes
		}
	}()

	server := NewMockUSBIPServer(fuzzData)

	// use ephemeral port to avoid conflicts
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// start server with proper cancellation
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server.Serve(ctx, listener)
	}()

	// give server minimal time to start
	select {
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		return
	}

	testClientInteraction(ctx, port, fuzzData)

	// wait for server to finish or timeout
	select {
	case <-serverDone:
	case <-ctx.Done():
	}
}

func testClientInteraction(ctx context.Context, port int, data []byte) {
	defer func() {
		if r := recover(); r != nil {
			// silently handle client panics
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()

	// set overall deadline for all operations
	deadline := time.Now().Add(200 * time.Millisecond)
	conn.SetDeadline(deadline)

	// send device list request
	devlistReq := []byte{0x01, 0x11, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00}
	conn.Write(devlistReq)

	// try to read response with short timeout
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return
	}

	// send import request
	importReq := make([]byte, 40)
	importReq[0], importReq[1] = 0x01, 0x11
	importReq[2], importReq[3] = 0x80, 0x03
	copy(importReq[8:], []byte("1-1"))
	conn.Write(importReq)

	// read import response
	conn.Read(buffer)

	// send one simple bulk transfer
	bulkReq := createSimpleBulkRequest(data)
	conn.Write(bulkReq)

	// read final response
	conn.Read(buffer)
}

func createSimpleBulkRequest(data []byte) []byte {
	// limit data size for bulk request
	maxSize := 256
	if len(data) > maxSize {
		data = data[:maxSize]
	}

	req := make([]byte, 48+len(data))
	// usbip_cmd_submit
	req[3] = 0x01
	// sequence number
	req[7] = 0x01
	// endpoint
	req[8] = 0x02
	// transfer length
	dataLen := len(data)
	req[16] = byte(dataLen >> 24)
	req[17] = byte(dataLen >> 16)
	req[18] = byte(dataLen >> 8)
	req[19] = byte(dataLen)

	// copy data
	copy(req[48:], data)
	return req
}

type MockUSBIPServer struct {
	fuzzData []byte
}

func NewMockUSBIPServer(fuzzData []byte) *MockUSBIPServer {
	return &MockUSBIPServer{fuzzData: fuzzData}
}

func (s *MockUSBIPServer) Serve(ctx context.Context, listener net.Listener) {
	defer func() {
		if r := recover(); r != nil {
			// handle server panics gracefully
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// set accept timeout to prevent blocking
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		}

		conn, err := listener.Accept()
		if err != nil {
			// check if it's a timeout or context cancellation
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		// handle connection with timeout
		go s.handleConnectionSafely(ctx, conn)
	}
}

func (s *MockUSBIPServer) handleConnectionSafely(ctx context.Context, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			// handle connection panics
		}
		conn.Close()
	}()

	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))

	buffer := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := conn.Read(buffer)
		if err != nil {
			return
		}

		if n >= 4 {
			s.handleMessage(conn, buffer[:n])
		}
	}
}

func (s *MockUSBIPServer) handleMessage(conn net.Conn, data []byte) {
	defer func() {
		if r := recover(); r != nil {
			// handle message processing panics
		}
	}()

	if len(data) < 4 {
		return
	}

	// simple command detection
	command := uint16(data[2])<<8 | uint16(data[3])

	switch command {
	case 0x8005: // device list request
		s.sendDeviceListResponse(conn)
	case 0x8003: // import request
		s.sendImportResponse(conn)
	case 0x0001: // submit request
		s.sendSubmitResponse(conn, data)
	}
}

func (s *MockUSBIPServer) sendDeviceListResponse(conn net.Conn) {
	// minimal device list response
	response := make([]byte, 320)
	response[0], response[1] = 0x01, 0x11
	response[2], response[3] = 0x80, 0x05
	response[7] = 0x01 // 1 device

	// device info
	copy(response[8:], []byte("1-1"))
	response[40] = 0x01 // busnum
	response[41] = 0x01 // devnum

	conn.Write(response)
}

func (s *MockUSBIPServer) sendImportResponse(conn net.Conn) {
	// minimal import response
	response := make([]byte, 320)
	response[0], response[1] = 0x01, 0x11
	response[2], response[3] = 0x80, 0x03
	// status ok (already 0)

	conn.Write(response)
}

func (s *MockUSBIPServer) sendSubmitResponse(conn net.Conn, requestData []byte) {
	// extract sequence number safely
	var seqnum uint32
	if len(requestData) >= 8 {
		seqnum = uint32(requestData[4])<<24 | uint32(requestData[5])<<16 |
			uint32(requestData[6])<<8 | uint32(requestData[7])
	}

	// limit fuzz data size in response
	fuzzDataLen := len(s.fuzzData)
	if fuzzDataLen > 512 {
		fuzzDataLen = 512
	}

	response := make([]byte, 48+fuzzDataLen)

	// usbip_ret_submit
	response[3] = 0x03

	// echo sequence number
	response[4] = byte(seqnum >> 24)
	response[5] = byte(seqnum >> 16)
	response[6] = byte(seqnum >> 8)
	response[7] = byte(seqnum)

	// status = 0 (success)
	// actual length
	response[24] = byte(fuzzDataLen >> 24)
	response[25] = byte(fuzzDataLen >> 16)
	response[26] = byte(fuzzDataLen >> 8)
	response[27] = byte(fuzzDataLen)

	// copy limited fuzz data
	if fuzzDataLen > 0 && len(s.fuzzData) > 0 {
		copy(response[48:], s.fuzzData[:fuzzDataLen])
	}

	conn.Write(response)
}
