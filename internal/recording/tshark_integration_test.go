package recording

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Set POSITION_TCP_TSHARK to run a real PCAP -> tshark -> reassembly -> TCP test.
// The fixture contains synthetic binary data, multiple devices, out-of-order
// segments, a partial-overlap retransmission, and service replies.
func TestTsharkPCAPToLiveTCP(t *testing.T) {
	tshark := os.Getenv("POSITION_TCP_TSHARK")
	if tshark == "" {
		t.Skip("POSITION_TCP_TSHARK not set")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), uint32(0), uint32(0), uint32(262144), uint32(1)} {
		if err := binary.Write(f, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	add := func(us uint32, device byte, srcPort uint16, seq, ack uint32, flags byte, payload []byte, server bool) {
		t.Helper()
		src, dst := []byte{10, 0, 0, device}, []byte{10, 0, 0, 200}
		dstPort := uint16(9000)
		if server {
			src, dst = dst, src
			srcPort, dstPort = dstPort, srcPort
		}
		ethernet := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0}
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(payload)))
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:16], src)
		copy(ip[16:20], dst)
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[:2], srcPort)
		binary.BigEndian.PutUint16(tcp[2:4], dstPort)
		binary.BigEndian.PutUint32(tcp[4:8], seq)
		binary.BigEndian.PutUint32(tcp[8:12], ack)
		tcp[12] = 0x50
		tcp[13] = flags
		binary.BigEndian.PutUint16(tcp[14:16], 65535)
		packet := append(append(append(ethernet, ip...), tcp...), payload...)
		for _, v := range []uint32{1700000000, us, uint32(len(packet)), uint32(len(packet))} {
			if err := binary.Write(f, binary.LittleEndian, v); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	first := []byte{'E', 'T', 'H', 'E', 0, 0xff, 'A', 'B', 'C', 'D', 'E', 'F'}
	second := []byte{0xff, 0, 'B', 'I', 'N', 'A', 'R', 'Y'}
	add(0, 1, 30001, 1000, 0, 2, nil, false)
	add(1000, 1, 30001, 5000, 1001, 0x12, nil, true)
	add(2000, 1, 30001, 1001, 5001, 0x10, nil, false)
	add(5000, 2, 30002, 2000, 0, 2, nil, false)
	add(6000, 2, 30002, 6000, 2001, 0x12, nil, true)
	add(7000, 2, 30002, 2001, 6001, 0x10, nil, false)
	add(10000, 1, 30001, 1007, 5001, 0x18, first[6:], false)
	add(20000, 1, 30001, 1001, 5001, 0x18, first[:6], false)
	add(25000, 1, 30001, 5001, 1013, 0x18, []byte("SERVER_ACK"), true)
	add(30000, 2, 30002, 2001, 6001, 0x18, second, false)
	add(40000, 1, 30001, 1005, 5011, 0x18, append(append([]byte(nil), first[4:]...), 'Z'), false)
	add(50000, 1, 30001, 1014, 5011, 0x11, nil, false)
	add(60000, 2, 30002, 2009, 6001, 0x11, nil, false)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r := Recording{Version: FormatVersion, ID: "synthetic", Port: 9000, Directory: dir, CaptureFiles: []string{"synthetic.pcap"}}
	if err := Prepare(context.Background(), tshark, &r); err != nil {
		log, _ := os.ReadFile(filepath.Join(dir, "analysis.log"))
		t.Fatalf("%v\n%s", err, log)
	}
	if r.Status != "ready" || len(r.Sessions) != 2 {
		t.Fatalf("unexpected recording: %+v", r)
	}
	data, err := os.ReadFile(filepath.Join(dir, "events.tcr"))
	if err != nil {
		t.Fatal(err)
	}
	gotMap := payloads(t, data)
	var got []string
	for _, p := range gotMap {
		got = append(got, hex.EncodeToString(p))
	}
	sort.Strings(got)
	expected := []string{hex.EncodeToString(append(append([]byte(nil), first...), 'Z')), hex.EncodeToString(second)}
	sort.Strings(expected)
	if !bytes.Equal([]byte(got[0]+got[1]), []byte(expected[0]+expected[1])) {
		t.Fatalf("reassembled %v expected %v", got, expected)
	}
	listener, port := startServer(t)
	received := make(chan string, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); b, _ := io.ReadAll(c); received <- hex.EncodeToString(b) }(conn)
		}
	}()
	if err := Replay(context.Background(), r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1}); err != nil {
		t.Fatal(err)
	}
	got = nil
	for range 2 {
		select {
		case p := <-received:
			got = append(got, p)
		case <-time.After(2 * time.Second):
			t.Fatal("replay socket not closed")
		}
	}
	sort.Strings(got)
	if got[0] != expected[0] || got[1] != expected[1] {
		t.Fatalf("live TCP bytes %v expected %v", got, expected)
	}
}

func TestFINBeforeMissingSegmentCanRecover(t *testing.T) {
	rows := []string{packet("1.0", 0, 100, nil, true, false, false), packet("1.1", 0, 104, nil, false, true, false), packet("1.2", 0, 101, []byte("ABC"), false, false, false)}
	var out bytes.Buffer
	_, err := ReassembleTSV(context.Background(), bytes.NewBufferString(rows[0]+"\n"+rows[1]+"\n"+rows[2]), &out, 9000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payloads(t, out.Bytes())[0]); got != "ABC" {
		t.Fatal(got)
	}
}
