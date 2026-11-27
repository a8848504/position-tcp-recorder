package recording

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func packet(ts string, id int, seq uint32, payload []byte, syn, fin, server bool) string {
	src, dst, srcPort, dstPort := "10.0.0.1", "10.0.0.2", "30001", "9000"
	if server {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}
	synFlag, finFlag := "0", "0"
	if syn {
		synFlag = "1"
	}
	if fin {
		finFlag = "1"
	}
	ack := "1"
	if syn && !server {
		ack = "0"
	}
	return strings.Join([]string{ts, strconv.Itoa(id), src, "", srcPort, dst, "", dstPort, strconv.FormatUint(uint64(seq), 10), synFlag, finFlag, "0", strconv.Itoa(len(payload)), hex.EncodeToString(payload), "100", "100", ack}, "\t")
}

func payloads(t *testing.T, data []byte) map[uint32][]byte {
	t.Helper()
	if err := ValidateEvents(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	r, err := NewEventReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint32][]byte{}
	for {
		e, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == Data {
			out[e.Session] = append(out[e.Session], e.Payload...)
		}
	}
	return out
}

func TestReassembleBinaryOutOfOrderOverlapAndReplies(t *testing.T) {
	rows := []string{
		packet("1700000000.000000001", 0, 100, nil, true, false, false),
		packet("1700000000.010000001", 0, 104, []byte{0xff}, false, false, false),
		packet("1700000000.020000001", 0, 101, []byte{'A', 0, 'C'}, false, false, false),
		packet("1700000000.030000001", 0, 103, []byte{'C', 0xff, 'X'}, false, false, false),
		packet("1700000000.040000001", 0, 101, []byte{'A', 0, 'C'}, false, false, false),
		packet("1700000000.050000001", 0, 500, []byte("SERVER RESPONSE"), false, false, true),
		packet("1700000000.060000001", 0, 106, nil, false, true, false),
	}
	var out bytes.Buffer
	r, err := ReassembleTSV(context.Background(), strings.NewReader(strings.Join(rows, "\n")), &out, 9000)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloads(t, out.Bytes())[0]; !bytes.Equal(got, []byte{'A', 0, 'C', 0xff, 'X'}) {
		t.Fatalf("payload %x", got)
	}
	if r.Bytes != 5 || r.Duplicates != 2 || r.DurationNS != 60_000_000 {
		t.Fatalf("stats %+v", r)
	}
	if len(r.Sessions) != 1 || r.Sessions[0].Partial {
		t.Fatalf("sessions %+v", r.Sessions)
	}
}

func TestSequenceNumberWrap(t *testing.T) {
	rows := []string{packet("1.0", 0, 0xfffffffd, nil, true, false, false), packet("1.1", 0, 0xfffffffe, []byte("ABCD"), false, false, false), packet("1.2", 0, 0xffffffff, []byte("BCDE"), false, false, false)}
	var out bytes.Buffer
	_, err := ReassembleTSV(context.Background(), strings.NewReader(strings.Join(rows, "\n")), &out, 9000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payloads(t, out.Bytes())[0]); got != "ABCDE" {
		t.Fatal(got)
	}
}

func TestMissingDataIsNotReplayable(t *testing.T) {
	rows := []string{packet("1.0", 0, 100, nil, true, false, false), packet("1.1", 0, 105, []byte("missing-prefix"), false, false, false)}
	_, err := ReassembleTSV(context.Background(), strings.NewReader(strings.Join(rows, "\n")), io.Discard, 9000)
	if err == nil || !strings.Contains(err.Error(), "缺口") {
		t.Fatalf("expected gap error, got %v", err)
	}
}

func TestMidConnectionCaptureIsExplicit(t *testing.T) {
	var out bytes.Buffer
	r, err := ReassembleTSV(context.Background(), strings.NewReader(packet("1.123456789", 3, 900, []byte("ETHE"), false, false, false)), &out, 9000)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 1 || !r.Sessions[0].Partial {
		t.Fatalf("missing partial marker %+v", r)
	}
}

func TestTruncatedPacketRejected(t *testing.T) {
	line := packet("1.0", 0, 100, []byte("payload"), false, false, false)
	fields := strings.Split(line, "\t")
	fields[14] = "60"
	line = strings.Join(fields, "\t")
	_, err := ReassembleTSV(context.Background(), strings.NewReader(line), io.Discard, 9000)
	if err == nil || !strings.Contains(err.Error(), "截断") {
		t.Fatal(err)
	}
}

func TestEmptyCaptureRejected(t *testing.T) {
	_, err := ReassembleTSV(context.Background(), strings.NewReader(""), io.Discard, 9000)
	if err == nil {
		t.Fatal("empty recording accepted")
	}
}

func TestManifestSaveReplaceAndList(t *testing.T) {
	root := t.TempDir()
	r, err := New(root, 9000, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	r.Status = "ready"
	r.Bytes = 123
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	items, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Bytes != 123 || items[0].Status != "ready" {
		t.Fatalf("%+v", items)
	}
}

func writeRecording(t *testing.T, events []Event) Recording {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "events.tcr"))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHeader(f); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := WriteEvent(f, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return Recording{Directory: dir, Status: "ready"}
}

func startServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener, listener.Addr().(*net.TCPAddr).Port
}

func TestReplayPreservesIndependentConnectionsAndBinaryBytes(t *testing.T) {
	listener, port := startServer(t)
	received := make(chan []byte, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var out bytes.Buffer
				buf := make([]byte, 32)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						out.Write(buf[:n])
						_, _ = conn.Write([]byte("reply"))
					}
					if err != nil {
						received <- out.Bytes()
						return
					}
				}
			}()
		}
	}()
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Open, Session: 1, OffsetNS: 10_000_000}, {Kind: Data, Session: 0, OffsetNS: 20_000_000, Payload: []byte{'A', 0, 0xff}}, {Kind: Data, Session: 1, OffsetNS: 30_000_000, Payload: []byte("DEVICE_B")}, {Kind: Data, Session: 0, OffsetNS: 50_000_000, Payload: []byte("END")}, {Kind: Close, Session: 1, OffsetNS: 60_000_000}, {Kind: Close, Session: 0, OffsetNS: 70_000_000}})
	start := time.Now()
	err := Replay(context.Background(), r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 60*time.Millisecond {
		t.Fatal("timing was discarded")
	}
	var got []string
	for range 2 {
		select {
		case b := <-received:
			got = append(got, hex.EncodeToString(b))
		case <-time.After(2 * time.Second):
			t.Fatal("server did not finish")
		}
	}
	sort.Strings(got)
	expected := []string{hex.EncodeToString([]byte{'A', 0, 0xff, 'E', 'N', 'D'}), hex.EncodeToString([]byte("DEVICE_B"))}
	sort.Strings(expected)
	if fmt.Sprint(got) != fmt.Sprint(expected) {
		t.Fatalf("got %v expected %v", got, expected)
	}
}

func TestReplayCanStopDuringLongGap(t *testing.T) {
	listener, port := startServer(t)
	first := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err == nil {
			close(first)
		}
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte("A")}, {Kind: Data, Session: 0, OffsetNS: 100_000_000_000, Payload: []byte("B")}, {Kind: Close, Session: 0, OffsetNS: 101_000_000_000}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Replay(ctx, r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1}) }()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("no first payload")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replay did not stop")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("socket leaked")
	}
}

func TestCorruptRecordingRejectedBeforeConnect(t *testing.T) {
	listener, port := startServer(t)
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte("payload")}, {Kind: Close, Session: 0}})
	path := filepath.Join(r.Directory, "events.tcr")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-22] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Replay(context.Background(), r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1}); err == nil {
		t.Fatal("corruption accepted")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("connected before validating recording")
	}
}

func TestReplayConnectionFailureReported(t *testing.T) {
	listener, port := startServer(t)
	listener.Close()
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte("x")}, {Kind: Close, Session: 0}})
	if err := Replay(context.Background(), r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1}); err == nil {
		t.Fatal("connection failure hidden")
	}
}

func TestInputValidation(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if ValidatePort(port) == nil {
			t.Fatal(port)
		}
	}
	for _, o := range []ReplayOptions{{Host: "cmd.exe", Port: 9000, Speed: 1}, {Host: "127.0.0.1", Port: 0, Speed: 1}, {Host: "127.0.0.1", Port: 9000, Speed: 0}} {
		if ValidateReplay(o) == nil {
			t.Fatal(o)
		}
	}
}

func TestBothEndpointsUseSamePort(t *testing.T) {
	row := func(base string) string {
		f := strings.Split(base, "\t")
		if f[4] == "30001" {
			f[4] = "9000"
		}
		if f[7] == "30001" {
			f[7] = "9000"
		}
		return strings.Join(f, "\t")
	}
	rows := []string{row(packet("1.0", 0, 100, nil, true, false, false)), row(packet("1.1", 0, 501, []byte("SERVER_REPLY"), false, false, true)), row(packet("1.2", 0, 101, []byte("CLIENT_DATA"), false, false, false))}
	var out bytes.Buffer
	_, err := ReassembleTSV(context.Background(), strings.NewReader(strings.Join(rows, "\n")), &out, 9000)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payloads(t, out.Bytes())[0]); got != "CLIENT_DATA" {
		t.Fatalf("direction mixed: %s", got)
	}
}

func TestSamePortMidstreamUsesRecordedServerAddresses(t *testing.T) {
	f := strings.Split(packet("1.0", 0, 501, []byte("SERVER_REPLY"), false, false, true), "\t")
	f[7] = "9000"
	g := strings.Split(packet("1.1", 0, 101, []byte("CLIENT_DATA"), false, false, false), "\t")
	g[4] = "9000"
	var out bytes.Buffer
	_, err := reassemble(context.Background(), strings.NewReader(strings.Join(f, "\t")+"\n"+strings.Join(g, "\t")), &out, 9000, []string{"10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(payloads(t, out.Bytes())[0]); got != "CLIENT_DATA" {
		t.Fatal(got)
	}
}
