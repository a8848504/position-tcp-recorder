package recording

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Exercise the real TCP path at two speeds. Resume must use the same socket,
// preserve binary bytes, and keep the remaining gap instead of catching up.
func TestPauseResumeTCPAndTimeline(t *testing.T) {
	for _, speed := range []float64{1, 2} {
		t.Run(map[float64]string{1: "normal", 2: "double"}[speed], func(t *testing.T) {
			listener, port := startServer(t)
			received := make(chan byte, 10)
			closed := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					closed <- err
					return
				}
				defer conn.Close()
				var b [1]byte
				for {
					_, err := io.ReadFull(conn, b[:])
					if err != nil {
						closed <- err
						return
					}
					received <- b[0]
				}
			}()
			r := writeRecording(t, []Event{
				{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte{0}},
				{Kind: Data, Session: 0, OffsetNS: 800_000_000, Payload: []byte{0xff}},
				{Kind: Close, Session: 0, OffsetNS: 900_000_000},
			})
			control := &ReplayControl{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- Replay(ctx, r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: speed, Control: control})
			}()
			select {
			case b := <-received:
				if b != 0 {
					t.Fatal(b)
				}
			case <-ctx.Done():
				t.Fatal("no first byte")
			}
			if !control.Pause() || !control.Paused() {
				t.Fatal("pause failed")
			}
			if control.Pause() {
				t.Fatal("second pause changed state")
			}
			select {
			case b := <-received:
				t.Fatalf("data while paused: %x", b)
			case err := <-closed:
				t.Fatalf("socket closed during pause: %v", err)
			case <-time.After(850 * time.Millisecond):
			}
			start := time.Now()
			if !control.Resume() || control.Paused() || control.Resume() {
				t.Fatal("resume state failed")
			}
			select {
			case b := <-received:
				if b != 0xff {
					t.Fatal(b)
				}
			case <-ctx.Done():
				t.Fatal("resume did not send")
			}
			if time.Since(start) < time.Duration(250/speed)*time.Millisecond {
				t.Fatal("resume caught up instead of preserving gap")
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("replay did not finish")
			}
			select {
			case err := <-closed:
				if !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("connection leaked")
			}
			// No reconnect occurred: the only accepted socket carried both bytes.
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
			if conn, err := listener.Accept(); err == nil {
				conn.Close()
				t.Fatal("pause reconnected")
			}
		})
	}
}

func TestStopWhilePausedBeforeFirstConnect(t *testing.T) {
	listener, port := startServer(t)
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte("payload")}, {Kind: Close, Session: 0}})
	control := &ReplayControl{}
	control.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Replay(ctx, r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1, Control: control})
	}()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("connected while paused")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop hung while paused")
	}
}

func TestStopPausedReplayClosesEstablishedConnection(t *testing.T) {
	listener, port := startServer(t)
	first, closed := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		close(first)
		io.Copy(io.Discard, conn)
		close(closed)
	}()
	r := writeRecording(t, []Event{{Kind: Open, Session: 0}, {Kind: Data, Session: 0, Payload: []byte("A")}, {Kind: Close, Session: 0, OffsetNS: 100_000_000_000}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := &ReplayControl{}
	done := make(chan error, 1)
	go func() {
		done <- Replay(ctx, r, ReplayOptions{Host: "127.0.0.1", Port: port, Speed: 1, Control: control})
	}()
	select {
	case <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("no data")
	}
	control.Pause()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop hung")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("socket leaked")
	}
}
