package recording

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type ReplayOptions struct {
	Host     string
	Port     int
	Speed    float64
	Progress func(bytes int64)
	Control  *ReplayControl
}

func ValidateReplay(options ReplayOptions) error {
	if net.ParseIP(options.Host) == nil {
		return fmt.Errorf("请输入有效的目标 IPv4 或 IPv6 地址")
	}
	if err := ValidatePort(options.Port); err != nil {
		return err
	}
	if math.IsNaN(options.Speed) || math.IsInf(options.Speed, 0) || options.Speed < 0.1 || options.Speed > 10 {
		return fmt.Errorf("回放倍速必须在 0.1 到 10 之间")
	}
	return nil
}

func Replay(ctx context.Context, r Recording, options ReplayOptions) error {
	if err := ValidateReplay(options); err != nil {
		return err
	}
	if r.Status != "ready" {
		return fmt.Errorf("请选择已完成分析的录制")
	}
	f, err := os.Open(filepath.Join(r.Directory, "events.tcr"))
	if err != nil {
		return err
	}
	defer f.Close()
	// Validate before opening any network connection, including CRC and event order.
	if err := ValidateEvents(bufio.NewReaderSize(f, 1024*1024)); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader, err := NewEventReader(bufio.NewReaderSize(f, 1024*1024))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	control := options.Control
	if control == nil {
		control = &ReplayControl{}
	}
	if err := control.start(); err != nil {
		return err
	}
	defer control.finish()
	address := net.JoinHostPort(options.Host, strconv.Itoa(options.Port))
	var wg sync.WaitGroup
	var sent atomic.Int64
	var active atomic.Int32
	errorsCh := make(chan error, 1)
	workers := map[uint32]chan Event{}
	report := func(err error) {
		select {
		case errorsCh <- err:
		default:
		}
		cancel()
	}
	startWorker := func(id uint32, queue chan Event) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer active.Add(-1)
			var conn net.Conn
			var stopClose func() bool
			defer func() {
				if stopClose != nil {
					stopClose()
				}
				if conn != nil {
					conn.Close()
				}
			}()
			for {
				var event Event
				select {
				case <-ctx.Done():
					return
				case item, ok := <-queue:
					if !ok {
						return
					}
					event = item
				}
				keepGoing := false
				err := control.perform(ctx, time.Duration(float64(event.OffsetNS)/options.Speed), func() {
					switch event.Kind {
					case Open:
						dialer := net.Dialer{Timeout: 5 * time.Second}
						var err error
						conn, err = dialer.DialContext(ctx, "tcp", address)
						if err != nil {
							report(fmt.Errorf("连接 %d 无法连接 %s: %w", id, address, err))
							return
						}
						stopClose = context.AfterFunc(ctx, func() { conn.Close() })
						go func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }(conn)
					case Data:
						if conn == nil {
							report(fmt.Errorf("连接 %d 尚未建立", id))
							return
						}
						if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
							report(err)
							return
						}
						payload := event.Payload
						for len(payload) > 0 {
							n, err := conn.Write(payload)
							if err != nil {
								report(fmt.Errorf("连接 %d 发送失败，已发送 %d 字节: %w", id, sent.Load(), err))
								return
							}
							if n == 0 {
								report(io.ErrNoProgress)
								return
							}
							payload = payload[n:]
							sent.Add(int64(n))
						}
					case Close:
						if tcp, ok := conn.(*net.TCPConn); ok {
							_ = tcp.CloseWrite()
						}
						return
					}
					keepGoing = true
				})
				if err != nil || !keepGoing {
					return
				}
			}
		}()
	}
	var feedErr error
	var lastProgress time.Time
	for {
		e, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			feedErr = err
			cancel()
			break
		}
		if err := control.wait(ctx, time.Duration(float64(e.OffsetNS)/options.Speed)); err != nil {
			feedErr = err
			break
		}
		if e.Kind == Open {
			if active.Add(1) > 1024 {
				active.Add(-1)
				feedErr = fmt.Errorf("同时回放连接超过 1024，已停止")
				cancel()
				break
			}
			q := make(chan Event, 16)
			workers[e.Session] = q
			startWorker(e.Session, q)
		}
		q, ok := workers[e.Session]
		if !ok {
			feedErr = fmt.Errorf("回放会话状态异常")
			cancel()
			break
		}
		select {
		case q <- e:
		case <-ctx.Done():
			feedErr = ctx.Err()
		}
		if feedErr != nil {
			break
		}
		if e.Kind == Close {
			delete(workers, e.Session)
		}
		if options.Progress != nil && time.Since(lastProgress) >= 100*time.Millisecond {
			options.Progress(sent.Load())
			lastProgress = time.Now()
		}
	}
	if feedErr != nil {
		cancel()
	}
	for _, q := range workers {
		close(q)
	}
	wg.Wait()
	if options.Progress != nil {
		options.Progress(sent.Load())
	}
	select {
	case err := <-errorsCh:
		return err
	default:
	}
	if feedErr != nil {
		return feedErr
	}
	return ctx.Err()
}
