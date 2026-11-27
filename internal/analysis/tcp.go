package analysis

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"positioning/tcp-recorder/internal/version"
	"strconv"
	"strings"
	"time"
)

var fields = []string{"frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.seq_raw", "tcp.flags", "tcp.len", "tcp.payload", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission", "tcp.analysis.out_of_order", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment", "tcp.analysis.zero_window", "tcp.analysis.window_full"}

type segment struct {
	seq    uint32
	data   []byte
	at     int64
	packet int
}
type channel struct {
	started    bool
	next       uint32
	pending    []segment
	history    []byte
	decoder    decoder
	connection *Connection
}

func epochNS(s string) (int64, error) {
	p := strings.SplitN(s, ".", 2)
	sec, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil {
		return 0, err
	}
	fraction := ""
	if len(p) == 2 {
		fraction = p[1]
	}
	if len(fraction) > 9 {
		fraction = fraction[:9]
	}
	fraction += strings.Repeat("0", 9-len(fraction))
	ns, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return 0, err
	}
	return sec*1e9 + ns, nil
}

func (a *analyzer) deliver(c *channel, data []byte, at int64, packet int) error {
	a.report.UniqueBytes += int64(len(data))
	if c.decoder.inbound {
		c.connection.InboundBytes += int64(len(data))
	} else {
		c.connection.OutboundBytes += int64(len(data))
	}
	c.next += uint32(len(data))
	c.history = append(c.history, data...)
	if len(c.history) > 65536 {
		c.history = append([]byte(nil), c.history[len(c.history)-65536:]...)
	}
	return c.decoder.feed(data, at, packet)
}

func (a *analyzer) ordered(c *channel, s segment, at int64, packet int) error {
	if back := -int64(int32(s.seq - c.next)); back > 0 {
		n := min(int64(len(s.data)), back)
		if back <= int64(len(c.history)) {
			start := int64(len(c.history)) - back
			if !bytes.Equal(c.history[start:start+n], s.data[:n]) {
				a.report.TCPConflicts++
				a.issue("TCP 重叠冲突", s.packet, s.at, c.decoder.stream, "相同 TCP 序号出现不同载荷，重组保留先收到的字节", s.data[:n])
			}
		}
		a.report.DuplicateSegments++
		s.data = s.data[n:]
		s.seq += uint32(n)
	}
	if len(s.data) == 0 {
		return nil
	}
	return a.deliver(c, s.data, at, packet)
}

func (a *analyzer) drain(c *channel, at int64, packet int) error {
	for {
		found := -1
		for i, s := range c.pending {
			if int32(s.seq-c.next) <= 0 && (found < 0 || int32(s.seq-c.pending[found].seq) < 0) {
				found = i
			}
		}
		if found < 0 {
			return nil
		}
		s := c.pending[found]
		c.pending = append(c.pending[:found], c.pending[found+1:]...)
		a.pendingBytes -= len(s.data)
		if err := a.ordered(c, s, at, packet); err != nil {
			return err
		}
	}
}

func (a *analyzer) add(c *channel, s segment) error {
	if !c.started {
		c.started = true
		c.next = s.seq
	}
	if int32(s.seq-c.next) > 0 {
		if a.pendingBytes+len(s.data) > 128*1024*1024 {
			return fmt.Errorf("TCP 乱序缓存超过 128 MiB，请分段录制")
		}
		c.pending = append(c.pending, s)
		a.pendingBytes += len(s.data)
		return nil
	}
	if err := a.ordered(c, s, s.at, s.packet); err != nil {
		return err
	}
	return a.drain(c, s.at, s.packet)
}

func (a *analyzer) finishTCP() error {
	for _, c := range a.channels {
		for len(c.pending) > 0 {
			if err := a.ctx.Err(); err != nil {
				return err
			}
			idx := 0
			for i := range c.pending {
				if int32(c.pending[i].seq-c.next) < int32(c.pending[idx].seq-c.next) {
					idx = i
				}
			}
			s := c.pending[idx]
			gap := int64(int32(s.seq - c.next))
			if gap > 0 {
				a.report.TCPGaps++
				a.report.MissingTCPBytes += gap
				a.issue("TCP 字节缺口", s.packet, s.at, c.decoder.stream, fmt.Sprintf("本抓包缺少 %d 字节；缺口前后分别拆帧，未拼接跨缺口数据", gap), nil)
				c.decoder.interrupt(s.packet, s.at, "TCP 字节缺口前未完成的外帧")
				c.history = nil
				c.next = s.seq
			}
			if err := a.drain(c, s.at, s.packet); err != nil {
				return err
			}
		}
		c.decoder.interrupt(0, a.lastNS, "录制结束时尚未完成的外帧，可能为录制边界或数据缺失")
		a.report.NonETHEBytes += c.decoder.skipped
	}
	return nil
}

func (a *analyzer) readTSV(input io.Reader, r recording.Recording, progress func(string)) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 65536), 8*1024*1024)
	local := map[string]bool{}
	for _, ip := range r.LocalAddresses {
		local[ip] = true
	}
	sessions := map[int]recording.Session{}
	for _, s := range r.Sessions {
		sessions[int(s.ID)] = s
	}
	ambiguous := map[int]bool{}
	clients := map[int]string{}
	for scanner.Scan() {
		if err := a.ctx.Err(); err != nil {
			return err
		}
		f := strings.Split(scanner.Text(), "\t")
		if len(f) != len(fields) {
			return fmt.Errorf("抓包字段不完整，期望 %d 列，得到 %d 列", len(fields), len(f))
		}
		if f[4] == "" {
			continue
		}
		var values [24]int64
		for _, i := range []int{0, 2, 3, 4, 7, 10, 11, 12, 13} {
			base := 10
			if i == 12 {
				base = 0
			}
			n, err := strconv.ParseInt(f[i], base, 64)
			if err != nil {
				return fmt.Errorf("报文字段 %s 无效: %w", fields[i], err)
			}
			values[i] = n
		}
		packet, stream := int(values[0]), int(values[4])
		at, err := epochNS(f[1])
		if err != nil {
			return err
		}
		if a.report.Packets == 0 || at < a.firstNS {
			a.firstNS = at
		}
		if a.report.Packets == 0 || at > a.lastNS {
			a.lastNS = at
		}
		a.report.Packets++
		if values[3] < values[2] {
			a.report.Truncated++
		}
		for i, label := range map[int]string{15: "retransmission", 16: "fast_retransmission", 17: "spurious_retransmission", 18: "out_of_order", 19: "duplicate_ack", 20: "lost_segment", 21: "ack_lost_segment", 22: "zero_window", 23: "window_full"} {
			if f[i] != "" && f[i] != "0" {
				a.report.Indicators[label]++
			}
		}
		src, dst := f[5], f[8]
		if src == "" {
			src = f[6]
		}
		if dst == "" {
			dst = f[9]
		}
		source, target := net.JoinHostPort(src, f[7]), net.JoinHostPort(dst, f[10])
		inbound := int(values[10]) == r.Port
		known := true
		flags := uint16(values[12])
		if int(values[7]) == r.Port && int(values[10]) == r.Port {
			if s, ok := sessions[stream]; ok {
				inbound = source == s.Client
			} else if local[dst] && !local[src] {
				inbound = true
			} else if local[src] && !local[dst] {
				inbound = false
			} else if client := clients[stream]; client != "" {
				inbound = source == client
			} else if flags&2 != 0 {
				inbound = flags&16 == 0
			} else {
				known = false
				inbound = false
			}
		}
		if !known && !ambiguous[stream] {
			a.report.Warnings = append(a.report.Warnings, fmt.Sprintf("连接 %d 两端端口相同，无法确认上报方向；仅统计 TCP，未计入设备上报", stream))
			ambiguous[stream] = true
		}
		if known {
			if inbound {
				clients[stream] = source
			} else {
				clients[stream] = target
			}
		}
		conn := a.connections[stream]
		if conn == nil {
			if len(a.connections) >= 4096 {
				return fmt.Errorf("连接数超过 4096，请分段录制")
			}
			conn = &Connection{Stream: stream, Client: source, Server: target}
			if !inbound {
				conn.Client, conn.Server = target, source
			}
			a.connections[stream] = conn
		}
		conn.Packets++
		if flags&2 != 0 {
			conn.SYN++
		}
		if flags&1 != 0 {
			conn.FIN++
		}
		if flags&4 != 0 {
			conn.RST++
		}
		payload, err := hex.DecodeString(strings.ReplaceAll(f[14], ":", ""))
		if err != nil {
			return err
		}
		if len(payload) != int(values[13]) {
			if len(payload) > int(values[13]) {
				return fmt.Errorf("报文 %d TCP 载荷长度超出声明", packet)
			}
			if values[3] >= values[2] {
				a.report.Truncated++
			}
			a.issue("截断载荷", packet, at, stream, fmt.Sprintf("仅捕获 %d / %d 字节 TCP 载荷，设备上报统计可能不完整", len(payload), values[13]), payload)
		}
		key := fmt.Sprintf("%d/%s", stream, source)
		c := a.channels[key]
		if c == nil && (len(payload) > 0 || flags&2 != 0) {
			c = &channel{connection: conn, decoder: decoder{stream: stream, source: source, target: target, inbound: inbound && known, a: a}}
			a.channels[key] = c
		}
		seq := uint32(values[11])
		if flags&2 != 0 {
			seq++
			if !c.started {
				c.started = true
				c.next = seq
			}
		}
		if len(payload) > 0 {
			if err := a.add(c, segment{seq: seq, data: payload, at: at, packet: packet}); err != nil {
				return err
			}
		}
		if progress != nil && a.report.Packets%2000 == 0 && time.Since(a.lastProgress) > time.Second {
			progress(fmt.Sprintf("已读取 %d 个网络包，识别 %d 条业务帧…", a.report.Packets, a.report.InnerValid))
			a.lastProgress = time.Now()
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return a.finishTCP()
}

// Analyze reads the original PCAP and writes a separate report directory.
// It never rewrites recording.json, events.tcr, or the original capture.
func Analyze(ctx context.Context, tshark string, r recording.Recording, opts Options) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.ExpectedSeconds == 0 {
		opts.ExpectedSeconds = 2
	}
	if err := ValidateInterval(opts.ExpectedSeconds); err != nil {
		return nil, err
	}
	macs, err := ParseMACs(strings.Join(opts.MACs, ","))
	if err != nil {
		return nil, err
	}
	if err := recording.ValidatePort(r.Port); err != nil {
		return nil, err
	}
	if len(r.CaptureFiles) != 1 {
		return nil, fmt.Errorf("请先用“重新整理”将录制合并为一个抓包文件")
	}
	name := r.CaptureFiles[0]
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `\/`) {
		return nil, fmt.Errorf("录制中的抓包文件名无效")
	}
	root := opts.OutputRoot
	if root == "" {
		root = r.Directory
	}
	staging, err := os.MkdirTemp(root, ".analysis-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	report := &Report{Version: version.Current, Name: r.Name, Note: r.Note, Port: r.Port, CaptureFile: name, Generated: time.Now().Format(time.RFC3339), ExpectedSeconds: opts.ExpectedSeconds, GapThreshold: opts.ExpectedSeconds * 1.5, Indicators: map[string]int{}, ProtocolCounts: map[string]int{}, Warnings: append([]string(nil), r.Warnings...)}
	report.SelectedMACs = macs
	a := &analyzer{ctx: ctx, report: report, devices: map[string]*Device{}, channels: map[string]*channel{}, connections: map[int]*Connection{}}
	if len(macs) > 0 {
		a.macFilter = map[string]bool{}
		for _, id := range macs {
			a.macFilter[id] = true
		}
	}
	args := []string{"-n", "-r", filepath.Join(r.Directory, name), "-Y", fmt.Sprintf("tcp.port == %d", r.Port), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	cmd := exec.CommandContext(ctx, tshark, args...)
	hideCommand(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	log, err := os.Create(filepath.Join(staging, "tshark.log"))
	if err != nil {
		return nil, err
	}
	defer log.Close()
	cmd.Stderr = log
	if opts.Progress != nil {
		opts.Progress("正在读取原始抓包并重组 TCP 字节流…")
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动内置分析组件: %w", err)
	}
	parseErr := a.readTSV(stdout, r, opts.Progress)
	if parseErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	_ = log.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		body, _ := os.ReadFile(filepath.Join(staging, "tshark.log"))
		if len(body) > 2000 {
			body = body[:2000]
		}
		return nil, fmt.Errorf("抓包读取失败: %w\n%s", waitErr, strings.TrimSpace(string(body)))
	}
	if report.Packets == 0 {
		return nil, fmt.Errorf("抓包中没有端口 %d 的 TCP 数据", r.Port)
	}
	if opts.Progress != nil {
		opts.Progress("正在统计设备周期并生成 HTML 报告…")
	}
	if err := a.finishStats(); err != nil {
		return nil, err
	}
	if err := writeReport(ctx, staging, report); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output := filepath.Join(root, "analysis-"+time.Now().Format("20060102-150405")+"-"+strings.TrimPrefix(filepath.Base(staging), ".analysis-"))
	if err := os.Rename(staging, output); err != nil {
		return nil, err
	}
	report.HTMLPath = filepath.Join(output, "report.html")
	return report, nil
}
