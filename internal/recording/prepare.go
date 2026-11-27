package recording

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Do not filter out retransmissions: an overlapping retransmission can carry new bytes.
var tsharkFields = []string{"frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "tcp.seq_raw", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.len", "tcp.payload", "frame.cap_len", "frame.len", "tcp.flags.ack"}

type segment struct {
	seq  uint32
	data []byte
}
type stream struct {
	info    Session
	next    uint32
	closed  bool
	pending []segment
	closeAt *uint32
}
type assembler struct {
	w                         io.Writer
	port                      int
	streams                   map[uint32]*stream
	started                   bool
	base, now                 int64
	pendingBytes              int
	bytes, events, duplicates int64
	localAddresses            map[string]bool
}

func (a *assembler) emit(kind byte, id uint32, payload []byte) error {
	if err := WriteEvent(a.w, Event{Kind: kind, Session: id, OffsetNS: a.now, Payload: payload}); err != nil {
		return err
	}
	a.events++
	return nil
}

func timestampNS(value string) (int64, error) {
	parts := strings.SplitN(value, ".", 2)
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	f := ""
	if len(parts) == 2 {
		f = parts[1]
	}
	if len(f) > 9 {
		f = f[:9]
	}
	f += strings.Repeat("0", 9-len(f))
	n, err := strconv.ParseInt(f, 10, 64)
	if err != nil {
		return 0, err
	}
	return s*1_000_000_000 + n, nil
}

func boolField(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

func (a *assembler) line(line string) error {
	f := strings.Split(line, "\t")
	if len(f) != len(tsharkFields) {
		return fmt.Errorf("分析工具字段不完整，期望 %d 列，得到 %d 列", len(tsharkFields), len(f))
	}
	if f[1] == "" {
		return nil
	}
	dstPort, err := strconv.Atoi(f[7])
	if err != nil {
		return err
	}
	srcPort, err := strconv.Atoi(f[4])
	if err != nil {
		return err
	}
	inbound := dstPort == a.port
	if !inbound && srcPort != a.port {
		return nil
	}
	id64, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return err
	}
	id := uint32(id64)
	source, destination := f[2], f[5]
	if source == "" {
		source = f[3]
	}
	if destination == "" {
		destination = f[6]
	}
	if srcPort == a.port && dstPort == a.port {
		if s := a.streams[id]; s != nil {
			inbound = net.JoinHostPort(source, f[4]) == s.info.Client
		} else if a.localAddresses[destination] && !a.localAddresses[source] {
			inbound = true
		} else if a.localAddresses[source] && !a.localAddresses[destination] {
			inbound = false
		} else if boolField(f[9]) {
			inbound = !boolField(f[16])
		} else {
			return fmt.Errorf("连接两端都使用端口 %d，且录制从连接中途开始，无法确认方向；请先开始抓包，再让硬件重新连接", a.port)
		}
	}
	t, err := timestampNS(f[0])
	if err != nil {
		return err
	}
	if !a.started {
		a.base = t
		a.started = true
	}
	if relative := t - a.base; relative > a.now {
		a.now = relative
	}
	capLen, err := strconv.ParseUint(f[14], 10, 64)
	if err != nil {
		return err
	}
	wireLen, err := strconv.ParseUint(f[15], 10, 64)
	if err != nil {
		return err
	}
	if capLen < wireLen {
		return fmt.Errorf("发现被截断的报文，原始文件已保留，请重新录制完整数据")
	}
	s := a.streams[id]
	if !inbound {
		if s != nil && boolField(f[11]) && !s.closed {
			return a.finish(s)
		}
		return nil
	}
	seq64, err := strconv.ParseUint(f[8], 10, 32)
	if err != nil {
		return err
	}
	seq := uint32(seq64)
	syn := boolField(f[9])
	if syn {
		seq++
	}
	payload, err := hex.DecodeString(strings.ReplaceAll(f[13], ":", ""))
	if err != nil {
		return err
	}
	declared, err := strconv.Atoi(f[12])
	if err != nil {
		return err
	}
	if declared != len(payload) {
		return fmt.Errorf("TCP 数据长度不完整：实际 %d 字节，报文声明 %d 字节", len(payload), declared)
	}
	if s == nil {
		if !syn && len(payload) == 0 {
			return nil
		}
		if len(a.streams) >= 4096 {
			return fmt.Errorf("录制连接数超过 4096，需分批回放")
		}
		src := f[2]
		if src == "" {
			src = f[3]
		}
		dst := f[5]
		if dst == "" {
			dst = f[6]
		}
		s = &stream{info: Session{ID: id, Client: net.JoinHostPort(src, f[4]), Server: net.JoinHostPort(dst, f[7]), Partial: !syn}, next: seq}
		a.streams[id] = s
		if err := a.emit(Open, id, nil); err != nil {
			return err
		}
	}
	if s.closed {
		if len(payload) > 0 {
			a.duplicates++
		}
		return nil
	}
	if len(payload) > 0 {
		if err := a.add(s, seq, payload); err != nil {
			return err
		}
	}
	if boolField(f[11]) {
		return a.finish(s)
	}
	if boolField(f[10]) {
		end := seq + uint32(len(payload))
		s.closeAt = &end
		if int32(s.next-end) >= 0 {
			return a.finish(s)
		}
	}
	return nil
}

func (a *assembler) add(s *stream, seq uint32, data []byte) error {
	offset := int64(int32(seq - s.next))
	if offset < 0 {
		trim := -offset
		if trim >= int64(len(data)) {
			a.duplicates++
			return nil
		}
		data = data[trim:]
		seq = s.next
		a.duplicates++
	}
	if seq != s.next {
		if a.pendingBytes+len(data) > 128*1024*1024 {
			return fmt.Errorf("TCP 乱序缓存超过 128 MiB，抓包可能存在缺失")
		}
		s.pending = append(s.pending, segment{seq: seq, data: append([]byte(nil), data...)})
		a.pendingBytes += len(data)
		return nil
	}
	if err := a.deliver(s, data); err != nil {
		return err
	}
	for {
		found := -1
		for i, p := range s.pending {
			if int32(p.seq-s.next) <= 0 {
				found = i
				break
			}
		}
		if found < 0 {
			if s.closeAt != nil && int32(s.next-*s.closeAt) >= 0 {
				return a.finish(s)
			}
			return nil
		}
		p := s.pending[found]
		s.pending = append(s.pending[:found], s.pending[found+1:]...)
		a.pendingBytes -= len(p.data)
		trim := int64(int32(s.next - p.seq))
		if trim >= int64(len(p.data)) {
			a.duplicates++
			continue
		}
		if trim > 0 {
			a.duplicates++
		}
		if err := a.deliver(s, p.data[trim:]); err != nil {
			return err
		}
	}
}

func (a *assembler) deliver(s *stream, data []byte) error {
	if err := a.emit(Data, s.info.ID, data); err != nil {
		return err
	}
	s.next += uint32(len(data))
	s.info.Bytes += int64(len(data))
	a.bytes += int64(len(data))
	return nil
}

func (a *assembler) finish(s *stream) error {
	if len(s.pending) > 0 {
		return fmt.Errorf("连接 %d 的 TCP 字节流存在缺口，不能完整回放", s.info.ID)
	}
	if err := a.emit(Close, s.info.ID, nil); err != nil {
		return err
	}
	s.closed = true
	return nil
}

func ReassembleTSV(ctx context.Context, input io.Reader, output io.Writer, port int) (Recording, error) {
	return reassemble(ctx, input, output, port, nil)
}

func reassemble(ctx context.Context, input io.Reader, output io.Writer, port int, localAddresses []string) (Recording, error) {
	if err := ValidatePort(port); err != nil {
		return Recording{}, err
	}
	if err := WriteHeader(output); err != nil {
		return Recording{}, err
	}
	a := assembler{w: output, port: port, streams: map[uint32]*stream{}, localAddresses: map[string]bool{}}
	for _, address := range localAddresses {
		a.localAddresses[address] = true
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return Recording{}, err
		}
		if err := a.line(scanner.Text()); err != nil {
			return Recording{}, fmt.Errorf("第 %d 条报文: %w", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Recording{}, err
	}
	ids := make([]int, 0, len(a.streams))
	for id := range a.streams {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	r := Recording{Bytes: a.bytes, DurationNS: a.now, Duplicates: a.duplicates}
	for _, id := range ids {
		s := a.streams[uint32(id)]
		if len(s.pending) > 0 || (s.closeAt != nil && int32(s.next-*s.closeAt) < 0) {
			return Recording{}, fmt.Errorf("连接 %d 的 TCP 字节流存在缺口，原始抓包已保留", id)
		}
		if !s.closed {
			if err := a.finish(s); err != nil {
				return Recording{}, err
			}
		}
		r.Sessions = append(r.Sessions, s.info)
		if s.info.Partial {
			r.Warnings = append(r.Warnings, fmt.Sprintf("连接 %d 从中途录制；回放只包含录制开始后的数据", id))
		}
	}
	r.Events = a.events
	if r.Bytes == 0 {
		return Recording{}, fmt.Errorf("没有抓到发往端口 %d 的 TCP 业务数据，请确认端口和网卡，并让硬件发送数据", port)
	}
	return r, nil
}

func Prepare(ctx context.Context, tshark string, r *Recording) error {
	r.Status = "preparing"
	r.Error = ""
	if err := r.Save(); err != nil {
		return err
	}
	if len(r.CaptureFiles) != 1 {
		return fmt.Errorf("需要先合并为一个抓包文件")
	}
	args := []string{"-n", "-r", filepath.Join(r.Directory, r.CaptureFiles[0]), "-Y", fmt.Sprintf("tcp.port == %d", r.Port), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"}
	for _, field := range tsharkFields {
		args = append(args, "-e", field)
	}
	cmd := exec.CommandContext(ctx, tshark, args...)
	hideCommand(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	diagnostic, err := os.Create(filepath.Join(r.Directory, "analysis.log"))
	if err != nil {
		return err
	}
	defer diagnostic.Close()
	cmd.Stderr = diagnostic
	f, err := os.Create(filepath.Join(r.Directory, "events.tcr.tmp"))
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动分析组件: %w", err)
	}
	writer := bufio.NewWriterSize(f, 1024*1024)
	result, parseErr := reassemble(ctx, stdout, writer, r.Port, r.LocalAddresses)
	if parseErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return parseErr
	}
	if waitErr != nil {
		return fmt.Errorf("抓包分析失败（详见录制目录 analysis.log）: %w", waitErr)
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFile(f.Name(), filepath.Join(r.Directory, "events.tcr")); err != nil {
		return err
	}
	r.Bytes = result.Bytes
	r.Events = result.Events
	r.DurationNS = result.DurationNS
	r.Duplicates = result.Duplicates
	r.Sessions = result.Sessions
	r.Warnings = append(r.Warnings, result.Warnings...)
	r.Status = "ready"
	return r.Save()
}
