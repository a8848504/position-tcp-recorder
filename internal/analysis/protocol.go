package analysis

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type innerFrame struct {
	protocol, device        string
	length, count, sequence int
	inferred                bool
}

// C/0x28 and TO/01/24 are structural inferences from the field recording.
// Their checksums and boundaries are checked, but their semantics are not
// treated as a hardware specification or a proven packet-loss counter.
var cLengths = map[byte][2]int{
	1: {7, 0}, 4: {7, 0}, 2: {9, 0}, 3: {7, 17}, 5: {7, 17}, 6: {7, 2},
	8: {7, 19}, 9: {7, 19}, 10: {9, 2}, 12: {7, 19}, 13: {7, 2}, 14: {7, 2},
	33: {7, 0}, 34: {7, 2}, 37: {7, 19}, 40: {9, 2},
}

func sumOK(b []byte, start int) bool {
	var sum byte
	for _, v := range b[start : len(b)-2] {
		sum += v
	}
	return sum == b[len(b)-2]
}

func parseInner(b []byte) (innerFrame, string) {
	f := innerFrame{sequence: -1}
	if len(b) < 9 {
		return f, ""
	}
	checksum, tail := 1, byte('A')
	switch {
	case bytes.HasPrefix(b, []byte("TO")) && b[2] == 1 && b[3] == 0x24:
		f.protocol = "TO"
		f.length = int(b[4]) + 6
		f.inferred = true
		checksum = 2
		tail = 'B'
	case bytes.HasPrefix(b, []byte("TA")):
		f.protocol = "TA"
		f.length = int(b[3]) + 5
		checksum = 2
		tail = 'B'
	case b[0] == 'L' && b[1] >= 1 && b[1] <= 4:
		f.protocol = "L"
		f.length = 13 + 5*int(b[2])
		f.count = int(b[2])
	case b[0] == 'C':
		layout, ok := cLengths[b[3]]
		if !ok {
			return innerFrame{}, ""
		}
		f.protocol = "C"
		f.length = 15 + int(b[4])*layout[0] + layout[1]
		f.count = int(b[4])
		tail = 'N'
		f.inferred = b[3] == 40
	case b[0] == 'R':
		f.protocol = "R"
		f.length = 9 + 5*int(b[1])
		f.count = int(b[1])
	default:
		return innerFrame{}, ""
	}
	if f.length > len(b) || f.length < 9 {
		return innerFrame{}, ""
	}
	x := b[:f.length]
	// Extract the declared ID before validation so an invalid selected-device
	// frame can be reported without exposing other devices' payloads.
	switch f.protocol {
	case "L":
		f.device = hex.EncodeToString(x[len(x)-10 : len(x)-6])
	case "C":
		st := 5 + cLengths[x[3]][0]*int(x[4])
		f.device = hex.EncodeToString(x[st : st+4])
		f.sequence = int(x[2])
	case "TA", "TO":
		if len(x) < 19 {
			return innerFrame{}, ""
		}
		f.device = hex.EncodeToString(x[len(x)-11 : len(x)-7])
		f.sequence = int(x[4])
		if f.protocol == "TO" {
			f.sequence = int(x[5])
			f.count = int(x[6])
		} else {
			f.count = int(x[5]) + int(x[6]) + int(x[7])
		}
	case "R":
		f.device = hex.EncodeToString(x[len(x)-7 : len(x)-3])
	}
	if x[len(x)-1] != tail {
		if sumOK(x, checksum) {
			return f, fmt.Sprintf("%s 帧尾错误：收到 %02x，应为 %02x", f.protocol, x[len(x)-1], tail)
		}
		return innerFrame{}, ""
	}
	if !sumOK(x, checksum) {
		return f, f.protocol + " 内帧校验和错误"
	}
	return f, ""
}

type decoder struct {
	b              []byte
	skipped        int64
	stream         int
	source, target string
	inbound        bool
	a              *analyzer
}

func (d *decoder) feed(payload []byte, at int64, packet int) error {
	d.b = append(d.b, payload...)
	for len(d.b) >= 4 {
		if !bytes.HasPrefix(d.b, []byte("ETHE")) {
			i := bytes.Index(d.b[1:], []byte("ETHE"))
			if i < 0 {
				i = len(d.b) - 3
			} else {
				i++
			}
			d.skipped += int64(i)
			d.b = d.b[i:]
			continue
		}
		if len(d.b) < 22 {
			break
		}
		n := int(binary.BigEndian.Uint16(d.b[4:6]))
		size := n + 22
		if len(d.b) < size {
			break
		}
		b := d.b[:size]
		if b[size-1] != 'M' || !sumOK(b, 4) {
			d.a.report.OuterInvalid++
			d.a.issue("外层封装错误", packet, at, d.stream, "ETHE 帧尾或校验和错误，已重新查找帧头", b)
			d.b = d.b[1:]
			continue
		}
		d.a.report.OuterValid++
		gateway := hex.EncodeToString(b[n+8 : n+20])
		if n == 0 {
			d.a.report.Heartbeats++
		}
		if n > 0 && d.inbound {
			if err := d.inner(b[8:8+n], gateway, at, packet); err != nil {
				return err
			}
		}
		d.b = d.b[size:]
	}
	// Retain only an incomplete frame, not the backing allocation of a large read.
	if len(d.b) == 0 {
		d.b = nil
	}
	return nil
}

func (d *decoder) inner(b []byte, gateway string, at int64, packet int) error {
	for off := 0; off < len(b); {
		f, reason := parseInner(b[off:])
		if f.length > 0 {
			if reason != "" {
				if d.a.includeDevice(f.device) {
					d.a.report.InnerInvalid++
					before := len(d.a.report.Issues)
					d.a.issue("内帧错误", packet, at, d.stream, reason, b[off:off+f.length])
					if len(d.a.report.Issues) > before {
						d.a.report.Issues[before].Device = f.device
					}
				}
			} else if err := d.a.addFrame(f, gateway, at, packet); err != nil {
				return err
			}
			off += f.length
			continue
		}
		end := off + 1
		for end < len(b) {
			next, _ := parseInner(b[end:])
			if next.length > 0 {
				break
			}
			end++
		}
		d.a.report.UnknownInnerChunks++
		d.a.report.UnknownInnerBytes += int64(end - off)
		if len(d.a.macFilter) == 0 {
			d.a.issue("未识别内载荷", packet, at, d.stream, "外层校验通过，但该内载荷不符合已支持的协议结构", b[off:end])
		}
		off = end
	}
	return nil
}

func (d *decoder) interrupt(packet int, at int64, reason string) {
	if len(d.b) > 0 {
		if bytes.HasPrefix([]byte("ETHE"), d.b) || bytes.HasPrefix(d.b, []byte("ETHE")) {
			d.a.report.IncompleteOuter++
			d.a.issue("不完整外帧", packet, at, d.stream, reason, d.b)
		} else {
			d.skipped += int64(len(d.b))
		}
		d.b = nil
	}
}
