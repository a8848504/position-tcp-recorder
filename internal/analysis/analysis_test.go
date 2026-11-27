package analysis

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"strings"
	"testing"
)

func testAnalyzer() *analyzer {
	return &analyzer{ctx: context.Background(), report: &Report{ExpectedSeconds: 2, GapThreshold: 3, Indicators: map[string]int{}, ProtocolCounts: map[string]int{}}, devices: map[string]*Device{}, channels: map[string]*channel{}, connections: map[int]*Connection{}}
}
func wrap(inner []byte) []byte {
	b := make([]byte, len(inner)+22)
	copy(b, "ETHE")
	binary.BigEndian.PutUint16(b[4:6], uint16(len(inner)))
	b[6] = 2
	b[7] = 1
	copy(b[8:], inner)
	copy(b[8+len(inner):], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	for _, v := range b[4 : len(b)-2] {
		b[len(b)-2] += v
	}
	b[len(b)-1] = 'M'
	return b
}
func cFrame(seq byte) []byte {
	b := make([]byte, 15)
	b[0] = 'C'
	b[1] = 1
	b[2] = seq
	b[3] = 0x21
	copy(b[5:], []byte{0x12, 0x34, 0xab, 0xcd})
	b[11] = 36
	b[14] = 'N'
	for _, v := range b[1:13] {
		b[13] += v
	}
	return b
}
func testChannel(a *analyzer) *channel {
	c := &channel{connection: &Connection{}, decoder: decoder{a: a, stream: 1, inbound: true}}
	a.channels["x"] = c
	return c
}

func TestOutOfOrderOverlapWrapAndMultiFrame(t *testing.T) {
	a := testAnalyzer()
	c := testChannel(a)
	// Begin near uint32 wrap, split an outer frame, deliver its tail first,
	// and repeat the complete stream afterwards. Two business frames must
	// remain two reports, not TCP segments or retransmission duplicates.
	b := wrap(append(cFrame(254), cFrame(255)...))
	base := uint32(math.MaxUint32 - 5)
	c.started = true
	c.next = base
	if err := a.add(c, segment{seq: base + 10, data: b[10:], at: 1e9, packet: 1}); err != nil {
		t.Fatal(err)
	}
	if err := a.add(c, segment{seq: base, data: b[:10], at: 2e9, packet: 2}); err != nil {
		t.Fatal(err)
	}
	if err := a.add(c, segment{seq: base, data: b, at: 3e9, packet: 3}); err != nil {
		t.Fatal(err)
	}
	if err := a.finishTCP(); err != nil {
		t.Fatal(err)
	}
	if a.report.InnerValid != 2 || a.report.OuterValid != 1 || a.report.DuplicateSegments != 1 || a.report.TCPGaps != 0 {
		t.Fatalf("%+v", a.report)
	}
	for _, d := range a.devices {
		for _, p := range d.Points {
			if p.At != 2e9 || p.Packet != 2 {
				t.Fatalf("completion provenance: %+v", p)
			}
		}
	}
}

func TestGapDoesNotJoinBrokenFrameToNextFrame(t *testing.T) {
	a := testAnalyzer()
	c := testChannel(a)
	b := wrap(cFrame(3))
	next := wrap(cFrame(4))
	if err := a.add(c, segment{seq: 100, data: b[:12], at: 1e9, packet: 1}); err != nil {
		t.Fatal(err)
	}
	if err := a.add(c, segment{seq: 200, data: next, at: 5e9, packet: 2}); err != nil {
		t.Fatal(err)
	}
	if err := a.finishTCP(); err != nil {
		t.Fatal(err)
	}
	if a.report.InnerValid != 1 || a.report.TCPGaps != 1 || a.report.MissingTCPBytes != 88 || a.report.IncompleteOuter != 1 {
		t.Fatalf("%+v", a.report)
	}
}

func TestProtocolChecksAndUnknownPayload(t *testing.T) {
	// A generated L frame with a valid checksum but wrong footer is invalid,
	// not silently counted. Valid concatenated data after it is still parsed.
	l := make([]byte, 13)
	l[0] = 'L'
	l[1] = 4
	copy(l[3:7], []byte{0xaa, 0xbb, 0xcc, 0xdd})
	l[12] = 0xc1
	for _, v := range l[1:11] {
		l[11] += v
	}
	a := testAnalyzer()
	d := decoder{a: a, inbound: true}
	if err := d.feed(wrap(append(append(l, 0x99, 0x88), cFrame(0)...)), 1e9, 42); err != nil {
		t.Fatal(err)
	}
	if a.report.InnerValid != 1 || a.report.InnerInvalid != 1 || a.report.UnknownInnerBytes != 2 {
		t.Fatalf("%+v", a.report)
	}
	if !strings.Contains(a.report.Issues[0].Detail, "帧尾错误") {
		t.Fatal(a.report.Issues)
	}
}

func TestPeriodStatisticsExcludeHardwareAndBoundaries(t *testing.T) {
	a := testAnalyzer()
	for i, s := range []int64{100, 102, 108} {
		if err := a.addFrame(innerFrame{protocol: "C", device: "1234", sequence: []int{254, 255, 2}[i]}, "gateway", s*1e9, i+1); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.addFrame(innerFrame{protocol: "R", device: "1234", sequence: -1}, "gateway", 1e9, 0)
	if err := a.finishStats(); err != nil {
		t.Fatal(err)
	}
	d := a.report.Devices[0]
	if d.Expected != 5 || d.Frames != 3 || d.Deficit != 2 || d.GapCount != 1 || d.Maximum != 6 || d.SequenceSkipped != 2 || d.SequencePositions != 5 {
		t.Fatalf("%+v", d)
	}
	if a.report.Devices[1].Expected != 0 || a.report.Devices[1].GapCount != 0 {
		t.Fatal("R incorrectly considered periodic")
	}
	for _, v := range []float64{-1, math.NaN(), math.Inf(1), 0.01, 86401} {
		if ValidateInterval(v) == nil {
			t.Fatal(v)
		}
	}
	if ValidateInterval(2.56) != nil {
		t.Fatal("valid fractional interval rejected")
	}
}

func TestHTMLIsOfflineAndNotesCannotInjectScripts(t *testing.T) {
	a := testAnalyzer()
	a.report.Note = "</script><img src=x onerror=alert(1)>"
	a.report.Name = "test"
	_ = a.addFrame(innerFrame{protocol: "C", device: "1234", sequence: 1}, "gateway", 1e9, 1)
	if err := a.finishStats(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeReport(context.Background(), dir, a.report); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(html, []byte(a.report.Note)) || bytes.Contains(html, []byte("__DATA__")) || bytes.Contains(html, []byte("<script src=")) {
		t.Fatal("unsafe or incomplete HTML")
	}
	for _, file := range []string{"report.json", "devices.csv", "gaps.csv", "frames.csv", "issues.csv"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnrecognizedDataStillProducesUsableTCPReport(t *testing.T) {
	a := testAnalyzer()
	c := testChannel(a)
	if err := a.add(c, segment{seq: 1, data: []byte("UNKNOWN_PROTOCOL"), at: 1e9, packet: 1}); err != nil {
		t.Fatal(err)
	}
	if err := a.finishTCP(); err != nil {
		t.Fatal(err)
	}
	if a.report.NonETHEBytes != 16 || a.report.IncompleteOuter != 0 || a.report.InnerValid != 0 {
		t.Fatalf("%+v", a.report)
	}
}

func TestCanceledAnalysisLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Analyze(ctx, "does-not-exist", recording.Recording{Port: 7100, Directory: dir, CaptureFiles: []string{"capture.pcapng"}}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("canceled analysis wrote output", entries, err)
	}
}

func TestTruncatedCaptureAndSamePortAmbiguity(t *testing.T) {
	a := testAnalyzer()
	fields := make([]string, 24)
	for i := range fields {
		fields[i] = ""
	}
	for i, v := range map[int]string{0: "1", 1: "100.000000", 2: "100", 3: "60", 4: "0", 5: "10.0.0.1", 7: "7100", 8: "10.0.0.2", 10: "7100", 11: "100", 12: "0x0018", 13: "46", 14: hex.EncodeToString(wrap(cFrame(1))[:6])} {
		fields[i] = v
	}
	if err := a.readTSV(strings.NewReader(strings.Join(fields, "\t")+"\n"), recording.Recording{Port: 7100}, nil); err != nil {
		t.Fatal(err)
	}
	if a.report.Truncated != 1 || a.report.InnerValid != 0 || len(a.report.Warnings) != 1 {
		t.Fatalf("%+v", a.report)
	}
	if a.report.Packets != 1 {
		t.Fatal(fmt.Sprint(a.report))
	}
}
