package analysis

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"reflect"
	"strings"
	"testing"
)

func TestMACInputNormalizationAndExactMatching(t *testing.T) {
	got, err := ParseMACs("AA:BB:CC:DD，11-22-33-44; 0xaabbccdd\n AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"aabbccdd", "11223344", "aabbccddeeff"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v want %v", got, want)
	}
	for _, bad := range []string{"123", "ab*cdef0", "863326eg", "---", "1234567"} {
		if _, err := ParseMACs(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if ids, err := ParseMACs(" , ；\n"); err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	a := testAnalyzer()
	a.macFilter = map[string]bool{"00aabbccdd": true}
	if a.includeDevice("aabbccdd") {
		t.Fatal("suffix match must not include a different ID")
	}
}

func frameForID(t *testing.T, id string, seq byte) []byte {
	t.Helper()
	b := cFrame(seq)
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 4 {
		t.Fatal(id, err)
	}
	copy(b[5:9], decoded)
	b[len(b)-2] = 0
	for _, v := range b[1 : len(b)-2] {
		b[len(b)-2] += v
	}
	return b
}

func TestMACFilterKeepsFullTCPStreamAndOnlySelectedReports(t *testing.T) {
	a := testAnalyzer()
	a.macFilter = map[string]bool{"1234abcd": true, "11112222": true, "00000000": true}
	a.report.SelectedMACs = []string{"1234abcd", "11112222", "00000000"}
	c := testChannel(a)
	seq := uint32(100)
	chunks := [][]byte{wrap(append(frameForID(t, "1234abcd", 10), frameForID(t, "aaaabbbb", 25)...)), wrap(frameForID(t, "aaaabbbb", 26)), wrap(append(frameForID(t, "1234abcd", 12), frameForID(t, "11112222", 1)...))}
	for i, b := range chunks {
		// Split the first outer frame at a position crossing an inner frame.
		if i == 0 {
			if err := a.add(c, segment{seq: seq, data: b[:30], at: 100e9, packet: 1}); err != nil {
				t.Fatal(err)
			}
			seq += 30
			b = b[30:]
		}
		if err := a.add(c, segment{seq: seq, data: b, at: int64(100+2*i) * 1e9, packet: i + 2}); err != nil {
			t.Fatal(err)
		}
		seq += uint32(len(b))
	}
	if err := a.finishTCP(); err != nil {
		t.Fatal(err)
	}
	if err := a.finishStats(); err != nil {
		t.Fatal(err)
	}
	r := a.report
	if r.TCPGaps != 0 || r.ScannedInnerValid != 5 || r.InnerValid != 3 || r.ExcludedFrames != 2 || r.DeviceCount != 2 {
		t.Fatalf("%+v", r)
	}
	d := r.Devices[0]
	if d.ID != "1234abcd" || d.Expected != 3 || d.Deficit != 1 || d.Maximum != 4 || d.SequenceSkipped != 1 {
		t.Fatalf("selected gap changed: %+v", d)
	}
	if !reflect.DeepEqual(r.UnmatchedMACs, []string{"00000000"}) {
		t.Fatal(r.UnmatchedMACs)
	}
	dir := t.TempDir()
	if err := writeReport(context.Background(), dir, r); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "devices.csv", "frames.csv", "gaps.csv"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "aaaabbbb") {
			t.Fatal("other device leaked into", name)
		}
	}
}

func TestMACFilterScopesInvalidFramesAndUnknownPayloadPreview(t *testing.T) {
	bad := make([]byte, 13)
	bad[0] = 'L'
	bad[1] = 4
	copy(bad[3:7], []byte{0xaa, 0xbb, 0xcc, 0xdd})
	bad[12] = 0xc1
	for _, v := range bad[1:11] {
		bad[11] += v
	}
	for _, id := range []string{"aabbccdd", "1234abcd"} {
		t.Run(id, func(t *testing.T) {
			a := testAnalyzer()
			a.macFilter = map[string]bool{id: true}
			d := decoder{a: a, inbound: true}
			if err := d.feed(wrap(append(append(bad, 0x99, 0x88), cFrame(1)...)), 1e9, 42); err != nil {
				t.Fatal(err)
			}
			if a.report.UnknownInnerBytes != 2 {
				t.Fatal(a.report)
			}
			for _, x := range a.report.Issues {
				if x.Kind == "未识别内载荷" {
					t.Fatal("unattributable payload should not be exposed in filtered report")
				}
			}
			if id == "aabbccdd" {
				if a.report.InnerInvalid != 1 || len(a.report.Issues) != 1 || a.report.Issues[0].Device != id {
					t.Fatal(a.report)
				}
			} else if a.report.InnerInvalid != 0 || a.report.InnerValid != 1 {
				t.Fatal(a.report)
			}
		})
	}
}

func TestInvalidMACFailsBeforeOpeningCaptureOrCreatingOutput(t *testing.T) {
	dir := t.TempDir()
	_, err := Analyze(context.Background(), "does-not-exist", recording.Recording{Directory: dir, Port: 5000, CaptureFiles: []string{"capture.pcapng"}}, Options{MACs: []string{"bad-mac"}})
	if err == nil || !strings.Contains(err.Error(), "设备 MAC") {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}
