package analysis

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

const maxFrames = 1_000_000

type Options struct {
	ExpectedSeconds float64
	MACs            []string
	OutputRoot      string
	Progress        func(string)
}

func ValidateInterval(seconds float64) error {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0.1 || seconds > 86400 {
		return fmt.Errorf("上报周期必须在 0.1 到 86400 秒之间")
	}
	return nil
}

type Point struct {
	At                      int64
	Packet, Sequence, Count int
}
type Gap struct {
	StartMS    int64   `json:"start"`
	EndMS      int64   `json:"end"`
	Seconds    float64 `json:"seconds"`
	FromPacket int     `json:"from_packet"`
	ToPacket   int     `json:"to_packet"`
	FromSeq    int     `json:"from_seq"`
	ToSeq      int     `json:"to_seq"`
}
type Device struct {
	ID                string       `json:"id"`
	Protocol          string       `json:"protocol"`
	Gateway           string       `json:"gateway"`
	Frames            int          `json:"frames"`
	FirstMS           int64        `json:"first"`
	LastMS            int64        `json:"last"`
	Expected          int          `json:"expected"`
	Deficit           int          `json:"deficit"`
	Median            float64      `json:"median"`
	P95               float64      `json:"p95"`
	Maximum           float64      `json:"maximum"`
	GapCount          int          `json:"gap_count"`
	SequenceMode      string       `json:"sequence_mode"`
	SequenceSkipped   int          `json:"sequence_skipped"`
	SequencePositions int          `json:"sequence_positions"`
	SequenceRepeated  int          `json:"sequence_repeated"`
	SequenceTypical   float64      `json:"sequence_typical"`
	Inferred          bool         `json:"inferred"`
	ZeroCount         int          `json:"zero_count"`
	Points            []Point      `json:"-"`
	Gaps              []Gap        `json:"-"`
	TopGaps           []Gap        `json:"top_gaps"`
	PlotPoints        [][3]float64 `json:"points"`
	Intervals         [][4]float64 `json:"intervals"`
	PlotLimited       bool         `json:"plot_limited"`
}
type Issue struct {
	Device string `json:"device,omitempty"`
	Kind   string `json:"kind"`
	Packet int    `json:"packet"`
	AtMS   int64  `json:"time"`
	Stream int    `json:"stream"`
	Detail string `json:"detail"`
	Length int    `json:"length"`
	Hex    string `json:"hex"`
}
type Connection struct {
	Stream        int    `json:"stream"`
	Client        string `json:"client"`
	Server        string `json:"server"`
	Packets       int    `json:"packets"`
	InboundBytes  int64  `json:"inbound_bytes"`
	OutboundBytes int64  `json:"outbound_bytes"`
	SYN           int    `json:"syn"`
	FIN           int    `json:"fin"`
	RST           int    `json:"rst"`
}
type Report struct {
	Version            string         `json:"version"`
	Name               string         `json:"name"`
	Note               string         `json:"note"`
	Port               int            `json:"port"`
	CaptureFile        string         `json:"capture_file"`
	Generated          string         `json:"generated"`
	ExpectedSeconds    float64        `json:"expected_seconds"`
	GapThreshold       float64        `json:"gap_threshold"`
	FirstMS            int64          `json:"first"`
	LastMS             int64          `json:"last"`
	Packets            int            `json:"packets"`
	Truncated          int            `json:"truncated"`
	UniqueBytes        int64          `json:"unique_bytes"`
	DuplicateSegments  int            `json:"duplicate_segments"`
	TCPGaps            int            `json:"tcp_gaps"`
	MissingTCPBytes    int64          `json:"missing_tcp_bytes"`
	TCPConflicts       int            `json:"tcp_conflicts"`
	Indicators         map[string]int `json:"indicators"`
	OuterValid         int            `json:"outer_valid"`
	OuterInvalid       int            `json:"outer_invalid"`
	IncompleteOuter    int            `json:"incomplete_outer"`
	NonETHEBytes       int64          `json:"non_ethe_bytes"`
	Heartbeats         int            `json:"heartbeats"`
	InnerValid         int            `json:"inner_valid"`
	InnerInvalid       int            `json:"inner_invalid"`
	UnknownInnerChunks int            `json:"unknown_inner_chunks"`
	UnknownInnerBytes  int64          `json:"unknown_inner_bytes"`
	DeviceCount        int            `json:"device_count"`
	SelectedMACs       []string       `json:"selected_macs,omitempty"`
	UnmatchedMACs      []string       `json:"unmatched_macs,omitempty"`
	ScannedInnerValid  int            `json:"scanned_inner_valid"`
	ExcludedFrames     int            `json:"excluded_frames"`
	PositionFrames     int            `json:"position_frames"`
	ProtocolCounts     map[string]int `json:"protocol_counts"`
	InferredProtocols  map[string]int `json:"inferred_protocols"`
	Devices            []*Device      `json:"devices"`
	Connections        []*Connection  `json:"connections"`
	Issues             []Issue        `json:"issues"`
	IssuesOmitted      int            `json:"issues_omitted"`
	Warnings           []string       `json:"warnings"`
	HTMLPath           string         `json:"-"`
}
type analyzer struct {
	ctx             context.Context
	report          *Report
	devices         map[string]*Device
	channels        map[string]*channel
	connections     map[int]*Connection
	pendingBytes    int
	firstNS, lastNS int64
	lastProgress    time.Time
	macFilter       map[string]bool
}

func (a *analyzer) issue(kind string, packet int, at int64, stream int, detail string, raw []byte) {
	if len(a.report.Issues) >= 10000 {
		a.report.IssuesOmitted++
		return
	}
	n := min(len(raw), 128)
	preview := raw[:n]
	if len(a.macFilter) > 0 && kind != "内帧错误" {
		preview = nil
	}
	a.report.Issues = append(a.report.Issues, Issue{Kind: kind, Packet: packet, AtMS: at / 1e6, Stream: stream, Detail: detail, Length: len(raw), Hex: hex.EncodeToString(preview)})
}

func (a *analyzer) addFrame(f innerFrame, gateway string, at int64, packet int) error {
	a.report.ScannedInnerValid++
	if !a.includeDevice(f.device) {
		a.report.ExcludedFrames++
		return nil
	}
	if a.report.InnerValid >= maxFrames {
		return fmt.Errorf("有效内帧超过 %d 条，请分段录制后分析", maxFrames)
	}
	key := gateway + "/" + f.device + "/" + f.protocol
	d := a.devices[key]
	if d == nil {
		d = &Device{ID: f.device, Protocol: f.protocol, Gateway: gateway}
		if f.protocol == "C" {
			d.SequenceMode = "源码定义字段；计数规则待硬件确认"
		}
		if f.protocol == "TA" || f.protocol == "TO" {
			d.SequenceMode = "由样本推断的 8 位计数器"
		}
		a.devices[key] = d
	}
	d.Inferred = d.Inferred || f.inferred
	d.Points = append(d.Points, Point{At: at, Packet: packet, Sequence: f.sequence, Count: f.count})
	a.report.InnerValid++
	a.report.ProtocolCounts[f.protocol]++
	if f.inferred {
		if a.report.InferredProtocols == nil {
			a.report.InferredProtocols = map[string]int{}
		}
		key := f.protocol
		if f.protocol == "C" {
			key = "C/0x28"
		}
		a.report.InferredProtocols[key]++
	}
	if f.protocol != "R" {
		a.report.PositionFrames++
	}
	return nil
}

func quantile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	x := float64(len(v)-1) * p
	i := int(x)
	j := min(i+1, len(v)-1)
	return v[i] + (v[j]-v[i])*(x-float64(i))
}

func makeGap(x, y Point) Gap {
	return Gap{StartMS: x.At / 1e6, EndMS: y.At / 1e6, Seconds: float64(y.At-x.At) / 1e9, FromPacket: x.Packet, ToPacket: y.Packet, FromSeq: x.Sequence, ToSeq: y.Sequence}
}

func (a *analyzer) finishStats() error {
	ids := map[string]bool{}
	for _, d := range a.devices {
		if err := a.ctx.Err(); err != nil {
			return err
		}
		sort.SliceStable(d.Points, func(i, j int) bool { return d.Points[i].At < d.Points[j].At })
		d.Frames = len(d.Points)
		d.FirstMS = d.Points[0].At / 1e6
		d.LastMS = d.Points[d.Frames-1].At / 1e6
		ids[d.ID] = true
		var intervals, consecutive []float64
		for i := 1; i < d.Frames; i++ {
			x, y := d.Points[i-1], d.Points[i]
			seconds := float64(y.At-x.At) / 1e9
			intervals = append(intervals, seconds)
			if seconds > a.report.GapThreshold && d.Protocol != "R" {
				d.Gaps = append(d.Gaps, makeGap(x, y))
			}
			if x.Sequence >= 0 && y.Sequence >= 0 {
				delta := (y.Sequence - x.Sequence + 256) % 256
				d.SequencePositions += delta
				if delta == 0 {
					d.SequenceRepeated++
				}
				if delta > 1 {
					d.SequenceSkipped += delta - 1
				}
				if delta == 1 {
					consecutive = append(consecutive, seconds)
				}
			}
		}
		if d.SequenceMode != "" {
			d.SequencePositions++
		}
		for _, p := range d.Points {
			if p.Count == 0 {
				d.ZeroCount++
			}
		}
		if d.Protocol != "R" {
			d.Expected = int(math.Floor(float64(d.Points[d.Frames-1].At-d.Points[0].At)/1e9/a.report.ExpectedSeconds)) + 1
			d.Deficit = d.Expected - d.Frames
		}
		sort.Float64s(intervals)
		sort.Float64s(consecutive)
		d.Median = quantile(intervals, .5)
		d.P95 = quantile(intervals, .95)
		d.Maximum = quantile(intervals, 1)
		d.SequenceTypical = quantile(consecutive, .5)
		d.GapCount = len(d.Gaps)
		d.TopGaps = append([]Gap(nil), d.Gaps...)
		sort.Slice(d.TopGaps, func(i, j int) bool { return d.TopGaps[i].Seconds > d.TopGaps[j].Seconds })
		if len(d.TopGaps) > 20 {
			d.TopGaps = d.TopGaps[:20]
		}
		// Statistics and CSVs use all frames. Charts are bounded and interval
		// samples are taken from actual adjacent frames, never resampled gaps.
		step := max(1, (d.Frames+4999)/5000)
		d.PlotLimited = step > 1
		for i, p := range d.Points {
			if i%step == 0 || i == d.Frames-1 {
				d.PlotPoints = append(d.PlotPoints, [3]float64{float64(p.At) / 1e6, float64(p.Packet), float64(p.Sequence)})
			}
			if i > 0 && (i%step == 0 || i == d.Frames-1) {
				d.Intervals = append(d.Intervals, [4]float64{float64(p.At) / 1e6, float64(p.At-d.Points[i-1].At) / 1e9, float64(d.Points[i-1].Packet), float64(p.Packet)})
			}
		}
		a.report.Devices = append(a.report.Devices, d)
	}
	a.report.DeviceCount = len(ids)
	for _, id := range a.report.SelectedMACs {
		if !ids[id] {
			a.report.UnmatchedMACs = append(a.report.UnmatchedMACs, id)
		}
	}
	sort.Slice(a.report.Devices, func(i, j int) bool {
		x, y := a.report.Devices[i], a.report.Devices[j]
		if x.Frames != y.Frames {
			return x.Frames > y.Frames
		}
		return x.Gateway+x.ID+x.Protocol < y.Gateway+y.ID+y.Protocol
	})
	for _, c := range a.connections {
		a.report.Connections = append(a.report.Connections, c)
	}
	sort.Slice(a.report.Connections, func(i, j int) bool { return a.report.Connections[i].Stream < a.report.Connections[j].Stream })
	a.report.FirstMS = a.firstNS / 1e6
	a.report.LastMS = a.lastNS / 1e6
	return nil
}
