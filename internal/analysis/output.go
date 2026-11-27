package analysis

import (
	"context"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed report.html
var reportTemplate string

func formatNS(at int64) string {
	return time.Unix(0, at).In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02 15:04:05.000000")
}
func integer(n int) string    { return strconv.Itoa(n) }
func number(n float64) string { return strconv.FormatFloat(n, 'f', 6, 64) }

func csvFile(path string, header []string, fill func(*csv.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}
	if err := fill(w); err != nil {
		return err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return f.Close()
}

func writeReport(ctx context.Context, dir string, r *Report) error {
	sort.SliceStable(r.Issues, func(i, j int) bool { return r.Issues[i].AtMS < r.Issues[j].AtMS })
	// json.Marshal escapes < > & and U+2028/2029. Recorded notes and paths
	// cannot terminate the inline script; dynamic labels use textContent.
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), data, 0600); err != nil {
		return err
	}
	html := strings.Replace(reportTemplate, "__DATA__", string(data), 1)
	if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte(html), 0600); err != nil {
		return err
	}
	if err := csvFile(filepath.Join(dir, "devices.csv"), []string{"设备ID", "协议", "网关", "上报条数", "首次收到_北京时间", "最后收到_北京时间", "理论周期秒", "理论应收", "数量差额_非确认丢包", "间隔中位数秒", "间隔P95秒", "最大间隔秒", "超阈值间隔数", "序号字段依据", "假设连续计数时未见序号数", "字段结构含推断"}, func(w *csv.Writer) error {
		for _, d := range r.Devices {
			if err := ctx.Err(); err != nil {
				return err
			}
			expected, deficit := integer(d.Expected), integer(d.Deficit)
			if d.Protocol == "R" {
				expected = ""
				deficit = ""
			}
			if err := w.Write([]string{d.ID, d.Protocol, d.Gateway, integer(d.Frames), formatNS(d.Points[0].At), formatNS(d.Points[d.Frames-1].At), number(r.ExpectedSeconds), expected, deficit, number(d.Median), number(d.P95), number(d.Maximum), integer(d.GapCount), d.SequenceMode, integer(d.SequenceSkipped), strconv.FormatBool(d.Inferred)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := csvFile(filepath.Join(dir, "gaps.csv"), []string{"设备ID", "协议", "网关", "前次收到_北京时间", "下次收到_北京时间", "间隔秒", "前帧号", "后帧号", "前包号", "后包号", "包号字段依据"}, func(w *csv.Writer) error {
		for _, d := range r.Devices {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, g := range d.Gaps {
				from, to := integer(g.FromSeq), integer(g.ToSeq)
				if g.FromSeq < 0 {
					from = ""
					to = ""
				}
				if err := w.Write([]string{d.ID, d.Protocol, d.Gateway, formatNS(g.StartMS * 1e6), formatNS(g.EndMS * 1e6), number(g.Seconds), integer(g.FromPacket), integer(g.ToPacket), from, to, d.SequenceMode}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := csvFile(filepath.Join(dir, "frames.csv"), []string{"设备ID", "协议", "网关", "收到时间_北京时间", "原抓包帧号", "包号或疑似计数器", "数量字段"}, func(w *csv.Writer) error {
		for _, d := range r.Devices {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, p := range d.Points {
				seq := integer(p.Sequence)
				if p.Sequence < 0 {
					seq = ""
				}
				if err := w.Write([]string{d.ID, d.Protocol, d.Gateway, formatNS(p.At), integer(p.Packet), seq, integer(p.Count)}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return csvFile(filepath.Join(dir, "issues.csv"), []string{"类型", "时间_北京时间", "原抓包帧号", "TCP流", "设备ID_声明字段", "说明", "字节数", "十六进制_最多128字节"}, func(w *csv.Writer) error {
		for _, x := range r.Issues {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := w.Write([]string{x.Kind, formatNS(x.AtMS * 1e6), integer(x.Packet), integer(x.Stream), x.Device, x.Detail, integer(x.Length), x.Hex}); err != nil {
				return err
			}
		}
		return nil
	})
}
