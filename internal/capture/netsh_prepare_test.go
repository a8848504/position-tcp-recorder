package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"strings"
	"testing"
	"time"
)

func stoppedNetsh(t *testing.T) *recording.Recording {
	t.Helper()
	r, err := recording.New(t.TempDir(), 5000, "netsh")
	if err != nil {
		t.Fatal(err)
	}
	r.Status = "error"
	r.Note = "现场测试"
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Directory, "capture.etl"), []byte("raw etl retained"), 0600); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStopDiagnosticsPreserveGrowingLiveCountWithoutClaimingPacketCapture(t *testing.T) {
	dir := t.TempDir()
	saveLiveDiagnostic(dir, LiveStats{Available: true, ReceivedBytes: 123456, ReceivedSegments: 75, Connections: 2, Elapsed: 3 * time.Minute, FileBytes: 1024})
	b, err := os.ReadFile(filepath.Join(dir, "port-diagnostics.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"123456", "数据段：75", "连接数：2", "180.0 秒", "不代表 ETL"} {
		if !strings.Contains(string(b), text) {
			t.Fatalf("missing %s: %s", text, b)
		}
	}
}

func dummyPCAPNG(t *testing.T, path string) {
	t.Helper()
	b := make([]byte, 28)
	copy(b, []byte{0x0a, 0x0d, 0x0d, 0x0a})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func requireRaw(t *testing.T, r *recording.Recording) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.Directory, "capture.etl"))
	if err != nil || string(b) != "raw etl retained" {
		t.Fatalf("raw ETL lost: %q %v", b, err)
	}
}

func TestNetshZeroExitWithoutOutputDoesNotInvokeTshark(t *testing.T) {
	r := stoppedNetsh(t)
	calls := 0
	// The actual etl2pcapng 1.11 source deletes its output and returns success
	// for an ETL containing no NDIS packets. A stale prior output must not
	// hide this condition either.
	dummyPCAPNG(t, filepath.Join(r.Directory, "intermediate-all.pcapng"))
	err := prepareNetsh(context.Background(), "tools", r, func(ctx context.Context, tool string, args ...string) (string, error) {
		calls++
		if filepath.Base(tool) != "etl2pcapng.exe" {
			t.Fatal("read missing output", tool)
		}
		return "Input ETL file does not contain an ndiscap packet capture.", nil
	}, func(context.Context, string, *recording.Recording) error {
		t.Fatal("must not prepare absent conversion")
		return nil
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "没有可转换的 NDIS 网络包") || calls != 1 {
		t.Fatalf("%v calls=%d", err, calls)
	}
	if r.Status != "error" || !CanPrepare(*r) {
		t.Fatal("failed recording must be retryable", r.Status)
	}
	requireRaw(t, r)
	log, readErr := os.ReadFile(filepath.Join(r.Directory, "conversion.log"))
	if readErr != nil || !strings.Contains(string(log), "does not contain an ndiscap") {
		t.Fatal(string(log), readErr)
	}
}

func TestNetshMissingOrInvalidOutputRetainsRaw(t *testing.T) {
	for _, kind := range []string{"absent", "empty", "garbage", "converter-error", "pktmon"} {
		t.Run(kind, func(t *testing.T) {
			r := stoppedNetsh(t)
			err := prepareNetsh(context.Background(), "tools", r, func(ctx context.Context, tool string, args ...string) (string, error) {
				if filepath.Base(tool) != "etl2pcapng.exe" {
					t.Fatal("tshark must not read invalid output")
				}
				switch kind {
				case "empty":
					_ = os.WriteFile(args[1], nil, 0600)
				case "garbage":
					_ = os.WriteFile(args[1], []byte(strings.Repeat("bad!", 20)), 0600)
				case "converter-error":
					return "OpenTrace failed with 5", fmt.Errorf("exit status 5")
				case "pktmon":
					return "Input ETL file does not contain an ndiscap packet capture. This file should be converted with pktmon, not etl2pcapng.", nil
				}
				return "converter ended", nil
			}, func(context.Context, string, *recording.Recording) error {
				t.Fatal("invalid output reached replay preparation")
				return nil
			}, nil)
			if err == nil {
				t.Fatal("accepted invalid conversion")
			}
			requireRaw(t, r)
			if kind == "pktmon" && !strings.Contains(err.Error(), "Pktmon 格式") {
				t.Fatal(err)
			}
		})
	}
}

func TestNetshFilterFailureCannotDeleteRawOrClaimReady(t *testing.T) {
	r := stoppedNetsh(t)
	err := prepareNetsh(context.Background(), "tools", r, func(ctx context.Context, tool string, args ...string) (string, error) {
		if filepath.Base(tool) == "etl2pcapng.exe" {
			dummyPCAPNG(t, args[1])
			return "converted", nil
		}
		return "no output despite success", nil
	}, func(context.Context, string, *recording.Recording) error {
		t.Fatal("missing filtered file reached preparation")
		return nil
	}, nil)
	if err == nil || r.Status != "error" {
		t.Fatal(err, r.Status)
	}
	requireRaw(t, r)
}

func successfulConversion(t *testing.T) executor {
	return func(ctx context.Context, tool string, args ...string) (string, error) {
		switch filepath.Base(tool) {
		case "etl2pcapng.exe":
			dummyPCAPNG(t, args[1])
			return "Wrote 2 frames", nil
		case "tshark.exe":
			if !strings.Contains(strings.Join(args, "|"), "|-Y|tcp.port == 5000|") {
				t.Fatal(args)
			}
			dummyPCAPNG(t, args[len(args)-1])
			return "", nil
		default:
			t.Fatal("recovery must never start/stop a global trace", tool, args)
			return "", nil
		}
	}
}

func TestNetshRawSurvivesByteIntegrityFailure(t *testing.T) {
	r := stoppedNetsh(t)
	err := prepareNetsh(context.Background(), "tools", r, successfulConversion(t), func(ctx context.Context, path string, r *recording.Recording) error {
		return fmt.Errorf("TCP 字节流存在缺口")
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "完整性整理失败") || r.Status != "error" {
		t.Fatal(err, r.Status)
	}
	requireRaw(t, r)
	if len(r.CaptureFiles) != 1 {
		t.Fatal("filtered capture should remain usable for analysis")
	}
	if err := validPCAPNG(filepath.Join(r.Directory, "traffic.pcapng")); err != nil {
		t.Fatal(err)
	}
}

func TestNetshSuccessCleansRawOnlyAfterReplayPreparation(t *testing.T) {
	r := stoppedNetsh(t)
	r.Status = "error"
	err := prepareNetsh(context.Background(), "tools", r, successfulConversion(t), func(ctx context.Context, path string, r *recording.Recording) error {
		requireRaw(t, r)
		if len(r.CaptureFiles) != 1 {
			t.Fatal(r.CaptureFiles)
		}
		r.Status = "ready"
		return r.Save()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "ready" || r.Note != "现场测试" {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "capture.etl")); !os.IsNotExist(err) {
		t.Fatal("raw not cleaned after full success", err)
	}
	if err := validPCAPNG(filepath.Join(r.Directory, "traffic.pcapng")); err != nil {
		t.Fatal(err)
	}
	work, _ := filepath.Glob(filepath.Join(r.Directory, ".netsh-convert-*"))
	if len(work) != 0 {
		t.Fatal(work)
	}
}

func TestNetshDiagnosticsKeepOnlySelectedPortAndNeverChangeState(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	collectNetshDiagnostics(context.Background(), dir, 5000, func(ctx context.Context, tool string, args ...string) (string, error) {
		calls++
		if filepath.Base(tool) == "netstat.exe" {
			return " TCP 0.0.0.0:5000 0.0.0.0:0 LISTENING 100\n TCP 127.0.0.1:5000 127.0.0.1:50100 ESTABLISHED 100\n TCP [::1]:50100 [::1]:5000 ESTABLISHED 100\n TCP 10.0.0.2:80 10.0.0.3:50001 ESTABLISHED 200\n UDP 0.0.0.0:5000 *:* 900", nil
		}
		if strings.Join(args, " ") != "trace show status" {
			t.Fatal("diagnostic must be read-only", args)
		}
		return "Trace running", nil
	})
	b, err := os.ReadFile(filepath.Join(dir, "port-diagnostics.log"))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(string(b), "127.0.0.1:5000") || !strings.Contains(string(b), "[::1]:5000") || strings.Contains(string(b), "50001") || !strings.Contains(string(b), "UDP 0.0.0.0:5000") {
		t.Fatalf("calls=%d %s", calls, b)
	}
}
