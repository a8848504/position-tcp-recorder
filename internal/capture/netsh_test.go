package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"strings"
	"testing"
)

func netshHandle(t *testing.T) *Handle {
	t.Helper()
	dir := t.TempDir()
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "etl2pcapng.exe"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return &Handle{Recording: &recording.Recording{Directory: dir}, config: Config{Tools: tools}}
}

func TestNetshStartUsesNormalCaptureWithoutInvalidZeroTruncation(t *testing.T) {
	h := netshHandle(t)
	// Exercise the startup path against the field server's observed rule:
	// PacketTruncateBytes=0 is rejected. Do not substitute a small positive
	// truncation limit, as replay needs the payload, not just packet headers.
	calls := 0
	err := h.startNetshUsing(context.Background(), func(ctx context.Context, tool string, args ...string) (string, error) {
		calls++
		if filepath.Base(tool) != "netsh.exe" {
			t.Fatalf("unexpected tool: %s", tool)
		}
		if len(args) < 2 || args[0] != "trace" || args[1] != "start" {
			t.Fatal(args)
		}
		for _, arg := range args {
			if strings.HasPrefix(strings.ToLower(arg), "packettruncatebytes=") {
				return "命令选项“PacketTruncateBytes”的值无效。", fmt.Errorf("invalid truncation option")
			}
		}
		joined := "|" + strings.Join(args, "|") + "|"
		for _, required := range []string{"capture=yes", "persistent=no", "perfmerge=no", "filemode=single", "maxsize=0", "protocol=TCP", "tracefile=" + filepath.Join(h.Recording.Directory, "capture.etl")} {
			if !strings.Contains(joined, "|"+required+"|") {
				t.Fatalf("missing %s in %v", required, args)
			}
		}
		return "跟踪已启动。", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !h.owned {
		t.Fatalf("calls=%d owned=%v", calls, h.owned)
	}
	log, err := os.ReadFile(filepath.Join(h.Recording.Directory, "capture-start.log"))
	if err != nil || string(log) != "跟踪已启动。" {
		t.Fatalf("%s %v", log, err)
	}
}

func TestNetshStartFailureDoesNotClaimOwnershipOrStopOtherTasks(t *testing.T) {
	h := netshHandle(t)
	calls := 0
	err := h.startNetshUsing(context.Background(), func(ctx context.Context, tool string, args ...string) (string, error) {
		calls++
		if len(args) < 2 || args[1] != "start" {
			t.Fatalf("must not stop another session: %v", args)
		}
		return "参数无效。", fmt.Errorf("netsh.exe: exit status 1\n参数无效。")
	})
	if err == nil || !strings.Contains(err.Error(), "参数无效") {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "已有其他抓包任务") {
		t.Fatalf("misdiagnosed generic failure: %v", err)
	}
	if calls != 1 || h.owned {
		t.Fatalf("calls=%d owned=%v", calls, h.owned)
	}
	log, readErr := os.ReadFile(filepath.Join(h.Recording.Directory, "capture-start.log"))
	if readErr != nil || string(log) != "参数无效。" {
		t.Fatal(readErr, string(log))
	}
}
