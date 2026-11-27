package capture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessingStageRecordsOutcomeAndKeepsOriginalError(t *testing.T) {
	dir := t.TempDir()
	want := errors.New("conversion failure")
	var logs []string
	err := processingStage(dir, "测试转换", func(s string) { logs = append(logs, s) }, func() error { return want })
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	b, readErr := os.ReadFile(filepath.Join(dir, "processing-times.log"))
	if readErr != nil || !strings.Contains(string(b), "测试转换失败，耗时") {
		t.Fatal(readErr, string(b))
	}
	if len(logs) != 2 || !strings.Contains(logs[1], "耗时") {
		t.Fatal(logs)
	}
}
