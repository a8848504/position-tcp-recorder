//go:build !windows

package capture

import (
	"fmt"
	"os/exec"
)

func hideCommand(cmd *exec.Cmd)                   {}
func systemTool(name string) string               { return name }
func decodeOutput(data []byte) string             { return string(data) }
func configureCaptureCommand(cmd *exec.Cmd) error { return fmt.Errorf("抓包界面仅支持 Windows") }
func stopCaptureProcess(cmd *exec.Cmd) error      { return fmt.Errorf("仅支持 Windows") }
