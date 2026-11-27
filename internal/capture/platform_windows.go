package capture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var consoleOnce sync.Once
var consoleError error

func hideCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
func systemTool(name string) string { return filepath.Join(os.Getenv("SystemRoot"), "System32", name) }

func decodeOutput(data []byte) string {
	// Console tools use the OEM codepage on Chinese Windows.
	if len(data) == 0 {
		return ""
	}
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		units := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
		}
		return string(utf16.Decode(units))
	}
	if utf8.Valid(data) {
		return string(data)
	}
	proc := kernel32.NewProc("MultiByteToWideChar")
	n, _, _ := proc.Call(1, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, 0)
	if n == 0 {
		return string(data)
	}
	buf := make([]uint16, n)
	proc.Call(1, 0, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&buf[0])), n)
	return string(utf16.Decode(buf))
}

func configureCaptureCommand(cmd *exec.Cmd) error {
	consoleOnce.Do(func() {
		window, _, _ := kernel32.NewProc("GetConsoleWindow").Call()
		if window == 0 {
			ok, _, err := kernel32.NewProc("AllocConsole").Call()
			if ok == 0 {
				consoleError = fmt.Errorf("创建抓包控制通道: %w", err)
				return
			}
			window, _, _ = kernel32.NewProc("GetConsoleWindow").Call()
		}
		syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(window, 0)
	})
	if consoleError != nil {
		return consoleError
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000200}
	return nil
}

func stopCaptureProcess(cmd *exec.Cmd) error {
	ok, _, err := kernel32.NewProc("GenerateConsoleCtrlEvent").Call(1, uintptr(cmd.Process.Pid))
	if ok == 0 {
		_ = cmd.Process.Kill()
		return fmt.Errorf("停止抓包控制失败，原始文件已保留: %w", err)
	}
	return nil
}
