package update

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const helperPrefix = "position-tcp-update-"
const helperName = "apply.exe"

func copyFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	return errors.Join(err, output.Close())
}

func checkExecutable(path string) error {
	file, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("升级文件不是有效 Windows EXE: %w", err)
	}
	defer file.Close()
	expected := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if runtime.GOARCH == "arm64" {
		expected = pe.IMAGE_FILE_MACHINE_ARM64
	}
	if file.Machine != expected || file.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
		return errors.New("升级文件和当前 Windows 程序的架构不一致")
	}
	return nil
}

func StartReplacement(target, candidate, digest string) error {
	if err := Verify(candidate, digest); err != nil {
		return err
	}
	if err := checkExecutable(candidate); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", helperPrefix)
	if err != nil {
		return err
	}
	helper := filepath.Join(directory, helperName)
	if err := copyFile(target, helper); err != nil {
		os.RemoveAll(directory)
		return err
	}
	// Keep the helper unelevated or elevated exactly as the application is.
	cmd := exec.Command(helper, "--apply-update", strconv.Itoa(os.Getpid()), target, candidate, digest)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		os.RemoveAll(directory)
		return err
	}
	cmd.Process.Release()
	return nil
}

func waitForExit(pid uint32) error {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	result, err := windows.WaitForSingleObject(process, 30_000)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 {
		return errors.New("等待原程序退出超时")
	}
	return nil
}

func moveReplace(from, to string) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Apply is the internal helper entry point. The download is verified again
// after the old executable exits and just before replacing it.
func Apply(args []string) error {
	if len(args) != 4 {
		return errors.New("升级参数无效")
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || pid == 0 {
		return errors.New("原程序进程编号无效")
	}
	target, staged, digest := args[1], args[2], args[3]
	if !filepath.IsAbs(target) || !filepath.IsAbs(staged) ||
		!strings.EqualFold(filepath.Dir(target), filepath.Dir(staged)) ||
		!strings.EqualFold(filepath.Ext(target), ".exe") ||
		!strings.HasPrefix(filepath.Base(staged), ".position-tcp-update-") {
		return errors.New("升级文件路径无效")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	helperDir := filepath.Dir(executable)
	if !validHelperDir(helperDir) {
		return errors.New("升级程序的位置无效")
	}
	if err := waitForExit(uint32(pid)); err != nil {
		return err
	}

	restart := func() error {
		cmd := exec.Command(target, "--cleanup-helper", helperDir)
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	if err := Verify(staged, digest); err != nil {
		os.Remove(staged)
		return errors.Join(err, restart())
	}
	if err := checkExecutable(staged); err != nil {
		os.Remove(staged)
		return errors.Join(err, restart())
	}
	backup, err := os.CreateTemp(filepath.Dir(target), ".position-tcp-previous-*.bin")
	if err != nil {
		return errors.Join(err, restart())
	}
	backupPath := backup.Name()
	backup.Close()
	if err := copyFile(target, backupPath); err != nil {
		os.Remove(backupPath)
		return errors.Join(err, restart())
	}
	if err := moveReplace(staged, target); err != nil {
		os.Remove(backupPath)
		return errors.Join(err, restart())
	}
	if err := restart(); err != nil {
		if restoreErr := moveReplace(backupPath, target); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("回退失败。旧程序保存在 %s: %w", backupPath, restoreErr))
		}
		return errors.Join(err, restart())
	}
	os.Remove(backupPath)
	return nil
}

func validHelperDir(directory string) bool {
	directory = filepath.Clean(directory)
	return strings.EqualFold(filepath.Dir(directory), filepath.Clean(os.TempDir())) &&
		strings.HasPrefix(filepath.Base(directory), helperPrefix)
}

func CleanHelper(directory string) {
	if !validHelperDir(directory) {
		return
	}
	for range 30 {
		err := os.Remove(filepath.Join(directory, helperName))
		if err == nil || errors.Is(err, os.ErrNotExist) {
			os.Remove(directory)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
