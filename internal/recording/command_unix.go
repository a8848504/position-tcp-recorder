//go:build !windows

package recording

import "os/exec"

func hideCommand(cmd *exec.Cmd) {}
