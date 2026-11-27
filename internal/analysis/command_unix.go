//go:build !windows

package analysis

import "os/exec"

func hideCommand(cmd *exec.Cmd) {}
