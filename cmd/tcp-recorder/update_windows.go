package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"positioning/tcp-recorder/internal/update"
	"positioning/tcp-recorder/internal/version"
)

func handleUpdateArguments() bool {
	if len(os.Args) > 1 && os.Args[1] == "--apply-update" {
		if err := update.Apply(os.Args[2:]); err != nil {
			dialog(0, "更新未完成", err.Error(), 0x10)
		}
		return true
	}
	if len(os.Args) == 3 && os.Args[1] == "--cleanup-helper" {
		go update.CleanHelper(os.Args[2])
		os.Args = os.Args[:1]
	}
	return false
}

func (a *application) makeUpdateUI() {
	a.control("STATIC", "当前版本 v"+version.Current, 0, 221, 442, 21, 162, 24)
	a.updateNotice = a.control("STATIC", "", 0, 222, 610, 21, 192, 24)
	a.control("BUTTON", "自动更新", 0x00010000, idUpdate, 810, 14, 126, 32)
	a.updateProgress = a.control("msctls_progress32", "", 0, 223, 670, 54, 158, 16)
	a.control("BUTTON", "取消下载", 0x00010000, idCancelUpdate, 836, 48, 100, 28)
	send(a.updateProgress, 0x0406, 0, 100) // PBM_SETRANGE32
	a.showUpdateProgress(false)
}

func (a *application) showUpdateProgress(show bool) {
	state := uintptr(0)
	if show {
		state = 5
	}
	call("ShowWindow", a.updateProgress, state)
	call("ShowWindow", a.controls[idCancelUpdate], state)
	enabled(a.controls[idCancelUpdate], show)
}

func (a *application) checkUpdate(interactive bool) {
	if a.checkingUpdate || (interactive && a.busy != "") {
		return
	}
	a.checkingUpdate = true
	github := update.NewGitHub(version.Repository)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if interactive {
		a.cancel = cancel
		a.begin("checking-update", "正在从 GitHub 检查新版本…")
	} else {
		a.updateButtons()
	}
	go func() {
		defer cancel()
		release, err := github.Latest(ctx, version.Current, runtime.GOARCH)
		a.post(func() {
			a.checkingUpdate = false
			if err == nil {
				notice := ""
				if release != nil {
					notice = "发现新版本 " + release.Version
				}
				text(a.updateNotice, notice)
			}
			if !interactive {
				a.updateButtons()
				return
			}
			if a.exitRequested {
				a.finished("已取消更新检查")
				return
			}
			if err != nil {
				a.finished("更新检查失败，可稍后重试")
				a.failure(err)
				return
			}
			if release == nil {
				a.finished("当前 v" + version.Current + " 已是最新版本")
				return
			}
			body := fmt.Sprintf("当前 v%s，发现新版本 %s。\r\n\r\n下载、校验并重启程序？已有录制和备注会保留。", version.Current, release.Version)
			if dialog(a.window, "更新程序", body, 0x124) != 6 {
				a.finished("已取消更新")
				return
			}
			a.downloadUpdate(github, release)
		})
	}()
}

func (a *application) downloadUpdate(github *update.GitHub, release *update.Release) {
	target, err := os.Executable()
	if err != nil {
		a.finished("更新未完成")
		a.failure(err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.begin("update", "正在连接 GitHub 下载更新…")
	a.showUpdateProgress(true)
	send(a.updateProgress, 0x0402, 0, 0)
	go func() {
		var last time.Time
		candidate, err := github.Download(ctx, release, filepath.Dir(target), func(p update.DownloadProgress) {
			if p.Received > 0 && p.Received < p.Total && time.Since(last) < 150*time.Millisecond {
				return
			}
			last = time.Now()
			a.post(func() {
				if ctx.Err() != nil || a.busy != "update" {
					return
				}
				percent := min(p.Received, p.Total) * 100 / p.Total
				send(a.updateProgress, 0x0402, uintptr(percent), 0)
				message := fmt.Sprintf("下载更新 %d%% · %s / %s", percent, sizeLabel(p.Received), sizeLabel(p.Total))
				if p.Attempt > 1 {
					message += "（备用地址）"
				}
				if p.Verifying {
					message = "下载完成，正在校验 SHA-256…"
				}
				text(a.status, message)
			})
		})
		a.post(func() {
			cancelled := ctx.Err() != nil || errors.Is(err, context.Canceled)
			cancel()
			if cancelled || err != nil {
				if candidate != "" {
					os.Remove(candidate)
				}
				a.showUpdateProgress(false)
				if cancelled {
					a.finished("已取消更新下载")
					return
				}
				a.finished("下载更新失败，可重试")
				a.failure(err)
				return
			}
			enabled(a.controls[idCancelUpdate], false)
			text(a.status, "校验通过，正在安装并重启程序…")
			// Installation handoff cannot be cancelled after the helper starts.
			a.busy = "installing-update"
			a.cancel = nil
			go func() {
				err := update.StartReplacement(target, candidate, release.Digest)
				a.post(func() {
					if err != nil {
						os.Remove(candidate)
						a.showUpdateProgress(false)
						a.finished("安装更新未完成")
						a.failure(err)
						return
					}
					call("DestroyWindow", a.window)
				})
			}()
		})
	}()
}
