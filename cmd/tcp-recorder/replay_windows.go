package main

import "fmt"

func (a *application) paintReplayStatus() {
	state := "回放中"
	if a.pauseChanging {
		state = "正在暂停，等待当前发送完成"
	} else if a.replayControl != nil && a.replayControl.Paused() {
		state = "已暂停，可点击“继续播放”"
	}
	text(a.status, fmt.Sprintf("%s · 已发送 %s / %s，可随时停止回放。", state, sizeLabel(a.replaySent), sizeLabel(a.replayTotal)))
}

func (a *application) toggleReplayPause() {
	control := a.replayControl
	if a.busy != "replay" || control == nil || a.pauseChanging {
		return
	}
	if control.Paused() {
		control.Resume()
		a.appendLog("继续回放，保持暂停前的连接和剩余时间间隔。")
		a.updateButtons()
		a.paintReplayStatus()
		return
	}
	a.pauseChanging = true
	a.updateButtons()
	a.paintReplayStatus()
	// Pause waits for an in-flight socket operation. Keep the UI responsive,
	// including the stop button, if that operation is waiting on the network.
	go func() {
		control.Pause()
		a.post(func() {
			if a.busy != "replay" || a.replayControl != control {
				return
			}
			a.pauseChanging = false
			a.appendLog("回放已暂停；已经交给 TCP 的字节可能仍在传输。")
			a.updateButtons()
			a.paintReplayStatus()
		})
	}()
}
