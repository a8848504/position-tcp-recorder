package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/analysis"
	"positioning/tcp-recorder/internal/bundle"
	"positioning/tcp-recorder/internal/capture"
	"positioning/tcp-recorder/internal/recording"
	"positioning/tcp-recorder/internal/version"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32        = syscall.NewLazyDLL("user32.dll")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	gdi32         = syscall.NewLazyDLL("gdi32.dll")
	shell32       = syscall.NewLazyDLL("shell32.dll")
	createWindow  = user32.NewProc("CreateWindowExW")
	sendMessage   = user32.NewProc("SendMessageW")
	setWindowText = user32.NewProc("SetWindowTextW")
	getWindowText = user32.NewProc("GetWindowTextW")
	postMessage   = user32.NewProc("PostMessageW")
	enableWindow  = user32.NewProc("EnableWindow")
	wndProc       = syscall.NewCallback(windowProcedure)
	currentApp    *application
)

const (
	idCapturePort  = 101
	idStart        = 102
	idStop         = 103
	idEngine       = 104
	idRefresh      = 105
	idFolder       = 106
	idList         = 107
	idHost         = 108
	idTargetPort   = 109
	idSpeed        = 110
	idReplay       = 111
	idStopReplay   = 112
	idAnalyze      = 113
	idCaptureNote  = 114
	idSelectedNote = 115
	idSaveNote     = 116
	idDelete       = 117
	idReport       = 118
	idInterval     = 119
	idMACs         = 120
	idPauseReplay  = 121
	idUpdate       = 122
	idCancelUpdate = 123
	wmApp          = 0x8001
	lvmFirst       = 0x1000
)

type windowClass struct {
	Size, Style                        uint32
	Procedure                          uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type point struct{ X, Y int32 }
type message struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          point
	Private        uint32
}
type rect struct{ Left, Top, Right, Bottom int32 }
type notifyHeader struct {
	Window, ID uintptr
	Code       uint32
}
type listNotification struct {
	Header                      notifyHeader
	Item, SubItem               int32
	NewState, OldState, Changed uint32
	Point                       point
	Param                       uintptr
}
type listColumn struct {
	Mask                                                               uint32
	Format, Width                                                      int32
	Text                                                               *uint16
	TextMax, SubItem, Image, Order, MinWidth, DefaultWidth, IdealWidth int32
}
type listItem struct {
	Mask                         uint32
	Item, SubItem                int32
	State, StateMask             uint32
	Text                         *uint16
	TextMax, Image               int32
	Param                        uintptr
	Indent, GroupID              int32
	Columns                      uint32
	ColumnIndices, ColumnFormats uintptr
	Group                        int32
}
type widget struct {
	handle     uintptr
	x, y, w, h int
}

type application struct {
	window, font, instance        uintptr
	controls                      map[int]uintptr
	widgets                       []widget
	status, details, logBox, list uintptr
	queue                         chan func()
	closed                        atomic.Bool
	root, tools, busy             string
	items                         []recording.Recording
	handle                        *capture.Handle
	cancel                        context.CancelFunc
	logLines                      []string
	exitRequested                 bool
	scale                         float64
	liveCancel                    context.CancelFunc
	liveStats                     capture.LiveStats
	liveID                        string
	noteRecordID                  string
	rebuildingList                bool
	replayControl                 *recording.ReplayControl
	replaySent, replayTotal       int64
	pauseChanging                 bool
	updateNotice, updateProgress  uintptr
	checkingUpdate                bool
}

func wide(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

//go:uintptrescapes
func call(proc string, args ...uintptr) uintptr {
	n, _, _ := user32.NewProc(proc).Call(args...)
	return n
}
func text(handle uintptr, value string) {
	setWindowText.Call(handle, uintptr(unsafe.Pointer(wide(value))))
}
func windowText(handle uintptr) string {
	var buf [8192]uint16
	getWindowText.Call(handle, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf[:])
}
func enabled(handle uintptr, value bool) {
	n := uintptr(0)
	if value {
		n = 1
	}
	enableWindow.Call(handle, n)
}

//go:uintptrescapes
func send(handle uintptr, message uint32, w, l uintptr) uintptr {
	n, _, _ := sendMessage.Call(handle, uintptr(message), w, l)
	return n
}
func dialog(window uintptr, title, body string, flags uintptr) uintptr {
	return call("MessageBoxW", window, uintptr(unsafe.Pointer(wide(body))), uintptr(unsafe.Pointer(wide(title))), flags)
}
func (a *application) px(n int) int { return int(float64(n) * a.scale) }

func (a *application) post(fn func()) {
	if a.closed.Load() {
		return
	}
	a.queue <- fn
	postMessage.Call(a.window, wmApp, 0, 0)
}
func (a *application) log(value string) { a.post(func() { a.appendLog(value) }) }
func (a *application) captureProgress(value string) {
	a.post(func() {
		a.appendLog(value)
		if a.busy == "preparing" {
			text(a.status, value)
		}
	})
}
func (a *application) appendLog(value string) {
	a.logLines = append(a.logLines, time.Now().Format("15:04:05")+"  "+value)
	if len(a.logLines) > 300 {
		a.logLines = a.logLines[len(a.logLines)-300:]
	}
	text(a.logBox, strings.Join(a.logLines, "\r\n"))
	send(a.logBox, 0x00B1, ^uintptr(0), ^uintptr(0))
	send(a.logBox, 0x00B7, 0, 0)
}

func (a *application) control(class, label string, style uint32, id, x, y, w, h int) uintptr {
	control, _, _ := createWindow.Call(0, uintptr(unsafe.Pointer(wide(class))), uintptr(unsafe.Pointer(wide(label))), uintptr(style|0x50000000), uintptr(a.px(x)), uintptr(a.px(y)), uintptr(a.px(w)), uintptr(a.px(h)), a.window, uintptr(id), a.instance, 0)
	send(control, 0x0030, a.font, 1)
	a.controls[id] = control
	a.widgets = append(a.widgets, widget{control, x, y, w, h})
	return control
}

func (a *application) makeUI() {
	a.control("STATIC", "定位系统 TCP 录制与回放", 0, 201, 22, 16, 420, 30)
	a.control("STATIC", "在定位服务所在电脑录制；定位程序保持运行。回放时请选择测试环境。", 0, 202, 22, 53, 640, 24)
	a.makeUpdateUI()
	a.control("STATIC", "接收端口", 0, 203, 22, 96, 78, 24)
	a.control("EDIT", "9000", 0x00810080, idCapturePort, 104, 91, 92, 30)
	engine := a.control("COMBOBOX", "", 0x00210003, idEngine, 212, 91, 224, 180)
	for _, s := range []string{"系统免安装（推荐）", "Wireshark（已有 Npcap）"} {
		send(engine, 0x0143, 0, uintptr(unsafe.Pointer(wide(s))))
	}
	send(engine, 0x014E, 0, 0)
	a.control("BUTTON", "开始抓包", 0x00010000, idStart, 454, 89, 126, 34)
	a.control("BUTTON", "结束抓包并保存", 0x00010000, idStop, 594, 89, 160, 34)
	a.control("BUTTON", "打开录制目录", 0x00010000, idFolder, 770, 89, 166, 34)
	a.control("STATIC", "本次备注", 0, 211, 22, 138, 78, 24)
	note := a.control("EDIT", "", 0x00810080, idCaptureNote, 104, 132, 832, 30)
	send(note, 0x00C5, 1000, 0)
	a.control("STATIC", "抓包列表", 0, 204, 22, 181, 150, 25)
	a.control("STATIC", "上报周期(秒)", 0, 213, 190, 180, 98, 24)
	a.control("EDIT", "2", 0x00810080, idInterval, 292, 174, 62, 30)
	a.control("BUTTON", "刷新", 0x00010000, idRefresh, 366, 174, 110, 30)
	a.control("BUTTON", "重新整理", 0x00010000, idAnalyze, 486, 174, 112, 30)
	a.control("BUTTON", "分析报告", 0x00010000, idReport, 610, 174, 176, 30)
	a.control("BUTTON", "删除录制", 0x00010000, idDelete, 798, 174, 138, 30)
	a.control("STATIC", "设备 MAC", 0, 214, 22, 222, 78, 24)
	macs := a.control("EDIT", "", 0x00810080, idMACs, 104, 216, 832, 30)
	send(macs, 0x00C5, 4096, 0)
	a.control("STATIC", "多个 MAC 用逗号、分号或空格分隔；与报告中的“设备 ID”一致；留空分析全部。", 0, 215, 22, 252, 914, 24)
	a.list = a.control("SysListView32", "", 0x0081000D, idList, 22, 284, 914, 160)
	send(a.list, lvmFirst+54, 0, 0x00000020|0x00000001|0x00010000|0x00004000)
	columns := []struct {
		name  string
		width int
	}{{"录制时间", 170}, {"端口", 52}, {"时长", 70}, {"上报数据", 120}, {"连接数", 60}, {"状态", 150}, {"备注", 250}}
	for i, c := range columns {
		column := listColumn{Mask: 0x0001 | 0x0002 | 0x0004, Width: int32(a.px(c.width)), Text: wide(c.name), SubItem: int32(i)}
		send(a.list, lvmFirst+97, uintptr(i), uintptr(unsafe.Pointer(&column)))
	}
	a.details = a.control("STATIC", "选择一条录制后可分析报告或回放。", 0, 205, 22, 454, 914, 42)
	a.control("STATIC", "所选备注", 0, 212, 22, 515, 78, 24)
	selectedNote := a.control("EDIT", "", 0x00810080, idSelectedNote, 104, 508, 658, 30)
	send(selectedNote, 0x00C5, 1000, 0)
	a.control("BUTTON", "保存备注", 0x00010000, idSaveNote, 772, 506, 164, 34)
	a.control("STATIC", "目标 IP", 0, 206, 22, 569, 72, 24)
	a.control("EDIT", "127.0.0.1", 0x00810080, idHost, 100, 562, 214, 32)
	a.control("STATIC", "端口", 0, 207, 334, 569, 42, 24)
	a.control("EDIT", "9000", 0x00810080, idTargetPort, 382, 562, 88, 32)
	a.control("STATIC", "倍速", 0, 208, 490, 569, 42, 24)
	speed := a.control("COMBOBOX", "", 0x00210003, idSpeed, 538, 562, 94, 150)
	for _, s := range []string{"0.5", "1", "2", "5"} {
		send(speed, 0x0143, 0, uintptr(unsafe.Pointer(wide(s))))
	}
	send(speed, 0x014E, 1, 0)
	a.control("BUTTON", "开始回放", 0x00010000, idReplay, 650, 560, 88, 36)
	a.control("BUTTON", "暂停", 0x00010000, idPauseReplay, 746, 560, 88, 36)
	a.control("BUTTON", "停止回放", 0x00010000, idStopReplay, 842, 560, 94, 36)
	a.status = a.control("STATIC", "正在准备内置组件…", 0, 209, 22, 606, 914, 44)
	a.logBox = a.control("EDIT", "", 0x00A108C4, 210, 22, 656, 914, 82)
	a.updateButtons()
}

func (a *application) selected() *recording.Recording {
	i := int(int32(send(a.list, lvmFirst+12, ^uintptr(0), 0x0002)))
	if i < 0 || i >= len(a.items) {
		return nil
	}
	return &a.items[i]
}

func (a *application) updateButtons() {
	idle := a.busy == "" && a.tools != ""
	selected := a.selected()
	enabled(a.controls[idStart], idle)
	enabled(a.controls[idStop], a.busy == "capture")
	enabled(a.controls[idReplay], idle && selected != nil && selected.Status == "ready")
	enabled(a.controls[idPauseReplay], a.busy == "replay" && !a.pauseChanging)
	if a.replayControl != nil && a.replayControl.Paused() {
		text(a.controls[idPauseReplay], "继续播放")
	} else {
		text(a.controls[idPauseReplay], "暂停")
	}
	enabled(a.controls[idUpdate], a.busy == "" && !a.checkingUpdate)
	enabled(a.controls[idStopReplay], a.busy == "replay" || a.busy == "report")
	if a.busy == "report" {
		text(a.controls[idStopReplay], "停止分析")
	} else {
		text(a.controls[idStopReplay], "停止回放")
	}
	enabled(a.controls[idAnalyze], idle && selected != nil && capture.CanPrepare(*selected))
	enabled(a.controls[idReport], idle && selected != nil && len(selected.CaptureFiles) > 0)
	enabled(a.controls[idDelete], a.busy == "" && selected != nil)
	noteEditable := selected != nil && (a.busy == "" || a.busy == "capture")
	enabled(a.controls[idSelectedNote], noteEditable)
	enabled(a.controls[idSaveNote], noteEditable)
	for _, id := range []int{idCapturePort, idEngine, idHost, idTargetPort, idSpeed, idCaptureNote, idInterval, idMACs} {
		enabled(a.controls[id], a.busy == "")
	}
}

func statusLabel(r recording.Recording) string {
	switch r.Status {
	case "ready":
		if len(r.Warnings) > 0 {
			return "可回放（有提示）"
		}
		return "可回放"
	case "capturing":
		return "录制中 / 尚未保存"
	case "preparing":
		return "待完成分析"
	default:
		return "未完成 / 查看详情"
	}
}
func sizeLabel(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return fmt.Sprintf("%.2f MiB", float64(n)/(1024*1024))
}

func (a *application) refresh() {
	oldID := ""
	if r := a.selected(); r != nil {
		oldID = r.ID
	}
	items, err := recording.List(a.root)
	if err != nil {
		a.appendLog("读取列表失败：" + err.Error())
		return
	}
	a.items = items
	a.rebuildingList = true
	send(a.list, lvmFirst+9, 0, 0)
	for i, r := range items {
		values := []string{r.Started.Format("2006-01-02 15:04:05"), strconv.Itoa(r.Port), fmt.Sprintf("%.1f 秒", float64(r.DurationNS)/1e9), sizeLabel(r.Bytes), strconv.Itoa(len(r.Sessions)), statusLabel(r), r.Note}
		for col, value := range values {
			item := listItem{Mask: 1, Item: int32(i), SubItem: int32(col), Text: wide(value)}
			if col == 0 {
				send(a.list, lvmFirst+77, 0, uintptr(unsafe.Pointer(&item)))
			} else {
				send(a.list, lvmFirst+116, uintptr(i), uintptr(unsafe.Pointer(&item)))
			}
		}
		if r.ID == oldID {
			item := listItem{State: 0x0002, StateMask: 0x0002}
			send(a.list, lvmFirst+43, uintptr(i), uintptr(unsafe.Pointer(&item)))
		}
	}
	a.rebuildingList = false
	if a.busy == "capture" && a.liveID != "" {
		a.paintLiveRow()
	}
	a.selectionChanged()
	a.updateButtons()
}

func (a *application) selectionChanged() {
	r := a.selected()
	if r == nil {
		text(a.details, "选择一条录制后可分析报告或回放。")
		a.noteRecordID = ""
		text(a.controls[idSelectedNote], "")
		a.updateButtons()
		return
	}
	if a.noteRecordID != r.ID {
		a.noteRecordID = r.ID
		text(a.controls[idSelectedNote], r.Note)
	}
	detail := fmt.Sprintf("%s · %s · 端口 %d · %s · TCP 重复段去重 %d 次", r.Name, statusLabel(*r), r.Port, sizeLabel(r.Bytes), r.Duplicates)
	if r.Error != "" {
		detail += "\r\n" + r.Error
	} else if len(r.Warnings) > 0 {
		detail += "\r\n" + r.Warnings[0]
	}
	text(a.details, detail)
	if a.busy == "capture" && r.ID == a.liveID {
		a.paintLiveDetails(*r)
	}
	a.updateButtons()
}

func (a *application) failure(err error) {
	a.appendLog(err.Error())
	dialog(a.window, "操作未完成", err.Error(), 0x10)
}
func (a *application) begin(kind, status string) {
	a.busy = kind
	text(a.status, status)
	a.updateButtons()
}
func (a *application) finished(status string) {
	a.busy = ""
	a.cancel = nil
	a.replayControl = nil
	a.pauseChanging = false
	text(a.status, status)
	a.refresh()
	if a.exitRequested {
		call("DestroyWindow", a.window)
	}
}

func (a *application) startCapture() {
	port, err := strconv.Atoi(strings.TrimSpace(windowText(a.controls[idCapturePort])))
	if err != nil {
		a.failure(fmt.Errorf("请输入接收 TCP 数据的端口"))
		return
	}
	if err := recording.ValidatePort(port); err != nil {
		a.failure(err)
		return
	}
	if _, err := recording.NormalizeNote(windowText(a.controls[idCaptureNote])); err != nil {
		a.failure(err)
		return
	}
	engine := "pktmon"
	if send(a.controls[idEngine], 0x0147, 0, 0) == 1 {
		engine = "dumpcap"
	}
	a.begin("starting", "正在启动抓包…")
	if engine == "pktmon" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			engine := capture.SystemEngine(ctx)
			a.post(func() {
				if engine == "netsh" && dialog(a.window, "系统兼容抓包", "当前 Windows 使用兼容模式。该模式会临时采集本机 TCP 流量，结束时只保留你输入端口的数据，并清理临时文件。\r\n\r\n是否开始？", 0x00000024) != 6 {
					a.finished("已取消抓包")
					return
				}
				a.launchCapture(port, engine)
			})
		}()
		return
	}
	a.launchCapture(port, engine)
}

func (a *application) launchCapture(port int, engine string) {
	note := windowText(a.controls[idCaptureNote])
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		h, err := capture.Start(ctx, capture.Config{Engine: engine, Tools: a.tools, Root: a.root, Port: port, Note: note, Log: a.captureProgress})
		a.post(func() {
			if err != nil {
				a.finished("抓包未启动")
				a.failure(err)
				return
			}
			a.handle = h
			a.liveID = h.Recording.ID
			a.liveStats = capture.LiveStats{}
			a.begin("capture", fmt.Sprintf("正在抓包：端口 %d。结束后将自动保存并分析。", port))
			a.refresh()
			a.selectRecording(h.Recording.ID)
			a.startLive(h)
			if a.exitRequested {
				a.stopCapture()
			}
		})
	}()
}

func (a *application) stopCapture() {
	if a.handle == nil {
		return
	}
	h := a.handle
	if a.liveCancel != nil {
		a.liveCancel()
		a.liveCancel = nil
	}
	a.begin("preparing", "正在结束抓包、保存并分析，请稍候…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		err := h.Stop(ctx)
		a.post(func() {
			a.handle = nil
			if err != nil {
				if h.Active() {
					a.handle = h
					a.exitRequested = false
					a.begin("capture", "停止抓包失败，录制仍在运行，请重试“结束抓包并保存”。")
					a.startLive(h)
					a.failure(err)
					return
				}
				a.finished("原始文件已保留，录制尚未就绪")
				a.failure(err)
				return
			}
			a.liveID = ""
			a.appendLog(fmt.Sprintf("录制已保存：%s，%d 个连接，%s。", h.Recording.Name, len(h.Recording.Sessions), sizeLabel(h.Recording.Bytes)))
			a.finished("录制已保存，请从列表选择后回放。")
		})
	}()
}

func (a *application) setCell(row, column int, value string) {
	item := listItem{SubItem: int32(column), Text: wide(value)}
	send(a.list, lvmFirst+116, uintptr(row), uintptr(unsafe.Pointer(&item)))
}

func (a *application) selectRecording(id string) {
	for i, r := range a.items {
		if r.ID == id {
			item := listItem{State: 2, StateMask: 2}
			send(a.list, lvmFirst+43, uintptr(i), uintptr(unsafe.Pointer(&item)))
			send(a.list, lvmFirst+19, uintptr(i), 0)
			a.selectionChanged()
			return
		}
	}
}

func (a *application) paintLiveRow() {
	for i, r := range a.items {
		if r.ID != a.liveID {
			continue
		}
		s := a.liveStats
		a.setCell(i, 2, fmt.Sprintf("%.0f 秒", s.Elapsed.Seconds()))
		value := "实时统计待就绪"
		if s.Available {
			value = sizeLabel(int64(s.ReceivedBytes)) + " 实时"
		}
		a.setCell(i, 3, value)
		a.setCell(i, 4, strconv.Itoa(s.Connections))
		a.setCell(i, 5, s.State(time.Now()))
		if selected := a.selected(); selected != nil && selected.ID == r.ID {
			a.paintLiveDetails(r)
		}
		return
	}
}

func (a *application) paintLiveDetails(r recording.Recording) {
	value := "暂不可用"
	if a.liveStats.Available {
		value = sizeLabel(int64(a.liveStats.ReceivedBytes))
	}
	text(a.details, fmt.Sprintf("%s · 端口 %d · %s · 实时接收 %s\r\n最终上报数据量将在结束后按抓包重组、去重统计。", r.Name, r.Port, a.liveStats.State(time.Now()), value))
}

func (a *application) startLive(h *capture.Handle) {
	if a.liveCancel != nil {
		a.liveCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.liveCancel = cancel
	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			stats := h.PollLive(time.Now())
			a.post(func() {
				if a.busy != "capture" || a.handle != h {
					return
				}
				a.liveStats = stats
				a.paintLiveRow()
				received := "暂不可用"
				if stats.Available {
					received = sizeLabel(int64(stats.ReceivedBytes))
				}
				state := stats.State(time.Now())
				extra := "实时接收为端口采样估算；保存后显示去重上报数据。"
				if stats.ReceivedBytes > 0 && stats.FileCount == 0 {
					extra = "端口已有接收数据，但尚未检测到抓包文件，请留意录制状态。"
				} else if stats.Error != "" {
					extra = stats.Error
				}
				text(a.status, fmt.Sprintf("%s · 实时接收 %s · %d 数据段 · %d 连接 · 已运行 %.0f 秒\r\n抓包文件 %s（%d 个）；%s", state, received, stats.ReceivedSegments, stats.Connections, stats.Elapsed.Seconds(), sizeLabel(stats.FileBytes), stats.FileCount, extra))
			})
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
}

func (a *application) saveNote() {
	if a.busy != "" && a.busy != "capture" {
		return
	}
	r := a.selected()
	if r == nil {
		return
	}
	note, err := recording.NormalizeNote(windowText(a.controls[idSelectedNote]))
	if err != nil {
		a.failure(err)
		return
	}
	if err := recording.UpdateNote(r.Directory, note); err != nil {
		a.failure(err)
		return
	}
	if a.handle != nil && a.busy == "capture" && a.handle.Recording.ID == r.ID {
		a.handle.Recording.Note = note
	}
	r.Note = note
	text(a.controls[idSelectedNote], note)
	a.refresh()
	a.appendLog("备注已保存。")
}

func (a *application) deleteRecording() {
	if a.busy != "" {
		return
	}
	r := a.selected()
	if r == nil {
		return
	}
	item := *r
	note := item.Note
	if note == "" {
		note = "（无）"
	}
	body := fmt.Sprintf("确定删除这条录制及其全部抓包文件？\r\n\r\n录制时间：%s\r\n接收端口：%d\r\n备注：%s\r\n\r\n删除后无法撤销。", item.Started.Format("2006-01-02 15:04:05"), item.Port, note)
	if dialog(a.window, "删除录制确认", body, 0x00000131) != 1 {
		return
	}
	a.begin("deleting", "正在删除所选录制…")
	go func() {
		err := recording.Delete(a.root, item.ID)
		a.post(func() {
			if err != nil {
				a.finished("删除未完成")
				a.failure(err)
				return
			}
			a.appendLog("已删除录制：" + item.Name)
			a.finished("所选录制已删除")
		})
	}()
}

func (a *application) prepareRecording() {
	r := a.selected()
	if r == nil {
		return
	}
	item := *r
	a.begin("preparing", "正在重新整理所选录制的回放文件…")
	go func() {
		err := capture.PrepareRecording(context.Background(), a.tools, &item, a.captureProgress)
		if err != nil {
			item.Status = "error"
			item.Error = err.Error()
			_ = item.Save()
		}
		a.post(func() {
			a.finished("录制整理已结束")
			if err != nil {
				a.failure(err)
			}
		})
	}()
}

func (a *application) analyzeReport() {
	r := a.selected()
	if r == nil || a.busy != "" {
		return
	}
	seconds, err := strconv.ParseFloat(strings.TrimSpace(windowText(a.controls[idInterval])), 64)
	if err != nil {
		a.failure(fmt.Errorf("请输入有效的上报周期，单位为秒，例如 2 或 2.56"))
		return
	}
	if err := analysis.ValidateInterval(seconds); err != nil {
		a.failure(err)
		return
	}
	macs, err := analysis.ParseMACs(windowText(a.controls[idMACs]))
	if err != nil {
		a.failure(err)
		return
	}
	item := *r
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.begin("report", fmt.Sprintf("正在分析 %s（理论周期 %g 秒），可点击“停止分析”。", item.Name, seconds))
	a.appendLog("开始生成分析报告：" + item.Name)
	if len(macs) > 0 {
		a.appendLog("仅分析设备 MAC：" + strings.Join(macs, ", "))
	}
	go func() {
		defer cancel()
		report, err := analysis.Analyze(ctx, filepath.Join(a.tools, "tshark.exe"), item, analysis.Options{ExpectedSeconds: seconds, MACs: macs, Progress: func(message string) {
			a.post(func() {
				if a.busy == "report" {
					text(a.status, message+" 可点击“停止分析”。")
				}
			})
		}})
		a.post(func() {
			if errors.Is(err, context.Canceled) {
				a.finished("分析已取消，录制文件未更改")
				return
			}
			if err != nil {
				a.finished("报告生成未完成，录制文件未更改")
				a.failure(err)
				return
			}
			a.appendLog(fmt.Sprintf("报告已生成：%d 个设备 ID，%d 条有效内帧。%s", report.DeviceCount, report.InnerValid, report.HTMLPath))
			a.finished("报告已生成，正在打开 HTML 分析界面。")
			if a.exitRequested || a.closed.Load() {
				return
			}
			result, _, _ := shell32.NewProc("ShellExecuteW").Call(a.window, uintptr(unsafe.Pointer(wide("open"))), uintptr(unsafe.Pointer(wide(report.HTMLPath))), 0, 0, 1)
			if result <= 32 {
				a.failure(fmt.Errorf("报告已生成，但默认浏览器未能打开（代码 %d）。请手动打开：\r\n%s", result, report.HTMLPath))
			}
		})
	}()
}

func (a *application) startReplay() {
	r := a.selected()
	if r == nil {
		return
	}
	item := *r
	port, err := strconv.Atoi(strings.TrimSpace(windowText(a.controls[idTargetPort])))
	if err != nil {
		a.failure(fmt.Errorf("请输入目标端口"))
		return
	}
	speed, err := strconv.ParseFloat(windowText(a.controls[idSpeed]), 64)
	if err != nil {
		a.failure(fmt.Errorf("请选择回放倍速"))
		return
	}
	opts := recording.ReplayOptions{Host: strings.TrimSpace(windowText(a.controls[idHost])), Port: port, Speed: speed}
	if err := recording.ValidateReplay(opts); err != nil {
		a.failure(err)
		return
	}
	if len(item.Warnings) > 0 {
		warnings := item.Warnings
		extra := ""
		if len(warnings) > 4 {
			extra = fmt.Sprintf("\r\n另有 %d 条提示，详见录制目录 recording.json。", len(warnings)-4)
			warnings = warnings[:4]
		}
		if dialog(a.window, "录制提示", strings.Join(warnings, "\r\n")+extra+"\r\n\r\n继续回放所选录制？", 0x00000034) != 6 {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.replayControl = &recording.ReplayControl{}
	opts.Control = a.replayControl
	a.replaySent, a.replayTotal = 0, item.Bytes
	a.begin("replay", fmt.Sprintf("正在向 %s:%d 回放（%.1f 倍速）…", opts.Host, opts.Port, opts.Speed))
	a.appendLog(fmt.Sprintf("开始回放 %s → %s:%d，%.1f 倍速。", item.Name, opts.Host, opts.Port, opts.Speed))
	opts.Progress = func(n int64) {
		a.post(func() {
			if a.busy == "replay" && a.replayControl == opts.Control {
				a.replaySent = n
				a.paintReplayStatus()
			}
		})
	}
	go func() {
		err := recording.Replay(ctx, item, opts)
		cancel()
		a.post(func() {
			if errors.Is(err, context.Canceled) {
				a.appendLog("回放已停止。")
				a.finished("回放已停止")
			} else if err != nil {
				a.finished("回放未完成")
				a.failure(err)
			} else {
				a.appendLog("回放完成。")
				a.finished("回放完成")
			}
		})
	}()
}

func (a *application) openFolder() {
	path := a.root
	if r := a.selected(); r != nil {
		path = r.Directory
	}
	shell32.NewProc("ShellExecuteW").Call(a.window, uintptr(unsafe.Pointer(wide("open"))), uintptr(unsafe.Pointer(wide(path))), 0, 0, 1)
}

func (a *application) close() {
	if a.busy != "" {
		if dialog(a.window, "退出工具", "当前任务尚未结束。是否停止任务、保存已有数据后退出？", 0x00000024) != 6 {
			return
		}
		a.exitRequested = true
		switch a.busy {
		case "capture":
			a.stopCapture()
		case "replay", "report", "update", "checking-update":
			a.cancel()
		}
		return
	}
	call("DestroyWindow", a.window)
}

func windowProcedure(window uintptr, msg uint32, w, l uintptr) uintptr {
	a := currentApp
	if a != nil {
		switch msg {
		case wmApp:
			for {
				select {
				case fn := <-a.queue:
					fn()
				default:
					return 0
				}
			}
		case 0x0111:
			switch int(w & 0xffff) {
			case idStart:
				if a.busy == "" {
					a.startCapture()
				}
			case idStop:
				if a.busy == "capture" {
					a.stopCapture()
				}
			case idReplay:
				if a.busy == "" {
					a.startReplay()
				}
			case idPauseReplay:
				a.toggleReplayPause()
			case idUpdate:
				a.checkUpdate(true)
			case idCancelUpdate:
				if a.busy == "update" && a.cancel != nil {
					a.cancel()
					enabled(a.controls[idCancelUpdate], false)
				}
			case idStopReplay:
				if a.cancel != nil {
					a.cancel()
				}
			case idRefresh:
				a.refresh()
			case idFolder:
				a.openFolder()
			case idAnalyze:
				if a.busy == "" {
					a.prepareRecording()
				}
			case idReport:
				if a.busy == "" {
					a.analyzeReport()
				}
			case idSaveNote:
				a.saveNote()
			case idDelete:
				a.deleteRecording()
			}
			return 0
		case 0x004E:
			// LPARAM is native memory, not a Go pointer. Copy the notification
			// header through the OS API rather than manufacturing a Go pointer.
			var h notifyHeader
			ok, _, _ := kernel32.NewProc("ReadProcessMemory").Call(^uintptr(0), l, uintptr(unsafe.Pointer(&h)), unsafe.Sizeof(h), 0)
			if ok != 0 && h.ID == idList && h.Code == 0xffffff9b && !a.rebuildingList {
				var change listNotification
				copied, _, _ := kernel32.NewProc("ReadProcessMemory").Call(^uintptr(0), l, uintptr(unsafe.Pointer(&change)), unsafe.Sizeof(change), 0)
				if copied != 0 && change.Changed&8 != 0 && (change.NewState^change.OldState)&2 != 0 {
					a.selectionChanged()
				}
			}
			return 0
		case 0x0138:
			if l == a.updateNotice {
				gdi32.NewProc("SetTextColor").Call(w, 0x000000D0)
				gdi32.NewProc("SetBkMode").Call(w, 1)
				return call("GetSysColorBrush", 15)
			}
		case 0x0010:
			a.close()
			return 0
		case 0x0002:
			a.closed.Store(true)
			call("PostQuitMessage", 0)
			return 0
		}
	}
	return call("DefWindowProcW", window, uintptr(msg), w, l)
}

func main() {
	runtime.LockOSThread()
	if handleUpdateArguments() {
		return
	}
	if runCLI() {
		return
	}
	mutex, _, mutexErr := kernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(wide("Local\\PositionTCPRecorder"))))
	if mutex == 0 {
		dialog(0, "启动失败", mutexErr.Error(), 0x10)
		return
	}
	defer kernel32.NewProc("CloseHandle").Call(mutex)
	if mutexErr == syscall.Errno(183) {
		dialog(0, "工具已在运行", "请使用已打开的 TCP 录制与回放窗口。", 0x40)
		return
	}
	user32.NewProc("SetProcessDPIAware").Call()
	a := &application{controls: map[int]uintptr{}, queue: make(chan func(), 1024), scale: 1}
	currentApp = a
	a.instance, _, _ = kernel32.NewProc("GetModuleHandleW").Call(0)
	dc := call("GetDC", 0)
	dpi, _, _ := gdi32.NewProc("GetDeviceCaps").Call(dc, 88)
	call("ReleaseDC", 0, dc)
	if dpi > 0 {
		a.scale = float64(dpi) / 96
	}
	var work rect
	if call("SystemParametersInfoW", 48, 0, uintptr(unsafe.Pointer(&work)), 0) != 0 {
		if fit := float64(work.Bottom-work.Top-24) / 798; fit < a.scale {
			a.scale = fit
		}
	}
	font, _, _ := gdi32.NewProc("CreateFontW").Call(uintptr(int64(-int64(a.px(16)))), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(wide("Microsoft YaHei UI"))))
	a.font = font
	defer gdi32.NewProc("DeleteObject").Call(font)
	common := struct{ Size, Classes uint32 }{8, 1 | 0x20}
	syscall.NewLazyDLL("comctl32.dll").NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&common)))
	className := wide("PositionTCPRecorderWindow")
	cursor := call("LoadCursorW", 0, 32512)
	class := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Procedure: wndProc, Instance: a.instance, Cursor: cursor, Background: 6, ClassName: className}
	if call("RegisterClassExW", uintptr(unsafe.Pointer(&class))) == 0 {
		dialog(0, "启动失败", "无法创建程序窗口。", 0x10)
		return
	}
	// Fixed-size native dialog avoids relying on any browser, Java or Python runtime.
	window, _, _ := createWindow.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(wide("定位系统 TCP 录制与回放 · "+version.Current))), 0x00CA0000, 0x80000000, 0x80000000, uintptr(a.px(980)), uintptr(a.px(798)), 0, 0, a.instance, 0)
	a.window = window
	if window == 0 {
		dialog(0, "启动失败", "无法打开操作界面。", 0x10)
		return
	}
	a.makeUI()
	call("ShowWindow", window, 1)
	call("UpdateWindow", window)
	root, err := os.UserCacheDir()
	if err != nil {
		a.failure(err)
		return
	}
	a.root = filepath.Join(root, "PositionTCP", "recordings")
	if err := os.MkdirAll(a.root, 0700); err != nil {
		a.failure(err)
		return
	}
	a.refresh()
	a.appendLog("录制目录：" + a.root)
	a.checkUpdate(false)
	go func() {
		tools, err := bundle.Extract(a.log)
		a.post(func() {
			if err != nil {
				a.failure(err)
				text(a.status, "组件准备失败")
				return
			}
			a.tools = tools
			text(a.status, "准备就绪。输入接收端口，点击“开始抓包”。")
			a.updateButtons()
		})
	}()
	var m message
	for {
		result := call("GetMessageW", uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if result == 0 || int32(result) == -1 {
			break
		}
		if call("IsDialogMessageW", a.window, uintptr(unsafe.Pointer(&m))) == 0 {
			call("TranslateMessage", uintptr(unsafe.Pointer(&m)))
			call("DispatchMessageW", uintptr(unsafe.Pointer(&m)))
		}
	}
}
