package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Engine string
	Tools  string
	Root   string
	Port   int
	Note   string
	Log    func(string)
}
type Handle struct {
	Recording  *recording.Recording
	config     Config
	cmd        *exec.Cmd
	done       chan error
	filter     string
	owned      bool
	stopMu     sync.Mutex
	stopErr    error
	captureLog *os.File
	live       *LiveMonitor
}

func command(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	hideCommand(cmd)
	return cmd
}

func run(ctx context.Context, path string, args ...string) (string, error) {
	cmd := command(ctx, path, args...)
	output, err := cmd.CombinedOutput()
	text := decodeOutput(output)
	if err != nil {
		return text, fmt.Errorf("%s: %w\n%s", filepath.Base(path), err, strings.TrimSpace(text))
	}
	return text, nil
}

func (h *Handle) log(text string) {
	if h.config.Log != nil {
		h.config.Log(text)
	}
}

func Start(ctx context.Context, config Config) (*Handle, error) {
	if err := recording.ValidatePort(config.Port); err != nil {
		return nil, err
	}
	if config.Engine != "pktmon" && config.Engine != "dumpcap" && config.Engine != "netsh" {
		return nil, fmt.Errorf("未知抓包模式")
	}
	note, err := recording.NormalizeNote(config.Note)
	if err != nil {
		return nil, err
	}
	r, err := recording.New(config.Root, config.Port, config.Engine)
	if err != nil {
		return nil, err
	}
	r.Note = note
	if err := r.Save(); err != nil {
		return nil, err
	}
	h := &Handle{Recording: r, config: config}
	// Prime counters before starting the capture so traffic received earlier in
	// an existing long-lived connection is excluded from the live estimate.
	h.live = NewLiveMonitor(r.Directory, r.Started, newPortSource(config.Port))
	h.live.Poll(time.Now())
	if config.Engine == "pktmon" {
		err = h.startPktmon(ctx)
	} else if config.Engine == "netsh" {
		err = h.startNetsh(ctx)
	} else {
		err = h.startDumpcap(ctx)
	}
	if err != nil {
		r.Status = "error"
		r.Error = err.Error()
		r.Stopped = time.Now()
		_ = r.Save()
		if h.filter != "" && !h.owned {
			_, _ = run(context.Background(), systemTool("pktmon.exe"), "filter", "remove", h.filter)
		}
		if h.captureLog != nil {
			h.captureLog.Close()
		}
		return nil, err
	}
	return h, nil
}

func (h *Handle) PollLive(now time.Time) LiveStats { return h.live.Poll(now) }

// Older Server 2019 builds lack pktmon's pcapng conversion command.
func SystemEngine(ctx context.Context) string {
	output, err := run(ctx, systemTool("pktmon.exe"), "help")
	if err == nil && (strings.Contains(strings.ToLower(output), "etl2pcap") || strings.Contains(strings.ToLower(output), "pcapng")) {
		return "pktmon"
	}
	return "netsh"
}

func (h *Handle) startNetsh(ctx context.Context) error {
	if err := h.startNetshUsing(ctx, run); err != nil {
		return err
	}
	collectNetshDiagnostics(ctx, h.Recording.Directory, h.config.Port, run)
	return nil
}

// PacketTruncateBytes is a Netsh truncation filter, not Pktmon's --pkt-size.
// Do not pass 0: the field server rejects it. Omitting the filter follows
// Microsoft's normal NETSH packet-capture examples.
func netshArguments(path string) []string {
	return []string{"trace", "start", "capture=yes", "report=disabled", "persistent=no", "correlation=no", "perfmerge=no", "filemode=single", "maxsize=0", "protocol=TCP", "tracefile=" + path}
}

func (h *Handle) startNetshUsing(ctx context.Context, execute func(context.Context, string, ...string) (string, error)) error {
	if _, err := os.Stat(filepath.Join(h.config.Tools, "etl2pcapng.exe")); err != nil {
		return fmt.Errorf("缺少系统兼容抓包的转换组件")
	}
	// Netsh cannot filter by TCP port at capture time. The UI asks the operator
	// before choosing this backend; intermediate broad captures are removed only
	// after a successful port-filtered pcapng has been saved.
	args := netshArguments(filepath.Join(h.Recording.Directory, "capture.etl"))
	output, err := execute(ctx, systemTool("netsh.exe"), args...)
	_ = os.WriteFile(filepath.Join(h.Recording.Directory, "capture-start.log"), []byte(output), 0600)
	if err != nil {
		return fmt.Errorf("系统兼容抓包启动失败: %w", err)
	}
	h.owned = true
	h.log("系统兼容模式已开始，结束时会只保留所选 TCP 端口的数据。")
	return nil
}

func (h *Handle) startPktmon(ctx context.Context) error {
	tool := systemTool("pktmon.exe")
	if _, err := os.Stat(tool); err != nil {
		return fmt.Errorf("当前 Windows 缺少系统抓包组件，请安装系统更新，或选择已有 Npcap 的 Wireshark 模式")
	}
	help, err := run(ctx, tool, "help")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(help), "etl2pcap") && !strings.Contains(strings.ToLower(help), "pcapng") {
		return fmt.Errorf("当前系统抓包组件不能导出 pcapng，请更新 Windows，或使用已有 Npcap 的 Wireshark 模式")
	}
	// Pktmon is machine-global. Never stop a session owned by another program.
	sessions, err := run(ctx, systemTool("logman.exe"), "query", "-ets")
	if err != nil {
		return fmt.Errorf("检查系统抓包资源: %w", err)
	}
	if regexp.MustCompile(`(?im)^\s*pktmon(?:\s|$)`).MatchString(sessions) {
		return fmt.Errorf("系统抓包资源正在被其他工具使用，请先结束已有抓包任务")
	}
	filters, err := run(ctx, tool, "filter", "list")
	if err != nil {
		return err
	}
	// Refuse unknown existing filters instead of clearing somebody else's configuration.
	if !filtersAreEmpty(filters) {
		return fmt.Errorf("系统已有抓包筛选规则，本工具不会清除它们；请由管理员确认后清理，或选择 Wireshark 模式。当前规则：\n%s", strings.TrimSpace(filters))
	}
	h.filter = "PositionTCP_" + strconv.Itoa(os.Getpid())
	if _, err := run(ctx, tool, "filter", "add", h.filter, "-t", "TCP", "-p", strconv.Itoa(h.config.Port)); err != nil {
		return err
	}
	path := filepath.Join(h.Recording.Directory, "capture.etl")
	output, err := run(ctx, tool, "start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", path, "--file-size", "256", "--log-mode", "multi-file")
	_ = os.WriteFile(filepath.Join(h.Recording.Directory, "capture-start.log"), []byte(output), 0600)
	if err != nil {
		return fmt.Errorf("启动系统抓包失败（请确认以管理员身份运行，且 Windows 已安装更新）: %w", err)
	}
	h.owned = true
	h.log("正在录制端口 " + strconv.Itoa(h.config.Port) + "，定位系统可继续运行。")
	return nil
}

func filtersAreEmpty(output string) bool {
	return regexp.MustCompile(`(?im)^\s*(?:none\.?|no filters?(?:\s.*)?|无[。.]?|没有(?:任何)?(?:数据包)?(?:筛选器|过滤器)[。.]?|未设置(?:任何)?(?:数据包)?(?:筛选器|过滤器)[。.]?)\s*$`).MatchString(output)
}

func (h *Handle) startDumpcap(ctx context.Context) error {
	tool := filepath.Join(h.config.Tools, "dumpcap.exe")
	output, err := run(ctx, tool, "-D")
	if err != nil {
		return fmt.Errorf("Wireshark 抓包需要已安装的 Npcap 驱动；可以改用系统免安装模式。%w", err)
	}
	args, err := dumpcapArguments(output, h.config.Port, filepath.Join(h.Recording.Directory, "capture.pcapng"))
	if err != nil {
		return err
	}
	cmd := exec.Command(tool, args...)
	if err := configureCaptureCommand(cmd); err != nil {
		return err
	}
	logFile, err := os.Create(filepath.Join(h.Recording.Directory, "capture.log"))
	if err != nil {
		return err
	}
	h.captureLog = logFile
	cmd.Stderr = logFile
	cmd.Stdout = logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	h.cmd = cmd
	h.owned = true
	h.done = make(chan error, 1)
	go func() { h.done <- cmd.Wait() }()
	select {
	case err := <-h.done:
		h.owned = false
		return fmt.Errorf("抓包进程提前退出: %v（详见 capture.log）", err)
	case <-time.After(350 * time.Millisecond):
	}
	h.log("Wireshark 模式正在录制所有本机 Npcap 网卡。")
	return nil
}

func dumpcapArguments(output string, port int, path string) ([]string, error) {
	if err := recording.ValidatePort(port); err != nil {
		return nil, err
	}
	// Per-interface defaults must precede every -i. Putting -f after the last
	// interface would leave earlier adapters capturing unrelated ports.
	args := []string{"-f", fmt.Sprintf("tcp port %d", port), "-s", "0", "-B", "32"}
	count := 0
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ".", 2)
		if len(parts) != 2 || !strings.Contains(strings.ToUpper(parts[1]), "NPF_") {
			continue
		}
		if _, err := strconv.Atoi(parts[0]); err == nil {
			args = append(args, "-i", parts[0])
			count++
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("没有找到可用的 Npcap 抓包网卡，请使用系统免安装模式")
	}
	return append(args, "-b", "filesize:262144", "-w", path), nil
}

func (h *Handle) Stop(ctx context.Context) error {
	h.stopMu.Lock()
	defer h.stopMu.Unlock()
	if !h.owned {
		return h.stopErr
	}
	h.stopErr = h.stop(ctx)
	return h.stopErr
}

func (h *Handle) Active() bool { h.stopMu.Lock(); defer h.stopMu.Unlock(); return h.owned }

func (h *Handle) stop(ctx context.Context) (resultErr error) {
	r := h.Recording
	r.Stopped = time.Now()
	r.Status = "preparing"
	defer func() {
		if h.captureLog != nil {
			h.captureLog.Close()
		}
		if resultErr != nil {
			r.Status = "error"
			r.Error = resultErr.Error()
		}
		if err := r.Save(); resultErr == nil && err != nil {
			resultErr = err
		}
	}()
	if !h.owned {
		return fmt.Errorf("没有本工具启动的抓包任务")
	}
	if h.config.Engine == "netsh" {
		if h.live != nil {
			saveLiveDiagnostic(r.Directory, h.live.Poll(time.Now()))
		}
		var output string
		err := processingStage(r.Directory, "Windows 停止系统抓包", h.log, func() error {
			var err error
			output, err = run(ctx, systemTool("netsh.exe"), "trace", "stop")
			return err
		})
		_ = os.WriteFile(filepath.Join(r.Directory, "capture-stop.log"), []byte(output), 0600)
		if err != nil {
			return fmt.Errorf("停止系统兼容抓包: %w", err)
		}
		h.owned = false
		collectNetshDiagnostics(ctx, r.Directory, r.Port, run)
		return prepareNetsh(ctx, h.config.Tools, r, run, recording.Prepare, h.log)
	}
	if h.config.Engine == "pktmon" {
		tool := systemTool("pktmon.exe")
		output, err := run(ctx, tool, "stop")
		_ = os.WriteFile(filepath.Join(r.Directory, "capture-stop.log"), []byte(output), 0600)
		if err != nil {
			return fmt.Errorf("停止系统抓包失败: %w", err)
		}
		h.owned = false
		if _, err := run(ctx, tool, "filter", "remove", h.filter); err != nil {
			r.Warnings = append(r.Warnings, "本工具的抓包筛选规则未清理："+err.Error())
		}
		files, err := filepath.Glob(filepath.Join(r.Directory, "*.etl"))
		if err != nil {
			return err
		}
		sort.Strings(files)
		if len(files) == 0 {
			return fmt.Errorf("系统未生成抓包文件")
		}
		for i, path := range files {
			h.log(fmt.Sprintf("正在整理抓包文件 %d/%d…", i+1, len(files)))
			out := strings.TrimSuffix(path, filepath.Ext(path)) + ".pcapng"
			if _, err := run(ctx, tool, "etl2pcap", path, "--out", out); err != nil {
				if _, fallback := run(ctx, tool, "pcapng", path, "--out", out); fallback != nil {
					return fmt.Errorf("导出抓包文件失败: %w", err)
				}
			}
		}
	} else {
		select {
		case err := <-h.done:
			if err != nil {
				r.Warnings = append(r.Warnings, "抓包进程提前退出："+err.Error())
			}
		default:
			if err := stopCaptureProcess(h.cmd); err != nil {
				<-h.done
				h.owned = false
				return err
			}
			select {
			case err := <-h.done:
				if err != nil {
					r.Warnings = append(r.Warnings, "抓包进程停止时报告："+err.Error())
				}
			case <-time.After(8 * time.Second):
				_ = h.cmd.Process.Kill()
				<-h.done
				h.owned = false
				return fmt.Errorf("抓包进程未正常停止，原始文件已保留，请重新分析后检查完整性")
			}
		}
		h.owned = false
	}
	files, err := filepath.Glob(filepath.Join(r.Directory, "*.pcapng"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return fmt.Errorf("没有生成抓包文件")
	}
	merged := filepath.Join(r.Directory, "traffic.pcapng")
	args := append([]string{"-w", merged}, files...)
	if _, err := run(ctx, filepath.Join(h.config.Tools, "mergecap.exe"), args...); err != nil {
		return fmt.Errorf("合并抓包文件: %w", err)
	}
	r.CaptureFiles = []string{"traffic.pcapng"}
	h.log("抓包已保存，正在去重和重组 TCP 字节流…")
	return recording.Prepare(ctx, filepath.Join(h.config.Tools, "tshark.exe"), r)
}
