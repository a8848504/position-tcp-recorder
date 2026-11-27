package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/recording"
	"strconv"
	"strings"
	"time"
)

type executor func(context.Context, string, ...string) (string, error)
type preparer func(context.Context, string, *recording.Recording) error

// CanPrepare includes stopped/failed Netsh records which have an ETL but no
// PCAP yet. Reprocessing never starts or stops a machine-global trace session.
func CanPrepare(r recording.Recording) bool {
	if len(r.CaptureFiles) > 0 {
		return true
	}
	if r.Engine != "netsh" {
		return false
	}
	info, err := os.Stat(filepath.Join(r.Directory, "capture.etl"))
	return err == nil && info.Mode().IsRegular()
}

func PrepareRecording(ctx context.Context, tools string, r *recording.Recording, log func(string)) error {
	if r.Engine == "netsh" {
		_, rawErr := os.Stat(filepath.Join(r.Directory, "capture.etl"))
		if rawErr == nil || len(r.CaptureFiles) == 0 {
			collectNetshDiagnostics(ctx, r.Directory, r.Port, run)
			return prepareNetsh(ctx, tools, r, run, recording.Prepare, log)
		}
	}
	return recording.Prepare(ctx, filepath.Join(tools, "tshark.exe"), r)
}

func loggedRun(ctx context.Context, execute executor, logPath, tool string, args ...string) (string, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", fmt.Errorf("保存转换日志: %w", err)
	}
	defer f.Close()
	var quoted []string
	for _, s := range append([]string{tool}, args...) {
		quoted = append(quoted, strconv.Quote(s))
	}
	if _, err := fmt.Fprintf(f, "\n[%s]\n%s\n", time.Now().Format(time.RFC3339), strings.Join(quoted, " ")); err != nil {
		return "", err
	}
	output, runErr := execute(ctx, tool, args...)
	if _, err := fmt.Fprintln(f, output); err != nil {
		return output, err
	}
	if runErr != nil {
		_, _ = fmt.Fprintf(f, "执行错误：%v\n", runErr)
	}
	return output, runErr
}

func validPCAPNG(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 28 {
		return fmt.Errorf("输出为空或不是有效的 pcapng 文件")
	}
	var header [4]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return err
	}
	if !bytes.Equal(header[:], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		return fmt.Errorf("输出文件缺少 pcapng 文件头")
	}
	return nil
}

func prepareNetsh(ctx context.Context, tools string, r *recording.Recording, execute executor, prepare preparer, log func(string)) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recording.ValidatePort(r.Port); err != nil {
		return err
	}
	etl := filepath.Join(r.Directory, "capture.etl")
	info, err := os.Stat(etl)
	if err != nil {
		return fmt.Errorf("找不到原始 capture.etl，无法重新转换：%w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("原始 capture.etl 为空，无法转换网络数据；请确认定位服务所在电脑、接收端口和硬件上报")
	}
	r.Status = "preparing"
	r.Error = ""
	if err := r.Save(); err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			r.Status = "error"
			r.Error = resultErr.Error()
			_ = r.Save()
		}
	}()
	// A fresh directory prevents a stale previous conversion from passing the
	// existence check. Failed intermediates remain available for diagnosis.
	work, err := os.MkdirTemp(r.Directory, ".netsh-convert-")
	if err != nil {
		return err
	}
	all := filepath.Join(work, "intermediate-all.pcapng")
	filtered := filepath.Join(work, "traffic.pcapng")
	logPath := filepath.Join(r.Directory, "conversion.log")
	var output string
	err = processingStage(r.Directory, "ETL 转换为网络包", log, func() error {
		var err error
		output, err = loggedRun(ctx, execute, logPath, filepath.Join(tools, "etl2pcapng.exe"), etl, all)
		return err
	})
	if err != nil {
		return fmt.Errorf("转换系统抓包文件失败，原始 ETL 已保留；详见 conversion.log：%w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// etl2pcapng 1.11 can return zero and delete its output when there are no
	// NDIS packets. Exit status alone is not evidence of a usable capture.
	if err := validPCAPNG(all); err != nil {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "should be converted with pktmon") {
			return fmt.Errorf("ETL 被转换器识别为 Pktmon 格式，不能按 Netsh 格式转换。原始 capture.etl 已保留；详见 conversion.log")
		}
		if strings.Contains(lower, "does not contain an ndiscap packet capture") {
			return fmt.Errorf("本次 ETL 没有可转换的 NDIS 网络包，转换器因此未保留输出文件。请核对端口 %d 的连接是否经过本机网卡；本地回环、虚拟网卡路径或抓包后端未取得网络包均需排查。原始 capture.etl 已保留，详见 conversion.log 和 port-diagnostics.log", r.Port)
		}
		return fmt.Errorf("转换器结束但未生成有效抓包：%w。原始 capture.etl 已保留；详见 conversion.log", err)
	}
	err = processingStage(r.Directory, "筛选所选 TCP 端口", log, func() error {
		_, err := loggedRun(ctx, execute, logPath, filepath.Join(tools, "tshark.exe"), "-n", "-r", all, "-Y", fmt.Sprintf("tcp.port == %d", r.Port), "-F", "pcapng", "-w", filtered)
		return err
	})
	if err != nil {
		return fmt.Errorf("筛选所选端口失败，原始文件已保留；详见 conversion.log：%w", err)
	}
	if err := validPCAPNG(filtered); err != nil {
		return fmt.Errorf("筛选命令结束但输出无效，原始文件已保留；详见 conversion.log：%w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(filtered, filepath.Join(r.Directory, "traffic.pcapng")); err != nil {
		return fmt.Errorf("保存端口抓包失败，原始文件已保留：%w", err)
	}
	r.CaptureFiles = []string{"traffic.pcapng"}
	if err := processingStage(r.Directory, "重组 TCP 并生成回放文件", log, func() error { return prepare(ctx, filepath.Join(tools, "tshark.exe"), r) }); err != nil {
		return fmt.Errorf("TCP 完整性整理失败，原始 ETL 已保留：%w", err)
	}
	// Broad intermediates are removed only after all byte-integrity checks and
	// manifest saving have succeeded. Failures remain retryable from the list.
	for _, path := range []string{etl, work} {
		if err := os.RemoveAll(path); err != nil {
			r.Warnings = append(r.Warnings, "临时文件未清理："+filepath.Base(path))
		}
	}
	return r.Save()
}

// These are read-only snapshots. They never stop a trace, change NIC bindings,
// modify firewall rules, or require the operator to run diagnostic commands.
func collectNetshDiagnostics(parent context.Context, directory string, port int, execute executor) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	path := filepath.Join(directory, "port-diagnostics.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "\n[%s] 所选 TCP 端口 %d\n", time.Now().Format(time.RFC3339), port)
	output, err := execute(ctx, systemTool("netstat.exe"), "-ano")
	if err != nil {
		_, _ = fmt.Fprintf(f, "读取连接表失败：%v\n", err)
	} else {
		matches, udpMatches := 0, 0
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.EqualFold(fields[0], "TCP") && (endpointPort(fields[1]) == port || endpointPort(fields[2]) == port) {
				_, _ = fmt.Fprintln(f, line)
				matches++
			}
			if len(fields) >= 3 && strings.EqualFold(fields[0], "UDP") && endpointPort(fields[1]) == port {
				_, _ = fmt.Fprintln(f, line)
				udpMatches++
			}
		}
		if matches == 0 {
			_, _ = fmt.Fprintln(f, "未发现本地或远端使用所选端口的 TCP 监听/连接。请核对定位程序实际接收端口及运行电脑。")
		}
		if matches == 0 && udpMatches > 0 {
			_, _ = fmt.Fprintln(f, "所选端口存在 UDP 端点，但本工具抓取 TCP。请核实设备实际传输协议。")
		}
	}
	output, err = execute(ctx, systemTool("netsh.exe"), "trace", "show", "status")
	_, _ = fmt.Fprintf(f, "\nNetsh 状态：\n%s\n", output)
	if err != nil {
		_, _ = fmt.Fprintf(f, "读取状态失败：%v\n", err)
	}
}

func endpointPort(endpoint string) int {
	i := strings.LastIndexByte(endpoint, ':')
	if i < 0 {
		return -1
	}
	port, err := strconv.Atoi(endpoint[i+1:])
	if err != nil {
		return -1
	}
	return port
}

func saveLiveDiagnostic(directory string, stats LiveStats) {
	f, err := os.OpenFile(filepath.Join(directory, "port-diagnostics.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "\n[%s] 停止前实时端口估算\n统计可用：%t；接收字节：%d；数据段：%d；连接数：%d；已运行：%.1f 秒；抓包文件字节：%d\n%s\n注意：实时接收估算来自 TCP 系统计数，不代表 ETL 已写入可转换的网络包。\n", time.Now().Format(time.RFC3339), stats.Available, stats.ReceivedBytes, stats.ReceivedSegments, stats.Connections, stats.Elapsed.Seconds(), stats.FileBytes, stats.Error)
}
