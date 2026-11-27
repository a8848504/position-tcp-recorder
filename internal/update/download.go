package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
)

type DownloadProgress struct {
	Received, Total int64
	Attempt         int
	Verifying       bool
}

var errDownloadIdle = errors.New("下载长时间没有收到数据")

type downloadMeter struct {
	progress DownloadProgress
	notify   func(DownloadProgress)
	timer    *time.Timer
	timeout  time.Duration
}

func (m *downloadMeter) Write(data []byte) (int, error) {
	m.timer.Reset(m.timeout)
	m.progress.Received += int64(len(data))
	m.notify(m.progress)
	return len(data), nil
}

func (g *GitHub) downloadAsset(ctx context.Context, file *os.File, address string, release *Release, progress DownloadProgress, notify func(DownloadProgress)) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	response, err := g.request(ctx, address, "application/octet-stream")
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return fmt.Errorf("连接下载地址超时: %w", err)
		}
		return err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != release.Size {
		return fmt.Errorf("下载文件大小不符，预期 %d 字节，响应为 %d 字节", release.Size, response.ContentLength)
	}
	timer := time.AfterFunc(g.idleTimeout, func() { cancel(errDownloadIdle) })
	hash := sha256.New()
	meter := &downloadMeter{progress: progress, notify: notify, timer: timer, timeout: g.idleTimeout}
	copied, err := io.Copy(io.MultiWriter(file, hash, meter), io.LimitReader(response.Body, release.Size+1))
	timer.Stop()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err != nil {
		return fmt.Errorf("读取下载文件失败: %w", err)
	}
	if copied != release.Size {
		return fmt.Errorf("下载未完成，已收到 %d / %d 字节", copied, release.Size)
	}
	progress.Received, progress.Verifying = copied, true
	notify(progress)
	if hex.EncodeToString(hash.Sum(nil)) != release.Digest {
		return errors.New("SHA-256 校验失败")
	}
	return nil
}

// Download prefers the public Release link and falls back to the asset API.
// Slow transfers can continue while data is arriving. Either path must pass
// the release metadata's size and SHA-256 checks before handing off the file.
func (g *GitHub) Download(ctx context.Context, release *Release, directory string, notify func(DownloadProgress)) (string, error) {
	if release == nil || !repoPattern.MatchString(g.repo) || !versionPattern.MatchString(release.Version) ||
		release.assetID <= 0 || release.assetName == "" || release.Size <= 0 || release.Size > maxUpdateSize || !validDigest(release.Digest) {
		return "", errors.New("下载版本信息无效")
	}
	if notify == nil {
		notify = func(DownloadProgress) {}
	}
	file, err := os.CreateTemp(directory, ".position-tcp-update-*.bin")
	if err != nil {
		return "", fmt.Errorf("当前程序目录无法保存更新: %w", err)
	}
	path := file.Name()
	var succeeded bool
	defer func() {
		if !succeeded {
			file.Close()
			os.Remove(path)
		}
	}()
	sources := []string{
		g.downloadBase + "/" + g.repo + "/releases/download/" + url.PathEscape(release.Version) + "/" + url.PathEscape(release.assetName),
		g.apiBase + "/repos/" + g.repo + "/releases/assets/" + strconv.FormatInt(release.assetID, 10),
	}
	var downloadErr error
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if i != 0 {
			if err := file.Truncate(0); err != nil {
				return "", fmt.Errorf("清理下载文件失败: %w", err)
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				return "", fmt.Errorf("重置下载文件失败: %w", err)
			}
		}
		progress := DownloadProgress{Attempt: i + 1, Total: release.Size}
		notify(progress)
		err := g.downloadAsset(ctx, file, source, release, progress, notify)
		if err == nil {
			if err := file.Close(); err != nil {
				return "", fmt.Errorf("保存下载文件失败: %w", err)
			}
			succeeded = true
			return path, nil
		}
		var fileErr *os.PathError
		if errors.As(err, &fileErr) {
			return "", fmt.Errorf("保存下载文件失败: %w", err)
		}
		downloadErr = errors.Join(downloadErr, fmt.Errorf("下载地址 %d: %w", i+1, err))
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", downloadErr
}
