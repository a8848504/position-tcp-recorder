package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets/*
var assets embed.FS

func Extract(log func(string)) (string, error) {
	data, err := assets.ReadFile("assets/wireshark-runtime.zip")
	if err != nil {
		return "", fmt.Errorf("程序缺少内置抓包分析组件，请使用完整发布版 EXE")
	}
	hash := sha256.Sum256(data)
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	root = filepath.Join(root, "PositionTCP", "engine", fmt.Sprintf("wireshark-%x", hash[:8]))
	marker := filepath.Join(root, ".complete")
	if _, err := os.Stat(marker); err == nil {
		return root, nil
	}
	if log != nil {
		log("首次启动，正在准备内置分析组件，无需安装…")
	}
	parent := filepath.Dir(root)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp(parent, "engine-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	for _, entry := range reader.File {
		path := filepath.Join(temp, filepath.FromSlash(entry.Name))
		relative, err := filepath.Rel(temp, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(entry.Name) {
			return "", fmt.Errorf("组件包包含无效路径")
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0700); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		r, err := entry.Open()
		if err != nil {
			return "", err
		}
		w, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			r.Close()
			return "", err
		}
		_, copyErr := io.Copy(w, r)
		closeErr := w.Close()
		r.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	for _, name := range []string{"tshark.exe", "dumpcap.exe", "mergecap.exe", "etl2pcapng.exe"} {
		if _, err := os.Stat(filepath.Join(temp, name)); err != nil {
			return "", fmt.Errorf("内置组件缺少 %s", name)
		}
	}
	if err := os.WriteFile(filepath.Join(temp, ".complete"), []byte(fmt.Sprintf("%x\n", hash)), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(temp, root); err != nil {
		// Another instance may have completed extraction first.
		if _, statErr := os.Stat(marker); statErr != nil {
			return "", err
		}
	}
	return root, nil
}
