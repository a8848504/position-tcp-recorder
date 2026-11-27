package recording

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const FormatVersion = 1

type Session struct {
	ID      uint32 `json:"id"`
	Client  string `json:"client"`
	Server  string `json:"server"`
	Bytes   int64  `json:"bytes"`
	Partial bool   `json:"partial"`
}

type Recording struct {
	Version        int       `json:"version"`
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Note           string    `json:"note,omitempty"`
	Started        time.Time `json:"started"`
	Stopped        time.Time `json:"stopped"`
	Port           int       `json:"port"`
	Engine         string    `json:"engine"`
	Status         string    `json:"status"`
	Error          string    `json:"error,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
	CaptureFiles   []string  `json:"capture_files"`
	Bytes          int64     `json:"bytes"`
	Events         int64     `json:"events"`
	DurationNS     int64     `json:"duration_ns"`
	Duplicates     int64     `json:"duplicate_segments"`
	Sessions       []Session `json:"sessions"`
	LocalAddresses []string  `json:"local_addresses,omitempty"`
	Directory      string    `json:"-"`
}

func NormalizeNote(note string) (string, error) {
	note = strings.TrimSpace(strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\t", " ").Replace(note))
	if strings.ContainsRune(note, 0) {
		return "", fmt.Errorf("备注不能包含空字符")
	}
	if utf8.RuneCountInString(note) > 500 {
		return "", fmt.Errorf("备注最多 500 个字")
	}
	return note, nil
}

// Read the newest manifest so changing a note cannot roll back capture metadata
// from an old list-row snapshot.
func UpdateNote(directory, note string) error {
	note, err := NormalizeNote(note)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(directory, "recording.json"))
	if err != nil {
		return err
	}
	var r Recording
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Version != FormatVersion {
		return fmt.Errorf("不支持的录制格式")
	}
	r.Directory = directory
	r.Note = note
	return r.Save()
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1 到 65535 之间")
	}
	return nil
}

func New(root string, port int, engine string) (*Recording, error) {
	if err := ValidatePort(port); err != nil {
		return nil, err
	}
	now := time.Now()
	id := now.Format("20060102-150405.000000000")
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("创建录制目录: %w", err)
	}
	r := &Recording{Version: FormatVersion, ID: id, Name: now.Format("2006-01-02 15:04:05"), Started: now, Port: port, Engine: engine, Status: "capturing", Directory: dir}
	if addresses, err := net.InterfaceAddrs(); err == nil {
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil {
				r.LocalAddresses = append(r.LocalAddresses, ip.String())
			}
		}
	}
	if err := r.Save(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Recording) Save() error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(r.Directory, "recording.json")
	f, err := os.CreateTemp(r.Directory, "manifest-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = replaceFile(tmp, path); err != nil {
		return fmt.Errorf("保存录制信息: %w", err)
	}
	return nil
}

func List(root string) ([]Recording, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []Recording
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		data, err := os.ReadFile(filepath.Join(dir, "recording.json"))
		if err != nil {
			continue
		}
		var r Recording
		if json.Unmarshal(data, &r) != nil || r.Version != FormatVersion {
			continue
		}
		r.Directory = dir
		if r.ID != entry.Name() {
			continue
		}
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Started.After(result[j].Started) })
	return result, nil
}

// Delete only a verified, direct child recording. In particular, never accept
// arbitrary paths from a list snapshot, and never follow a directory symlink.
func Delete(root, id string) error {
	if id == "" || id == "." || id == ".." || strings.HasPrefix(id, ".") || filepath.Base(id) != id || strings.ContainsAny(id, `\/:`) {
		return fmt.Errorf("无效的录制编号")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	directory := filepath.Join(canonicalRoot, id)
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("不能删除链接或非录制目录")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(canonicalRoot, resolved)
	if err != nil || relative != id {
		return fmt.Errorf("录制目录不在允许删除的范围内")
	}
	data, err := os.ReadFile(filepath.Join(directory, "recording.json"))
	if err != nil {
		return fmt.Errorf("无法确认这是录制目录: %w", err)
	}
	var r Recording
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Version != FormatVersion || r.ID != id {
		return fmt.Errorf("录制信息与目录不匹配，已取消删除")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	// Preserve the manifest until all capture files have been removed. A file
	// locked by another Windows process then leaves a visible, retryable row.
	for _, entry := range entries {
		if entry.Name() == "recording.json" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return fmt.Errorf("删除录制文件失败: %w", err)
		}
	}
	if err := os.Remove(filepath.Join(directory, "recording.json")); err != nil {
		return err
	}
	return os.Remove(directory)
}
