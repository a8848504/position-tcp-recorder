package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ConnectionCounter struct {
	Key             string
	Bytes, Segments uint64
	Valid           bool
}
type PortSnapshot struct {
	Connections []ConnectionCounter
	Complete    bool
	Error       string
}
type PortSource interface{ Sample() PortSnapshot }

type LiveStats struct {
	ReceivedBytes    uint64
	ReceivedSegments uint64
	Connections      int
	FileBytes        int64
	FileCount        int
	Elapsed          time.Duration
	LastData         time.Time
	Available        bool
	Error            string
}

type LiveMonitor struct {
	mu        sync.Mutex
	directory string
	started   time.Time
	source    PortSource
	previous  map[string]ConnectionCounter
	primed    bool
	stats     LiveStats
}

func NewLiveMonitor(directory string, started time.Time, source PortSource) *LiveMonitor {
	return &LiveMonitor{directory: directory, started: started, source: source, previous: map[string]ConnectionCounter{}}
}

// Only one polling goroutine owns a monitor. Live estimates deliberately do not
// overwrite the recording's final, PCAP-derived deduplicated byte count.
func (m *LiveMonitor) Poll(now time.Time) LiveStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := m.source.Sample()
	seen := map[string]bool{}
	valid := 0
	m.stats.Connections = len(snapshot.Connections)
	m.stats.Error = snapshot.Error
	for _, current := range snapshot.Connections {
		seen[current.Key] = true
		if !current.Valid {
			if _, exists := m.previous[current.Key]; !exists {
				m.previous[current.Key] = current
			}
			continue
		}
		valid++
		old, exists := m.previous[current.Key]
		if !exists {
			// For connections first appearing after the baseline, these counters
			// belong to a new connection. Existing sockets were sampled at start.
			if m.primed && snapshot.Complete {
				m.stats.ReceivedBytes += current.Bytes
				m.stats.ReceivedSegments += current.Segments
				if current.Bytes > 0 {
					m.stats.LastData = now
				}
			}
		} else if old.Valid {
			delta := counterDelta(current.Bytes, old.Bytes)
			m.stats.ReceivedBytes += delta
			m.stats.ReceivedSegments += counterDelta(current.Segments, old.Segments)
			if delta > 0 {
				m.stats.LastData = now
			}
		}
		m.previous[current.Key] = current
	}
	if snapshot.Complete {
		for key := range m.previous {
			if !seen[key] {
				delete(m.previous, key)
			}
		}
		m.primed = true
	}
	m.stats.Available = snapshot.Complete && (len(snapshot.Connections) == 0 || valid == len(snapshot.Connections))
	if valid > 0 {
		m.stats.Available = true
	}
	m.stats.FileBytes, m.stats.FileCount = captureFileSize(m.directory)
	m.stats.Elapsed = now.Sub(m.started)
	if m.stats.Elapsed < 0 {
		m.stats.Elapsed = 0
	}
	return m.stats
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func captureFileSize(directory string) (int64, int) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, 0
	}
	var size int64
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".etl" && extension != ".pcapng" && extension != ".pcap" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size += info.Size()
		count++
	}
	return size, count
}

func (s LiveStats) State(now time.Time) string {
	if !s.Available {
		return "实时接收统计暂不可用"
	}
	if s.ReceivedBytes == 0 {
		return "等待端口数据"
	}
	if !s.LastData.IsZero() && now.Sub(s.LastData) <= 3*time.Second {
		return "正在接收数据"
	}
	return fmt.Sprintf("最近 %.0f 秒无新增数据", now.Sub(s.LastData).Seconds())
}
