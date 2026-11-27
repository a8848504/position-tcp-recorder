package capture

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakePortSource struct {
	samples []PortSnapshot
	index   int
}

func (s *fakePortSource) Sample() PortSnapshot {
	i := s.index
	if i >= len(s.samples) {
		i = len(s.samples) - 1
	}
	s.index++
	return s.samples[i]
}
func snap(counters ...ConnectionCounter) PortSnapshot {
	return PortSnapshot{Connections: counters, Complete: true}
}

func TestLiveCounterExcludesHistoryAndReportsActivity(t *testing.T) {
	start := time.Unix(1000, 0)
	source := &fakePortSource{samples: []PortSnapshot{snap(ConnectionCounter{Key: "device", Bytes: 100000, Segments: 1000, Valid: true}), snap(ConnectionCounter{Key: "device", Bytes: 100512, Segments: 1002, Valid: true}), snap(ConnectionCounter{Key: "device", Bytes: 100512, Segments: 1002, Valid: true})}}
	m := NewLiveMonitor(t.TempDir(), start, source)
	if s := m.Poll(start); s.ReceivedBytes != 0 || s.State(start) != "等待端口数据" {
		t.Fatalf("history counted: %+v", s)
	}
	s := m.Poll(start.Add(time.Second))
	if s.ReceivedBytes != 512 || s.ReceivedSegments != 2 || s.Connections != 1 || s.State(start.Add(time.Second)) != "正在接收数据" {
		t.Fatalf("live sample %+v", s)
	}
	s = m.Poll(start.Add(8 * time.Second))
	if !strings.Contains(s.State(start.Add(8*time.Second)), "无新增") {
		t.Fatal(s.State(start.Add(8 * time.Second)))
	}
}

func TestLiveFileHeadersDoNotPretendToBeBusinessTraffic(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"capture.etl", "capture1.etl", "capture.log", "recording.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 128), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := NewLiveMonitor(dir, time.Now(), &fakePortSource{samples: []PortSnapshot{snap()}})
	s := m.Poll(time.Now())
	if s.FileCount != 2 || s.FileBytes != 256 || s.ReceivedBytes != 0 || s.State(time.Now()) != "等待端口数据" {
		t.Fatalf("incorrect inference: %+v", s)
	}
}

func TestLiveReconnectAndCounterResetRemainCumulative(t *testing.T) {
	source := &fakePortSource{samples: []PortSnapshot{snap(), snap(ConnectionCounter{Key: "a", Bytes: 20, Segments: 2, Valid: true}), snap(), snap(ConnectionCounter{Key: "b", Bytes: 30, Segments: 3, Valid: true}), snap(ConnectionCounter{Key: "b", Bytes: 5, Segments: 1, Valid: true})}}
	m := NewLiveMonitor(t.TempDir(), time.Now(), source)
	var s LiveStats
	for range 5 {
		s = m.Poll(time.Now())
	}
	if s.ReceivedBytes != 55 || s.ReceivedSegments != 6 {
		t.Fatalf("%+v", s)
	}
}

func TestFailedLiveSampleIsUnavailableAndDoesNotImportHistory(t *testing.T) {
	source := &fakePortSource{samples: []PortSnapshot{snap(ConnectionCounter{Key: "a", Valid: false}), snap(ConnectionCounter{Key: "a", Bytes: 50000, Segments: 100, Valid: true}), snap(ConnectionCounter{Key: "a", Bytes: 50010, Segments: 101, Valid: true})}}
	m := NewLiveMonitor(t.TempDir(), time.Now(), source)
	if s := m.Poll(time.Now()); s.Available {
		t.Fatal("failure displayed as an available zero")
	}
	if s := m.Poll(time.Now()); s.ReceivedBytes != 0 {
		t.Fatalf("unobserved history imported: %+v", s)
	}
	if s := m.Poll(time.Now()); s.ReceivedBytes != 10 {
		t.Fatalf("recovery %+v", s)
	}
}

type increasingSource struct{ counter uint64 }

func (s *increasingSource) Sample() PortSnapshot {
	s.counter++
	return snap(ConnectionCounter{Key: "a", Bytes: s.counter, Valid: true})
}

func TestLivePollingSerializesRestartedObservers(t *testing.T) {
	m := NewLiveMonitor(t.TempDir(), time.Now(), &increasingSource{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				m.Poll(time.Now())
			}
		}()
	}
	wg.Wait()
	if s := m.Poll(time.Now()); s.ReceivedBytes != 80 {
		t.Fatalf("lost concurrent polls: %+v", s)
	}
}
