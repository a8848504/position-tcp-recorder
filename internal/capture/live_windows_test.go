package capture

import (
	"testing"
	"unsafe"
)

func TestWindowsCounterABI(t *testing.T) {
	if unsafe.Sizeof(tcpRow4{}) != 20 || unsafe.Sizeof(tcpRow6{}) != 52 || unsafe.Sizeof(dataStats{}) != 96 {
		t.Fatal("Windows TCP statistics ABI mismatch")
	}
	var stats dataStats
	if unsafe.Offsetof(stats.DataBytesIn) != 16 || unsafe.Offsetof(stats.ThruBytesReceived) != 88 {
		t.Fatal("Windows counter offsets mismatch")
	}
}
