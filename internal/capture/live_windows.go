package capture

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
var getTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
var getStats4 = iphlpapi.NewProc("GetPerTcpConnectionEStats")
var setStats4 = iphlpapi.NewProc("SetPerTcpConnectionEStats")
var getStats6 = iphlpapi.NewProc("GetPerTcp6ConnectionEStats")
var setStats6 = iphlpapi.NewProc("SetPerTcp6ConnectionEStats")

type tcpRow4 struct{ State, LocalAddr, LocalPort, RemoteAddr, RemotePort uint32 }

// MIB_TCP6ROW has State first; OWNER_PID rows returned by GetExtendedTcpTable
// have State near the end, so they must be converted, never cast directly.
type tcpRow6 struct {
	State                   uint32
	LocalAddr               [16]byte
	LocalScope, LocalPort   uint32
	RemoteAddr              [16]byte
	RemoteScope, RemotePort uint32
}
type dataStats struct {
	DataBytesOut, DataSegsOut, DataBytesIn, DataSegsIn, SegsOut, SegsIn uint64
	SoftErrors, SoftErrorReason, SndUna, SndNxt, SndMax                 uint32
	ThruBytesAcked                                                      uint64
	RcvNxt                                                              uint32
	ThruBytesReceived                                                   uint64
}
type windowsPortSource struct{ port int }

func newPortSource(port int) PortSource { return &windowsPortSource{port: port} }

func tcpTable(family uint32) ([]byte, error) {
	var size uint32
	code, _, _ := getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 5, 0)
	if code != 0 && code != 122 {
		return nil, syscall.Errno(code)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if size < 4 {
			size = 4
		}
		if size > 64*1024*1024 {
			return nil, fmt.Errorf("TCP 连接表超过大小限制")
		}
		data := make([]byte, size)
		code, _, _ = getTCPTable.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 5, 0)
		if code == 0 {
			if size < 4 || int(size) > len(data) {
				return nil, fmt.Errorf("TCP 连接表长度无效")
			}
			return data[:size], nil
		}
		if code != 122 {
			return nil, syscall.Errno(code)
		}
	}
	return nil, fmt.Errorf("TCP 连接表正在变化，请稍后重试")
}

func connectionStats4(row *tcpRow4) (dataStats, error) {
	var rw byte
	var stats dataStats
	code, _, _ := getStats4.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0, 0, 0, uintptr(unsafe.Pointer(&stats)), 0, unsafe.Sizeof(stats))
	if code != 0 {
		return stats, syscall.Errno(code)
	}
	if rw == 0 {
		rw = 1
		code, _, _ = setStats4.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0)
		if code != 0 {
			return stats, syscall.Errno(code)
		}
		code, _, _ = getStats4.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0, 0, 0, uintptr(unsafe.Pointer(&stats)), 0, unsafe.Sizeof(stats))
	}
	if code != 0 {
		return stats, syscall.Errno(code)
	}
	if rw == 0 {
		return stats, fmt.Errorf("端口接收统计未启用")
	}
	return stats, nil
}

func connectionStats6(row *tcpRow6) (dataStats, error) {
	var rw byte
	var stats dataStats
	code, _, _ := getStats6.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0, 0, 0, uintptr(unsafe.Pointer(&stats)), 0, unsafe.Sizeof(stats))
	if code != 0 {
		return stats, syscall.Errno(code)
	}
	if rw == 0 {
		rw = 1
		code, _, _ = setStats6.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0)
		if code != 0 {
			return stats, syscall.Errno(code)
		}
		code, _, _ = getStats6.Call(uintptr(unsafe.Pointer(row)), 1, uintptr(unsafe.Pointer(&rw)), 0, 1, 0, 0, 0, uintptr(unsafe.Pointer(&stats)), 0, unsafe.Sizeof(stats))
	}
	if code != 0 {
		return stats, syscall.Errno(code)
	}
	if rw == 0 {
		return stats, fmt.Errorf("端口接收统计未启用")
	}
	return stats, nil
}

func (s *windowsPortSource) Sample() PortSnapshot {
	result := PortSnapshot{Complete: true}
	for _, family := range []uint32{2, 23} {
		table, err := tcpTable(family)
		if err != nil {
			result.Complete = false
			result.Error = "部分连接的实时接收统计暂不可用：" + err.Error()
			continue
		}
		rowSize := 24
		if family == 23 {
			rowSize = 56
		}
		count := int(binary.LittleEndian.Uint32(table[:4]))
		if count > (len(table)-4)/rowSize {
			result.Complete = false
			result.Error = "实时连接信息不完整"
			continue
		}
		for i := 0; i < count; i++ {
			data := table[4+i*rowSize : 4+(i+1)*rowSize]
			var key string
			var stats dataStats
			var statErr error
			if family == 2 {
				row := tcpRow4{State: binary.LittleEndian.Uint32(data), LocalAddr: binary.LittleEndian.Uint32(data[4:]), LocalPort: binary.LittleEndian.Uint32(data[8:]) & 0xffff, RemoteAddr: binary.LittleEndian.Uint32(data[12:]), RemotePort: binary.LittleEndian.Uint32(data[16:]) & 0xffff}
				if int(binary.BigEndian.Uint16(data[8:10])) != s.port || row.State < 5 || row.State > 10 {
					continue
				}
				key = fmt.Sprintf("4/%x/%x/%x/%x/%d", row.LocalAddr, row.LocalPort, row.RemoteAddr, row.RemotePort, binary.LittleEndian.Uint32(data[20:]))
				stats, statErr = connectionStats4(&row)
			} else {
				state := binary.LittleEndian.Uint32(data[48:])
				if int(binary.BigEndian.Uint16(data[20:22])) != s.port || state < 5 || state > 10 {
					continue
				}
				row := tcpRow6{State: state, LocalScope: binary.LittleEndian.Uint32(data[16:]), LocalPort: binary.LittleEndian.Uint32(data[20:]) & 0xffff, RemoteScope: binary.LittleEndian.Uint32(data[40:]), RemotePort: binary.LittleEndian.Uint32(data[44:]) & 0xffff}
				copy(row.LocalAddr[:], data[:16])
				copy(row.RemoteAddr[:], data[24:40])
				key = fmt.Sprintf("6/%x/%d/%x/%x/%d/%x/%d", row.LocalAddr, row.LocalScope, row.LocalPort, row.RemoteAddr, row.RemoteScope, row.RemotePort, binary.LittleEndian.Uint32(data[52:]))
				stats, statErr = connectionStats6(&row)
			}
			reading := ConnectionCounter{Key: key, Valid: statErr == nil}
			if statErr == nil {
				reading.Bytes = stats.DataBytesIn
				reading.Segments = stats.DataSegsIn
			} else {
				result.Error = "部分连接的实时接收统计暂不可用：" + statErr.Error()
			}
			result.Connections = append(result.Connections, reading)
		}
	}
	// Microsoft recommends leaving collection enabled; disabling/resetting it
	// can disturb another monitoring application using the same connection.
	return result
}
