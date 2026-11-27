package recording

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	Open       byte = 1
	Data       byte = 2
	Close      byte = 3
	maxPayload      = 16 * 1024 * 1024
)

var eventMagic = [8]byte{'T', 'C', 'P', 'R', 'E', 'C', '0', '1'}

type Event struct {
	Kind     byte
	Session  uint32
	OffsetNS int64
	Payload  []byte
}

func WriteHeader(w io.Writer) error { _, err := w.Write(eventMagic[:]); return err }

func WriteEvent(w io.Writer, e Event) error {
	if e.Kind < Open || e.Kind > Close || e.OffsetNS < 0 || len(e.Payload) > maxPayload || (e.Kind != Data && len(e.Payload) != 0) {
		return fmt.Errorf("无效回放事件")
	}
	var head [21]byte
	head[0] = e.Kind
	binary.LittleEndian.PutUint32(head[1:5], e.Session)
	binary.LittleEndian.PutUint64(head[5:13], uint64(e.OffsetNS))
	binary.LittleEndian.PutUint32(head[13:17], uint32(len(e.Payload)))
	crc := crc32.Update(0, crc32.IEEETable, head[:17])
	crc = crc32.Update(crc, crc32.IEEETable, e.Payload)
	binary.LittleEndian.PutUint32(head[17:21], crc)
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(e.Payload)
	return err
}

type EventReader struct{ r io.Reader }

func NewEventReader(r io.Reader) (*EventReader, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != eventMagic {
		return nil, fmt.Errorf("回放文件格式不受支持")
	}
	return &EventReader{r: r}, nil
}

func (r *EventReader) Next() (Event, error) {
	var head [21]byte
	_, err := io.ReadFull(r.r, head[:])
	if err != nil {
		return Event{}, err
	}
	e := Event{Kind: head[0], Session: binary.LittleEndian.Uint32(head[1:5]), OffsetNS: int64(binary.LittleEndian.Uint64(head[5:13]))}
	length := binary.LittleEndian.Uint32(head[13:17])
	if e.Kind < Open || e.Kind > Close || e.OffsetNS < 0 || length > maxPayload || (e.Kind != Data && length != 0) {
		return Event{}, fmt.Errorf("回放文件包含无效记录")
	}
	e.Payload = make([]byte, length)
	if _, err = io.ReadFull(r.r, e.Payload); err != nil {
		return Event{}, err
	}
	crc := crc32.Update(0, crc32.IEEETable, head[:17])
	crc = crc32.Update(crc, crc32.IEEETable, e.Payload)
	if crc != binary.LittleEndian.Uint32(head[17:21]) {
		return Event{}, fmt.Errorf("回放文件校验失败，文件可能损坏")
	}
	return e, nil
}

func ValidateEvents(r io.Reader) error {
	er, err := NewEventReader(r)
	if err != nil {
		return err
	}
	sessions := map[uint32]bool{}
	seen := map[uint32]bool{}
	var previous int64
	for {
		e, err := er.Next()
		if err == io.EOF {
			if len(sessions) != 0 {
				return fmt.Errorf("回放文件缺少连接结束记录，文件可能未完整保存")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if e.OffsetNS < previous {
			return fmt.Errorf("回放事件时间倒序")
		}
		previous = e.OffsetNS
		switch e.Kind {
		case Open:
			if seen[e.Session] {
				return fmt.Errorf("重复建立会话")
			}
			sessions[e.Session] = true
			seen[e.Session] = true
		case Data:
			if !sessions[e.Session] {
				return fmt.Errorf("数据没有对应连接")
			}
		case Close:
			if !sessions[e.Session] {
				return fmt.Errorf("关闭了不存在的连接")
			}
			delete(sessions, e.Session)
		}
	}
}
