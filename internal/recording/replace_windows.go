package recording

import (
	"syscall"
	"unsafe"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(source, destination string) error {
	s, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	d, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	ok, _, e := moveFileEx.Call(uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(d)), 0x1|0x8)
	if ok == 0 {
		return e
	}
	return nil
}
