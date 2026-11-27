//go:build !windows

package capture

type unsupportedSource struct{}

func newPortSource(port int) PortSource { return unsupportedSource{} }
func (unsupportedSource) Sample() PortSnapshot {
	return PortSnapshot{Error: "实时端口统计仅支持 Windows"}
}
