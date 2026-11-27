package analysis

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// Device IDs in the positioning frames are not necessarily Ethernet MACs.
// Match the complete normalized ID; never use suffix or substring matching.
func ParseMACs(input string) ([]string, error) {
	parts := strings.FieldsFunc(input, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(",;，；、|", r) })
	var result []string
	seen := map[string]bool{}
	for _, part := range parts {
		value := strings.TrimPrefix(strings.ToLower(part), "0x")
		value = strings.NewReplacer(":", "", "-", "").Replace(value)
		if len(value) < 6 || len(value) > 24 || len(value)%2 != 0 {
			return nil, fmt.Errorf("设备 MAC/ID %q 格式无效：请输入报告中的完整设备 ID（6～24 位偶数十六进制）", part)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return nil, fmt.Errorf("设备 MAC/ID %q 包含非十六进制字符", part)
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
		if len(result) > 128 {
			return nil, fmt.Errorf("每次最多分析 128 个设备 MAC")
		}
	}
	return result, nil
}

func (a *analyzer) includeDevice(id string) bool {
	return len(a.macFilter) == 0 || a.macFilter[id]
}
