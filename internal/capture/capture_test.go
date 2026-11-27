package capture

import (
	"strings"
	"testing"
)

func TestDumpcapPortFilterAppliesToEveryAdapter(t *testing.T) {
	output := "1. \\Device\\NPF_{ABC} (Ethernet)\n2. \\Device\\NPF_Loopback (Loopback)\n3. sshdump (SSH remote capture)\n"
	args, err := dumpcapArguments(output, 9000, `C:\captures\data.pcapng`)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "|")
	if !strings.HasPrefix(joined, "-f|tcp port 9000|-s|0|-B|32|-i|1|-i|2|") {
		t.Fatalf("filter is not a default for all adapters: %v", args)
	}
	if strings.Contains(joined, "-i|3") {
		t.Fatal("included remote extcap adapter")
	}
}

func TestExistingPktmonRulesAreNotConsideredEmpty(t *testing.T) {
	for _, value := range []string{"Packet Filters:\r\n    None.\r\n", "数据包筛选器:\r\n    无。\r\n"} {
		if !filtersAreEmpty(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"", "Packet Filters:\n  NoneProduction TCP 443", "数据包筛选器:\n 无线业务 TCP 443", "unknown locale output"} {
		if filtersAreEmpty(value) {
			t.Fatalf("accepted existing/unknown filter set: %q", value)
		}
	}
}
