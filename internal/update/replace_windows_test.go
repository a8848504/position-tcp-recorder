package update

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the actual replacement helper in child processes. The driver exits so
// Apply can replace its EXE, then the restarted candidate writes a receipt.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--replacement-driver":
			if err := StartReplacement(os.Args[2], os.Args[3], os.Args[4]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			os.Exit(0)
		case "--apply-update":
			if err := Apply(os.Args[2:]); err != nil {
				os.WriteFile(os.Getenv("POSITION_TCP_UPDATE_RECEIPT"), []byte(err.Error()), 0600)
				os.Exit(2)
			}
			os.Exit(0)
		case "--cleanup-helper":
			exe, _ := os.Executable()
			data, _ := os.ReadFile(exe)
			os.WriteFile(os.Getenv("POSITION_TCP_UPDATE_RECEIPT"), []byte(fmt.Sprintf("%x", sha256.Sum256(data))), 0600)
			CleanHelper(os.Args[2])
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestWindowsReplacementAndRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "中文 path & $ parentheses ()")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "PositionTCP-old.exe")
	if err := copyFile(self, target); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(directory, ".position-tcp-update-test.bin")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("new version test marker")...)
	if err := os.WriteFile(candidate, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	receipt := filepath.Join(directory, "receipt.txt")
	t.Setenv("POSITION_TCP_UPDATE_RECEIPT", receipt)
	if out, err := exec.Command(target, "--replacement-driver", target, candidate, digest).CombinedOutput(); err != nil {
		t.Fatalf("driver: %v %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, err := os.ReadFile(receipt)
		if err == nil {
			if strings.TrimSpace(string(got)) != digest {
				t.Fatalf("replacement failed: %s", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("updated application did not restart")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := Verify(target, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(candidate); !os.IsNotExist(err) {
		t.Fatal("candidate not moved", err)
	}
}
