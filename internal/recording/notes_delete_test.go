package recording

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotesPersistWithoutReplacingNewestRecordingStatistics(t *testing.T) {
	root := t.TempDir()
	r, err := New(root, 9000, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	r.Status = "ready"
	r.Bytes = 54321
	r.Events = 42
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if err := UpdateNote(r.Directory, "  一楼定位漂移\r\n人员走动  "); err != nil {
		t.Fatal(err)
	}
	items, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Note != "一楼定位漂移 人员走动" || items[0].Bytes != 54321 || items[0].Events != 42 || items[0].Status != "ready" {
		t.Fatalf("note clobbered metadata: %+v", items)
	}
	if err := UpdateNote(r.Directory, ""); err != nil {
		t.Fatal(err)
	}
	items, err = List(root)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Note != "" {
		t.Fatal("note was not cleared")
	}
}

func TestOldRecordingsWithoutNotesRemainReadable(t *testing.T) {
	root := t.TempDir()
	r, err := New(root, 9000, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(r.Directory, "recording.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"note"`) {
		t.Fatal("fixture is not a legacy manifest")
	}
	items, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Note != "" {
		t.Fatalf("%+v", items)
	}
	if err := UpdateNote(r.Directory, "旧录制补充备注"); err != nil {
		t.Fatal(err)
	}
}

func TestNoteValidationUsesCharactersAndRejectsInvalidInput(t *testing.T) {
	if _, err := NormalizeNote(strings.Repeat("中", 500)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{strings.Repeat("中", 501), "bad\x00note"} {
		if _, err := NormalizeNote(value); err == nil {
			t.Fatal("invalid note accepted")
		}
	}
}

func TestDeleteOnlySelectedRecording(t *testing.T) {
	root := t.TempDir()
	first, err := New(root, 9000, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(root, 9001, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Recording{first, second} {
		if err := os.WriteFile(filepath.Join(r.Directory, "traffic.pcapng"), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Delete(root, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first.Directory); !os.IsNotExist(err) {
		t.Fatalf("selected recording remains: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(second.Directory, "traffic.pcapng")); err != nil || string(data) != "synthetic" {
		t.Fatalf("other recording changed: %s %v", data, err)
	}
}

func TestDeleteRejectsEscapesAndUnmanagedDirectories(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "unmanaged"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "../escape", outside, `C:\outside`, "unmanaged"} {
		if err := Delete(root, id); err == nil {
			t.Fatalf("accepted unsafe delete %q", id)
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("outside data changed")
	}
}

func TestDeleteDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	r, err := New(root, 9000, "pktmon")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.Directory, "external")); err != nil {
		t.Skip("symlink unavailable: " + err.Error())
	}
	if err := Delete(root, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("followed nested link outside recording")
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked-recording")); err != nil {
		t.Fatal(err)
	}
	if err := Delete(root, "linked-recording"); err == nil {
		t.Fatal("accepted linked recording")
	}
}
