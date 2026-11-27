package update

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestUpdateDownloadAndVersionCheck(t *testing.T) {
	raw := []byte("test release asset")
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/repos/demo/analyzer/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v1.10.0","assets":[{"id":10,"name":"PositionTCP-Windows-amd64-1.10.0.exe","size":%d,"digest":"sha256:%s"}]}`, len(raw), digest)
		case "/demo/analyzer/releases/download/v1.10.0/PositionTCP-Windows-amd64-1.10.0.exe", "/repos/demo/analyzer/releases/assets/10":
			if r.Header.Get("Accept") != "application/octet-stream" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Write(raw)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api := NewGitHub("demo/analyzer")
	api.apiBase, api.downloadBase = server.URL, server.URL
	ctx := context.Background()
	current, err := api.Latest(ctx, "v1.10.1", "amd64")
	if err != nil || current != nil {
		t.Fatalf("downgrade accepted: %+v %v", current, err)
	}
	release, err := api.Latest(ctx, "v1.9.1", "amd64")
	if err != nil || release == nil {
		t.Fatalf("update missing: %+v %v", release, err)
	}
	directory := t.TempDir()
	path, err := api.Download(ctx, release, directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, digest); err != nil {
		t.Fatal(err)
	}
	release.Digest = fmt.Sprintf("%064x", 1)
	if _, err := api.Download(ctx, release, directory, nil); err == nil {
		t.Fatal("changed EXE accepted")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("failed download was left on disk: %v %v", files, err)
	}
}

func TestDownloadProgressAndIdleFallback(t *testing.T) {
	payload := []byte("complete and verified")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/demo/analyzer/releases/assets/10" {
			w.Write(payload)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.Write(payload[:4])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	api, release := testDownload(server.URL, payload)
	api.idleTimeout = 200 * time.Millisecond
	var progress []DownloadProgress
	path, err := api.Download(context.Background(), release, t.TempDir(),
		func(value DownloadProgress) { progress = append(progress, value) })
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, release.Digest); err != nil {
		t.Fatal(err)
	}
	if len(progress) < 5 || progress[1].Attempt != 1 || progress[1].Received != 4 ||
		progress[2].Attempt != 2 || progress[2].Received != 0 {
		t.Fatalf("partial transfer or fallback progress missing: %+v", progress)
	}
	if last := progress[len(progress)-1]; !last.Verifying || last.Received != int64(len(payload)) || last.Attempt != 2 {
		t.Fatalf("verification stage missing: %+v", last)
	}
}

func TestDownloadContinuesWhileReceivingBytes(t *testing.T) {
	payload := []byte("12345678")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		for i := range payload {
			w.Write(payload[i : i+1])
			w.(http.Flusher).Flush()
			if i+1 < len(payload) {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer server.Close()
	api, release := testDownload(server.URL, payload)
	api.idleTimeout = 300 * time.Millisecond
	var attempt int
	_, err := api.Download(context.Background(), release, t.TempDir(),
		func(progress DownloadProgress) { attempt = progress.Attempt })
	if err != nil || attempt != 1 {
		t.Fatalf("slow active download stalled: attempt=%d error=%v", attempt, err)
	}
}

func TestCancelDownloadRemovesPartialFile(t *testing.T) {
	payload := []byte("test release asset")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.Write(payload[:4])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	api, release := testDownload(server.URL, payload)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	directory := t.TempDir()
	_, err := api.Download(ctx, release, directory, func(progress DownloadProgress) {
		if progress.Received > 0 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("download was not cancelled: %v", err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("partial update left on disk: %v %v", files, err)
	}
}

func testDownload(base string, payload []byte) (*GitHub, *Release) {
	client := NewGitHub("demo/analyzer")
	client.apiBase, client.downloadBase = base, base
	release := &Release{
		Version: "v1.0.0", Size: int64(len(payload)), Digest: fmt.Sprintf("%x", sha256.Sum256(payload)),
		assetID: 10, assetName: "PositionTCP-Windows-amd64-1.10.0.exe",
	}
	return client, release
}

func TestRejectInvalidReleaseMetadata(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"missing digest", `{"tag_name":"v1.5.0","assets":[{"id":1,"name":"PositionTCP-Windows-amd64-1.5.0.exe","size":10}]}`},
		{"wrong architecture", `{"tag_name":"v1.5.0","assets":[{"id":1,"name":"PositionTCP-Windows-arm64-1.5.0.exe","size":10,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`},
		{"prerelease", `{"tag_name":"v1.5.0","prerelease":true}`},
		{"invalid version", `{"tag_name":"v1.5.0-rc1"}`},
		{"draft", `{"tag_name":"v1.5.0","draft":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, test.body) }))
			defer server.Close()
			api := NewGitHub("demo/analyzer")
			api.apiBase = server.URL
			if release, err := api.Latest(context.Background(), "1.4.0", "amd64"); err == nil || release != nil {
				t.Fatal("unusable update accepted", release, err)
			}
		})
	}
}
