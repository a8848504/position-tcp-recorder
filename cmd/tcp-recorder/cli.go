package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"positioning/tcp-recorder/internal/analysis"
	"positioning/tcp-recorder/internal/recording"
	"positioning/tcp-recorder/internal/version"
	"strconv"
)

// This non-GUI path supports scripted Windows acceptance checks and offline recovery.
func runCLI() bool {
	if len(os.Args) < 2 {
		return false
	}
	if os.Args[1] == "--version" {
		fmt.Println("PositionTCP " + version.Current)
		return true
	}
	if os.Args[1] == "--analyze" && len(os.Args) == 5 {
		port, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path, err := filepath.Abs(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		r := recording.Recording{Version: recording.FormatVersion, ID: "import", Port: port, Directory: filepath.Dir(path), CaptureFiles: []string{filepath.Base(path)}}
		if err := recording.Prepare(context.Background(), os.Args[2], &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return true
	}
	if os.Args[1] == "--report" && len(os.Args) >= 5 && len(os.Args) <= 8 {
		port, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path, err := filepath.Abs(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		seconds := 2.0
		if len(os.Args) >= 6 {
			seconds, err = strconv.ParseFloat(os.Args[5], 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		root := ""
		if len(os.Args) >= 7 {
			root = os.Args[6]
		}
		var macs []string
		if len(os.Args) == 8 {
			macs, err = analysis.ParseMACs(os.Args[7])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		r := recording.Recording{Version: recording.FormatVersion, Name: filepath.Base(filepath.Dir(path)), Port: port, Directory: filepath.Dir(path), CaptureFiles: []string{filepath.Base(path)}}
		// Reuse notes and local-address hints when invoked for an existing recording.
		if data, readErr := os.ReadFile(filepath.Join(r.Directory, "recording.json")); readErr == nil {
			var saved recording.Recording
			if json.Unmarshal(data, &saved) == nil {
				r.Name = saved.Name
				r.Note = saved.Note
				r.Sessions = saved.Sessions
				r.LocalAddresses = saved.LocalAddresses
				r.Warnings = saved.Warnings
			}
		}
		report, err := analysis.Analyze(context.Background(), os.Args[2], r, analysis.Options{ExpectedSeconds: seconds, OutputRoot: root, MACs: macs})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"html": report.HTMLPath, "devices": report.DeviceCount, "inner_frames": report.InnerValid, "tcp_gaps": report.TCPGaps})
		return true
	}
	fmt.Fprintln(os.Stderr, "Usage: --version | --analyze <tshark> <capture.pcapng> <server-port> | --report <tshark> <capture.pcapng> <server-port> [period-seconds] [output-directory] [mac1,mac2,...]")
	os.Exit(2)
	return true
}
