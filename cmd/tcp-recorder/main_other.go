//go:build !windows

package main

import "fmt"

func main() {
	if !runCLI() {
		fmt.Println("GUI is available in the Windows release. Use --analyze for offline verification.")
	}
}
