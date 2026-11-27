package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Keep the native UI responsive during Windows' own synchronous shutdown.
// Never terminate a slow stop command just to make the button return sooner.
func processingStage(directory, name string, log func(string), action func() error) error {
	start := time.Now()
	if log != nil {
		log(name + "…")
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if log != nil {
					log(fmt.Sprintf("%s，已等待 %.0f 秒…", name, time.Since(start).Seconds()))
				}
			}
		}
	}()
	err := action()
	close(done)
	<-stopped
	state := "完成"
	if err != nil {
		state = "失败"
	}
	message := fmt.Sprintf("%s%s，耗时 %.2f 秒", name, state, time.Since(start).Seconds())
	if f, openErr := os.OpenFile(filepath.Join(directory, "processing-times.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); openErr == nil {
		_, _ = fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), message)
		_ = f.Close()
	}
	if log != nil {
		log(message)
	}
	return err
}
