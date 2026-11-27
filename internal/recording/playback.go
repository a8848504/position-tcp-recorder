package recording

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ReplayControl freezes the common timeline for every replay connection.
// Its zero value is ready to use. Pause returns after any current socket
// operation completes; bytes already handed to TCP cannot be recalled.
type ReplayControl struct {
	mu               sync.RWMutex
	changed          chan struct{}
	anchor, pausedAt time.Time
	pausedFor        time.Duration
	paused, active   bool
	pausedSnapshot   atomic.Bool
}

func (c *ReplayControl) signal() {
	if c.changed != nil {
		close(c.changed)
	}
	c.changed = make(chan struct{})
}

func (c *ReplayControl) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active {
		return fmt.Errorf("回放控制器正在使用中")
	}
	c.active = true
	c.anchor = time.Now()
	c.pausedFor = 0
	if c.paused {
		c.pausedAt = c.anchor
	}
	c.signal()
	return nil
}

func (c *ReplayControl) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.signal()
}

func (c *ReplayControl) Pause() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return false
	}
	c.paused, c.pausedAt = true, time.Now()
	c.pausedSnapshot.Store(true)
	c.signal()
	return true
}

func (c *ReplayControl) Resume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		return false
	}
	c.pausedFor += time.Since(c.pausedAt)
	c.paused = false
	c.pausedSnapshot.Store(false)
	c.signal()
	return true
}

func (c *ReplayControl) Paused() bool { return c.pausedSnapshot.Load() }

func (c *ReplayControl) wait(ctx context.Context, offset time.Duration) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.RLock()
		paused, changed := c.paused, c.changed
		delay := offset - time.Since(c.anchor) + c.pausedFor
		c.mu.RUnlock()
		if paused {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-changed:
			}
			continue
		}
		if delay <= 0 {
			return ctx.Err()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Keep the pause state stable across the socket operation. Multiple connection
// workers may run together, while Pause waits for all in-flight writes/dials.
func (c *ReplayControl) perform(ctx context.Context, offset time.Duration, fn func()) error {
	for {
		if err := c.wait(ctx, offset); err != nil {
			return err
		}
		c.mu.RLock()
		if c.paused {
			c.mu.RUnlock()
			continue
		}
		if err := ctx.Err(); err != nil {
			c.mu.RUnlock()
			return err
		}
		fn()
		c.mu.RUnlock()
		return nil
	}
}
