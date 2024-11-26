//go:build windows

package ndisapi

import (
	"errors"

	"golang.org/x/sys/windows"
)

// SafeObjectHandle is a wrapper class for a Windows handle
type SafeObjectHandle struct {
	Handle windows.Handle
}

// NewSafeObjectHandle creates a new SafeObjectHandle from an existing handle.
func NewSafeObjectHandle(handle windows.Handle) *SafeObjectHandle {
	return &SafeObjectHandle{Handle: handle}
}

// Close releases the handle if valid
func (h *SafeObjectHandle) Close() error {
	if h.IsValid() {
		return windows.CloseHandle(h.Handle)
	}
	return nil
}

// Get returns the stored handle value.
func (h *SafeObjectHandle) Get() windows.Handle {
	return h.Handle
}

// IsValid checks if the handle is valid (not invalid or nil).
func (h *SafeObjectHandle) IsValid() bool {
	return h.Handle != windows.InvalidHandle && h.Handle != 0
}

// SafeEvent is a wrapper for a Windows event object, extending SafeObjectHandle.
type SafeEvent struct {
	*SafeObjectHandle
}

// NewSafeEvent constructs a SafeEvent from an existing handle.
func NewSafeEvent(handle windows.Handle) *SafeEvent {
	return &SafeEvent{SafeObjectHandle: NewSafeObjectHandle(handle)}
}

// Wait waits on the event for a specified timeout in milliseconds.
// Returns the result of WaitForSingleObject and any errors.
func (e *SafeEvent) Wait(milliseconds uint32) (uint32, error) {
	if !e.IsValid() {
		return 0, errors.New("invalid handle")
	}
	result, err := windows.WaitForSingleObject(e.Get(), milliseconds)
	return result, err
}

// Signal sets the event to a signaled state.
func (e *SafeEvent) Signal() error {
	if !e.IsValid() {
		return errors.New("invalid handle")
	}
	return windows.SetEvent(e.Get())
}

// Reset sets the event to a non-signaled state.
func (e *SafeEvent) Reset() error {
	if !e.IsValid() {
		return errors.New("invalid handle")
	}
	return windows.ResetEvent(e.Get())
}
