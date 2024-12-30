//go:build windows

package ndisapi

import (
	"errors"

	"golang.org/x/sys/windows"
)

// safeObjectHandle is a wrapper class for a Windows handle
type safeObjectHandle struct {
	Handle windows.Handle
}

// NewSafeObjectHandle creates a new SafeObjectHandle from an existing handle.
func NewSafeObjectHandle(handle windows.Handle) *safeObjectHandle {
	return &safeObjectHandle{Handle: handle}
}

// Close releases the handle if valid
func (h *safeObjectHandle) Close() error {
	if !h.IsValid() {
		return nil
	}
	err := windows.CloseHandle(h.Handle)
	h.Handle = 0
	return err
}

// Get returns the stored handle value.
func (h *safeObjectHandle) Get() windows.Handle {
	return h.Handle
}

// IsValid checks if the handle is valid (not invalid or nil).
func (h *safeObjectHandle) IsValid() bool {
	return h.Handle != windows.InvalidHandle && h.Handle != 0
}

// SafeEvent is a wrapper for a Windows event object, extending SafeObjectHandle.
type SafeEvent struct {
	*safeObjectHandle
}

// NewSafeEvent constructs a SafeEvent from an existing handle.
func NewSafeEvent(handle windows.Handle) *SafeEvent {
	return &SafeEvent{safeObjectHandle: NewSafeObjectHandle(handle)}
}

// Wait waits on the event for a specified timeout in milliseconds.
// Returns the result of WaitForSingleObject and any errors.
func (e *SafeEvent) Wait(milliseconds uint32) (uint32, error) {
	if !e.IsValid() {
		return windows.WAIT_FAILED, errors.New("invalid handle")
	}
	return windows.WaitForSingleObject(e.Get(), milliseconds)
}

// Signal sets the event to a signaled state.
func (e *SafeEvent) Signal() error {
	if !e.IsValid() {
		return errors.New("invalid handle")
	}
	if err := windows.SetEvent(e.Get()); err != nil {
		return err
	}
	return nil
}

// Reset sets the event to a non-signaled state.
func (e *SafeEvent) Reset() error {
	if !e.IsValid() {
		return errors.New("invalid handle")
	}
	if err := windows.ResetEvent(e.Get()); err != nil {
		return err
	}
	return nil
}
