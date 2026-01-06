package main

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// enterNetns locks the current thread, saves the original namespace, and
// switches into the target namespace so subsequent netlink operations run
// inside the container's netns.
func enterNetns(path string) error {
	runtime.LockOSThread()

	orig, err := os.Open("/proc/self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("open original netns: %w", err)
	}

	target, err := os.Open(path)
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		return fmt.Errorf("open target netns %s: %w", path, err)
	}
	defer target.Close()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		return fmt.Errorf("setns into %s: %w", path, err)
	}

	origNetns = orig
	return nil
}

// exitNetns restores the original namespace and unlocks the thread.
func exitNetns() {
	if origNetns != nil {
		_ = unix.Setns(int(origNetns.Fd()), unix.CLONE_NEWNET)
		origNetns.Close()
		origNetns = nil
	}
	runtime.UnlockOSThread()
}

var origNetns *os.File
