//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package main

import "os"

// isTerminal falls back to the character-device check where there is no
// termios ioctl (Windows, Plan 9…).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
