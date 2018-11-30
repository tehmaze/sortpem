// +build darwin dragonfly freebsd linux netbsd openbsd

package main

import (
	"syscall"
	"unsafe"
)

var (
	stdinfd    = uintptr(syscall.Stdin)
	tiocgwinsz = uintptr(syscall.TIOCGWINSZ)
)

type winsize struct {
	Row, Col, X, Y uint16
}

func systemTerminalWidth() (width int) {
	var (
		ws        = &winsize{}
		ret, _, _ = syscall.Syscall(syscall.SYS_IOCTL, stdinfd, tiocgwinsz, uintptr(unsafe.Pointer(ws)))
	)
	if int(ret) == -1 {
		return
	}
	return int(ws.Col)
}
