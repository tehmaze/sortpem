package main

import (
	"syscall"
	"unsafe"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func systemTerminalWidth() (width int) {
	var (
		ws        = &winsize{}
		ret, _, _ = syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(syscall.Stdin),
			uintptr(syscall.TIOCGWINSZ),
			uintptr(unsafe.Pointer(ws)))
	)
	if int(ret) == -1 {
		return
	}
	return int(ws.Col)
}
