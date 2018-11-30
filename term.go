package main

import (
	"os"
	"strconv"
)

const defaultTerminalWidth = 80

// terminalWidth resolves the system terminal width, by:
//  1. observe the COLUMNS environment setting, if set and int it is used
//  2. call systemTerminalWidth() to get the terminal width from the system
//  3. return 80 if all else fails
func terminalWidth() (width int) {
	if v := os.Getenv("COLUMNS"); v != "" {
		if width, _ = strconv.Atoi(v); width > 0 {
			debugf("terminal width: from environment: %d", width)
			return
		}
	}

	if width = systemTerminalWidth(); width > 0 {
		debugf("terminal width: from system: %d", width)
		return
	}

	width = defaultTerminalWidth
	debugf("terminal width: using default: %d", width)
	return
}
