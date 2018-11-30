// +build darwin

package sortpem

import "testing"

func TestMain(m *testing.M) {
	debugExecDarwinRoots = true
	m.Run()
}
