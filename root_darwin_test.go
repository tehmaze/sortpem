// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sortpem

import (
	"runtime"
	"testing"
	"time"
)

func TestSystemRoots(t *testing.T) {
	switch runtime.GOARCH {
	case "arm", "arm64":
		t.Skipf("skipping on %s/%s, no system root", runtime.GOOS, runtime.GOARCH)
	}

	/*
		switch runtime.GOOS {
		case "darwin":
			t.Skipf("skipping on %s/%s until golang.org/issue/24652 has been resolved.", runtime.GOOS, runtime.GOARCH)
		}
	*/

	t1 := time.Now()
	sysRoots := systemRootsPool() // non-cgo roots
	sysRootsDuration := time.Since(t1)

	t.Logf("sys roots: %v", sysRootsDuration)

	for _, tt := range []*CertPool{sysRoots} {
		if tt == nil {
			t.Fatal("no system roots")
		}
		// On Mavericks, there are 212 bundled certs, at least
		// there was at one point in time on one machine.
		// (Maybe it was a corp laptop with extra certs?)
		// Other OS X users report
		// 135, 142, 145...  Let's try requiring at least 100,
		// since this is just a sanity check.
		t.Logf("got %d roots", len(tt.certs))
		if want, have := 100, len(tt.certs); have < want {
			t.Fatalf("want at least %d system roots, have %d", want, have)
		}
	}
}
