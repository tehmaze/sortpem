// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build plan9

package main

import (
	"crypto/x509"
	"io/ioutil"
	"os"
)

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/sys/lib/tls/ca.pem",
}

func systemVerify(c *x509.Certificate, opts *x509.VerifyOptions) (chains [][]*x509.Certificate, err error) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, error) {
	roots := NewCertPool()
	var bestErr error
	for _, file := range certFiles {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			return roots, nil
		}
		if bestErr == nil || (os.IsNotExist(bestErr) && !os.IsNotExist(err)) {
			bestErr = err
		}
	}
	if bestErr == nil {
		return roots, nil
	}
	return nil, bestErr
}