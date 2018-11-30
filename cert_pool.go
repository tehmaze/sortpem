// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sortpem

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"runtime"
)

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyID map[string][]int
	byName         map[string][]int
	certs          []*x509.Certificate
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

func (pool *CertPool) copy() *CertPool {
	p := &CertPool{
		bySubjectKeyID: make(map[string][]int, len(pool.bySubjectKeyID)),
		byName:         make(map[string][]int, len(pool.byName)),
		certs:          make([]*x509.Certificate, len(pool.certs)),
	}
	for k, v := range pool.bySubjectKeyID {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.bySubjectKeyID[k] = indexes
	}
	for k, v := range pool.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	copy(p.certs, pool.certs)
	return p
}

// SystemCertPool returns a copy of the system cert pool.
//
// Any mutations to the returned pool are not written to disk and do
// not affect any other pool.
//
// New changes in the the system cert pool might not be reflected
// in subsequent calls.
func SystemCertPool() (*CertPool, error) {
	if runtime.GOOS == "windows" {
		// Issue 16736, 18609:
		return nil, errors.New("crypto/x509: system root pool is not available on Windows")
	}

	if sysRoots := systemRootsPool(); sysRoots != nil {
		return sysRoots.copy(), nil
	}

	return loadSystemRoots()
}

// findVerifiedParents attempts to find certificates in s which have signed the
// given certificate. If any candidates were rejected then errCert will be set
// to one of them, arbitrarily, and err will contain the reason that it was
// rejected.
func (pool *CertPool) findVerifiedParents(cert *x509.Certificate) (parents []int, errCert *x509.Certificate, err error) {
	if pool == nil {
		return
	}
	var candidates []int

	if len(cert.AuthorityKeyId) > 0 {
		candidates = pool.bySubjectKeyID[string(cert.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = pool.byName[string(cert.RawIssuer)]
	}

	for _, c := range candidates {
		if err = cert.CheckSignatureFrom(pool.certs[c]); err == nil {
			parents = append(parents, c)
		} else {
			errCert = pool.certs[c]
		}
	}

	return
}

// Contains checks if the cert is a trusted root certificate in this pool.
func (pool *CertPool) Contains(cert *x509.Certificate) bool {
	if pool == nil {
		return false
	}

	candidates := pool.byName[string(cert.RawSubject)]
	for _, c := range candidates {
		if pool.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
func (pool *CertPool) AddCert(cert *x509.Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if pool.Contains(cert) {
		return
	}

	n := len(pool.certs)
	pool.certs = append(pool.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyID := string(cert.SubjectKeyId)
		pool.bySubjectKeyID[keyID] = append(pool.bySubjectKeyID[keyID], n)
	}
	name := string(cert.RawSubject)
	pool.byName[name] = append(pool.byName[name], n)
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (pool *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		pool.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (pool *CertPool) Subjects() [][]byte {
	res := make([][]byte, len(pool.certs))
	for i, c := range pool.certs {
		res[i] = c.RawSubject
	}
	return res
}
