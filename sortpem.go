package sortpem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
)

// Sorter can help sort slices of PEM blocks. You can use this struct directly,
// but the certificate resolution won't be cached, if you wish to use a
// cached version of the Sorter, invoke New.
//
// The sorter deploys the following sorting strategy:
// * Compare the block types A and B:
//   * If A and B are certificates:
//     * If A is an invalid certificate, sort after
//     * If B is an invalid certificate, sort before
//     * If A is signed by B, sort before
//     * If B is signed by A, sort after
//   * If either one of A and B are a certificate and the other a private key:
//     * If key A belongs to certificate B, reverse sort against Order list
//     * If key B belongs to certificate A, forward sort against Order list
// * Lookup the block type of A and B against the Order list, then:
//   * If A is unknown, sort after
//   * If B is unknown, sort before
//   * Compare if A is before B in the order list
type Sorter struct {
	// Blocks are our PEM blocks.
	Blocks []*pem.Block

	// Roots are our trusted root certificates.
	Roots *CertPool

	// Order of our blocks.
	Order []string

	// cache of already-parsed certificate blocks.
	cache map[string]*x509.Certificate
}

// New sorter for the PEM block slice.
func New(blocks []*pem.Block) *Sorter {
	return &Sorter{
		Blocks: blocks,
		cache:  make(map[string]*x509.Certificate),
	}
}

// Len is the number of Blocks contained.
func (sorter *Sorter) Len() int {
	return len(sorter.Blocks)
}

// Less comapares Blocks with index i and j.
func (sorter *Sorter) Less(i, j int) (less bool) {
	if sorter == nil {
		//log.Printf("sorter.Less(%d, %d): false (sorter is nil)", i, j)
		return false
	}

	l := len(sorter.Blocks)
	if i < 0 || j < 0 || i > l || j > l {
		// Out of bounds, can't compare
		//log.Printf("sorter.Less(%d, %d): false (out of bounds)", i, j)
		return false
	}

	a, b := sorter.Blocks[i], sorter.Blocks[j]
	if a.Type == certificate {
		if b.Type == certificate {
			//log.Printf("sorter.Less(%d, %d): compareCertificates", i, j)
			return sorter.compareCertificates(a.Bytes, b.Bytes)
		}
		if isPrivateKeyType(b.Type) {
			//log.Printf("sorter.Less(%d, %d): compareCertificatePrivateKey", i, j)
			return sorter.compareCertificatePrivateKey(a.Bytes, b.Bytes, b.Type)
		}
	} else if isPrivateKeyType(a.Type) {
		if b.Type == certificate {
			//log.Printf("sorter.Less(%d, %d): !compareCertificatePrivateKey", i, j)
			return !sorter.compareCertificatePrivateKey(b.Bytes, a.Bytes, a.Type)
		}
	}

	return sorter.compareTypes(a.Type, b.Type)
}

func isPrivateKeyType(kind string) bool {
	return kind == privateKey || kind == dsaPrivateKey || kind == rsaPrivateKey || kind == ecPrivateKey
}

// Swap Blocks with index i and j.
func (sorter *Sorter) Swap(i, j int) {
	//log.Printf("sorter: Swap(%d, %d)", i, j)
	sorter.Blocks[i], sorter.Blocks[j] = sorter.Blocks[j], sorter.Blocks[i]
}

func lessIndex(i, j int) bool {
	if i == -1 {
		return false
	}
	if j == -1 {
		return true
	}
	return i < j
}

func (sorter *Sorter) compareTypes(a, b string) bool {
	i, j := sorter.index(a), sorter.index(b)
	//log.Printf("compareTypes(%q, %q): lessIndex(%d, %d): %t", a, b, i, j, lessIndex(i, j))
	return lessIndex(i, j)
}

func (sorter *Sorter) index(kind string) int {
	for i, other := range sorter.Order {
		if kind == other {
			return i
		}
	}
	return -1
}

func (sorter *Sorter) compareCertificates(i, j []byte) bool {
	var (
		a, b *x509.Certificate
		err  error
	)
	if a, err = sorter.decodeCertificate(i); err != nil {
		// a is an invalid certificate
		//log.Printf("compareCertificates: a is invalid")
		return false
	}
	if b, err = sorter.decodeCertificate(j); err != nil {
		// b is an invalid certificate, but a is not
		//log.Printf("compareCertificates: b is invalid")
		return true
	}

	if IsSignedBy(a, b) {
		// a is signed by b
		//log.Println("compareCertificates: a is signed by b")
		return true
	}
	if IsSignedBy(b, a) {
		// b is signed by a
		//log.Println("compareCertificates: b is signed by a")
		return false
	}

	// don't know
	//log.Println("compareCertificates: don't know")
	return false
}

// compareCertificateKey checks if the
func (sorter *Sorter) compareCertificatePrivateKey(a, b []byte, kind string) bool {
	cert, err := sorter.decodeCertificate(a)
	if err != nil {
		//log.Printf("compareCertificatePrivateKey: invalid certificate: %v", err)
		return false
	}

	key, err := sorter.decodePrivateKey(b, kind)
	if err != nil {
		//log.Printf("compareCertificatePrivateKey: invalid private key: %v", err)
		return false
	}

	if PrivateKeyBelongTo(cert, key) {
		// depend on Order list
		i, j := sorter.index(certificate), sorter.index(kind)
		//log.Printf("compareCertificatePrivateKey: lessIndex(%d, %d): %t", i, j, lessIndex(i, j))
		return lessIndex(i, j)
	}

	// don't know
	//log.Printf("compareCertificatePrivateKey: %T doesn't belong to %s", key, cert.Subject)
	return false
}

func (sorter *Sorter) decodeCertificate(der []byte) (cert *x509.Certificate, err error) {
	if sorter.cache == nil {
		// we'll have to do without cache
		return x509.ParseCertificate(der)
	}

	var ok bool
	if cert, ok = sorter.cache[string(der)]; ok {
		return cert, nil
	}

	if cert, err = x509.ParseCertificate(der); err != nil {
		return
	}

	sorter.cache[string(der)] = cert
	return
}

func (sorter *Sorter) decodePrivateKey(data []byte, kind string) (key interface{}, err error) {
	switch kind {
	case privateKey:
		return x509.ParsePKCS8PrivateKey(data)
	case dsaPrivateKey:
		return parseDSAPrivateKey(data)
	case rsaPrivateKey:
		return x509.ParsePKCS1PrivateKey(data)
	case ecPrivateKey:
		return x509.ParseECPrivateKey(data)
	default:
		return nil, fmt.Errorf("sorter: unsupported private key type %q", kind)
	}
}

// ResolveRoots checks if the blocks in sorter have a root certificate and if
// they do not, it will attempt to resolve the root certificate for the passed
// certificates.
func (sorter *Sorter) ResolveRoots() (changed bool) {
	if sorter == nil || sorter.Roots == nil || len(sorter.Roots.certs) == 0 {
		// Fast path
		return
	}

	var certs = make([]*x509.Certificate, 0, len(sorter.Blocks))
	for _, block := range sorter.Blocks {
		if block.Type == certificate {
			cert, err := sorter.decodeCertificate(block.Bytes)
			if err == nil && sorter.Roots.Contains(cert) {
				// Found a trusted certificate, we're done here
				return
			}
			certs = append(certs, cert)
		}
	}

	// Now, for the parsed certificates, find roots
	for _, cert := range certs {
		if parents, _, err := sorter.Roots.findVerifiedParents(cert); err == nil && len(parents) > 0 {
			for _, root := range parents {
				sorter.Blocks = append(sorter.Blocks, &pem.Block{
					Type:  certificate,
					Bytes: sorter.Roots.certs[root].Raw,
				})
				changed = true
			}
		}
	}

	return
}

// ExcludeRoots checks if the blocks in sorter are a root certificate, and if
// they are, they will be removed.
func (sorter *Sorter) ExcludeRoots() (changed bool) {
	if sorter == nil || sorter.Roots == nil {
		return
	}
	for sorter.excludeRoots() {
		changed = true
	}
	return
}

func (sorter *Sorter) excludeRoots() (changed bool) {
	for i, block := range sorter.Blocks {
		if block.Type == certificate {
			if cert, err := sorter.decodeCertificate(block.Bytes); err == nil && sorter.Roots.Contains(cert) {
				sorter.Blocks = append(sorter.Blocks[:i], sorter.Blocks[i+1:]...)
				return true
			}
		}
	}
	return
}

// Interface checks.
var _ sort.Interface = (*Sorter)(nil)
