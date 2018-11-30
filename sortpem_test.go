package sortpem_test

import (
	"crypto/x509"
	"encoding/pem"
	"sort"
	"testing"

	"github.com/tehmaze/sortpem"
)

func TestSorter(t *testing.T) {
	var (
		root, _         = pem.Decode([]byte(selfSignedRootPEM))
		intermediate, _ = pem.Decode([]byte(selfSignedIntermediatePEM))
		issuer, _       = pem.Decode([]byte(selfSignedIssuerPEM))
		endpoint, _     = pem.Decode([]byte(selfSignedEndpointPEM))
		endpointKey, _  = pem.Decode([]byte(selfSignedEndpointKeyPEM))
		randomKeyDSA, _ = pem.Decode([]byte(selfSignedRootDSAKeyPEM))
		randomKeyEC, _  = pem.Decode([]byte(selfSignedRootECKeyPEM))
		sorter          *sortpem.Sorter
	)

	// Sorter must not panic if nil
	sorter.Less(0, 0)

	// Sorter must not panic if out of bounds
	sorter = new(sortpem.Sorter)
	sorter.Less(-1, -1)

	sorter = sortpem.New([]*pem.Block{
		&pem.Block{Type: "TEST", Bytes: []byte("Testing :D")},
		issuer,
		endpoint,
		&pem.Block{Type: "EMPTY"},
		root,
		endpointKey,
		intermediate,
		randomKeyEC,
		randomKeyDSA,
	})
	sorter.Order = []string{"RSA PRIVATE KEY", "CERTIFICATE", "TEST"}

	// Do the sorting
	sort.Stable(sorter)

	for i, block := range sorter.Blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Error(err)
			} else {
				t.Logf("block %d: %s: %s", i, block.Type, cert.Subject)
			}

		default:
			t.Logf("block %d: %s", i, block.Type)

		}
	}

	if sorter.Blocks[0].Type != "RSA PRIVATE KEY" {
		t.Fatalf("expected first block to be an RSA PRIVATE KEY, got %s", sorter.Blocks[0].Type)
	}

	wantSubjects := []string{
		`CN=endpoint.example.org,L=IL`,
		`CN=Test Issuer`,
		`CN=Test Intermediate`,
		`CN=Test Root`,
	}
	for i := 1; i < 5; i++ {
		if sorter.Blocks[i].Type != "CERTIFICATE" {
			t.Fatalf("expected block %d to be a CERTIFICATE, got %s", i, sorter.Blocks[i].Type)
		}
		cert, err := x509.ParseCertificate(sorter.Blocks[i].Bytes)
		if err != nil {
			t.Error(err)
			continue
		} else if s := cert.Subject.String(); s != wantSubjects[i-1] {
			t.Errorf("expected block %d to have subject %q, got %q", i, wantSubjects[i-1], s)
		}
	}
}

func TestSorterRoots(t *testing.T) {
	roots, _ := sortpem.SystemCertPool()
	roots.AppendCertsFromPEM([]byte(selfSignedRootPEM))
	var (
		intermediate, _ = pem.Decode([]byte(selfSignedIntermediatePEM))
		issuer, _       = pem.Decode([]byte(selfSignedIssuerPEM))
		endpoint, _     = pem.Decode([]byte(selfSignedEndpointPEM))
		sorter          = &sortpem.Sorter{
			Blocks: []*pem.Block{
				intermediate,
				issuer,
				endpoint,
			},
		}
	)

	if sorter.ResolveRoots() {
		t.Fatalf("expected sorter without Roots to not change")
	}
	sorter.Roots = roots
	if !sorter.ResolveRoots() {
		t.Fatalf("expected sorter with Roots to change")
	}
	if l := len(sorter.Blocks); l != 4 {
		t.Fatalf("expected 4 blocks in sorter, got %d", l)
	}

	sorter.Roots = nil
	if sorter.ExcludeRoots() {
		t.Fatalf("expected sorter without Roots to not change")
	}
	sorter.Roots = roots
	if !sorter.ExcludeRoots() {
		t.Fatalf("expected sorter with Roots to change")
	}
	if l := len(sorter.Blocks); l != 3 {
		t.Fatalf("expected 3 blocks in sorter, got %d", l)
	}
}
