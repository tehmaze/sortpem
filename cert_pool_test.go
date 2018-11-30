package sortpem_test

import (
	"testing"

	"github.com/tehmaze/sortpem"
)

func TestCertPool(t *testing.T) {
	roots, err := sortpem.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	roots.AppendCertsFromPEM([]byte(globalSignRootR2PEM))

	var (
		a = testDecodeCertificate(t, globalSignRootR2PEM)
		b = testDecodeCertificate(t, selfSignedRootPEM)
		c = testDecodeCertificate(t, googleIntermediatePEM)
	)

	if !roots.Contains(a) {
		t.Fatalf("expected root to be in certificate pool")
	}
	if roots.Contains(b) {
		t.Fatalf("expected self-signed root to not be in certificate pool")
	}
	if roots.Contains(c) {
		t.Fatalf("expected intermediate certificate not to be a trusted root")
	}
}
