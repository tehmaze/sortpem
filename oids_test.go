package main

import (
	"encoding/asn1"
	"testing"
)

func TestOIDName(t *testing.T) {
	var tests = []struct {
		Test asn1.ObjectIdentifier
		Want string
	}{
		{oidPKIX, "PKIX"},
		{oidISGR, "ISGR"},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947, 1, 2, 3}, "id-ISGR-1.2.3"},
		{asn1.ObjectIdentifier{6, 6, 6}, ""},
	}
	for _, test := range tests {
		t.Run(test.Test.String(), func(t *testing.T) {
			if s := oidName(test.Test); s != test.Want {
				t.Fatalf("expected %q to return %q, got %q", test.Test, test.Want, s)
			}
		})
	}
}
