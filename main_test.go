package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"
)

func TestRegexps(t *testing.T) {
	var test = regexps{
		regexp.MustCompile(`o`),
		regexp.MustCompile(`r$`),
		regexp.MustCompile(`z^`),
	}
	if !test.MatchString("foo") {
		t.Fatal(`must match "foo"`)
	}
	if i := test.Index("bar"); i != 1 {
		t.Fatalf(`expected "bar" to match index 1, got %d`, i)
	}
	if i := test.Index("qux"); i != -1 {
		t.Fatalf(`expected "qux" to not match, got index %d`, i)
	}

	want := `o,r$,z^`
	if s := test.String(); s != want {
		t.Fatalf(`expected %q, got %q`, want, s)
	}

	if err := test.Set(`(`); err == nil {
		t.Fatalf("expected error")
	}
	if err := test.Set("qux"); err != nil {
		t.Fatal(err)
	}
}

func TestTypeFilter(t *testing.T) {
	var tests = []struct {
		Regexp          *regexp.Regexp
		Match, NotMatch []string
	}{
		/*
			oneCertificate      = regexp.MustCompile(`^` + certificate + `$`)
			anyPrivateKey       = regexp.MustCompile(privateKey + `$`)
			oneX509PrivateKey   = regexp.MustCompile(`^` + x509PrivateKey + `$`)
			oneRSAPrivateKey    = regexp.MustCompile(`^` + rsaPrivateKey + `$`)
			oneOpenVPNStaticKey = regexp.MustCompile(`^` + openVPNStaticKey)
			onePGPPublicKey     = regexp.MustCompile(`^` + pgpPublicKey + `$`)
			onePGPPrivateKey    = regexp.MustCompile(`^` + pgpPrivateKey + `$`)
		*/
		{oneCertificate, []string{certificate}, []string{publicKey}},
		{anyPrivateKey, []string{privateKey, rsaPrivateKey, ecPrivateKey, pgpPrivateKey}, []string{certificate, publicKey}},
		{oneX509PrivateKey, []string{privateKey, rsaPrivateKey, ecPrivateKey}, []string{publicKey, pgpPrivateKey}},
		{oneRSAPrivateKey, []string{rsaPrivateKey}, []string{ecPrivateKey}},
		{oneOpenVPNStaticKey, []string{openVPNStaticKey + " V1"}, []string{privateKey, rsaPrivateKey}},
		{onePGPPublicKey, []string{pgpPublicKey}, []string{publicKey}},
		{onePGPPrivateKey, []string{pgpPrivateKey}, []string{privateKey}},
	}
	for _, test := range tests {
		t.Run(test.Regexp.String(), func(t *testing.T) {
			for _, s := range test.Match {
				if !test.Regexp.MatchString(s) {
					t.Errorf("expected %q to match", s)
				}
			}
			for _, s := range test.NotMatch {
				if test.Regexp.MatchString(s) {
					t.Errorf("expected %q to not match", s)
				}
			}
		})
	}
}

func TestPreset(t *testing.T) {
	p := preset{
		Name:    "test",
		Reverse: true,
		Root:    true,
		Stable:  true,
		Unique:  true,
		Filter:  regexps{oneCertificate, oneX509PrivateKey},
	}
	s := p.String()
	want := `-t "^` + certificate + `$" -t "^` + x509PrivateKey + `$" -r -root -s -u`
	if s != want {
		t.Fatalf("expected preset to return %q, got %q", want, s)
	}

	p.Apply()
	if !*reverseFlag {
		t.Fatal("apply failed")
	}

	listPresets()
}

func TestReadInput(t *testing.T) {
	// lol?
}

func TestOpenOutput(t *testing.T) {
	*outputFlag = ""
	if wc, _, err := openOutput(); err != nil {
		t.Fatal(err)
	} else if f, ok := wc.(*os.File); !ok {
		t.Fatalf("expected standard output to be a file, got %T", f)
	} else if f != os.Stdout {
		t.Fatalf("expected openOutput() to return standard output, got %q (%T)", f.Name(), wc)
	}

	*outputFlag = "-"
	if wc, _, err := openOutput(); err != nil {
		t.Fatal(err)
	} else if f, ok := wc.(*os.File); !ok {
		t.Fatalf("expected standard output to be a file, got %T", f)
	} else if f != os.Stdout {
		t.Fatalf("expected openOutput() to return standard output, got %q (%T)", f.Name(), wc)
	}

	*outputFlag = filepath.Join("testdata", "test.output")
	defer os.Remove(*outputFlag)
	if wc, _, err := openOutput(); err != nil {
		t.Fatal(err)
	} else if _, ok := wc.(*os.File); !ok {
		t.Fatalf("expected standard output to be a file, got %T", wc)
	} else if err = wc.Close(); err != nil {
		t.Fatalf("error closing file: %v", err)
	}
}

func TestDecodeAll(t *testing.T) {
	if blocks := decodeAll(nil); len(blocks) != 0 {
		t.Fatalf("expected no blocks, got %d", len(blocks))
	}
	if blocks := decodeAll([]byte("-----BEGIN TEST-----\n\n\n-----END TEST-----\n")); len(blocks) != 1 {
		t.Fatalf("expected one block, got %d", len(blocks))
	}
}

func TestDecodeCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(googleEndpoint))

	t0 := time.Now()
	c, err := decodeCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	d0 := time.Since(t0)
	if c == nil {
		t.Fatal("decodeCertificate returned nil certificate but no error")
	}
	t.Logf("decode in %s", d0)

	// Next one should come from cache
	t1 := time.Now()
	if c, _ = decodeCertificate(block.Bytes); c == nil {
		t.Fatal("decodeCertificate returned nil certificate on second run")
	}
	d1 := time.Since(t1)
	t.Logf("decode in %s (from cache)", d1)

	if d1 >= d0 {
		t.Fatalf("first certificate parsed in %s, second in %s which should have come from cache", d0, d1)
	}
}

func TestCompareBlock(t *testing.T) {
	var (
		a, _    = pem.Decode([]byte(googleIntermediate))
		b, _    = pem.Decode([]byte(googleEndpoint))
		c       = &pem.Block{Type: privateKey}
		d, _    = pem.Decode([]byte(selfSignedRoot))
		blocks  = []*pem.Block{a, b, c, d}
		compare = compareBlock(blocks)
	)

	if compare(0, 1) {
		t.Fatal("expected compare(0, 1) to return false")
	}
	if !compare(1, 0) {
		t.Fatal("expected compare(1, 0) to return true")
	}
	if compare(0, 0) {
		t.Fatal("expected compare(0, 0) to return false")
	}
	if compare(2, 0) {
		t.Fatal("expected compare(2, 0) to return false")
	}
	if !compare(0, 2) {
		t.Fatal("expected compare(0, 2) to return false")
	}

	sort.SliceStable(blocks, compare)

	if blocks[0].Type != certificate {
		t.Fatalf("expected block[0] to be a %s, got %s", certificate, blocks[0].Type)
	}
	if blocks[1].Type != certificate {
		t.Fatalf("expected block[1] to be a %s, got %s", certificate, blocks[1].Type)
	}
	if blocks[2].Type != certificate {
		t.Fatalf("expected block[2] to be a %s, got %s", certificate, blocks[2].Type)
	}
	if blocks[3].Type != privateKey {
		t.Fatalf("expected block[3] to be a %s, got %s", privateKey, blocks[3].Type)
	}
}

func TestCompareCertificates(t *testing.T) {
	a, _ := pem.Decode([]byte(googleEndpoint))
	b, _ := pem.Decode([]byte(googleIntermediate))

	// decode i & j failed
	if compareCertificates(nil, nil) {
		t.Fatal("expected compareCertificates(nil, nil) to return false")
	}

	// decode i failed
	if compareCertificates(nil, a.Bytes) {
		t.Fatal("expected compareCertificates(nil, der) to return false")
	}

	// decode j failed
	if !compareCertificates(a.Bytes, nil) {
		t.Fatal("expected compareCertificates(def, nil) to return true")
	}

	// a is signed by b
	if !compareCertificates(a.Bytes, b.Bytes) {
		t.Fatal("expected compareCertificates to return true")
	}
}

func TestReadRoots(t *testing.T) {
	*caFlag = ""
	if p, err := readRoots(); err != nil {
		t.Fatal(err)
	} else if p == nil {
		t.Fatal("returned nil CertPool")
	}

	*caFlag = filepath.Join("testdata/root.crt")
	if p, err := readRoots(); err != nil {
		t.Fatal(err)
	} else if p == nil {
		t.Fatal("returned nil CertPool")
	}
}

func TestIncludeRoot(t *testing.T) {
	roots = NewCertPool()
	roots.AppendCertsFromPEM([]byte(globalSignRootR2))

	var (
		a, _      = pem.Decode([]byte(googleIntermediate))
		b, _      = pem.Decode([]byte(googleEndpoint))
		c         = &pem.Block{Type: privateKey}
		d         = &pem.Block{Type: certificate, Bytes: []byte("bogus")}
		blocks    = []*pem.Block{a, b, c, d}
		withRoots = includeRoot(blocks)
	)
	if len(withRoots) != len(blocks) {
		t.Fatalf("expected no more certificate after includeRoot, but got %d before and %d after", len(blocks), len(withRoots))
	}
}

func TestExcludeRoots(t *testing.T) {
	var (
		a, _         = pem.Decode([]byte(googleIntermediate))
		b, _         = pem.Decode([]byte(googleEndpoint))
		c, _         = pem.Decode([]byte(selfSignedRoot))
		d            = &pem.Block{Type: certificate, Bytes: []byte("bogus")}
		blocks       = []*pem.Block{a, b, c, d}
		withoutRoots = excludeRoots(blocks)
	)
	if len(blocks)-len(withoutRoots) != 2 {
		t.Fatalf("expected 2 less certificate after excludeRoots, but got %d before and %d after", len(blocks), len(withoutRoots))
	}
}

func TestIsRoot(t *testing.T) {
	roots = NewCertPool()
	roots.AppendCertsFromPEM([]byte(globalSignRootR2))

	var (
		a, _ = pem.Decode([]byte(globalSignRootR2))
		b, _ = pem.Decode([]byte(selfSignedRoot))
		c, _ = pem.Decode([]byte(googleIntermediate))
	)

	ac, err := decodeCertificate(a.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !isRoot(ac) {
		t.Fatalf("expected root certificate")
	}

	bc, err := decodeCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !isRoot(bc) {
		t.Fatalf("expected self-signed root certificate")
	}

	cc, err := decodeCertificate(c.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if isRoot(cc) {
		t.Fatalf("expected intermediate certificate not to be a trusted root")
	}
}

const googleEndpoint = `-----BEGIN CERTIFICATE-----
MIIIgjCCB2qgAwIBAgIITFQTbb/xK/QwDQYJKoZIhvcNAQELBQAwVDELMAkGA1UE
BhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczElMCMGA1UEAxMc
R29vZ2xlIEludGVybmV0IEF1dGhvcml0eSBHMzAeFw0xODEwMzAxMzE1MDVaFw0x
OTAxMjIxMzE1MDBaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKDApHb29nbGUgTExDMRUw
EwYDVQQDDAwqLmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDRv5QQH5QVvWw7g5dJKa0IYxgRG1d9TbM/nM1i7etN0mt4Pz8BSEOogbZC
9hp8cAen9Xqp+i9qddtUZFRFIuxc26OQ9xEYcfbKBN5UvHjoz3QSnzIrQa5vAbRs
MEadRC6wz/nI8uk6bIKjWv5SX9sJgR5+vDil3ZGw9JkBqXf/Dw0QGTFLyiNCZtv7
B/XMLUbWCPDurI0yPeUb/R0p6vKfn4KfGl9B42oibXMGuyvqfzE7CSBLwIkEfi5o
kGoeNsY93oMpOdc/zr4UcGst7n2PMJX32lZN7mn2SiwpI3ezOOHkJLghxJ7lhsZz
RU+ob+CB805GAz3p0gFbb1c8ItSDAgMBAAGjggVEMIIFQDATBgNVHSUEDDAKBggr
BgEFBQcDATCCBBkGA1UdEQSCBBAwggQMggwqLmdvb2dsZS5jb22CDSouYW5kcm9p
ZC5jb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNv
bYIGKi5nLmNvgg4qLmdjcC5ndnQyLmNvbYIKKi5nZ3BodC5jboIWKi5nb29nbGUt
YW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2ds
ZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2ds
ZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdv
b2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8q
Lmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29n
bGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyou
Z29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdv
b2dsZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVv
LmNvbYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tghIqLmdzdGF0aWNjbmFw
cHMuY26CCiouZ3Z0MS5jb22CCiouZ3Z0Mi5jb22CFCoubWV0cmljLmdzdGF0aWMu
Y29tggwqLnVyY2hpbi5jb22CECoudXJsLmdvb2dsZS5jb22CFioueW91dHViZS1u
b2Nvb2tpZS5jb22CDSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlvbi5j
b22CESoueW91dHViZWtpZHMuY29tggcqLnl0LmJlggsqLnl0aW1nLmNvbYIaYW5k
cm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tghtkZXZlbG9wZXIu
YW5kcm9pZC5nb29nbGUuY26CHGRldmVsb3BlcnMuYW5kcm9pZC5nb29nbGUuY26C
BGcuY2+CCGdncGh0LmNuggZnb28uZ2yCFGdvb2dsZS1hbmFseXRpY3MuY29tggpn
b29nbGUuY29tghJnb29nbGVjb21tZXJjZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdv
b2dsZS5jboIKdXJjaGluLmNvbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1
YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbYIPeW91dHViZWtpZHMuY29tggV5
dC5iZTBoBggrBgEFBQcBAQRcMFowLQYIKwYBBQUHMAKGIWh0dHA6Ly9wa2kuZ29v
Zy9nc3IyL0dUU0dJQUczLmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AucGtp
Lmdvb2cvR1RTR0lBRzMwHQYDVR0OBBYEFImk2MctNTxFuj4sWG46mRHmaVq8MAwG
A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUd8K4UJpndnaxLcKG0IOgfqZ+ukswIQYD
VR0gBBowGDAMBgorBgEEAdZ5AgUDMAgGBmeBDAECAjAxBgNVHR8EKjAoMCagJKAi
hiBodHRwOi8vY3JsLnBraS5nb29nL0dUU0dJQUczLmNybDANBgkqhkiG9w0BAQsF
AAOCAQEAx1ekl60y4V8QUwW6A8TNLhHJfTapTBaoRqFaMMRPBIaNi+GVJDRilEi5
ij3S10nrpWxZcsNk9iTdADkxW0rU0PlzTnsLcIlw+ql2KsSB7boW393ZDb3N0dKR
p4F06S15yPAuyTO1TS8BBjzaL0h+C7er2duQRclPyt2pWBsgIOxqgVqmmUcHFGA/
pvxysdjrJ8qfUyD0AY/Z8dCs1RQfx8SKbXuoML9e0X5uxRmeyjQ0s+BPJDIQG5b8
IGSRGSm8vWtg9vz/GDZIErtEO1kgXOslBBGL5NSCFpxkp1lh/Usi3nFzPcU6Fbvx
WMSdoZZKpgy5+6GGjYv/dEyEdnXYzg==
-----END CERTIFICATE-----
`

const googleIntermediate = `-----BEGIN CERTIFICATE-----
MIIEXDCCA0SgAwIBAgINAeOpMBz8cgY4P5pTHTANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMFQxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzMw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKUkvqHv/OJGuo2nIYaNVW
XQ5IWi01CXZaz6TIHLGp/lOJ+600/4hbn7vn6AAB3DVzdQOts7G5pH0rJnnOFUAK
71G4nzKMfHCGUksW/mona+Y2emJQ2N+aicwJKetPKRSIgAuPOB6Aahh8Hb2XO3h9
RUk2T0HNouB2VzxoMXlkyW7XUR5mw6JkLHnA52XDVoRTWkNty5oCINLvGmnRsJ1z
ouAqYGVQMc/7sy+/EYhALrVJEA8KbtyX+r8snwU5C1hUrwaW6MWOARa8qBpNQcWT
kaIeoYvy/sGIJEmjR0vFEwHdp1cSaWIr6/4g72n7OqXwfinu7ZYW97EfoOSQJeAz
AgMBAAGjggEzMIIBLzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH
AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHfCuFCa
Z3Z2sS3ChtCDoH6mfrpLMB8GA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYu
MDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdv
b2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dz
cjIvZ3NyMi5jcmwwPwYDVR0gBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYc
aHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEA
HLeJluRT7bvs26gyAZ8so81trUISd7O45skDUmAge1cnxhG1P2cNmSxbWsoiCt2e
ux9LSD+PAj2LIYRFHW31/6xoic1k4tbWXkDCjir37xTTNqRAMPUyFRWSdvt+nlPq
wnb8Oa2I/maSJukcxDjNSfpDh/Bd1lZNgdd/8cLdsE3+wypufJ9uXO1iQpnh9zbu
FIwsIONGl1p3A8CgxkqI/UAih3JaGOqcpcdaCIzkBaR9uYQ1X4k2Vg5APRLouzVy
7a8IVk6wuy6pm+T7HT4LY8ibS5FEZlfAFLSW8NwsVz9SBK2Vqn1N0PIMn5xA6NZV
c7o835DLAFshEWfC7TIe3g==
-----END CERTIFICATE-----
`

const globalSignRootR2 = `-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
-----END CERTIFICATE-----
`

const selfSignedRoot = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDYMaYch34jBTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlU
ZXN0IFJvb3QwHhcNMTgxMTI4MjMwNTIzWhcNMjgxMTI1MjMwNTIzWjAUMRIwEAYD
VQQDDAlUZXN0IFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT
q/+a6DFFcu6C9ho2srlGCJO1nznvTx8v4rkj0D4v8S437hdJRNkp8bGf9Id5SFiV
Z/INWcmiK48K0AXRIMS4vFIc9yd8pt3WgBkXruKR5R9QQTIwBKDfxk6wlHZsx5eV
xF1RXdjYjChkzK9r8ZW0Qoog41rIvxaIW9SlT+Rh4d+u1d6xabupplF4fQvDSCy+
f/IbqcbHR50ulSqUm7C1P0Fn6fWELKYn4mMhLMxUrT5DLSpgswMWv/rzyqnr9wwe
HaZte6N8NIzgChxnuEbGwMQpV4dB8RWn5c7XhmssVTHHq1EuIKp8jzU9en9JRfhL
SgtvMgX63bZ7RXghkL2DAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAynSDikx4jk
BsTySVeszT4iPsW6OSCU8vznc/aF56f4m9ZD8nTd4+D3V1zT8I5ux6hL3Td+GMzM
VlcDv/LBdi7P6Jl+Ht2q1JkCZbRGo9LFFGJCK9SBOXpHdVLxT9N2BHEHiKzvtz8B
HIHkGcfgZe/iEj+wCcLsOLTpkEhh/OCda+LEzWU4LpzlHVP7w1XuNMGgf4j8XySd
oO7th4OUv3/7XUkb9eGcAF+/soO6NVctINTXXU6QUTvAfs6FUH9hyamytd0SjzNx
DKRie58JByzI4LEDqxPuV26JrVqMG/6pJuENJKG8/pw0id0axoJMeywvV/47JN7Q
XxQkrbhzbh4=
-----END CERTIFICATE-----
`
