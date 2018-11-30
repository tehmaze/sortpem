package sortpem_test

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/tehmaze/sortpem"
)

func testDecodeCertificate(t *testing.T, s string) (cert *x509.Certificate) {
	var (
		der, _ = pem.Decode([]byte(s))
		err    error
	)
	if cert, err = x509.ParseCertificate(der.Bytes); err != nil {
		t.Fatal(err)
	}
	return
}

func TestKeyBelongsTo(t *testing.T) {
	var (
		globalSignRootR2  = testDecodeCertificate(t, globalSignRootR2PEM)
		selfSignedRootRSA = testDecodeCertificate(t, selfSignedRootPEM)
		selfSignedRootDSA = testDecodeCertificate(t, selfSignedRootDSAPEM)
		selfSignedRootEC  = testDecodeCertificate(t, selfSignedRootECPEM)
	)

	var (
		rsaPrivateKeyDER, _ = pem.Decode([]byte(selfSignedRootKeyPEM))
		rsaPrivateKey, rerr = x509.ParsePKCS1PrivateKey(rsaPrivateKeyDER.Bytes)
	)
	if rerr != nil {
		t.Fatal(rerr)
	}

	var (
		dsaPrivateKeyDER, _ = pem.Decode([]byte(selfSignedRootDSAKeyPEM))
		dsaPrivateKey, derr = parseDERDSAPrivateKey(dsaPrivateKeyDER.Bytes)
	)
	if derr != nil {
		t.Fatal(derr)
	}

	var (
		ecPrivateKeyDER, _ = pem.Decode([]byte(selfSignedRootECKeyPEM))
		ecPrivateKey, eerr = x509.ParseECPrivateKey(ecPrivateKeyDER.Bytes)
	)
	if eerr != nil {
		t.Fatal(eerr)
	}

	var (
		edPublicKey, edPrivateKey, cerr = ed25519.GenerateKey(rand.Reader)
	)
	if cerr != nil {
		t.Fatal(cerr)
	}

	if sortpem.KeyBelongsTo(globalSignRootR2, rsaPrivateKey) {
		t.Errorf("private key %T must not belong to %s", rsaPrivateKey, globalSignRootR2.Subject)
	}
	if sortpem.KeyBelongsTo(globalSignRootR2, nil) {
		t.Errorf("private key nil must not belong to %s", globalSignRootR2.Subject)
	}
	if !sortpem.KeyBelongsTo(selfSignedRootRSA, rsaPrivateKey) {
		t.Errorf("private key %T must belong to %s", rsaPrivateKey, selfSignedRootRSA.Subject)
	}
	if !sortpem.KeyBelongsTo(selfSignedRootDSA, dsaPrivateKey) {
		t.Errorf("private key %T must belong to %s %#+v", dsaPrivateKey.PublicKey, selfSignedRootDSA.Subject, selfSignedRootDSA.PublicKey)
	}
	if sortpem.KeyBelongsTo(selfSignedRootRSA, dsaPrivateKey) {
		t.Errorf("private key %T must not belong to %s %#+v", dsaPrivateKey.PublicKey, selfSignedRootRSA.Subject, selfSignedRootRSA.PublicKey)
	}
	if !sortpem.KeyBelongsTo(selfSignedRootEC, ecPrivateKey) {
		t.Errorf("private key %T must belong to %s", ecPrivateKey, selfSignedRootEC.Subject)
	}
	if sortpem.KeyBelongsTo(selfSignedRootEC, rsaPrivateKey) {
		t.Errorf("private key %T must not belong to %s", rsaPrivateKey, selfSignedRootEC.Subject)
	}
	if sortpem.KeyBelongsTo(selfSignedRootEC, edPrivateKey) {
		t.Errorf("private key %T must not belong to %s", edPrivateKey, selfSignedRootEC.Subject)
	}
	selfSignedRootEC.PublicKey = &edPublicKey
	if !sortpem.KeyBelongsTo(selfSignedRootEC, edPrivateKey) {
		t.Errorf("private key %T must belong to %s", edPrivateKey, selfSignedRootEC.Subject)
	}

	selfSignedRootEC.PublicKey = "invalid"
	if sortpem.KeyBelongsTo(selfSignedRootEC, edPrivateKey) {
		t.Errorf("private key %T must not belong to %s", edPrivateKey, selfSignedRootEC.Subject)
	}
}

func parseDERDSAPrivateKey(asn1Bytes []byte) (key *dsa.PrivateKey, err error) {
	var src struct {
		E1, P, Q, G, Y, X *big.Int
	}
	if _, err = asn1.Unmarshal(asn1Bytes, &src); err != nil {
		return
	}

	return &dsa.PrivateKey{
		X: src.X,
		PublicKey: dsa.PublicKey{
			Y: src.Y,
			Parameters: dsa.Parameters{
				P: src.P,
				Q: src.Q,
				G: src.G,
			},
		},
	}, nil
}

func TestIsSignedBy(t *testing.T) {
	var (
		rootRSA      = testDecodeCertificate(t, selfSignedRootPEM)
		rootDSA      = testDecodeCertificate(t, selfSignedRootDSAPEM)
		rootEC       = testDecodeCertificate(t, selfSignedRootECPEM)
		intermediate = testDecodeCertificate(t, selfSignedIntermediatePEM)
		issuer       = testDecodeCertificate(t, selfSignedIssuerPEM)
		endpoint     = testDecodeCertificate(t, selfSignedEndpointPEM)
	)

	if !sortpem.IsSignedBy(intermediate, rootRSA) {
		t.Errorf("expected %q to be signed by %q (%T)", intermediate.Subject, rootRSA.Subject, rootRSA.PublicKey)
	}
	if sortpem.IsSignedBy(intermediate, rootDSA) {
		t.Errorf("expected %q not to be signed by %q (%T)", intermediate.Subject, rootDSA.Subject, rootDSA.PublicKey)
	}
	if sortpem.IsSignedBy(intermediate, rootEC) {
		t.Errorf("expected %q not to be signed by %q (%T)", intermediate.Subject, rootEC.Subject, rootEC.PublicKey)
	}

	// test key ID mismatch
	intermediate.AuthorityKeyId = []byte("not sure")
	rootRSA.SubjectKeyId = []byte("invalid")
	if sortpem.IsSignedBy(intermediate, rootRSA) {
		t.Errorf("expected %q not to be signed by %q with invalid SubjectKeyId (%T)", intermediate.Subject, rootRSA.Subject, rootRSA.PublicKey)
	}

	if !sortpem.IsSignedBy(endpoint, issuer) {
		t.Errorf("expected %q to be signed by %q (%T)", endpoint.Subject, issuer.Subject, issuer.PublicKey)
	}

	// test broken signature
	endpoint.Signature = []byte("invalid")
	if sortpem.IsSignedBy(endpoint, issuer) {
		t.Errorf("expected %q to not be signed by %q with invalid Signature (%T)", endpoint.Subject, issuer.Subject, issuer.PublicKey)
	}

	// test unsupported public key algorithm (skipping signature checks)
	issuer.PublicKeyAlgorithm = x509.UnknownPublicKeyAlgorithm
	if !sortpem.IsSignedBy(endpoint, issuer) {
		t.Errorf("expected %q to be signed by %q with UnknownPublicKeyAlgorithm (%T)", endpoint.Subject, issuer.Subject, issuer.PublicKey)
	}

}

func TestIsSelfSigned(t *testing.T) {
	var (
		googleEndpoint   = testDecodeCertificate(t, googleEndpointPEM)
		globalSignRootR2 = testDecodeCertificate(t, globalSignRootR2PEM)
		selfSignedRoot   = testDecodeCertificate(t, selfSignedRootPEM)
	)

	t.Logf("comparing %s key %T", googleEndpoint.Subject, googleEndpoint.PublicKey)
	if sortpem.IsSelfSigned(googleEndpoint) {
		t.Errorf("expected %s to not be self-signed", googleEndpoint.Subject)
	}

	t.Logf("comparing %s key %T", globalSignRootR2.Subject, globalSignRootR2.PublicKey)
	if !sortpem.IsSelfSigned(globalSignRootR2) {
		t.Errorf("expected %s to be self-signed", globalSignRootR2.Subject)
	}

	t.Logf("comparing %s key %T", selfSignedRoot.Subject, selfSignedRoot.PublicKey)
	if !sortpem.IsSelfSigned(selfSignedRoot) {
		t.Errorf("expected %s to be self-signed", selfSignedRoot.Subject)
	}
}

const googleEndpointPEM = `-----BEGIN CERTIFICATE-----
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

const googleIntermediatePEM = `-----BEGIN CERTIFICATE-----
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

const globalSignRootR2PEM = `-----BEGIN CERTIFICATE-----
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

const selfSignedEndpointPEM = `-----BEGIN CERTIFICATE-----
MIIDEjCCAfqgAwIBAgIJAOwuuYAYA5kcMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC1Rlc3QgSXNzdWVyMB4XDTE4MTEzMDE0MTM0N1oXDTI4MTEyNzE0MTM0N1ow
LDEdMBsGA1UEAwwUZW5kcG9pbnQuZXhhbXBsZS5vcmcxCzAJBgNVBAcMAklMMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5gluxG1z6ma3f9MSbyt/J7i
VgvwsN6mrer2FS1cvq/YqzWjvG3jtnoiGs5YFrJXkqXMg4aQZZ3pThWTyI6U4zA6
CUPQW5vZK5eV2GP2YgTZ7eM0MkViqD3f1YYttledjLxf7t256HHJf0aW2oqRGkCD
O3x/cbPmVLUYIyOZJFau53v7oJn3o7+LDfFKZcQi5jUVvMqo9XvNUxTh3rZsRk6Y
st8tA8eJwXgxR3vtRTcIx0Ot697kmY7RBCUxI6BK9GXDCuWmRJPFkCB4nHqqvL7X
MczwR5+WUA0L/0wAj2CkqOpGY7oMTknwhxe+3Qx7yiOqtYOrYF/4kbgcxK2iAQID
AQABo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQXWGeyX9yO6Sw1NjBV2ly1t/Jn
MzAfBgNVHSMEGDAWgBQZ7BAS86+b9tOwtfASqT9MsbzmPTANBgkqhkiG9w0BAQsF
AAOCAQEAf8sYcrHr8uHp6AtgmtdpdkEEUgC6NUP/f1ITcwkIXoOuzA2ehem0dvx4
SmNbr5L9E0/3UGrEk6PonYiq1A00p326JiAjB7BcBmoHd5RXWRjkLnnOuQ0IU+7y
2xwZAnLS1bBXk6rSS8TwFK589O7szsCK7KdfUoN2PwUxpWfmNpfrT5VqKZdFh4FM
4fCD34fLVntnaKsOfxDjuIlZoYCIXfmq76pgeRkpArXFjEb6pGBqItsB44Wxi/Pl
rLpQTH2TGndGRVA6Tz0AbBCqdfo0bnBOnwOc9AtcgSSxQku4Lh/Ms/tmjvF0F3ED
NhCAEbXMKyQ9tUioc44hncPBeasqow==
-----END CERTIFICATE-----
`

const selfSignedEndpointKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv5gluxG1z6ma3f9MSbyt/J7iVgvwsN6mrer2FS1cvq/YqzWj
vG3jtnoiGs5YFrJXkqXMg4aQZZ3pThWTyI6U4zA6CUPQW5vZK5eV2GP2YgTZ7eM0
MkViqD3f1YYttledjLxf7t256HHJf0aW2oqRGkCDO3x/cbPmVLUYIyOZJFau53v7
oJn3o7+LDfFKZcQi5jUVvMqo9XvNUxTh3rZsRk6Yst8tA8eJwXgxR3vtRTcIx0Ot
697kmY7RBCUxI6BK9GXDCuWmRJPFkCB4nHqqvL7XMczwR5+WUA0L/0wAj2CkqOpG
Y7oMTknwhxe+3Qx7yiOqtYOrYF/4kbgcxK2iAQIDAQABAoIBAQCB/0biheK5kxes
NxPZGDdpJ5jkz1cxevDXIoxz1AKQs5msmUmOiXUvE/FeBNHKHJnEu9BnEX+aIynw
vD04oF2vRMKsFKIj9jvFEyYt262J1kbT3QxGa8PD6a+dHlyX0xzoJ8xjs3f3mnUg
cZHbmJdZm5ovW4rRaEIJCZLmDLpU53rgbgx8bjI/XyGnkh+07V7sAzASG7c8xovG
3j4Bra4KcYT/PoQsp3LSPSJce35N035Js/6EyRahTiSiFyj3c8rjR5r8xxv6apPH
oPldLvSRczEhQR4sO5RrTBd3kpluA500O8JZFyfBHyvX0cMh/YKGb/KXxideSuQ9
SkqMA1Y9AoGBAOp218jghYv8X4stSz6xJcy5TIsaEqmX13rMZUiiJPvdTtuqc+7U
Dm/B9b0lPcSXQJah1w+YrJ7/hctzdqTNnB5MEeNLjqI6OwRYpuF99fbqTJ2vI5jH
RvGED2HZzOyU3dnBtVNxY60MTVaJsFnFmFCfe9B/JrxtI8B8psvnx+07AoGBANEx
RJXNyI+1BdlqjJeSzoY0W34eNw3jWHPRIW8bVBxN5a3pEBsf9OLV50eX7JCoAtKs
ipI9/VPQTAjT/TCGO7SMFKAN/hfmOT1H0hr9bMKamSCtc9JQqWxd3dXJfIQg8Gxi
Yq+GvwfqYD1OhIO0E8B6DH9ZmQlWiCVnwOVsKynzAoGBAIaGPXTR7Y3N9XvDNyL3
PPrjbll5Ui/gIRAh6hLshU/FQJOkjvP+03Gn1bj6fyAmsDY9EUmvjYuEjF2ZF/+i
wOpZNwI0vdeylV3/B3DldpR/BgqLDF+CJuA3pyO7dWpgV5GzJLiFnG0TW+RFB9va
FXRcrQuJiM4fyJ2OZ50ilYE1AoGBALiD6mjv/+2x0Bz7fFLdrMh3OhQ99nWLiCNv
3TuxMTleBC6nmgsy3r+NyNg/Suw1JXhJtFhV0TKyUb6frX21iMgxnqemb+8IpIhG
5y3jRqFH17UZCUYC28235cmCVQ/+NdKD3WPRSIJk2sp4jS3WEm39uTRDBVdVOfU0
VNKH3HK9AoGAIrXKdRBUBDGQXYCmrdOdIEvsoNru8mcCYtML/RdfPi7MuwXO6CQT
ai3It+rnoJz9sunM0qvsnO7HgYR+JpLWxYS+aEResw9KB1WykYzOECP3PONCnmCQ
rn/BRzhdR0tMNiUEaT/4WbTaZpnAYUINpaejFsZl+KQ+AXb7haiOqLk=
-----END RSA PRIVATE KEY-----
`

const selfSignedIssuerPEM = `-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIJAMSTCxfrnfpqMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNV
BAMMEVRlc3QgSW50ZXJtZWRpYXRlMB4XDTE4MTEzMDE0MTM0N1oXDTI4MTEyNzE0
MTM0N1owFjEUMBIGA1UEAwwLVGVzdCBJc3N1ZXIwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC8csN66RXZT1lgXUwjA7cRYZXgwlE4DcLHeHIaKnqHvHzC
/2SuaoYSRJgEJNyCktz1V0v+neai97Jzuy+6ubuAfDGOmU+dm6jPRyKjl9VTMRej
vhBIC+kQWJgLmiFfYwiU9UmdLrCKKY3/43AiQQUDfhZnsEoB/0ARyufjDVxMuKRm
RQaP3cZ9A1Qv/ZwOG4FW3DJYOqLE/qdcpF279zCnuGt/MrgWVvDNoBNM3h1owHkR
Grn2+57xR+0CYkVJd+k1lbmVz26uyGnipVg35EV5ZH42TSwdojpjTInGuNF+14dv
D+yov8fTGsTF7K3/+m6DigtsD7kXvwkJ1BICP4WdAgMBAAGjXzBdMAwGA1UdEwQF
MAMBAf8wHQYDVR0OBBYEFBnsEBLzr5v207C18BKpP0yxvOY9MC4GA1UdIwQnMCWh
GKQWMBQxEjAQBgNVBAMMCVRlc3QgUm9vdIIJAJRHIlwBUm3PMA0GCSqGSIb3DQEB
CwUAA4IBAQCHkCr74kMopDNOW6nsEsVvLT/NKwxOYaYgcG1F7kzHBvPz3wpdR13d
RNll13XqvX3Rie2/Bk5NuGGTVCDxWp+9Dh+sdF3MJC1AdltEZtdDVP70SPVk4h2i
xnvQrwm3sMa5LQ0zF0dcWEmA+CJA7fTfyYDFEmR/G+m/4xujeSk1EzUbRl6JFjkI
qynQNAm+33w1gAitbsFr5f/vNBxFcjMCQEXRxXl9mfIJkV9COH5FNvGTgDK79tl0
ivfigHrze5JzTGcwqp+vNZFT+/3OFfgN/MrFhtNwdzngPnPVc8r1aPYcop8ZCYuj
ZkKLU7xnytBLMePOD7XhKVBYeVa/oj1M
-----END CERTIFICATE-----
`

const selfSignedIntermediatePEM = `-----BEGIN CERTIFICATE-----
MIICwzCCAaugAwIBAgIJAJRHIlwBUm3PMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCVRlc3QgUm9vdDAeFw0xODExMzAxNDEzNDdaFw0yODExMjcxNDEzNDdaMBwx
GjAYBgNVBAMMEVRlc3QgSW50ZXJtZWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA5T1NkFsexiOo7i/06t8mO89Msjwle+5t5Bd22derzDCp2aWh
xmro9sXGnGyZxpQ42Tec+V4xoMEhFLX/qb4OPGb7K8W4sFOF8XXnqOgFzOG7A1H3
G+dvRLNQL9q/xGpTu8tN4SH4UsGws7qF3nJoI5UXSPgp2JYJfyKQ/XrzwbDFZOlF
DBcyvwMJAgVwZZe2mWRZGrjRDHwIU5gS1SjVi+EFCVlx0J0Djs37nIIsbdgMkq4J
jomdMsvpZqVb8h8i/BTAzDdcX3Si/K3VhtgS9+WGrz+zBxUug+FaHnxQ5/fH1DMo
kv1mMmZ88epDcUiSmy8JQ+pbWCLGq4HEJoVdpwIDAQABoxAwDjAMBgNVHRMEBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCqGTWy2QGc61L4POeICK0vY6iU7DrVyYO1
sNi2oCiAxfYqb1ZIhAsayAVwcMBl4QTD6Jk63eDAbF3U4w1YbY+AQWmsAplAySE3
CDZ2ExTQRakvTSyxj9QoqFDdzrZeP0uyaTlAiMEdlG2D5mjF101ZbfPt31Wc5+nI
cmwrE6RpZqM0xFAXPjVLWRRE14rjuvUokefpXasNjZmKgj8Lo3i8/pSjjWWQXMnH
E2yN8056rGxnqAcHef0PZwHBPkg3aVUk6DYmS6pSCgRWnYkcdGYjnlDU12A+sPM6
nkGoD+AGWd0qji4WH8yQEO/YDOY/WMirP/clo9GSPXhwc6+aXQ58
-----END CERTIFICATE-----
`

const selfSignedRootPEM = `-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIJAOyKc7oUs6k/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCVRlc3QgUm9vdDAeFw0xODExMzAxNDA2MTlaFw0yODExMjcxNDA2MTlaMBQx
EjAQBgNVBAMMCVRlc3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALOH7lR3CvxAw7ohQpWpyMb9rYUVXHee2my4k0AToLikZjA3jXHmwfWWusz9
836zup9BpXRqj/ahaNqJUliSdkal1N+uje/PnZHCXMXYSfSfhqiOoSdMi1s/x8nV
3jdjn2Pp+sNJm4Lavy36341zOs3V+ET7n64hZ/clfcESlEtCRGjz5KONHe7jr46s
8OjRg9NIagZLiLlt9a5/m/+wdsy5pp21kOseQnYP41bJNZEU76NnKXUEVW2joAb9
dgdA/Jz+mCPAWFqH88yLViqtj03TXIoEjZuHrFjF5vAFTvcrAFfJUxNdWETQlSlz
vRgP3bHlcvQWqQz5LfikOVnn3asCAwEAAaN1MHMwDAYDVR0TBAUwAwEB/zAdBgNV
HQ4EFgQUAuZz5jxA1FsCiWH+fzS9QET8N+MwRAYDVR0jBD0wO4AUAuZz5jxA1FsC
iWH+fzS9QET8N+OhGKQWMBQxEjAQBgNVBAMMCVRlc3QgUm9vdIIJAOyKc7oUs6k/
MA0GCSqGSIb3DQEBCwUAA4IBAQACT4HS03JcSb9bBAcw8WoWsPv6Fo0VqWiOM30m
0s7DJW1FTupKZT1JU3TGTcGkuswW6O1PE5RvFfuIY1+gG9JO+ldOM9r8D2lTv6Ge
y0W+xL/ypgiYC233M2Ts3jfywc384qgDHRuI7kxF5CXxuqcIxx9nwn5VReRIVYvq
kaFj9o/6z8JRuTjU2gnHp9E+iiOHHHgp7oGWAqn+LLdDoUNJUd7dzw5U33Ls+ckH
5n93+b6q8pXAF59pMrPLtXAScpz6bW71Ntj7jOz25n96tx0By+j3Vc0nNN1hLwrQ
wd7qqwtxBhSlMYJ47TxS80I14M8Ds96Ne6wLWqVEUGGdtfcQ
-----END CERTIFICATE-----
`

const selfSignedRootKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs4fuVHcK/EDDuiFClanIxv2thRVcd57abLiTQBOguKRmMDeN
cebB9Za6zP3zfrO6n0GldGqP9qFo2olSWJJ2RqXU366N78+dkcJcxdhJ9J+GqI6h
J0yLWz/HydXeN2OfY+n6w0mbgtq/LfrfjXM6zdX4RPufriFn9yV9wRKUS0JEaPPk
o40d7uOvjqzw6NGD00hqBkuIuW31rn+b/7B2zLmmnbWQ6x5Cdg/jVsk1kRTvo2cp
dQRVbaOgBv12B0D8nP6YI8BYWofzzItWKq2PTdNcigSNm4esWMXm8AVO9ysAV8lT
E11YRNCVKXO9GA/dseVy9BapDPkt+KQ5WefdqwIDAQABAoIBAGsE/cp2CCNlDAf5
abLDuj7826I4oJ1iIXyr7oNE8AsBXTUi+HtMfpTCnGo0fCEsTHRA8rtaBqWThGi5
cVABRuZIVoRcjpnE3n4UKa96hmN/cQsrst81XuEvPQ6RId1M0qgBw40EZOJ1OX/U
S80LQqOPCGc+w+pOWaZXQAaG58WQIzpCuQIU2F4TIYEP5vr9gEv0kLSFtQN5I64b
lRjtH/M/6FmPW051OlbAOpsbLjviKaW17T34E3d/6H03M6m/oY/+hcE5j3fPZ7EU
m2RyqKGn5jAl2SySXpDWMwZ1OyQQ1oM9zvclBbyek/DnjpE8aYoN/mOnNYj3TJRh
aR9NrrECgYEA7aRGglIocOp2pqMPR4Hi7k0QkUm/CZ+wOBlUpzmMqjSF33GGzCPK
d9drkyEnsxKcy4hSwHHAo1CZSqqKM5EoCROiNUO/szw/9mVHl/fulj8XV94fNT5a
X4VSKWVZUo8foFbUWuk2tHudN3gdX/G0CH637Z1mX9fwK6fCoX3g8lMCgYEAwWZt
k8YHP74Y9vAngdEp3aRUUiquBh07m0o/VYsGcXmK3ITJHy7Rxx7glzG7vRHJqwXs
Yr+44J8rvWtkiu+k7mAY2QLoT0sSG+xgjX9DYr1iSomfz5IRZa34rB0FeWgTzFW4
7/r/Ko3Zdr24DqDiSsf2ld+vXgmaoRz2jW3hrEkCgYEAoq/t3VXlfbfl1pqW4TtY
Yg+8Idq8wBfkieM9guXxGKywYZHU2HhAKd7+NFFkXkGFugjvrfOyD5wj9WvfBQKA
yAX67EAfQtMibspTQwRm/9DdaDgWYVr4f6BD6TcK+WwmGJyY8EvsOY7OyKSgZ4iO
2an2vOMerMqmDxzgL7J/hyUCgYA0NAu76aYnRI7EiQqA9g6Q7zx7eV3D9LwULLRv
yLkShDZBU+5d5mtljiYdaaU9YcHH0i9+cDXdG9nYpVZcUld4qKPMYAaI8MCQnPtq
9kEgM/KGICPtCYZ8pbsL6kGCBd/iNflXfa7Gs8dRT+CQwkiS2urqhZh2j60XdBPx
FQnnUQKBgQC5/P8gy168r52nuE2+nL399EQW2INhFXDzrVjakOcUy/N7Cvbtt/7A
S8ob7kgyFaVd87pMNd9MV+yfZZnufJ+9kYG99LQ5SqAmKW7FG0w0YLZZKVZO4rws
ZeZVB2scDwCqpZpdhVim+QnfwrJiIqWuvP3U8BkZGdDdcvVNsrr8ew==
-----END RSA PRIVATE KEY-----
`

const selfSignedRootDSAPEM = `-----BEGIN CERTIFICATE-----
MIIC6TCCAqagAwIBAgIJAN46X/yW7bQQMAsGCWCGSAFlAwQDAjAYMRYwFAYDVQQD
DA1UZXN0IFJvb3QgRFNBMB4XDTE4MTEzMDE0NTAyNVoXDTI4MTEyNzE0NTAyNVow
GDEWMBQGA1UEAwwNVGVzdCBSb290IERTQTCCAbYwggErBgcqhkjOOAQBMIIBHgKB
gQCNB9oBw5/df6kKVsSWG5GqkvkSVPw2KAO2kRkv+bsofTPWNm1qMJsi5wjcHiuE
U+SrIKKWOB3AU2LL51hjBH+KvkUaPS9yYLti1iPyaZYN0Zou04EfNBrq7BZTj85y
udh6DKVBhcijv4tgvnyC5TCHFrYKLuuY86bHN7mgKveJgQIVAKGG+BMOfIWKJeVU
bRua3mPhtdWFAoGAALM5ItcMZGDiuxZ6FNzKm/hCqjjK/KFqq1Mv0H/N3MVhxrUv
8DlHempCsoAHG9sYY8XiPiLHeS2ODOoP3Wb5KR4kFc/xKHM5hON4fF5LIBaeHqCu
Hz6mRmCxIgYHtUKeHprsO5hPFA/DWgTz7ydFumm+9WvZ7CTAZ6voAIl45IUDgYQA
AoGAVFwcffsICW9Mr4aluuZ14TE/ZhwHbAGOwMJCUfcgOYpCbR6kIQ+XD9kRJHeR
DHdGpV6a5hK7a5eanSCSYVGs497/cs+hHc6bFyG6CmJLSPdUDPcHoJZgSCoVIUTj
7CNvSfEyOIrqezbqlbTvfqIidYG7WTQQdWq2RrpDharMnSKjeTB3MAwGA1UdEwQF
MAMBAf8wHQYDVR0OBBYEFBJuN5OifJedSiaKb8G7UmwocPLlMEgGA1UdIwRBMD+A
FBJuN5OifJedSiaKb8G7UmwocPLloRykGjAYMRYwFAYDVQQDDA1UZXN0IFJvb3Qg
RFNBggkA3jpf/JbttBAwCwYJYIZIAWUDBAMCAzAAMC0CFQCIqAOI+YAn18ZFvAwf
p59Rbi+13QIUdZL197wS8asZoPx5Y5HWnC4hZp8=
-----END CERTIFICATE-----
`

const selfSignedRootDSAKeyPEM = `-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCNB9oBw5/df6kKVsSWG5GqkvkSVPw2KAO2kRkv+bsofTPWNm1q
MJsi5wjcHiuEU+SrIKKWOB3AU2LL51hjBH+KvkUaPS9yYLti1iPyaZYN0Zou04Ef
NBrq7BZTj85yudh6DKVBhcijv4tgvnyC5TCHFrYKLuuY86bHN7mgKveJgQIVAKGG
+BMOfIWKJeVUbRua3mPhtdWFAoGAALM5ItcMZGDiuxZ6FNzKm/hCqjjK/KFqq1Mv
0H/N3MVhxrUv8DlHempCsoAHG9sYY8XiPiLHeS2ODOoP3Wb5KR4kFc/xKHM5hON4
fF5LIBaeHqCuHz6mRmCxIgYHtUKeHprsO5hPFA/DWgTz7ydFumm+9WvZ7CTAZ6vo
AIl45IUCgYBUXBx9+wgJb0yvhqW65nXhMT9mHAdsAY7AwkJR9yA5ikJtHqQhD5cP
2REkd5EMd0alXprmErtrl5qdIJJhUazj3v9yz6EdzpsXIboKYktI91QM9weglmBI
KhUhROPsI29J8TI4iup7NuqVtO9+oiJ1gbtZNBB1arZGukOFqsydIgIVAIGpdWlV
0AD+Uh8CMEMRxC6hhemW
-----END DSA PRIVATE KEY-----
`

const selfSignedRootECPEM = `-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIJANrfRnrX0NOyMAoGCCqGSM49BAMCMBcxFTATBgNVBAMM
DFRlc3QgUm9vdCBFQzAeFw0xODExMzAxNDU3NDVaFw0yODExMjcxNDU3NDVaMBcx
FTATBgNVBAMMDFRlc3QgUm9vdCBFQzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BCGWSdSJ4AJkO+SbEGIq2sqnz9TMGZ/RH6KxD6pz/wfiveq88f8D3ajKl5aAtcXe
fq/i8FJ0RHZBJDZWhuIIrPGjeDB2MAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFLlT
bjd0R6+fOLsUBLWUFxSpWPiHMEcGA1UdIwRAMD6AFLlTbjd0R6+fOLsUBLWUFxSp
WPiHoRukGTAXMRUwEwYDVQQDDAxUZXN0IFJvb3QgRUOCCQDa30Z619DTsjAKBggq
hkjOPQQDAgNIADBFAiB2EQNiZMVBDJ7Paxwq8KyKW3xlyTvYIz2ZtxDD43m0RAIh
AI7EY0ycY6IMZOwiOPnyBJkyUrnvIYBzUyD9TaQn5fVH
-----END CERTIFICATE-----
`

const selfSignedRootECKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG3ree24cLKZj/SOkKvbaWBFdiniINPulGdk0y9tb24PoAoGCCqGSM49
AwEHoUQDQgAEIZZJ1IngAmQ75JsQYirayqfP1MwZn9EforEPqnP/B+K96rzx/wPd
qMqXloC1xd5+r+LwUnREdkEkNlaG4gis8Q==
-----END EC PRIVATE KEY-----
`
