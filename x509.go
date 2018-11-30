package sortpem

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

// known PEM types
const (
	certificate   = "CERTIFICATE"
	privateKey    = "PRIVATE KEY"
	dsaPrivateKey = "DSA " + privateKey
	rsaPrivateKey = "RSA " + privateKey
	ecPrivateKey  = "EC " + privateKey
)

// KeyBelongsTo checks if the cert is signed by the key. The key can be any
// supported public or private key. See PrivateKeyBelongsTo for how private
// keys are handled.
func KeyBelongsTo(cert *x509.Certificate, key interface{}) (ok bool) {
	switch key := key.(type) {
	case *dsa.PublicKey:
		if pub, ok := cert.PublicKey.(*dsa.PublicKey); ok {
			return pub.P.Cmp(key.P) == 0 && pub.Q.Cmp(key.Q) == 0 && pub.G.Cmp(key.G) == 0
		}
		return false

	case *ecdsa.PublicKey:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return pub.X.Cmp(key.X) == 0 && pub.Y.Cmp(key.Y) == 0
		}
		return false

	case ed25519.PublicKey:
		return KeyBelongsTo(cert, &key)

	case *ed25519.PublicKey:
		if pub, ok := cert.PublicKey.(*ed25519.PublicKey); ok {
			return bytes.Equal(*pub, *key)
		}
		return false

	case *rsa.PublicKey:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub.E == key.E && pub.N.Cmp(key.N) == 0
		}
		return false

	default:
		// Unsupported key, but maybe it's a private key
		return PrivateKeyBelongTo(cert, key)
	}
}

// PrivateKeyBelongTo is like KeyBelongsTo, but only for private keys. Note
// that we're just comparing public key parts of the passed key. There are no
// checks performed to see if the public key part of the private key is
// actually valid (since we should only be using this function for sorting).
func PrivateKeyBelongTo(cert *x509.Certificate, key interface{}) (ok bool) {
	switch key := key.(type) {
	case *dsa.PrivateKey:
		return KeyBelongsTo(cert, &key.PublicKey)

	case *ecdsa.PrivateKey:
		return KeyBelongsTo(cert, &key.PublicKey)

	case ed25519.PrivateKey:
		return PrivateKeyBelongTo(cert, &key)

	case *ed25519.PrivateKey:
		return KeyBelongsTo(cert, key.Public())

	case *rsa.PrivateKey:
		return KeyBelongsTo(cert, key.Public())

	default:
		// Unsupported key
		return
	}
}

// IsSelfSigned checks for a self-signed certificate.
func IsSelfSigned(cert *x509.Certificate) bool {
	return IsSignedBy(cert, cert)
}

// IsSignedBy does a check if cert is signed by root. Do not ever use this
// function for any other purpose than sorting, as it's skipping a lot of
// important steps from 5280 such as verifying basic constraints, validity or
// path depths (since we're only interested in sorting certificates).
func IsSignedBy(cert, root *x509.Certificate) (ok bool) {
	/*
		// Skipping this check, since the basic constraints may not even be
		// properly configured.
		if !root.IsCA {
			// Root can't sign.
			return
		}
	*/

	if !bytes.Equal(cert.RawIssuer, root.RawSubject) {
		// Subjects don't match
		return
	}

	if cert.AuthorityKeyId != nil && root.SubjectKeyId != nil && !bytes.Equal(cert.AuthorityKeyId, root.SubjectKeyId) {
		// Key id's don't match
		return
	}

	if root.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		// We can't verify the signature, since we don't support the signing
		// algorithm, so assume yes since all previous checks succeeded.
		return true
	}

	if err := root.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		// Signature verification failed.
		return
	}

	// All above checks passed, so it's not unlikely that cert is signed by root.
	return true
}

// parseDSAPrivateKey parses a DSA ASN.1 structure DER sequence
func parseDSAPrivateKey(asn1Bytes []byte) (key *dsa.PrivateKey, err error) {
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
