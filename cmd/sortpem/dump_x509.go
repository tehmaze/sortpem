package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/ed25519"
)

func dumpCertificate(w io.Writer, c *x509.Certificate) (err error) {
	fmt.Fprintln(w, "Certificate:")
	fmt.Fprintf(w, "  Version:    %d (%#x)\n", c.Version, c.Version-1)
	fmt.Fprintf(w, "  Serial:     %d (%s)\n", c.SerialNumber, paddedBytes(c.SerialNumber.Bytes()))
	fmt.Fprintf(w, "  Subject:    %s\n", c.Subject)
	fmt.Fprintf(w, "  Issuer:     %s\n", c.Issuer)
	fmt.Fprintf(w, "  Not before: %s\n", c.NotBefore.Format(timeFormat))
	fmt.Fprintf(w, "  Not after:  %s\n", c.NotAfter.Format(timeFormat))
	//fmt.Fprintln(w, "  Public key:")
	switch key := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if err = dumpECDSAPublicKey(indentWriter{w, 2}, key); err != nil {
			return
		}
	case *rsa.PublicKey:
		if err = dumpRSAPublicKey(indentWriter{w, 2}, key); err != nil {
			return
		}
	default:
		i := indentWriter{w, 2}
		fmt.Fprintf(i, "Unsupported Public Key (%T):\n", key)
		i.indent += 2
		if err = dumpBytes(i, c.RawSubjectPublicKeyInfo); err != nil {
			return
		}
	}
	if err = dumpExtensions(indentWriter{w, 2}, c.Extensions, c); err != nil {
		return
	}
	fmt.Fprintln(w, "  Signature:")
	fmt.Fprintf(w, "    Algorithm: %s\n", c.SignatureAlgorithm)
	if err = dumpPaddedBytesLimit(indentWriter{w, 6}, c.Signature, maxWidth); err != nil {
		return
	}
	return
}

func dumpCertificateData(w io.Writer, data []byte) (err error) {
	var c *x509.Certificate
	if c, err = decodeCertificate(data); err != nil {
		fmt.Fprintf(w, "Invalid Certificate (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpCertificate(w, c)
}

func dumpCertificateRequest(w io.Writer, r *x509.CertificateRequest) (err error) {
	fmt.Fprintln(w, "Certificate Request:")
	fmt.Fprintf(w, "  Version:    %d (%#x)\n", r.Version, r.Version)
	fmt.Fprintf(w, "  Subject:    %s\n", r.Subject)
	fmt.Fprintln(w, "  Public key:")
	i := indentWriter{w, 4}
	switch key := r.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if err = dumpECDSAPublicKey(i, key); err != nil {
			return
		}
	case *rsa.PublicKey:
		if err = dumpRSAPublicKey(i, key); err != nil {
			return
		}
	default:
		fmt.Fprintf(i, "Unsupported Public Key (%T):\n", key)
		i.indent += 2
		if err = dumpBytes(i, r.RawSubjectPublicKeyInfo); err != nil {
			return
		}
		i.indent -= 2
	}
	if len(r.Attributes) > 0 {
		fmt.Fprintln(w, "    Attributes:")
		for _, attr := range r.Attributes {
			if err = dumpOID(i, attr.Type); err != nil {
				return
			}
		}
	}
	if err = dumpExtensions(i, r.Extensions, r); err != nil {
		return
	}
	return
}

func dumpCertificateRequestData(w io.Writer, data []byte) (err error) {
	var r *x509.CertificateRequest
	if r, err = x509.ParseCertificateRequest(data); err != nil {
		fmt.Fprintf(w, "Invalid Certificate Request (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpCertificateRequest(w, r)
}

func dumpCertificateRevocationList(w io.Writer, list *pkix.CertificateList) (err error) {
	fmt.Fprintln(w, "Certificate Revocation List:")
	fmt.Fprintf(w, "  Version:     %d (%#x)\n", list.TBSCertList.Version, list.TBSCertList.Version-1)
	fmt.Fprintf(w, "  Issuer:      %s\n", list.TBSCertList.Issuer)
	fmt.Fprintf(w, "  Last update: %s\n", list.TBSCertList.ThisUpdate)
	fmt.Fprintf(w, "  Next update: %s\n", list.TBSCertList.NextUpdate)
	if err = dumpExtensions(indentWriter{w, 2}, list.TBSCertList.Extensions, list); err != nil {
		return
	}
	fmt.Fprintf(w, "  Revoked Certificates (%d):\n", len(list.TBSCertList.RevokedCertificates))
	for _, revoked := range list.TBSCertList.RevokedCertificates {
		fmt.Fprintf(w, "    Serial: %d (%s)\n", revoked.SerialNumber, paddedBytes(revoked.SerialNumber.Bytes()))
		fmt.Fprintf(w, "      Revoked: %s\n", revoked.RevocationTime)
		dumpExtensions(indentWriter{w, 6}, revoked.Extensions, revoked)
	}
	return
}

func dumpCertificateRevocationListData(w io.Writer, data []byte) (err error) {
	var list *pkix.CertificateList
	if list, err = x509.ParseDERCRL(data); err != nil {
		return
	}
	return dumpCertificateRevocationList(w, list)
}

/*
DHParameter ::= SEQUENCE {
 prime INTEGER, -- p
 base INTEGER, -- g
 privateValueLength INTEGER OPTIONAL }
*/
type dhParameter struct {
	Prime *big.Int
	Base  int
}

func dumpDHParameters(w io.Writer, p *dhParameter) (err error) {
	fmt.Fprintln(w, "Diffie-Hellman Parameters:")
	fmt.Fprintln(w, "  Prime:")
	if err = dumpBytes(indentWriter{w, 4}, p.Prime.Bytes()); err != nil {
		return
	}
	fmt.Fprintf(w, "  Base: %d (%#x)\n", p.Base, p.Base)
	return
}

func dumpDHParametersData(w io.Writer, data []byte) (err error) {
	var param dhParameter
	if _, err = asn1.Unmarshal(data, &param); err != nil {
		return
	}
	return dumpDHParameters(w, &param)
}

func dumpPublicKeyData(w io.Writer, data []byte) (err error) {
	var k interface{}
	if k, err = x509.ParsePKIXPublicKey(data); err != nil {
		fmt.Fprintf(w, "Invalid PKIX Public Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	switch key := k.(type) {
	case *ecdsa.PublicKey:
		return dumpECDSAPublicKey(w, key)
	case *rsa.PublicKey:
		return dumpRSAPublicKey(w, key)
	default:
		fmt.Fprintf(w, "Unsupported Public Key (%T):\n", key)
		return dumpBytes(indentWriter{w, 2}, data)
	}
}

func dumpPrivateKey(w io.Writer, key interface{}, data []byte) (err error) {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return dumpECDSAPrivateKey(w, key)
	case *ed25519.PrivateKey:
		return dumpED25519PrivateKey(w, key)
	case *rsa.PrivateKey:
		return dumpRSAPrivateKey(w, key)
	default:
		fmt.Fprintf(w, "Unsupported Private Key (%T):", key)
		return dumpBytes(indentWriter{w, 2}, data)
	}
}

func dumpPrivateKeyData(w io.Writer, data []byte) (err error) {
	var key interface{}
	if key, err = x509.ParsePKCS8PrivateKey(data); err != nil {
		fmt.Fprintf(w, "Invalid PKCS#8 Private Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpPrivateKey(w, key, data)
}

func dumpEncryptedPrivateKeyData(w io.Writer, data []byte, headers map[string]string) (err error) {
	return dumpEncryptedData(w, "Private Key", data, headers)
}

func dumpECDSAPrivateKey(w io.Writer, key *ecdsa.PrivateKey) (err error) {
	p := key.Curve.Params()
	i := indentWriter{w, 4}
	fmt.Fprintf(w, "ECDSA Private Key: (%d bits, %s)\n", p.BitSize, p.Name)
	fmt.Fprintln(w, "  Private:")
	dumpBytes(i, key.D.Bytes())
	fmt.Fprintf(w, "  Public X:")
	dumpBytes(i, key.X.Bytes())
	fmt.Fprintln(w, "  Public Y:")
	dumpBytes(i, key.Y.Bytes())
	return
}

func dumpED25519PrivateKey(w io.Writer, key *ed25519.PrivateKey) (err error) {
	fmt.Fprintln(w, "ED25519 Private Key:")
	fmt.Fprintln(w, "  Point:")
	return dumpBytes(indentWriter{w, 4}, []byte(*key))
}

func dumpECDSAPrivateKeyData(w io.Writer, data []byte) (err error) {
	var k *ecdsa.PrivateKey
	if k, err = x509.ParseECPrivateKey(data); err != nil {
		fmt.Fprintf(w, "Invalid EC Private Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpECDSAPrivateKey(w, k)
}

func dumpEncryptedECDSAPrivateKeyData(w io.Writer, data []byte, headers map[string]string) (err error) {
	return dumpEncryptedData(w, "EC Private Key", data, headers)
}

func dumpECDSAPublicKey(w io.Writer, key *ecdsa.PublicKey) (err error) {
	p := key.Curve.Params()
	i := indentWriter{w, 4}
	fmt.Fprintf(w, "ECDSA Public Key: (%d bits, %s)\n", p.BitSize, p.Name)
	fmt.Fprintln(w, "  Public X:")
	dumpBytes(i, key.X.Bytes())
	fmt.Fprintln(w, "  Public Y:")
	dumpBytes(i, key.Y.Bytes())
	return
}

func dumpRSAPublicKey(w io.Writer, key *rsa.PublicKey) (err error) {
	fmt.Fprintf(w, "RSA Public Key: (%d bit)\n", key.N.BitLen())
	fmt.Fprintf(w, "  Exponent: %d (%#x)\n", key.E, key.E)
	fmt.Fprintln(w, "  Modulus:")
	return dumpPaddedBytesLimit(indentWriter{w, 4}, key.N.Bytes(), maxWidth)
}

func dumpRSAPrivateKey(w io.Writer, key *rsa.PrivateKey) (err error) {
	fmt.Fprintf(w, "RSA Private Key: (%d bit)\n", key.N.BitLen())
	fmt.Fprintf(w, "  Exponent: %d (%#x)\n", key.E, key.E)
	fmt.Fprintln(w, "  Modulus:")
	if err = dumpPaddedBytesLimit(indentWriter{w, 4}, key.N.Bytes(), maxWidth); err != nil {
		return
	}
	return
}

func dumpRSAPrivateKeyData(w io.Writer, data []byte) (err error) {
	var k *rsa.PrivateKey
	if k, err = x509.ParsePKCS1PrivateKey(data); err != nil {
		fmt.Fprintf(w, "Invalid PKCS#1 Private Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpRSAPrivateKey(w, k)
}

func dumpEncryptedRSAPrivateKeyData(w io.Writer, data []byte, headers map[string]string) (err error) {
	return dumpEncryptedData(w, "RSA Private Key", data, headers)
}

func dumpExtensions(w io.Writer, exts []pkix.Extension, v interface{}) (err error) {
	if len(exts) == 0 {
		return
	}
	fmt.Fprintf(w, "Extensions (%d):\n", len(exts))
	for _, ext := range exts {
		if err = dumpExtension(indentWriter{w, 2}, ext, v); err != nil {
			return
		}
	}
	return
}

var (
	keyUsages = []x509.KeyUsage{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageContentCommitment,
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
		x509.KeyUsageEncipherOnly,
		x509.KeyUsageDecipherOnly,
	}
	keyUsageNames = map[x509.KeyUsage]string{
		x509.KeyUsageCRLSign:           "CRL Signing",
		x509.KeyUsageCertSign:          "Certificate Signing",
		x509.KeyUsageContentCommitment: "Content Commitment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	}
	extKeyUsageNames = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
		x509.ExtKeyUsageTimeStamping:                   "Timestamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
	}
)

func dumpExtension(w io.Writer, ext pkix.Extension, v interface{}) (err error) {
	if ext.Critical {
		err = dumpOID(w, ext.Id, "Critical")
	} else {
		err = dumpOID(w, ext.Id)
	}
	if err != nil {
		return
	}
	switch v := v.(type) {
	case *x509.Certificate:
		switch {
		case ext.Id.Equal(oidBasicConstraints):
			fmt.Fprintf(w, "  CA:%t\n", v.IsCA)
			if !v.MaxPathLenZero {
				fmt.Fprintf(w, "  Max Path Length: %d\n", v.MaxPathLen)
			}
			return

		case ext.Id.Equal(oidSubjectAlternateName):
			i := indentWriter{w, 4}
			fmt.Fprintln(w, "  Subject Alternative Name:")
			if err = dumpStringsLimit(i, "DNS Name", v.DNSNames, maxWidth); err != nil {
				return
			}
			if err = dumpStringsLimit(i, "Email Address", v.EmailAddresses, maxWidth); err != nil {
				return
			}
			var s []string
			for _, ip := range v.IPAddresses {
				s = append(s, ip.String())
			}
			if err = dumpStringsLimit(i, "IP Address", s, maxWidth); err != nil {
				return
			}
			s = s[:0]
			for _, uri := range v.URIs {
				s = append(s, uri.String())
			}
			if err = dumpStringsLimit(i, "URI", s, maxWidth); err != nil {
				return
			}
			return

		case ext.Id.Equal(oidCertificatePolicies):
			for _, id := range v.PolicyIdentifiers {
				if err = dumpOID(indentWriter{w, 2}, id); err != nil {
					return
				}
			}
			return

		case ext.Id.Equal(oidCRLDistributionPoints):
			for _, uri := range v.CRLDistributionPoints {
				fmt.Fprintf(w, "  %s\n", uri)
			}
			return

		case ext.Id.Equal(oidAuthorityInformationAccess):
			for _, uri := range v.OCSPServer {
				fmt.Fprintf(w, "  OCSP: %s\n", uri)
			}
			for _, uri := range v.IssuingCertificateURL {
				fmt.Fprintf(w, "  Issuing Certificate URL: %s\n", uri)
			}
			return

		case ext.Id.Equal(oidKeyUsage):
			var usages []string
			for _, usage := range keyUsages {
				if v.KeyUsage&usage == usage {
					usages = append(usages, keyUsageNames[usage])
				}
			}
			if len(usages) > 0 {
				fmt.Fprintf(w, "  %s\n", strings.Join(usages, ", "))
			}
			return

		case ext.Id.Equal(oidExtendedKeyUsage):
			var usages []string
			for _, usage := range v.ExtKeyUsage {
				usages = append(usages, extKeyUsageNames[usage])
			}
			if len(usages) > 0 {
				fmt.Fprintf(w, "  %s\n", strings.Join(usages, ", "))
			}
			return
		}
	}

	switch {
	case ext.Id.Equal(oidAuthorityKeyIdentifier):
		var keyID struct {
			ID []byte `asn1:"optional,tag:0"`
		}
		if _, uerr := asn1.Unmarshal(ext.Value, &keyID); uerr != nil {
			fmt.Fprintf(w, "  (invalid) (%s)\n", uerr)
		} else {
			return dumpPaddedBytesLimit(indentWriter{w, 2}, keyID.ID, maxWidth)
		}
		return

	case ext.Id.Equal(oidSubjectKeyIdentifier):
		var keyID []byte
		if _, uerr := asn1.Unmarshal(ext.Value, &keyID); uerr != nil {
			fmt.Fprintf(w, "  (invalid) (%s)\n", uerr)
		} else {
			return dumpPaddedBytesLimit(indentWriter{w, 2}, keyID, maxWidth)
		}
		return

	case ext.Id.Equal(oidCRLNumber):
		var number int
		if _, uerr := asn1.Unmarshal(ext.Value, &number); uerr != nil {
			fmt.Fprintf(w, "  (invalid) (%s)\n", uerr)
		} else {
			fmt.Fprintf(w, "  %d\n", number)
		}
		return

	case ext.Id.Equal(oidRevocationReason):
		var reason asn1.Enumerated
		if _, uerr := asn1.Unmarshal(ext.Value, &reason); uerr != nil {
			fmt.Fprintf(w, "  (invalid) (%s)\n", uerr)
		} else {
			fmt.Fprintf(w, "  %v\n", CRLReasonCode(reason))
		}
		return
	}

	return dumpBytes(indentWriter{w, 2}, ext.Value)
}
