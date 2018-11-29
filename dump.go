package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

const timeFormat = "Jan _2 15:04:05 2006 MST"

type indentWriter struct {
	io.Writer
	indent int
}

func (w indentWriter) Write(p []byte) (int, error) {
	return w.Writer.Write(append(bytes.Repeat([]byte{0x20}, w.indent), p...))
}

// dumpText decodes and dumps the contents of a PEM block; only errors
// encountered during writing shall be reported
func dumpText(w io.Writer, block *pem.Block) (err error) {
	switch block.Type {
	case certificate:
		return dumpCertificateData(w, block.Bytes)
	case certificateRequest:
		return dumpCertificateRequestData(w, block.Bytes)
	case publicKey:
		return dumpPublicKeyData(w, block.Bytes)
	case privateKey:
		return dumpPrivateKeyData(w, block.Bytes)
	case ecPrivateKey:
		return dumpECDSAPrivateKeyData(w, block.Bytes)
	case rsaPrivateKey:
		return dumpRSAPrivateKeyData(w, block.Bytes)
	default:
		fmt.Fprintf(w, "%s:\n", strings.Title(strings.ToLower(block.Type)))
		return dumpBytes(indentWriter{w, 2}, block.Bytes)
	}
}

func dumpBytes(w io.Writer, data []byte) (err error) {
	if len(data) == 0 {
		_, err = fmt.Fprintln(w, "(empty)")
		return
	}
	var (
		//rightChars [18]byte
		buf  [14]byte
		line = new(bytes.Buffer)
		used int  // number of bytes in the current line
		l    int  // number of chars in the current byte
		n    uint // number of bytes, total
	)
	for i := range data {
		if used == 0 {
			// At the beginning of a line we print the current
			// offset in hex.
			buf[1] = byte(n >> 16)
			buf[2] = byte(n >> 8)
			buf[3] = byte(n)
			hex.Encode(buf[4:], buf[:4])
			buf[12] = ' '
			buf[13] = ' '
			if len(data) <= 0xfff {
				buf[6] = '0'
				buf[7] = 'x'
				line.Write(buf[6:])
			} else {
				buf[4] = '0'
				buf[5] = 'x'
				line.Write(buf[4:])
			}
		}
		hex.Encode(buf[:], data[i:i+1])
		buf[2] = ' '
		l = 3
		if used == 7 {
			// There's an additional space after the 8th byte.
			buf[3] = ' '
			l = 4
		} else if used == 15 {
			l = 3
		}
		line.Write(buf[:l])
		n++
		used++
		n++
		if used == 16 {
			line.WriteByte('\n')
			if _, err = w.Write(line.Bytes()); err != nil {
				return
			}
			line.Reset()
			used = 0
		}
	}
	return
}

func dumpCertificate(w io.Writer, c *x509.Certificate) (err error) {
	fmt.Fprintln(w, "Certificate:")
	fmt.Fprintf(w, "  Version:    %d (%#x)\n", c.Version, c.Version-1)
	fmt.Fprintf(w, "  Serial:     %d (%#x)\n", c.SerialNumber, c.SerialNumber)
	fmt.Fprintf(w, "  Issuer:     %s\n", c.Issuer)
	fmt.Fprintf(w, "  Not before: %s\n", c.NotBefore.Format(timeFormat))
	fmt.Fprintf(w, "  Not after:  %s\n", c.NotAfter.Format(timeFormat))
	fmt.Fprintf(w, "  Subject:    %s\n", c.Subject)
	fmt.Fprintln(w, "  Public key:")
	switch key := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if err = dumpECDSAPublicKey(indentWriter{w, 4}, key); err != nil {
			return
		}
	case *rsa.PublicKey:
		if err = dumpRSAPublicKey(indentWriter{w, 4}, key); err != nil {
			return
		}
	default:
		i := indentWriter{w, 6}
		fmt.Fprintf(i, "Unsupported Public Key (%T):\n", key)
		i.indent += 2
		if err = dumpBytes(i, c.RawSubjectPublicKeyInfo); err != nil {
			return
		}
	}
	if err = dumpExtensions(indentWriter{w, 2}, c.Extensions, c); err != nil {
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

func dumpPrivateKeyData(w io.Writer, data []byte) (err error) {
	var k interface{}
	if k, err = x509.ParsePKCS8PrivateKey(data); err != nil {
		fmt.Fprintf(w, "Invalid PKCS#8 Private Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		return dumpECDSAPrivateKey(w, key)
	case *rsa.PrivateKey:
		return dumpRSAPrivateKey(w, key)
	default:
		fmt.Fprintf(w, "Unsupported Private Key (%T):", key)
		return dumpBytes(indentWriter{w, 2}, data)
	}
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

func dumpECDSAPrivateKeyData(w io.Writer, data []byte) (err error) {
	var k *ecdsa.PrivateKey
	if k, err = x509.ParseECPrivateKey(data); err != nil {
		fmt.Fprintf(w, "Invalid EC Private Key (%v):\n", err)
		return dumpBytes(indentWriter{w, 2}, data)
	}
	return dumpECDSAPrivateKey(w, k)
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
	return dumpBytes(indentWriter{w, 4}, key.N.Bytes())
}

func dumpRSAPrivateKey(w io.Writer, key *rsa.PrivateKey) (err error) {
	fmt.Fprintf(w, "RSA Private Key: (%d bit)\n", key.N.BitLen())
	fmt.Fprintf(w, "  Exponent: %d (%#x)\n", key.E, key.E)
	fmt.Fprintln(w, "  Modulus:")
	if err = dumpBytes(indentWriter{w, 4}, key.N.Bytes()); err != nil {
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
		case ext.Id.Equal(oidSubjectKeyIdentifier):
			fmt.Fprintf(w, "  %x\n", v.SubjectKeyId)

		case ext.Id.Equal(oidAuthorityKeyIdentifier):
			fmt.Fprintf(w, "  %x\n", v.AuthorityKeyId)

		case ext.Id.Equal(oidBasicConstraints):
			fmt.Fprintf(w, "  CA:%t\n", v.IsCA)
			if !v.MaxPathLenZero {
				fmt.Fprintf(w, "  Max Path Length: %d\n", v.MaxPathLen)
			}

		case ext.Id.Equal(oidSubjectAlternateName):
			fmt.Fprintln(w, "  Subject Alternative Name:")
			for _, name := range v.DNSNames {
				fmt.Fprintf(w, "    DNS Name: %s\n", name)
			}
			for _, name := range v.EmailAddresses {
				fmt.Fprintf(w, "    Email Address: %s\n", name)
			}
			for _, ip := range v.IPAddresses {
				fmt.Fprintf(w, "    IP Address: %s\n", ip)
			}
			for _, uri := range v.URIs {
				fmt.Fprintf(w, "    URI: %s\n", uri)
			}

		case ext.Id.Equal(oidCertificatePolicies):
			for _, id := range v.PolicyIdentifiers {
				if err = dumpOID(indentWriter{w, 2}, id); err != nil {
					return
				}
			}

		case ext.Id.Equal(oidNameConstraints):

		case ext.Id.Equal(oidCRLDistributionPoints):
			for _, uri := range v.CRLDistributionPoints {
				fmt.Fprintf(w, "  %s\n", uri)
			}

		case ext.Id.Equal(oidAuthorityInformationAccess):
			for _, uri := range v.OCSPServer {
				fmt.Fprintf(w, "  OCSP: %s\n", uri)
			}
			for _, uri := range v.IssuingCertificateURL {
				fmt.Fprintf(w, "  Issuing Certificate URL: %s\n", uri)
			}

		case ext.Id.Equal(oidAuthorityInformationAccessOCSP):
		case ext.Id.Equal(oidAuthorityInformationAccessIssuers):

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

		case ext.Id.Equal(oidExtendedKeyUsage):
			var usages []string
			for _, usage := range v.ExtKeyUsage {
				usages = append(usages, extKeyUsageNames[usage])
			}
			if len(usages) > 0 {
				fmt.Fprintf(w, "  %s\n", strings.Join(usages, ", "))
			}

		default:
			if err = dumpBytes(indentWriter{w, 2}, ext.Value); err != nil {
				return
			}
		}

	case *x509.CertificateRequest:
		switch {
		default:
			if err = dumpBytes(indentWriter{w, 2}, ext.Value); err != nil {
				return
			}
		}
	}
	return
}

func dumpOID(w io.Writer, oid asn1.ObjectIdentifier, extra ...string) (err error) {
	if s := oidName(oid); s != "" {
		_, err = fmt.Fprintf(w, "%s (%s) %s\n", s, oid, strings.Join(extra, " "))
		return
	}
	_, err = fmt.Fprintf(w, "%s %s\n", oid, strings.Join(extra, " "))
	return
}
