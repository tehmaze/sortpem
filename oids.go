//go:generate go run oids_gen.go -o oids.go

package main

import (
	"encoding/asn1"
	"fmt"
)

// Object identifiers
var (
	oidRSA                                          = asn1.ObjectIdentifier{1, 2, 840, 113549}                // 1.2.840.113549
	oidPKCS                                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1}             // 1.2.840.113549.1
	oidPKCS1                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1}          // 1.2.840.113549.1.1
	oidPKCS3                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3}          // 1.2.840.113549.1.3
	oidPKCS5                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}          // 1.2.840.113549.1.5
	oidPKCS7                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7}          // 1.2.840.113549.1.7
	oidPKCS9                                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9}          // 1.2.840.113549.1.9
	oidPKCS9EmailAddress                            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}       // 1.2.840.113549.1.9.1
	oidPKCS9UnstructuredName                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}       // 1.2.840.113549.1.9.2
	oidPKCS9ContentType                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}       // 1.2.840.113549.1.9.3
	oidPKCS9MessageDigest                           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}       // 1.2.840.113549.1.9.4
	oidPKCS9SigningTime                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}       // 1.2.840.113549.1.9.5
	oidPKCS9CounterSignature                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}       // 1.2.840.113549.1.9.6
	oidPKCS9ChallengePassword                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}       // 1.2.840.113549.1.9.7
	oidPKCS9UnstructuredAddress                     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 8}       // 1.2.840.113549.1.9.8
	oidPKCS9SigningDescription                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 13}      // 1.2.840.113549.1.9.13
	oidPKCS9ExtensionRequest                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}      // 1.2.840.113549.1.9.14
	oidPKCS9SMIMECapabilities                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 15}      // 1.2.840.113549.1.9.15
	oidPKCS9SMIMEOIDRegistry                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16}      // 1.2.840.113549.1.9.16
	oidPKCS9FriendyName                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}      // 1.2.840.113549.1.9.20
	oidPKCS9LocalKeyID                              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}      // 1.2.840.113549.1.9.21
	oidPKCS9CertificateTypes                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22}      // 1.2.840.113549.1.9.22
	oidPKCS9CRLTypes                                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 23}      // 1.2.840.113549.1.9.23
	oidPKCS10                                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 10}         // 1.2.840.113549.1.10
	oidPKCS11                                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 11}         // 1.2.840.113549.1.11
	oidPKCS12                                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12}         // 1.2.840.113549.1.12
	oidPrivateEnterprise                            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1}                 // 1.3.6.1.4.1
	oidMicrosoft                                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311}            // 1.3.6.1.4.1.311
	oidSoftwarePublishing                           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2}      // 1.3.6.1.4.1.311.2.2
	oidGoogle                                       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129}          // 1.3.6.1.4.1.11129
	oidCertificateTransparency                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4}    // 1.3.6.1.4.1.11129.2.4
	oidCertificateTransparencyEnabled               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2} // 1.3.6.1.4.1.11129.2.4.2
	oidCertificateTransparencyPrecertificatePoison  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3} // 1.3.6.1.4.1.11129.2.4.3
	oidCertificateTransparencyPrecertificateSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4} // 1.3.6.1.4.1.11129.2.4.4
	oidGoogleCertificatePolicyCompliant             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 5, 3} // 1.3.6.1.4.1.11129.2.5.3
	oidISGR                                         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947}          // 1.3.6.1.4.1.44947
	oidPKIX                                         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5}                 // 1.3.6.1.5.5
	oidAuthorityInformationAccess                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}        // 1.3.6.1.5.5.7.1.1
	oidAuthorityInformationAccessOCSP               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}       // 1.3.6.1.5.5.7.48.1
	oidAuthorityInformationAccessIssuers            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}       // 1.3.6.1.5.5.7.48.2
	oidCertificateExtension                         = asn1.ObjectIdentifier{2, 5, 29}                         // 2.5.29
	oidSubjectKeyIdentifier                         = asn1.ObjectIdentifier{2, 5, 29, 14}                     // 2.5.29.14
	oidKeyUsage                                     = asn1.ObjectIdentifier{2, 5, 29, 15}                     // 2.5.29.15
	oidSubjectAlternateName                         = asn1.ObjectIdentifier{2, 5, 29, 17}                     // 2.5.29.17
	oidBasicConstraints                             = asn1.ObjectIdentifier{2, 5, 29, 19}                     // 2.5.29.19
	oidNameConstraints                              = asn1.ObjectIdentifier{2, 5, 29, 30}                     // 2.5.29.30
	oidCRLDistributionPoints                        = asn1.ObjectIdentifier{2, 5, 29, 31}                     // 2.5.29.31
	oidCertificatePolicies                          = asn1.ObjectIdentifier{2, 5, 29, 32}                     // 2.5.29.32
	oidAnyPolicy                                    = asn1.ObjectIdentifier{2, 5, 29, 32, 0}                  // 2.5.29.32.0
	oidAuthorityKeyIdentifier                       = asn1.ObjectIdentifier{2, 5, 29, 35}                     // 2.5.29.35
	oidExtendedKeyUsage                             = asn1.ObjectIdentifier{2, 5, 29, 37}                     // 2.5.29.37
	oidCAbrowserForum                               = asn1.ObjectIdentifier{2, 23, 140}                       // 2.23.140
	oidCABExtendedValidation                        = asn1.ObjectIdentifier{2, 23, 140, 1, 1}                 // 2.23.140.1.1
	oidCABBaselineRequirements                      = asn1.ObjectIdentifier{2, 23, 140, 1, 2}                 // 2.23.140.1.2
	oidDomainValidated                              = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}              // 2.23.140.1.2.1
	oidOrganizationValidated                        = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}              // 2.23.140.1.2.2
	oidIndividualValidated                          = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3}              // 2.23.140.1.2.3
	oidCABExtendedValidationCodeSigning             = asn1.ObjectIdentifier{2, 23, 140, 1, 3}                 // 2.23.140.1.3
	oidCABExtendedValidationTOR                     = asn1.ObjectIdentifier{2, 23, 140, 1, 31}                // 2.23.140.1.31
	oidCABTestCertificate                           = asn1.ObjectIdentifier{2, 23, 140, 2, 1}                 // 2.23.140.2.1

	oidBases = []asn1.ObjectIdentifier{
		oidCABTestCertificate,
		oidCABExtendedValidationTOR,
		oidCABExtendedValidationCodeSigning,
		oidCABBaselineRequirements,
		oidCAbrowserForum,
		oidCertificateExtension,
		oidPKIX,
		oidISGR,
		oidCertificateTransparency,
		oidGoogle,
		oidMicrosoft,
		oidPrivateEnterprise,
		oidPKCS12,
		oidPKCS11,
		oidPKCS9,
		oidPKCS7,
		oidPKCS5,
		oidPKCS3,
		oidPKCS1,
		oidRSA,
	}

	oidNames = map[string]string{
		"1.2.840.113549":          "RSA",
		"1.2.840.113549.1":        "PKCS",
		"1.2.840.113549.1.1":      "PKCS#1",
		"1.2.840.113549.1.3":      "PKCS#3",
		"1.2.840.113549.1.5":      "PKCS#5",
		"1.2.840.113549.1.7":      "PKCS#7",
		"1.2.840.113549.1.9":      "PKCS#9",
		"1.2.840.113549.1.9.1":    "PKCS#9 Email Address",
		"1.2.840.113549.1.9.2":    "PKCS#9 Unstructured Name",
		"1.2.840.113549.1.9.3":    "PKCS#9 Content Type",
		"1.2.840.113549.1.9.4":    "PKCS#9 Message Digest",
		"1.2.840.113549.1.9.5":    "PKCS#9 Signing Time",
		"1.2.840.113549.1.9.6":    "PKCS#9 Counter Signature",
		"1.2.840.113549.1.9.7":    "PKCS#9 Challenge Password",
		"1.2.840.113549.1.9.8":    "PKCS#9 Unstructured Address",
		"1.2.840.113549.1.9.13":   "PKCS#9 Signing Description",
		"1.2.840.113549.1.9.14":   "PKCS#9 Extension Request",
		"1.2.840.113549.1.9.15":   "PKCS#9 SMIME Capabilities",
		"1.2.840.113549.1.9.16":   "PKCS#9 SMIME OID Registry",
		"1.2.840.113549.1.9.20":   "PKCS#9 Friendy Name",
		"1.2.840.113549.1.9.21":   "PKCS#9 Local Key ID",
		"1.2.840.113549.1.9.22":   "PKCS#9 Certificate Types",
		"1.2.840.113549.1.9.23":   "PKCS#9 CRL Types",
		"1.2.840.113549.1.10":     "PKCS#10",
		"1.2.840.113549.1.11":     "PKCS#11",
		"1.2.840.113549.1.12":     "PKCS#12",
		"1.3.6.1.4.1":             "Private Enterprise",
		"1.3.6.1.4.1.311":         "Microsoft",
		"1.3.6.1.4.1.311.2.2":     "Software Publishing",
		"1.3.6.1.4.1.11129":       "Google",
		"1.3.6.1.4.1.11129.2.4":   "Certificate Transparency",
		"1.3.6.1.4.1.11129.2.4.2": "Certificate Transparency Enabled",
		"1.3.6.1.4.1.11129.2.4.3": "Certificate Transparency Precertificate Poison",
		"1.3.6.1.4.1.11129.2.4.4": "Certificate Transparency Precertificate Signing",
		"1.3.6.1.4.1.11129.2.5.3": "Google Certificate Policy Compliant",
		"1.3.6.1.4.1.44947":       "ISGR",
		"1.3.6.1.5.5":             "PKIX",
		"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
		"1.3.6.1.5.5.7.48.1":      "Authority Information Access OCSP",
		"1.3.6.1.5.5.7.48.2":      "Authority Information Access Issuers",
		"2.5.29":                  "Certificate Extension",
		"2.5.29.14":               "Subject Key Identifier",
		"2.5.29.15":               "Key Usage",
		"2.5.29.17":               "Subject Alternate Name",
		"2.5.29.19":               "Basic Constraints",
		"2.5.29.30":               "Name Constraints",
		"2.5.29.31":               "CRL Distribution Points",
		"2.5.29.32":               "Certificate Policies",
		"2.5.29.32.0":             "Any Policy",
		"2.5.29.35":               "Authority Key Identifier",
		"2.5.29.37":               "Extended Key Usage",
		"2.23.140":                "CA/Browser Forum",
		"2.23.140.1.1":            "CAB Extended Validation",
		"2.23.140.1.2":            "CAB Baseline Requirements",
		"2.23.140.1.2.1":          "Domain Validated",
		"2.23.140.1.2.2":          "Organization Validated",
		"2.23.140.1.2.3":          "Individual Validated",
		"2.23.140.1.3":            "CAB Extended Validation Code Signing",
		"2.23.140.1.31":           "CAB Extended Validation TOR",
		"2.23.140.2.1":            "CAB Test Certificate",
	}
)

func oidName(oid asn1.ObjectIdentifier) string {
	if s, ok := oidNames[oid.String()]; ok {
		return s
	}

	l := len(oid)
	for _, base := range oidBases {
		if n := len(base); l > n && oid[:n].Equal(base) {
			return fmt.Sprintf("id-%s-%s", oidNames[base.String()], oid[n:])
		}
	}

	return ""
}
