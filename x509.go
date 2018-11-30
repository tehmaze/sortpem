package main

// CRLReasonCode identifies the reason for a certificate revocation.
type CRLReasonCode int

func (code CRLReasonCode) String() string {
	switch code {
	case CRLReasonUnspecified:
		return "Unspecified"
	case CRLReasonKeyCompromise:
		return "Key compromise"
	case CRLReasonCACompromise:
		return "CA compromise"
	case CRLReasonAffiliationChanged:
		return "Affiliation changed"
	case CRLReasonSuperseded:
		return "Superseded"
	case CRLReasonCessationOfOperation:
		return "Cessation of operation"
	case CRLReasonCertificateHold:
		return "Certificate hold"
	case CRLReasonRemoveFromCRL:
		return "Remove from CRL"
	case CRLReasonPrivilegeWithdrawn:
		return "Privilege withdrawn"
	case CRLReasonAACompromise:
		return "AA compromise"
	default:
		return "Invalid"
	}
}

// CRL reason codes as defined in RFC 5280.
const (
	CRLReasonUnspecified CRLReasonCode = iota
	CRLReasonKeyCompromise
	CRLReasonCACompromise
	CRLReasonAffiliationChanged
	CRLReasonSuperseded
	CRLReasonCessationOfOperation
	CRLReasonCertificateHold
	_
	CRLReasonRemoveFromCRL
	CRLReasonPrivilegeWithdrawn
	CRLReasonAACompromise
)
