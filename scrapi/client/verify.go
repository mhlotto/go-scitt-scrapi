package client

import (
	"crypto"

	"github.com/mhlotto/go-scitt-scrapi/scrapi"
)

// Verify calls the shared scrapi verification helper to validate statement + receipt.
func Verify(statementRaw, receiptRaw []byte, issuerKey, tsKey crypto.PublicKey) error {
	return scrapi.VerifyStatementAndReceipt(statementRaw, receiptRaw, scrapi.VerificationInputs{
		IssuerKey: issuerKey,
		TSKey:     tsKey,
	})
}
