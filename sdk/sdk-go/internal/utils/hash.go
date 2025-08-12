package utils

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

// CalculateUserIdentifierHash generates a deterministic user identifier hash from the provided context data.
//
// The function computes a SHA-256 hash of the input buffer, then applies a RIPEMD-160 hash to the result.
// The final output is a hexadecimal string, left-padded with zeros to 40 characters and prefixed with "0x".
//
// Parameters:
//   - userContextData: The byte slice containing user context data to hash
//
// Returns:
//   - A 40-character hexadecimal user identifier string prefixed with "0x"
func CalculateUserIdentifierHash(userContextData []byte) string {
	// Compute SHA-256 hash
	sha256Hasher := sha256.New()
	sha256Hasher.Write(userContextData)
	sha256Hash := sha256Hasher.Sum(nil)

	// Compute RIPEMD-160 hash of the SHA-256 hash
	ripemdHasher := ripemd160.New()
	ripemdHasher.Write(sha256Hash)
	ripemdHash := ripemdHasher.Sum(nil)

	hexString := fmt.Sprintf("%x", ripemdHash)

	// Pad with leading zeros to ensure 40 hex chars
	if len(hexString) < 40 {
		hexString = fmt.Sprintf("%040s", hexString)
	}

	return "0x" + hexString
}
