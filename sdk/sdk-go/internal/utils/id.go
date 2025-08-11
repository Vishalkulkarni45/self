package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// FormatRevealedDataPacked extracts and formats revealed data from public signals

func FormatRevealedDataPacked(attestationID AttestationId, publicSignals PublicSignals) (GenericDiscloseOutput, error) {

	revealedDataPacked, err := GetRevealedDataBytes(attestationID, publicSignals)

	if err != nil {
		return GenericDiscloseOutput{}, err
	}

	discloseIndices, exists := DiscloseIndices[attestationID]
	if !exists {
		return GenericDiscloseOutput{}, fmt.Errorf("disclose indices not found for attestation ID: %d", attestationID)
	}

	// Convert revealedDataPacked ([]int) to byte array for string operations
	revealedDataPackedBytes := make([]byte, len(revealedDataPacked))
	for i, b := range revealedDataPacked {
		revealedDataPackedBytes[i] = byte(b)
	}

	// Get revealed data indices for this attestation ID
	revealedDataIndices, exists := RevealedDataIndices[attestationID]
	if !exists {
		return GenericDiscloseOutput{}, fmt.Errorf("revealed data indices not found for attestation ID: %d", attestationID)
	}

	// Extract nullifier
	nullifier := publicSignals[discloseIndices.NullifierIndex]

	// Extract forbidden countries list packed
	startIndex := discloseIndices.ForbiddenCountriesListPackedIndex
	forbiddenCountriesListPacked := publicSignals[startIndex : startIndex+3]

	// Extract issuing state
	issuingState := string(revealedDataPackedBytes[revealedDataIndices.IssuingStateStart : revealedDataIndices.IssuingStateEnd+1])

	// Extract name with cleaning (equivalent to regex replacements and trim)
	nameRaw := string(revealedDataPackedBytes[revealedDataIndices.NameStart : revealedDataIndices.NameEnd+1])
	name := cleanName(nameRaw)

	// Extract ID number
	idNumber := string(revealedDataPackedBytes[revealedDataIndices.IdNumberStart : revealedDataIndices.IdNumberEnd+1])

	// Extract nationality
	nationality := string(revealedDataPackedBytes[revealedDataIndices.NationalityStart : revealedDataIndices.NationalityEnd+1])

	// Extract date of birth
	dateOfBirth := string(revealedDataPackedBytes[revealedDataIndices.DateOfBirthStart : revealedDataIndices.DateOfBirthEnd+1])

	// Extract gender
	gender := string(revealedDataPackedBytes[revealedDataIndices.GenderStart : revealedDataIndices.GenderEnd+1])

	// Extract expiry date
	expiryDate := string(revealedDataPackedBytes[revealedDataIndices.ExpiryDateStart : revealedDataIndices.ExpiryDateEnd+1])

	// Extract minimum age (olderThan)
	minimumAge := string(revealedDataPackedBytes[revealedDataIndices.OlderThanStart : revealedDataIndices.OlderThanEnd+1])

	// Extract OFAC data and convert to boolean array
	ofacBytes := revealedDataPackedBytes[revealedDataIndices.OfacStart : revealedDataIndices.OfacEnd+1]
	ofac := make([]bool, len(ofacBytes))
	for i, b := range ofacBytes {
		ofac[i] = b != 0 // Convert byte to boolean (non-zero = true)
	}

	// Return the structured output
	return GenericDiscloseOutput{
		Nullifier:                    nullifier,
		ForbiddenCountriesListPacked: forbiddenCountriesListPacked,
		IssuingState:                 issuingState,
		Name:                         name,
		IdNumber:                     idNumber,
		Nationality:                  nationality,
		DateOfBirth:                  dateOfBirth,
		Gender:                       gender,
		ExpiryDate:                   expiryDate,
		MinimumAge:                   minimumAge,
		Ofac:                         ofac,
	}, nil
}

// cleanName cleans the name string equivalent to the TypeScript regex operations
// .replace(/([A-Z])<+([A-Z])/g, '$1 $2').replace(/</g, ”).trim()
func cleanName(nameRaw string) string {
	// Replace pattern ([A-Z])<+([A-Z]) with '$1 $2'
	re1 := regexp.MustCompile(`([A-Z])<+([A-Z])`)
	name := re1.ReplaceAllString(nameRaw, "$1 $2")

	// Replace all remaining '<' characters
	name = strings.ReplaceAll(name, "<", "")

	// Trim whitespace
	name = strings.TrimSpace(name)

	return name
}
