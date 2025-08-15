package utils

import (
	"fmt"
	"math/big"
	"self-sdk-go/common"
	"self-sdk-go/internal/types"
	"strings"
)

// trimU0000 filters out null characters (\u0000) from a slice of strings
func trimU0000(unpackedReveal []string) []string {
	var result []string
	for _, value := range unpackedReveal {
		if value != "\u0000" {
			result = append(result, value)
		}
	}
	return result
}

// UnpackForbiddenCountriesList unpacks a list of packed forbidden country codes into an array of 3-character country codes.
//
// Parameters:
//   - forbiddenCountriesListPacked: A slice of packed strings representing forbidden countries
//
// Returns:
//   - A slice of 3-character country codes extracted from the packed input
func UnpackForbiddenCountriesList(forbiddenCountriesListPacked []string) []string {
	// Unpack the revealed data using the unpackReveal function
	unpacked := common.UnpackReveal(forbiddenCountriesListPacked, "id")
	trimmed := trimU0000(unpacked)

	var countries []string

	// Join all trimmed strings to work with characters
	joined := strings.Join(trimmed, "")

	// Extract 3-character country codes
	for i := 0; i < len(joined); i += 3 {
		if i+3 <= len(joined) {
			countryCode := joined[i : i+3]
			if len(countryCode) == 3 {
				countries = append(countries, countryCode)
			}
		}
	}

	return countries
}

// castToUserIdentifier converts a big integer to user identifier string based on the specified type
func CastToUserIdentifier(bigInt *big.Int, userIdType types.UserIDType) string {
	switch userIdType {
	case types.UserIDTypeHex:
		return CastToAddress(bigInt)
	case types.UserIDTypeUUID:
		return CastToUUID(bigInt)
	default:
		return bigInt.String()
	}
}

// castToAddress converts big integer to hex address format (0x + 40 hex chars)
func CastToAddress(bigInt *big.Int) string {
	hexStr := bigInt.Text(16) // Convert to hex without 0x prefix
	// Pad to 40 characters (20 bytes = 40 hex chars)
	if len(hexStr) < 40 {
		hexStr = fmt.Sprintf("%040s", hexStr)
	}
	return "0x" + hexStr
}

// castToUUID converts big integer to UUID format
func CastToUUID(bigInt *big.Int) string {
	hexStr := bigInt.Text(16) // Convert to hex without 0x prefix
	// Pad to 32 characters
	if len(hexStr) < 32 {
		hexStr = fmt.Sprintf("%032s", hexStr)
	}
	// Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}
