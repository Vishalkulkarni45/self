package utils

import (
	"self-sdk-go/common"
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
