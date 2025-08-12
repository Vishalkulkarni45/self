package selfBackendVerifier

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	bindings "self-sdk-go/contracts/bindings"
	"self-sdk-go/internal/types"
	"self-sdk-go/internal/utils"
)

const (
	CELO_MAINNET_RPC_URL = "https://forno.celo.org"
	CELO_TESTNET_RPC_URL = "https://alfajores-forno.celo-testnet.org"

	IDENTITY_VERIFICATION_HUB_ADDRESS         = "0xe57F4773bd9c9d8b6Cd70431117d353298B9f5BF"
	IDENTITY_VERIFICATION_HUB_ADDRESS_STAGING = "0x68c931C9a534D37aa78094877F46fE46a49F1A51"
)

type ConfigMismatch string

const (
	InvalidId                     ConfigMismatch = "InvalidId"
	InvalidUserContextHash        ConfigMismatch = "InvalidUserContextHash"
	InvalidScope                  ConfigMismatch = "InvalidScope"
	InvalidRoot                   ConfigMismatch = "InvalidRoot"
	InvalidAttestationId          ConfigMismatch = "InvalidAttestationId"
	InvalidForbiddenCountriesList ConfigMismatch = "InvalidForbiddenCountriesList"
	InvalidMinimumAge             ConfigMismatch = "InvalidMinimumAge"
	InvalidTimestamp              ConfigMismatch = "InvalidTimestamp"
	InvalidOfac                   ConfigMismatch = "InvalidOfac"
	ConfigNotFound                ConfigMismatch = "ConfigNotFound"
)

// containsHexChars checks if a string contains hexadecimal characters (a-f)
func containsHexChars(s string) bool {
	for _, char := range s {
		if (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			return true
		}
	}
	return false
}

type ConfigIssue struct {
	Type    ConfigMismatch `json:"type"`
	Message string         `json:"message"`
}

type ConfigMismatchError struct {
	Issues []ConfigIssue `json:"issues"`
}

func (e *ConfigMismatchError) Error() string {
	var message []string
	for _, issue := range e.Issues {
		message = append(message, fmt.Sprintf("[%s]: %s", issue.Type, issue.Message))
	}
	return strings.Join(message, "\n")
}

func NewConfigMismatchError(issue []ConfigIssue) *ConfigMismatchError {
	return &ConfigMismatchError{Issues: issue}
}

type ConfigStore interface {
	GetConfig(ctx context.Context, id string) (types.VerificationConfig, error)
	SetConfig(ctx context.Context, id string, config types.VerificationConfig) (bool, error)
	GetActionId(ctx context.Context, userIdentifier string, actionId string) (string, error)
}

type SelfBackendVerifier struct {
	scope                           string
	identityVerificationHubContract *bindings.IdentityVerificationHubImpl
	configStorage                   ConfigStore
	provider                        *ethclient.Client
	allowedIDs                      map[types.AttestationId]bool
	userIdentifierType              types.UserIDType
}

// NewSelfBackendVerifier creates a new SelfBackendVerifier instance
func NewSelfBackendVerifier(
	scope string,
	endpoint string,
	mockPassport bool,
	allowedIds map[types.AttestationId]bool,
	configStorage ConfigStore,
	userIdentifierType types.UserIDType,
) (*SelfBackendVerifier, error) {
	rpcUrl := CELO_MAINNET_RPC_URL
	hubAddress := IDENTITY_VERIFICATION_HUB_ADDRESS

	if mockPassport {
		rpcUrl = CELO_TESTNET_RPC_URL
		hubAddress = IDENTITY_VERIFICATION_HUB_ADDRESS_STAGING
	}

	provider, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ethereum client: %v", err)
	}

	// Create the contract binding
	hubContract, err := bindings.NewIdentityVerificationHubImpl(
		common.HexToAddress(hubAddress),
		provider,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create hub contract binding: %v", err)
	}

	// TODO: Implement hashEndpointWithScope function similar to TypeScript version
	// For now, using a simple concatenation as placeholder
	hashedScope := fmt.Sprintf("%s-%s", endpoint, scope)

	return &SelfBackendVerifier{
		scope:                           hashedScope,
		identityVerificationHubContract: hubContract,
		configStorage:                   configStorage,
		provider:                        provider,
		allowedIDs:                      allowedIds,
		userIdentifierType:              userIdentifierType,
	}, nil
}

// Verify performs the verification of attestation with the given proof and signals
func (s *SelfBackendVerifier) Verify(
	ctx context.Context,
	attestationId types.AttestationId,
	proof types.VcAndDiscloseProof,
	pubSignals []*big.Int,
	userContextData string,
) (*types.VerificationResult, error) {
	// Check if attestation id is allowed
	allowedId, exists := s.allowedIDs[attestationId]
	var issues []ConfigIssue

	if !exists || !allowedId {
		issues = append(issues, ConfigIssue{
			Type:    InvalidId,
			Message: fmt.Sprintf("Attestation ID is not allowed, received: %d", attestationId),
		})
	}

	// Convert public signals to string format, adding 0x prefix for hex values
	publicSignals := make([]string, len(pubSignals))
	for i, signal := range pubSignals {
		signalStr := signal.String()
		// Check if string contains hex characters and has length > 0
		if len(signalStr) > 0 && containsHexChars(signalStr) {
			publicSignals[i] = "0x" + signalStr
		} else {
			publicSignals[i] = signalStr
		}
	}

	// Pre-calculate attestation ID in hex format (reused multiple times throughout function)
	attestationIdHex := fmt.Sprintf("%064x", attestationId)
	attestationIdBytes32 := [32]byte{}
	copy(attestationIdBytes32[:], common.FromHex("0x"+attestationIdHex))

	// Check if user context hash matches
	discloseIndices, exists := utils.DiscloseIndices[attestationId]
	if !exists {
		issues = append(issues, ConfigIssue{
			Type:    InvalidAttestationId,
			Message: fmt.Sprintf("Unknown attestation ID: %d", attestationId),
		})
	} else {

		// Get user context hash from circuit
		userContextHashInCircuit := new(big.Int)
		userContextHashInCircuit.SetString(publicSignals[discloseIndices.UserIdentifierIndex], 10)

		// Calculate expected user context hash
		userContextDataBytes, err := hex.DecodeString(userContextData)
		if err != nil {
			issues = append(issues, ConfigIssue{
				Type:    InvalidUserContextHash,
				Message: fmt.Sprintf("Invalid hex string in userContextData: %v", err),
			})
		} else {
			userContextHashStr := utils.CalculateUserIdentifierHash(userContextDataBytes)
			userContextHash := new(big.Int)
			userContextHash.SetString(userContextHashStr, 16)

			if userContextHashInCircuit.Cmp(userContextHash) != 0 {
				issues = append(issues, ConfigIssue{
					Type: InvalidUserContextHash,
					Message: fmt.Sprintf("User context hash does not match with the one in the circuit\nCircuit: %s\nUser context hash: %s",
						userContextHashInCircuit.String(), userContextHash.String()),
				})
			}
		}

		// Check if scope matches
		isValidScope := s.scope == publicSignals[discloseIndices.ScopeIndex]
		if !isValidScope {
			issues = append(issues, ConfigIssue{
				Type: InvalidScope,
				Message: fmt.Sprintf("Scope does not match with the one in the circuit\nCircuit: %s\nScope: %s",
					publicSignals[discloseIndices.ScopeIndex], s.scope),
			})
		}

		// Check the root (reusing pre-calculated attestationIdBytes32)

		registryAddress, err := s.identityVerificationHubContract.Registry(nil, attestationIdBytes32)
		if err != nil || registryAddress == (common.Address{}) {
			issues = append(issues, ConfigIssue{
				Type:    InvalidRoot,
				Message: "Registry contract not found",
			})
		} else {
			// Create Registry contract binding
			registryContract, err := bindings.NewRegistry(registryAddress, s.provider)
			if err != nil {
				issues = append(issues, ConfigIssue{
					Type:    InvalidRoot,
					Message: fmt.Sprintf("Failed to create registry contract binding: %v", err),
				})
			} else {
				// Convert merkle root to big.Int
				merkleRoot := new(big.Int)
				merkleRoot.SetString(publicSignals[discloseIndices.MerkleRootIndex], 10)

				currentRoot, err := registryContract.CheckIdentityCommitmentRoot(nil, merkleRoot)
				if err != nil || !currentRoot {
					issues = append(issues, ConfigIssue{
						Type:    InvalidRoot,
						Message: fmt.Sprintf("Onchain root does not exist, received: %s", publicSignals[discloseIndices.MerkleRootIndex]),
					})
				}
			}
		}

		// Check if attestation id matches
		attestationIdFromCircuit := publicSignals[discloseIndices.AttestationIdIndex]
		if fmt.Sprintf("%d", attestationId) != attestationIdFromCircuit {
			issues = append(issues, ConfigIssue{
				Type:    InvalidAttestationId,
				Message: "Attestation ID does not match with the one in the circuit",
			})
		}
	}

	// Extract user identifier and user defined data from userContextData (declare at function scope for reuse)
	// userContextData format: configId(32 bytes) + userIdentifier(32 bytes) + userDefinedData(rest)
	var userIdentifier, userDefinedData string
	var verificationConfig types.VerificationConfig
	var configErr error
	var forbiddenCountriesList []string
	var genericDiscloseOutput types.GenericDiscloseOutput

	if len(userContextData) < 128 {
		issues = append(issues, ConfigIssue{
			Type:    ConfigNotFound,
			Message: "userContextData too short",
		})
	} else {
		// Extract userIdentifier from bytes 64-128 (32-64 in hex string = 64-128 chars)
		userIdentifierHex := userContextData[64:128]
		userIdentifierBigInt := new(big.Int)
		userIdentifierBigInt.SetString(userIdentifierHex, 16)

		userIdentifier = s.castToUserIdentifier(userIdentifierBigInt, s.userIdentifierType)
		userDefinedData = userContextData[128:]

		// Get config ID from storage
		configId, err := s.configStorage.GetActionId(ctx, userIdentifier, userDefinedData)
		if err != nil || configId == "" {
			issues = append(issues, ConfigIssue{
				Type:    ConfigNotFound,
				Message: "Config Id not found",
			})
		} else {
			// Get verification config
			verificationConfig, configErr = s.configStorage.GetConfig(ctx, configId)

			// Check for GetConfig error first
			if configErr != nil {
				issues = append(issues, ConfigIssue{
					Type:    ConfigNotFound,
					Message: fmt.Sprintf("Config not found for %s", configId),
				})
			}

			// Check if returned config is empty/invalid (like TypeScript's finally block)
			if s.isEmptyVerificationConfig(verificationConfig) {
				issues = append(issues, ConfigIssue{
					Type:    ConfigNotFound,
					Message: fmt.Sprintf("Config not found for %s", configId),
				})
			}

			// Only proceed with validations if no error and config is not empty
			if configErr == nil && !s.isEmptyVerificationConfig(verificationConfig) {
				forbiddenCountriesList, genericDiscloseOutput, _ = s.validateWithConfig(verificationConfig, publicSignals, discloseIndices, attestationId, &issues)
			}
		}
	}

	// If there are validation issues, return them
	if len(issues) > 0 {
		return nil, NewConfigMismatchError(issues)
	}

	// Block 13: Proof verification using Verifier contract
	isProofValid := false

	// Use the pre-calculated attestationIdBytes32 from above
	verifierAddress, err := s.identityVerificationHubContract.DiscloseVerifier(nil, attestationIdBytes32)
	if err != nil || verifierAddress == (common.Address{}) {
		// Verifier contract not found - this should probably be an error, but TypeScript version returns false
		isProofValid = false
	} else {
		// Create Verifier contract binding
		verifierContract, err := bindings.NewVerifier(verifierAddress, s.provider)
		if err != nil {
			isProofValid = false
		} else {
			// Verify the proof
			// Convert proof format: TypeScript swaps B coordinates like [proof.b[0][1], proof.b[0][0]]
			bFormatted := [2][2]*big.Int{
				{proof.B[0][1], proof.B[0][0]}, // Swap first pair
				{proof.B[1][1], proof.B[1][0]}, // Swap second pair
			}

			// Use publicSignals (processed strings) like TypeScript version
			// Convert the processed string signals to *big.Int for Go contract call
			var publicSignalsArray [21]*big.Int
			for i, signal := range publicSignals {
				if i >= 21 {
					break // Contract ABI specifies exactly 21 elements
				}
				signalBigInt := new(big.Int)
				// Handle both hex (0x...) and decimal strings
				if strings.HasPrefix(signal, "0x") {
					signalBigInt.SetString(signal, 0) // Auto-detect base (0x = hex)
				} else {
					signalBigInt.SetString(signal, 10) // Decimal
				}
				publicSignalsArray[i] = signalBigInt
			}
			// Fill remaining slots with zero if publicSignals has less than 21 elements
			for i := len(publicSignals); i < 21; i++ {
				publicSignalsArray[i] = big.NewInt(0)
			}

			isValid, err := verifierContract.VerifyProof(nil, proof.A, bFormatted, proof.C, publicSignalsArray)
			if err != nil {
				isProofValid = false
			} else {
				isProofValid = isValid
			}
		}
	}

	// Block 14: Construct return value using already computed values
	// If validation failed, we might not have computed these values, so compute them only if needed
	if forbiddenCountriesList == nil || len(genericDiscloseOutput.Nullifier) == 0 {
		// Fallback: compute missing values if validation was skipped due to errors
		if len(userContextData) >= 128 {
			discloseIndices, exists = utils.DiscloseIndices[attestationId]
			if exists {
				forbiddenCountriesListPacked := make([]string, 4)
				for i := 0; i < 4; i++ {
					forbiddenCountriesListPacked[i] = publicSignals[discloseIndices.ForbiddenCountriesListPackedIndex+i]
				}
				forbiddenCountriesList = utils.UnpackForbiddenCountriesList(forbiddenCountriesListPacked)

				var err error
				genericDiscloseOutput, err = utils.FormatRevealedDataPacked(attestationId, publicSignals)
				if err != nil {
					return nil, fmt.Errorf("error formatting revealed data: %v", err)
				}
			}
		}
	}

	// Calculate validation details for return value using already computed config
	isMinimumAgeValid := true
	if configErr == nil && verificationConfig.MinimumAge != nil {
		configMinAge := *verificationConfig.MinimumAge
		circuitMinAge := genericDiscloseOutput.MinimumAge
		circuitMinAgeInt := 0
		if circuitMinAge != "00" {
			fmt.Sscanf(circuitMinAge, "%d", &circuitMinAgeInt)
		}
		isMinimumAgeValid = configMinAge <= circuitMinAgeInt
	}

	isOfacValid := true
	if configErr == nil && verificationConfig.Ofac != nil && *verificationConfig.Ofac {
		for _, ofacCheck := range genericDiscloseOutput.Ofac {
			if !ofacCheck {
				isOfacValid = false
				break
			}
		}
	}

	return &types.VerificationResult{
		AttestationId: attestationId,
		IsValidDetails: types.IsValidDetails{
			IsValid:           isProofValid,
			IsMinimumAgeValid: isMinimumAgeValid,
			IsOfacValid:       isOfacValid,
		},
		ForbiddenCountriesList: forbiddenCountriesList,
		DiscloseOutput:         genericDiscloseOutput,
		UserData: types.UserData{
			UserIdentifier:  userIdentifier,
			UserDefinedData: userDefinedData,
		},
	}, nil
}

// castToUserIdentifier converts a big integer to user identifier string based on the specified type
func (s *SelfBackendVerifier) castToUserIdentifier(bigInt *big.Int, userIdType types.UserIDType) string {
	switch userIdType {
	case types.UserIDTypeHex:
		return s.castToAddress(bigInt)
	case types.UserIDTypeUUID:
		return s.castToUUID(bigInt)
	default:
		return bigInt.String()
	}
}

// castToAddress converts big integer to hex address format (0x + 40 hex chars)
func (s *SelfBackendVerifier) castToAddress(bigInt *big.Int) string {
	hexStr := bigInt.Text(16) // Convert to hex without 0x prefix
	// Pad to 40 characters (20 bytes = 40 hex chars)
	if len(hexStr) < 40 {
		hexStr = fmt.Sprintf("%040s", hexStr)
	}
	return "0x" + hexStr
}

// castToUUID converts big integer to UUID format
func (s *SelfBackendVerifier) castToUUID(bigInt *big.Int) string {
	hexStr := bigInt.Text(16) // Convert to hex without 0x prefix
	// Pad to 32 characters (16 bytes = 32 hex chars)
	if len(hexStr) < 32 {
		hexStr = fmt.Sprintf("%032s", hexStr)
	}
	// Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}

// validateWithConfig performs config-based validations (forbidden countries, minimum age, timestamp, OFAC)
// Returns the computed values for reuse in return value construction
func (s *SelfBackendVerifier) validateWithConfig(
	verificationConfig types.VerificationConfig,
	publicSignals []string,
	discloseIndices utils.DiscloseIndicesEntry,
	attestationId types.AttestationId,
	issues *[]ConfigIssue,
) ([]string, types.GenericDiscloseOutput, error) {
	// Block 9: Check if forbidden countries list matches
	forbiddenCountriesListPacked := make([]string, 4)
	for i := 0; i < 4; i++ {
		forbiddenCountriesListPacked[i] = publicSignals[discloseIndices.ForbiddenCountriesListPackedIndex+i]
	}

	forbiddenCountriesList := utils.UnpackForbiddenCountriesList(forbiddenCountriesListPacked)

	// Check if all config excluded countries are in the circuit's forbidden list
	isForbiddenCountryListValid := true
	for _, country := range verificationConfig.ExcludedCountries {
		found := false
		for _, circuitCountry := range forbiddenCountriesList {
			if string(country) == circuitCountry {
				found = true
				break
			}
		}
		if !found {
			isForbiddenCountryListValid = false
			break
		}
	}

	if !isForbiddenCountryListValid {
		*issues = append(*issues, ConfigIssue{
			Type: InvalidForbiddenCountriesList,
			Message: fmt.Sprintf("Forbidden countries list in config does not match with the one in the circuit\nCircuit: %s\nConfig: %v",
				strings.Join(forbiddenCountriesList, ", "), verificationConfig.ExcludedCountries),
		})
	}

	// Block 10: Check minimum age matches
	genericDiscloseOutput, err := utils.FormatRevealedDataPacked(attestationId, publicSignals)
	if err != nil {
		*issues = append(*issues, ConfigIssue{
			Type:    InvalidMinimumAge,
			Message: fmt.Sprintf("Error formatting revealed data: %v", err),
		})
		return nil, types.GenericDiscloseOutput{}, err
	}

	if verificationConfig.MinimumAge != nil {
		configMinAge := *verificationConfig.MinimumAge
		circuitMinAge := genericDiscloseOutput.MinimumAge

		// Parse circuit minimum age
		circuitMinAgeInt := 0
		if circuitMinAge != "00" {
			fmt.Sscanf(circuitMinAge, "%d", &circuitMinAgeInt)
		}

		isMinimumAgeValid := configMinAge == circuitMinAgeInt || circuitMinAge == "00"
		if !isMinimumAgeValid {
			*issues = append(*issues, ConfigIssue{
				Type: InvalidMinimumAge,
				Message: fmt.Sprintf("Minimum age in config does not match with the one in the circuit\nCircuit: %s\nConfig: %d",
					circuitMinAge, configMinAge),
			})
		}
	}

	// Block 11: Check timestamp validation
	s.validateTimestamp(publicSignals, discloseIndices, issues)

	// Block 12: Check OFAC validation
	if verificationConfig.Ofac != nil && !*verificationConfig.Ofac {
		for i, ofacCheck := range genericDiscloseOutput.Ofac {
			if ofacCheck {
				var ofacType string
				switch i {
				case 0:
					ofacType = "Passport number OFAC check"
				case 1:
					ofacType = "Name and DOB OFAC check"
				case 2:
					ofacType = "Name and YOB OFAC check"
				default:
					ofacType = fmt.Sprintf("OFAC check %d", i)
				}
				*issues = append(*issues, ConfigIssue{
					Type:    InvalidOfac,
					Message: fmt.Sprintf("%s is not allowed", ofacType),
				})
			}
		}
	}

	// Return computed values for reuse
	return forbiddenCountriesList, genericDiscloseOutput, nil
}

// validateTimestamp checks if the circuit timestamp is within acceptable range (not too old, not in future)
func (s *SelfBackendVerifier) validateTimestamp(
	publicSignals []string,
	discloseIndices utils.DiscloseIndicesEntry,
	issues *[]ConfigIssue,
) {
	// Extract timestamp components from circuit (YYMMDD format)
	currentDateIndex := discloseIndices.CurrentDateIndex

	// Build year: "20" + YY digits
	yy1, _ := strconv.Atoi(publicSignals[currentDateIndex])
	yy2, _ := strconv.Atoi(publicSignals[currentDateIndex+1])
	year := 2000 + yy1*10 + yy2

	// Build month: MM digits
	mm1, _ := strconv.Atoi(publicSignals[currentDateIndex+2])
	mm2, _ := strconv.Atoi(publicSignals[currentDateIndex+3])
	month := mm1*10 + mm2

	// Build day: DD digits
	dd1, _ := strconv.Atoi(publicSignals[currentDateIndex+4])
	dd2, _ := strconv.Atoi(publicSignals[currentDateIndex+5])
	day := dd1*10 + dd2

	// Create circuit timestamp
	// Note: TypeScript subtracts 1 from month because JS Date is 0-indexed (0=Jan)
	// Go time.Month is 1-indexed (1=Jan), so we use month directly
	circuitTimestamp := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	currentTimestamp := time.Now().UTC()

	// Check if timestamp is more than 1 day in the future
	oneDayAhead := currentTimestamp.Add(24 * time.Hour)
	if circuitTimestamp.After(oneDayAhead) {
		*issues = append(*issues, ConfigIssue{
			Type:    InvalidTimestamp,
			Message: "Circuit timestamp is in the future",
		})
	}

	// Check if timestamp is more than 1 day in the past
	oneDayAgo := currentTimestamp.Add(-24 * time.Hour)
	if circuitTimestamp.Before(oneDayAgo) {
		*issues = append(*issues, ConfigIssue{
			Type:    InvalidTimestamp,
			Message: "Circuit timestamp is too old",
		})
	}
}

// isEmptyVerificationConfig checks if a VerificationConfig is empty/invalid
// Since we can't directly compare structs with slices, we check individual fields
func (s *SelfBackendVerifier) isEmptyVerificationConfig(config types.VerificationConfig) bool {
	// A config is considered empty if all fields are nil/zero values
	return config.MinimumAge == nil &&
		config.ExcludedCountries == nil &&
		config.Ofac == nil
}
