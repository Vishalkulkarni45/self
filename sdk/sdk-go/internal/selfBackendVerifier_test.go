package selfBackendVerifier

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"self-sdk-go/common"
	"self-sdk-go/internal/types"
	"self-sdk-go/internal/utils"
)

// MockConfigStore implements ConfigStore interface for testing
type MockConfigStore struct {
	configs   map[string]types.VerificationConfig
	actionIds map[string]string
}

func (m *MockConfigStore) GetConfig(ctx context.Context, id string) (types.VerificationConfig, error) {
	if config, exists := m.configs[id]; exists {
		return config, nil
	}
	return types.VerificationConfig{}, nil
}

func (m *MockConfigStore) SetConfig(ctx context.Context, id string, config types.VerificationConfig) (bool, error) {
	if m.configs == nil {
		m.configs = make(map[string]types.VerificationConfig)
	}
	m.configs[id] = config
	return true, nil
}

func (m *MockConfigStore) GetActionId(ctx context.Context, userIdentifier string, actionId string) (string, error) {
	key := userIdentifier + actionId
	if actionId, exists := m.actionIds[key]; exists {
		return actionId, nil
	}
	return "", nil
}

// Test data based on the provided inputs
var testProof = types.VcAndDiscloseProof{
	A: [2]*big.Int{
		mustParseBigInt("19978035591559142190701827820645990013414633793180672686938226685776304489564"),
		mustParseBigInt("5729195691952204724157922378821526527130089592215448275678040621795037604051"),
	},
	B: [2][2]*big.Int{
		{
			mustParseBigInt("11751985993692270888240656856501733091634778410910150825443605743432104365496"),
			mustParseBigInt("4452136363546266459130979435587765558483594623092208966946297079596510893605"),
		},
		{
			mustParseBigInt("3810657409440735818003229201852551662656469950107499750244154014975554267923"),
			mustParseBigInt("10470222606272472527954481346783037896628046865041659088202192358643101806862"),
		},
	},
	C: [2]*big.Int{
		mustParseBigInt("15884364794774631813944040023461646992309624876334078534233455116862274883339"),
		mustParseBigInt("20393368791665166818799823852194418481289576790771157544865526424140268474306"),
	},
}

var testPublicSignals = []*big.Int{
	big.NewInt(0),
	mustParseBigInt("88695642300982331844063832786964092168707990538423248083901435067469135872"),
	mustParseBigInt("5917645764266387229099807922771871753544163856784761583567435202615"),
	big.NewInt(4936272),
	big.NewInt(0),
	big.NewInt(0),
	big.NewInt(0),
	mustParseBigInt("13444167391765850209653844241387268774183214285042803350347364004811481522835"),
	big.NewInt(1),
	mustParseBigInt("3128220823265944096261447595696332812503333375431456287926106302900687520341"),
	big.NewInt(2),
	big.NewInt(5),
	big.NewInt(0),
	big.NewInt(8),
	big.NewInt(1),
	big.NewInt(2),
	mustParseBigInt("17359956125106148146828355805271472653597249114301196742546733402427978706344"),
	mustParseBigInt("7420120618403967585712321281997181302561301414016003514649937965499789236588"),
	mustParseBigInt("16836358042995742879630198413873414945978677264752036026400967422611478610995"),
	mustParseBigInt("13934606664243914063643606771911468856671016933765586820821710153612586828695"),
	mustParseBigInt("333950092602874832043713879344132078365835356296"),
}

// Helper function to parse big integers
func mustParseBigInt(s string) *big.Int {
	bi := new(big.Int)
	bi.SetString(s, 10)
	return bi
}

// Helper function to create test verification config
func createTestVerificationConfig() types.VerificationConfig {
	minimumAge := 20
	ofac := true
	return types.VerificationConfig{
		MinimumAge:        &minimumAge,
		ExcludedCountries: []common.Country3LetterCode{"AFG", "ALB"}, // Afghanistan, Albania
		Ofac:              &ofac,
	}
}

// Helper function to create properly formatted test user context data
func createTestUserContextData() string {
	// Correct format: configId(32 bytes) + destChainId(32 bytes) + userIdentifier(32 bytes) + userDefinedData
	// This matches the format expected by the smart contracts and verification logic

	// 32 bytes configId (64 hex chars)
	configId := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 32 bytes destChainId (64 hex chars) - Celo testnet chain ID (42220 = 0xa4ec)
	destChainId := "000000000000000000000000000000000000000000000000000000000000a4ec"

	// 32 bytes userIdentifier (64 hex chars)
	userIdentifier := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	// User defined data (hex encoded)
	userDefinedData := hex.EncodeToString([]byte("test-user-data"))

	return configId + destChainId + userIdentifier + userDefinedData
}

// Helper function to extract user identifier from properly formatted userContextData
func extractUserIdentifierFromContextData(userContextData string) string {
	// userIdentifier is at bytes 64-96 (hex chars 128-192)
	if len(userContextData) < 192 {
		return ""
	}
	userIdentifierHex := userContextData[128:192] // Extract userIdentifier hex
	userIdentifierBigInt := new(big.Int)
	userIdentifierBigInt.SetString(userIdentifierHex, 16)

	// Convert to address format (0x + 40 hex chars) - matching UserIDTypeHex
	hexStr := userIdentifierBigInt.Text(16)
	if len(hexStr) < 40 {
		hexStr = fmt.Sprintf("%040s", hexStr)
	}
	return "0x" + hexStr
}

// Helper function to extract user defined data from properly formatted userContextData
func extractUserDefinedDataFromContextData(userContextData string) string {
	// userDefinedData starts at byte 96 (hex char 192)
	if len(userContextData) < 192 {
		return ""
	}
	userDefinedDataHex := userContextData[192:] // Everything after userIdentifier
	userDefinedDataBytes, err := hex.DecodeString(userDefinedDataHex)
	if err != nil {
		return ""
	}
	return string(userDefinedDataBytes)
}

func TestSelfBackendVerifier_Verify_ValidAttestationId(t *testing.T) {
	userContextData := createTestUserContextData()

	// Extract the actual values that will be used for config lookup
	extractedUserIdentifier := extractUserIdentifierFromContextData(userContextData)
	extractedUserDefinedData := extractUserDefinedDataFromContextData(userContextData)

	t.Logf("UserContextData: %s", userContextData)
	t.Logf("Extracted UserIdentifier: %s", extractedUserIdentifier)
	t.Logf("Extracted UserDefinedData: %s", extractedUserDefinedData)

	mockConfigStore := &MockConfigStore{
		configs: map[string]types.VerificationConfig{
			"test-config-id": createTestVerificationConfig(),
		},
		actionIds: map[string]string{
			// Use the correctly extracted values for the lookup key
			extractedUserIdentifier + extractedUserDefinedData: "test-config-id",
		},
	}

	allowedIds := map[types.AttestationId]bool{
		types.AttestationId(1): true, // Allow attestation ID 1
	}

	verifier, err := NewSelfBackendVerifier(
		"test-scope",
		"https://example.com",
		true, // Use testnet for testing
		allowedIds,
		mockConfigStore,
		types.UserIDTypeHex,
	)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	ctx := context.Background()

	// Try to verify with valid attestation ID 1
	result, err := verifier.Verify(
		ctx,
		types.AttestationId(1), // Valid ID
		testProof,
		testPublicSignals,
		userContextData,
	)

	// Log detailed results for debugging
	if err != nil {
		t.Logf("Verification failed: %v", err)
		// Check if it's a ConfigMismatchError or contract-related error
		if configErr, ok := err.(*ConfigMismatchError); ok {
			t.Logf("Config validation issues found:")
			for i, issue := range configErr.Issues {
				t.Logf("  Issue %d: %s - %s", i+1, issue.Type, issue.Message)
			}
		}
	}
	if result != nil {
		t.Logf("Got verification result: %+v", result)
	}
}

// Test specifically for userContextHash validation
func TestUserContextHashValidation(t *testing.T) {
	userContextData := createTestUserContextData()

	// Decode the hex string to bytes (like the Go code does)
	userContextDataBytes, err := hex.DecodeString(userContextData)
	if err != nil {
		t.Fatalf("Failed to decode userContextData: %v", err)
	}

	// Calculate the hash using the same method as the verifier
	userContextHashStr := utils.CalculateUserIdentifierHash(userContextDataBytes)
	t.Logf("Calculated userContextHash: %s", userContextHashStr)

	// The public signals should contain this hash at the userIdentifierIndex
	// For attestationId 1, userIdentifierIndex is 20 (from constants.go)
	if len(testPublicSignals) > 20 {
		circuitHash := testPublicSignals[20].String()
		t.Logf("Circuit userContextHash: %s", circuitHash)

		// Convert calculated hash to big.Int for comparison (remove 0x prefix)
		calculatedHashBigInt := new(big.Int)
		hashForParsing := strings.TrimPrefix(userContextHashStr, "0x")
		calculatedHashBigInt.SetString(hashForParsing, 16)

		if calculatedHashBigInt.Cmp(testPublicSignals[20]) == 0 {
			t.Logf("✅ UserContextHash matches!")
		} else {
			t.Logf("❌ UserContextHash mismatch!")
			t.Logf("Expected: %s", calculatedHashBigInt.String())
			t.Logf("Got: %s", testPublicSignals[20].String())
		}
	}

	t.Logf("UserContextData format validation:")
	t.Logf("  Total length: %d chars (%d bytes)", len(userContextData), len(userContextData)/2)
	t.Logf("  ConfigId: %s", userContextData[0:64])
	t.Logf("  DestChainId: %s", userContextData[64:128])
	t.Logf("  UserIdentifier: %s", userContextData[128:192])
	t.Logf("  UserDefinedData: %s", userContextData[192:])
}
