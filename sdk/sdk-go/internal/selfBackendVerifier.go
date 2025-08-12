package selfBackendVerifier

import (
	"context"
	//"encoding/hex"
	"fmt"
	// "math/big"
	// "strconv"
	"strings"
	//"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"

	//"self-sdk-go/common"
	"self-sdk-go/internal/types"
	//"self-sdk-go/internal/utils"
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
	identityVerificationHubContract *bind.BoundContract // Generic contract binding
	configStorage                   ConfigStore
	provider                        *ethclient.Client
	allowedIDs                      map[types.AttestationId]bool
	userIdentifierType              types.UserIDType
}
