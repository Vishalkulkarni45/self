package store

import (
	"context"
	"self-sdk-go/internal/types"

)

type ConfigStore interface {
	GetConfig(ctx context.Context, id string) (types.VerificationConfig, error)
	SetConfig(ctx context.Context, id string, config types.VerificationConfig) (bool, error)
	GetActionId(ctx context.Context, userIdentifier string, actionId string) (string, error)
}
