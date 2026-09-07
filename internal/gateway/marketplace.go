package gateway

// AWS Marketplace metering.
//
// Paid container products sold through AWS Marketplace must call RegisterUsage
// for entitlement and metering. Free and BYOL listings are exempt, and so is
// every deployment that does not configure it: with no marketplace block in the
// configuration nothing here contacts AWS at all, which keeps the development
// harness and non-Marketplace deployments unaffected.
//
// The call happens once, at startup, before serving. AWS meters per ECS task per
// hour and bills for running tasks regardless of subscription state, so there is
// no runtime entitlement re-check to write; entitlement exceptions are only
// raised on the first call from a given task.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering/types"
)

// MarketplaceConfig is optional. Absent means this gateway was not obtained
// through AWS Marketplace and no metering call is made.
type MarketplaceConfig struct {
	ProductCode      string `json:"product_code"`
	PublicKeyVersion int32  `json:"public_key_version"`
}

// Pattern published for the RegisterUsage ProductCode parameter.
var productCodePattern = regexp.MustCompile(`^[-a-zA-Z0-9/=:_.@]{1,255}$`)

func (m *MarketplaceConfig) Validate() error {
	if m == nil {
		return nil
	}
	if !productCodePattern.MatchString(m.ProductCode) {
		return errors.New("marketplace product_code is not a valid product code")
	}
	if m.PublicKeyVersion < 1 {
		return errors.New("marketplace public_key_version must be at least 1")
	}
	return nil
}

// UsageRegistrar is the single Marketplace call this package makes. It exists so
// the entitlement paths can be exercised without AWS.
type UsageRegistrar interface {
	RegisterUsage(context.Context, *marketplacemetering.RegisterUsageInput,
		...func(*marketplacemetering.Options)) (*marketplacemetering.RegisterUsageOutput, error)
}

// ErrNotEntitled reports that the customer running this software has no valid
// subscription. The gateway must not serve.
var ErrNotEntitled = errors.New("no valid AWS Marketplace subscription for this product")

// NewUsageRegistrar builds a client against the ambient AWS configuration.
// The region is deliberately left to the SDK: RegisterUsage must be called in
// the same Region the task was launched in, and hardcoding one raises
// InvalidRegionException.
func NewUsageRegistrar(ctx context.Context) (UsageRegistrar, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws configuration unavailable: %w", err)
	}
	return marketplacemetering.NewFromConfig(cfg), nil
}

// RegisterUsage performs the startup registration. A nil configuration is not an
// error: it means this deployment is not metered through Marketplace.
//
// Every failure is returned rather than swallowed. A paid product that cannot
// establish entitlement should refuse to serve rather than serve unmetered.
func RegisterUsage(ctx context.Context, m *MarketplaceConfig, api UsageRegistrar) error {
	if m == nil {
		return nil
	}
	nonce, err := registrationNonce()
	if err != nil {
		return fmt.Errorf("marketplace nonce unavailable: %w", err)
	}
	_, err = api.RegisterUsage(ctx, &marketplacemetering.RegisterUsageInput{
		ProductCode:      aws.String(m.ProductCode),
		PublicKeyVersion: aws.Int32(m.PublicKeyVersion),
		Nonce:            aws.String(nonce),
	})
	if err == nil {
		return nil
	}
	var notEntitled *types.CustomerNotEntitledException
	if errors.As(err, &notEntitled) {
		return ErrNotEntitled
	}
	return fmt.Errorf("marketplace registration failed: %w", err)
}

// registrationNonce scopes a registration to this process and guards against
// replay, as the Nonce parameter is documented to do.
func registrationNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
