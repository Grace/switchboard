package bedrock

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/Grace/switchboard/internal/switchboard"
)

// clientFor returns the Bedrock client to serve this request with.
//
// Unattributed requests use the gateway's own credentials, which is what the
// provider bills today. An attributed request gets a client whose credentials
// came from assuming the configured role with the caller as the session name
// and a session tag naming the team — so the same call arrives at the provider
// wearing an identity the bill can split on.
//
// Clients are cached per team. The credentials underneath refresh themselves
// before expiry, so a busy team costs one STS call per session duration rather
// than one per request.
func (b *Backend) clientFor(ctx context.Context) (*bedrockruntime.Client, error) {
	base, err := b.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if !b.attr.Enabled {
		return base, nil
	}
	caller, ok := switchboard.CallerFrom(ctx)
	if !ok || caller.Team == "" {
		if b.attr.RequireCaller {
			return nil, errUnattributed
		}
		return base, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if c, ok := b.byTeam[caller.Team]; ok {
		return c, nil
	}

	cfg := b.baseCfg.Copy()
	provider := stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(b.baseCfg),
		b.attr.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = caller.Team
			o.Duration = time.Duration(b.attr.SessionDuration)
			o.Tags = []ststypes.Tag{{
				Key:   aws.String(b.attr.TagKey),
				Value: aws.String(caller.Team),
			}}
		},
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)

	client := bedrockruntime.NewFromConfig(cfg)
	if b.byTeam == nil {
		b.byTeam = map[string]*bedrockruntime.Client{}
	}
	b.byTeam[caller.Team] = client
	return client, nil
}

var errUnattributed = fmt.Errorf(
	"attribution.require_caller is set and this request carried no team; " +
		"present a team key as a bearer token")

// Unattributed reports whether err is a refusal to serve an unattributed
// request, so the server can answer 401 rather than 500.
func Unattributed(err error) bool { return err == errUnattributed }
