package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering/types"
)

type fakeRegistrar struct {
	calls  int
	inputs []*marketplacemetering.RegisterUsageInput
	err    error
}

func (f *fakeRegistrar) RegisterUsage(_ context.Context, in *marketplacemetering.RegisterUsageInput,
	_ ...func(*marketplacemetering.Options)) (*marketplacemetering.RegisterUsageOutput, error) {
	f.calls++
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &marketplacemetering.RegisterUsageOutput{}, nil
}

// Absent configuration must not reach AWS at all. This is what keeps the
// development harness and non-Marketplace deployments unaffected.
func TestMarketplaceSkippedWhenUnconfigured(t *testing.T) {
	f := &fakeRegistrar{}
	if err := RegisterUsage(context.Background(), nil, f); err != nil {
		t.Fatalf("unconfigured registration returned %v, want nil", err)
	}
	if f.calls != 0 {
		t.Fatalf("made %d AWS calls with no marketplace configuration, want 0", f.calls)
	}
}

func TestMarketplaceEntitled(t *testing.T) {
	f := &fakeRegistrar{}
	m := &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 1}
	if err := RegisterUsage(context.Background(), m, f); err != nil {
		t.Fatalf("entitled registration returned %v, want nil", err)
	}
	if f.calls != 1 {
		t.Fatalf("made %d calls, want exactly 1: registration happens once at startup", f.calls)
	}
	in := f.inputs[0]
	if *in.ProductCode != m.ProductCode || *in.PublicKeyVersion != 1 {
		t.Fatalf("sent product code %q version %d, want %q version 1",
			*in.ProductCode, *in.PublicKeyVersion, m.ProductCode)
	}
	if in.Nonce == nil || *in.Nonce == "" {
		t.Fatal("no nonce sent; the nonce guards against replay")
	}
}

// An unsubscribed customer must fail closed, matching how an expired policy
// already fails readiness closed.
func TestMarketplaceNotEntitledFailsClosed(t *testing.T) {
	f := &fakeRegistrar{err: &types.CustomerNotEntitledException{}}
	m := &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 1}
	err := RegisterUsage(context.Background(), m, f)
	if !errors.Is(err, ErrNotEntitled) {
		t.Fatalf("returned %v, want ErrNotEntitled", err)
	}
}

// Any other failure is surfaced rather than swallowed: serving unmetered is
// worse than refusing to start.
func TestMarketplaceClientFailureSurfaces(t *testing.T) {
	sentinel := errors.New("throttled")
	f := &fakeRegistrar{err: sentinel}
	m := &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 1}
	err := RegisterUsage(context.Background(), m, f)
	if err == nil {
		t.Fatal("client failure returned nil; registration must not silently succeed")
	}
	if errors.Is(err, ErrNotEntitled) {
		t.Fatal("a transport failure was reported as an entitlement failure")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned %v, which does not wrap the underlying error", err)
	}
}

// Each registration carries a distinct nonce.
func TestMarketplaceNonceIsPerCall(t *testing.T) {
	f := &fakeRegistrar{}
	m := &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 1}
	for i := 0; i < 2; i++ {
		if err := RegisterUsage(context.Background(), m, f); err != nil {
			t.Fatalf("registration %d returned %v", i, err)
		}
	}
	if *f.inputs[0].Nonce == *f.inputs[1].Nonce {
		t.Fatal("nonce repeated across registrations")
	}
}

// Startup ordering: an invalid marketplace block must be rejected by config
// validation, so a bad configuration never reaches the point of serving.
func TestMarketplaceConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *MarketplaceConfig
		ok   bool
	}{
		{"absent", nil, true},
		{"valid", &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 1}, true},
		{"empty product code", &MarketplaceConfig{ProductCode: "", PublicKeyVersion: 1}, false},
		{"illegal characters", &MarketplaceConfig{ProductCode: "bad code!", PublicKeyVersion: 1}, false},
		{"zero key version", &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: 0}, false},
		{"negative key version", &MarketplaceConfig{ProductCode: "cqcvf9f0ugw8rkbgmf1c9dxyz", PublicKeyVersion: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if tc.ok && err != nil {
				t.Fatalf("valid configuration rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
