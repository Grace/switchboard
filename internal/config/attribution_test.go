package config

import "testing"

func base() *Config {
	return &Config{
		Listen: "127.0.0.1:11435",
		Models: []Line{{Name: "m", Backend: BackendBedrock, ModelID: "x"}},
	}
}

func TestAttributionOffIsFine(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("attribution absent should validate: %v", err)
	}
}

// Fail closed only makes sense if there is something to close over.
func TestRequireCallerWithoutEnabledIsRefused(t *testing.T) {
	c := base()
	c.Attribution = Attribution{RequireCaller: true}
	if err := c.Validate(); err == nil {
		t.Fatal("require_caller without enabled must be refused")
	}
}

func TestEnabledNeedsRoleAndTeams(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Fatal("enabled without role_arn must be refused")
	}

	c.Attribution.RoleARN = "arn:aws:iam::1:role/r"
	if err := c.Validate(); err == nil {
		t.Fatal("enabled with no teams must be refused: nothing to attribute to")
	}
}

func TestDefaultsAreFilledIn(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}
	c.Teams = []Team{{Name: "search", Keys: []string{"0123456789abcdef"}}}
	if err := c.Validate(); err != nil {
		t.Fatalf("should validate: %v", err)
	}
	if c.Attribution.TagKey != "team" {
		t.Errorf("tag_key default = %q, want team", c.Attribution.TagKey)
	}
	if c.Attribution.SessionDuration == 0 {
		t.Error("session_duration should default rather than be zero")
	}
}

// A session name AWS rejects is a runtime failure switchboard cannot recover
// from, so it is a config error instead.
func TestTeamNameMustBeAValidSessionName(t *testing.T) {
	for _, name := range []string{"a", "has space", "emoji🙂", ""} {
		c := base()
		c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}
		c.Teams = []Team{{Name: name, Keys: []string{"0123456789abcdef"}}}
		if err := c.Validate(); err == nil {
			t.Errorf("team name %q should be refused", name)
		}
	}
}

func TestKeysMustBeUniqueAndLongEnough(t *testing.T) {
	c := base()
	c.Attribution = Attribution{Enabled: true, RoleARN: "arn:aws:iam::1:role/r"}

	c.Teams = []Team{{Name: "search", Keys: []string{"short"}}}
	if err := c.Validate(); err == nil {
		t.Error("a five-character key should be refused")
	}

	shared := "0123456789abcdef"
	c.Teams = []Team{
		{Name: "search", Keys: []string{shared}},
		{Name: "billing", Keys: []string{shared}},
	}
	if err := c.Validate(); err == nil {
		t.Error("a key shared by two teams makes attribution ambiguous and must be refused")
	}

	c.Teams = []Team{{Name: "search", Keys: nil}}
	if err := c.Validate(); err == nil {
		t.Error("a team with no keys can never be authenticated as")
	}
}

func TestTeamForKey(t *testing.T) {
	teams := []Team{
		{Name: "search", Keys: []string{"key-search-0123456789"}},
		{Name: "billing", Keys: []string{"key-billing-0123456789", "key-billing-alt-01234"}},
	}
	for key, want := range map[string]string{
		"key-search-0123456789":  "search",
		"key-billing-0123456789": "billing",
		"key-billing-alt-01234":  "billing",
	} {
		if got, ok := TeamForKey(teams, key); !ok || got != want {
			t.Errorf("TeamForKey(%q) = %q,%v; want %q", key, got, ok, want)
		}
	}
	if _, ok := TeamForKey(teams, "nope"); ok {
		t.Error("unknown key must not resolve")
	}
	if _, ok := TeamForKey(teams, ""); ok {
		t.Error("empty key must not resolve")
	}
}
