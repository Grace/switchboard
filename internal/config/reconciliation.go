package config

import "fmt"

// Reconciliation maps the names on a provider's invoice onto the models this
// gateway routes.
//
// It exists because the two names are not the same and cannot be derived from
// one another. AWS bills "Claude4.6Sonnet" for what this gateway invoked as
// "anthropic.claude-sonnet-4-6-20260501-v1:0" under the local name
// "claude-sonnet". The resemblance is obvious to a person and worth nothing to
// a program, and the cost of guessing is asymmetric: an unmapped line produces
// a question somebody answers, while a wrongly matched one produces a
// reconciliation that balances between two different models. Nobody goes
// looking to disprove a clean report.
//
// So this is declared, for the same reason the rate card is declared — record
// what you observed, configure what you assume.
//
// Deliberately not part of the policy fingerprint. It changes nothing the
// gateway allows, redacts, attributes or refuses; it only affects how a report
// read afterwards is assembled, and a fingerprint that moved for that would
// train people to ignore it.
type Reconciliation struct {
	// Models maps an invoice name to a name in models[]. Several invoice names
	// may map to one model: a bill separates in-region from cross-region
	// routing and one service tier from another, and those are the same model
	// answering.
	Models map[string]string `json:"models,omitempty"`
}

func (r *Reconciliation) validate() error {
	for billed, local := range r.Models {
		if billed == "" {
			return fmt.Errorf("reconciliation.models has an entry with no invoice name")
		}
		if local == "" {
			return fmt.Errorf("reconciliation.models[%q]: maps to no model name", billed)
		}
	}
	return nil
}
