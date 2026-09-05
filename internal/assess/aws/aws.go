// Package aws adapts a Bedrock deployment into an assessable one.
//
// The input is a directory of `aws ... --output json` exports. That choice is
// the same one the databricks adapter makes and for the same reason: an
// assessment tool that wants production credentials is a six-week security
// review, and one that reads output the customer already has permission to
// produce is a conversation. Four commands, emailed as four files.
//
// Files are recognised by shape rather than by name, because nobody will name
// them what you asked. What is not recognised is reported rather than ignored —
// a report that silently skipped the guardrail export would understate the
// deployment, which is the same failure as overstating it.
//
// Bedrock is not a gateway, and the mapping is not a translation of one into
// another. Two places where it matters most:
//
// A guardrail is not a chokepoint. Databricks' AI Gateway applies its
// guardrails to everything through the endpoint. Bedrock applies a guardrail
// when the caller names one in the request, so an application can simply not
// pass it — unless an IAM condition forbids that, which no export here can
// show. This adapter therefore reports redaction as unbypassable Unknown and
// says exactly what to go and check.
//
// CloudTrail log file validation is real tamper-evidence, and it is
// tamper-evidence about the wrong thing. It chains digests of API call records,
// not of model invocations. Conflating the two would hand a deployment credit
// for a control it does not have over the record that matters.
//
// Every field is read from AWS's published shapes rather than from a schema
// verified against a live account, and AWS will drift. Absent or renamed fields
// yield Unknown rather than No: a wrong Unknown wastes a question, a wrong No
// invents a finding, and one invented finding is all it takes for a customer to
// stop reading. Verify against a real account before trusting any row.
package aws

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Grace/switchboard/internal/assess"
)

// Export is everything the directory turned out to hold.
type Export struct {
	Logging    *LoggingConfig
	Guardrails []Guardrail
	ObjectLock *ObjectLockConfiguration
	Trails     []Trail

	// Read and Skipped name the files, so the report can say what it was given
	// and what it made nothing of.
	Read    []string
	Skipped []string
}

// LoggingConfig is `aws bedrock get-model-invocation-logging-configuration`.
type LoggingConfig struct {
	CloudWatch *struct {
		LogGroupName string `json:"logGroupName"`
		RoleArn      string `json:"roleArn"`
	} `json:"cloudWatchConfig"`
	S3 *struct {
		BucketName string `json:"bucketName"`
		KeyPrefix  string `json:"keyPrefix"`
	} `json:"s3Config"`
	TextDataDelivery      *bool `json:"textDataDeliveryEnabled"`
	ImageDataDelivery     *bool `json:"imageDataDeliveryEnabled"`
	EmbeddingDataDelivery *bool `json:"embeddingDataDeliveryEnabled"`
}

// Guardrail is `aws bedrock get-guardrail`, or one element of the list form.
type Guardrail struct {
	Name        string `json:"name"`
	GuardrailID string `json:"guardrailId"`
	ARN         string `json:"guardrailArn"`
	Status      string `json:"status"`
	Version     string `json:"version"`

	ContentPolicy *struct {
		Filters []struct {
			Type           string `json:"type"`
			InputStrength  string `json:"inputStrength"`
			OutputStrength string `json:"outputStrength"`
		} `json:"filters"`
	} `json:"contentPolicy"`
	SensitiveInformationPolicy *struct {
		PIIEntities []struct {
			Type   string `json:"type"`
			Action string `json:"action"` // BLOCK | ANONYMIZE
		} `json:"piiEntities"`
		Regexes []struct {
			Name   string `json:"name"`
			Action string `json:"action"`
		} `json:"regexes"`
	} `json:"sensitiveInformationPolicy"`
	TopicPolicy *struct {
		Topics []struct {
			Name string `json:"name"`
		} `json:"topics"`
	} `json:"topicPolicy"`
	WordPolicy *struct {
		ManagedWordLists []any `json:"managedWordLists"`
		Words            []any `json:"words"`
	} `json:"wordPolicy"`
	ContextualGroundingPolicy *struct {
		Filters []any `json:"filters"`
	} `json:"contextualGroundingPolicy"`
}

// ObjectLockConfiguration is `aws s3api get-object-lock-configuration`.
//
// Note what it does not carry: the name of the bucket it belongs to. That is an
// unavoidable ambiguity in the export, and it is reported as a caveat rather
// than assumed away.
type ObjectLockConfiguration struct {
	Config *struct {
		ObjectLockEnabled string `json:"ObjectLockEnabled"`
		Rule              *struct {
			DefaultRetention *struct {
				Mode  string `json:"Mode"` // GOVERNANCE | COMPLIANCE
				Days  int    `json:"Days"`
				Years int    `json:"Years"`
			} `json:"DefaultRetention"`
		} `json:"Rule"`
	} `json:"ObjectLockConfiguration"`
}

// Trail is one element of `aws cloudtrail describe-trails`.
type Trail struct {
	Name                 string `json:"Name"`
	S3BucketName         string `json:"S3BucketName"`
	IsMultiRegionTrail   *bool  `json:"IsMultiRegionTrail"`
	LogFileValidation    *bool  `json:"LogFileValidationEnabled"`
	IncludeGlobalService *bool  `json:"IncludeGlobalServiceEvents"`
}

// ReadDir reads every .json file in a directory, recognising each by shape.
func ReadDir(dir string) (*Export, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	e := &Export{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if e.absorb(data) {
			e.Read = append(e.Read, entry.Name())
		} else {
			e.Skipped = append(e.Skipped, entry.Name())
		}
	}
	if len(e.Read) == 0 {
		return nil, fmt.Errorf("%s: nothing here looks like a Bedrock export. "+
			"Expected the JSON output of: bedrock get-model-invocation-logging-configuration, "+
			"bedrock get-guardrail (or list-guardrails), s3api get-object-lock-configuration, "+
			"cloudtrail describe-trails", dir)
	}
	sort.Strings(e.Read)
	sort.Strings(e.Skipped)
	return e, nil
}

// absorb identifies one document and files it. It reports whether it recognised
// anything at all.
//
// Each shape is keyed on a field the others do not have, and the document is
// decoded into a map first so that "the key is present but null" is
// distinguishable from "the key is absent" — `get-model-invocation-logging-
// configuration` on an account with logging switched off returns an empty
// object, and reading that as an unrecognised file would turn a real finding
// into a silence.
func (e *Export) absorb(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}

	if raw, ok := probe["loggingConfig"]; ok {
		var cfg LoggingConfig
		if err := json.Unmarshal(raw, &cfg); err == nil {
			e.Logging = &cfg
			return true
		}
		// Present and null: logging is not configured. That is the answer, not
		// a parse failure.
		e.Logging = &LoggingConfig{}
		return true
	}
	if _, ok := probe["guardrailId"]; ok {
		var g Guardrail
		if err := json.Unmarshal(data, &g); err == nil {
			e.Guardrails = append(e.Guardrails, g)
			return true
		}
	}
	if raw, ok := probe["guardrails"]; ok {
		var list []Guardrail
		if err := json.Unmarshal(raw, &list); err == nil {
			e.Guardrails = append(e.Guardrails, list...)
			return true
		}
	}
	if _, ok := probe["ObjectLockConfiguration"]; ok {
		var ol ObjectLockConfiguration
		if err := json.Unmarshal(data, &ol); err == nil {
			e.ObjectLock = &ol
			return true
		}
	}
	if raw, ok := probe["trailList"]; ok {
		var list []Trail
		if err := json.Unmarshal(raw, &list); err == nil {
			e.Trails = append(e.Trails, list...)
			return true
		}
	}
	return false
}

func tri(b *bool) assess.Support {
	if b == nil {
		return assess.Unknown
	}
	return assess.Bool(*b)
}
