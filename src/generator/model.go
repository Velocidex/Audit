package generator

import "github.com/Velocidex/ordereddict"

type Check struct {
	Id       string `json:"Id,omitempty"`
	Disabled bool   `json:"Disabled,omitempty"`

	Title     string  `json:"Title,omitempty"`
	Condition string  `json:"Condition,omitempty"`
	Rules     []*Test `json:"Rules,omitempty"`

	// Any VQL that should be run to remediate this check (bring into
	// compliance)
	Remediate string `json:"Remediate,omitempty"`
}

type Test struct {
	Type             string `json:"Type,omitempty"`
	Name             string `json:"Name,omitempty"`
	ColumnExpression string `json:"ColumnExpression,omitempty"`
	WhereExpression  string `json:"WhereExpression,omitempty"`
	OriginalTest     string `json:"OriginalTest,omitempty"`
	Error            string `json:"Error,omitempty"`

	Env *ordereddict.Dict `json:"Env,omitempty"`

	// A VQL expression to provide context on the test (for example
	// contents of reg value).
	Context string `json:"Context,omitempty"`
}

// If changing this update the merge rules in merge.go
type Rules struct {
	Source string `json:"Source,omitempty"`

	// The exported artifact will have this name and precondition.
	ArtifactName string `json:"ArtifactName,omitempty"`
	Precondition string `json:"Precondition,omitempty"`
	Description  string `json:"Description,omitempty"`

	// Contains any VQL that should be added to the export section.
	Export string `json:"Export,omitempty"`

	// The TYPE of the artifact (e.g. SCA)
	Type string `json:"Type,omitempty"`

	// A list of checks
	Checks []*Check `json:"Checks,omitempty"`
}
