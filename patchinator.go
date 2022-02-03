package gopatchinator

import (
	"encoding/json"
	"fmt"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"regexp"
)

type Op struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type Patch []Op

// PatchRule defines a rule to evaluate if a patch is acceptable or not
type PatchRule struct {
	Op          []string
	rex         *regexp.Regexp
	Path        string
	Deny        bool
	ShouldAllow func(path string, value interface{}) bool
}

// PatchRules is a slice of PatchRule
type PatchRules []PatchRule

// Patchinator is the interface that allows the user
type Patchinator interface {
	IsWhitelist(whitelist bool)
	Run(patch []byte) error
	Apply(patch []byte, original []byte) ([]byte, error)
}

type patchinator struct {
	rules     PatchRules
	whitelist bool
}

func NewPatchinator(rules PatchRules) (Patchinator, error) {
	for i, rule := range rules {
		rex, err := regexp.Compile(rule.Path)
		if err != nil {
			return nil, err
		}
		rules[i].rex = rex
	}

	return &patchinator{
		rules:     rules,
		whitelist: false,
	}, nil
}

func (p *patchinator) IsWhitelist(whitelist bool) {
	p.whitelist = whitelist
}

func (p *patchinator) Run(bytes []byte) error {
	var patch Patch
	err := json.Unmarshal(bytes, &patch)

	if err != nil {
		return err
	}

	for _, op := range patch {
		err := p.verifyOperation(op)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *patchinator) Apply(patch []byte, original []byte) ([]byte, error) {
	err := p.Run(patch)

	if err != nil {
		return nil, err
	}

	patcher, err := jsonpatch.DecodePatch(patch)

	if err != nil {
		return nil, err
	}

	return patcher.Apply(original)
}

func (p *patchinator) verifyOperation(op Op) error {
	if p.whitelist {
		return p.verifyWhitelist(op)
	}

	return p.verifyBlacklist(op)
}

func (p *patchinator) verifyWhitelist(op Op) error {
	for _, rule := range p.rules {
		rex := *rule.rex
		if rex.Match([]byte(op.Path)) {
			if err := verifyOperation(op.Op, rule.Op); err != nil {
				return err
			}

			if rule.ShouldAllow != nil && rule.ShouldAllow(op.Path, op.Value) == false {
				return fmt.Errorf("%s is not allowed", op.Path)
			} else if rule.Deny {
				return fmt.Errorf("%s is not allowed", op.Path)
			} else {
				return nil
			}
		}
	}

	return fmt.Errorf("%s is not whitelisted", op.Path)
}

func (p *patchinator) verifyBlacklist(op Op) error {
	for _, rule := range p.rules {
		rex := *rule.rex
		if rex.Match([]byte(op.Path)) {
			if err := verifyOperation(op.Op, rule.Op); err != nil {
				return err
			}
			if rule.Deny {
				return fmt.Errorf("%s is not allowed", op.Path)
			}
			if rule.ShouldAllow != nil && rule.ShouldAllow(op.Path, op.Value) == false {
				return fmt.Errorf("%s is not allowed", op.Path)
			}
		}
	}

	return nil
}

func verifyOperation(op string, opList []string) error {
	hasOp := false
	for _, operation := range opList {
		if operation == op {
			hasOp = true
		}
	}
	if !hasOp {
		return fmt.Errorf("%s is not in the list of acceptable operations", op)
	}
	return nil
}
