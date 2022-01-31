package gopatchinator

import (
	"encoding/json"
	"testing"
)

type test struct {
	A string `json:"a"`
	B string `json:"b"`
}

func TestNewPatchinator(t *testing.T) {
	// buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
		},
	}

	_, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
	}

	// p.Run(buf)
}

func TestPatchinator_IsWhitelist(t *testing.T) {
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(false)

	if err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run_Regex(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "^/a/.*",
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run_Deny(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
			Deny: true,
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		// t.Error(err)
		t.Error("expected error indicating rule failure")
	}
}

func TestPatchinator_Run_WrongOperation(t *testing.T) {
	buf := []byte(`[{"op":"replace","path":"/a/b","value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"add"},
			Path: "/a/b",
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
	}

	err = p.Run(buf)

	if err == nil {
		t.Error("expected an error for wrong operation")
	}
}

func TestPatchinator_Run_ShouldAllowPass(t *testing.T) {
	buf := []byte(`[{"op":"replace","path":"/a/b","value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return true
			},
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
		return
	}

	err = p.Run(buf)

	if err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run_ShouldAllowFail(t *testing.T) {
	buf := []byte(`[{"op":"replace","path":"/a/b","value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return false
			},
		},
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
		return
	}

	err = p.Run(buf)

	if err == nil {
		t.Error("expected error when none exists")
	}
}

func TestPatchinator_Run_Whitelist(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run_Whitelist_ShouldAllow(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return true
			},
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err != nil {
		t.Error(err)
	}
}

func TestPatchinator_Run_Whitelist_ShouldAllowFail(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return false
			},
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_Run_Whitelist_PathNotInWhitelist(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/c",
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_IsWhitelist_OpMismatch(t *testing.T) {

	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"add"},
			Path: "/a/b",
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_IsWhitelist_ShouldAllowSuccess(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return true
			},
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err != nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_IsWhitelist_ShouldAllowFail(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
			ShouldAllow: func(path string, value interface{}) bool {
				return false
			},
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_IsWhitelist_Deny(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a/b", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace"},
			Path: "/a/b",
			Deny: true,
		},
	}

	p, err := NewPatchinator(rules)
	p.IsWhitelist(true)

	if err != nil {
		t.Error(err)
	}

	if err := p.Run(buf); err == nil {
		t.Errorf("expected no error got %s", err.Error())
	}
}

func TestPatchinator_Apply(t *testing.T) {
	buf := []byte(`[{"op":"replace", "path":"/a", "value":"c"}]`)
	rules := PatchRules{
		PatchRule{
			Op:   []string{"replace", "add"},
			Path: "/a/b",
		},
	}

	original := test{
		A: "b",
		B: "b",
	}

	originalBuf, err := json.Marshal(&original)

	if err != nil {
		t.Error(err)
		return
	}

	p, err := NewPatchinator(rules)

	if err != nil {
		t.Error(err)
		return
	}

	patched, err := p.Apply(buf, originalBuf)

	if err != nil {
		t.Error(err)
		return
	}

	err = json.Unmarshal(patched, &original)

	if err != nil {
		t.Error(err)
		return
	}

	if original.A != "c" {
		t.Error("value should have changed but did not")
		return
	}
}
