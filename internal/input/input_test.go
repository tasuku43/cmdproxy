package input

import "testing"

func TestNormalizeGenericExec(t *testing.T) {
	req, err := Normalize([]byte(`{"action":"exec","command":"git status"}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if req.Command != "git status" {
		t.Fatalf("got %q", req.Command)
	}
}

func TestNormalizeClaudeBash(t *testing.T) {
	req, err := Normalize([]byte(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if req.Action != "exec" || req.Command != "git status" {
		t.Fatalf("got %+v", req)
	}
}

func TestNormalizeRejectsUnknownAction(t *testing.T) {
	if _, err := Normalize([]byte(`{"action":"write","command":"x"}`)); err == nil {
		t.Fatal("expected error")
	}
}
