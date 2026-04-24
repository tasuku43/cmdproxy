package invocation

import (
	"reflect"
	"testing"
)

func TestParseUnwrapsCommonWrappers(t *testing.T) {
	parsed := Parse("sudo -u root /usr/bin/env bash -c 'echo hi'")
	if parsed.Command != "bash" {
		t.Fatalf("Command = %q", parsed.Command)
	}
	if len(parsed.Args) < 2 || parsed.Args[0] != "-c" || parsed.Args[1] != "echo hi" {
		t.Fatalf("Args = %#v", parsed.Args)
	}
}

func TestTokensPreserveQuotedPayload(t *testing.T) {
	got := Tokens("bash -c 'git status'")
	if len(got) != 3 || got[2] != "git status" {
		t.Fatalf("Tokens() = %#v", got)
	}
}

func TestJoinRoundTripPreservesQuotedArgs(t *testing.T) {
	command := `aws s3 cp "hello world" s3://bucket/key`

	want := Tokens(command)
	got := Tokens(Join(want))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokens(Join(Tokens(command))) = %#v, want %#v", got, want)
	}
}

func TestJoinRoundTripPreservesEnvAssignmentWithSpaces(t *testing.T) {
	command := `FOO="hello world" env`

	want := Tokens(command)
	got := Tokens(Join(want))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokens(Join(Tokens(command))) = %#v, want %#v", got, want)
	}
}

func TestJoinRoundTripPreservesSingleQuotesInToken(t *testing.T) {
	command := `printf "%s\n" "it's fine"`

	want := Tokens(command)
	got := Tokens(Join(want))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokens(Join(Tokens(command))) = %#v, want %#v", got, want)
	}
}

func TestIsEnvAssignmentAcceptsEmptyValue(t *testing.T) {
	if !IsEnvAssignment("FOO=") {
		t.Fatal("expected empty env assignment to be treated as env assignment")
	}
}

func TestIsSafeSingleCommandRejectsCompoundPayload(t *testing.T) {
	if IsSafeSingleCommand("git status && git diff") {
		t.Fatal("expected safe single command check to fail")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    CommandClass
	}{
		{name: "simple", command: "git status", want: CommandClassSimple},
		{name: "env prefixed", command: "AWS_PROFILE=dev git status", want: CommandClassEnvPrefixedSimple},
		{name: "wrapper prefixed env", command: "env AWS_PROFILE=dev git status", want: CommandClassWrapperPrefixed},
		{name: "wrapper prefixed sudo", command: "sudo -u root git status", want: CommandClassWrapperPrefixed},
		{name: "compound and", command: "git status && rm -rf /tmp/x", want: CommandClassUnsafeCompound},
		{name: "compound semicolon", command: "git status; rm -rf /tmp/x", want: CommandClassUnsafeCompound},
		{name: "pipeline", command: "git status | sh", want: CommandClassUnsafeCompound},
		{name: "redirect", command: "git status > /tmp/out", want: CommandClassUnsafeCompound},
		{name: "command substitution", command: "git status $(whoami)", want: CommandClassUnsafeCompound},
		{name: "comment", command: "git status # harmless", want: CommandClassUnsafeCompound},
		{name: "bash c unsafe", command: "bash -c 'git status && rm -rf /tmp/x'", want: CommandClassUnsafeCompound},
		{name: "bash c redirect", command: "bash -c 'git status > /tmp/out'", want: CommandClassUnsafeCompound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.command); got != tt.want {
				t.Fatalf("Classify(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}
