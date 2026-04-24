package directive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnwrapShellDashC(t *testing.T) {
	got, ok := UnwrapShellDashC("bash -c 'git status'")
	if !ok || got != "git status" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveFlagToEnv(t *testing.T) {
	got, ok := MoveFlagToEnv("aws --profile read-only-profile s3 ls", "--profile", "AWS_PROFILE")
	if !ok || got != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveFlagToEnvSupportsEqualsForm(t *testing.T) {
	got, ok := MoveFlagToEnv("aws --profile=read-only-profile s3 ls", "--profile", "AWS_PROFILE")
	if !ok || got != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveFlagToEnvPreservesQuotedArgs(t *testing.T) {
	got, ok := MoveFlagToEnv(`aws --profile read-only-profile s3 cp "hello world" s3://bucket/key`, "--profile", "AWS_PROFILE")
	if !ok || got != `AWS_PROFILE=read-only-profile aws s3 cp 'hello world' s3://bucket/key` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveEnvToFlag(t *testing.T) {
	got, ok := MoveEnvToFlag("AWS_PROFILE=read-only-profile aws s3 ls", "AWS_PROFILE", "--profile")
	if !ok || got != "aws --profile read-only-profile s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveEnvToFlagPreservesOtherEnvAssignments(t *testing.T) {
	got, ok := MoveEnvToFlag("FOO=bar AWS_PROFILE=read-only-profile aws s3 ls", "AWS_PROFILE", "--profile")
	if !ok || got != "FOO=bar aws --profile read-only-profile s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveEnvToFlagPreservesEmptyEnvAssignments(t *testing.T) {
	got, ok := MoveEnvToFlag("FOO= AWS_PROFILE=read-only-profile aws s3 ls", "AWS_PROFILE", "--profile")
	if !ok || got != "FOO= aws --profile read-only-profile s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestMoveEnvToFlagPreservesQuotedValues(t *testing.T) {
	got, ok := MoveEnvToFlag(`FOO=bar AWS_PROFILE=read-only-profile aws s3 cp "it's fine" s3://bucket/key`, "AWS_PROFILE", "--profile")
	if !ok || got != `FOO=bar aws --profile read-only-profile s3 cp 'it'"'"'s fine' s3://bucket/key` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestUnwrapWrapper(t *testing.T) {
	got, ok := UnwrapWrapper("env AWS_PROFILE=read-only-profile command exec aws s3 ls", []string{"env", "command", "exec"})
	if !ok || got != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestUnwrapWrapperRejectsEnvOptions(t *testing.T) {
	if _, ok := UnwrapWrapper("env -i aws s3 ls", []string{"env"}); ok {
		t.Fatal("expected unwrap to fail")
	}
}

func TestUnwrapWrapperPreservesQuotedArgs(t *testing.T) {
	got, ok := UnwrapWrapper(`env FOO="hello world" command aws s3 cp "hello world" s3://bucket/key`, []string{"env", "command"})
	if !ok || got != `FOO='hello world' aws s3 cp 'hello world' s3://bucket/key` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestUnwrapWrapperPreservesEmptyEnvAssignments(t *testing.T) {
	got, ok := UnwrapWrapper(`env FOO= command aws s3 ls`, []string{"env", "command"})
	if !ok || got != `FOO= aws s3 ls` {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestStripCommandPath(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "fakecmd")
	t.Setenv("PATH", filepath.Dir(tool))

	got, ok := StripCommandPath(tool + " -R foo")
	if !ok || got != "fakecmd -R foo" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestStripCommandPathPreservesEnvAssignments(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "fakecmd")
	t.Setenv("PATH", filepath.Dir(tool))

	got, ok := StripCommandPath("FOO=bar " + tool + " -R foo")
	if !ok || got != "FOO=bar fakecmd -R foo" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestStripCommandPathRejectsDifferentPathTarget(t *testing.T) {
	original := writeExecutable(t, t.TempDir(), "fakecmd")
	pathTarget := writeExecutable(t, t.TempDir(), "fakecmd")
	t.Setenv("PATH", filepath.Dir(pathTarget))

	if _, ok := StripCommandPath(original + " -R foo"); ok {
		t.Fatal("expected strip_command_path to fail when PATH target differs")
	}
}

func TestStripCommandPathRejectsMissingPathCommand(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "fakecmd")
	t.Setenv("PATH", t.TempDir())

	if _, ok := StripCommandPath(tool + " -R foo"); ok {
		t.Fatal("expected strip_command_path to fail when basename is not on PATH")
	}
}

func TestStripCommandPathRejectsRelativeCommand(t *testing.T) {
	if _, ok := StripCommandPath("ls -R foo"); ok {
		t.Fatal("expected strip_command_path to fail")
	}
}

func writeExecutable(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
