package directive

import "testing"

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

func TestStripCommandPath(t *testing.T) {
	got, ok := StripCommandPath("/bin/ls -R foo")
	if !ok || got != "ls -R foo" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestStripCommandPathPreservesEnvAssignments(t *testing.T) {
	got, ok := StripCommandPath("FOO=bar /bin/ls -R foo")
	if !ok || got != "FOO=bar ls -R foo" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestStripCommandPathRejectsRelativeCommand(t *testing.T) {
	if _, ok := StripCommandPath("ls -R foo"); ok {
		t.Fatal("expected strip_command_path to fail")
	}
}
