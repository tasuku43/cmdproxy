package command

import (
	"reflect"
	"testing"
)

func TestGitParserExtractsActionPathAndGlobalOptions(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		wantGlobal       []string
		wantAction       []string
		wantOptions      []string
		wantWorkingDir   string
		wantStructuredOK bool
	}{
		{
			name:             "status",
			raw:              "git status",
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "working directory",
			raw:              "git -C repo status",
			wantGlobal:       []string{"-C=repo"},
			wantAction:       []string{"status"},
			wantWorkingDir:   "repo",
			wantStructuredOK: true,
		},
		{
			name:             "no pager",
			raw:              "git --no-pager status",
			wantGlobal:       []string{"--no-pager"},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "config",
			raw:              "git -c core.quotePath=false status",
			wantGlobal:       []string{"-c=core.quotePath=false"},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "multiple globals and command option",
			raw:              "git -C repo -c core.quotePath=false status --short",
			wantGlobal:       []string{"-C=repo", "-c=core.quotePath=false"},
			wantAction:       []string{"status"},
			wantOptions:      []string{"--short"},
			wantWorkingDir:   "repo",
			wantStructuredOK: true,
		},
		{
			name:             "git dir and work tree",
			raw:              "git --git-dir .git --work-tree . status",
			wantGlobal:       []string{"--git-dir=.git", "--work-tree=."},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "git dir and work tree equals",
			raw:              "git --git-dir=.git --work-tree=. status",
			wantGlobal:       []string{"--git-dir=.git", "--work-tree=."},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "namespace and bare",
			raw:              "git --namespace main --bare status",
			wantGlobal:       []string{"--namespace=main", "--bare"},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "namespace equals",
			raw:              "git --namespace=main status",
			wantGlobal:       []string{"--namespace=main"},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "double dash before action is not treated as status",
			raw:              "git -C repo -- status",
			wantGlobal:       []string{"-C=repo"},
			wantAction:       []string{"--", "status"},
			wantWorkingDir:   "repo",
			wantStructuredOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if len(plan.Commands) != 1 {
				t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
			}
			if plan.SafeForStructuredAllow != tt.wantStructuredOK {
				t.Fatalf("SafeForStructuredAllow = %v, want %v", plan.SafeForStructuredAllow, tt.wantStructuredOK)
			}
			cmd := plan.Commands[0]
			if cmd.Parser != "git" {
				t.Fatalf("Parser = %q, want git", cmd.Parser)
			}
			if cmd.Program != "git" {
				t.Fatalf("Program = %q, want git", cmd.Program)
			}
			if !reflect.DeepEqual(cmd.GlobalOptions, tt.wantGlobal) {
				t.Fatalf("GlobalOptions = %#v, want %#v", cmd.GlobalOptions, tt.wantGlobal)
			}
			if !reflect.DeepEqual(cmd.ActionPath, tt.wantAction) {
				t.Fatalf("ActionPath = %#v, want %#v", cmd.ActionPath, tt.wantAction)
			}
			if !reflect.DeepEqual(cmd.Options, tt.wantOptions) {
				t.Fatalf("Options = %#v, want %#v", cmd.Options, tt.wantOptions)
			}
			if cmd.WorkingDirectory != tt.wantWorkingDir {
				t.Fatalf("WorkingDirectory = %q, want %q", cmd.WorkingDirectory, tt.wantWorkingDir)
			}
		})
	}
}

func TestGitParserDoesNotMakeCompoundStructuredAllowSafe(t *testing.T) {
	plan := Parse("git status && git diff")

	if plan.SafeForStructuredAllow {
		t.Fatal("SafeForStructuredAllow = true, want false")
	}
	if len(plan.Commands) != 2 {
		t.Fatalf("len(Commands) = %d, want 2", len(plan.Commands))
	}
	for _, cmd := range plan.Commands {
		if cmd.Parser != "git" {
			t.Fatalf("Parser = %q, want git", cmd.Parser)
		}
	}
}
