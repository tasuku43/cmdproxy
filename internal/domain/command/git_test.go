package command

import (
	"reflect"
	"testing"
)

func TestGitParserExtractsActionPathAndGlobalOptions(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		wantGlobal       []Option
		wantAction       []string
		wantOptions      []Option
		wantArgs         []string
		wantRawWords     []string
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
			wantGlobal:       []Option{{Name: "-C", Value: "repo", HasValue: true, Position: 0}},
			wantAction:       []string{"status"},
			wantWorkingDir:   "repo",
			wantStructuredOK: true,
		},
		{
			name:             "no pager",
			raw:              "git --no-pager status",
			wantGlobal:       []Option{{Name: "--no-pager", Position: 0}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "status short option",
			raw:              "git status --short",
			wantAction:       []string{"status"},
			wantOptions:      []Option{{Name: "--short", Position: 1}},
			wantArgs:         []string{},
			wantStructuredOK: true,
		},
		{
			name:             "config",
			raw:              "git -c core.quotePath=false status",
			wantGlobal:       []Option{{Name: "-c", Value: "core.quotePath=false", HasValue: true, Position: 0}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "multiple globals and command option",
			raw:              "git -C repo -c core.quotePath=false status --short",
			wantGlobal:       []Option{{Name: "-C", Value: "repo", HasValue: true, Position: 0}, {Name: "-c", Value: "core.quotePath=false", HasValue: true, Position: 2}},
			wantAction:       []string{"status"},
			wantOptions:      []Option{{Name: "--short", Position: 5}},
			wantArgs:         []string{},
			wantWorkingDir:   "repo",
			wantStructuredOK: true,
		},
		{
			name:             "diff range is positional arg",
			raw:              "git diff main...HEAD",
			wantAction:       []string{"diff"},
			wantArgs:         []string{"main...HEAD"},
			wantRawWords:     []string{"diff", "main...HEAD"},
			wantStructuredOK: true,
		},
		{
			name:             "checkout branch name is positional arg",
			raw:              "git checkout -b feature",
			wantAction:       []string{"checkout"},
			wantOptions:      []Option{{Name: "-b", Position: 1}},
			wantArgs:         []string{"feature"},
			wantStructuredOK: true,
		},
		{
			name:             "git dir and work tree",
			raw:              "git --git-dir .git --work-tree . status",
			wantGlobal:       []Option{{Name: "--git-dir", Value: ".git", HasValue: true, Position: 0}, {Name: "--work-tree", Value: ".", HasValue: true, Position: 2}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "git dir and work tree equals",
			raw:              "git --git-dir=.git --work-tree=. status",
			wantGlobal:       []Option{{Name: "--git-dir", Value: ".git", HasValue: true, Position: 0}, {Name: "--work-tree", Value: ".", HasValue: true, Position: 1}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "namespace and bare",
			raw:              "git --namespace main --bare status",
			wantGlobal:       []Option{{Name: "--namespace", Value: "main", HasValue: true, Position: 0}, {Name: "--bare", Position: 2}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "namespace equals",
			raw:              "git --namespace=main status",
			wantGlobal:       []Option{{Name: "--namespace", Value: "main", HasValue: true, Position: 0}},
			wantAction:       []string{"status"},
			wantStructuredOK: true,
		},
		{
			name:             "double dash before action is not treated as status",
			raw:              "git -C repo -- status",
			wantGlobal:       []Option{{Name: "-C", Value: "repo", HasValue: true, Position: 0}},
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
			if tt.wantArgs != nil && !reflect.DeepEqual(cmd.Args, tt.wantArgs) {
				t.Fatalf("Args = %#v, want %#v", cmd.Args, tt.wantArgs)
			}
			if tt.wantRawWords != nil && !reflect.DeepEqual(cmd.RawWords, tt.wantRawWords) {
				t.Fatalf("RawWords = %#v, want %#v", cmd.RawWords, tt.wantRawWords)
			}
			if cmd.WorkingDirectory != tt.wantWorkingDir {
				t.Fatalf("WorkingDirectory = %q, want %q", cmd.WorkingDirectory, tt.wantWorkingDir)
			}
		})
	}
}

func TestCommandOptionHelpers(t *testing.T) {
	plan := Parse("git -C repo --git-dir=.git status --short --pathspec-from-file=list.txt")
	if len(plan.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]

	if !cmd.HasGlobalOption("-C") {
		t.Fatal("HasGlobalOption(-C) = false, want true")
	}
	if got := cmd.GlobalOptionValues("-C"); !reflect.DeepEqual(got, []string{"repo"}) {
		t.Fatalf("GlobalOptionValues(-C) = %#v, want [repo]", got)
	}
	if got := cmd.GlobalOptionValues("--git-dir"); !reflect.DeepEqual(got, []string{".git"}) {
		t.Fatalf("GlobalOptionValues(--git-dir) = %#v, want [.git]", got)
	}
	if !cmd.HasOption("--short") {
		t.Fatal("HasOption(--short) = false, want true")
	}
	if got := cmd.OptionValues("--pathspec-from-file"); !reflect.DeepEqual(got, []string{"list.txt"}) {
		t.Fatalf("OptionValues(--pathspec-from-file) = %#v, want [list.txt]", got)
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
