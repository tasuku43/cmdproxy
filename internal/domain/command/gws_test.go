package command

import "testing"

func TestGwsParserExtractsSemanticFields(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		wantService      string
		wantResourcePath []string
		wantMethod       string
		wantHelper       bool
		wantMutating     bool
		wantDestructive  bool
		wantReadOnly     bool
		wantDryRun       bool
		wantParams       bool
		wantJSONBody     bool
		wantUpload       bool
		wantUnmasked     bool
		wantScope        string
	}{
		{name: "drive list files", raw: `gws drive files list --params '{"pageSize": 5}'`, wantService: "drive", wantResourcePath: []string{"files"}, wantMethod: "list", wantReadOnly: true, wantParams: true},
		{name: "drive get file id", raw: `gws drive files get 1abcDEF`, wantService: "drive", wantResourcePath: []string{"files"}, wantMethod: "get", wantReadOnly: true},
		{name: "drive export file id", raw: `gws drive files export 1abcDEF --mime-type text/plain`, wantService: "drive", wantResourcePath: []string{"files"}, wantMethod: "export"},
		{name: "drive delete files", raw: `gws drive files delete --params '{"fileId":"abc"}'`, wantService: "drive", wantResourcePath: []string{"files"}, wantMethod: "delete", wantMutating: true, wantDestructive: true, wantParams: true},
		{name: "sheets append values", raw: `gws sheets spreadsheets values append --params '{"spreadsheetId":"id"}' --json '{"values":[["A"]]}'`, wantService: "sheets", wantResourcePath: []string{"spreadsheets", "values"}, wantMethod: "append", wantMutating: true, wantParams: true, wantJSONBody: true},
		{name: "gmail helper send", raw: `gws gmail +send --to a@example.com --subject hi --body hello`, wantService: "gmail", wantMethod: "+send", wantHelper: true, wantMutating: true},
		{name: "drive helper upload", raw: `gws drive +upload ./report.pdf --name "Q1 Report"`, wantService: "drive", wantMethod: "+upload", wantHelper: true, wantMutating: true},
		{name: "auth export unmasked", raw: `gws auth export --unmasked`, wantService: "auth", wantMethod: "export", wantUnmasked: true},
		{name: "auth login scopes", raw: `gws auth login --scopes drive,gmail`, wantService: "auth", wantMethod: "login", wantScope: "gmail"},
		{name: "chat create dry run", raw: `gws chat spaces messages create --params '{"parent":"spaces/xyz"}' --json '{"text":"Deploy complete."}' --dry-run`, wantService: "chat", wantResourcePath: []string{"spaces", "messages"}, wantMethod: "create", wantMutating: true, wantDryRun: true, wantParams: true, wantJSONBody: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := singleParsedCommand(t, tt.raw)
			if cmd.Parser != "gws" || cmd.SemanticParser != "gws" || cmd.Gws == nil {
				t.Fatalf("parser state = (%q, %q, %v), want gws semantic", cmd.Parser, cmd.SemanticParser, cmd.Gws)
			}
			got := cmd.Gws
			if got.Service != tt.wantService || got.Method != tt.wantMethod || !sameStrings(got.ResourcePath, tt.wantResourcePath) ||
				got.Helper != tt.wantHelper || got.Mutating != tt.wantMutating || got.Destructive != tt.wantDestructive ||
				got.ReadOnly != tt.wantReadOnly || got.DryRun != tt.wantDryRun || got.Params != tt.wantParams ||
				got.JSONBody != tt.wantJSONBody || got.Upload != tt.wantUpload || got.Unmasked != tt.wantUnmasked {
				t.Fatalf("Gws=%+v, want service=%q resource=%#v method=%q helper=%v mutating=%v destructive=%v read_only=%v dry_run=%v params=%v json=%v upload=%v unmasked=%v",
					got, tt.wantService, tt.wantResourcePath, tt.wantMethod, tt.wantHelper, tt.wantMutating, tt.wantDestructive, tt.wantReadOnly, tt.wantDryRun, tt.wantParams, tt.wantJSONBody, tt.wantUpload, tt.wantUnmasked)
			}
			if tt.wantScope != "" && !containsString(got.Scopes, tt.wantScope) {
				t.Fatalf("Scopes=%#v, want %q", got.Scopes, tt.wantScope)
			}
		})
	}
}

func sameStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
