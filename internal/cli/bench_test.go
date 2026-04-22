package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkEvaluateRequestWithSmallConfig(b *testing.B) {
	home := b.TempDir()
	cacheHome := b.TempDir()
	writeUserConfigBenchmark(b, home, benchmarkConfig(10, 4))
	streams := Streams{
		Stdin:  bytes.NewBuffer(nil),
		Stdout: bytes.NewBuffer(nil),
		Stderr: bytes.NewBuffer(nil),
	}
	env := Env{Cwd: b.TempDir(), Home: home, XDGCacheHome: cacheHome}
	reqJSON := []byte(`{"tool_name":"Bash","tool_input":{"command":"git -C repos/foo status"}}`)

	if code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  bytes.NewReader(reqJSON),
		Stdout: bytes.NewBuffer(nil),
		Stderr: bytes.NewBuffer(nil),
	}, env); code != 0 {
		b.Fatalf("unexpected warmup code %d", code)
	}

	b.ResetTimer()
	for b.Loop() {
		streams.Stdout = bytes.NewBuffer(nil)
		streams.Stderr = bytes.NewBuffer(nil)
		code := Run([]string{"hook", "claude"}, Streams{
			Stdin:  bytes.NewReader(reqJSON),
			Stdout: streams.Stdout,
			Stderr: streams.Stderr,
		}, env)
		if code != 0 {
			b.Fatalf("unexpected code %d", code)
		}
	}
}

func BenchmarkEvaluateRequestWithLargeConfig(b *testing.B) {
	home := b.TempDir()
	cacheHome := b.TempDir()
	writeUserConfigBenchmark(b, home, benchmarkConfig(200, 20))
	env := Env{Cwd: b.TempDir(), Home: home, XDGCacheHome: cacheHome}
	reqJSON := []byte(`{"tool_name":"Bash","tool_input":{"command":"git -C repos/foo status"}}`)

	if code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  bytes.NewReader(reqJSON),
		Stdout: bytes.NewBuffer(nil),
		Stderr: bytes.NewBuffer(nil),
	}, env); code != 0 {
		b.Fatalf("unexpected warmup code %d", code)
	}

	b.ResetTimer()
	for b.Loop() {
		code := Run([]string{"hook", "claude"}, Streams{
			Stdin:  bytes.NewReader(reqJSON),
			Stdout: bytes.NewBuffer(nil),
			Stderr: bytes.NewBuffer(nil),
		}, env)
		if code != 0 {
			b.Fatalf("unexpected code %d", code)
		}
	}
}

func benchmarkConfig(ruleCount, examplesPerRule int) string {
	var buf bytes.Buffer
	buf.WriteString("permission:\n")
	buf.WriteString("  deny:\n")
	for i := 0; i < ruleCount; i++ {
		if i == ruleCount-1 {
			buf.WriteString("    - match:\n")
			buf.WriteString("        command: git\n")
			buf.WriteString("        args_contains:\n")
			buf.WriteString("          - \"-C\"\n")
		} else {
			buf.WriteString("    - match:\n")
			fmt.Fprintf(&buf, "        command: command-%d\n", i)
		}
		if i == ruleCount-1 {
			buf.WriteString("      message: \"git -C is blocked. cd into the repo first.\"\n")
		} else {
			fmt.Fprintf(&buf, "      message: \"command-%d is blocked. use a safer alternative instead.\"\n", i)
		}
		buf.WriteString("      test:\n")
		buf.WriteString("        deny:\n")
		for j := 0; j < examplesPerRule; j++ {
			if i == ruleCount-1 && j == 0 {
				buf.WriteString("          - \"git -C repos/foo status\"\n")
				continue
			}
			fmt.Fprintf(&buf, "          - \"command-%d example-%d\"\n", i, j)
		}
		buf.WriteString("        pass:\n")
		for j := 0; j < examplesPerRule; j++ {
			fmt.Fprintf(&buf, "          - \"safe-command-%d-%d\"\n", i, j)
		}
	}
	buf.WriteString("test:\n")
	buf.WriteString("  - in: \"git -C repos/foo status\"\n")
	buf.WriteString("    decision: deny\n")
	return buf.String()
}

func writeUserConfigBenchmark(b *testing.B, home string, body string) {
	b.Helper()
	path := filepath.Join(home, ".config", "cmdproxy", "cmdproxy.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		b.Fatal(err)
	}
}
