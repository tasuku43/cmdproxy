package input

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type ExecRequest struct {
	Action  string `json:"action"`
	Command string `json:"command"`
}

type genericInput struct {
	Action  string `json:"action"`
	Command string `json:"command"`
}

type claudeInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

func Normalize(raw []byte) (ExecRequest, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return ExecRequest{}, errors.New("stdin is empty")
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ExecRequest{}, fmt.Errorf("malformed JSON: %w", err)
	}

	if _, ok := probe["tool_name"]; ok {
		var in claudeInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return ExecRequest{}, fmt.Errorf("invalid Claude Code payload: %w", err)
		}
		if in.ToolName != "Bash" {
			return ExecRequest{}, fmt.Errorf("unsupported tool_name %q", in.ToolName)
		}
		if strings.TrimSpace(in.ToolInput.Command) == "" {
			return ExecRequest{}, errors.New("tool_input.command must be non-empty")
		}
		return ExecRequest{Action: "exec", Command: in.ToolInput.Command}, nil
	}

	if _, ok := probe["action"]; ok {
		var in genericInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return ExecRequest{}, fmt.Errorf("invalid exec payload: %w", err)
		}
		if in.Action != "exec" {
			return ExecRequest{}, fmt.Errorf("action must be exec")
		}
		if strings.TrimSpace(in.Command) == "" {
			return ExecRequest{}, errors.New("command must be non-empty")
		}
		return ExecRequest{Action: "exec", Command: in.Command}, nil
	}

	return ExecRequest{}, errors.New("unsupported input payload")
}
