package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"agent-sentinel/audit/llm"
	"text/template"
	"time"
)

type AuditWithoutTrace struct {
	config              Config
	securityQueryClient llm.Client
	securityQueryTempl  *template.Template
	toolUseCtxAnalyzer  *ToolUseCtxAnalyzer
	lastAns             bool
	lastResult          string
}

func NewAuditWithoutTrace(config *Config) (*AuditWithoutTrace, error) {
	audit := &AuditWithoutTrace{
		config: *config,
	}

	systemPrompt := SecurityQueryWithoutTraceSystemPrompt
	switch config.SecurityQueryBaseLLM {
	case AuditBaseLLMCladue35:
		fallthrough
	case AuditBaseLLMCladue37:
		claudeClient, err := llm.NewClaudeClient(config.SecurityQueryBaseLLM, systemPrompt)
		if err != nil {
			log.Error().Err(err).Msg("audit: create claude client failed")
			return nil, err
		}
		audit.securityQueryClient = claudeClient
	case AuditBaseLLMGPT4Turbor:
		fallthrough
	case AuditBaseLLMGPT4o:
		fallthrough
	case AuditBaseLLMGPT61Sol:
		openaiClient, err := llm.NewOpenAIClient(config.SecurityQueryBaseLLM, systemPrompt)
		if err != nil {
			log.Error().Err(err).Msg("audit: create openai client failed")
			return nil, err
		}
		audit.securityQueryClient = openaiClient
	case AuditBaseLLMCustom:
		if config.CustomizedSecurityQueryClient == nil {
			log.Error().Msg("audit: customized security query client is nil")
			return nil, fmt.Errorf("audit: customized security query client is nil")
		}
		audit.securityQueryClient = config.CustomizedSecurityQueryClient
	default:
		log.Error().Msgf("audit: unknown security query client type %d", config.SecurityQueryBaseLLM)
	}

	templ, err := template.New("security_query").Parse(SecurityQueryWithoutTraceTemplate)
	if err != nil {
		log.Error().Err(err).Msg("audit: parse security query template")
		return nil, err
	}
	audit.securityQueryTempl = templ

	toolUseCtxAnalyzer, err := NewToolUseCtxAnalyzer(config.TaskCtxSummarizingBaseLLM, config.CustomizedTaskCtxSummarizingClient)
	if err != nil {
		log.Error().Err(err).Msg("audit: create tool use ctx analyzer failed")
		return nil, err
	}
	audit.toolUseCtxAnalyzer = toolUseCtxAnalyzer

	return audit, nil
}

func (audit *AuditWithoutTrace) Query(toolUseMsg []*ToolUseMessage) (bool, string) {
	answer := true
	result := ""

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	taskCtx := audit.toolUseCtxAnalyzer.SummarizeToolUseCtxRaw(ctx, toolUseMsg)
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 55*time.Second)
	ans, err := audit.queryWithLLM(ctx, taskCtx.TaskInfo, toolUseMsg[len(toolUseMsg)-1].Message)
	cancel()

	if err == nil {
		answer = ans.ActionIsSafe
		result = ans.Result
	}

	if answer {
		log.Debug().Msg("audit: give `tool_use_safe`")
	} else {
		log.Debug().Msg("audit: give `tool_use_unsafe`")
	}

	// only leave enforcement information
	if !answer {
		audit.lastAns = answer
		audit.lastResult = result
	} else {
		audit.lastResult = ""
	}

	return answer, result
}

func (audit *AuditWithoutTrace) queryWithLLM(ctx context.Context, taskDescription string, toolUse string) (*AuditorAnswerWithoutTrace, error) {
	buf := new(bytes.Buffer)

	err := audit.securityQueryTempl.Execute(buf, map[string]string{
		"task":     taskDescription,
		"tool_use": toolUse,
	})

	if err != nil {
		log.Error().Err(err).Msg("audit: execute security query template")
		return nil, err
	}

	// send ctx
	rawJson, err := audit.securityQueryClient.SendTextMessage(ctx, buf.String(), 0)
	if err != nil {
		log.Error().Err(err).Msg("audit: security query client sends message failed")
		return nil, err
	}

	// log.Debug().Msgf("audit: recv message from client: %s", rawJson)

	var answer AuditorAnswerWithoutTrace
	err = json.Unmarshal([]byte(rawJson), &answer)
	if err != nil {
		log.Error().Err(err).Msg("audit: unmarshal answer failed")
		return nil, err
	}

	return &answer, nil
}

func (audit *AuditWithoutTrace) GetLastSafetyCheckResult() (bool, string, error) {
	if audit.lastResult == "" {
		log.Debug().Msg("audit: safety check result is empty")
		return true, "", fmt.Errorf("audit: safety check result is empty")
	}

	return audit.lastAns, audit.lastResult, nil
}
