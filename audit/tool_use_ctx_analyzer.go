package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"agent-sentinel/audit/llm"
	"text/template"
)

type ToolUseCtxAnalyzer struct {
	taskCtxTempl    *template.Template
	taskCtxSumTempl *template.Template
	prevTaskCtx     *TaskContext
	currentTaskCtx  string
	queryClient     llm.Client
}

func NewToolUseCtxAnalyzer(TaskCtxSummarizingLLMType string, CustomizedTaskCtxSummarizingClient llm.Client) (*ToolUseCtxAnalyzer, error) {
	analyzer := &ToolUseCtxAnalyzer{}

	switch TaskCtxSummarizingLLMType {
	case AuditBaseLLMCladue35:
		fallthrough
	case AuditBaseLLMCladue37:
		claudeClient, err := llm.NewClaudeClient(TaskCtxSummarizingLLMType, TaskContextSummarizingSystemPrompt)
		if err != nil {
			log.Error().Err(err).Msg("audit: create claude client failed")
			return nil, err
		}
		analyzer.queryClient = claudeClient
	case AuditBaseLLMGPT4Turbor:
		fallthrough
	case AuditBaseLLMGPT4o:
		fallthrough
	case AuditBaseLLMGPT61Sol:
		openaiClient, err := llm.NewOpenAIClient(TaskCtxSummarizingLLMType, TaskContextSummarizingSystemPrompt)
		if err != nil {
			log.Error().Err(err).Msg("audit: create openai client failed")
			return nil, err
		}
		analyzer.queryClient = openaiClient
	case AuditBaseLLMCustom:
		if CustomizedTaskCtxSummarizingClient == nil {
			log.Error().Msg("audit: customized task context summarizing client is nil")
			return nil, fmt.Errorf("audit: customized task context summarizing client is nil")
		}
		analyzer.queryClient = CustomizedTaskCtxSummarizingClient
	default:
		log.Error().Msgf("audit: unknown security query client type %s", TaskCtxSummarizingLLMType)
		return nil, fmt.Errorf("audit: unknown security query client type %s", TaskCtxSummarizingLLMType)
	}

	templ, err := template.New("task_ctx").Parse(TaskContextTemplate)
	if err != nil {
		log.Error().Err(err).Msg("audit: parse task context template")
		return nil, err
	}
	analyzer.taskCtxTempl = templ

	templ, err = template.New("task_ctx_sum").Parse(TaskContextSummarizingTemplate)
	if err != nil {
		log.Error().Err(err).Msg("audit: parse task context summarizing template")
		return nil, err
	}
	analyzer.taskCtxSumTempl = templ

	return analyzer, nil
}

func (A *ToolUseCtxAnalyzer) SummarizeToolUseCtxRaw(ctx context.Context, toolUseMsg []*ToolUseMessage) *TaskContext {
	buf := new(bytes.Buffer)

	for {
		prevTaskCtxStr := `{}`
		var taskContextSummary TaskContext

		if A.prevTaskCtx != nil {
			data, err := json.Marshal(A.prevTaskCtx)
			if err != nil {
				log.Error().Err(err).Msg("audit: marshal previous task context summary")
			} else {
				prevTaskCtxStr = string(data)
			}
		}

		conversations, err := json.Marshal(toolUseMsg)
		if err != nil {
			log.Error().Err(err).Msg("audit: marshal tool use messages summary failed")
			break
		}

		err = A.taskCtxSumTempl.Execute(buf, map[string]string{
			"previous_task_context":    prevTaskCtxStr,
			"additional_conversations": string(conversations),
		})

		if err != nil {
			log.Error().Err(err).Msg("audit: execute task context summarizing template failed")
			break
		}

		resp, err := A.queryClient.SendTextMessage(ctx, buf.String(), 0)
		if err != nil {
			log.Error().Err(err).Msg("audit: send task context summarizing failed")
			break
		}

		err = json.Unmarshal([]byte(resp), &taskContextSummary)
		if err != nil {
			// TODO: repeat
			log.Error().Err(err).Msg("audit: unmarshal task context summarizing failed")
			break
		}

		buf.Reset()
		err = A.taskCtxTempl.Execute(buf, map[string]string{
			"task":              taskContextSummary.TaskInfo,
			"tool_use":          taskContextSummary.CurrentToolUse,
			"last_tool_use_msg": toolUseMsg[len(toolUseMsg)-1].Message,
		})

		if err != nil {
			log.Error().Err(err).Msg("audit: execute task context template failed")
			break
		}

		// update prev task context
		A.prevTaskCtx = &taskContextSummary
		A.currentTaskCtx = buf.String()

		// TODO: better struct printer
		log.Debug().Msgf("audit: generate new task context %+v", taskContextSummary)

		return &taskContextSummary
	}

	// task changed in default
	return &TaskContext{
		TaskInfo:       toolUseMsg[len(toolUseMsg)-1].Message,
		CurrentToolUse: toolUseMsg[len(toolUseMsg)-1].Message,
		TaskChanged:    true,
	}
}

func (A *ToolUseCtxAnalyzer) SummarizeToolUseCtx(ctx context.Context, toolUseMsg []*ToolUseMessage) (string, bool) {
	buf := new(bytes.Buffer)

	for {
		prevTaskCtxStr := `{}`
		var taskContextSummary TaskContext

		if A.prevTaskCtx != nil {

			// ignore the field `TaskChanged`
			exTaskCtx := &ExportTaskContext{
				TaskInfo:       A.prevTaskCtx.TaskInfo,
				CurrentToolUse: A.prevTaskCtx.CurrentToolUse,
			}

			data, err := json.Marshal(exTaskCtx)
			if err != nil {
				log.Error().Err(err).Msg("audit: marshal previous task context summary")
			} else {
				prevTaskCtxStr = string(data)
			}
		}

		conversations, err := json.Marshal(toolUseMsg)
		if err != nil {
			log.Error().Err(err).Msg("audit: marshal tool use messages summary failed")
			break
		}

		err = A.taskCtxSumTempl.Execute(buf, map[string]string{
			"previous_task_context":    prevTaskCtxStr,
			"additional_conversations": string(conversations),
		})

		if err != nil {
			log.Error().Err(err).Msg("audit: execute task context summarizing template failed")
			break
		}

		resp, err := A.queryClient.SendTextMessage(ctx, buf.String(), 0)
		if err != nil {
			log.Error().Err(err).Msg("audit: send task context summarizing failed")
			break
		}

		err = json.Unmarshal([]byte(resp), &taskContextSummary)
		if err != nil {
			// TODO: repeat
			log.Error().Err(err).Msg("audit: unmarshal task context summarizing failed")
			break
		}

		buf.Reset()
		err = A.taskCtxTempl.Execute(buf, map[string]string{
			"task":              taskContextSummary.TaskInfo,
			"tool_use":          taskContextSummary.CurrentToolUse,
			"last_tool_use_msg": toolUseMsg[len(toolUseMsg)-1].Message,
		})

		if err != nil {
			log.Error().Err(err).Msg("audit: execute task context template failed")
			break
		}

		// update prev task context
		A.prevTaskCtx = &taskContextSummary
		A.currentTaskCtx = buf.String()

		// TODO: better struct printer
		log.Debug().Msgf("audit: generate new task context %+v", taskContextSummary)

		return A.currentTaskCtx, bool(taskContextSummary.TaskChanged)
	}

	buf.Reset()
	// if query failed, then the last message is used
	_ = A.taskCtxTempl.Execute(buf, map[string]string{
		"task":              toolUseMsg[len(toolUseMsg)-1].Message,
		"tool_use":          toolUseMsg[len(toolUseMsg)-1].Message,
		"last_tool_use_msg": toolUseMsg[len(toolUseMsg)-1].Message,
	})

	// task changed in default
	return buf.String(), true
}

func (A *ToolUseCtxAnalyzer) GetCurrentTaskContext() string {
	return A.currentTaskCtx
}
