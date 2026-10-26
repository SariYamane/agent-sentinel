package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"agent-sentinel/audit/cache"
	"agent-sentinel/audit/filters"
	"agent-sentinel/audit/llm"
	"agent-sentinel/tracer"
	"strings"
	"sync"
	"text/template"
	"time"
)

type Audit struct {
	securityQueryClient                       llm.Client
	securityQueryTempl                        *template.Template
	toolUseCtxAnalyzer                        *ToolUseCtxAnalyzer
	DNSCache                                  *DNSCache
	cache                                     *cache.ACache
	FileFilter                                *filters.FileEventFilter
	NetFilter                                 *filters.NetEventFilter
	traceCTR                                  *tracePolicy
	lock                                      sync.Mutex
	config                                    *Config
	optimizer                                 *Optimizer
	lastSensitiveOperation                    string
	lastProcessTerminateOpResult              string
	formattedProcessTerminateOpResultTemplate *template.Template
	agentProcessProtector                     *SecureAgentProcess
}

func NewAudit(config *Config) (*Audit, error) {
	audit := &Audit{
		config: config,
	}

	systemPrompt := SecurityQuerySystemPrompt
	//if config.ProcessLevelCache {
	//	systemPrompt = SecurityQuerySystemPromptEnableProcessSafe
	//}

	// set up security query client
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
		log.Error().Msgf("audit: unknown security query client type %s", config.SecurityQueryBaseLLM)
		return nil, fmt.Errorf("audit: unknown security query client type %s", config.SecurityQueryBaseLLM)
	}

	templ, err := template.New("security_query").Parse(SecurityQueryTemplate)
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

	// filters
	fileFilter, err := filters.NewFileEventFilter()
	if err != nil {
		log.Error().Err(err).Msg("audit: create file event filter failed")
		return nil, err
	}
	audit.FileFilter = fileFilter

	netFilter, err := filters.NewNetEventFilter()
	if err != nil {
		log.Error().Err(err).Msg("audit: create net event filter failed")
		return nil, err
	}
	audit.NetFilter = netFilter

	templ, err = templ.New("security_enforcement_result").Parse(SecurityEnforcementResult)
	if err != nil {
		log.Error().Err(err).Msg("audit: parse security enforcement template failed")
	}
	audit.formattedProcessTerminateOpResultTemplate = templ

	// cache
	audit.cache = cache.NewACache()

	return audit, nil
}

func (audit *Audit) EnableDNSCache() *DNSCache {
	if audit.DNSCache != nil {
		return audit.DNSCache
	}

	log.Debug().Msg("audit: DNS cache is enabled")

	audit.DNSCache = NewDNSCache()
	return audit.DNSCache
}

func (audit *Audit) SetTraceInfo(tracer *tracer.Tracer, info *AgentProcessInfo) error {
	if audit.traceCTR != nil {
		log.Error().Msg("audit: trace info info is already set")
		return fmt.Errorf("audit: trace info is already set")
	}

	tp, err := newTracePolicy(tracer, audit.config.ProcessTraceLevel, info.NSPid, info.HostPid)
	if err != nil {
		log.Error().Msg("audit: create trace policy failed")
		return err
	}

	audit.traceCTR = tp

	if audit.config.SecureAgentProcess {
		protector := NewSecureAgentProcess(tracer, info)
		audit.agentProcessProtector = protector
	}

	return nil
}

func (audit *Audit) Start() error {
	if audit.traceCTR == nil {
		log.Error().Msg("audit: trace info is not set")
		return fmt.Errorf("audit: trace info is not set")
	}

	policies := make([]*EnforcePolicy, 0)

	if audit.agentProcessProtector != nil {
		audit.agentProcessProtector.Start()
		policies = append(policies, audit.agentProcessProtector.getRequiredEnforcePolicy())
	}

	err := audit.traceCTR.SetEnforcePolicy(policies)
	if err != nil {
		log.Error().Msg("audit: set default trace policy failed")
		return err
	}

	// TODO: change optimizer place?
	audit.optimizer = NewOptimizer(audit.traceCTR, audit.config.ToolUseTime)

	return nil
}

// Query
// pid: host pid
func (audit *Audit) Query(pid int, sensitiveOp interface{}, traceRecord map[uint32]*ProcessEventTable, toolUseMsg []*ToolUseMessage, newToolUseMsg []*ToolUseMessage) int {
	// TODO: support safely parallel calls
	// audit.lock.Lock()

	// hard audit
	if audit.agentProcessProtector != nil {
		answer, result := audit.agentProcessProtector.Query(pid, sensitiveOp, traceRecord, toolUseMsg, newToolUseMsg)
		if answer != AUDIT_OP_UNKNOWN {
			if answer == AUDIT_OP_RESUME_PROCESS {
				log.Debug().Msg("audit(hard): give `resume_process`")
			} else {
				log.Debug().Msg("audit(hard): give `terminate_process`")
			}

			audit.lastSensitiveOperation = TraceEventToString(sensitiveOp)
			audit.lastProcessTerminateOpResult = result

			return answer
		}
	}

	startTime := time.Now()
	answer := AUDIT_OP_UNKNOWN

	taskCtx := audit.toolUseCtxAnalyzer.GetCurrentTaskContext()
	taskChanged := false

	// Lazy mode: do task summarizing as needed (some sensitive operations occur)
	if len(newToolUseMsg) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), audit.optimizer.getRemainingTime(pid))
		taskCtx, taskChanged = audit.toolUseCtxAnalyzer.SummarizeToolUseCtx(ctx, newToolUseMsg)
		cancel()
	}

	// clean task-level cache
	if taskChanged {
		log.Debug().Msg("audit: flush task-level cache")
		audit.cache.ClearFileOpOnce()
		audit.cache.ClearFileOpTask()
		audit.cache.ClearFileOpPatternTask()
		audit.cache.ClearNetOpOnce()
		audit.cache.ClearNetOpTask()
		audit.cache.ClearSafeBinaryOnce()
		audit.cache.ClearSafeBinaryTask()
	}

	// get necessary information from event and query from cache
	var desc string
	switch t := sensitiveOp.(type) {
	case *tracer.ProcessEvent:
		if audit.config.BinaryLevelCache {
			// Ignore the cmdline
			op := querySafeBinaryCache(t.ExecutablePath, audit.cache)
			if op != AUDIT_OP_NOT_FOUND_IN_CACHE {
				answer = op
				break
			}
		}

		desc = ExecEventToString(t)
		log.Debug().Msgf("audit: new security query for process event %s", desc)
	case *tracer.FileEvent:
		op := QueryFileOperationCache(t, audit.cache, false)
		if op != AUDIT_OP_NOT_FOUND_IN_CACHE {
			answer = op
			break
		}

		desc = FileEventToString(t)
		log.Debug().Msgf("audit: new security query for file event %s", desc)
	case *tracer.SocketEvent:
		domain, _ := audit.DNSCache.IP2Domain(t.RemoteIP)
		op := QueryNetOperationCache(t, domain, audit.cache, false)
		if op != AUDIT_OP_NOT_FOUND_IN_CACHE {
			answer = op
			break
		}

		desc = NetEventToString(t, domain)
		log.Debug().Msgf("audit: new security query for net event %s", desc)
	default:
		log.Error().Msgf("audit: unknown sensitive operation type %T", t)
		return AUDIT_OP_RESUME_PROCESS
	}

	// security query with LLM
	if answer == AUDIT_OP_UNKNOWN {
		tree := audit.NewTransformTraceRecordToProcessTree(uint32(pid), traceRecord)
		treeRaw, err := json.Marshal(tree)
		if err != nil {
			log.Error().Err(err).Msg("audit: json marshal failed")
			return AUDIT_OP_RESUME_PROCESS
		}
		treeStr := string(treeRaw)
		log.Debug().Msgf("audit: generated process tree %s", treeStr)

		ctx, cancel := context.WithTimeout(context.Background(), audit.optimizer.getRemainingTime(pid))
		ans, err := audit.queryWithLLM(ctx, desc, treeStr, taskCtx)
		cancel()

		if err != nil {
			answer = AUDIT_OP_RESUME_PROCESS
		} else {
			if ans.ActionIsSafe {
				answer = AUDIT_OP_RESUME_PROCESS
			} else {
				answer = AUDIT_OP_TERMINATE_PROCESS

				audit.lastSensitiveOperation = TraceEventToString(sensitiveOp)
				audit.lastProcessTerminateOpResult = ans.Result
			}
		}
	}

	if answer == AUDIT_OP_RESUME_PROCESS {
		log.Debug().Msg("audit: give `resume_process`")
	} else {
		log.Debug().Msg("audit: give `terminate_process`")
	}

	if audit.optimizer != nil && pid != 0 {
		queryTime := time.Now().Sub(startTime)
		log.Debug().Msgf("audit: query time %f", queryTime.Seconds())
		audit.optimizer.timeAccumulating(pid, queryTime)
		audit.optimizer.removeTimeCountIfTimeout(pid)
	}

	// audit.lock.Unlock()

	// TODO: remove verified files/networks
	return answer
}

// stripMarkdownCodeFence removes a surrounding ```json ... ``` (or plain
// ``` ... ```) code fence from an LLM response, if present. Despite being
// asked for raw JSON, some models still wrap their answer in a markdown
// code block, which would otherwise make json.Unmarshal fail and the
// auditor silently fail open (see queryWithLLM's caller) even though the
// model's actual verdict was successfully generated.
func stripMarkdownCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}

	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	// drop an optional language identifier on the first line (e.g. "json")
	if nl := strings.IndexByte(s, '\n'); nl != -1 {
		firstLine := strings.TrimSpace(s[:nl])
		if firstLine != "" && !strings.ContainsAny(firstLine, "{[\"") {
			s = strings.TrimSpace(s[nl+1:])
		}
	}

	return s
}

func (audit *Audit) queryWithLLM(ctx context.Context, sensitiveOp string, systemTrace string, taskDescription string) (*AuditorAnswer, error) {
	buf := new(bytes.Buffer)

	err := audit.securityQueryTempl.Execute(buf, map[string]string{
		"task":         taskDescription,
		"sensitive_op": sensitiveOp,
		"system_trace": systemTrace,
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

	rawJson = stripMarkdownCodeFence(rawJson)

	var answer AuditorAnswer
	err = json.Unmarshal([]byte(rawJson), &answer)
	if err != nil {
		log.Error().Err(err).Msg("audit: unmarshal answer failed")
		return nil, err
	}

	addAuditorAnswerToCache(&answer, audit.cache, audit.config.BinaryLevelCache)

	return &answer, nil
}

func (audit *Audit) GetLastFormattedProcessTerminateOpResult() (string, error) {
	buf := new(bytes.Buffer)

	if audit.lastProcessTerminateOpResult == "" {
		return "", fmt.Errorf("audit: no recent process terminate operation")
	}

	// FIXME: reset lastProcessTerminateOpResult after every tool use
	err := audit.formattedProcessTerminateOpResultTemplate.Execute(buf, map[string]string{
		"sensitive_op": audit.lastSensitiveOperation,
		"result":       audit.lastProcessTerminateOpResult,
	})
	if err != nil {
		log.Error().Err(err).Msg("audit: execute security enforcement template failed")
		return "", err
	}

	return buf.String(), nil
}

func (audit *Audit) NotifyNewToolUse(msgs []*ToolUseMessage) {
	// reset result from previous security queries for other tool uses.
	audit.lastProcessTerminateOpResult = ""
	audit.lastSensitiveOperation = ""
}

func (audit *Audit) NotifyProcessFork(e *tracer.ProcessEvent) {
	if audit.traceCTR == nil {
		return
	}

	// TODO: keep ns tgid???
	audit.traceCTR.NotifyProcessFork(int(e.ParentTgid), int(e.ChildTgid))
}

func (audit *Audit) NotifyProcessExec(e *tracer.ProcessEvent) {
	if audit.traceCTR == nil {
		return
	}

	audit.traceCTR.NotifyProcessExec(int(e.ChildTgid))
}

func (audit *Audit) NotifyProcessExit(e *tracer.ProcessEvent) {
	if audit.traceCTR == nil {
		return
	}

	audit.traceCTR.NotifyProcessExit(int(e.ChildTgid))
}

func (audit *Audit) FilterFileEvent(e *tracer.FileEvent) bool {
	if audit.FileFilter == nil {
		return false
	}

	return audit.FileFilter.Filter(e)
}

func (audit *Audit) FilterNetEvent(e *tracer.SocketEvent) bool {
	if audit.NetFilter == nil {
		return false
	}

	return audit.NetFilter.Filter(e)
}

func (audit *Audit) GetEventCountLimit() int {
	return audit.config.EventCountLimit
}
