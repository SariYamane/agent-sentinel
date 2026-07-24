package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"io"
	"agent-sentinel/api"
	"agent-sentinel/audit"
	"agent-sentinel/helper"
	"agent-sentinel/tracer"
	"sync"
	"time"
)

const (
	stopEventHandling     = 0
	finishedEventHandling = 1
)

type Handler struct {
	ctx                  context.Context
	tracer               *tracer.Tracer
	passiveMode          bool
	passiveTracing       *PassiveTracing
	currentActiveTracing *ActiveTracing
	dnsEventCh           <-chan interface{}
	startTracing         bool
	handlerName          string
	nsRootPid            int
	hostRootPid          int
	pidNS                int
	enableDNSCache       bool
	dnsCache             *audit.DNSCache
	audit                *audit.Audit
	enableAudit          bool
	// FIXME: how to handle stop, stop, stop....
	inProcessingMu sync.Mutex
	inProcessing   map[int]bool

	// knownPids tracks pids that are currently traced (from fork/exec to
	// exit), so the orphan-stop watchdog knows which pids to check.
	knownPidsMu sync.Mutex
	knownPids   map[int]struct{}
}

func NewHandler(pidNS int, auditor *audit.Audit) (*Handler, error) {
	h := &Handler{
		startTracing: false,
		pidNS:        pidNS,
		audit:        auditor,
		enableAudit:  true,
		inProcessing: make(map[int]bool),
		knownPids:    make(map[int]struct{}),
	}

	// FIXME: audit may not required
	if auditor == nil {
		log.Error().Msg("handler: auditor is nil")
		return nil, fmt.Errorf("handler: auditor is nil")
	}

	id, err := uuid.NewUUID()
	if err != nil {
		log.Error().Err(err).Msg("handler: generate UUID failed")
		return nil, err
	}
	h.handlerName = id.String()

	return h, nil
}

func (h *Handler) DisableAudit() {
	h.enableAudit = false
}

func (h *Handler) SetTracer(tracer *tracer.Tracer) {
	h.tracer = tracer
}

func (h *Handler) EnableDNSCache() {
	h.enableDNSCache = true
}

func (h *Handler) Start(ctx context.Context) error {
	h.ctx = ctx

	if h.tracer == nil {
		return fmt.Errorf("handler: require tracer")
	}

	if !h.tracer.HasTracer(tracer.DNSTracer) && h.enableDNSCache {
		log.Error().Msg("handler: dns tracer is unavailable")
		return fmt.Errorf("handler: dns tracer is unavailable")
	}

	if h.enableDNSCache {
		ch, err := h.tracer.AddSubscriber(tracer.DNSTracer, h.handlerName)
		if err != nil {
			log.Error().Err(err).Msg("handler: register dns event subscriber failed")
		}

		h.dnsEventCh = ch
		// TODO: hide audit filed access
		h.dnsCache = h.audit.EnableDNSCache()
		go h.handleDNSEvent()
	}

	return nil
}

func (h *Handler) Close() {
	_ = h.tracer.DeleteSubscriber(tracer.DNSTracer, h.handlerName)
	if h.passiveMode {
		h.stopPassiveTracing()
	}
}

func (h *Handler) handleDNSEvent() {
	for {
		select {
		case e, ok := <-h.dnsEventCh:
			if !ok {
				return
			}
			if e, ok := e.(*tracer.DNSEvent); ok {
				h.dnsCache.AddDNSRecord(e)
			}
			break
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) handleTraceEvent(ctrCh chan int, chs *TraceChannel, eventCallback *TraceEventCallback, cb *callbackChannel) {
	var timeCh <-chan time.Time

	for {
		select {
		case e := <-chs.processEventCh:
			if e, ok := e.(*tracer.ProcessEvent); ok {
				if eventCallback != nil && eventCallback.processEventCallback != nil {
					eventCallback.processEventCallback(e)
				}
			}
			break
		case e := <-chs.readlineEventCh:
			if e, ok := e.(*tracer.ReadlineEvent); ok {
				if eventCallback != nil && eventCallback.readlineEventCallback != nil {
					eventCallback.readlineEventCallback(e)
				}
			}
			break
		case e := <-chs.netEventCh:
			if e, ok := e.(*tracer.SocketEvent); ok {
				if eventCallback != nil && eventCallback.netEventCallback != nil {
					eventCallback.netEventCallback(e)
				}
			}
			break
		case e := <-chs.fileEventCh:
			if e, ok := e.(*tracer.FileEvent); ok {
				if eventCallback != nil && eventCallback.fileEventCallback != nil {
					eventCallback.fileEventCallback(e)
				}
			}
			break
		// stop event handling
		case _ = <-ctrCh:
			// fixme: better waiting strategy
			timeCh = time.After(100 * time.Millisecond)
			break
		case _ = <-timeCh:
			ctrCh <- finishedEventHandling
			return
		// it can maintain the record without a lock
		case <-cb.ch:
			cb.callback()
			break
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) NewConnectHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		reader := bytes.NewReader(msg.Data)
		decoder := json.NewDecoder(reader)

		var agentProcessInfo audit.AgentProcessInfo

		for {
			err := decoder.Decode(&agentProcessInfo)
			if err == io.EOF {
				break
			} else if err != nil {
				log.Error().Err(err).Msgf("handler: unmarshal tool use failed, data: %s", string(msg.Data))
				return &api.ComputerMonitorCallbackResponse{
					Close: true,
				}
			}
		}

		log.Debug().Msgf("handler: new connect message %+v", agentProcessInfo)

		// check the target process if exists
		pid, err := helper.GetHostPID(agentProcessInfo.NSPid, h.pidNS)
		if err != nil {
			log.Error().Err(err).Msg("handler: root pid is invalid")
			return &api.ComputerMonitorCallbackResponse{
				Close: true,
			}
		}
		agentProcessInfo.HostPid = pid

		log.Debug().Msgf("handler: root pid is %d and host root pid is %d", agentProcessInfo.NSPid, agentProcessInfo.HostPid)

		h.hostRootPid = agentProcessInfo.HostPid
		h.nsRootPid = agentProcessInfo.NSPid
		h.trackKnownPid(h.hostRootPid)

		err = h.audit.SetTraceInfo(h.tracer, &agentProcessInfo)
		if err != nil {
			log.Error().Err(err).Msg("handler: set trace info for audit failed")
		}

		err = h.tracer.AddInterestingPID(uint32(pid), true)
		if err != nil {
			log.Error().Err(err).Msg("handler: add interesting pid failed")
		}

		return api.CreateEmptyComputerMonitorMessageResponse()
	}
}

func (h *Handler) NewStartTracingHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		log.Debug().Msgf("handler: handle start tracing")

		// do not restart
		if h.startTracing {
			return &api.ComputerMonitorCallbackResponse{}
		}
		h.startTracing = true

		id, err := uuid.NewUUID()
		if err != nil {
			log.Error().Err(err).Msg("handler: generate UUID failed")
		}

		name := id.String()
		tracerCh := h.createTraceChannel(name)

		// TODO: save previous records
		activeTracing := &ActiveTracing{
			name:              id.String(),
			ch:                tracerCh,
			record:            map[uint32]*audit.ProcessEventTable{},
			ctrEvenHandlingCh: make(chan int),
		}

		h.currentActiveTracing = activeTracing

		eventCallback := &TraceEventCallback{
			fileEventCallback: func(e *tracer.FileEvent) {
				procTable, ok := activeTracing.record[e.Tgid]
				if ok {
					procTable.AddFileEvent(e)
				}
			},
			processEventCallback: func(e *tracer.ProcessEvent) {
				if e.Type != tracer.ProcessEventTypeFork && e.Type != tracer.ProcessEventTypeExec {
					return
				}

				if e.Type == tracer.ProcessEventTypeFork {
					procTable := audit.NewProcessEventTable()
					activeTracing.record[e.ChildTgid] = procTable
				} else {
					if procTable, ok := activeTracing.record[e.ChildTgid]; ok {
						procTable.SetExecEvent(e)
					}
				}
			},
			readlineEventCallback: func(e *tracer.ReadlineEvent) {
				procTable, ok := activeTracing.record[e.Tgid]
				if ok {
					procTable.AddReadlineEvent(e)
				}
			},
			netEventCallback: func(e *tracer.SocketEvent) {
				procTable, ok := activeTracing.record[e.Tgid]
				if ok {
					procTable.AddNetEvent(e)
				}
			},
		}

		defaultCallback := &callbackChannel{
			ch:       make(chan bool),
			callback: nil,
		}

		go h.handleTraceEvent(activeTracing.ctrEvenHandlingCh, activeTracing.ch, eventCallback, defaultCallback)

		return api.CreateEmptyComputerMonitorMessageResponse()
	}
}

func (h *Handler) NewStopTracingHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		if !h.startTracing {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}
		h.startTracing = false

		log.Debug().Msgf("handler: handle stop tracing")

		h.currentActiveTracing.ctrEvenHandlingCh <- stopEventHandling
		<-h.currentActiveTracing.ctrEvenHandlingCh

		if h.currentActiveTracing.ch.processEventCh != nil {
			_ = h.tracer.DeleteSubscriber(tracer.ProcessTracer, h.currentActiveTracing.name)
		}

		if h.currentActiveTracing.ch.readlineEventCh != nil {
			_ = h.tracer.DeleteSubscriber(tracer.ReadlineTracer, h.currentActiveTracing.name)
		}

		if h.currentActiveTracing.ch.fileEventCh != nil {
			_ = h.tracer.DeleteSubscriber(tracer.FileTracer, h.currentActiveTracing.name)
		}

		if h.currentActiveTracing.ch.netEventCh != nil {
			_ = h.tracer.DeleteSubscriber(tracer.SocketTracer, h.currentActiveTracing.name)
		}

		return api.CreateEmptyComputerMonitorMessageResponse()
	}
}

func (h *Handler) NewGetLastTraceRecordHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		log.Debug().Msgf("handler: handle get last trace record")

		if h.currentActiveTracing == nil {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		// FIXME: process tree
		// tree := h.audit.NewTransformTraceRecordToProcessTree(h.currentActiveTracing.record)
		tree := &audit.ProcessTree{}
		data, err := json.Marshal(tree)

		log.Debug().Msgf("handler: handle get last trace record, data: %s", string(data))

		if err != nil {
			log.Error().Err(err).Msg("handler: marshal tree failed")
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		return &api.ComputerMonitorCallbackResponse{
			Close: false,
			Data:  data,
		}
	}
}

func (h *Handler) TakeDecisionByAudit(pid int, event interface{}, traceRecord map[uint32]*audit.ProcessEventTable, toolUseCtx []*audit.ToolUseMessage, newToolUseMsg []*audit.ToolUseMessage) {
	h.markInProcessing(pid)
	defer h.clearInProcessing(pid)

	if h.audit.Query(pid, event, traceRecord, toolUseCtx, newToolUseMsg) == audit.AUDIT_OP_RESUME_PROCESS {
		if err := resumeProcessReliably(pid); err != nil {
			log.Error().Err(err).Msg("handler: resume process failed")
		}
	} else {
		if err := terminateProcess(pid); err != nil {
			log.Error().Err(err).Msg("handler: terminate process failed")
		}
	}
}

func (h *Handler) markInProcessing(pid int) {
	h.inProcessingMu.Lock()
	h.inProcessing[pid] = true
	h.inProcessingMu.Unlock()
}

func (h *Handler) clearInProcessing(pid int) {
	h.inProcessingMu.Lock()
	delete(h.inProcessing, pid)
	h.inProcessingMu.Unlock()
}

func (h *Handler) isInProcessing(pid int) bool {
	h.inProcessingMu.Lock()
	defer h.inProcessingMu.Unlock()
	return h.inProcessing[pid]
}

func (h *Handler) trackKnownPid(pid int) {
	h.knownPidsMu.Lock()
	h.knownPids[pid] = struct{}{}
	h.knownPidsMu.Unlock()
}

func (h *Handler) untrackKnownPid(pid int) {
	h.knownPidsMu.Lock()
	delete(h.knownPids, pid)
	h.knownPidsMu.Unlock()
}

func (h *Handler) knownPidsSnapshot() []int {
	h.knownPidsMu.Lock()
	defer h.knownPidsMu.Unlock()

	pids := make([]int, 0, len(h.knownPids))
	for pid := range h.knownPids {
		pids = append(pids, pid)
	}
	return pids
}

// startOrphanStopWatchdog periodically looks for traced processes that are
// stuck in the kernel's stopped state (T) with no in-flight audit decision
// for them. This can happen when an eBPF probe's bpf_send_signal(SIGSTOP)
// is never followed by a matching ring buffer event reaching this process
// (or is followed by one whose resume race is lost, see
// resumeProcessReliably) — in either case, nothing is ever going to send a
// SIGCONT for that specific process again, so it would otherwise be stuck
// forever. Processes with an audit currently in flight are skipped so we
// never resume a process before its security decision has actually been
// made.
func (h *Handler) startOrphanStopWatchdog() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.sweepOrphanedStops()
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) sweepOrphanedStops() {
	for _, pid := range h.knownPidsSnapshot() {
		if h.isInProcessing(pid) {
			continue
		}

		state, err := readProcessState(pid)
		if err != nil || state != "T" {
			continue
		}

		log.Warn().Msgf("handler: watchdog found orphaned stopped process %d with no in-flight audit, resuming", pid)
		if err := resumeProcess(pid); err != nil {
			log.Error().Err(err).Msgf("handler: watchdog failed to resume process %d", pid)
		}
	}
}

func (h *Handler) handlePassiveTracing() {
	resetRecord := &callbackChannel{
		ch: make(chan bool),
		callback: func() {
			h.passiveTracing.record = map[uint32]*audit.ProcessEventTable{}
		},
	}

	// ask for audit if only the process is stopped
	eventCallback := &TraceEventCallback{
		processEventCallback: func(e *tracer.ProcessEvent) {
			// TODO: process filter

			if e.Type == tracer.ProcessEventTypeExit {
				// nodify the audit
				h.audit.NotifyProcessExit(e)

				h.untrackKnownPid(int(e.ChildTgid))

				// notice parent process that child process exited
				if procTable, ok := h.passiveTracing.record[e.ParentTgid]; ok {
					procTable.DecAliveChildProcess()
				}

				// delete it if all its child processes have been exited
				if procTable, ok := h.passiveTracing.record[e.ChildTgid]; ok {
					if procTable.AreAllChildProcessExited() {
						delete(h.passiveTracing.record, e.ChildTgid)
					}
				}

				return
			} else if e.Type == tracer.ProcessEventTypeFork {
				h.audit.NotifyProcessFork(e)
				procTable := audit.NewProcessEventTable()
				h.passiveTracing.record[e.ChildTgid] = procTable
				procTable.SetExecEvent(e)

				h.trackKnownPid(int(e.ChildTgid))

				if parent, ok := h.passiveTracing.record[e.ParentTgid]; ok {
					parent.IncAliveChildProcess()
				}
			} else if e.Type == tracer.ProcessEventTypeExec {
				h.audit.NotifyProcessExec(e)
				procTable, ok := h.passiveTracing.record[e.ChildTgid]
				if ok {
					procTable.SetExecEvent(e)
				}
			}

			// tracer.ProcessEventTypeBprmCheck is only the stop point
			if e.Flag&tracer.EventFlagProcessStopped == tracer.EventFlagProcessStopped {
				h.passiveTracing.toolUseMsgRequestCh <- true
				newToolUseMsg := <-h.passiveTracing.toolUseMsgReceiverCh

				// for thread-safe
				record := audit.CopyTraceRecord(h.passiveTracing.record)

				// Why `go` here ???
				// To can handle events from multiple processes.
				go h.TakeDecisionByAudit(int(e.ChildTgid), e, record, newToolUseMsg, newToolUseMsg)
			}
		},
		readlineEventCallback: func(e *tracer.ReadlineEvent) {
			procTable, ok := h.passiveTracing.record[e.Tgid]
			if ok {
				procTable.AddReadlineEvent(e)
			}
		},
		netEventCallback: func(e *tracer.SocketEvent) {
			if h.audit.FilterNetEvent(e) {
				if e.Flag&tracer.EventFlagProcessStopped == tracer.EventFlagProcessStopped {
					log.Debug().Msgf("handler: resume process from the filter")
					_ = resumeProcessReliably(int(e.Tgid))
				}
				return
			}

			if e.Flag&tracer.EventFlagProcessStopped == tracer.EventFlagProcessStopped {
				h.passiveTracing.toolUseMsgRequestCh <- true
				newToolUseMsg := <-h.passiveTracing.toolUseMsgReceiverCh

				// for thread-safe
				record := audit.CopyTraceRecord(h.passiveTracing.record)

				go h.TakeDecisionByAudit(int(e.Tgid), e, record, h.passiveTracing.curToolUseMsg, newToolUseMsg)
			}

			procTable, ok := h.passiveTracing.record[e.Tgid]
			if ok {
				procTable.AddNetEvent(e)
			}
		},
		fileEventCallback: func(e *tracer.FileEvent) {
			if h.audit.FilterFileEvent(e) {
				if e.Flag&tracer.EventFlagProcessStopped == tracer.EventFlagProcessStopped {
					log.Debug().Msgf("handler: resume process from the filter")
					_ = resumeProcessReliably(int(e.Tgid))
				}
				return
			}

			if e.Flag&tracer.EventFlagProcessStopped == tracer.EventFlagProcessStopped {
				h.passiveTracing.toolUseMsgRequestCh <- true
				newToolUseMsg := <-h.passiveTracing.toolUseMsgReceiverCh

				// for thread-safe
				record := audit.CopyTraceRecord(h.passiveTracing.record)

				go h.TakeDecisionByAudit(int(e.Tgid), e, record, h.passiveTracing.curToolUseMsg, newToolUseMsg)
			}

			procTable, ok := h.passiveTracing.record[e.Tgid]
			if ok {
				procTable.AddFileEvent(e)
			}
		},
	}

	// start collecting events
	go h.handleTraceEvent(h.passiveTracing.ctrEvenHandlingCh, h.passiveTracing.ch, eventCallback, resetRecord)

	for {
		select {
		case msg := <-h.passiveTracing.toolUseMsgProducerCh:
			// clear record for previous tool use
			resetRecord.ch <- true
			// TODO: may add preserve old one?
			h.passiveTracing.curToolUseMsg = msg
			h.passiveTracing.unusedToolUseMsg = append(h.passiveTracing.unusedToolUseMsg, msg...)
		case <-h.passiveTracing.toolUseMsgRequestCh:
			// consume saved context messages
			h.passiveTracing.toolUseMsgReceiverCh <- h.passiveTracing.unusedToolUseMsg
			h.passiveTracing.unusedToolUseMsg = make([]*audit.ToolUseMessage, 0)
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) stopPassiveTracing() {
	log.Info().Msg("handler: stop passive tracing")
	h.passiveTracing.ctrEvenHandlingCh <- stopEventHandling
	<-h.passiveTracing.ctrEvenHandlingCh

	if h.passiveTracing.ch.processEventCh != nil {
		_ = h.tracer.DeleteSubscriber(tracer.ProcessTracer, h.passiveTracing.name)
	}

	if h.passiveTracing.ch.readlineEventCh != nil {
		_ = h.tracer.DeleteSubscriber(tracer.ReadlineTracer, h.passiveTracing.name)
	}

	if h.passiveTracing.ch.fileEventCh != nil {
		_ = h.tracer.DeleteSubscriber(tracer.FileTracer, h.passiveTracing.name)
	}

	if h.passiveTracing.ch.netEventCh != nil {
		_ = h.tracer.DeleteSubscriber(tracer.SocketTracer, h.passiveTracing.name)
	}
}

func (h *Handler) NewStartPassiveTracingHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		if h.passiveMode {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}
		h.passiveMode = true

		log.Info().Msgf("handler: start passive tracing")

		id, err := uuid.NewUUID()
		if err != nil {
			log.Error().Err(err).Msg("handler: generate UUID failed")
		}

		name := id.String()
		tracerCh := h.createTraceChannel(name)

		// TODO: save previous records
		h.passiveTracing = &PassiveTracing{
			name:                 name,
			ch:                   tracerCh,
			record:               make(map[uint32]*audit.ProcessEventTable),
			ctrEvenHandlingCh:    make(chan int),
			unusedToolUseMsg:     make([]*audit.ToolUseMessage, 0),
			curToolUseMsg:        make([]*audit.ToolUseMessage, 0),
			toolUseMsgProducerCh: make(chan []*audit.ToolUseMessage),
			toolUseMsgReceiverCh: make(chan []*audit.ToolUseMessage),
			toolUseMsgRequestCh:  make(chan bool),
		}

		// TODO: save previous records

		if h.enableAudit {
			err = h.audit.Start()
			if err != nil {
				log.Error().Err(err).Msg("handler: audit start failed")
			}
		}

		go h.handlePassiveTracing()
		go h.startOrphanStopWatchdog()

		return api.CreateEmptyComputerMonitorMessageResponse()
	}
}

func (h *Handler) NewSendToolUseHandler() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		if !h.passiveMode {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		reader := bytes.NewReader(msg.Data)
		decoder := json.NewDecoder(reader)

		toolUseMsg := make([]*audit.ToolUseMessage, 0)

		for {
			err := decoder.Decode(&toolUseMsg)
			if err == io.EOF {
				break
			} else if err != nil {
				log.Error().Err(err).Msgf("handler: unmarshal tool use failed, data: %s", string(msg.Data))
				return api.CreateEmptyComputerMonitorMessageResponse()
			}
		}

		log.Debug().Msgf("handler: accept tool use message: %+q", toolUseMsg)

		h.passiveTracing.toolUseMsgProducerCh <- toolUseMsg
		h.audit.NotifyNewToolUse(toolUseMsg)

		return api.CreateEmptyComputerMonitorMessageResponse()
	}
}

func (h *Handler) NewGetLastEnforcementResult() api.ComputerMonitorMessageCallback {
	return func(op int16, msg *api.ComputerMonitorMessage) *api.ComputerMonitorCallbackResponse {
		// only enabled if passive mode is enabled
		if !h.passiveMode {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		log.Debug().Msgf("handler: accept get_last_enforement_result request")

		res, err := h.audit.GetLastFormattedProcessTerminateOpResult()
		if err != nil {
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		alert := &SecurityAlert{Message: res}
		jsonData, err := json.Marshal(alert)
		if err != nil {
			log.Error().Err(err).Msg("handler: marshal alert failed")
			return api.CreateEmptyComputerMonitorMessageResponse()
		}

		log.Debug().Msgf("handler: send last_enforement_result %+v", alert)

		return &api.ComputerMonitorCallbackResponse{
			Close: false,
			Data:  jsonData,
		}
	}
}

func (h *Handler) createTraceChannel(name string) *TraceChannel {
	var processEventCh <-chan interface{}
	var readlineEventCh <-chan interface{}
	var fileEventCh <-chan interface{}
	var netEventCh <-chan interface{}

	if h.tracer.HasTracer(tracer.ProcessTracer) {
		ch, err := h.tracer.AddSubscriber(tracer.ProcessTracer, name)
		if err != nil {
			log.Error().Err(err).Msg("handler: register process event subscriber failed")
		}
		processEventCh = ch
	}

	if h.tracer.HasTracer(tracer.ReadlineTracer) {
		ch, err := h.tracer.AddSubscriber(tracer.ReadlineTracer, name)
		if err != nil {
			log.Error().Err(err).Msg("handler: register readline event subscriber failed")
		}
		readlineEventCh = ch
	}

	if h.tracer.HasTracer(tracer.FileTracer) {
		ch, err := h.tracer.AddSubscriber(tracer.FileTracer, name)
		if err != nil {
			log.Error().Err(err).Msg("handler: register file event subscriber failed")
		}
		fileEventCh = ch
	}

	if h.tracer.HasTracer(tracer.SocketTracer) {
		ch, err := h.tracer.AddSubscriber(tracer.SocketTracer, name)
		if err != nil {
			log.Error().Err(err).Msg("handler: register sock_ops event subscriber failed")
		}
		netEventCh = ch
	}

	return &TraceChannel{
		processEventCh:  processEventCh,
		readlineEventCh: readlineEventCh,
		fileEventCh:     fileEventCh,
		netEventCh:      netEventCh,
	}
}

// TODO:
func (h *Handler) resumeProcessWhenNoAvaialbleEnformentOperation(pid int) {
	leftNumOfEnforcementOpertaions, err := h.tracer.FinishEnforcementOperation(pid)
	if err != nil {
		log.Error().Msgf("handler: resume process failed when read the number of enforcement operations")
		_ = resumeProcess(pid)
		return
	}

	// resume when all enforcement operations are handled
	if leftNumOfEnforcementOpertaions == 0 {
		_ = resumeProcess(pid)
	}
}

func getSignForFileEvent(event *tracer.FileEvent) string {
	return fmt.Sprintf("%d:%d:%d:%s:%s", event.NsTgid, event.Type, event.AccMode, event.Path, event.NewPath)
}
