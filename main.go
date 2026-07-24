package main

import (
	"agent-sentinel/api"
	"agent-sentinel/audit"
	"agent-sentinel/handler"
	"agent-sentinel/helper"
	moniterlog "agent-sentinel/log"
	"agent-sentinel/tracer"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
	"time"
)

type computerUseMonitor struct {
	enableDebug       bool
	outputFile        string
	targetContainerID string
	// mount namespace id
	targetMntNsID int
	targetPidNSID int
	// X11 server addr
	x11ServerAddr            string
	tracer                   *tracer.Tracer
	processEventCh           <-chan interface{}
	readlineEventCh          <-chan interface{}
	netEventCh               <-chan interface{}
	dnsEventCh               <-chan interface{}
	fileEvenCh               <-chan interface{}
	mountPath                string
	enableAudit              bool
	processTraceLevel        int
	binaryLevelCache         bool
	toolUseTimeout           int
	enableAuditWithoutTracer bool
	model                    string
}

func newComputerUseMonitor() (*computerUseMonitor, error) {
	cum := &computerUseMonitor{}

	flag.BoolVar(&cum.enableDebug, "debug", false, "enable debug mode")
	flag.StringVar(&cum.outputFile, "output", "", "output file to record logs")
	flag.StringVar(&cum.targetContainerID, "cid", "", "target container id")
	flag.StringVar(&cum.x11ServerAddr, "x11", "", "X11 server addr")
	flag.StringVar(&cum.mountPath, "mount-path", "", "mount path for computer monitor unix socket")
	flag.BoolVar(&cum.enableAudit, "audit", true, "enable audit")
	flag.BoolVar(&cum.enableAuditWithoutTracer, "audit-without-tracer", false, "enable audit-without-tracer")
	flag.IntVar(&cum.processTraceLevel, "process-trace-level", 0, "limit process trace level")
	flag.BoolVar(&cum.binaryLevelCache, "binary-level-cache", false, "enable binary level cache")
	flag.IntVar(&cum.toolUseTimeout, "tool-use-timeout", 60, "tool use timeout (s)")
	flag.StringVar(&cum.model, "model", audit.AuditBaseLLMCladue35, "LLM model name")
	flag.Parse()

	// init global monitor logger
	if err := moniterlog.InitMonitorLogger(cum.outputFile); err != nil {
		return nil, err
	}

	// enable debug mode
	if cum.enableDebug {
		moniterlog.WithDebugLevel()
		log.Debug().Msg("Debug mode enabled")
	}

	if cum.model != audit.AuditBaseLLMCladue35 && cum.model != audit.AuditBaseLLMCladue37 && cum.model != audit.AuditBaseLLMGPT4Turbor && cum.model != audit.AuditBaseLLMGPT4o {
		log.Error().Msgf("LLM model %s is not supported", cum.model)
		return nil, fmt.Errorf("LLM model %s is not supported", cum.model)
	}
	log.Debug().Msgf("Set LLM model %s", cum.model)

	if cum.mountPath == "" {
		log.Error().Msg("Mount path is required")
		return nil, fmt.Errorf("mount path is required")
	}

	if _, err := os.Stat(cum.mountPath); errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Mount path does not exist")
		return nil, err
	}

	if cum.enableAuditWithoutTracer {
		log.Debug().Msg("Audit-without-tracer enabled")
		return cum, nil
	}

	if !cum.enableAudit {
		log.Debug().Msg("Audit disabled")
	}

	if cum.processTraceLevel > 0 {
		log.Debug().Msgf("Process trace level is %d", cum.processTraceLevel)
	}

	if cum.binaryLevelCache {
		log.Debug().Msg("Binary-level cache enabled")
	}

	log.Debug().Msgf("Tool use timeout is %ds", cum.toolUseTimeout)

	if cum.targetContainerID == "" {
		log.Error().Msg("Target container id is required")
		return nil, fmt.Errorf("target container id is required")
	}

	// TODO move to tracer initialization
	// query full container id
	conID, err := helper.QueryFullIDFromContainerID(cum.targetContainerID)
	if err != nil {
		log.Error().Err(err).Msg("Query container full id failed")
		return nil, err
	}

	// query the root pid of the container
	cpid, err := helper.QueryPIDFromContainerID(cum.targetContainerID)
	if err != nil {
		log.Error().Err(err).Msg("Query target container id failed")
		return nil, err
	}
	if cpid == 0 {
		log.Error().Msg("Seem like target container is not active")
		return nil, fmt.Errorf("seem like target container is not active")
	}

	// get mount namespace of the container
	cum.targetMntNsID, err = helper.GetMountNamespaceID(cpid)
	if err != nil {
		log.Error().Err(err).Msg("Get target mount namespace ID failed")
		return nil, err
	}

	cum.targetPidNSID, err = helper.GetPIDNamespaceID(cpid)
	if err != nil {
		log.Error().Err(err).Msg("Get target pid namespace ID failed")
		return nil, err
	}
	log.Info().Msg(fmt.Sprintf("Found target containter %s with mount namespace id %d and pid namespace id %d", cum.targetContainerID, cum.targetMntNsID, cum.targetPidNSID))

	// get remote bash binary in the container
	bashPath, err := helper.GetBaseBashBinaryPathFromContainerID(cum.targetContainerID)
	if err != nil {
		log.Error().Err(err).Msg("Get remote bash binary failed")
		return nil, err
	}

	if _, err := os.Stat(bashPath); errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Access remote bash binary failed")
		return nil, err
	}

	//if cum.x11ServerAddr == "" {
	//	log.Error().Msg("Target X11 server addr is required")
	//	return nil, fmt.Errorf("target X11 server addr is required")
	//}

	// cgroupV2Path, err := helper.FindCgroupV2Path(conID)
	cgroupV2Path, err := helper.FindCgroupV2Path(cpid)
	if err != nil {
		log.Error().Err(err).Msg("find cgroup path failed")
		return nil, err
	}
	log.Info().Msg(fmt.Sprintf("Found cgroup path %s", cgroupV2Path))

	t, err := tracer.NewTracer(&tracer.Options{
		EnableTracer: []int{
			tracer.ProcessTracer,
			tracer.ReadlineTracer,
			tracer.SocketTracer,
			tracer.DNSTracer,
			tracer.FileTracer},
		ContainerID: conID,
		MountNSID:   cum.targetMntNsID,
		PidNSID:     cum.targetPidNSID,
		BashPath:    bashPath,
		CgroupPath:  cgroupV2Path,
	})

	if err != nil {
		log.Error().Msg("Init tracer failed")
		return nil, err
	}

	log.Info().Msg("Tracer is ready")

	cum.tracer = t
	return cum, nil
}

func (cum *computerUseMonitor) Close() {
	if cum.tracer != nil {
		cum.tracer.Close()
	}
}

func (cum *computerUseMonitor) RegisterDefaultEventSubscriber() error {
	var err error
	_ = err

	cum.processEventCh, err = cum.tracer.AddSubscriber(tracer.ProcessTracer, "default")
	if err != nil {
		log.Error().Msg("Register default process event subscriber failed")
		return err
	}

	cum.readlineEventCh, err = cum.tracer.AddSubscriber(tracer.ReadlineTracer, "default")
	if err != nil {
		log.Error().Msg("Register default readline event subscriber failed")
		return err
	}

	cum.netEventCh, err = cum.tracer.AddSubscriber(tracer.SocketTracer, "default")
	if err != nil {
		log.Error().Msg("Register default sock_ops event subscriber failed")
		return err
	}

	cum.dnsEventCh, err = cum.tracer.AddSubscriber(tracer.DNSTracer, "default")
	if err != nil {
		log.Error().Msg("Register default dns event subscriber failed")
		return err
	}

	cum.fileEvenCh, err = cum.tracer.AddSubscriber(tracer.FileTracer, "default")
	if err != nil {
		log.Error().Msg("Register default file event subscriber failed")
		return err
	}

	go cum.handleEventDefault()

	return nil
}

func (cum *computerUseMonitor) handleEventDefault() {
	for {
		// TODO: health checking here ???
		select {
		case <-cum.processEventCh:
		case <-cum.readlineEventCh:
		case <-cum.netEventCh:
		case <-cum.dnsEventCh:
		case <-cum.fileEvenCh:
		}
	}
}

func (cum *computerUseMonitor) Start() {
	err := cum.RegisterDefaultEventSubscriber()
	if err != nil {
		log.Error().Msg("Register default event subscriber failed")
		return
	}

	server, err := api.NewComputerMonitorServer(cum.mountPath)
	if err != nil {
		log.Error().Msg("Create computer monitor server failed")
		return
	}

	auditor, err := audit.NewAudit(&audit.Config{
		SecurityQueryBaseLLM:      cum.model,
		TaskCtxSummarizingBaseLLM: cum.model,
		ProcessTraceLevel:         cum.processTraceLevel,
		BinaryLevelCache:          cum.binaryLevelCache,
		ToolUseTime:               time.Duration(cum.toolUseTimeout) * time.Second,
		SecureAgentProcess:        true,
		EventCountLimit:           20,
	})

	// TODO: add test interface for audit
	//auditor, err := createAuditTest()
	//if err != nil {
	//	log.Error().Err(err).Msg("Create audit failed")
	//	return
	//}

	handlerInstance, err := handler.NewHandler(cum.targetPidNSID, auditor)
	if err != nil {
		log.Error().Msg("Create handler failed")
		return
	}

	// tracing only
	if !cum.enableAudit {
		handlerInstance.DisableAudit()
	}

	handlerInstance.SetTracer(cum.tracer)
	handlerInstance.EnableDNSCache()

	// register handler of computer monitor api
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_CONNECT, handlerInstance.NewConnectHandler())
	// server.RegisterComputerMonitorMessageHandler(api.CM_OP_START_TRACING, handlerInstance.NewStartTracingHandler())
	// server.RegisterComputerMonitorMessageHandler(api.CM_OP_STOP_TRACING, handlerInstance.NewStopTracingHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_START_PASSIVE_TRACING, handlerInstance.NewStartPassiveTracingHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_SEND_TOOL_USE, handlerInstance.NewSendToolUseHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_GET_LAST_ENFORCEMENT_RESULT, handlerInstance.NewGetLastEnforcementResult())

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	go func() {
		select {
		case <-stop:
			server.Close()
			handlerInstance.Close()
			cancel()
		}
	}()

	_ = handlerInstance.Start(ctx)
	_ = server.Start(ctx)

	log.Info().Msg("Computer monitor server closed")
}

func (cum *computerUseMonitor) StartWithoutTracer() {
	server, err := api.NewComputerMonitorServer(cum.mountPath)
	if err != nil {
		log.Error().Msg("Create computer monitor server failed")
		return
	}

	auditor, err := audit.NewAuditWithoutTrace(&audit.Config{
		ToolUseTime:               time.Duration(cum.toolUseTimeout) * time.Second,
		SecurityQueryBaseLLM:      cum.model,
		TaskCtxSummarizingBaseLLM: cum.model,
	})

	handlerInstance, err := handler.NewHandlerWithoutTracer(auditor)
	if err != nil {
		log.Error().Msg("Create handler failed")
		return
	}

	server.RegisterComputerMonitorMessageHandler(api.CM_OP_CONNECT, handlerInstance.NewConnectHandler())
	// server.RegisterComputerMonitorMessageHandler(api.CM_OP_START_TRACING, handlerInstance.NewStartTracingHandler())
	// server.RegisterComputerMonitorMessageHandler(api.CM_OP_STOP_TRACING, handlerInstance.NewStopTracingHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_START_PASSIVE_TRACING, handlerInstance.NewStartPassiveTracingHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_SEND_TOOL_USE, handlerInstance.NewSendToolUseHandler())
	server.RegisterComputerMonitorMessageHandler(api.CM_OP_GET_LAST_ENFORCEMENT_RESULT, handlerInstance.NewGetLastEnforcementResult())

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	go func() {
		select {
		case <-stop:
			server.Close()
			handlerInstance.Close()
			cancel()
		}
	}()

	_ = handlerInstance.Start(ctx)
	_ = server.Start(ctx)

	log.Info().Msg("Computer monitor server closed")
}

func main() {
	cum, err := newComputerUseMonitor()
	if err != nil {
		log.Fatal().Msg("Create computer use monitor failed")
	}
	defer cum.Close()

	if !cum.enableAuditWithoutTracer {
		cum.Start()
	} else {
		cum.StartWithoutTracer()
	}

	// testProcessTree(65369, cum)
	// testProcessResume(cum)
	// testNetTracer(65369, cum)
}
