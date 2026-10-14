package tsutil

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

type AutoSwitchMode string

const (
	AutoSwitchDisabled    AutoSwitchMode = "disabled"
	AutoSwitchWaiting     AutoSwitchMode = "waiting"
	AutoSwitchGrace       AutoSwitchMode = "grace"
	AutoSwitchMonitoring  AutoSwitchMode = "monitoring"
	AutoSwitchSuspect     AutoSwitchMode = "suspect"
	AutoSwitchSwitching   AutoSwitchMode = "switching"
	AutoSwitchVerifying   AutoSwitchMode = "verifying"
	AutoSwitchRollingBack AutoSwitchMode = "rolling-back"
	AutoSwitchBackoff     AutoSwitchMode = "backoff"
)

const (
	autoSwitchGracePeriod      = 30 * time.Second
	autoSwitchConfirmInterval  = 5 * time.Second
	autoSwitchVerifyTimeout    = 25 * time.Second
	autoSwitchBackoffPeriod    = 5 * time.Minute
	autoSwitchQuarantinePeriod = 30 * time.Minute
	autoSwitchMaxCandidates    = 2
)

type AutoSwitchConfig struct {
	Enabled       bool
	Threshold     time.Duration
	ProbeInterval time.Duration
}

func (c AutoSwitchConfig) normalized() AutoSwitchConfig {
	if c.Threshold < 10*time.Second {
		c.Threshold = 10 * time.Second
	}
	if c.ProbeInterval < 10*time.Second {
		c.ProbeInterval = 60 * time.Second
	}
	return c
}

type AutoSwitchEvent struct {
	Time    time.Time `json:"time"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Reason  string    `json:"reason"`
	Outcome string    `json:"outcome"`
	Error   string    `json:"error,omitempty"`
}

type AutoSwitchRuntime struct {
	Enabled          bool
	Mode             AutoSwitchMode
	Message          string
	ConsecutiveFails int
	NextAction       time.Time
	LastProbe        time.Time
	LastProbeOK      bool
	LastEvent        AutoSwitchEvent
}

type AutoSwitchManager struct {
	ops autoSwitchOps

	configMu     sync.Mutex
	configLatest AutoSwitchConfig
	configWake   chan struct{}
	status       chan *IPNStatus
	invalidate   chan struct{}
	unavailable  chan struct{}
	modeControl  chan autoSwitchModeControl
	epoch        atomic.Uint64

	runtimeMu      sync.RWMutex
	runtime        AutoSwitchRuntime
	runtimeUpdates chan AutoSwitchRuntime
	overrides      chan struct{}
}

func NewAutoSwitchManager() *AutoSwitchManager {
	return newAutoSwitchManager(localAutoSwitchOps{})
}

func newAutoSwitchManager(ops autoSwitchOps) *AutoSwitchManager {
	return &AutoSwitchManager{
		ops:            ops,
		configWake:     make(chan struct{}, 1),
		status:         make(chan *IPNStatus, 1),
		invalidate:     make(chan struct{}, 1),
		unavailable:    make(chan struct{}, 1),
		runtimeUpdates: make(chan AutoSwitchRuntime, 1),
		overrides:      make(chan struct{}, 1),
		modeControl:    make(chan autoSwitchModeControl),
		runtime: AutoSwitchRuntime{
			Mode:    AutoSwitchDisabled,
			Message: "Auto-switch is disabled",
		},
	}
}

type autoSwitchModeControl struct {
	pause         bool
	expectedID    tailcfg.StableNodeID
	expectedOwner tailcfg.StableNodeID
	ctx           context.Context
	result        chan error
}

func (m *AutoSwitchManager) SetConfig(config AutoSwitchConfig) {
	config = config.normalized()
	if !config.Enabled {
		exitNodeMu.Lock()
		m.epoch.Add(1)
		exitNodeMu.Unlock()
	} else {
		m.epoch.Add(1)
	}
	m.configMu.Lock()
	m.configLatest = config
	m.configMu.Unlock()
	select {
	case m.configWake <- struct{}{}:
	default:
	}
}

func (m *AutoSwitchManager) latestConfig() AutoSwitchConfig {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	return m.configLatest
}

func (m *AutoSwitchManager) Invalidate() {
	exitNodeMu.Lock()
	m.epoch.Add(1)
	exitNodeMu.Unlock()
	select {
	case m.invalidate <- struct{}{}:
	default:
	}
}

func (m *AutoSwitchManager) DaemonUnavailable() {
	select {
	case m.unavailable <- struct{}{}:
	default:
	}
}

func (m *AutoSwitchManager) Pause(ctx context.Context) error {
	exitNodeMu.Lock()
	m.epoch.Add(1)
	exitNodeMu.Unlock()
	request := autoSwitchModeControl{pause: true, result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.modeControl <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.result:
		return err
	}
}

func (m *AutoSwitchManager) Resume(ctx context.Context) error {
	return m.resume(ctx, "")
}

func (m *AutoSwitchManager) resumeWhenSpecific(ctx context.Context, id, owner tailcfg.StableNodeID) error {
	request := autoSwitchModeControl{
		expectedID:    id,
		expectedOwner: owner,
		ctx:           ctx,
		result:        make(chan error, 1),
	}
	return m.sendModeControl(request)
}

func (m *AutoSwitchManager) resume(ctx context.Context, expectedID tailcfg.StableNodeID) error {
	request := autoSwitchModeControl{expectedID: expectedID, ctx: ctx, result: make(chan error, 1)}
	return m.sendModeControl(request)
}

func (m *AutoSwitchManager) sendModeControl(request autoSwitchModeControl) error {
	select {
	case <-request.ctx.Done():
		return request.ctx.Err()
	case m.modeControl <- request:
	}
	select {
	case <-request.ctx.Done():
		return request.ctx.Err()
	case err := <-request.result:
		return err
	}
}

func (m *AutoSwitchManager) RuntimeUpdates() <-chan AutoSwitchRuntime {
	return m.runtimeUpdates
}

func (m *AutoSwitchManager) Overrides() <-chan struct{} {
	return m.overrides
}

func (m *AutoSwitchManager) reportOverride() {
	select {
	case m.overrides <- struct{}{}:
	default:
	}
}

func (m *AutoSwitchManager) UpdateStatus(status *IPNStatus) {
	if status == nil {
		return
	}
	select {
	case m.status <- status.copy():
	default:
		select {
		case <-m.status:
		default:
		}
		m.status <- status.copy()
	}
}

func (m *AutoSwitchManager) Runtime() AutoSwitchRuntime {
	m.runtimeMu.RLock()
	defer m.runtimeMu.RUnlock()
	return m.runtime
}

func (m *AutoSwitchManager) setRuntime(runtime AutoSwitchRuntime) {
	m.runtimeMu.Lock()
	m.runtime = runtime
	m.runtimeMu.Unlock()
	select {
	case m.runtimeUpdates <- runtime:
	default:
		select {
		case <-m.runtimeUpdates:
		default:
		}
		m.runtimeUpdates <- runtime
	}
}

type autoSwitchProbeKind uint8

const (
	probeMonitor autoSwitchProbeKind = iota
	probeConfirm
	probeVerify
)

type autoSwitchProbeEvent struct {
	generation uint64
	kind       autoSwitchProbeKind
	result     exitPathProbeResult
}

type autoSwitchCandidateEvent struct {
	generation uint64
	peer       tailcfg.NodeView
	err        error
}

type autoSwitchApplyEvent struct {
	generation uint64
	target     tailcfg.NodeView
	rollback   bool
	err        error
}

type autoSwitchLoop struct {
	manager   *AutoSwitchManager
	ctx       context.Context
	config    AutoSwitchConfig
	configSet bool
	status    *IPNStatus
	runtime   AutoSwitchRuntime

	generation uint64
	cancel     context.CancelFunc
	busy       bool

	currentID         tailcfg.StableNodeID
	currentLabel      string
	incidentSourceID  tailcfg.StableNodeID
	expectedID        tailcfg.StableNodeID
	expectedPeer      tailcfg.NodeView
	incidentFrom      string
	incidentReason    string
	incidentEpoch     uint64
	badSince          time.Time
	verifyDeadline    time.Time
	verifyCount       int
	attempts          int
	probeTarget       int
	quarantine        map[tailcfg.StableNodeID]time.Time
	backoffUntil      time.Time
	stateOwner        tailcfg.StableNodeID
	managedID         tailcfg.StableNodeID
	stateReconciled   bool
	restoredIncident  *persistedAutoSwitchIncident
	daemonUnavailable bool
	paused            bool
	pendingResume     *autoSwitchModeControl

	probeResults     chan autoSwitchProbeEvent
	candidateResults chan autoSwitchCandidateEvent
	applyResults     chan autoSwitchApplyEvent
	operationWorkers sync.WaitGroup
}

func (m *AutoSwitchManager) Run(ctx context.Context) {
	loop := autoSwitchLoop{
		manager:          m,
		ctx:              ctx,
		quarantine:       make(map[tailcfg.StableNodeID]time.Time),
		probeResults:     make(chan autoSwitchProbeEvent, 1),
		candidateResults: make(chan autoSwitchCandidateEvent, 1),
		applyResults:     make(chan autoSwitchApplyEvent, 1),
		runtime: AutoSwitchRuntime{
			Mode:    AutoSwitchDisabled,
			Message: "Auto-switch is disabled",
		},
	}
	loop.loadState()
	loop.publish()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		loop.cancelOperation()
		loop.operationWorkers.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.configWake:
			loop.configSet = true
			loop.handleConfig(m.latestConfig(), time.Now())
		case status := <-m.status:
			loop.handleStatus(status, time.Now())
			loop.resumeIfReady()
		case <-m.invalidate:
			loop.backoffUntil = time.Time{}
			loop.abandonIncident()
			loop.saveState()
			if loop.config.Enabled {
				loop.enterGrace(time.Now(), "Exit node changed manually")
			} else {
				loop.runtime.Mode = AutoSwitchDisabled
				loop.runtime.Message = "Auto-switch is disabled"
				loop.runtime.NextAction = time.Time{}
				loop.publish()
			}
		case <-m.unavailable:
			loop.cancelOperation()
			loop.generation++
			loop.busy = false
			loop.status = nil
			loop.daemonUnavailable = true
			loop.runtime.Message = "Waiting for Tailscale"
			loop.runtime.NextAction = time.Time{}
			loop.saveState()
			loop.publish()
		case request := <-m.modeControl:
			if loop.pendingResume != nil {
				loop.pendingResume.result <- errors.New("exit-node mode change superseded")
				loop.pendingResume = nil
			}
			if request.pause {
				loop.paused = true
				loop.abandonIncident()
				loop.saveState()
				loop.runtime.Enabled = false
				loop.runtime.Mode = AutoSwitchDisabled
				loop.runtime.Message = "Changing exit-node mode"
				loop.runtime.NextAction = time.Time{}
				loop.publish()
				request.result <- nil
			} else if request.expectedID == "" {
				loop.resume(request)
			} else if ready, err := resumeStatusReady(loop.status, request.expectedID, request.expectedOwner); err != nil {
				request.result <- err
			} else if ready {
				loop.resume(request)
			} else {
				loop.pendingResume = &request
			}
		case result := <-loop.probeResults:
			loop.handleProbeResult(result, time.Now())
		case result := <-loop.candidateResults:
			loop.handleCandidateResult(ctx, result, time.Now())
		case result := <-loop.applyResults:
			loop.handleApplyResult(result, time.Now())
		case now := <-ticker.C:
			if loop.pendingResume != nil && loop.pendingResume.ctx.Err() != nil {
				loop.pendingResume.result <- loop.pendingResume.ctx.Err()
				loop.pendingResume = nil
			}
			loop.handleTick(ctx, now)
		}
	}
}

func (l *autoSwitchLoop) resumeIfReady() {
	if l.pendingResume != nil && l.pendingResume.ctx.Err() != nil {
		l.pendingResume.result <- l.pendingResume.ctx.Err()
		l.pendingResume = nil
		return
	}
	if l.pendingResume == nil {
		return
	}
	ready, err := resumeStatusReady(l.status, l.pendingResume.expectedID, l.pendingResume.expectedOwner)
	if err != nil {
		l.pendingResume.result <- err
		l.pendingResume = nil
		return
	}
	if ready {
		request := *l.pendingResume
		l.pendingResume = nil
		l.resume(request)
	}
}

func (l *autoSwitchLoop) resume(request autoSwitchModeControl) {
	l.paused = false
	if request.expectedID != "" {
		l.currentID = ""
		l.currentLabel = ""
	}
	l.config = AutoSwitchConfig{}
	l.configSet = true
	l.handleConfig(l.manager.latestConfig(), time.Now())
	request.result <- nil
}

func resumeStatusReady(status *IPNStatus, expected, owner tailcfg.StableNodeID) (bool, error) {
	statusOwner, ok := autoSwitchStatusOwner(status)
	if ok && owner != "" && statusOwner != owner {
		return false, errors.New("tailscale profile changed during exit-node update")
	}
	_, id, _, eligible := eligibleAutoSwitchStatus(status)
	return eligible && id == expected && statusOwner == owner, nil
}

func (l *autoSwitchLoop) handleConfig(config AutoSwitchConfig, now time.Time) {
	config = config.normalized()
	changed := config != l.config
	l.config = config
	if !config.Enabled {
		l.abandonIncident()
		l.restoredIncident = nil
		l.managedID = ""
		l.currentID = ""
		l.currentLabel = ""
		l.reconcileDisabledOwner()
		l.runtime.Enabled = false
		l.runtime.Mode = AutoSwitchDisabled
		l.runtime.Message = "Auto-switch is disabled"
		l.runtime.NextAction = time.Time{}
		l.saveState()
		l.publish()
		return
	}
	if l.paused {
		l.runtime.Enabled = false
		l.runtime.Mode = AutoSwitchDisabled
		l.runtime.Message = "Changing exit-node mode"
		l.runtime.NextAction = time.Time{}
		l.publish()
		return
	}
	l.runtime.Enabled = true
	if changed {
		l.abandonIncident()
		if l.backoffUntil.After(now) {
			l.runtime.Mode = AutoSwitchBackoff
			l.runtime.Message = "Waiting after a previous failed attempt"
			l.runtime.NextAction = l.backoffUntil
			l.publish()
			return
		}
		l.enterGrace(now, "Waiting for stable Tailscale state")
		l.reconcileStatus(now)
	}
}

func (l *autoSwitchLoop) handleStatus(status *IPNStatus, now time.Time) {
	l.status = status
	if !l.configSet {
		return
	}
	if !l.config.Enabled {
		if l.reconcileDisabledOwner() {
			l.saveState()
		}
		return
	}
	if owner, ok := autoSwitchStatusOwner(status); ok && l.stateReconciled && l.stateOwner != "" && owner != l.stateOwner {
		l.disableAfterProfileChange(owner)
		return
	}
	if l.paused {
		return
	}
	l.reconcileStatus(now)
}

func (l *autoSwitchLoop) reconcileDisabledOwner() bool {
	owner, ok := autoSwitchStatusOwner(l.status)
	if !ok || (l.stateReconciled && owner == l.stateOwner) {
		return false
	}
	if l.stateOwner != "" && owner != l.stateOwner {
		clear(l.quarantine)
		l.backoffUntil = time.Time{}
	}
	l.stateOwner = owner
	l.stateReconciled = true
	return true
}

func (l *autoSwitchLoop) reconcileStatus(now time.Time) {
	if !l.stateReconciled {
		reconciled, handled := l.reconcilePersistedState(now)
		if !reconciled {
			return
		}
		l.stateReconciled = true
		if handled {
			return
		}
	}
	if l.status != nil && l.status.Prefs.Valid() && l.status.Prefs.AutoExitNode().IsSet() {
		l.abandonIncident()
		l.managedID = ""
		l.saveState()
		l.config.Enabled = false
		l.runtime.Enabled = false
		l.runtime.Mode = AutoSwitchDisabled
		l.runtime.Message = "Tailscale Automatic is active"
		l.runtime.NextAction = time.Time{}
		l.manager.reportOverride()
		l.publish()
		return
	}
	peer, id, reason, eligible := eligibleAutoSwitchStatus(l.status)
	if !eligible {
		if l.incidentSourceID != "" && autoSwitchStatusTransient(l.status) {
			l.cancelOperation()
			l.generation++
			l.busy = false
			l.daemonUnavailable = true
			l.runtime.Message = reason
			l.runtime.NextAction = time.Time{}
			l.saveState()
			l.publish()
			return
		}
		if healthSelectionOverridden(l.status) {
			l.disableAfterOverride("Exit-node selection changed outside connection checks")
			return
		}
		l.abandonIncident()
		l.currentID = ""
		l.runtime.Mode = AutoSwitchWaiting
		l.runtime.Message = reason
		l.runtime.NextAction = time.Time{}
		l.publish()
		return
	}
	if l.incidentSourceID == "" && l.managedID != "" && id != l.managedID {
		l.disableAfterOverride("Exit node changed while Tailscale was reconnecting")
		return
	}
	if l.managedID == "" {
		l.managedID = id
		l.saveState()
	}
	if l.backoffUntil.After(now) {
		l.runtime.Mode = AutoSwitchBackoff
		l.runtime.Message = "Waiting after a previous failed attempt"
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		l.runtime.NextAction = l.backoffUntil
		l.publish()
		return
	}
	wasUnavailable := l.daemonUnavailable
	l.daemonUnavailable = false

	if l.runtime.Mode == AutoSwitchSwitching && l.expectedID != "" && id == l.expectedID {
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		l.runtime.Mode = AutoSwitchVerifying
		l.runtime.Message = fmt.Sprintf("Verifying %s", l.currentLabel)
		l.runtime.NextAction = now.Add(5 * time.Second)
		l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
		l.publish()
		return
	}
	if l.runtime.Mode == AutoSwitchRollingBack {
		if id == l.expectedID {
			failedLabel := l.currentLabel
			l.currentID = id
			l.currentLabel = peerLabel(peer)
			l.completeRollback(now, failedLabel)
			return
		}
		if id == l.currentID {
			if wasUnavailable {
				l.runtime.Message = fmt.Sprintf("Returning to previous exit node %s", peerLabel(l.expectedPeer))
				l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
				l.publish()
				l.startApply(l.ctx, l.expectedPeer)
			}
			return
		}
		l.manager.epoch.Add(1)
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		l.disableAfterOverride("Exit node changed while returning to the previous node")
		return
	}

	if l.runtime.Mode == AutoSwitchVerifying {
		if id == l.expectedID {
			l.currentID = id
			l.currentLabel = peerLabel(peer)
			if wasUnavailable {
				l.runtime.Message = fmt.Sprintf("Resuming verification of %s", l.currentLabel)
				l.runtime.NextAction = now
				l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
				l.publish()
			}
			return
		}
		if id == l.currentID {
			return
		}
		l.manager.epoch.Add(1)
		l.disableAfterOverride("Exit node changed outside connection checks")
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		return
	}
	if wasUnavailable {
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		l.enterGrace(now, "Waiting after Tailscale restarted")
		return
	}

	if l.currentID != id {
		if l.currentID != "" {
			l.manager.epoch.Add(1)
			l.currentID = id
			l.currentLabel = peerLabel(peer)
			l.disableAfterOverride("Exit node changed outside connection checks")
			return
		}
		l.abandonIncident()
		l.currentID = id
		l.currentLabel = peerLabel(peer)
		l.enterGrace(now, "Waiting after exit node or daemon change")
		return
	}

	if l.runtime.Mode == AutoSwitchWaiting || l.runtime.Mode == AutoSwitchDisabled {
		l.enterGrace(now, "Waiting for stable Tailscale state")
	}
}

func (l *autoSwitchLoop) reconcilePersistedState(now time.Time) (reconciled, handled bool) {
	if autoSwitchStatusTransient(l.status) {
		return false, false
	}
	owner, ok := autoSwitchStatusOwner(l.status)
	if !ok || !l.status.Prefs.Valid() {
		return false, false
	}
	if l.stateOwner != "" && l.stateOwner != owner {
		l.disableAfterProfileChange(owner)
		return true, true
	}
	l.stateOwner = owner
	pending := l.restoredIncident
	l.restoredIncident = nil
	if pending == nil || pending.SourceID == "" {
		if l.managedID != "" && l.status.Prefs.ExitNodeID() != l.managedID {
			l.disableAfterOverride("Exit node changed while Trayscale was not running")
			return true, true
		}
		return true, false
	}

	l.incidentSourceID = tailcfg.StableNodeID(pending.SourceID)
	l.incidentFrom = pending.SourceLabel
	l.incidentReason = pending.Reason
	l.incidentEpoch = l.manager.epoch.Load()
	l.attempts = pending.Attempts
	l.expectedID = tailcfg.StableNodeID(pending.TargetID)
	if peer, ok := l.status.Peers[l.expectedID]; ok {
		l.expectedPeer = peer
	}
	currentID := l.status.Prefs.ExitNodeID()
	if pending.Phase == AutoSwitchSwitching && l.expectedID == "" && currentID == tailcfg.StableNodeID(pending.CurrentID) {
		if current, ok := l.status.Peers[currentID]; ok {
			l.currentID = currentID
			l.currentLabel = peerLabel(current)
			l.runtime.Mode = AutoSwitchSwitching
			l.runtime.Message = "Resuming selection of another Mullvad exit node"
			l.saveState()
			l.publish()
			l.startCandidateSelection(l.ctx)
			return true, true
		}
	}
	if pending.Phase == AutoSwitchSwitching && currentID == l.expectedID && l.expectedPeer.Valid() {
		l.currentID = currentID
		l.currentLabel = peerLabel(l.expectedPeer)
		l.runtime.Mode = AutoSwitchVerifying
		l.runtime.Message = fmt.Sprintf("Resuming verification of %s", l.currentLabel)
		l.runtime.NextAction = now
		l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
		l.verifyCount = 0
		l.saveState()
		l.publish()
		return true, true
	}
	if pending.Phase == AutoSwitchVerifying && currentID == l.expectedID && l.expectedPeer.Valid() {
		l.currentID = currentID
		l.currentLabel = peerLabel(l.expectedPeer)
		l.runtime.Mode = AutoSwitchVerifying
		l.runtime.Message = fmt.Sprintf("Resuming verification of %s", l.currentLabel)
		l.runtime.NextAction = now
		l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
		l.verifyCount = 0
		l.publish()
		return true, true
	}
	if pending.Phase == AutoSwitchRollingBack && currentID == l.expectedID && l.expectedPeer.Valid() {
		l.currentID = currentID
		l.currentLabel = peerLabel(l.expectedPeer)
		l.completeRollback(now, pending.CurrentLabel)
		return true, true
	}
	if pending.Phase == AutoSwitchRollingBack && currentID == tailcfg.StableNodeID(pending.CurrentID) && l.expectedPeer.Valid() {
		if current, ok := l.status.Peers[currentID]; ok {
			l.currentID = currentID
			l.currentLabel = peerLabel(current)
			l.runtime.Mode = AutoSwitchRollingBack
			l.runtime.Message = fmt.Sprintf("Resuming return to %s", peerLabel(l.expectedPeer))
			l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
			l.publish()
			l.startApply(l.ctx, l.expectedPeer)
			return true, true
		}
	}
	if currentID == l.incidentSourceID {
		l.abandonIncident()
		l.saveState()
		return true, false
	}

	l.clearIncident()
	l.saveState()
	l.disableAfterOverride("Exit node changed while Trayscale was not running")
	return true, true
}

func (l *autoSwitchLoop) disableAfterOverride(message string) {
	l.abandonIncident()
	l.managedID = ""
	l.saveState()
	l.config.Enabled = false
	l.runtime.Enabled = false
	l.runtime.Mode = AutoSwitchDisabled
	l.runtime.Message = message
	l.runtime.NextAction = time.Time{}
	l.manager.reportOverride()
	l.publish()
}

func (l *autoSwitchLoop) disableAfterProfileChange(owner tailcfg.StableNodeID) {
	exitNodeMu.Lock()
	l.manager.epoch.Add(1)
	exitNodeMu.Unlock()
	l.abandonIncident()
	clear(l.quarantine)
	l.backoffUntil = time.Time{}
	l.restoredIncident = nil
	l.managedID = ""
	l.currentID = ""
	l.currentLabel = ""
	l.stateOwner = owner
	l.stateReconciled = true
	l.daemonUnavailable = false
	l.config.Enabled = false
	l.runtime = AutoSwitchRuntime{
		Mode:    AutoSwitchDisabled,
		Message: "Profile changed; connection checks are disabled",
	}
	l.saveState()
	l.manager.reportOverride()
	l.publish()
}

func autoSwitchStatusOwner(status *IPNStatus) (tailcfg.StableNodeID, bool) {
	self, ok := status.Self()
	if !ok || self.StableID() == "" {
		return "", false
	}
	return self.StableID(), true
}

func healthSelectionOverridden(status *IPNStatus) bool {
	if status == nil || status.State != ipn.Running || !status.Prefs.Valid() {
		return false
	}
	if status.Prefs.AutoExitNode().IsSet() || status.Prefs.ExitNodeIP().IsValid() {
		return true
	}
	id := status.Prefs.ExitNodeID()
	if id == "" {
		_, complete := status.Self()
		return complete
	}
	peer, ok := status.Peers[id]
	return ok && peer.Valid() && !IsMullvad(peer)
}

func autoSwitchStatusTransient(status *IPNStatus) bool {
	_, hasSelf := status.Self()
	return status == nil || status.State != ipn.Running || !hasSelf || status.Peers == nil || !status.Prefs.Valid()
}

func eligibleAutoSwitchStatus(status *IPNStatus) (tailcfg.NodeView, tailcfg.StableNodeID, string, bool) {
	if status == nil || status.State != ipn.Running {
		return tailcfg.NodeView{}, "", "Waiting for Tailscale to be running", false
	}
	if _, ok := status.Self(); !ok || status.Peers == nil {
		return tailcfg.NodeView{}, "", "Waiting for complete Tailscale status", false
	}
	if !status.Prefs.Valid() {
		return tailcfg.NodeView{}, "", "Waiting for Tailscale preferences", false
	}
	if status.Prefs.AutoExitNode().IsSet() {
		return tailcfg.NodeView{}, "", "Connection checks are off while Tailscale Automatic is active", false
	}
	id := status.Prefs.ExitNodeID()
	if id == "" {
		return tailcfg.NodeView{}, "", "No ID-based exit node is selected", false
	}
	peer, ok := status.Peers[id]
	if !ok || !peer.Valid() {
		return tailcfg.NodeView{}, "", "Waiting for the selected exit node", false
	}
	if !IsMullvad(peer) {
		return tailcfg.NodeView{}, "", "The selected exit node is not Mullvad", false
	}
	return peer, id, "", true
}

func (l *autoSwitchLoop) handleTick(ctx context.Context, now time.Time) {
	if !l.config.Enabled || l.paused || l.daemonUnavailable || l.busy || !l.stateReconciled {
		return
	}
	if _, _, _, eligible := eligibleAutoSwitchStatus(l.status); !eligible {
		return
	}
	switch l.runtime.Mode {
	case AutoSwitchGrace:
		if !now.Before(l.runtime.NextAction) {
			l.runtime.Mode = AutoSwitchMonitoring
			l.runtime.Message = "Monitoring exit path"
			l.runtime.NextAction = now
			l.publish()
		}
	case AutoSwitchMonitoring:
		if !now.Before(l.runtime.NextAction) {
			l.startProbe(ctx, probeMonitor)
		}
	case AutoSwitchSuspect:
		if !now.Before(l.runtime.NextAction) {
			l.startProbe(ctx, probeConfirm)
		}
	case AutoSwitchVerifying:
		if now.After(l.verifyDeadline) {
			l.deferVerification(now, "Replacement verification timed out")
			return
		}
		if l.currentID == l.expectedID && !now.Before(l.runtime.NextAction) {
			l.startProbe(ctx, probeVerify)
		}
	case AutoSwitchRollingBack:
		if now.After(l.verifyDeadline) {
			l.recordFailure(now, "timed out while returning to the previous exit node")
			l.enterBackoff(now, "Could not return to the previous exit node")
		}
	case AutoSwitchBackoff:
		if !now.Before(l.runtime.NextAction) {
			l.backoffUntil = time.Time{}
			l.attempts = 0
			l.badSince = time.Time{}
			l.runtime.ConsecutiveFails = 0
			l.runtime.Mode = AutoSwitchMonitoring
			l.runtime.Message = "Monitoring exit path after backoff"
			l.runtime.NextAction = now
			l.saveState()
			l.publish()
		}
	}
}

func (l *autoSwitchLoop) startProbe(ctx context.Context, kind autoSwitchProbeKind) {
	if l.status == nil {
		return
	}
	l.busy = true
	l.generation++
	generation := l.generation
	probeTarget := l.probeTarget
	l.probeTarget = (l.probeTarget + 1) % len(autoSwitchProbeTargets)
	checkDNS := l.status.Prefs.CorpDNS()
	probeCtx, cancel := context.WithCancel(ctx)
	if kind == probeVerify && !l.verifyDeadline.IsZero() {
		cancel()
		probeCtx, cancel = context.WithDeadline(ctx, l.verifyDeadline)
	}
	l.cancel = cancel
	l.operationWorkers.Add(1)
	go func() {
		defer l.operationWorkers.Done()
		result := probeExitPath(probeCtx, l.manager.ops, probeTarget, checkDNS)
		select {
		case l.probeResults <- autoSwitchProbeEvent{generation: generation, kind: kind, result: result}:
		case <-ctx.Done():
		}
	}()
}

func (l *autoSwitchLoop) handleProbeResult(event autoSwitchProbeEvent, now time.Time) {
	if event.generation != l.generation {
		return
	}
	l.busy = false
	l.finishOperation()
	l.runtime.LastProbe = now
	l.runtime.LastProbeOK = event.result.EgressOK
	if event.result.Inconclusive {
		if event.kind == probeVerify {
			if now.After(l.verifyDeadline) {
				l.deferVerification(now, "Verification remained inconclusive until its deadline")
				return
			}
			l.runtime.Mode = AutoSwitchVerifying
			l.runtime.Message = "Verification inconclusive: " + event.result.Reason
			l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
			l.publish()
			return
		}
		l.badSince = time.Time{}
		l.runtime.ConsecutiveFails = 0
		l.runtime.Mode = AutoSwitchMonitoring
		l.runtime.Message = "Probe inconclusive: " + event.result.Reason
		l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
		l.publish()
		return
	}

	if event.result.EgressOK {
		if event.kind == probeVerify {
			if now.After(l.verifyDeadline) {
				l.failVerification(l.ctx, now, "verification probe exceeded its deadline")
				return
			}
			l.verifyCount++
			if l.verifyCount >= 2 {
				l.completeVerification(now)
				return
			}
			l.runtime.Message = fmt.Sprintf("Verification passed %d/2", l.verifyCount)
			l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
			l.publish()
			return
		}
		l.badSince = time.Time{}
		l.runtime.ConsecutiveFails = 0
		l.runtime.Mode = AutoSwitchMonitoring
		if event.result.DNSOK {
			l.runtime.Message = fmt.Sprintf("Exit path healthy (%v)", event.result.Latency.Round(time.Millisecond))
		} else {
			l.runtime.Message = "Exit egress healthy; " + event.result.Reason
		}
		l.runtime.NextAction = now.Add(l.config.ProbeInterval)
		l.publish()
		return
	}

	if event.kind == probeVerify {
		if !event.result.Underlay.Healthy() {
			message := underlayBlockedMessage("Verification failed", event.result.Underlay)
			if now.After(l.verifyDeadline) {
				l.deferVerification(now, message)
				return
			}
			l.runtime.Mode = AutoSwitchVerifying
			l.runtime.Message = message
			l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
			l.publish()
			return
		}
		l.failVerification(l.ctx, now, event.result.Reason)
		return
	}
	if !event.result.Underlay.Healthy() {
		l.badSince = time.Time{}
		l.runtime.ConsecutiveFails = 0
		l.runtime.Mode = AutoSwitchMonitoring
		l.runtime.Message = underlayBlockedMessage(event.result.Reason, event.result.Underlay)
		l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
		slog.Warn("exit path probe failed with unavailable underlay", "exit_node", l.currentLabel, "reason", event.result.Reason, "underlay_state", event.result.Underlay.State, "underlay_reason", event.result.Underlay.Reason)
		l.publish()
		return
	}

	if l.badSince.IsZero() {
		l.badSince = now
	}
	l.runtime.ConsecutiveFails++
	l.runtime.Mode = AutoSwitchSuspect
	l.runtime.Message = event.result.Reason
	l.runtime.NextAction = now.Add(autoSwitchConfirmInterval)
	slog.Warn("exit path probe failed", "exit_node", l.currentLabel, "failures", l.runtime.ConsecutiveFails, "reason", event.result.Reason, "underlay_state", event.result.Underlay.State)

	if l.runtime.ConsecutiveFails >= 3 && now.Sub(l.badSince) >= l.config.Threshold {
		if _, _, reason, eligible := eligibleAutoSwitchStatus(l.status); !eligible {
			l.enterGrace(now, reason)
			return
		}
		l.beginSwitch(l.ctx, now)
		return
	}
	l.publish()
}

func underlayBlockedMessage(prefix string, result underlayProbeResult) string {
	switch result.State {
	case underlayProbeUnhealthy:
		return prefix + "; not switching while the underlay is unhealthy: " + result.Reason
	case underlayProbeInconclusive:
		return prefix + "; not switching while the underlay check is inconclusive: " + result.Reason
	default:
		return prefix + "; not switching without a healthy underlay check"
	}
}

func (l *autoSwitchLoop) beginSwitch(ctx context.Context, now time.Time) {
	if l.currentID == "" || l.status == nil {
		l.enterBackoff(now, "current exit node is unavailable")
		return
	}
	if l.incidentFrom == "" {
		l.incidentSourceID = l.currentID
		l.incidentFrom = l.currentLabel
		l.incidentReason = l.runtime.Message
		l.incidentEpoch = l.manager.epoch.Load()
		l.quarantine[l.currentID] = now.Add(autoSwitchQuarantinePeriod)
		l.saveState()
	}
	l.runtime.Mode = AutoSwitchSwitching
	l.runtime.Message = "Selecting a replacement exit node"
	l.runtime.NextAction = time.Time{}
	l.publish()
	l.startCandidateSelection(ctx)
}

func (l *autoSwitchLoop) startCandidateSelection(ctx context.Context) {
	l.busy = true
	l.generation++
	generation := l.generation
	snapshot := l.status.copy()
	quarantine := maps.Clone(l.quarantine)
	selectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	l.cancel = cancel
	l.operationWorkers.Add(1)
	go func() {
		defer l.operationWorkers.Done()
		peer, err := selectAutoSwitchCandidate(selectCtx, l.manager.ops, snapshot, quarantine, time.Now())
		select {
		case l.candidateResults <- autoSwitchCandidateEvent{generation: generation, peer: peer, err: err}:
		case <-ctx.Done():
		}
	}()
}

func (l *autoSwitchLoop) handleCandidateResult(ctx context.Context, event autoSwitchCandidateEvent, now time.Time) {
	if event.generation != l.generation {
		return
	}
	l.busy = false
	l.finishOperation()
	if event.err != nil {
		if l.attempts > 0 && l.incidentSourceID != "" {
			l.startRollback(ctx, now, event.err.Error())
		} else {
			l.enterBackoff(now, event.err.Error())
		}
		return
	}
	if l.manager.epoch.Load() != l.incidentEpoch {
		l.enterGrace(now, "Auto-switch was cancelled by a newer user or configuration change")
		return
	}
	if l.status == nil || l.status.Prefs.ExitNodeID() != l.currentID {
		l.enterGrace(now, "Exit node changed during candidate selection")
		return
	}
	peer, ok := l.status.Peers[event.peer.StableID()]
	if !ok || !candidateEligible(peer, l.currentID, l.quarantine, now) {
		if l.attempts > 0 && l.incidentSourceID != "" {
			l.startRollback(ctx, now, "Selected Mullvad exit node is no longer available")
		} else {
			l.enterBackoff(now, "Selected Mullvad exit node is no longer available")
		}
		return
	}

	l.expectedPeer = peer
	l.expectedID = peer.StableID()
	l.runtime.Message = fmt.Sprintf("Switching %s to %s", l.currentLabel, peerLabel(peer))
	l.saveState()
	l.publish()
	l.startApply(ctx, peer)
}

func (l *autoSwitchLoop) startApply(ctx context.Context, target tailcfg.NodeView) {
	l.busy = true
	l.generation++
	generation := l.generation
	sourceID := l.currentID
	applyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	l.cancel = cancel
	epoch := l.incidentEpoch
	rollback := l.runtime.Mode == AutoSwitchRollingBack
	l.operationWorkers.Add(1)
	go func() {
		defer l.operationWorkers.Done()
		var err error
		writeAttempted := false
		if !rollback {
			underlay := l.manager.ops.ProbeUnderlay(applyCtx)
			if !underlay.Healthy() {
				err = fmt.Errorf("underlay changed before exit-node update: %s", underlay.Reason)
			}
		}
		var prefs *ipn.Prefs
		if err == nil {
			prefs, err = l.manager.ops.Prefs(applyCtx)
		}
		if err == nil && prefs == nil {
			err = errors.New("tailscaled returned no preferences")
		}
		if err == nil && prefs.ExitNodeID != sourceID {
			err = errors.New("exit node changed before automatic update")
		}
		if err == nil && (prefs.AutoExitNode.IsSet() || prefs.ExitNodeIP.IsValid()) {
			err = errors.New("exit-node mode changed before automatic update")
		}
		if err == nil {
			writeAttempted = true
			err = l.manager.ops.SetExitNode(applyCtx, target.StableID(), sourceID, func() bool {
				return l.manager.epoch.Load() == epoch && applyCtx.Err() == nil
			})
		}
		if err != nil && writeAttempted {
			verifyCtx, verifyCancel := context.WithTimeout(ctx, 3*time.Second)
			defer verifyCancel()
			if current, currentErr := l.manager.ops.Prefs(verifyCtx); currentErr == nil && current.ExitNodeID == target.StableID() && !current.ExitNodeIP.IsValid() && !current.AutoExitNode.IsSet() {
				err = nil
			}
		}
		select {
		case l.applyResults <- autoSwitchApplyEvent{generation: generation, target: target, rollback: rollback, err: err}:
		case <-ctx.Done():
		}
	}()
}

func (l *autoSwitchLoop) handleApplyResult(event autoSwitchApplyEvent, now time.Time) {
	if event.generation != l.generation {
		return
	}
	l.busy = false
	l.finishOperation()
	if event.err != nil {
		l.recordFailure(now, event.err.Error())
		if event.rollback {
			l.expectedID = ""
			l.expectedPeer = tailcfg.NodeView{}
			l.enterBackoff(now, "Could not return to the previous exit node")
			return
		}
		if l.attempts > 0 && l.incidentSourceID != "" {
			l.startRollback(l.ctx, now, event.err.Error())
		} else {
			l.enterBackoff(now, event.err.Error())
		}
		return
	}
	if event.rollback {
		l.runtime.Mode = AutoSwitchRollingBack
		l.runtime.Message = fmt.Sprintf("Waiting to return to %s", peerLabel(event.target))
		l.runtime.NextAction = time.Time{}
		l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
		l.saveState()
		l.publish()
		return
	}
	l.runtime.Mode = AutoSwitchVerifying
	l.runtime.Message = fmt.Sprintf("Waiting for %s to become current", peerLabel(event.target))
	l.runtime.NextAction = now.Add(5 * time.Second)
	l.verifyDeadline = now.Add(autoSwitchVerifyTimeout)
	l.verifyCount = 0
	l.saveState()
	l.publish()
}

func (l *autoSwitchLoop) failVerification(ctx context.Context, now time.Time, reason string) {
	if l.expectedID != "" {
		l.quarantine[l.expectedID] = now.Add(autoSwitchQuarantinePeriod)
	}
	l.recordFailure(now, reason)
	l.attempts++
	l.verifyCount = 0
	l.expectedID = ""
	l.expectedPeer = tailcfg.NodeView{}
	if l.attempts >= autoSwitchMaxCandidates {
		l.startRollback(ctx, now, reason)
		return
	}
	peer, id, eligibilityReason, eligible := eligibleAutoSwitchStatus(l.status)
	if !eligible {
		l.enterGrace(now, eligibilityReason)
		return
	}
	l.currentID = id
	l.currentLabel = peerLabel(peer)
	l.runtime.Mode = AutoSwitchSwitching
	l.runtime.Message = "Replacement failed verification; selecting another"
	l.saveState()
	l.publish()
	l.startCandidateSelection(ctx)
}

func (l *autoSwitchLoop) startRollback(ctx context.Context, now time.Time, reason string) {
	if l.incidentSourceID == "" || l.status == nil {
		l.enterBackoff(now, reason)
		return
	}
	peer, ok := l.status.Peers[l.incidentSourceID]
	if !ok || !peer.Valid() {
		l.enterBackoff(now, "Previous exit node is no longer available")
		return
	}
	l.expectedID = l.incidentSourceID
	l.expectedPeer = peer
	if l.status.Prefs.ExitNodeID() == l.incidentSourceID {
		l.completeRollback(now, l.currentLabel)
		return
	}
	l.runtime.Mode = AutoSwitchRollingBack
	l.runtime.Message = fmt.Sprintf("Returning to previous exit node %s", peerLabel(peer))
	l.runtime.NextAction = time.Time{}
	l.saveState()
	l.publish()
	l.startApply(ctx, peer)
}

func (l *autoSwitchLoop) completeRollback(now time.Time, failedLabel string) {
	event := AutoSwitchEvent{
		Time:    now,
		From:    failedLabel,
		To:      peerLabel(l.expectedPeer),
		Reason:  l.incidentReason,
		Outcome: "rolled-back",
		Error:   "Replacement exit nodes failed verification",
	}
	l.runtime.LastEvent = event
	l.managedID = l.incidentSourceID
	l.enterBackoff(now, "Returned to the previous exit node")
	slog.Warn("auto-switch returned to previous exit node", "from", event.From, "to", event.To, "reason", event.Reason)
}

func (l *autoSwitchLoop) deferVerification(now time.Time, reason string) {
	event := AutoSwitchEvent{
		Time:    now,
		From:    l.incidentFrom,
		To:      peerLabel(l.expectedPeer),
		Reason:  l.incidentReason,
		Outcome: "unverified",
		Error:   reason,
	}
	l.runtime.LastEvent = event
	slog.Warn("auto-switch exit node verification deferred", "from", event.From, "to", event.To, "reason", event.Reason, "err", reason)
	l.enterBackoff(now, reason)
}

func (l *autoSwitchLoop) completeVerification(now time.Time) {
	event := AutoSwitchEvent{
		Time:    now,
		From:    l.incidentFrom,
		To:      l.currentLabel,
		Reason:  l.incidentReason,
		Outcome: "verified",
	}
	l.runtime.LastEvent = event
	l.managedID = l.currentID
	l.runtime.Mode = AutoSwitchMonitoring
	l.runtime.Message = fmt.Sprintf("Verified switch to %s", l.currentLabel)
	l.runtime.NextAction = now.Add(l.config.ProbeInterval)
	l.runtime.ConsecutiveFails = 0
	l.badSince = time.Time{}
	l.verifyCount = 0
	l.expectedID = ""
	l.expectedPeer = tailcfg.NodeView{}
	l.incidentFrom = ""
	l.incidentSourceID = ""
	l.incidentReason = ""
	l.incidentEpoch = 0
	l.attempts = 0
	l.backoffUntil = time.Time{}
	l.saveState()
	l.publish()
	slog.Info("auto-switch exit node verified", "from", event.From, "to", event.To, "reason", event.Reason)
}

func (l *autoSwitchLoop) recordFailure(now time.Time, reason string) {
	event := AutoSwitchEvent{
		Time:    now,
		From:    l.incidentFrom,
		To:      peerLabel(l.expectedPeer),
		Reason:  l.incidentReason,
		Outcome: "failed",
		Error:   reason,
	}
	l.runtime.LastEvent = event
	slog.Error("auto-switch exit node failed", "from", event.From, "to", event.To, "reason", event.Reason, "err", reason)
}

func (l *autoSwitchLoop) enterGrace(now time.Time, message string) {
	l.abandonIncident()
	l.runtime.Mode = AutoSwitchGrace
	l.runtime.Message = message
	l.runtime.NextAction = now.Add(autoSwitchGracePeriod)
	l.runtime.ConsecutiveFails = 0
	l.badSince = time.Time{}
	l.publish()
}

func (l *autoSwitchLoop) enterBackoff(now time.Time, message string) {
	managedID := l.currentID
	if (l.runtime.Mode == AutoSwitchVerifying || l.runtime.Mode == AutoSwitchRollingBack) && l.expectedID != "" {
		managedID = l.expectedID
	}
	l.resetOperation()
	if managedID != "" {
		l.managedID = managedID
	}
	l.runtime.Mode = AutoSwitchBackoff
	l.runtime.Message = message
	l.runtime.NextAction = now.Add(autoSwitchBackoffPeriod)
	l.backoffUntil = l.runtime.NextAction
	l.runtime.ConsecutiveFails = 0
	l.badSince = time.Time{}
	l.clearIncident()
	l.saveState()
	l.publish()
}

func (l *autoSwitchLoop) resetOperation() {
	l.cancelOperation()
	l.generation++
	l.busy = false
	l.expectedID = ""
	l.expectedPeer = tailcfg.NodeView{}
	l.verifyCount = 0
}

func (l *autoSwitchLoop) cancelOperation() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

func (l *autoSwitchLoop) finishOperation() {
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

func (l *autoSwitchLoop) abandonIncident() {
	l.resetOperation()
	l.clearIncident()
}

func (l *autoSwitchLoop) clearIncident() {
	l.incidentSourceID = ""
	l.incidentFrom = ""
	l.incidentReason = ""
	l.incidentEpoch = 0
	l.attempts = 0
	l.badSince = time.Time{}
	l.runtime.ConsecutiveFails = 0
}

func (l *autoSwitchLoop) publish() {
	previous := l.manager.Runtime()
	l.manager.setRuntime(l.runtime)
	if previous.Mode != l.runtime.Mode || previous.Message != l.runtime.Message {
		slog.Info("auto-switch state changed", "from", previous.Mode, "to", l.runtime.Mode, "message", l.runtime.Message, "exit_node", l.currentLabel)
	}
}

func selectAutoSwitchCandidate(ctx context.Context, ops autoSwitchOps, status *IPNStatus, quarantine map[tailcfg.StableNodeID]time.Time, now time.Time) (tailcfg.NodeView, error) {
	if status == nil {
		return tailcfg.NodeView{}, errors.New("missing status")
	}
	currentID := status.Prefs.ExitNodeID()
	current, ok := status.Peers[currentID]
	if !ok || !current.Valid() {
		return tailcfg.NodeView{}, errors.New("current exit node is missing from status")
	}
	if suggested, err := ops.SuggestExitNode(ctx); err == nil {
		if peer, ok := status.Peers[suggested.ID]; ok && candidateEligible(peer, currentID, quarantine, now) {
			return peer, nil
		}
	}

	candidates := make([]tailcfg.NodeView, 0, len(status.Peers))
	for _, peer := range status.Peers {
		if candidateEligible(peer, currentID, quarantine, now) {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) == 0 {
		return tailcfg.NodeView{}, errors.New("no unquarantined Mullvad exit node is available")
	}
	slices.SortFunc(candidates, func(a, b tailcfg.NodeView) int {
		return compareAutoSwitchCandidates(current, a, b)
	})
	return candidates[0], nil
}

func selectInitialMullvadCandidate(ctx context.Context, ops autoSwitchOps, status *IPNStatus, now time.Time) (tailcfg.NodeView, error) {
	if status == nil || status.Peers == nil || !status.Prefs.Valid() {
		return tailcfg.NodeView{}, errors.New("complete Tailscale status is unavailable")
	}
	currentID := status.Prefs.ExitNodeID()
	if current, ok := status.Peers[currentID]; ok && current.Valid() && IsMullvad(current) {
		return current, nil
	}
	if suggested, err := ops.SuggestExitNode(ctx); err == nil {
		if peer, ok := status.Peers[suggested.ID]; ok && candidateEligible(peer, currentID, nil, now) {
			return peer, nil
		}
	}

	candidates := make([]tailcfg.NodeView, 0, len(status.Peers))
	for _, peer := range status.Peers {
		if candidateEligible(peer, currentID, nil, now) {
			candidates = append(candidates, peer)
		}
	}
	if len(candidates) == 0 {
		return tailcfg.NodeView{}, errors.New("no online Mullvad exit node is available")
	}
	slices.SortFunc(candidates, ComparePeers)
	return candidates[0], nil
}

func candidateEligible(peer tailcfg.NodeView, current tailcfg.StableNodeID, quarantine map[tailcfg.StableNodeID]time.Time, now time.Time) bool {
	if !peer.Valid() || peer.StableID() == current || !IsMullvad(peer) || !peer.Online().Get() {
		return false
	}
	return !quarantine[peer.StableID()].After(now)
}

func compareAutoSwitchCandidates(current, a, b tailcfg.NodeView) int {
	var currentLocation, aLocation, bLocation tailcfg.LocationView
	if hi := current.Hostinfo(); hi.Valid() {
		currentLocation = hi.Location()
	}
	if hi := a.Hostinfo(); hi.Valid() {
		aLocation = hi.Location()
	}
	if hi := b.Hostinfo(); hi.Valid() {
		bLocation = hi.Location()
	}
	aCity := currentLocation.Valid() && aLocation.Valid() && aLocation.CityCode() == currentLocation.CityCode()
	bCity := currentLocation.Valid() && bLocation.Valid() && bLocation.CityCode() == currentLocation.CityCode()
	if aCity != bCity {
		if aCity {
			return -1
		}
		return 1
	}
	aCountry := currentLocation.Valid() && aLocation.Valid() && aLocation.CountryCode() == currentLocation.CountryCode()
	bCountry := currentLocation.Valid() && bLocation.Valid() && bLocation.CountryCode() == currentLocation.CountryCode()
	if aCountry != bCountry {
		if aCountry {
			return -1
		}
		return 1
	}
	return ComparePeers(a, b)
}

func peerLabel(peer tailcfg.NodeView) string {
	if !peer.Valid() {
		return "none"
	}
	if hi := peer.Hostinfo(); hi.Valid() {
		if hostname := hi.Hostname(); hostname != "" {
			return hostname
		}
	}
	return peer.Name()
}
