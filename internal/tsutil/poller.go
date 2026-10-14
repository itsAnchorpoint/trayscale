package tsutil

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os/user"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/taildrop"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

// A Poller gets the latest Tailscale status at regular intervals or
// when manually triggered.
//
// A zero-value of a Poller is ready to use.
//
// It is a race condition to change any exported fields of Poller
// while Run is running.
type Poller struct {
	// Interval is the default interval to use for polling.
	//
	// If it is a zero, a non-zero default will be used.
	Interval time.Duration

	// If non-nil, New will be called when a new status is received from
	// Tailscale.
	New func(Status)

	once sync.Once

	poll     chan struct{}
	getIPN   chan *IPNStatus
	nextIPN  chan *IPNStatus
	interval chan time.Duration

	autoSwitch *AutoSwitchManager
}

func (p *Poller) init() {
	p.once.Do(func() {
		p.poll = make(chan struct{})
		p.getIPN = make(chan *IPNStatus)
		p.nextIPN = make(chan *IPNStatus)
		p.interval = make(chan time.Duration)
		p.autoSwitch = NewAutoSwitchManager()
	})
}

// Run runs the poller. It blocks until polling is done, which is
// generally a result of the given Context being cancelled.
//
// The behavior of two calls to Run running concurrently is undefined.
// Don't do it.
func (p *Poller) Run(ctx context.Context) {
	p.init()

	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()

	n := newNotifier()
	run := func(f func(context.Context)) {
		workers.Go(func() {
			f(ctx)
		})
	}
	run(p.autoSwitch.Run)
	run(p.watchIPN)
	run(func(ctx context.Context) { p.watchFiles(ctx, n) })
	run(func(ctx context.Context) { p.watchProfiles(ctx, n) })

	interval := p.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	check := time.NewTicker(interval)
	defer check.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case p.poll <- struct{}{}:
			n = n.Notify()
			check.Reset(interval)
		case interval = <-p.interval:
			n = n.Notify()
			check.Reset(interval)
		case <-check.C:
			n = n.Notify()
		}
	}
}

func (p *Poller) watchIPN(ctx context.Context) {
	set := make(chan *IPNStatus)
	stateWorkerDone := make(chan struct{})
	go func() {
		defer close(stateWorkerDone)
		var get chan *IPNStatus
		var s *IPNStatus
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-set:
				s = next.copy()
				s.AutoSwitch = p.autoSwitch.Runtime()
				get = p.getIPN
				p.publish(s)
			case runtime := <-p.autoSwitch.RuntimeUpdates():
				if s != nil {
					s = s.copy()
					s.AutoSwitch = runtime
					p.publish(s)
					select {
					case p.nextIPN <- s:
					default:
					}
				}
			case get <- s:
			}
		}
	}()
	defer func() { <-stateWorkerDone }()

	for {
		err := p.watchIPNBus(ctx, set)
		if ctx.Err() != nil {
			return
		}
		p.autoSwitch.DaemonUnavailable()
		unavailable := &IPNStatus{AutoSwitch: p.autoSwitch.Runtime()}
		select {
		case <-ctx.Done():
			return
		case set <- unavailable:
		}
		slog.Error("IPN bus watcher stopped", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *Poller) watchIPNBus(ctx context.Context, set chan<- *IPNStatus) error {
	const watcherOpts = ipn.NotifyInitialState |
		ipn.NotifyInitialPrefs |
		ipn.NotifyWatchEngineUpdates |
		ipn.NotifyInitialStatus |
		ipn.NotifyPeerChanges

	watcher, err := localClient.WatchIPNBus(ctx, watcherOpts)
	if err != nil {
		return fmt.Errorf("start IPN bus watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	var s IPNStatus
	var targetsPending bool
	for {
		notify, err := watcher.Next()
		if err != nil {
			return err
		}

		if notify.ErrMessage != nil {
			var state ipn.State
			if notify.State != nil {
				state = *notify.State
			}
			slog.Error("watcher got error message", "state", state, "err", notify.ErrMessage)
		}

		dirty, targetsDirty := s.applyNotify(&notify)
		if notify.State != nil && *notify.State == ipn.NoState {
			targetsPending = false
		}
		if targetsDirty {
			clear(s.FileTargets)
		}
		targetsPending = targetsPending || targetsDirty
		if targetsPending && s.refreshFileTargets(ctx) {
			targetsPending = false
			dirty = true
		}

		// TODO: Handle health warnings.
		if !dirty {
			continue
		}
		p.autoSwitch.UpdateStatus(s.copy())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.poll:
		}

		c := s.copy()
		c.AutoSwitch = p.autoSwitch.Runtime()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case set <- c:
		}
		select {
		case p.nextIPN <- c:
		default:
		}
	}
}

func (p *Poller) watchFiles(ctx context.Context, n *notifier) {
	for {
		files, err := WaitingFiles(ctx)
		if err != nil && !errors.Is(err, taildrop.ErrNoTaildrop) {
			if ctx.Err() != nil {
				return
			}
			slog.Error("get waiting files", "err", err)
			goto wait
		}

		p.publish(&FileStatus{Files: files})

	wait:
		select {
		case <-ctx.Done():
			return
		case <-n.notify:
			n = n.next
		}
	}
}

func (p *Poller) watchProfiles(ctx context.Context, n *notifier) {
	for {
		profile, profiles, err := GetProfileStatus(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("get profile status", "err", err)
			goto wait
		}

		p.publish(&ProfileStatus{Profile: profile, Profiles: profiles})

	wait:
		select {
		case <-ctx.Done():
			return
		case <-n.notify:
			n = n.next
		}
	}
}

// Poll returns a channel that, when received from, refreshes waiting
// files and login profiles. IPN status comes from the watch bus;
// receiving also unblocks publishing of a pending IPN update.
func (p *Poller) Poll() <-chan struct{} {
	p.init()

	return p.poll
}

// GetIPN returns a channel that yields the most recently fetched
// network status. It will block until the network status has been
// fetched successfully once.
func (p *Poller) GetIPN() <-chan *IPNStatus {
	p.init()

	return p.getIPN
}

// NextIPN returns a channel that is sent the new IPNStatus each time
// it is available if anyone is receiving from it. Unlike [GetIPN],
// this channel does not yield the previous status, so it is useful if
// an update is expected to arrive soon. Most usages should use
// [GetIPN] instead as it significantly faster.
func (p *Poller) NextIPN() <-chan *IPNStatus {
	p.init()

	return p.nextIPN
}

// SetInterval returns a channel that modifies the polling interval of
// a running poller. This will delay the next poll until the new
// interval has elapsed.
func (p *Poller) SetInterval() chan<- time.Duration {
	p.init()

	return p.interval
}

func (p *Poller) publish(status Status) {
	if p.New != nil {
		p.New(status)
	}
}

func (p *Poller) SetAutoSwitch(config AutoSwitchConfig) {
	p.init()
	p.autoSwitch.SetConfig(config)
}

func (p *Poller) AutoSwitchOverrides() <-chan struct{} {
	p.init()
	return p.autoSwitch.Overrides()
}

func (p *Poller) SetAutomaticExitNode(ctx context.Context) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}
	if err := SetAutomaticExitNode(ctx); err != nil {
		p.resumeAutoSwitch()
		return err
	}
	return nil
}

func (p *Poller) SetHealthCheckedExitNode(ctx context.Context) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}

	var status *IPNStatus
	select {
	case <-ctx.Done():
		p.resumeAutoSwitch()
		return ctx.Err()
	case status = <-p.GetIPN():
	}
	if status == nil || !status.Online() {
		p.resumeAutoSwitch()
		return errors.New("tailscale is not running")
	}
	owner, ok := autoSwitchStatusOwner(status)
	if !ok {
		p.resumeAutoSwitch()
		return errors.New("complete Tailscale status is unavailable")
	}

	peer, err := selectInitialMullvadCandidate(ctx, localAutoSwitchOps{}, status, time.Now())
	if err != nil {
		p.resumeAutoSwitch()
		return err
	}
	if status.Prefs.ExitNodeID() == peer.StableID() {
		err = disableAutomaticExitNode(ctx, peer.StableID())
	} else {
		err = ExitNode(ctx, peer.StableID())
	}
	if err != nil {
		p.resumeAutoSwitch()
		return err
	}

	return p.autoSwitch.resumeWhenSpecific(ctx, peer.StableID(), owner)
}

func (p *Poller) SetSpecificExitNodeMode(ctx context.Context) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}

	var status *IPNStatus
	select {
	case <-ctx.Done():
		p.resumeAutoSwitch()
		return ctx.Err()
	case status = <-p.GetIPN():
	}
	if status == nil || !status.Prefs.Valid() || !status.Prefs.AutoExitNode().IsSet() {
		return nil
	}
	id := status.Prefs.ExitNodeID()
	if id == "" {
		p.resumeAutoSwitch()
		return errors.New("tailscale has not selected an automatic exit node yet")
	}
	if _, ok := status.Peers[id]; !ok {
		p.resumeAutoSwitch()
		return errors.New("the automatic exit node is not available yet")
	}
	if err := disableAutomaticExitNode(ctx, id); err != nil {
		p.resumeAutoSwitch()
		return err
	}
	return nil
}

func (p *Poller) resumeAutoSwitch() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.autoSwitch.Resume(ctx); err != nil {
		slog.Error("resume exit-node connection checks", "err", err)
	}
}

func (p *Poller) ExitNode(ctx context.Context, peer tailcfg.StableNodeID) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}
	if err := ExitNode(ctx, peer); err != nil {
		p.resumeAutoSwitch()
		return err
	}
	return nil
}

func (p *Poller) SetUseExitNode(ctx context.Context, use bool) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}
	if err := SetUseExitNode(ctx, use); err != nil {
		p.resumeAutoSwitch()
		return err
	}
	return nil
}

func (p *Poller) SwitchProfile(ctx context.Context, id ipn.ProfileID) error {
	p.init()
	if err := p.autoSwitch.Pause(ctx); err != nil {
		return err
	}
	if err := SwitchProfile(ctx, id); err != nil {
		p.resumeAutoSwitch()
		return err
	}
	return nil
}

type Status interface {
	status()
}

type IPNStatus struct {
	State       ipn.State
	Prefs       ipn.PrefsView
	self        tailcfg.NodeView
	Peers       map[tailcfg.StableNodeID]tailcfg.NodeView
	FileTargets set.Set[tailcfg.StableNodeID]
	Engine      *ipn.EngineStatus
	AutoSwitch  AutoSwitchRuntime
	BrowseToURL string
}

func (*IPNStatus) status() {}

func (s IPNStatus) copy() *IPNStatus {
	s.Peers = maps.Clone(s.Peers)
	s.FileTargets = maps.Clone(s.FileTargets)
	return &s
}

func (s *IPNStatus) ensurePeers() {
	if s.Peers == nil {
		s.Peers = make(map[tailcfg.StableNodeID]tailcfg.NodeView)
	}
}

// applyNotify applies notify. targetsDirty reports that Taildrop eligibility
// may have changed.
func (s *IPNStatus) applyNotify(notify *ipn.Notify) (dirty, targetsDirty bool) {
	if notify.State != nil {
		state := *notify.State
		if state == ipn.NoState {
			// Profile switches keep the bus session but do not send removals for
			// the previous profile's self and peers.
			*s = IPNStatus{}
		}
		s.State = state
		dirty = true
	}
	if notify.Prefs != nil && notify.Prefs.Valid() {
		s.Prefs = *notify.Prefs
		dirty = true
	}
	if notify.Engine != nil {
		s.Engine = notify.Engine
		dirty = true
	}
	if notify.BrowseToURL != nil {
		s.BrowseToURL = *notify.BrowseToURL
		dirty = true
	}

	if notify.InitialStatus != nil {
		s.applyInitialStatus(notify.InitialStatus)
		dirty = true
		targetsDirty = true
	}
	if notify.SelfChange != nil {
		dirty = true
		s.applySelfChange(notify.SelfChange)
		targetsDirty = true
	}
	if len(notify.PeersChanged) != 0 {
		dirty = true
		s.applyPeersChanged(notify.PeersChanged)
		targetsDirty = true
	}
	if len(notify.PeersRemoved) != 0 {
		dirty = true
		targetsDirty = s.applyPeersRemoved(notify.PeersRemoved) || targetsDirty
	}
	return dirty, targetsDirty
}

func (s *IPNStatus) applyInitialStatus(st *ipnstate.Status) {
	var suffix string
	if st.CurrentTailnet != nil {
		suffix = st.CurrentTailnet.MagicDNSSuffix
	}

	if st.Self != nil {
		s.self = nodeViewFromPeerStatus(st.Self, suffix)
	}

	s.ensurePeers()
	clear(s.Peers)
	for _, peer := range st.Peer {
		if peer == nil {
			continue
		}
		s.Peers[peer.ID] = nodeViewFromPeerStatus(peer, suffix)
	}
}

func (s *IPNStatus) applySelfChange(self *tailcfg.Node) (identityChanged bool) {
	nv := self.View()
	if s.self.Valid() && nv.Valid() && !sameSelfNode(s.self, nv) {
		// Profile switches reuse the watch session and send a complete
		// PeersChanged list without PeersRemoved for the old nodes.
		clear(s.Peers)
		clear(s.FileTargets)
		identityChanged = true
	}
	s.self = nv
	return identityChanged
}

func sameSelfNode(a, b tailcfg.NodeView) bool {
	return a.ID() == b.ID() && a.StableID() == b.StableID() && a.User() == b.User()
}

func (s *IPNStatus) applyPeersChanged(peers []*tailcfg.Node) (added bool) {
	s.ensurePeers()
	for _, peer := range peers {
		if _, ok := s.Peers[peer.StableID]; !ok {
			added = true
		}
		s.Peers[peer.StableID] = peer.View()
	}
	return added
}

func (s *IPNStatus) applyPeersRemoved(ids []tailcfg.NodeID) (removed bool) {
	for _, id := range ids {
		for stableID, peer := range s.Peers {
			if peer.ID() == id {
				delete(s.Peers, stableID)
				removed = true
				break
			}
		}
	}
	return removed
}

func (s *IPNStatus) refreshFileTargets(ctx context.Context) bool {
	// This is a lot longer than it probably should be. It's basically
	// just to make sure that the poller doesn't get completely stuck. If
	// this is getting hit, though, the UI is going to be updating
	// horribly slow.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	targets, err := FileTargets(ctx)
	if err != nil {
		slog.Error("failed to get file targets", "err", err)
		return false
	}
	s.FileTargets.Make()
	clear(s.FileTargets)
	for _, target := range targets {
		s.FileTargets.Add(target.Node.StableID)
	}
	return true
}

// nodeViewFromPeerStatus builds a NodeView from an ipnstate.PeerStatus for
// the InitialStatus bootstrap. Subsequent updates use full Nodes from
// SelfChange / PeersChanged.
func nodeViewFromPeerStatus(ps *ipnstate.PeerStatus, magicDNSSuffix string) tailcfg.NodeView {
	if ps == nil {
		return tailcfg.NodeView{}
	}

	online := ps.Online
	n := &tailcfg.Node{
		ID:       ps.NodeID,
		StableID: ps.ID,
		Name:     ps.DNSName,
		User:     ps.UserID,
		Sharer:   ps.AltSharerUserID,
		Key:      ps.PublicKey,
		Created:  ps.Created,
		Online:   &online,
		Expired:  ps.Expired,
		CapMap:   maps.Clone(ps.CapMap),
	}
	if ps.KeyExpiry != nil {
		n.KeyExpiry = *ps.KeyExpiry
	}
	if !ps.LastSeen.IsZero() {
		lastSeen := ps.LastSeen
		n.LastSeen = &lastSeen
	}
	for _, ip := range ps.TailscaleIPs {
		n.Addresses = append(n.Addresses, netip.PrefixFrom(ip, ip.BitLen()))
	}
	if ps.AllowedIPs != nil {
		n.AllowedIPs = ps.AllowedIPs.AsSlice()
	}
	if ps.Tags != nil {
		n.Tags = ps.Tags.AsSlice()
	}
	if ps.PrimaryRoutes != nil {
		n.PrimaryRoutes = ps.PrimaryRoutes.AsSlice()
	}

	hi := &tailcfg.Hostinfo{
		Hostname:   ps.HostName,
		OS:         ps.OS,
		ShareeNode: ps.ShareeNode,
	}
	if ps.Location != nil {
		loc := *ps.Location
		hi.Location = &loc
	}
	n.Hostinfo = hi.View()
	n.InitDisplayNames(magicDNSSuffix)
	return n.View()
}

// Online returns true if s indicates that the local node is online
// and connected to the tailnet.
func (s *IPNStatus) Online() bool {
	return s != nil && s.State == ipn.Running
}

func (s *IPNStatus) NeedsAuth() bool {
	return s != nil && s.State == ipn.NeedsLogin
}

func (s *IPNStatus) ExitNodeActive() bool {
	if s == nil || !s.Prefs.Valid() {
		return false
	}
	return s.Prefs.ExitNodeID() != "" || s.Prefs.ExitNodeIP().IsValid()
}

func (s *IPNStatus) ExitNode() tailcfg.NodeView {
	if s == nil || !s.Prefs.Valid() {
		return tailcfg.NodeView{}
	}
	if node, ok := s.Peers[s.Prefs.ExitNodeID()]; ok {
		return node
	}
	if addr := s.Prefs.ExitNodeIP(); addr.IsValid() {
		return s.peerByTailscaleIP(addr)
	}
	return tailcfg.NodeView{}
}

func (s *IPNStatus) peerByTailscaleIP(ip netip.Addr) tailcfg.NodeView {
	for _, peer := range s.Peers {
		for _, a := range peer.Addresses().All() {
			if a.Addr() == ip {
				return peer
			}
		}
	}
	return tailcfg.NodeView{}
}

func (s *IPNStatus) OperatorIsCurrent() bool {
	if s == nil || !s.Prefs.Valid() {
		return false
	}
	current, err := user.Current()
	if err != nil {
		slog.Error("get current user", "err", err)
		return false
	}

	return s.Prefs.OperatorUser() == current.Username
}

// Self returns the local node. The boolean is false when the node is
// missing or invalid.
func (s *IPNStatus) Self() (tailcfg.NodeView, bool) {
	if s == nil {
		return tailcfg.NodeView{}, false
	}
	n := s.self
	return n, n.Valid()
}

func (s *IPNStatus) SelfAddr() netip.Addr {
	self, ok := s.Self()
	if !ok {
		return netip.Addr{}
	}

	addrs := self.Addresses()
	if addrs.Len() == 0 {
		return netip.Addr{}
	}

	addr := addrs.At(0)
	for _, a := range addrs.SliceFrom(1).All() {
		if a.Compare(addr) < 0 {
			addr = a
		}
	}
	return addr.Addr()
}

type FileStatus struct {
	Files []apitype.WaitingFile
}

func (*FileStatus) status() {}

type ProfileStatus struct {
	Profile  ipn.LoginProfile
	Profiles []ipn.LoginProfile
}

func (*ProfileStatus) status() {}

type notifier struct {
	notify chan struct{}
	next   *notifier
}

func newNotifier() *notifier {
	return &notifier{
		notify: make(chan struct{}),
	}
}

func (n *notifier) Notify() *notifier {
	n.next = newNotifier()
	close(n.notify)
	return n.next
}
