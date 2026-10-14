package tsutil

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
)

func TestMain(m *testing.M) {
	stateHome, err := os.MkdirTemp("", "trayscale-autoswitch-test-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_STATE_HOME", stateHome); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(stateHome)
	os.Exit(code)
}

type fakeAutoSwitchOps struct {
	dial     func(context.Context, string, uint16) (net.Conn, error)
	dns      func(context.Context, string, string) ([]byte, error)
	underlay func(context.Context) underlayProbeResult
	suggest  func(context.Context) (apitype.ExitNodeSuggestionResponse, error)
	prefs    func(context.Context) (*ipn.Prefs, error)
	setExit  func(context.Context, tailcfg.StableNodeID, tailcfg.StableNodeID, func() bool) error
}

func (f *fakeAutoSwitchOps) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return f.dial(ctx, host, port)
}

func (f *fakeAutoSwitchOps) QueryDNS(ctx context.Context, name, queryType string) ([]byte, error) {
	return f.dns(ctx, name, queryType)
}

func (f *fakeAutoSwitchOps) ProbeUnderlay(ctx context.Context) underlayProbeResult {
	if f.underlay == nil {
		return underlayProbeResult{State: underlayProbeInconclusive, Reason: "not configured"}
	}
	return f.underlay(ctx)
}

func (f *fakeAutoSwitchOps) SuggestExitNode(ctx context.Context) (apitype.ExitNodeSuggestionResponse, error) {
	if f.suggest == nil {
		return apitype.ExitNodeSuggestionResponse{}, errors.New("no suggestion")
	}
	return f.suggest(ctx)
}

func (f *fakeAutoSwitchOps) Prefs(ctx context.Context) (*ipn.Prefs, error) {
	return f.prefs(ctx)
}

func (f *fakeAutoSwitchOps) SetExitNode(ctx context.Context, id, expected tailcfg.StableNodeID, valid func() bool) error {
	return f.setExit(ctx, id, expected, valid)
}

func testMullvadNode(id tailcfg.StableNodeID, nodeID tailcfg.NodeID, hostname, country, city string, online bool) tailcfg.NodeView {
	return (&tailcfg.Node{
		ID:       nodeID,
		StableID: id,
		Name:     hostname + ".mullvad.ts.net.",
		Tags:     []string{"tag:mullvad-exit-node"},
		Online:   &online,
		Hostinfo: (&tailcfg.Hostinfo{
			Hostname: hostname,
			Location: &tailcfg.Location{
				CountryCode: country,
				CityCode:    city,
			},
		}).View(),
	}).View()
}

func testAutoSwitchStatus(current tailcfg.NodeView, others ...tailcfg.NodeView) *IPNStatus {
	peers := make(map[tailcfg.StableNodeID]tailcfg.NodeView, len(others)+1)
	peers[current.StableID()] = current
	for _, peer := range others {
		peers[peer.StableID()] = peer
	}
	return &IPNStatus{
		State: ipn.Running,
		Prefs: (&ipn.Prefs{
			ExitNodeID: current.StableID(),
			CorpDNS:    true,
		}).View(),
		self:   (&tailcfg.Node{ID: 100, StableID: "self", User: 1}).View(),
		Peers:  peers,
		Engine: &ipn.EngineStatus{LiveDERPs: 1},
	}
}

func TestProbeExitPath(t *testing.T) {
	tests := []struct {
		name             string
		first            int
		checkDNS         bool
		dialError        map[string]error
		dnsError         error
		wantDial         []string
		wantUnderlay     bool
		wantOK           bool
		wantInconclusive bool
	}{
		{
			name:     "first target and DNS healthy",
			checkDNS: true,
			wantDial: []string{"1.1.1.1"},
			wantOK:   true,
		},
		{
			name:      "fallback target healthy",
			first:     1,
			checkDNS:  true,
			dialError: map[string]error{"9.9.9.9": errors.New("unreachable")},
			wantDial:  []string{"9.9.9.9", "1.1.1.1"},
			wantOK:    true,
		},
		{
			name:         "both egress targets fail",
			checkDNS:     true,
			dialError:    map[string]error{"1.1.1.1": errors.New("unreachable"), "9.9.9.9": errors.New("unreachable")},
			wantDial:     []string{"1.1.1.1", "9.9.9.9"},
			wantUnderlay: true,
		},
		{
			name:     "DNS fails while egress works",
			checkDNS: true,
			dnsError: errors.New("resolver timeout"),
			wantDial: []string{"1.1.1.1"},
		},
		{
			name:     "DNS LocalAPI error does not invalidate egress",
			checkDNS: true,
			dnsError: errors.New("access denied by LocalAPI"),
			wantDial: []string{"1.1.1.1"},
		},
		{
			name:     "DNS is not required when disabled",
			wantDial: []string{"1.1.1.1"},
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dialed []string
			var underlayProbes int
			ops := &fakeAutoSwitchOps{
				dial: func(_ context.Context, host string, _ uint16) (net.Conn, error) {
					dialed = append(dialed, host)
					if err := tt.dialError[host]; err != nil {
						return nil, err
					}
					conn, peer := net.Pipe()
					_ = peer.Close()
					return conn, nil
				},
				dns: func(_ context.Context, name, queryType string) ([]byte, error) {
					require.Equal(t, "example.com.", name)
					require.Equal(t, "A", queryType)
					if tt.dnsError != nil {
						return nil, tt.dnsError
					}
					return testDNSResponse(t, dnsmessage.RCodeSuccess, true), nil
				},
				underlay: func(context.Context) underlayProbeResult {
					underlayProbes++
					return underlayProbeResult{State: underlayProbeHealthy}
				},
			}

			result := probeExitPath(context.Background(), ops, tt.first, tt.checkDNS)
			require.Equal(t, tt.wantOK, result.Healthy())
			require.Equal(t, tt.wantInconclusive, result.Inconclusive)
			require.Equal(t, tt.wantDial, dialed)
			require.Equal(t, tt.wantUnderlay, underlayProbes == 1)
		})
	}
}

func TestLocalAPIDialTimeoutIsExitPathFailure(t *testing.T) {
	timeout := errors.New(`Post "http://local-tailscaled.sock/localapi/v0/dial": context deadline exceeded`)
	var underlayProbes atomic.Int32
	ops := &fakeAutoSwitchOps{
		dial: func(context.Context, string, uint16) (net.Conn, error) {
			return nil, timeout
		},
		underlay: func(context.Context) underlayProbeResult {
			underlayProbes.Add(1)
			return underlayProbeResult{State: underlayProbeHealthy}
		},
	}

	result := probeExitPath(context.Background(), ops, 0, false)
	require.False(t, result.Healthy())
	require.False(t, result.Inconclusive)
	require.Equal(t, underlayProbeHealthy, result.Underlay.State)
	require.EqualValues(t, 1, underlayProbes.Load())
}

func TestAutoSwitchDialRejectsDirectFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Dial-Self", "true")
		w.Header().Set("Dial-Addr", "127.0.0.1:1")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := local.Client{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	conn, err := dialTCPViaTailscale(context.Background(), &client, "1.1.1.1", 443)
	require.Nil(t, conn)
	require.ErrorIs(t, err, errAutoSwitchDirectDial)
}

func TestValidateDNSResponse(t *testing.T) {
	require.NoError(t, validateDNSResponse(testDNSResponse(t, dnsmessage.RCodeSuccess, true)))
	require.Error(t, validateDNSResponse(testDNSResponse(t, dnsmessage.RCodeNameError, false)))
	require.Error(t, validateDNSResponse(testDNSResponse(t, dnsmessage.RCodeSuccess, false)))
	require.Error(t, validateDNSResponse([]byte("not DNS")))
}

func testDNSResponse(t *testing.T, rcode dnsmessage.RCode, withAnswer bool) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("example.com.")
	require.NoError(t, err)
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RCode: rcode},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	if withAnswer {
		message.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}}
	}
	response, err := message.Pack()
	require.NoError(t, err)
	return response
}

func TestEligibleAutoSwitchStatusDoesNotDependOnDERPConnection(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-303", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	status.Engine.LiveDERPs = 0

	_, _, reason, eligible := eligibleAutoSwitchStatus(status)
	require.True(t, eligible)
	require.Empty(t, reason)

	status.Engine = nil
	_, _, _, eligible = eligibleAutoSwitchStatus(status)
	require.True(t, eligible)

	status.Prefs = ipn.PrefsView{}
	require.NotPanics(t, func() {
		_, _, _, eligible = eligibleAutoSwitchStatus(status)
	})
	require.False(t, eligible)
}

func TestBuiltInAutomaticDisablesHealthChecks(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-303", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	prefs := status.Prefs.AsStruct()
	prefs.AutoExitNode = ipn.AnyExitNode
	status.Prefs = prefs.View()

	_, _, reason, eligible := eligibleAutoSwitchStatus(status)
	require.False(t, eligible)
	require.Contains(t, reason, "Tailscale Automatic")

	loop := newTestAutoSwitchLoop(status)
	loop.config.Enabled = true
	loop.runtime.Enabled = true
	loop.reconcileStatus(time.Now())
	require.False(t, loop.runtime.Enabled)
	require.Equal(t, AutoSwitchDisabled, loop.runtime.Mode)
	select {
	case <-loop.manager.Overrides():
	default:
		t.Fatal("expected automatic mode to report a health-check override")
	}
}

func TestIncompleteStatusAccessorsDoNotPanic(t *testing.T) {
	status := &IPNStatus{}
	require.NotPanics(t, func() {
		require.False(t, status.ExitNodeActive())
		require.False(t, status.ExitNode().Valid())
		require.False(t, status.OperatorIsCurrent())
	})
}

func TestHalfAliveExitStartsOneSwitchAfterConfirmedFailures(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-301", "DE", "FRA", true)
	status := testAutoSwitchStatus(current, replacement)

	var suggestions atomic.Int32
	loop := newTestAutoSwitchLoop(status)
	loop.manager.ops = &fakeAutoSwitchOps{
		suggest: func(context.Context) (apitype.ExitNodeSuggestionResponse, error) {
			suggestions.Add(1)
			return apitype.ExitNodeSuggestionResponse{ID: replacement.StableID()}, nil
		},
	}
	loop.runtime.Mode = AutoSwitchMonitoring
	start := time.Date(2026, 7, 20, 15, 45, 0, 0, time.UTC)
	failed := exitPathProbeResult{Reason: "egress probes failed"}
	failed.Underlay.State = underlayProbeHealthy

	for i := range 3 {
		loop.handleProbeResult(autoSwitchProbeEvent{
			generation: loop.generation,
			kind:       probeConfirm,
			result:     failed,
		}, start.Add(time.Duration(i)*5*time.Second))
	}
	require.Equal(t, AutoSwitchSwitching, loop.runtime.Mode)
	require.True(t, loop.busy)

	require.Eventually(t, func() bool { return suggestions.Load() == 1 }, time.Second, time.Millisecond)
	loop.handleProbeResult(autoSwitchProbeEvent{generation: 0, kind: probeConfirm, result: failed}, start.Add(15*time.Second))
	require.EqualValues(t, 1, suggestions.Load())
	loop.cancelOperation()
}

func TestSharedUnderlayFailureDoesNotSwitch(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-301", "DE", "FRA", true)
	status := testAutoSwitchStatus(current, replacement)

	var suggestions atomic.Int32
	loop := newTestAutoSwitchLoop(status)
	loop.manager.ops = &fakeAutoSwitchOps{
		suggest: func(context.Context) (apitype.ExitNodeSuggestionResponse, error) {
			suggestions.Add(1)
			return apitype.ExitNodeSuggestionResponse{ID: replacement.StableID()}, nil
		},
	}
	loop.runtime.Mode = AutoSwitchMonitoring
	start := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	failed := exitPathProbeResult{
		Reason: "egress probes failed",
		Underlay: underlayProbeResult{
			State:  underlayProbeUnhealthy,
			Reason: "no DERP region reachable over TCP/443",
		},
	}

	for i := range 3 {
		loop.handleProbeResult(autoSwitchProbeEvent{
			generation: loop.generation,
			kind:       probeConfirm,
			result:     failed,
		}, start.Add(time.Duration(i)*5*time.Second))
	}
	require.Equal(t, AutoSwitchMonitoring, loop.runtime.Mode)
	require.Zero(t, loop.runtime.ConsecutiveFails)
	require.Contains(t, loop.runtime.Message, "underlay is unhealthy")
	require.Zero(t, suggestions.Load())

	failed.Underlay = underlayProbeResult{State: underlayProbeHealthy}
	for i := range 3 {
		loop.handleProbeResult(autoSwitchProbeEvent{
			generation: loop.generation,
			kind:       probeConfirm,
			result:     failed,
		}, start.Add(time.Duration(15+i*5)*time.Second))
	}
	require.Equal(t, AutoSwitchSwitching, loop.runtime.Mode)
	require.Eventually(t, func() bool { return suggestions.Load() == 1 }, time.Second, time.Millisecond)
	loop.cancelOperation()
}

func TestDNSOnlyFailureNeverSwitches(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-003", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-004", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current, replacement))
	var suggestions atomic.Int32
	loop.manager.ops = &fakeAutoSwitchOps{
		suggest: func(context.Context) (apitype.ExitNodeSuggestionResponse, error) {
			suggestions.Add(1)
			return apitype.ExitNodeSuggestionResponse{ID: replacement.StableID()}, nil
		},
	}
	start := time.Date(2026, 7, 24, 2, 14, 31, 0, time.UTC)
	failedDNS := exitPathProbeResult{
		EgressOK: true,
		Reason:   "DNS probe failed: context deadline exceeded",
	}

	for i := range 3 {
		loop.handleProbeResult(autoSwitchProbeEvent{
			generation: loop.generation,
			kind:       probeConfirm,
			result:     failedDNS,
		}, start.Add(time.Duration(i)*15*time.Second))
	}

	require.Equal(t, AutoSwitchMonitoring, loop.runtime.Mode)
	require.Zero(t, loop.runtime.ConsecutiveFails)
	require.True(t, loop.runtime.LastProbeOK)
	require.Contains(t, loop.runtime.Message, "egress healthy")
	require.Zero(t, suggestions.Load())
}

func TestVerificationUsesEgressNotSharedDNS(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	current := testMullvadNode("current", 1, "de-fra-wg-004", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.runtime.Mode = AutoSwitchVerifying
	loop.expectedID = current.StableID()
	loop.expectedPeer = current
	loop.verifyDeadline = time.Now().Add(time.Minute)
	result := exitPathProbeResult{
		EgressOK: true,
		Reason:   "DNS probe failed: context deadline exceeded",
	}

	loop.handleProbeResult(autoSwitchProbeEvent{generation: loop.generation, kind: probeVerify, result: result}, time.Now())
	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.Equal(t, 1, loop.verifyCount)

	loop.handleProbeResult(autoSwitchProbeEvent{generation: loop.generation, kind: probeVerify, result: result}, time.Now().Add(5*time.Second))
	require.Equal(t, AutoSwitchMonitoring, loop.runtime.Mode)
	require.Equal(t, "verified", loop.runtime.LastEvent.Outcome)
}

func TestVerificationFailureWaitsForHealthyUnderlay(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.runtime.Mode = AutoSwitchVerifying
	loop.expectedID = current.StableID()
	loop.expectedPeer = current
	loop.verifyDeadline = time.Now().Add(time.Minute)

	loop.handleProbeResult(autoSwitchProbeEvent{
		generation: loop.generation,
		kind:       probeVerify,
		result: exitPathProbeResult{
			Reason: "egress probes failed",
			Underlay: underlayProbeResult{
				State:  underlayProbeUnhealthy,
				Reason: "no DERP region reachable over TCP/443",
			},
		},
	}, time.Now())

	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.Empty(t, loop.quarantine)
	require.Contains(t, loop.runtime.Message, "underlay is unhealthy")
}

func TestClassifyUnderlayProbe(t *testing.T) {
	require.Equal(t, underlayProbeHealthy, classifyUnderlayProbe(&netcheck.Report{
		UDP:           false,
		RegionLatency: map[int]time.Duration{4: 40 * time.Millisecond},
	}, nil).State)
	require.Equal(t, underlayProbeUnhealthy, classifyUnderlayProbe(&netcheck.Report{}, nil).State)
	require.Equal(t, underlayProbeInconclusive, classifyUnderlayProbe(nil, nil).State)
	require.Equal(t, underlayProbeInconclusive, classifyUnderlayProbe(nil, errors.New("netcheck unavailable")).State)
}

func TestPreferenceUpdateIsNotRecordedAsSuccess(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-301", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current, replacement))
	loop.runtime.Mode = AutoSwitchSwitching
	loop.expectedID = replacement.StableID()
	loop.expectedPeer = replacement

	loop.handleApplyResult(autoSwitchApplyEvent{generation: loop.generation, target: replacement}, time.Now())
	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.True(t, loop.runtime.LastEvent.Time.IsZero())
}

func TestInconclusiveVerificationRemainsInVerification(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.runtime.Mode = AutoSwitchVerifying
	loop.expectedID = current.StableID()
	loop.verifyDeadline = time.Now().Add(time.Minute)

	loop.handleProbeResult(autoSwitchProbeEvent{
		generation: loop.generation,
		kind:       probeVerify,
		result: exitPathProbeResult{
			Inconclusive: true,
			Reason:       "LocalAPI unavailable",
		},
	}, time.Now())
	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.Contains(t, loop.runtime.Message, "inconclusive")
}

func TestRestoredBackoffSurvivesFirstStatus(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	loop := newTestAutoSwitchLoop(status)
	loop.currentID = ""
	loop.runtime.Mode = AutoSwitchWaiting
	loop.backoffUntil = time.Now().Add(time.Minute)

	loop.reconcileStatus(time.Now())
	require.Equal(t, AutoSwitchBackoff, loop.runtime.Mode)
	require.Equal(t, current.StableID(), loop.currentID)
}

func TestManualInvalidationPreventsPendingAutomaticWrite(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-301", "DE", "FRA", true)
	status := testAutoSwitchStatus(current, replacement)
	enteredPrefs := make(chan struct{})
	releasePrefs := make(chan struct{})
	var prefsCalls atomic.Int32
	manager := newAutoSwitchManager(&fakeAutoSwitchOps{
		underlay: func(context.Context) underlayProbeResult {
			return underlayProbeResult{State: underlayProbeHealthy}
		},
		prefs: func(context.Context) (*ipn.Prefs, error) {
			if prefsCalls.Add(1) == 1 {
				close(enteredPrefs)
				<-releasePrefs
			}
			return &ipn.Prefs{ExitNodeID: current.StableID()}, nil
		},
		setExit: func(_ context.Context, _, _ tailcfg.StableNodeID, valid func() bool) error {
			if !valid() {
				return context.Canceled
			}
			return errors.New("automatic write unexpectedly remained valid")
		},
	})
	loop := newTestAutoSwitchLoop(status)
	loop.manager = manager

	loop.startApply(context.Background(), replacement)
	<-enteredPrefs
	manager.Invalidate()
	close(releasePrefs)
	result := <-loop.applyResults
	require.ErrorIs(t, result.err, context.Canceled)
}

func TestCandidateFallbackPrefersSameCity(t *testing.T) {
	now := time.Now()
	current := testMullvadNode("current", 1, "de-fra-wg-403", "DE", "FRA", true)
	sameCity := testMullvadNode("same-city", 2, "de-fra-wg-301", "DE", "FRA", true)
	sameCountry := testMullvadNode("same-country", 3, "de-ber-wg-001", "DE", "BER", true)
	foreign := testMullvadNode("foreign", 4, "al-tia-wg-001", "AL", "TIA", true)
	status := testAutoSwitchStatus(current, foreign, sameCountry, sameCity)
	ops := &fakeAutoSwitchOps{
		suggest: func(context.Context) (apitype.ExitNodeSuggestionResponse, error) {
			return apitype.ExitNodeSuggestionResponse{}, errors.New("no suggestion")
		},
	}

	peer, err := selectAutoSwitchCandidate(context.Background(), ops, status, nil, now)
	require.NoError(t, err)
	require.Equal(t, sameCity.StableID(), peer.StableID())

	peer, err = selectAutoSwitchCandidate(context.Background(), ops, status, map[tailcfg.StableNodeID]time.Time{
		sameCity.StableID(): now.Add(time.Hour),
	}, now)
	require.NoError(t, err)
	require.Equal(t, sameCountry.StableID(), peer.StableID())
}

func TestInitialMullvadCandidateRejectsNonMullvadSuggestion(t *testing.T) {
	mullvad := testMullvadNode("mullvad", 1, "de-fra-wg-301", "DE", "FRA", true)
	nonMullvad := (&tailcfg.Node{ID: 2, StableID: "homebox", Name: "homebox", Online: new(bool)}).View()
	status := testAutoSwitchStatus(nonMullvad, mullvad)
	ops := &fakeAutoSwitchOps{
		suggest: func(context.Context) (apitype.ExitNodeSuggestionResponse, error) {
			return apitype.ExitNodeSuggestionResponse{ID: nonMullvad.StableID()}, nil
		},
	}

	peer, err := selectInitialMullvadCandidate(context.Background(), ops, status, time.Now())
	require.NoError(t, err)
	require.Equal(t, mullvad.StableID(), peer.StableID())
}

func TestFailedReplacementsReturnToOriginalExitNode(t *testing.T) {
	original := testMullvadNode("original", 1, "de-fra-wg-001", "DE", "FRA", true)
	failed := testMullvadNode("failed", 2, "de-fra-wg-002", "DE", "FRA", true)
	status := testAutoSwitchStatus(failed, original)
	var applied atomic.Value
	loop := newTestAutoSwitchLoop(status)
	loop.manager.ops = &fakeAutoSwitchOps{
		prefs: func(context.Context) (*ipn.Prefs, error) {
			return &ipn.Prefs{ExitNodeID: failed.StableID()}, nil
		},
		setExit: func(_ context.Context, id, expected tailcfg.StableNodeID, valid func() bool) error {
			require.Equal(t, failed.StableID(), expected)
			require.True(t, valid())
			applied.Store(id)
			return nil
		},
	}
	loop.runtime.Mode = AutoSwitchVerifying
	loop.incidentSourceID = original.StableID()
	loop.incidentFrom = peerLabel(original)
	loop.incidentReason = "egress probes failed"
	loop.incidentEpoch = loop.manager.epoch.Load()
	loop.expectedID = failed.StableID()
	loop.expectedPeer = failed
	loop.attempts = autoSwitchMaxCandidates - 1

	now := time.Now()
	loop.failVerification(context.Background(), now, "replacement egress failed")
	require.Equal(t, AutoSwitchRollingBack, loop.runtime.Mode)
	require.Eventually(t, func() bool { return applied.Load() != nil }, time.Second, time.Millisecond)
	require.Equal(t, original.StableID(), applied.Load())
	result := <-loop.applyResults
	loop.handleApplyResult(result, now.Add(time.Second))
	require.Equal(t, AutoSwitchRollingBack, loop.runtime.Mode)

	status.Prefs = (&ipn.Prefs{ExitNodeID: original.StableID(), CorpDNS: true}).View()
	loop.handleStatus(status, now.Add(2*time.Second))
	require.Equal(t, AutoSwitchBackoff, loop.runtime.Mode)
	require.Equal(t, "rolled-back", loop.runtime.LastEvent.Outcome)
	require.Equal(t, original.Hostinfo().Hostname(), loop.runtime.LastEvent.To)
}

func TestAutoSwitchStateRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	now := time.Now().Round(time.Second)
	want := persistedAutoSwitchState{
		Version: autoSwitchStateVersion,
		Owner:   "self",
		LastEvent: AutoSwitchEvent{
			Time:    now,
			From:    "old",
			To:      "new",
			Reason:  "probe failure",
			Outcome: "verified",
		},
		Quarantine:   map[string]time.Time{"bad": now.Add(time.Hour)},
		BackoffUntil: now.Add(time.Minute),
		Pending: &persistedAutoSwitchIncident{
			SourceID:     "old",
			SourceLabel:  "old-label",
			TargetID:     "new",
			TargetLabel:  "new-label",
			CurrentID:    "new",
			CurrentLabel: "new-label",
			Reason:       "probe failure",
			Phase:        AutoSwitchVerifying,
			Attempts:     1,
		},
	}

	require.NoError(t, saveAutoSwitchState(want))
	got, err := loadAutoSwitchState()
	require.NoError(t, err)
	require.Equal(t, want, got)

	path, err := autoSwitchStatePath()
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestAutoSwitchStateV1Migration(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	path, err := autoSwitchStatePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"managedID":"old","lastEvent":{"outcome":"verified"},"quarantine":{"bad":"2099-01-01T00:00:00Z"},"backoffUntil":"2099-01-01T00:00:00Z","pending":{"sourceID":"old","phase":"verifying"}}`), 0o600))

	state, err := loadAutoSwitchState()
	require.NoError(t, err)
	require.Equal(t, autoSwitchStateVersion, state.Version)
	require.Equal(t, "verified", state.LastEvent.Outcome)
	require.Empty(t, state.ManagedID)
	require.Empty(t, state.Quarantine)
	require.True(t, state.BackoffUntil.IsZero())
	require.Nil(t, state.Pending)
}

func TestRestoredVerificationResumesForSameProfile(t *testing.T) {
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-002", "DE", "FRA", true)
	status := testAutoSwitchStatus(replacement)
	status.self = (&tailcfg.Node{ID: 10, StableID: "self"}).View()
	loop := newTestAutoSwitchLoop(status)
	loop.stateReconciled = false
	loop.stateOwner = "self"
	loop.restoredIncident = &persistedAutoSwitchIncident{
		SourceID:     "original",
		SourceLabel:  "de-fra-wg-001",
		TargetID:     string(replacement.StableID()),
		TargetLabel:  peerLabel(replacement),
		CurrentID:    string(replacement.StableID()),
		CurrentLabel: peerLabel(replacement),
		Reason:       "egress probes failed",
		Phase:        AutoSwitchVerifying,
	}

	loop.reconcileStatus(time.Now())
	require.True(t, loop.stateReconciled)
	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.Equal(t, replacement.StableID(), loop.expectedID)
}

func TestRestoredSwitchingResumesVerificationAfterAppliedWrite(t *testing.T) {
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-002", "DE", "FRA", true)
	status := testAutoSwitchStatus(replacement)
	status.self = (&tailcfg.Node{ID: 10, StableID: "self"}).View()
	loop := newTestAutoSwitchLoop(status)
	loop.stateReconciled = false
	loop.stateOwner = "self"
	loop.restoredIncident = &persistedAutoSwitchIncident{
		SourceID:     "original",
		SourceLabel:  "de-fra-wg-001",
		TargetID:     string(replacement.StableID()),
		TargetLabel:  peerLabel(replacement),
		CurrentID:    string(replacement.StableID()),
		CurrentLabel: peerLabel(replacement),
		Reason:       "egress probes failed",
		Phase:        AutoSwitchSwitching,
	}

	loop.reconcileStatus(time.Now())
	require.Equal(t, AutoSwitchVerifying, loop.runtime.Mode)
	require.Equal(t, replacement.StableID(), loop.expectedID)
}

func TestManagedExitNodeChangeWhileStoppedDisablesHealthChecks(t *testing.T) {
	current := testMullvadNode("current", 2, "de-fra-wg-002", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	status.self = (&tailcfg.Node{ID: 10, StableID: "self"}).View()
	loop := newTestAutoSwitchLoop(status)
	loop.stateReconciled = false
	loop.stateOwner = "self"
	loop.managedID = "previous"
	loop.config.Enabled = true
	loop.runtime.Enabled = true

	loop.reconcileStatus(time.Now())
	require.False(t, loop.runtime.Enabled)
	require.Equal(t, AutoSwitchDisabled, loop.runtime.Mode)
	select {
	case <-loop.manager.Overrides():
	default:
		t.Fatal("expected external exit-node change to report an override")
	}
}

func TestProfileChangeClearsAndDisablesHealthChecks(t *testing.T) {
	current := testMullvadNode("current", 2, "de-fra-wg-002", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	loop := newTestAutoSwitchLoop(status)
	loop.stateOwner = "self"
	loop.managedID = current.StableID()
	loop.quarantine["bad"] = time.Now().Add(time.Hour)
	loop.backoffUntil = time.Now().Add(time.Hour)
	loop.runtime.Enabled = true

	status.self = (&tailcfg.Node{ID: 101, StableID: "other-self", User: 2}).View()
	loop.handleStatus(status, time.Now())

	require.False(t, loop.runtime.Enabled)
	require.Equal(t, AutoSwitchDisabled, loop.runtime.Mode)
	require.Equal(t, tailcfg.StableNodeID("other-self"), loop.stateOwner)
	require.Empty(t, loop.managedID)
	require.Empty(t, loop.quarantine)
	require.True(t, loop.backoffUntil.IsZero())
	select {
	case <-loop.manager.Overrides():
	default:
		t.Fatal("expected profile change to report an override")
	}
}

func TestTerminalBackoffClearsPersistedIncident(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.incidentSourceID = current.StableID()
	loop.incidentFrom = peerLabel(current)
	loop.incidentReason = "egress probes failed"
	loop.expectedID = "replacement"

	loop.enterBackoff(time.Now(), "no replacement worked")
	state, err := loadAutoSwitchState()
	require.NoError(t, err)
	require.Nil(t, state.Pending)
	require.Empty(t, loop.incidentSourceID)
	require.Zero(t, loop.incidentEpoch)
}

func TestBackoffOwnsCurrentReplacement(t *testing.T) {
	current := testMullvadNode("replacement", 2, "de-fra-wg-002", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.managedID = "original"
	loop.incidentSourceID = "original"

	loop.enterBackoff(time.Now(), "verification inconclusive")
	require.Equal(t, current.StableID(), loop.managedID)
}

func TestBackoffOwnsDelayedSuccessfulWrite(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	for _, mode := range []AutoSwitchMode{AutoSwitchVerifying, AutoSwitchRollingBack} {
		t.Run(string(mode), func(t *testing.T) {
			loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
			loop.runtime.Mode = mode
			loop.expectedID = "expected"

			loop.enterBackoff(time.Now(), "status update timed out")
			require.Equal(t, tailcfg.StableNodeID("expected"), loop.managedID)
		})
	}
}

func TestPersistedRecoveryWaitsForRunningStatus(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	status.State = ipn.Stopped
	loop := newTestAutoSwitchLoop(status)
	loop.stateReconciled = false
	loop.restoredIncident = &persistedAutoSwitchIncident{
		SourceID: string(current.StableID()),
		Phase:    AutoSwitchSwitching,
	}

	loop.reconcileStatus(time.Now())
	require.False(t, loop.stateReconciled)
	require.False(t, loop.busy)
}

func TestFreshUnderlayFailureCancelsApply(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-002", "DE", "FRA", true)
	var prefsCalls atomic.Int32
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current, replacement))
	loop.manager.ops = &fakeAutoSwitchOps{
		underlay: func(context.Context) underlayProbeResult {
			return underlayProbeResult{State: underlayProbeUnhealthy, Reason: "gateway unavailable"}
		},
		prefs: func(context.Context) (*ipn.Prefs, error) {
			prefsCalls.Add(1)
			return &ipn.Prefs{ExitNodeID: current.StableID()}, nil
		},
	}

	loop.startApply(context.Background(), replacement)
	result := <-loop.applyResults
	require.ErrorContains(t, result.err, "underlay changed")
	require.Zero(t, prefsCalls.Load())
}

func TestAmbiguousApplyErrorIsReconciledFromLivePrefs(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	replacement := testMullvadNode("replacement", 2, "de-fra-wg-002", "DE", "FRA", true)
	var prefsCalls atomic.Int32
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current, replacement))
	loop.manager.ops = &fakeAutoSwitchOps{
		underlay: func(context.Context) underlayProbeResult {
			return underlayProbeResult{State: underlayProbeHealthy}
		},
		prefs: func(context.Context) (*ipn.Prefs, error) {
			if prefsCalls.Add(1) == 1 {
				return &ipn.Prefs{ExitNodeID: current.StableID()}, nil
			}
			return &ipn.Prefs{ExitNodeID: replacement.StableID()}, nil
		},
		setExit: func(context.Context, tailcfg.StableNodeID, tailcfg.StableNodeID, func() bool) error {
			return context.DeadlineExceeded
		},
	}

	loop.startApply(context.Background(), replacement)
	result := <-loop.applyResults
	require.NoError(t, result.err)
	require.EqualValues(t, 2, prefsCalls.Load())
}

func TestPauseIsBarrierAndResumeRestartsSupervisor(t *testing.T) {
	manager := newAutoSwitchManager(&fakeAutoSwitchOps{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	manager.SetConfig(AutoSwitchConfig{Enabled: true, Threshold: 10 * time.Second, ProbeInterval: time.Minute})
	require.Eventually(t, func() bool { return manager.Runtime().Enabled }, time.Second, time.Millisecond)

	pauseCtx, pauseCancel := context.WithTimeout(context.Background(), time.Second)
	defer pauseCancel()
	require.NoError(t, manager.Pause(pauseCtx))
	require.False(t, manager.Runtime().Enabled)
	require.Equal(t, AutoSwitchDisabled, manager.Runtime().Mode)

	require.NoError(t, manager.Resume(pauseCtx))
	require.Eventually(t, func() bool { return manager.Runtime().Enabled }, time.Second, time.Millisecond)
}

func TestPausedConfigDoesNotRestartRecovery(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	loop := newTestAutoSwitchLoop(testAutoSwitchStatus(current))
	loop.paused = true
	loop.stateReconciled = false
	loop.restoredIncident = &persistedAutoSwitchIncident{
		SourceID: string(current.StableID()),
		Phase:    AutoSwitchSwitching,
	}

	loop.handleConfig(AutoSwitchConfig{Enabled: true}, time.Now())
	require.False(t, loop.busy)
	require.False(t, loop.runtime.Enabled)
	require.Equal(t, AutoSwitchDisabled, loop.runtime.Mode)
}

func TestResumeStatusRequiresRequestedSpecificNode(t *testing.T) {
	current := testMullvadNode("current", 1, "de-fra-wg-001", "DE", "FRA", true)
	status := testAutoSwitchStatus(current)
	ready, err := resumeStatusReady(status, current.StableID(), "self")
	require.NoError(t, err)
	require.True(t, ready)
	ready, err = resumeStatusReady(status, "other", "self")
	require.NoError(t, err)
	require.False(t, ready)

	prefs := status.Prefs.AsStruct()
	prefs.AutoExitNode = ipn.AnyExitNode
	status.Prefs = prefs.View()
	ready, err = resumeStatusReady(status, current.StableID(), "self")
	require.NoError(t, err)
	require.False(t, ready)

	status.self = (&tailcfg.Node{ID: 101, StableID: "other-self", User: 2}).View()
	_, err = resumeStatusReady(status, current.StableID(), "self")
	require.Error(t, err)
}

func newTestAutoSwitchLoop(status *IPNStatus) *autoSwitchLoop {
	manager := newAutoSwitchManager(&fakeAutoSwitchOps{})
	return &autoSwitchLoop{
		manager:          manager,
		ctx:              context.Background(),
		config:           AutoSwitchConfig{Enabled: true, Threshold: 10 * time.Second, ProbeInterval: time.Minute},
		configSet:        true,
		status:           status,
		runtime:          AutoSwitchRuntime{Mode: AutoSwitchMonitoring},
		currentID:        status.Prefs.ExitNodeID(),
		currentLabel:     peerLabel(status.ExitNode()),
		stateReconciled:  true,
		quarantine:       make(map[tailcfg.StableNodeID]time.Time),
		probeResults:     make(chan autoSwitchProbeEvent, 1),
		candidateResults: make(chan autoSwitchCandidateEvent, 1),
		applyResults:     make(chan autoSwitchApplyEvent, 1),
	}
}
