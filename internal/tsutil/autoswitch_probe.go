package tsutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

var autoSwitchProbeTargets = [...]string{"1.1.1.1", "9.9.9.9"}

var errAutoSwitchDirectDial = errors.New("tailscaled would dial the probe outside Tailscale")

type autoSwitchOps interface {
	DialTCP(context.Context, string, uint16) (net.Conn, error)
	QueryDNS(context.Context, string, string) ([]byte, error)
	ProbeUnderlay(context.Context) underlayProbeResult
	SuggestExitNode(context.Context) (apitype.ExitNodeSuggestionResponse, error)
	Prefs(context.Context) (*ipn.Prefs, error)
	SetExitNode(context.Context, tailcfg.StableNodeID, tailcfg.StableNodeID, func() bool) error
}

type localAutoSwitchOps struct{}

func (localAutoSwitchOps) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return dialTCPViaTailscale(ctx, &localClient, host, port)
}

func dialTCPViaTailscale(ctx context.Context, client *local.Client, host string, port uint16) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { connCh <- info.Conn },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+apitype.LocalAPIHost+"/localapi/v0/dial", nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"Upgrade":      {"ts-dial"},
		"Connection":   {"upgrade"},
		"Dial-Host":    {host},
		"Dial-Port":    {fmt.Sprint(port)},
		"Dial-Network": {"tcp"},
	}
	res, err := client.DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK && res.Header.Get("Dial-Self") == "true" {
			return nil, errAutoSwitchDirectDial
		}
		return nil, fmt.Errorf("unexpected LocalAPI dial response: %s, %s", res.Status, body)
	}

	var conn net.Conn
	select {
	case conn = <-connCh:
	default:
	}
	if conn == nil {
		_ = res.Body.Close()
		return nil, errors.New("LocalAPI dial did not provide a connection")
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		_ = res.Body.Close()
		return nil, errors.New("LocalAPI dial response is not writable")
	}
	return netutil.NewAltReadWriteCloserConn(rwc, conn), nil
}

func (localAutoSwitchOps) QueryDNS(ctx context.Context, name, queryType string) ([]byte, error) {
	response, _, err := localClient.QueryDNS(ctx, name, queryType)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (localAutoSwitchOps) ProbeUnderlay(ctx context.Context) underlayProbeResult {
	start := time.Now()
	if monitor == nil {
		return underlayProbeResult{
			State:  underlayProbeInconclusive,
			Reason: "network monitor is unavailable",
		}
	}
	dm, err := localClient.CurrentDERPMap(ctx)
	if err != nil {
		return underlayProbeResult{
			State:   underlayProbeInconclusive,
			Reason:  fmt.Sprintf("get DERP map: %v", err),
			Latency: time.Since(start),
		}
	}
	if dm == nil || len(dm.Regions) == 0 {
		return underlayProbeResult{
			State:   underlayProbeInconclusive,
			Reason:  "DERP map is empty",
			Latency: time.Since(start),
		}
	}
	client := netcheck.Client{NetMon: monitor, Logf: logger.Discard}
	report, err := client.GetReport(ctx, dm, &netcheck.GetReportOpts{OnlyTCP443: true})
	result := classifyUnderlayProbe(report, err)
	result.Latency = time.Since(start)
	return result
}

func (localAutoSwitchOps) SuggestExitNode(ctx context.Context) (apitype.ExitNodeSuggestionResponse, error) {
	return localClient.SuggestExitNode(ctx)
}

func (localAutoSwitchOps) Prefs(ctx context.Context) (*ipn.Prefs, error) {
	return localClient.GetPrefs(ctx)
}

func (localAutoSwitchOps) SetExitNode(ctx context.Context, id, expected tailcfg.StableNodeID, valid func() bool) error {
	return setExitNodeAutomatic(ctx, id, expected, valid)
}

type exitPathProbeResult struct {
	EgressOK     bool
	DNSOK        bool
	Reason       string
	Latency      time.Duration
	Inconclusive bool
	Underlay     underlayProbeResult
}

func (r exitPathProbeResult) Healthy() bool {
	return r.EgressOK && r.DNSOK
}

type underlayProbeState uint8

const (
	underlayProbeNotRun underlayProbeState = iota
	underlayProbeHealthy
	underlayProbeUnhealthy
	underlayProbeInconclusive
)

type underlayProbeResult struct {
	State   underlayProbeState
	Reason  string
	Latency time.Duration
}

func (r underlayProbeResult) Healthy() bool {
	return r.State == underlayProbeHealthy
}

func classifyUnderlayProbe(report *netcheck.Report, err error) underlayProbeResult {
	if err != nil {
		return underlayProbeResult{
			State:  underlayProbeInconclusive,
			Reason: fmt.Sprintf("TCP/443 netcheck failed: %v", err),
		}
	}
	if report == nil {
		return underlayProbeResult{
			State:  underlayProbeInconclusive,
			Reason: "TCP/443 netcheck returned no report",
		}
	}
	if len(report.RegionLatency) > 0 {
		return underlayProbeResult{State: underlayProbeHealthy}
	}
	return underlayProbeResult{
		State:  underlayProbeUnhealthy,
		Reason: "TCP/443 netcheck could not reach any DERP region",
	}
}

func probeExitPath(ctx context.Context, ops autoSwitchOps, firstTarget int, checkDNS bool) exitPathProbeResult {
	start := time.Now()
	result := exitPathProbeResult{DNSOK: !checkDNS}

	dnsResult := make(chan error, 1)
	if checkDNS {
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			response, err := ops.QueryDNS(probeCtx, "example.com.", "A")
			if err == nil {
				err = validateDNSResponse(response)
			}
			dnsResult <- err
		}()
	}

	var dialErrors []error
	for i := range autoSwitchProbeTargets {
		target := autoSwitchProbeTargets[(firstTarget+i)%len(autoSwitchProbeTargets)]
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		conn, err := ops.DialTCP(probeCtx, target, 443)
		cancel()
		if err == nil {
			_ = conn.Close()
			result.EgressOK = true
			break
		}
		dialErrors = append(dialErrors, fmt.Errorf("%s: %w", target, err))
	}

	if checkDNS {
		select {
		case err := <-dnsResult:
			result.DNSOK = err == nil
			if err != nil {
				result.Reason = fmt.Sprintf("DNS probe failed: %v", err)
			}
		case <-ctx.Done():
			result.Reason = fmt.Sprintf("DNS probe failed: %v", ctx.Err())
		}
	}

	if !result.EgressOK {
		for _, err := range dialErrors {
			if isProbeInfrastructureError(err) {
				result.Inconclusive = true
			}
		}
		result.Reason = fmt.Sprintf("egress probes failed: %v", errors.Join(dialErrors...))
	} else if !result.DNSOK && result.Reason == "" {
		result.Reason = "DNS probe failed"
	}
	if !result.EgressOK && !result.Inconclusive {
		result.Underlay = ops.ProbeUnderlay(ctx)
	}
	result.Latency = time.Since(start)
	return result
}

func validateDNSResponse(response []byte) error {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return fmt.Errorf("parse DNS response: %w", err)
	}
	if !message.Response {
		return errors.New("DNS packet is not a response")
	}
	if message.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("DNS response code is %v", message.RCode)
	}
	for _, answer := range message.Answers {
		if answer.Header.Type == dnsmessage.TypeA {
			return nil
		}
	}
	return errors.New("DNS response has no A answer")
}

func isProbeInfrastructureError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, errAutoSwitchDirectDial) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		"permission denied",
		"access denied",
		"tailscaled.service not running",
		"no such file or directory",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
