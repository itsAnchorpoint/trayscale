package tsutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/tailscale/cli"
	"tailscale.com/ipn"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

var (
	localClient    local.Client
	bus            = eventbus.New()
	monitor        = initMonitor()
	netcheckClient = netcheck.Client{
		NetMon: monitor,
		Logf:   logger.Discard,
	}
	exitNodeMu sync.Mutex
)

func initMonitor() *netmon.Monitor {
	monitor, err := netmon.New(bus, logger.Discard)
	if err != nil {
		slog.Error("init netmon monitor", "err", err)
	}
	return monitor
}

// Prefs returns the options of the local node.
func Prefs(ctx context.Context) (*ipn.Prefs, error) {
	return localClient.GetPrefs(ctx)
}

// Start connects the local peer to the Tailscale network.
func Start(ctx context.Context) error {
	return cli.RunWithContext(ctx, []string{"up"})
}

// Stop disconnects the local peer from the Tailscale network.
func Stop(ctx context.Context) error {
	return cli.RunWithContext(ctx, []string{"down"})
}

// ExitNode uses the specified peer as an exit node, or unsets
// an existing exit node if peer is an empty string.
func ExitNode(ctx context.Context, peer tailcfg.StableNodeID) error {
	exitNodeMu.Lock()
	defer exitNodeMu.Unlock()
	return editExitNode(ctx, peer)
}

func editExitNode(ctx context.Context, peer tailcfg.StableNodeID) error {
	prefs, err := localClient.EditPrefs(ctx, specificExitNodeMaskedPrefs(peer))
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}
	if prefs == nil {
		return errors.New("tailscaled returned no preferences")
	}
	if prefs.AutoExitNode.IsSet() || prefs.ExitNodeID != peer || prefs.ExitNodeIP.IsValid() {
		return errors.New("tailscaled did not apply the requested specific exit node")
	}

	return nil
}

// SetAutomaticExitNode lets tailscaled persistently select any exit node
// permitted by the current tailnet policy.
func SetAutomaticExitNode(ctx context.Context) error {
	exitNodeMu.Lock()
	defer exitNodeMu.Unlock()

	prefs, err := localClient.EditPrefs(ctx, automaticExitNodeMaskedPrefs())
	if err != nil {
		return fmt.Errorf("enable automatic exit node: %w", err)
	}
	if prefs == nil {
		return errors.New("tailscaled returned no preferences")
	}
	if prefs.AutoExitNode != ipn.AnyExitNode {
		return errors.New("tailscaled did not enable automatic exit-node selection")
	}
	return nil
}

func disableAutomaticExitNode(ctx context.Context, expected tailcfg.StableNodeID) error {
	exitNodeMu.Lock()
	defer exitNodeMu.Unlock()

	current, err := localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}
	if current == nil {
		return errors.New("tailscaled returned no preferences")
	}
	if expected != "" && current.ExitNodeID != expected {
		return errors.New("exit node changed before automatic mode could be disabled")
	}
	if !current.AutoExitNode.IsSet() {
		return nil
	}

	prefs, err := localClient.EditPrefs(ctx, disableAutomaticExitNodeMaskedPrefs())
	if err != nil {
		return fmt.Errorf("disable automatic exit node: %w", err)
	}
	if prefs == nil {
		return errors.New("tailscaled returned no preferences")
	}
	if prefs.AutoExitNode.IsSet() || prefs.ExitNodeID != current.ExitNodeID || prefs.ExitNodeIP != current.ExitNodeIP {
		return errors.New("tailscaled did not preserve the selected exit node")
	}
	return nil
}

func setExitNodeAutomatic(ctx context.Context, peer, expected tailcfg.StableNodeID, valid func() bool) error {
	exitNodeMu.Lock()
	defer exitNodeMu.Unlock()
	if !valid() {
		return context.Canceled
	}
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs before automatic exit-node update: %w", err)
	}
	if prefs == nil {
		return errors.New("tailscaled returned no preferences")
	}
	if prefs.AutoExitNode.IsSet() || prefs.ExitNodeIP.IsValid() || prefs.ExitNodeID != expected {
		return errors.New("exit-node mode changed before automatic update")
	}
	if !valid() {
		return context.Canceled
	}
	return editExitNode(ctx, peer)
}

func SetUseExitNode(ctx context.Context, use bool) error {
	exitNodeMu.Lock()
	defer exitNodeMu.Unlock()
	useErr := localClient.SetUseExitNode(ctx, use)
	if useErr == nil {
		return nil
	}
	if !use {
		return useErr
	}

	suggested, suggestErr := localClient.SuggestExitNode(ctx)
	if suggestErr == nil {
		if suggested.ID == "" {
			suggestErr = errors.New("tailscaled did not suggest an exit node")
		} else {
			slog.Info("got suggested exit node", "id", suggested.ID, "name", suggested.Name, "location", suggested.Location)
			suggestErr = editExitNode(ctx, suggested.ID)
			if suggestErr == nil {
				return nil
			}
		}
	}

	return errors.Join(useErr, suggestErr)
}

// AdvertiseExitNode enables and disables exit node advertisement for
// the current node.
func AdvertiseExitNode(ctx context.Context, enable bool) error {
	var prefs ipn.Prefs
	prefs.SetAdvertiseExitNode(enable)

	_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              prefs,
		AdvertiseRoutesSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}

	return nil
}

func AdvertiseRoutes(ctx context.Context, routes []netip.Prefix) error {
	prefs, err := Prefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}
	exit := prefs.AdvertisesExitNode()
	prefs.AdvertiseRoutes = routes
	prefs.SetAdvertiseExitNode(exit)

	_, err = localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              *prefs,
		AdvertiseRoutesSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}

	return nil
}

// AllowLANAccess enables and disables the ability for the current
// node to get access to the regular LAN that it is connected to while
// an exit node is in use.
func AllowLANAccess(ctx context.Context, allow bool) error {
	prefs := ipn.Prefs{
		ExitNodeAllowLANAccess: allow,
	}

	_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:                     prefs,
		ExitNodeAllowLANAccessSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}

	return nil
}

// AcceptRoutes sets whether or not all shared subnet routes from
// other nodes should be used by the local node.
func AcceptRoutes(ctx context.Context, accept bool) error {
	prefs := ipn.Prefs{
		RouteAll: accept,
	}

	_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       prefs,
		RouteAllSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}

	return nil
}

// AcceptDNS sets whether or not the Tailscale DNS config should be
// used.
func AcceptDNS(ctx context.Context, accept bool) error {
	prefs := ipn.Prefs{
		CorpDNS: accept,
	}

	_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:      prefs,
		CorpDNSSet: true,
	})
	if err != nil {
		return fmt.Errorf("edit prefs: %w", err)
	}

	return nil
}

// SetControlURL changes the URL of the control plane server used by
// the daemon. If controlURL is empty, the default Tailscale server is
// used.
func SetControlURL(ctx context.Context, controlURL string) error {
	prefs, err := Prefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}
	prefs.ControlURL = controlURL

	err = localClient.Start(ctx, ipn.Options{
		UpdatePrefs: prefs,
	})
	if err != nil {
		return fmt.Errorf("start local client: %w", err)
	}

	return nil
}

func NetCheck(ctx context.Context, full bool) (*netcheck.Report, *tailcfg.DERPMap, error) {
	err := netcheckClient.Standalone(ctx, "")
	if err != nil {
		return nil, nil, fmt.Errorf("standalone: %w", err)
	}

	dm, err := localClient.CurrentDERPMap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("current DERP map: %w", err)
	}

	if full {
		netcheckClient.MakeNextReportFull()
	}
	r, err := netcheckClient.GetReport(ctx, dm, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("get netcheck report: %w", err)
	}

	return r, dm, nil
}

func PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error {
	return localClient.PushFile(ctx, target, size, name, r)
}

func GetWaitingFile(ctx context.Context, name string) (io.ReadCloser, int64, error) {
	return localClient.GetWaitingFile(ctx, name)
}

func DeleteWaitingFile(ctx context.Context, name string) error {
	return localClient.DeleteWaitingFile(ctx, name)
}

// WaitingFiles polls for any pending incoming files. It returns
// quickly if there are no files currently pending.
func WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	return localClient.AwaitWaitingFiles(ctx, 0)
}

func FileTargets(ctx context.Context) ([]apitype.FileTarget, error) {
	return localClient.FileTargets(ctx)
}

func GetProfileStatus(ctx context.Context) (ipn.LoginProfile, []ipn.LoginProfile, error) {
	return localClient.ProfileStatus(ctx)
}

func SwitchProfile(ctx context.Context, id ipn.ProfileID) error {
	return localClient.SwitchProfile(ctx, id)
}

func StartLogin(ctx context.Context) error {
	return localClient.StartLoginInteractive(ctx)
}
