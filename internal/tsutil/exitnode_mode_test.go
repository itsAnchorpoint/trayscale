package tsutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func TestExitNodeMode(t *testing.T) {
	tests := []struct {
		name   string
		prefs  ipn.Prefs
		health bool
		want   ExitNodeMode
	}{
		{name: "off", want: ExitNodeModeOff},
		{name: "specific", prefs: ipn.Prefs{ExitNodeID: "node"}, want: ExitNodeModeSpecific},
		{name: "health checked", prefs: ipn.Prefs{ExitNodeID: "node"}, health: true, want: ExitNodeModeHealthChecked},
		{name: "automatic takes precedence", prefs: ipn.Prefs{AutoExitNode: ipn.AnyExitNode, ExitNodeID: "node"}, health: true, want: ExitNodeModeAutomatic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &IPNStatus{
				Prefs:      tt.prefs.View(),
				AutoSwitch: AutoSwitchRuntime{Enabled: tt.health},
			}
			require.Equal(t, tt.want, status.ExitNodeMode())
		})
	}
}

func TestAutomaticExitNodeMaskedPrefs(t *testing.T) {
	prefs := automaticExitNodeMaskedPrefs()
	require.Equal(t, ipn.AnyExitNode, prefs.AutoExitNode)
	require.Empty(t, prefs.ExitNodeID)
	require.False(t, prefs.ExitNodeIP.IsValid())
	require.True(t, prefs.AutoExitNodeSet)
	require.False(t, prefs.ExitNodeIDSet)
	require.False(t, prefs.ExitNodeIPSet)
}

func TestSpecificExitNodeMaskedPrefs(t *testing.T) {
	prefs := specificExitNodeMaskedPrefs(tailcfg.StableNodeID("node"))
	require.Equal(t, tailcfg.StableNodeID("node"), prefs.ExitNodeID)
	require.False(t, prefs.ExitNodeIP.IsValid())
	require.Empty(t, prefs.AutoExitNode)
	require.True(t, prefs.AutoExitNodeSet)
	require.True(t, prefs.ExitNodeIDSet)
	require.True(t, prefs.ExitNodeIPSet)
}

func TestDisableAutomaticExitNodeMaskedPrefsPreservesConcreteSelection(t *testing.T) {
	prefs := disableAutomaticExitNodeMaskedPrefs()
	require.Empty(t, prefs.AutoExitNode)
	require.True(t, prefs.AutoExitNodeSet)
	require.False(t, prefs.ExitNodeIDSet)
	require.False(t, prefs.ExitNodeIPSet)
}
