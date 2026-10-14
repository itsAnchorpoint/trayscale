package tsutil

import (
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

type ExitNodeMode string

const (
	ExitNodeModeOff           ExitNodeMode = "off"
	ExitNodeModeSpecific      ExitNodeMode = "specific"
	ExitNodeModeAutomatic     ExitNodeMode = "automatic"
	ExitNodeModeHealthChecked ExitNodeMode = "health-checked"
)

func (s *IPNStatus) ExitNodeMode() ExitNodeMode {
	if s == nil || !s.Prefs.Valid() {
		return ExitNodeModeOff
	}
	if s.Prefs.AutoExitNode().IsSet() {
		return ExitNodeModeAutomatic
	}
	if s.AutoSwitch.Enabled {
		return ExitNodeModeHealthChecked
	}
	if s.ExitNodeActive() {
		return ExitNodeModeSpecific
	}
	return ExitNodeModeOff
}

func automaticExitNodeMaskedPrefs() *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		AutoExitNode:    ipn.AnyExitNode,
		AutoExitNodeSet: true,
	}
}

func specificExitNodeMaskedPrefs(peer tailcfg.StableNodeID) *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		ExitNodeID:      peer,
		ExitNodeIP:      netip.Addr{},
		ExitNodeIDSet:   true,
		ExitNodeIPSet:   true,
		AutoExitNodeSet: true,
	}
}

func disableAutomaticExitNodeMaskedPrefs() *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{AutoExitNodeSet: true}
}
