package tsutil

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tailcfg"
)

const autoSwitchStateVersion = 2

type persistedAutoSwitchIncident struct {
	SourceID     string         `json:"sourceID"`
	SourceLabel  string         `json:"sourceLabel"`
	TargetID     string         `json:"targetID,omitempty"`
	TargetLabel  string         `json:"targetLabel,omitempty"`
	CurrentID    string         `json:"currentID,omitempty"`
	CurrentLabel string         `json:"currentLabel,omitempty"`
	Reason       string         `json:"reason"`
	Phase        AutoSwitchMode `json:"phase"`
	Attempts     int            `json:"attempts,omitempty"`
}

type persistedAutoSwitchState struct {
	Version      int                          `json:"version"`
	Owner        string                       `json:"owner,omitempty"`
	ManagedID    string                       `json:"managedID,omitempty"`
	LastEvent    AutoSwitchEvent              `json:"lastEvent"`
	Quarantine   map[string]time.Time         `json:"quarantine,omitempty"`
	BackoffUntil time.Time                    `json:"backoffUntil,omitempty"`
	Pending      *persistedAutoSwitchIncident `json:"pending,omitempty"`
}

func autoSwitchStatePath() (string, error) {
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateHome, "trayscale", "autoswitch.json"), nil
}

func loadAutoSwitchState() (persistedAutoSwitchState, error) {
	path, err := autoSwitchStatePath()
	if err != nil {
		return persistedAutoSwitchState{}, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedAutoSwitchState{Version: autoSwitchStateVersion}, nil
	}
	if err != nil {
		return persistedAutoSwitchState{}, err
	}
	defer func() { _ = file.Close() }()

	var state persistedAutoSwitchState
	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return persistedAutoSwitchState{}, err
	}
	if state.Version != 1 && state.Version != autoSwitchStateVersion {
		return persistedAutoSwitchState{}, errors.New("unsupported auto-switch state version")
	}
	if state.Version == 1 {
		// V1 had no profile owner, so its recovery state cannot be adopted safely.
		state.ManagedID = ""
		state.Quarantine = nil
		state.BackoffUntil = time.Time{}
		state.Pending = nil
	}
	state.Version = autoSwitchStateVersion
	return state, nil
}

func saveAutoSwitchState(state persistedAutoSwitchState) error {
	path, err := autoSwitchStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".autoswitch-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(state); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func (l *autoSwitchLoop) loadState() {
	state, err := loadAutoSwitchState()
	if err != nil {
		slog.Warn("load auto-switch state", "err", err)
		return
	}
	l.runtime.LastEvent = state.LastEvent
	l.backoffUntil = state.BackoffUntil
	l.stateOwner = tailcfg.StableNodeID(state.Owner)
	l.managedID = tailcfg.StableNodeID(state.ManagedID)
	l.restoredIncident = state.Pending
	now := time.Now()
	for rawID, until := range state.Quarantine {
		if until.After(now) {
			l.quarantine[tailcfg.StableNodeID(rawID)] = until
		}
	}
}

func (l *autoSwitchLoop) saveState() {
	quarantine := make(map[string]time.Time)
	now := time.Now()
	for id, until := range l.quarantine {
		if until.After(now) {
			quarantine[string(id)] = until
		}
	}
	state := persistedAutoSwitchState{
		Version:      autoSwitchStateVersion,
		Owner:        string(l.currentStateOwner()),
		ManagedID:    string(l.managedID),
		LastEvent:    l.runtime.LastEvent,
		Quarantine:   quarantine,
		BackoffUntil: l.backoffUntil,
	}
	if l.incidentSourceID != "" {
		state.Pending = &persistedAutoSwitchIncident{
			SourceID:     string(l.incidentSourceID),
			SourceLabel:  l.incidentFrom,
			TargetID:     string(l.expectedID),
			TargetLabel:  peerLabel(l.expectedPeer),
			CurrentID:    string(l.currentID),
			CurrentLabel: l.currentLabel,
			Reason:       l.incidentReason,
			Phase:        l.runtime.Mode,
			Attempts:     l.attempts,
		}
	}
	if err := saveAutoSwitchState(state); err != nil {
		slog.Error("save auto-switch state", "err", err)
	}
}

func (l *autoSwitchLoop) currentStateOwner() tailcfg.StableNodeID {
	if owner, ok := autoSwitchStatusOwner(l.status); ok {
		return owner
	}
	return l.stateOwner
}
