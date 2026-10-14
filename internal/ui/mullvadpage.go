package ui

import (
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"iter"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"deedles.dev/trayscale/internal/gutil"
	"deedles.dev/trayscale/internal/locale"
	"deedles.dev/trayscale/internal/peersearch"
	"deedles.dev/trayscale/internal/tsutil"
	"github.com/diamondburned/gotk4-adwaita/pkg/adw"
	"github.com/diamondburned/gotk4/pkg/gio/v2"
	"github.com/diamondburned/gotk4/pkg/gtk/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

//go:embed mullvadpage.ui
var mullvadPageXML string

type MullvadPage struct {
	app       *App
	stackPage *adw.ViewStackPage

	Page                     *adw.StatusPage
	SearchEntry              *gtk.SearchEntry
	LocationList             *gtk.ListBox
	EmptyLabel               *gtk.Label
	AutomaticExitNodeRow     *adw.SwitchRow
	HealthCheckedExitNodeRow *adw.SwitchRow
	AutoSwitchStatus         *gtk.Label
	LastAutoSwitchStatus     *gtk.Label

	locations       map[string]*adw.ExpanderRow
	exitNodes       map[tailcfg.StableNodeID]*mullvadExitNodeRow
	searchTokens    []string
	healthAvailable bool
	modeChanging    bool
}

func NewMullvadPage(a *App, status *tsutil.IPNStatus) *MullvadPage {
	page := MullvadPage{
		app:       a,
		locations: make(map[string]*adw.ExpanderRow),
		exitNodes: make(map[tailcfg.StableNodeID]*mullvadExitNodeRow),
	}
	gutil.FillFromUI(&page, mullvadPageXML)
	page.connectModeRows()

	page.LocationList.SetSortFunc(func(r1, r2 *gtk.ListBoxRow) int {
		return page.compareListRows(r1, r2)
	})
	page.LocationList.SetFilterFunc(func(row *gtk.ListBoxRow) bool {
		return page.listRowVisible(row)
	})

	page.SearchEntry.ConnectSearchChanged(func() {
		page.setQuery(page.SearchEntry.Text())
	})

	return &page
}

func (page *MullvadPage) setQuery(q string) {
	tokens := strings.Fields(q)
	if slices.Equal(tokens, page.searchTokens) {
		return
	}
	page.searchTokens = tokens
	page.applySearch()
}

func (page *MullvadPage) searching() bool {
	return len(page.searchTokens) > 0
}

func (page *MullvadPage) listRowVisible(row *gtk.ListBoxRow) bool {
	if node := page.exitNodes[tailcfg.StableNodeID(row.Name())]; node != nil {
		return page.searching() && node.match
	}
	return !page.searching()
}

func (page *MullvadPage) compareListRows(r1, r2 *gtk.ListBoxRow) int {
	if page.searching() {
		n1 := page.exitNodes[tailcfg.StableNodeID(r1.Name())]
		n2 := page.exitNodes[tailcfg.StableNodeID(r2.Name())]
		if n1 != nil && n2 != nil {
			return cmp.Or(
				cmp.Compare(n2.score, n1.score),
				strings.Compare(n1.row.Title(), n2.row.Title()),
				strings.Compare(r1.Name(), r2.Name()),
			)
		}
		return strings.Compare(r1.Name(), r2.Name())
	}
	return strings.Compare(page.expanderTitle(r1), page.expanderTitle(r2))
}

func (page *MullvadPage) expanderTitle(row *gtk.ListBoxRow) string {
	if loc := page.locations[row.Name()]; loc != nil {
		return loc.Title()
	}
	return row.Name()
}

func (page *MullvadPage) connectModeRows() {
	automatic := page.AutomaticExitNodeRow.ActivatableWidget().(*gtk.Switch)
	automatic.ConnectStateSet(func(active bool) bool {
		if active == automatic.State() {
			return false
		}
		mode := tsutil.ExitNodeModeSpecific
		if active {
			mode = tsutil.ExitNodeModeAutomatic
		}
		page.changeExitNodeMode(mode)
		return true
	})

	health := page.HealthCheckedExitNodeRow.ActivatableWidget().(*gtk.Switch)
	health.ConnectStateSet(func(active bool) bool {
		if active == health.State() {
			return false
		}
		mode := tsutil.ExitNodeModeSpecific
		if active {
			mode = tsutil.ExitNodeModeHealthChecked
		}
		page.changeExitNodeMode(mode)
		return true
	})
}

func (page *MullvadPage) changeExitNodeMode(mode tsutil.ExitNodeMode) {
	page.modeChanging = true
	page.AutomaticExitNodeRow.SetSensitive(false)
	page.HealthCheckedExitNodeRow.SetSensitive(false)
	page.app.runExitNodeChange(func(ctx context.Context) error {
		return page.app.setExitNodeMode(ctx, mode)
	}, func(err error) {
		page.modeChanging = false
		page.AutomaticExitNodeRow.SetSensitive(true)
		page.HealthCheckedExitNodeRow.SetSensitive(page.healthAvailable)
		if err != nil {
			slog.Error("set exit node mode", "mode", mode, "err", err)
			if page.app.win != nil {
				page.app.win.Toast(fmt.Sprintf("Failed to change exit-node mode: %v", err))
			}
		}
	})
}

func (page *MullvadPage) Widget() gtk.Widgetter {
	return page.Page
}

func (page *MullvadPage) Actions() gio.ActionGrouper {
	return nil
}

func (page *MullvadPage) Bind(stackPage *adw.ViewStackPage) {
	page.stackPage = stackPage
	stackPage.SetTitle(locale.Get("Mullvad Exit Nodes"))
	stackPage.SetIconName("network-workgroup-symbolic")
}

func (page *MullvadPage) Update(s tsutil.Status) bool {
	status, ok := s.(*tsutil.IPNStatus)
	if !ok {
		return true
	}
	if !status.Online() {
		return false
	}

	self, ok := status.Self()
	if !ok {
		return true
	}
	if !tsutil.CanMullvad(self) {
		return false
	}

	page.healthAvailable = page.app.settings != nil
	page.AutomaticExitNodeRow.SetSensitive(!page.modeChanging)
	page.HealthCheckedExitNodeRow.SetSensitive(page.healthAvailable && !page.modeChanging)

	mode := status.ExitNodeMode()
	setSwitchState(page.AutomaticExitNodeRow, mode == tsutil.ExitNodeModeAutomatic)
	setSwitchState(page.HealthCheckedExitNodeRow, mode == tsutil.ExitNodeModeHealthChecked)

	var exitNodeID tailcfg.StableNodeID
	if exitNode := status.ExitNode(); exitNode.Valid() {
		exitNodeID = exitNode.StableID()
	}

	var exitNodeCountryCode string
	var exitLoc tailcfg.LocationView
	found := make(set.Set[tailcfg.StableNodeID])
	nodesChanged := false
	for id, peer := range status.Peers {
		hi := peer.Hostinfo()
		if tsutil.IsMullvad(peer) && hi.Valid() && hi.Location().Valid() {
			found.Add(id)
			currentExitNode := id == exitNodeID
			explicitlySelected := currentExitNode && mode == tsutil.ExitNodeModeSpecific

			_, existed := page.exitNodes[id]
			row := page.getExitNodeRow(peer)
			if !existed {
				nodesChanged = true
			}
			row.peer = peer
			sw := row.row.ActivatableWidget().(*gtk.Switch)
			sw.SetState(explicitlySelected)
			sw.SetActive(explicitlySelected)

			loc := hi.Location()
			countryCode := loc.CountryCode()
			page.locations[countryCode].SetSubtitle("")
			if currentExitNode {
				exitNodeCountryCode = countryCode
				exitLoc = loc
			}
		}
	}
	for id, row := range page.exitNodes {
		if !found.Contains(id) {
			delete(page.exitNodes, id)
			page.removeNodeRow(row)
			nodesChanged = true
		}
	}
	page.updateAutoSwitchStatus(status)
	if exitNodeCountryCode != "" {
		page.locations[exitNodeCountryCode].SetSubtitle(locale.Get("Current exit node location"))
		page.stackPage.SetTitle(mullvadLongLocationName(exitLoc))
		page.stackPage.SetNeedsAttention(true)
	} else {
		page.stackPage.SetTitle(locale.Get("Mullvad Exit Nodes"))
		page.stackPage.SetNeedsAttention(false)
	}

	if nodesChanged {
		page.applySearch()
	}
	return true
}

func (page *MullvadPage) applySearch() {
	searching := page.searching()
	anyMatch := false
	for _, node := range page.exitNodes {
		match := true
		score := 0
		if searching {
			score, match = peersearch.ScoreFields(mullvadSearchFields(node.peer), page.searchTokens)
		}
		node.score = score
		node.match = match
		if match {
			anyMatch = true
		}
		page.setNodeTitle(node, searching)
		page.setNodeFlat(node, searching)
	}

	empty := searching && !anyMatch
	page.LocationList.SetVisible(!empty)
	page.EmptyLabel.SetVisible(empty)
	if empty {
		return
	}
	page.LocationList.InvalidateFilter()
	page.LocationList.InvalidateSort()
}

func (page *MullvadPage) setNodeTitle(node *mullvadExitNodeRow, searching bool) {
	loc := node.peer.Hostinfo().Location()
	if searching {
		node.row.SetTitle(mullvadLongLocationName(loc))
		return
	}
	node.row.SetTitle(loc.City())
}

func (page *MullvadPage) setNodeFlat(node *mullvadExitNodeRow, flat bool) {
	if node.flat == flat {
		return
	}
	loc := page.locations[node.country]
	if flat {
		if loc != nil {
			loc.Remove(node.row)
		}
		page.LocationList.Append(node.row)
		node.flat = true
		return
	}
	page.LocationList.Remove(node.row)
	if loc != nil {
		loc.AddRow(node.row)
	}
	node.flat = false
}

func (page *MullvadPage) removeNodeRow(node *mullvadExitNodeRow) {
	if node.flat {
		page.LocationList.Remove(node.row)
	} else if loc := page.locations[node.country]; loc != nil {
		loc.Remove(node.row)
	}
	if page.countryHasNodes(node.country) {
		return
	}
	if loc := page.locations[node.country]; loc != nil {
		delete(page.locations, node.country)
		page.LocationList.Remove(loc)
	}
}

func (page *MullvadPage) countryHasNodes(code string) bool {
	for _, node := range page.exitNodes {
		if node.country == code {
			return true
		}
	}
	return false
}

func mullvadSearchFields(peer tailcfg.NodeView) iter.Seq[string] {
	return func(yield func(string) bool) {
		if !peer.Valid() {
			return
		}
		hi := peer.Hostinfo()
		if hi.Valid() {
			if !yield(hi.Hostname()) {
				return
			}
			if loc := hi.Location(); loc.Valid() {
				city := loc.City()
				for _, s := range []string{city, loc.Country(), loc.CountryCode(), loc.CityCode(), usStateName(city)} {
					if s == "" {
						continue
					}
					if !yield(s) {
						return
					}
				}
			}
		}
		yield(strings.TrimSuffix(peer.Name(), "."))
	}
}

func (page *MullvadPage) updateAutoSwitchStatus(status *tsutil.IPNStatus) {
	current := "none"
	if exitNode := status.ExitNode(); exitNode.Valid() {
		current = strings.TrimSuffix(exitNode.Name(), ".")
		if hi := exitNode.Hostinfo(); hi.Valid() && hi.Hostname() != "" {
			current = hi.Hostname()
		}
	}
	runtime := status.AutoSwitch
	switch status.ExitNodeMode() {
	case tsutil.ExitNodeModeAutomatic:
		page.AutoSwitchStatus.SetText(fmt.Sprintf("Exit node: Automatic | Current: %s | Managed by Tailscale", current))
	case tsutil.ExitNodeModeHealthChecked:
		page.AutoSwitchStatus.SetText(fmt.Sprintf("Exit node: Automatic with connection checks | Current: %s | %s", current, autoSwitchDisplayText(runtime)))
	case tsutil.ExitNodeModeSpecific:
		page.AutoSwitchStatus.SetText(fmt.Sprintf("Exit node: Specific | Current: %s", current))
	default:
		page.AutoSwitchStatus.SetText("Exit node: off")
	}

	last := runtime.LastEvent
	if last.Time.IsZero() {
		page.LastAutoSwitchStatus.SetText("Last auto-switch: never")
		return
	}
	text := fmt.Sprintf(
		"Last automatic change: %s | %s -> %s | %s",
		last.Time.Format("2006-01-02 15:04:05"),
		last.From,
		last.To,
		autoSwitchOutcomeText(last.Outcome),
	)
	if last.Error != "" {
		text += " | " + last.Error
	}
	page.LastAutoSwitchStatus.SetText(text)
}

func setSwitchState(row *adw.SwitchRow, active bool) {
	sw := row.ActivatableWidget().(*gtk.Switch)
	sw.SetState(active)
	sw.SetActive(active)
}

func autoSwitchDisplayText(runtime tsutil.AutoSwitchRuntime) string {
	switch runtime.Mode {
	case tsutil.AutoSwitchGrace:
		return "Connection checks will start shortly"
	case tsutil.AutoSwitchMonitoring:
		if runtime.LastProbeOK {
			return "Exit-node connection is healthy"
		}
		return "Connection checks are active"
	case tsutil.AutoSwitchSuspect:
		return "Checking a possible connection failure"
	case tsutil.AutoSwitchSwitching:
		return "Changing to another Mullvad exit node"
	case tsutil.AutoSwitchVerifying:
		return "Checking the replacement exit node"
	case tsutil.AutoSwitchRollingBack:
		return "Returning to the previous exit node"
	case tsutil.AutoSwitchBackoff:
		return "Paused after an unsuccessful change"
	case tsutil.AutoSwitchWaiting:
		return "Waiting for Tailscale and a Mullvad exit node"
	default:
		return "Connection checks are off"
	}
}

func autoSwitchOutcomeText(outcome string) string {
	switch outcome {
	case "verified":
		return "successful"
	case "rolled-back":
		return "returned to previous exit node"
	case "unverified":
		return "could not be verified"
	default:
		return "unsuccessful"
	}
}

func (page *MullvadPage) getLocationRow(loc tailcfg.LocationView) *adw.ExpanderRow {
	if row, ok := page.locations[loc.CountryCode()]; ok {
		return row
	}

	row := adw.NewExpanderRow()
	row.SetName(loc.CountryCode())
	row.SetTitle(mullvadLocationName(loc))
	gutil.ExpanderRowListBox(row).SetSortFunc(func(r1, r2 *gtk.ListBoxRow) int {
		sw1 := r1.Cast().(*adw.SwitchRow)
		sw2 := r2.Cast().(*adw.SwitchRow)
		c1, s1 := splitCityState(sw1.Title())
		c2, s2 := splitCityState(sw2.Title())
		return cmp.Or(
			strings.Compare(s1, s2),
			strings.Compare(c1, c2),
			strings.Compare(sw1.Subtitle(), sw2.Subtitle()),
		)
	})

	page.locations[loc.CountryCode()] = row
	page.LocationList.Append(row)
	return row
}

func (page *MullvadPage) getExitNodeRow(peer tailcfg.NodeView) *mullvadExitNodeRow {
	if row, ok := page.exitNodes[peer.StableID()]; ok {
		return row
	}

	info := peer.Hostinfo()

	row := adw.NewSwitchRow()
	row.SetName(string(peer.StableID()))
	row.SetTitle(info.Location().City())
	row.SetSubtitle(info.Hostname())

	sw := row.ActivatableWidget().(*gtk.Switch)
	sw.SetMarginTop(12)
	sw.SetMarginBottom(12)
	sw.ConnectStateSet(func(s bool) bool {
		if s == sw.State() {
			return false
		}

		var node tailcfg.StableNodeID
		if s {
			node = peer.StableID()
		}
		row.SetSensitive(false)
		page.app.runExitNodeChange(func(ctx context.Context) error {
			if s {
				if err := tsutil.AdvertiseExitNode(ctx, false); err != nil {
					slog.Error("disable exit node advertisement", "err", err)
				}
			}
			return page.app.setSpecificExitNode(ctx, node)
		}, func(err error) {
			row.SetSensitive(true)
			if err != nil {
				slog.Error("set exit node", "err", err)
				sw.SetActive(sw.State())
			}
		})
		return true
	})

	locRow := page.getLocationRow(info.Location())
	node := &mullvadExitNodeRow{
		country: info.Location().CountryCode(),
		row:     row,
		peer:    peer,
		flat:    page.searching(),
	}
	if node.flat {
		page.LocationList.Append(row)
	} else {
		locRow.AddRow(row)
	}
	page.exitNodes[peer.StableID()] = node
	return node
}

type mullvadExitNodeRow struct {
	country string
	row     *adw.SwitchRow
	peer    tailcfg.NodeView
	score   int
	match   bool
	flat    bool
}

func mullvadLongLocationName(loc tailcfg.LocationView) string {
	return fmt.Sprintf(
		"%v %v, %v",
		countryCodeToFlag(loc.CountryCode()),
		loc.City(),
		loc.Country(),
	)
}

func mullvadLocationName(loc tailcfg.LocationView) string {
	return fmt.Sprintf(
		"%v %v",
		countryCodeToFlag(loc.CountryCode()),
		loc.Country(),
	)
}

func countryCodeToFlag(code string) string {
	var raw [2]rune
	for i, c := range code {
		raw[i] = 127397 + c
	}

	return string(raw[:])
}

var cityStateRE = regexp.MustCompile(`^(.*),?\s+([A-Z]{2})$`)

func splitCityState(str string) (city, state string) {
	parts := cityStateRE.FindStringSubmatch(str)
	if len(parts) == 0 {
		return str, ""
	}
	return parts[1], parts[2]
}

func usStateName(city string) string {
	_, code := splitCityState(city)
	return usStateNames[code]
}
