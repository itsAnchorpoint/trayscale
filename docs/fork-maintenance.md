# Maintaining the Anchorpoint fork

`anchorpoint` is the default branch and contains the custom changes. The GitHub
fork retains the upstream history; `upstream` points to DeedleFake/Trayscale.
The current base is upstream `v0.20.0`. The current fork release is
`v0.20.0-anchorpoint.5`, packaged as `trayscale-anchorpoint 0.20.0-5`.

## Updating to an upstream release

1. Fetch upstream tags and start an update branch from `anchorpoint`.
2. Merge the chosen upstream release tag. Resolve conflicts while preserving the
   newer upstream dependencies, localization, and notification handling.
3. Run `go test -vet=all ./...`, `go test -race ./internal/tsutil`,
   `go tool golangci-lint run --disable=errcheck`, and
   `glib-compile-schemas --strict --dry-run .`. Validate the AppStream metainfo.
4. Check the main window, Preferences, and exit-node mode controls against the
   running daemon without changing the user's network preferences.
5. Update the README base, metainfo, and Arch `pkgver` / `pkgrel`. Tag the
   verified commit using `v<upstream-version>-anchorpoint.<pkgrel>`, push it, and
   build with `makepkg` in `packaging/arch`.
6. Install the resulting package with `pacman -U`. Check package ownership,
   installed schema keys, startup, tray registration, and the embedded version.

Do not force-update release tags. The Arch recipe fetches the exact release tag
and uses the standard package hooks to refresh schemas, icons, and desktop data.
Fork updates are deliberate; this repository is not registered in the AUR.

## Modes and recovery

- Automatic is owned by Tailscale and survives closing Trayscale.
- Automatic with Connection Checks requires Trayscale to run. It needs three
  consecutive failed TCP checks with a healthy underlay before changing nodes.
  Shared DNS or underlay failures cannot trigger node churn. Replacement nodes
  must pass verification; failed recovery returns to the original node.
- Selecting a specific node, toggling exit-node use, or changing profiles cancels
  pending recovery. Trayscale never disables the exit node as a recovery step.

Settings use the existing `dev.deedles.Trayscale` GSettings schema. Recovery
history stays in `$XDG_STATE_HOME/trayscale/autoswitch.json`, defaulting to
`~/.local/state/trayscale/autoswitch.json`. Neither belongs in the repository.

## Returning to upstream

Install the ordinary `trayscale` package and accept replacing
`trayscale-anchorpoint`. Existing settings and autostart use the same app ID.
Keep a copy of the previous fork package for a straightforward `pacman -U`
rollback. Do not copy binaries over files owned by pacman.
