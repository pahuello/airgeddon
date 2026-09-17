# DEVLOG — tmux panes mode for airgeddon utilities

Goal: when airgeddon runs in tmux mode, launch helper utilities as tmux **panes**
inside the main window instead of as separate tmux **windows**, so the user can
mouse-select / copy text from them. Requested layouts (by number of utilities,
max observed = 3), main airgeddon menu always kept as one pane:

- 1 utility  -> 2 panes  -> vertical split (menu left, utility right)      == tmux `even-horizontal`
- 2 utilities -> 3 panes -> menu on top full width, 2 utilities bottom row  == tmux `main-horizontal`
- 3 utilities -> 4 panes -> 2x2 grid, menu top-left                         == tmux `tiled`
- 4+ utilities            -> fallback to tmux `tiled`

## Decisions (confirmed with user)
- Scope: GLOBAL. All tmux-mode attacks use panes (covers WPA Enterprise, Evil Twin,
  handshake/PMKID, WPS, DoS, WEP, etc.), not only Enterprise.
- Layouts: use tmux built-in named layouts (even-horizontal / main-horizontal / tiled).
- Overflow (>3 utilities): tiled.
- Toggle: new boolean setting `AIRGEDDON_TMUX_PANES` (default `true`). Set it to
  `false` in the rc file to fall back to the old one-window-per-utility behaviour.

## Architecture of airgeddon's tmux handling (as found upstream, base commit 6f453c1)
- `manage_output()` (central dispatcher) -> in tmux mode calls `start_tmux_processes()`
  which does `tmux new-window` per utility. Used by ~69 call sites (most attacks).
- Cleanup by window name: `wait_for_process()` (`tmux kill-window`),
  `kill_tmux_windows()` (iterates `tmux list-windows`), and a direct
  `tmux kill-window` in `interruptible_capture_poll()`.
- Enterprise / Evil Twin attacks additionally generate a "control" script
  (`ag.enterprise_control.sh` / `ag.et_control.sh`) that runs in its own `Control`
  window and, on teardown, calls its OWN copy of `kill_tmux_windows "Control"`.
- WEP all-in-one generates two scripts (`ag.wepattack.sh`, key handler) with their
  OWN copies of `manage_output` / `start_tmux_processes` / `kill_tmux_windows` /
  `kill_tmux_window_by_name`.
- The main airgeddon menu runs in window `airgeddon-Main` (`${tmux_main_window}`),
  session `airgeddon${uid}` (`${session_name}`).

So there are effectively 5 copies of the window logic: the native one in the main
script + 4 inside generated (here-doc) scripts. All operate on the SAME tmux session.

## Implementation
### Pane identity
Each utility pane gets a tmux pane user option `@ag_name` = the old window name
(e.g. "Control", "AP", "Exploring for targets"). Using a pane option (not the
pane title, which a program could overwrite) lets the separate generated scripts
find/kill panes by name across processes. The main menu pane gets `@ag_name` =
`${tmux_main_window}`.

### Layout helper
`arrange_tmux_panes()` counts panes in the main window, toggles
`pane-border-status` (off for 1 pane, top otherwise), applies the layout by count,
and reselects the menu pane so keyboard input keeps going to the airgeddon menu.

### Native (main script) changes in airgeddon.sh
- New config var `AIRGEDDON_TMUX_PANES` registered as boolean option #18
  (default true) + rc file text + validation (generic boolean loop handles it).
- New var `tmux_panes_helper_file="ag.tmux_panes.sh"` (helper script for generated
  scripts).
- New functions: `tmux_panes_active()`, `arrange_tmux_panes()`,
  `kill_tmux_pane_by_name()`, `set_tmux_panes_helper()` (writes the helper file).
- `start_airgeddon_from_tmux()`: when panes active, set menu pane `@ag_name`,
  title and `pane-border-format`.
- `start_tmux_processes()`: pane branch (split main window, tag pane, send command,
  arrange) guarded by `tmux_panes_active`; else original window branch.
- `kill_tmux_windows()`: pane branch (kill panes by `@ag_name` except menu and an
  optional kept name, then arrange); else original.
- `wait_for_process()` and `interruptible_capture_poll()`: kill the pane by name
  when panes active; else `tmux kill-window`.

### Generated scripts
When panes are active, each generated script bakes `session_name`,
`tmux_main_window`, `AIRGEDDON_WINDOWS_HANDLING`, `AIRGEDDON_TMUX_PANES` and then
`source`s `${tmpdir}${tmux_panes_helper_file}` AFTER its own inline function
definitions, so the helper's pane versions of `start_tmux_processes`,
`kill_tmux_windows`, `kill_tmux_window_by_name` override the inline window ones.
`set_tmux_panes_helper` is called from each generator before writing its script.
When panes are inactive, generated scripts are emitted unchanged (old behaviour).

### Helper file (`ag.tmux_panes.sh`)
Written by `set_tmux_panes_helper` via a QUOTED here-doc (no escaping). Uses runtime
`${session_name}` / `${tmux_main_window}` (set by the sourcing script). Contains
pane-only versions of arrange/kill/create.

## Testing
Validated the tmux pane logic in isolation (headless tmux 3.7b) with dummy
`sleep` "utilities": verified 1/2/3/4 panes produce even-horizontal / main-horizontal
/ tiled, that the menu pane stays index 0 / focused, and that killing panes by
`@ag_name` re-arranges correctly.

On a default 80x24 terminal, vanilla `main-horizontal` used `main-pane-height=24`,
which left the two bottom utility panes 1 line tall. Fixed by setting
`main-pane-height 50%` before applying that layout (menu ~half height, two
utilities share the remaining half). Splits now always target the menu pane id,
not whichever pane happens to be current.

WEP all-in-one generated scripts (`ag.wepattack.sh`, key handler) initially still
called `tmux new-window`. They now `source` the same helper after their inline
window functions, so Chop-Chop / Fragmentation / Fake Auth / etc. also become
panes. Enterprise and Evil Twin Control scripts already sourced the helper.

## Notes / caveats
- `main-horizontal` keeps the lowest-index pane (the menu, created first) as the top
  main pane; `tiled` fills panes by index order so the menu stays top-left.
- Splitting can fail with "no space" on very small terminals; handled defensively
  (empty pane id -> skip).
- Reverting: set `AIRGEDDON_TMUX_PANES=false` in the rc file (or disable) to restore
  the original one-window-per-utility behaviour.
