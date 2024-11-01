# Change Log

<!-- next-header -->

## [Unreleased] - ReleaseDate

### User Interface

- Make the update message scrollable, so it doesn't go outside visible area making it impossible to close
- Update button names to better reflect what they do
- Swap postion of "Update mods" and "Uninstall mods"
- Update mod address entry to be scrollable
- Fix changing load priority value, while using priority sort option, resulting in weird behaviour
- Removed "Optional" tag and shortened "RequiredByAll" to "ReqByAll"
- Moved sorting options to combobox
- Added an option to disable some of the items on mod list
- Changed the issue with changing load priority option when using priority sorting option
- Added logs window that displays info previously displayed in the terminal

### Core Functionality

- Removed redundant patch to fix gas clouds not exploding
- Disabled Windows terminal opening by default

### Internal Changes

- Updated egui to version 0.29.1

## [Unreleased master branch] - 2024-06

### General

- Fix unintentionally linking to libssl on Linux. This used to prevent some users on various Linux
  distros from being able to launch mint at all.

### User Interface

- Add light/dark mode toggle to settings menu
- Replace escape menu modding tab with new modding menu
- Show mint mods in public server list
- Show time since last action
- Make mod URL searchable for mods without cache data
- Implement load priority to no longer rely on implicit ordering
- Add mod list sorting
- Slightly improved error reporting; mint should now indicate the mod that caused a failure
- Various GUI improvements

### Core Functionality

- Implement Asset Registry handling. This should be sufficient for most mods that were previously
  not usable with mint due to the lack of Asset Registry handling.
- Implement self-update
- Fix mod url resolution
- Fix mods sometimes integrating in incorrect order
- Add patch to fix gas clouds not exploding sometimes
- Some mod save file fixes for Windows store version

### Internal Changes

- Significantly optimize cache updates (first update will still be a full update)
- Allow overriding appdata dir via CLI flag
- Rename cache and config directories from `drg-mod-integration` to `mint` and default to legacy
  if they exist
- Fix Windows console being full of garbage characters
- Disable LTO for dev builds
- Add nix flake
- Improved testing
- Various CI improvements
- Reduce release size by removing debug symbols
- Package Linux target with zip instead of tar
- Compress bundled mod pak

## [0.2.10] - 2023-08-18

- Many small improvements to the GUI
- Add simple in game UI to show local and remote integration version and active mods
- Add experimental mod linting to assist with common mod issues such as conflicts ([#55](https://github.com/trumank/mint/pull/55))
- Microsoft Store: Fix mods being unable to write custom save files ([#58](https://github.com/trumank/mint/issues/58))
- Fix `profile` CLI command not respecting mod's `enable` flag

## [0.2.9] - 2023-08-11

- Update `egui_dnd` which makes dragging and re-ordering mods significantly smoother
- Restore modding subsystem config upon uninstalling to prevent all mods getting enabled and kicking the user to sandbox
- Fix regression introduced by case sensitive path fix ([#36](https://github.com/trumank/mint/issues/36))

## [0.2.8] - 2023-08-05

- Fix `*.ushaderbytecode` files not being filtered out and causing crash on load
- Fix including same asset paths with different casings causing Unreal Engine to load neither ([#29](https://github.com/trumank/mint/issues/29))

<!-- next-url -->
[Unreleased]: https://github.com/trumank/mint/compare/master...BlueCookieFrog:mint:master
[Unreleased master branch]: https://github.com/trumank/mint/compare/v0.2.10...HEAD
[0.2.10]: https://github.com/trumank/mint/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/trumank/mint/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/trumank/mint/compare/v0.2.7...v0.2.8
