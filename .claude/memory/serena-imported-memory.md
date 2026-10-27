# 从 Serena 迁移的项目记忆

以下是用户要求保留的 Serena 原始项目资料。它们是历史快照；使用前请核对当前源码、项目约定和用户要求。原文中的 `mem:` 引用属于旧的 Serena 工具，现仅作为历史引用保留。

## 原文件：conventions.md

# Conventions
- Code comments are expected in Chinese for project code; keep normal multi-line style and avoid compressed one-line code.
- Simple toolbar buttons should use icons and tooltips instead of visible text.
- New or changed `QMenu` instances must explicitly set background/readable state, typically via `KswordTheme::ContextMenuStyle()`.
- New `QDialog` pages must force opaque readable backgrounds when parent widgets may have transparent/special styling.
- Text/log/detail popups should prefer the project `CodeEditorWidget` unless the use case clearly does not fit.
- Avoid `.inc` file stacking; split by clear `.h`/`.cpp` modules.

## 原文件：core.md

# Core
- Main Qt app lives under `Ksword5.1/Ksword5.1`; `MainWindow` wires docks, `WindowDock` currently subclasses `OtherDock` as the window-management page.
- R0/R3 protocol definitions belong only in `shared/driver/`; UI code must not define driver IOCTL contracts.
- UI access to KswordARK driver must go through `Ksword5.1/Ksword5.1/ArkDriverClient/`; Dock files should not call KswordARK `DeviceIoControl` directly.
- New source files must be added to both `Ksword5.1/Ksword5.1/Ksword5.1.vcxproj` and `.vcxproj.filters`.
- Read module-specific notes in `mem:conventions` before broad UI or driver edits.

## 原文件：memory_maintenance.md

# Memory Maintenance

## Discovery Model

- Core principle: progressive discovery through references, building a graph of memories.
- Initially, agents are provided with the list of all memories (names only).
- Agents should read `mem:core` as the top-level entry point (graph root).
  This memory should contain references to other memories covering major project domains.
  The referenced memories shall, in turn, shall contain references to even more specific memories, and so on.
  The depth of the graph shall depend on the project complexity.
- Use topics/folders to group related memories in order to make the content structure explicit.
  Folders can mirror project structure (e.g. modules like frontend/backend) or topics like debugging, architecture, etc.
- Memory references must use a mem: prefix inside backticks, e.g. `mem:frontend/core`.
  The surrounding text should clearly indicate when to read the memory/which content to expect.
  The text should provide more precise guidance than the memory name alone, 
  i.e. avoid a reference like "frontend debugging: `mem:frontend/debugging` and instead make clear which aspects of frontend debugging are covered.
- Memories themselves should not contain information about when to read them; this is the responsibility of the referring memory.

## Style

Dense agent notes, not prose docs. Prefer invariants, terse bullets. 
Avoid obvious context, rationale, and examples unless they prevent likely mistakes. 
Keep guidance durable and generalizable, not task-local.

## Add/update threshold

Add or update memories only with stable, non-obvious project conventions that avoid complex rediscovery in the future.
Do not add: quick-read facts; generic language/framework knowledge; one-off task notes; volatile line-level details; behavior likely to change soon.

## Maintenance Actions

- Renaming memories: References are updated automatically if handled via Serena's memory rename tool.
- Checking for stale memories (e.g. after deletion): Call `serena memories check` for a report.

## 原文件：suggested_commands.md

# Suggested Commands
- Quick status: `git status --short --branch --untracked-files=all`.
- Main Release build from repo root: set `$env:KSWORD_QT_DIR=(Resolve-Path '.deps\\Qt\\6.9.3\\msvc2022_64').Path`; set `$qtMsBuild=(Resolve-Path '.deps\\QtVsTools\\msbuild').Path`; then run MSBuild on `Ksword5.1\\Ksword5.1\\Ksword5.1.vcxproj` with `/p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal`.
- For text search in PowerShell, prefer `rg -g "*.cpp"` style globs instead of shell-expanded `*.cpp`.

## 原文件：task_completion.md

# Task Completion
- For code changes, run a targeted MSBuild of the touched project when feasible; for main app use `Ksword5.1/Ksword5.1/Ksword5.1.vcxproj` with explicit `Configuration` and `Platform`.
- If MSBuild fails because Qt is unbound, set `KSWORD_QT_DIR` and pass `QtMsBuild` as described in `mem:suggested_commands`.
- After build, check `git status --short --branch --untracked-files=all` and ensure intended new `.cpp/.h` files are represented in `.vcxproj` and `.vcxproj.filters`.

## 原文件：tech_stack.md

# Tech Stack
- Windows C++/Qt application; main project uses MSVC, QtMsBuild, and C++23 in `Ksword5.1/Ksword5.1/Ksword5.1.vcxproj`.
- Qt path is expected through `KSWORD_QT_DIR`; local dependency path from AGENTS is `.deps/Qt/6.9.3/msvc2022_64` with QtVsTools msbuild under `.deps/QtVsTools/msbuild`.
- Driver project is separate under `KswordARKDriver` and may require WDK; release packaging can reuse existing unsigned R0 artifacts when driver build is unavailable.

