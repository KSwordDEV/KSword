<div align="right">
  <a href="./docs/readme_zh.md">简体中文</a> |
  <strong>English</strong>
</div>

<div align="center">

  <img
    src="./Ksword5.1/Ksword5.1/Resource/Logo/KswordHome-En.png"
    alt="KSword ARK Logo"
    width="520"
  />

  <a href="https://github.com/user-attachments/assets/02085a90-af21-4880-b956-d059a655a4da">
    <img
      src="https://github.com/user-attachments/assets/02085a90-af21-4880-b956-d059a655a4da"
      alt="KSword ARK dark interface"
      width="49%"
    />
  </a>
  <a href="https://github.com/user-attachments/assets/aeda0d71-c2c0-4317-abac-0fac811c153d">
    <img
      src="https://github.com/user-attachments/assets/aeda0d71-c2c0-4317-abac-0fac811c153d"
      alt="KSword ARK light interface"
      width="49%"
    />
  </a>

  <br>

  <sub>Dark Mode　|　Light Mode</sub>

</div>

<h1 align="center">Ksword5.1</h1>
<p align="center"><strong>A high-coverage source-available Windows ARK and kernel analysis suite</strong></p>

<p align="center">
  <a href="https://github.com/KSwordDEV/KSword/stargazers">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/network/members">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/issues">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
  <a href="https://github.com/KSwordDEV/KSword/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/KSwordDEV/KSword.svg?style=for-the-badge" />
  </a>
</p>

---

## Overview

Ksword5.1 is a source-available Windows ARK, kernel-debugging, and system-forensics suite. It includes the full Qt/ADS desktop application, the lightweight native Win32 `KswordARKLight`, the `KswordARKDriver` kernel driver, a CLI, desktop helper components, and an optional installer.

The current codebase focuses on R3/R0 cross-view evidence, PDB/DynData-driven offsets, read-only audit pages, and explicit gates for destructive or mutation-oriented actions.

## Recent Highlights

- KernelDock now includes a bilingual Kernel Knowledge center derived from `第二规划.md`: 71 searchable topics across 12 categories, each with a complete eight-part article, a versioned R3/R0 live-context query, centrally verified business IOCTL sources, and a route into the corresponding evidence page. Runtime `unsupported`, partial, truncation, DynData, privilege, and hardware limits remain explicit.
- A dedicated Scanner dock now performs background structural scans of PE, ELF, and Mach-O files. Its optional byte editor is deliberately constrained to length-preserving changes, revalidates the source snapshot, atomically replaces the target, and can keep a backup after explicit risk acknowledgement.
- Kernel and storage forensics now include clean loaded-image and IDT baselines, descriptor-table and IOCTL decoding tools, kernel disassembly, expanded R0 network inventories, and a raw filesystem browser with deleted-entry analysis.
- The HVM page supports confirmation-gated VMX self-tests, a one-shot guest, and a guarded resident Intel VT-x/EPT monitor with VM-exit telemetry. Resident start is rejected on AMD, under an existing hypervisor, or when power/topology/unload lifecycle guards are unavailable; it is intended for authorized lab and diagnostic use only.
- When a packaged DynData profile does not match, the full and lightweight applications can resolve an exact runtime PDB profile in the background. Identity checks are required before any result is applied.
- Recent usability work adds table-freeze controls, smooth scrolling, and a cancellable UI stall detector. Startup and network-configuration changes also have stronger target validation, recovery, and transaction handling.

## Components

- `Ksword5.1`: full Qt application with ADS dock layout and the complete ARK workflow.
- `KswordARKLight`: lightweight native Win32 ARK for older systems and low-resource environments, with simpler dependencies, faster startup, and a focused feature set.
- `Launcher`: pure Win32 startup and compatibility assistant. It checks the readable support manifest before launching the Qt or Light target and can prepare an offline developer collection bundle when loaded kernel modules have missing offsets.
- `KswordARKDriver`: kernel driver that implements process, thread, handle, memory, network, kernel-object, device, and security audit protocols.
- `KswordCLI`: command-line interface for automation, validation, and troubleshooting.
- `KswordSetup`: optional installer that extracts the release payload and creates shortcuts or integration settings. Manually extracting the full `Release\` directory is functionally equivalent.
- `Taskbar`, `KswordHUD`, and `APIMonitor_x64`: helper components for desktop integration, HUD, and API monitoring.

## Key Capabilities

- Process, thread, CID, and handle cross-view; hidden-object evidence; thread-stack inspection; process details; PDB field diagnostics; and guarded R0 actions.
- Memory-region browsing, search, hex viewing, bookmarks and breakpoints, R0 memory paths, kernel executable-memory scanning, memory evidence, and PTE/VA translation.
- Structured PE/ELF/Mach-O scanning and a guarded, length-preserving byte-editing path with source revalidation, atomic replacement, and optional backup.
- Packet monitoring, connection management, per-process throttling, request construction, HTTPS analysis, firewall/WFP views, NIDS, segmented downloads, and R0 TCP/UDP/AFD/NSI/NDIS/WFP inventory and audit views.
- Driver services, loaded modules, DriverObject/DeviceObject/MajorFunction/FastIo diagnostics, transactional MajorFunction and DriverObject/KLDR image/list editors, Driver Integrity, Module Cross-View, Unloaded/PiDDB evidence, clean loaded-image and IDT baselines, descriptor-table/IOCTL decoding, kernel disassembly, SSDT/SSSDT, hooks, callbacks, and object-namespace inspection.
- A bilingual, full-text-searchable Kernel Knowledge catalog with 71 articles, versioned R3/R0 request/CPU/time/WDF-WDM evidence, centrally verified business IOCTL mappings, Microsoft Learn references, and read-only navigation into existing KernelDock evidence pages.
- File management and recovery, hashes, signatures, PE/strings/hex views, file unlocker, minifilter/FileObject/Section/storage evidence, read-only raw filesystem and deleted-entry forensics, hardware utilization, disk monitoring, device trees, and R0 device-stack audits.
- AppLocker, WDAC/Code Integrity, Defender/ASR, VBS/Hyper-V, platform security, driver trust, and event-log diagnostics.
- ADS layout persistence and restoration, lazy initialization of visible docks, table-freeze and smooth-scrolling controls, a cancellable UI stall detector, top-menu settings, UIAccess/always-on-top policies, log and task-progress panels, and the Taskbar top AppBar with the `S O S Enter` quick launch.

## ARK Features by Main Application Dock

> This inventory is based on recent code, comments, dock-initialization logic, and the R0/R3 protocols. See `docs/OpenArk功能对照与TODO.md` for the OpenArk coverage comparison and remaining TODOs.

### Main Workspace Docks (17)

> Settings have moved from the primary docks to the top menu; the main workspace includes the Scanner and Miscellaneous docks.

| Primary Dock | Subpages / Key Areas | Primary Capabilities |
|---|---|---|
| Welcome | Welcome page | Shows version, build time, user information, avatar, and project entry points. |
| Process | Process list, create process, details, threads, modules, tokens, Cross-View, PDB Catalog | Process tree/list, icons and difference highlighting, terminate/suspend/resume/priority/critical-process actions, recoverable R0 hiding, R3/R0 process and thread comparison, thread stacks, and risk prompts for PPL/Signature/CID operations. |
| Network | Traffic monitor, per-process throttling, connection management, request builder, HTTPS, ARP/DNS, live hosts, firewall, NIDS, downloads, network audit | Packet capture and filtering, TCP/UDP connection management, WFP firewall events and rules, real-time detection, segmented HTTP/HTTPS downloads, and read-only R0 TCP/UDP/AFD/NSI/NDIS/WFP inventories and cross-view. |
| Memory | Processes and modules, regions, search, viewer, breakpoints/bookmarks, R0 read/write, Kernel Exec Scan, Memory Evidence, PTE | R3 memory browsing/search, R0 region reads, kernel executable-memory scanning, kernel/process memory evidence, and page-table/virtual-address translation. |
| File | File manager, recovery, properties, unlock, Minifilter, FileObject, Section, Storage/BitLocker | Dual-pane management, ownership/permission handling, hashes/signatures/PE/strings/hex, NTFS recovery, file-lock and Section mappings, and read-only storage-stack/BitLocker evidence. |
| Scanner | Structured scan, guarded byte editor | Background structural scanning for PE, ELF, and Mach-O files. The optional editor permits only length-preserving edits after explicit risk acknowledgement; it revalidates the original snapshot, atomically replaces the target, and can retain a backup. |
| Driver | Overview, operations, debug output, object information, integrity, module Cross-View, Unloaded/PiDDB | Driver-service registration/load/unload/delete, loaded modules, DBWIN output, DriverObject/DeviceObject/MajorFunction/FastIo, atomic MajorFunction and image-metadata transactions, reversible loader-list removal, Driver Integrity, unloaded-driver/PiDDB evidence, and warn-only explicitly confirmed operator actions. |
| Kernel | Object namespace, atom table, NtQuery, SSDT, SSSDT, Inline Hook, IAT/EAT, CID, IPC, DynData, driver status, callbacks, baselines, HVM, Kernel Knowledge | Recursive object directories, BaseNamedObjects, NamedPipe, symbolic links, device/driver objects, object-type matrix, CID/cross-view, ALPC/IPC, dynamic offsets, capability matrix, clean loaded-image and IDT baselines, descriptor-table/IOCTL decoding, kernel disassembly, and callback inventory/management. The bilingual Kernel Knowledge center adds 71 searchable articles, a versioned live R0 context/source query, official references, and read-only routes into existing evidence pages without hiding runtime degradation. Callback inventory covers notify, registry, object, filter, bugcheck, shutdown, file-system, logon, CallbackObject, image-verification, and NMI sources with module ownership plus v3 snapshot/row identity diagnostics. The HVM workflow has explicit confirmations for VMX self-tests, one-shot test guests, and guarded resident Intel VT-x/EPT monitoring. |
| Monitor | Process targeting, direct kernel calls, WinAPI, WMI, ETW, Risk Center | Target-process-tree ETW, syscall capture, WinAPI Agent, WMI subscriptions, ETW provider/session management, and ARK risk aggregation. |
| Hardware | Utilization, overview, CPU, GPU, memory, disk monitoring, device management, R0 device audit | Task-Manager-style performance views, dynamic disk/network/GPU cards, process I/O and ETW file activity, SetupAPI/CfgMgr device tree, and DevNode/USB/HID/PCI/ACPI/GPU/display/watchdog audit. |
| Privileges | Accounts, privileges | Local users, create user/reset password, group information, and the current process privilege snapshot. |
| Windows | Window list, desktop/window details, Win32k/GUI, hotkeys/hooks, clipboard, GPU/display | Window enumeration, filtering, preview, picking, control, desktop management, message monitoring, and structured win32k GUI/session plus hotkey/hook audit. |
| Registry | Tree, value list, search results | Registry browsing, key/value CRUD, `.reg` import/export, asynchronous search, and navigation. |
| Handles | Handle list, object types, object details | PID/keyword/type filtering, named-object resolution, object-type statistics, and HandleTable/ObjectHeader/ObjectType evidence. |
| Startup | Overview, logon, services, drivers, scheduled tasks, advanced registry, WMI | Categorized startup overview, icon rendering, filtering/export, file and registry location lookup, recovery-aware changes, and navigation to service management. Risk-gated actions validate targets before permanent removal and retain recovery transactions where the source supports them. |
| Services | Main service table, general, logon, recovery, dependencies, audit | Service filtering/sorting, startup-type changes, start/stop/pause/continue, property editing, dependency/audit information, and TSV/JSON export. |
| Miscellaneous | Boot, sound sources, system speed, Shell association management, disk editing, raw filesystem forensics, application control | BCD/boot entry points; Core Audio sound-source attribution; R0 system-wide speedup/slowdown with persistent warnings, two-step confirmation, and a recovery path; management of context menus, URL bindings, file Open With handlers, format-specific menus, and third-party Explorer Home entries; read-only disk editing, raw filesystem browsing, and deleted-entry analysis by default (writes require unlocking); and AppLocker/WDAC/Defender/ASR/platform-security/event-log diagnostics. |

### Auxiliary Panel Docks

| Panel | Key Areas | Primary Capabilities |
|---|---|---|
| Current Operations | Task cards | Shows the steps and progress of background tasks, then hides automatically when complete. |
| Log Output | Level filters, log table, context menu | Log filtering, copy/export, double-confirmation clearing, and GUID call-chain tracing. |
| Immediate Window | Code/text editor | Quick verification, temporary notes, and immediate output. |
| Monitor Panel | CPU/memory/disk/network charts | Bottom real-time performance monitor with multi-line throughput trends. |

## KswordARKLight (Lightweight Edition)

`KswordARKLight` is a lightweight ARK for earlier systems, low-resource environments, and rapid-response scenarios:

- It is implemented in native Win32/C++; its entry point, docks, controls, themes, and placeholder pages do not depend on Qt.
- Modules load on demand: inexpensive placeholder pages are created at startup, then real pages are materialized when a dock is activated to reduce startup stalls.
- Current modules cover processes, memory, registry, files, drivers, kernel, monitoring, hardware, windows, startup items, networking, handles, and miscellaneous security.
- It reuses the `shared/driver/` protocols and `ArkDriverClient`-style wrappers, and is connected to real KswordARK driver calls.
- `DriverService` can restore `KswordARK.sys` from EXE resources when needed, then install, start, stop, and query the service through SCM.
- Recent updates include lightweight kernel-UI layering; monitoring, window, startup, file, and process icons; process-difference highlighting; driver-page details; and unload IOCTL support.

## KswordSetup Installer

`KswordSetup` is a convenience installer for the release package, not a runtime requirement:

- The build script embeds the `Release\` payload into the installer as RCDATA.
- During installation, it extracts files, can optionally write appearance/startup settings, and creates desktop and Start-menu shortcuts.
- It can trigger UAC when needed for system-level options such as Task Manager replacement and test signing.
- If a complete `Release\` directory is already available, extracting it to a target directory and running the main program is functionally equivalent.

## Architecture Notes

- Shared R0/R3 protocols live under `shared/driver/`; new IOCTL headers, structures, and version fields must not be scattered across UI or driver-private directories.
- Driver IOCTL handlers are registered through `KswordARKDriver/src/dispatch/ioctl_registry.c`. `ioctl_dispatch.c` is limited to lookup, validation, invocation, logging, and request completion.
- User-mode access to the KswordARK device goes through `Ksword5.1/Ksword5.1/ArkDriverClient/` or the corresponding lightweight wrapper. Dock/UI code must not open the device or issue raw `DeviceIoControl` calls.
- PDB/DynData uses the v4 profile pack generated by `tools/pdb_offset_generator/`. Release packages carry only `ark_dyndata_pack_v4.json.qz`; R3 projects core v4 items in memory for existing field consumers.
- R0 features that depend on undocumented fields must declare their required capability. The dispatch layer applies the gate before the handler; missing DynData or a mismatched profile must degrade safely or fail closed.
- Audit pages should be read-only by default. Unload, delete, patch, bypass, disk-write, and similar mutation actions require a separate entry point, risk notice, and rollback/audit strategy.
- The first DynData phase uses the vendored System Informer dynamic-offset data in `third_party/systeminformer_dyn/`. Ksword integrates only the `KphDynConfig` data and a lightweight parser, not the KPH communication layer, object system, or session tokens.
- The DynData R0/R3 protocol is centralized in `shared/driver/KswordArkDynDataIoctl.h`. KernelDock's Dynamic Offsets page uses `ArkDriverClient` to show profile matches, field sources, and capability gates; when the driver loads, the main window automatically refreshes and applies the DynData profile.
- If a packaged profile does not match, the full and lightweight applications can resolve an exact runtime PDB profile in a serialized background DbgHelp session. Results are applied only after PE/PDB identity checks succeed; unsupported or mismatched data is not guessed across builds.
- Process extended information uses the v2 protocol in `shared/driver/KswordArkProcessIoctl.h` to provide session, full image path, Protection/SignatureLevel, ObjectTable/SectionObject availability, field source, and DynData capability. ProcessDock/ProcessDetail shows availability only and does not enumerate the handle table or Section directly when DynData is missing.
- Recoverable R0 process hiding uses `IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY`. The driver changes `_EPROCESS.UniqueProcessId` and unlinks `ActiveProcessLinks` while retaining the PspCidTable record, allowing restoration by the original PID.
- The unified driver status/capability protocol is in `shared/driver/KswordArkCapabilityIoctl.h`. KernelDock's Driver Status page shows Driver Loaded/Missing, Protocol Mismatch, DynData Missing, Limited, security policy, the most recent R0 error, and the feature-capability matrix.
- R0 PPL changes require `KSW_CAP_PROCESS_PROTECTION_PATCH`. The user-mode confirmation dialog must show the current/target Protection, SignatureLevel impact, field source, and rollback risk.
- New source files must be added to the corresponding `.vcxproj` and `.vcxproj.filters` files. Third-party integrations must keep their upstream license text.

## Repository Layout

- `Ksword5.1/`: main solution and full Qt application.
- `KswordARKLight/`: lightweight native Win32 ARK.
- `KswordARKDriver/`: kernel driver.
- `shared/driver/`: shared IOCTL protocol headers.
- `KswordCLI/`: command-line tool.
- `KswordSetup/`: optional installer and payload-generation scripts.
- `Taskbar/`: top AppBar, status display, and `S O S Enter` quick launch of the main application.
- `KswordHUD/`: HUD helper application.
- `APIMonitor_x64/`: API Monitor injection and monitoring component.
- `tools/pdb_offset_generator/`: PDB offset/profile-pack generation and validation tools.
- `docs/pdb_r0_audit_prep/`: PDB/R0 audit-preparation and acceptance documents.
- `third_party/systeminformer_dyn/`: vendored System Informer DynData snapshot with LICENSE/NOTICE and Ksword wrapper headers.
- [KSwordDEV/Website](https://github.com/KSwordDEV/Website): independently maintained product website and module documentation.

## Build Requirements

- Windows 10/11 x64.
- Visual Studio 2022, MSVC, and MSBuild.
- Qt 6.9.3 `msvc2022_64` for the full Qt application and helper UI projects. `KswordARKLight` does not require Qt.
- WDK is required for building the kernel driver.

## Quick Build

Use the repository script first to discover and store the local Qt path, avoiding machine-specific paths in individual `.vcxproj` files:

```powershell
# Run from the repository root; replace the path with the local Qt installation
.\Setup-QtPaths.ps1 -QtDir 'C:\Qt\6.9.3\msvc2022_64'

# Replace this MSBuild path for the local Visual Studio installation; a Developer PowerShell can use msbuild directly
$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'

# Build the full solution, including the main application, Taskbar, HUD, driver, CLI, installer, and lightweight edition
& $msbuild '.\Ksword5.1\Ksword5.1.sln' /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

Build only the lightweight ARK:

```powershell
& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

Build the native launcher and generate the readable release support manifest:

```powershell
& $msbuild '.\Launcher\Launcher.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

### MSVC and WDK recovery notes

Keep the standard MSVC toolchain for this project; it is not adapted to LLVM. If a main-application link emits `LNK1000` with `IMAGE::BuildImage` or an `.iobj` failure, run one clean rebuild with Whole Program Optimization and LTCG disabled **for that build only**. Do not edit the project files to make the change persistent and do not immediately run another normal build after it: the WPO-disabled output invalidates the normal incremental-build cache. Confirm the real MSBuild exit code and a nonzero `Ksword5.1\x64\Release\Ksword5.1.exe` instead. Updating, downgrading, or reinstalling MSVC is only a later option if this one-shot recovery also reproduces the linker failure.

For the x64 kernel driver, a WDK post-build `ApiValidator`/`aitstatic` failure can be an architecture-selection problem after `KswordARK.sys` has already linked. Verify that the `.sys` was freshly linked and that the stalled MSBuild has no active compiler, linker, or validator child process before stopping that exact process. Then run the validator separately with the x64 WDK binary directory (substitute the installed WDK version):

```powershell
$solutionDir = (Resolve-Path '.\Ksword5.1').Path + '\'
$apiValidatorX64 = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild '.\KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` confirms that standalone API/architecture validation. It does not prove a full driver build, INF/CAT generation, signing, or driver-load acceptance; report and validate those stages separately. A compiler or linker failure that occurs before the `.sys` is updated remains a real build failure and must be fixed directly.

If the current machine does not have a WDK or driver-signing environment, build the user-mode projects first. The release process can reuse an existing unsigned R0 release artifact.

## Release and Run

- A release archive should contain a `Release\` root with `Launcher.exe`, `Ksword5.1.exe`, `KswordARKLight.exe`, helper programs, driver, `profiles\launcher_support_manifest.json`, the DynData packs, Qt dependencies, and Qt plugin directories. Shortcuts and the installer post-install action launch `Launcher.exe`.
- `KswordSetup.exe` is optional. Extracting `Release\` and running `Launcher.exe` is the supported entry point; it chooses `Ksword5.1.exe` or `KswordARKLight.exe` after checking compatibility.
- R0 features require administrator privileges, a running driver service, and compatible system security settings. Test-signing and driver-signing requirements depend on the target system.

## Project Website

The [KSwordDEV/Website](https://github.com/KSwordDEV/Website) repository independently maintains the project website and module introductions.

## Notice

This project includes system-level debugging, auditing, and management capabilities. Use it only in legally authorized and compliant environments.

## License

Ksword is source-available under the [KSword Community Source License v1.6](LICENSE). In this project, "open source" means source code visibility and access; it does not mean the project uses an Open Source Initiative (OSI)-approved license.
Please follow the terms in LICENSE for what is permitted, especially around redistribution and commercial usage models. Third-party components keep their own licenses.

Except where a file says otherwise, Ksword's own code follows LICENSE. The [Ksword Community Covenant](COMMUNITY_COVENANT.md) is about honesty, attribution, responsible use, and not pretending an unofficial fork is official. It is a community promise, not another layer of license restrictions. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Star History

<a href="https://www.star-history.com/?repos=KSwordDEV%2FKSword&type=timeline&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&theme=dark&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
 </picture>
</a>
