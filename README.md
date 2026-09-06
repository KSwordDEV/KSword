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
<p align="center"><strong>Source-available Windows ARK &amp; kernel analysis suite</strong></p>

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

KSword is an ARK (Anti-Rootkit) and system analysis toolkit for Windows 10/11 x64. It ships a desktop app and a kernel driver together — the app enumerates processes, drivers, connections, etc. from user mode, the driver does the same from Ring 0, and then they compare. Discrepancies mean something is hiding.

On top of that, there is a full set of system tools: memory search & hex editing, PE/ELF/Mach-O scanning, packet capture, raw NTFS forensics, SSDT/callback/hook inspection, registry & startup auditing, device-stack tracing, and security policy checks — roughly what you'd otherwise piece together from ten different programs.

All audit pages are read-only by default. Anything that modifies the system (driver unload, disk write, protection-level change, etc.) is behind a separate button with a confirmation dialog and undo where possible. When a kernel offset or feature isn't available on the current build, the UI says so instead of guessing.

Source-available under the [KSword Community Source License v1.6](LICENSE) (not OSI-approved — see [License](#license)).

## Quick Start

Extract the release archive, run `Launcher.exe` as admin. It reads the support manifest and starts the right edition.

`KswordSetup.exe` is an optional installer that does the same thing plus creates shortcuts.

> [!IMPORTANT]
> R0 features need the KswordARK driver loaded. Without it the app still works, but kernel-side pages will show "unavailable."

## Two Editions

|  | Ksword5.1 | KswordARKLight |
|---|---|---|
| Stack | Qt 6 / ADS dockable workspace | Native Win32, no runtime dependencies |
| Use case | Full workflow | Old machines, quick triage, minimal footprint |

Both use the same driver and the same `shared/driver/` protocol. Launcher picks for you.

## Features

**Process / Thread / Handle** — tree & list views, R3/R0 cross-view to detect hidden objects, thread stacks, modules, tokens, PDB diagnostics. Gated actions for kill, suspend, R0 hide (recoverable), PPL patch.

**Memory** — region browser, pattern search, hex viewer, bookmarks, R0 reads, kernel executable-memory scan, PTE translation.

**Scanner** — structural PE / ELF / Mach-O analysis. Byte editor is length-preserving only, checks the source snapshot before writing, atomic replace, optional backup.

**Network** — capture & filter, connection management, per-process throttle, request builder, HTTPS inspection, WFP firewall, NIDS, segmented download. R0 inventories: TCP / UDP / AFD / NSI / NDIS / WFP.

**Driver / Kernel** — service management, DriverObject / DeviceObject / MajorFunction inspection, transactional dispatch-table editor, loader-list removal (reversible), integrity & cross-view checks, unloaded-driver / PiDDB evidence. Object namespace, SSDT/SSSDT, IAT/EAT/inline hooks, callbacks (notify, registry, object, filter, bugcheck, shutdown, FS, logon, NMI, …), IDT baselines, descriptor-table & IOCTL decoding, disassembly.

**File / Storage** — dual-pane manager, hashes, signatures, PE/strings/hex, unlocker, NTFS recovery, minifilter & Section evidence, raw filesystem browser with deleted-entry analysis (read-only by default, write requires unlock), device tree and R0 device-stack audit.

**Monitor** — per-process ETW, syscall capture, WinAPI agent, WMI subscriptions, ETW session management, risk center. Task-Manager-style live charts.

**Window / Registry / Handle / Startup / Service / Privilege** — what you'd expect, plus Win32k GUI audit, startup-item risk gating with recovery, and service TSV/JSON export.

**Security** — AppLocker, WDAC, Defender/ASR, VBS/Hyper-V, driver trust, event logs.

**Kernel Knowledge** — 71 bilingual searchable articles, each linked to live R3/R0 evidence pages.

**HVM** — VMX self-test, one-shot guest, guarded Intel VT-x/EPT resident monitor. Refuses on AMD or incompatible config. Lab use only.

<details>
<summary>Full dock-by-dock table (17 main + 4 auxiliary)</summary>

<br>

See also [docs/OpenArk功能对照与TODO.md](docs/OpenArk功能对照与TODO.md) for the OpenArk comparison.

| Dock | Contents |
|---|---|
| **Welcome** | Version, build info, project links. |
| **Process** | Tree/list with icons & diff highlighting. Kill/suspend/resume/priority. Thread stacks, modules, tokens. R3/R0 cross-view. Recoverable R0 hiding (gated). PPL/signature ops with risk prompts. |
| **Network** | Capture & filter. TCP/UDP management. Per-process throttle. Request builder. HTTPS. ARP/DNS. Live hosts. WFP events & rules. NIDS. Segmented download. R0 stack inventories. |
| **Memory** | Region browser & search. Hex viewer + bookmarks/breakpoints. R0 reads. Kernel exec scan. Memory evidence. PTE/VA translation. |
| **File** | Dual-pane manager. Hash/sig/PE/strings/hex. Unlocker. NTFS recovery. Minifilter/FileObject/Section evidence. Storage & BitLocker. |
| **Scanner** | PE/ELF/Mach-O structural scan. Guarded byte editor (length-preserving, atomic, optional backup). |
| **Driver** | Service CRUD. Loaded modules. DBWIN. DriverObj/DeviceObj/MajorFunction/FastIo. Transactional editors. Reversible loader-list removal. Integrity. Module cross-view. Unloaded/PiDDB evidence. |
| **Kernel** | Object namespace. Atom table. SSDT/SSSDT. Inline/IAT/EAT hooks. CID cross-view. ALPC/IPC. DynData. Capability matrix. Loaded-image & IDT baselines. Descriptor/IOCTL decode. Disassembly. Callback inventory. Kernel Knowledge (71 articles). HVM. |
| **Monitor** | Process ETW. Syscall capture. WinAPI agent. WMI subs. ETW provider/session mgmt. Risk center. |
| **Hardware** | CPU/GPU/mem/disk/net charts. Process I/O & ETW file activity. SetupAPI/CfgMgr tree. R0 device audit. |
| **Privileges** | Local accounts, groups, current process privileges. |
| **Windows** | Window enum/filter/preview/pick/control. Desktop mgmt. Message monitor. Win32k GUI/session audit. Hotkey/hook audit. |
| **Registry** | Tree browser. Key/value CRUD. .reg import/export. Async search. |
| **Handles** | PID/keyword/type filter. Named-object resolution. Type stats. HandleTable/ObjectHeader evidence. |
| **Startup** | Categorized across logon/service/driver/task/registry/WMI. Risk-gated changes with recovery. |
| **Services** | Filter/sort. Start/stop/pause. Startup type. Property editing. Dependencies. TSV/JSON export. |
| **Miscellaneous** | BCD/boot. Audio source attribution. System speed (with warnings). Shell association management. Read-only disk edit & raw FS forensics (write = unlock). AppLocker/WDAC/Defender/ASR diagnostics. |

Auxiliary: task progress panel, log output with GUID call-chain tracing, immediate window, real-time perf monitor.

</details>

## Repository Layout

```
Ksword5.1/              Full Qt app
KswordARKLight/          Lightweight Win32 edition
KswordARKDriver/         Kernel driver
Launcher/                Startup helper
KswordCLI/               CLI (docs: docs/CLI使用文档.md)
KswordSetup/             Optional installer
Taskbar/                 Top AppBar (S O S Enter quick launch)
KswordHUD/               HUD overlay
APIMonitor_x64/          API monitoring helper
shared/driver/           Shared IOCTL protocol headers
tools/                   PDB offset generator, build tools
docs/                    Technical docs
```

Website: [KSwordDEV/Website](https://github.com/KSwordDEV/Website)

## Building

Requirements: Windows 10/11, VS 2022 (MSVC), Qt 6.9.3 msvc2022_64 (not needed for Light/Launcher), WDK (driver only).

```powershell
.\Setup-QtPaths.ps1 -QtDir 'C:\Qt\6.9.3\msvc2022_64'

$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
& $msbuild '.\Ksword5.1\Ksword5.1.sln' /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

Light only: `& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m`

No WDK? Build the user-mode projects and reuse an existing driver binary for the release.

<details>
<summary>Build troubleshooting</summary>

<br>

**LNK1000 / IMAGE::BuildImage on the main app** — do a one-off clean rebuild with WPO and LTCG off. Don't make it permanent. Check exit code and that `Ksword5.1\x64\Release\Ksword5.1.exe` exists and is non-zero.

**WDK ApiValidator fails after the driver links** — usually arch mismatch. Run standalone:

```powershell
$solutionDir = (Resolve-Path '.\Ksword5.1').Path + '\'
$apiValidatorX64 = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild '.\KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

</details>

## Contributing

Protocol headers in `shared/driver/`, UI talks to the driver through `ArkDriverClient` only, kernel offsets come from verified PDB/DynData profiles (never hardcoded), new files go in `.vcxproj` + `.vcxproj.filters`.

Details: [CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md)

<details>
<summary>Protocol reference</summary>

<br>

All headers under `shared/driver/`.

| Area | Header | Notes |
|---|---|---|
| Driver status / capabilities | `KswordArkCapabilityIoctl.h` | Powers the Driver Status page. |
| Dynamic offsets | `KswordArkDynDataIoctl.h` | Profile matching, field sources, capability gates. |
| Process extended info | `KswordArkProcessIoctl.h` (v2) | Session, image path, protection level, field availability. |
| Process hiding | `IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY` | Unlinks from lists, keeps CID entry for restore. |
| PPL patch | `KSW_CAP_PROCESS_PROTECTION_PATCH` | Gated; dialog shows impact + rollback risk. |
| Vendored offsets | `third_party/systeminformer_dyn/` | System Informer offset data only, no KPH comms. |

</details>

## Docs

[CLI使用文档](docs/CLI使用文档.md) · [功能技术文档](docs/功能技术文档.md) · [内核知识中心](docs/内核知识中心.md) · [IOCTL audit](docs/driver_ioctl_audit.md) · [OpenArk对照](docs/OpenArk功能对照与TODO.md) · [动态偏移接入](docs/动态偏移功能接入步骤.md) · [PDB/R0 audit prep](docs/pdb_r0_audit_prep/) · [插件系统](docs/插件系统规范.md) · [多语言规范](docs/多语言语言包规范.md)

## Notice

This project includes system-level debugging, auditing, and management capabilities. Use only in legally authorized environments.

## License

KSword is source-available under the [KSword Community Source License v1.6](LICENSE). "Open source" here means the code is visible — it is not an OSI-approved license. See `LICENSE` for redistribution and commercial-use terms.

The [Community Covenant](COMMUNITY_COVENANT.md) is about attribution and responsible use, not additional license restrictions. Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

## Star History

<a href="https://www.star-history.com/?repos=KSwordDEV%2FKSword&type=timeline&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&theme=dark&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=KSwordDEV/KSword&type=timeline&legend=top-left&sealed_token=hbas9yW4Wjk96TQwUcVo8iWbLMLjxz1Ageym2BTfRw2bV9g97jc35XTCzmb2yHYYxsOm4xNQrBp8kpr-mfkhnFg0-fSBW5otNIhxK0DEocUY0dBWKTMJ0vG7LsEBA0oNQIkZW2pCO44UEI3kps_J3yhO0jN_uvS1AArEXxLA4uGMoiFmiVzWuBuo6KlU" />
 </picture>
</a>

## ❤️ Sponsor

If this project helps you, consider supporting its development.

<img width="300" alt="1788661997687_d" src="https://github.com/user-attachments/assets/659eff17-5fd7-46e6-a66b-77ff0099875b" />
