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

<details>
<summary><b>Nested Virtualization Preview</b></summary>

<br>

<a href="https://github.com/user-attachments/assets/fa80eeca-e7a8-4176-bbd9-d94aca8ca36e">
<img
  src="https://github.com/user-attachments/assets/fa80eeca-e7a8-4176-bbd9-d94aca8ca36e"
  alt="Nested Virtualization Preview"
  width="100%"
/>
</a>

</details>

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

KSword is an ARK (Anti-Rootkit) and system analysis toolkit for Windows 10/11 x64. Its desktop apps and kernel driver compare user-mode and Ring 0 views of processes, drivers, connections and other objects. Differences are investigation evidence: availability, sampling time and legitimate system behavior must also be checked before attributing them to hidden activity.

On top of that, there is a full set of system tools: memory search & hex editing, PE/ELF/Mach-O scanning, packet capture, raw NTFS forensics, SSDT/callback/hook inspection, registry & startup auditing, device-stack tracing, and security policy checks — roughly what you'd otherwise piece together from ten different programs.

Inspection and system-changing actions have separate entry points. Sensitive operations such as driver unload, raw disk writes and protection changes have their own capability checks and confirmation flows; recovery is available for supported operations. Missing offsets or unavailable features are reported explicitly.

Source-available under the [KSword Community Source License v1.6](LICENSE) (not OSI-approved — see [License](#license)).

## Quick Start

Extract the release archive, run `Launcher.exe` as admin. It reads the support manifest and starts the right edition.

`KswordSetup.exe` is an optional installer that does the same thing plus creates shortcuts.

> [!IMPORTANT]
> R0 features need the KswordARK driver loaded. Without it the app still works, but kernel-side pages will show "unavailable."

The driver requires OS build 16299 or later. Launcher and the driver no longer impose a maximum OS build; exact PE/PDB profiles and per-feature checks still determine which kernel features are available. A newer Windows build is not automatically a validated configuration.

## Two Editions

|  | Ksword5.1 | KswordARKLight |
|---|---|---|
| Stack | Qt 6 / ADS dockable workspace | Native Win32, no runtime dependencies |
| Use case | Full workflow, HVM workspace and plugin integrations | Quick triage and an evidence workspace with minimal footprint |

Both use the same driver and the same `shared/driver/` protocol. Launcher selects an edition from the support manifest. Light adds lazy-loaded workspaces, process/entity navigation, evidence snapshots and row differences, JSON/TSV export with optional user-path redaction, and cross-process driver leases. A driver already running before Light starts is preserved when Light exits. Qt plugins and the unified Qt memory editor belong to the full edition.

## Features

**Process / Thread / Handle** — tree & list views, R3/R0 cross-view, thread stacks, modules, tokens, PDB diagnostics and injection-trace checks that distinguish findings from collection gaps. Gated actions for kill, suspend, R0 hide (recoverable), PPL patch.

**Memory** — region browsing, pattern search, bookmarks, kernel executable-memory scans and PTE/VA translation. The full edition shares one snapshot editor across Hex, disassembly, text and byte differences, with x86/x64 Intel assembly, patch previews, local undo/redo, and explicit application. Writes bind to the captured target/backend, compare original bytes before writing and verify actual readback; local undo does not undo a committed write. Memory access can use R3, standard R0, a private page-table window or **DDMA**, subject to page/backend capabilities; resident R-1 access has a separate workflow. See the [memory editor inventory](docs/内存编辑器组件清单.md).

<details>
<summary>DDMA — physical memory access through the disk controller, conditions and limits</summary>

<br>

DDMA issues a `_DIRECT` pass-through command against a `\Driver\Disk` device with
the transfer buffer pointed at a physical page — `ATA_PASS_THROUGH_DIRECT`
where ATA is available, otherwise `SCSI_PASS_THROUGH_DIRECT`. Compatibility with
NVMe, SAS/SATA and synthetic SCSI depends on the actual storage stack. The storage port driver builds the MDL and
programs the controller, so the *host bus adapter* moves the bytes. The data path never goes through the CPU page tables,
so DMA on real hardware can follow a different translation path from CPU reads;
IOMMU policy and controller limits still apply. The
DDMA sub-tab reads the same physical page through both backends and diffs them,
providing byte-level evidence of a backend discrepancy.

Technique credit: [btbd/ddma](https://github.com/btbd/ddma).

Required conditions and limits:

1. **It must borrow a disk sector as a staging area.** ATA only has read-sector
   and write-sector, so reading a physical page means writing it to a sector and
   reading it back. KSword requires you to name that LBA explicitly and tick an
   acknowledgement — there is **no default sector**, and the "is the LBA set?"
   test is a separate flag bit rather than "is it non-zero", because LBA 0 is a
   legal target and is also where the MBR lives. Each request backs the sectors
   up, uses them, and restores them inside one call; a failed restore is reported
   as an explicit warning rather than swallowed.
2. **Kernel debugging must be off.** Mapping ordinary RAM with `MmMapIoSpace`
   trips `MiShowBadMapper` and bugchecks. The driver reports the debugger state
   as a capability bit and the UI refuses the whole channel when it is set.
3. **The disk's driver stack has to accept a pass-through command.** ATA
   pass-through is tried first; if it is refused, SCSI pass-through is tried,
   which can be translated by the storage stack. A disk that refuses both
   cannot be used, and some HBAs cannot address above 4 GB. Note that the
   SLAT-bypass property itself only exists where the OS owns real hardware: in a
   hypervisor *guest* the "DMA" is emulated by the host and goes through the same
   address translation as everything else.

Non-full-page writes are read-modify-write and are reported as such, because
they leave a 4 KiB lost-update window for other bytes on the same page.

`KswordCLI.exe ddma selftest` checks capabilities and refusal paths without
writing disk sectors. Adding `--lba N` enables a real ATA/SCSI disk-read probe at
that LBA and still does not write sectors. This differs from `ddma read`, whose
physical-memory read uses scratch-sector backup, writes and restoration.
Lab use only.

</details>

**Scanner** — structural PE / ELF / Mach-O analysis. Byte editor is length-preserving only, checks the source snapshot before writing, atomic replace, optional backup.

**Network** — capture & filter, connection management, per-process throttle, request builder, HTTPS inspection, WFP firewall, NIDS, segmented download. R0 inventories: TCP / UDP / AFD / NSI / NDIS / WFP.

**Driver / Kernel** — service management, DriverObject / DeviceObject / MajorFunction inspection, transactional dispatch-table editor, loader-list removal (reversible), integrity & cross-view checks, unloaded-driver / PiDDB evidence. Object namespace, SSDT/SSSDT, IAT/EAT/inline hooks, callbacks (notify, registry, object, filter, bugcheck, shutdown, FS, logon, NMI, …), IDT baselines, descriptor-table & IOCTL decoding, disassembly.

**File / Storage** — dual-pane manager, hashes, signatures, PE/strings/hex, unlocker, NTFS recovery, minifilter & Section evidence, raw filesystem browser with deleted-entry analysis (read-only by default, write requires unlock), device tree and R0 device-stack audit.

**Monitor** — per-process ETW, syscall capture, WinAPI agent, WMI subscriptions, ETW session management, risk center. Task-Manager-style live charts.

**Debugger / Plugins** — executable and UI plugins, a plugin market, and optional standalone 64-bit Cheat Engine / x64dbg integrations through a shared KSword backend. The KSword tab provides controls and logs; each debugger keeps its own window. Native debugging remains available without the driver. R0/HVM paths, hidden execution breakpoints and optional Shadow execution-page writes depend on the selected policy and capabilities; unsupported data breakpoints and fallback paths are reported. See [debugger validation and limits](docs/ksword-debugger-vm-validation.md).

**Window / Registry / Handle / Startup / Service / Privilege** — what you'd expect, plus Win32k GUI audit, startup-item risk gating with recovery, and service TSV/JSON export.

**Security** — AppLocker, WDAC, Defender/ASR, VBS/Hyper-V, driver trust, event logs.

**Clipboard Guard** — process/global rules for independently allowing, logging or blocking clipboard reads, writes and enumeration. Architecture-matched x86/x64 agents report hook readiness and access events; coverage depends on successful injection and session access.

**Crash Analysis** — dump inspection, bugcheck evidence and screenshot/cached attribution support. The optional Shield uses public bugcheck callbacks for a bounded diagnostic buffer; it does not promise crash prevention or recovery from arbitrary kernel faults.

**Kernel Knowledge** — 71 bilingual searchable articles, each linked to live R3/R0 evidence pages.

**HVM / KVM Workspace** — guarded multiprocessor Intel VT-x/EPT residency, nested VMX dispatch with composed shadow EPT, EPT split views, EPTP-switching hooks, execution domains, R-1 memory/process actions and a guided hook wizard. AMD SVM/VMCB/NPT and nested SVM are implemented and exposed through a separate experimental path. Admission checks hardware, outer hypervisor, prepared resources, all-CPU self-tests and lifecycle state. Intel EPT extensions do not transfer to AMD; full inner-OS startup and broad AMD performance acceptance remain incomplete. Lab use only.

<details>
<summary>Where the HVM layer sits, and the scope of the recorded experiments</summary>

<br>

KSword HVM virtualizes the **Windows instance already running**. Intel enters
VMX non-root after `VMLAUNCH`; AMD uses the experimental SVM path. The monitor
handles exits beneath that same OS. A descendant VMM can then use the nested
VMX/SVM dispatcher when the selected backend and configuration admit it.

```text
Physical CPU / optional outer hypervisor
└─ KSword HVM: Intel VMX/EPT or experimental AMD SVM/NPT
   └─ Existing Windows instance
      └─ Descendant VMM through nested VMX/SVM
         └─ Child guest, subject to backend validation
```

Residency keeps this layer active. Stopping it ends the capabilities that depend
on its EPT/NPT mappings. Ordinary EPT view/domain changes follow the stopped-state
workflow; debugger-owned Shadow rules have a separate lifecycle. The driver
cannot be unloaded while CPUs remain resident; incomplete teardown retains its
resources and unload protection.

Recorded Intel experiments include a Hyper-V → Windows → KSword → VMware →
TinyCore chain, controlled 4×2 page remap/restore and fault trials, and a separate
same-binary timing follow-up. The earlier 2×2 long observation, newer 4×2 trials
and performance measurements are separate evidence sets; they do not establish
arbitrary guest compatibility or long-term stability of every later binary.
See [4×2 results](docs/next/hvm-4x2-results.md),
[timing follow-up](docs/next/hvm-followup-results.md) and the
[earlier gap-closure record](docs/next/hvm-paper-gap-closure.md).

AMD records include bounded bare-metal residency/cleanup and VMware guest
1/2/4/8-vCPU nested-SVM probes, including repeated cycles. These are controlled
probe results, while full inner-OS startup, sustained performance and wider
hardware acceptance remain experimental. See the
[AMD lab status](docs/next/ksword-amd-lab-status.md).

Architecture and lifecycle: [嵌套虚拟化架构](docs/next/嵌套虚拟化架构.md).

</details>

<details>
<summary>Full dock-by-dock table (17 main + 3 auxiliary)</summary>

<br>

See also [docs/OpenArk功能对照与TODO.md](docs/OpenArk功能对照与TODO.md) for the OpenArk comparison.

| Dock | Contents |
|---|---|
| **Welcome** | Version, build info, project links. |
| **Process** | Tree/list with icons & diff highlighting. Kill/suspend/resume/priority. Thread stacks, modules, tokens. R3/R0 cross-view. Recoverable R0 hiding (gated). PPL/signature ops with risk prompts. |
| **Network** | Capture & filter. TCP/UDP management. Per-process throttle. Request builder. HTTPS. ARP/DNS. Live hosts. WFP events & rules. NIDS. Segmented download. R0 stack inventories. |
| **Memory** | Region browser & search. Shared snapshot/assembly editor, bookmarks/breakpoints. R3/R0/private-window/DDMA backends. Kernel exec scan. Memory evidence. PTE/VA translation. |
| **File** | Dual-pane manager. Hash/sig/PE/strings/hex. PE/ELF/Mach-O scanner and guarded file-byte editor. Unlocker. NTFS recovery. Minifilter/FileObject/Section evidence. Storage & BitLocker. |
| **Driver** | Service CRUD. Loaded modules. DBWIN. DriverObj/DeviceObj/MajorFunction/FastIo. Transactional editors. Reversible loader-list removal. Integrity. Module cross-view. Unloaded/PiDDB evidence. |
| **Kernel** | Object namespace. Atom table. SSDT/SSSDT. Inline/IAT/EAT hooks. CID cross-view. ALPC/IPC. DynData. Capability matrix. Loaded-image & IDT baselines. Descriptor/IOCTL decode. Disassembly. Callback inventory/monitor. Kernel Knowledge (71 articles). |
| **KVM** | HVM admission, self-tests and residency. Nested VMX / experimental SVM, EPT views/hooks/domains, R-1 memory/process controls, SLAT/IOMMU evidence and diagnostics. |
| **Monitor** | Process ETW. Syscall capture. WinAPI agent. WMI subs. ETW provider/session mgmt. Risk center. |
| **Hardware** | CPU/GPU/mem/disk/net charts. Process I/O & ETW file activity. SetupAPI/CfgMgr tree. R0 device audit. |
| **Privileges** | Local accounts, groups, current process privileges. |
| **Windows** | Window enum/filter/preview/pick/control. Desktop mgmt. Message monitor. Win32k GUI/session audit. Hotkey/hook audit. |
| **Registry** | Tree browser. Key/value CRUD. .reg import/export. Async search. |
| **Handles** | PID/keyword/type filter. Named-object resolution. Type stats. HandleTable/ObjectHeader evidence. |
| **Startup** | Categorized across logon/service/driver/task/registry/WMI. Risk-gated changes with recovery. |
| **Services** | Filter/sort. Start/stop/pause. Startup type. Property editing. Dependencies. TSV/JSON export. |
| **Miscellaneous** | BCD/boot. Audio source attribution. System speed (with warnings). Shell associations. Clipboard Guard. Crash analysis. Disk edit & raw FS forensics (write = unlock). AppLocker/WDAC/Defender/ASR diagnostics. |

Auxiliary: task progress panel, log output with GUID call-chain tracing, real-time performance monitor. Settings use a separate dialog; file scanning is part of the file workflow.

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
APIMonitor_x64/          64-bit API/clipboard agent
APIMonitor_x86/          32-bit API/clipboard agent
DebuggerBackend/        Shared CE/x64dbg backend
CheatEngineExecutablePlugin/  Optional CE integration
X96dbgExecutablePlugin/       Optional x64dbg integration
shared/driver/           Shared IOCTL protocol headers
tools/                   PDB offset generator, build tools
docs/                    Technical docs
```

Website source: [Felix3322/KSwordWebsite](https://github.com/Felix3322/KSwordWebsite)

## Building

Requirements: Windows 10/11, VS 2022 with MSVC x64 tools, Qt 6.9.3
`msvc2022_64` plus QtMsBuild for the full edition, and WDK for the driver.
Light/Launcher do not need Qt. Use 64-bit MSBuild and HostX64 compiler/linker;
a 32-bit build host is not supported by this workflow.

The main Release/x64 build entry is the repository script. It prefers
`.deps/Qt/6.9.3/msvc2022_64` and `.deps/QtVsTools/msbuild`, checks the approved
64-bit toolchain and reads back HostX64 before building:

```powershell
& .\tools\Invoke-KSwordBuildCheck.ps1 -RepositoryRoot (Get-Location).Path -Action Build
```

For a standalone Light build using an **existing** `KswordARK.sys` in the output
directory, skip the driver's build/signing targets explicitly:

```powershell
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (!(Test-Path -LiteralPath $msbuild)) { $msbuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' }
if (!(Test-Path -LiteralPath $msbuild)) { throw '64-bit MSBuild is required.' }
$hostToolArgs = @('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
& $msbuild '.\KswordARKLight\KswordARKLight.vcxproj' /t:Build `
  /p:Configuration=Release /p:Platform=x64 @hostToolArgs `
  /p:KswordArkLightEnsureDriverBuilt=false /p:KswordArkLightSkipDriverSign=true `
  /p:KswordArkLightReuseSignedDriver=true /m:1 /v:minimal
```

Pass all three host-architecture properties on every manual MSBuild command.
A reused driver still has to match the intended protocol/capabilities; skipping
its build does not validate its signature or loading. Release packaging and
auxiliary targets are documented in [AGENTS.md](AGENTS.md).

<details>
<summary>Build troubleshooting</summary>

<br>

**Main-app `LNK1000`, `IMAGE::BuildImage` or `.iobj` failures** — use one clean
rebuild with a build-local WPO/LTCG override:

```powershell
& .\tools\Invoke-KSwordBuildCheck.ps1 -RepositoryRoot (Get-Location).Path `
  -Action Rebuild -DisableWholeProgramOptimization
```

Require `BUILD_RESULT=SUCCESS`, `EXIT_CODE=0` and a nonempty
`Ksword5.1/x64/Release/Ksword5.1.exe`. After this recovery use
`-VerifyArtifactOnly` for an artifact check; do not immediately repeat an ordinary
Build and invalidate the compatibility build cache.

**WDK validation failure after successful driver linking** — verify the actual
failing stage, then run x64 ApiValidator against the newly linked driver. Replace
the WDK version below with the installed one:

```powershell
$solutionDir = (Resolve-Path '.\Ksword5.1').Path + '\'
$apiValidatorX64 = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild '.\KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir @hostToolArgs `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` validates that stage only. Full Build, INF/CAT,
signing and actual loading remain separate checks; an interrupted Build must
not be reported as successful.

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
| Disk DMA (DDMA) | `KswordArkDdmaIoctl.h`, `KswordArkDdmaPlan.h` | Scratch LBA is mandatory and carries its own flag bit, so LBA 0 stays a legal target rather than an "unset" sentinel. Plan header holds the ATA task-file encoding shared by driver, client and tests. |
| Vendored offsets | `third_party/systeminformer_dyn/` | System Informer offset data only, no KPH comms. |

</details>

## Docs

[Documentation index](docs/README.md) — current feature guides, build/development references, validation records and historical research.

[CLI使用文档](docs/CLI使用文档.md) · [功能技术文档](docs/功能技术文档.md) · [内核知识中心](docs/内核知识中心.md) · [IOCTL audit](docs/driver_ioctl_audit.md) · [OpenArk对照](docs/OpenArk功能对照与TODO.md) · [动态偏移接入](docs/动态偏移功能接入步骤.md) · [PDB/R0 audit prep](docs/pdb_r0_audit_prep/) · [插件系统](docs/插件系统规范.md) · [多语言规范](docs/多语言语言包规范.md)

Virtualization (HVM): [嵌套虚拟化架构](docs/next/嵌套虚拟化架构.md) · [EPT切换后端设计](docs/next/EPT切换后端设计.md) · [嵌套下的跨核TLB失效](docs/next/嵌套下的跨核TLB失效.md) · [隐蔽Hook安全边界决策](docs/next/隐蔽Hook安全边界决策.md) · [自动化测试](docs/next/自动化测试.md) · [VM测试机搭建](docs/next/VM测试机搭建.md)

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

## Development Status

Nested VMX dispatch and shadow-EPT composition are implemented; they are no
longer future work. AMD SVM/NPT, wider guest/hardware compatibility and HVM
performance remain experimental and are tracked with their own evidence.
Bugcheck diagnostics and Shield also have bounded implementations; they are not
a general anti-BSOD guarantee. Current guides and historical experiments are
separated in the [documentation index](docs/README.md).
