# Light/CLI R3 backend

Shared Windows C++20 implementation under `ks::r3`; no Qt or Light headers. Light keeps UI, confirmations, async scheduling and R0 adapters. Existing Qt-free `ksword` implementations remain unchanged.

The 66 feature commits and their build/regression results are recorded in [MIGRATION.jsonl](MIGRATION.jsonl). Raw logs are retained locally in `.codex-build-logs/r3-migration/`. Each feature was linked and tested before its commit.

| Function | Evidence prefix |
|---|---|
| TCP/UDP connection enumeration and TCP close | 01-connections |
| Ping | 02-ping |
| route tracing | 03-trace-route |
| DNS lookup | 04-dns |
| firewall rules | 05-firewall |
| network R3 endpoint audit | 06-endpoint-audit |
| service enumeration and control | 07-service |
| registry browsing and reads | 08-registry-browse |
| registry search | 09-registry-search |
| registry mutations | 10-registry-mutations |
| startup enumeration | 11-startup-enumeration |
| startup enable disable and deletion | 12-startup-actions |
| current process token and privilege control | 13-privilege |
| directory browsing and path navigation | 14-directory |
| file creation transfer rename and deletion | 15-file-operations |
| file ownership and lock inspection | 16-file-ownership |
| file hash signature and entropy analysis | 17-file-analysis |
| file hex and PE snapshot analysis | 18-file-pe |
| process base enumeration | 19-process-enumeration |
| process extended field collection | 20-process-details |
| process dynamic and network telemetry | 21-process-telemetry |
| native process controls | 22-process-controls |
| process detail basic collection | 23-process-detail-basic |
| process thread queries and controls | 24-process-threads |
| process module queries and controls | 25-process-modules |
| process token details and editing | 26-process-token |
| process token switches | 27-process-token-switches |
| process PEB and memory queries | 28-process-peb |
| process usermode hotkey collection | 29-process-hotkeys |
| driver R3 enumeration and metadata | 30-driver |
| hardware device enumeration | 31-hardware-devices |
| hardware system performance sampling | 32-hardware-performance |
| hardware disk activity sampling | 33-hardware-disk |
| hardware USB topology | 34-hardware-usb |
| hardware system bus topology | 35-hardware-bus |
| window enumeration and management | 36-window |
| window clipboard reading | 37-window-clipboard |
| window capture protection | 38-window-capture |
| window hierarchy diagnostics | 39-window-hierarchy |
| global hotkey occupancy probing | 40-window-hotkey |
| ETW sessions event capture and filtering | 41-monitor-etw |
| system file holder scanning | 42-system-file-holder |
| system event log reading | 43-system-event-log |
| system context menu scanning and recovery | 44-system-context-menu |
| system time and timezone | 45-system-time |
| IOCTL decoding | 46-system-ioctl |
| kernel object namespace overview | 47-kernel-namespace |
| kernel recursive object directories | 48-kernel-directory |
| kernel symbolic links | 49-kernel-symlink |
| kernel Device and Driver objects | 50-kernel-device |
| kernel BaseNamedObjects | 51-kernel-base |
| kernel communication endpoints | 52-kernel-communication |
| kernel object type matrix | 53-kernel-types |
| kernel named pipes | 54-kernel-pipe |
| kernel Atom tables | 55-kernel-atom |
| kernel NtQuery queries | 56-kernel-ntquery |
| kernel Hook disk image baseline | 57-kernel-hook-disk |
| security Code Integrity and WDAC | 58-security-ci |
| security VBS HVCI and SKCI | 59-security-vbs |
| security Hyper-V | 60-security-hyperv |
| security AppLocker | 61-security-applocker |
| security BAM and ahcache | 62-security-bam |
| security Bugcheck VMware R3 evidence | 63-security-bugcheck |
| window list capture protection | 64-window-list-capture |
| clipboard clearing and live owner queries | 65-clipboard-control |
| process identity sampling adapters | 66-process-identity |

## Final validation

- Light Release/x64 clean rebuild: PASS; existing driver artifact reused, driver rebuild/sign disabled.
- Full LightTests and expected-suite audit: PASS, 42 suites; shared backend contract suite: 68 assertions.
- All 98 backend implementation files are registered in Light and its standalone `/W4 /WX` test project, including corresponding filters.
- All 109 backend headers compiled independently with C++20/v143/HostX64. Compiler include traces contain no Qt or Light headers; the standalone test executable has no Qt DLL dependency.
- The 66 migration commits modify only Light, its tests/manifest, this backend, shared memory and the boundary-check tool. Main-program, CLI, existing shared implementation and driver/protocol code were not changed by these commits.
- All original Light C++ string literals remain in Light or the extracted backend. This is a source preservation check, supplemented by regression assertions; it does not replace live acceptance of every page and system configuration.

Reproduce the public-header check with `pwsh -File tools/Test-KSwordR3BackendBoundary.ps1` from the repository root. Build Light and LightTests with 64-bit MSBuild and the three architecture properties documented in the repository agent notes. Final local evidence prefixes are `final-clean` and `final-boundary`.

## Calling and lifecycle boundaries

Include the required headers from the business directory and compile the corresponding sources with C++20 and Win32 SDK libraries. The current Light and standalone test projects provide complete source and link-dependency registrations for a future CLI consumer. Existing Qt-free `ksword`, driver-client and evidence implementations remain referenced.

Light owns controls, confirmation prompts, navigation, table conversion, refresh scheduling and R0 adapters. Mixed token/object-type flows keep their preflight/fallback/evidence merging in Light and call shared R3 operations in the original sequence. The caller retains the detail process identity lease across R3 and R0 collection. PID-cache selection stays with navigation; native process identity sampling is shared.

Clipboard and display-affinity operations execute on the original calling thread. Global hotkey probes register/unregister on the original worker; shortcut COM initialization, ETW callbacks/stop/join, PDH priming/locking and shared sampler ownership keep their original lifetimes. Backend functions do not manipulate Light controls.

The file mapped-process scan is implemented wholly through R0 in this checkout; it was retained and did not receive a migration commit. Pure R0 pages and UI copy/export/paste helpers also remain in Light. CLI commands have not been added.
