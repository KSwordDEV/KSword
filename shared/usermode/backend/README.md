# Light/CLI R3 backend

Shared Windows C++20 implementation under `ks::r3`; no Qt or Light headers. Light keeps UI, confirmations, async scheduling and R0 adapters. Existing Qt-free `ksword` implementations remain unchanged.

Migration evidence is recorded in `.codex-build-logs/r3-migration/` (build/test logs and `progress.jsonl` with commit IDs). Each function group is validated and committed separately.

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
