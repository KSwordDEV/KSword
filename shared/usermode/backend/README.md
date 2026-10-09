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
