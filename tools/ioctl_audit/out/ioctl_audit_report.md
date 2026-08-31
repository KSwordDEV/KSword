# KswordARKDriver IOCTL Audit Report

- Generated at: `2026-08-08T06:58:45.612070+00:00`
- Repository root: `C:\Users\Felix\CLionProjects\KSword`
- Headers scanned: `45`
- Registry scanned: `KswordARKDriver/src/dispatch/ioctl_registry.c`

## Summary

| Metric | Value |
| --- | --- |
| Shared IOCTL definitions | 170 |
| Registry entries | 170 |
| Registered definitions | 170 |
| Unregistered definitions | 0 |
| HIGH findings | 14 |
| MEDIUM findings | 6 |
| LOW findings | 0 |

## High-risk findings

| Category | IOCTL | Message | Details |
| --- | --- | --- | --- |
| mutating_any_access | IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["ANSWER"], "source": "shared/driver/KswordArkCallbackIoctl.h", "line": 48} |
| mutating_any_access | IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4 | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["APPLY"], "source": "shared/driver/KswordArkDynDataIoctl.h", "line": 61} |
| mutating_any_access | IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["CANCEL"], "source": "shared/driver/KswordArkCallbackIoctl.h", "line": 55} |
| mutating_any_access | IOCTL_KSWORD_ARK_DELETE_PATH | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["DELETE"], "source": "shared/driver/KswordArkFileIoctl.h", "line": 21} |
| mutating_any_access | IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["CONTROL"], "source": "shared/driver/KswordArkFileMonitorIoctl.h", "line": 67} |
| mutating_any_access | IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["CONTROL", "PATCH"], "source": "shared/driver/KswordArkHwidIoctl.h", "line": 25} |
| mutating_any_access | IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["PATCH"], "source": "shared/driver/KswordArkHwidIoctl.h", "line": 18} |
| mutating_any_access | IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["CONTROL"], "source": "shared/driver/KswordArkSecurityAuditIoctl.h", "line": 41} |
| mutating_any_access | IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["UNLOAD"], "source": "shared/driver/KswordArkUnloadedDriverIoctl.h", "line": 16} |
| mutating_any_access | IOCTL_KSWORD_ARK_SET_CALLBACK_RULES | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["SET"], "source": "shared/driver/KswordArkCallbackIoctl.h", "line": 27} |
| mutating_any_access | IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["SET"], "source": "shared/driver/KswordArkCallbackIoctl.h", "line": 83} |
| mutating_any_access | IOCTL_KSWORD_ARK_SET_PPL_LEVEL | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["SET"], "source": "shared/driver/KswordArkProcessIoctl.h", "line": 79} |
| mutating_any_access | IOCTL_KSWORD_ARK_SUSPEND_PROCESS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["SUSPEND"], "source": "shared/driver/KswordArkProcessIoctl.h", "line": 67} |
| mutating_any_access | IOCTL_KSWORD_ARK_TERMINATE_PROCESS | Mutating keyword matched but access is FILE_ANY_ACCESS. | {"keywords": ["TERMINATE"], "source": "shared/driver/KswordArkProcessIoctl.h", "line": 54} |

## All findings

| Severity | Category | Name | Message |
| --- | --- | --- | --- |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4 | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_DELETE_PATH | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_SET_CALLBACK_RULES | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_SET_PPL_LEVEL | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_SUSPEND_PROCESS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| HIGH | mutating_any_access | IOCTL_KSWORD_ARK_TERMINATE_PROCESS | Mutating keyword matched but access is FILE_ANY_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_RXPF_QUERY_STATS | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |
| MEDIUM | query_write_access | IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT | Query/read-only keyword matched but access requires FILE_WRITE_ACCESS. |

## IOCTL inventory

| IOCTL | Function | Method | Access | Registered | Handler | Source |
| --- | --- | --- | --- | --- | --- | --- |
| IOCTL_KSWORD_ARK_QUERY_ALPC_PORT | 0x80E | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKAlpcIoctlQueryAlpcPort | shared/driver/KswordArkAlpcIoctl.h:17 |
| IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP | 0x8FA | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKBugcheckIoctlSetBitmap | shared/driver/KswordArkBugcheckIoctl.h:24 |
| IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD | 0x8FB | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKBugcheckGuardIoctlConfigure | shared/driver/KswordArkBugcheckIoctl.h:56 |
| IOCTL_KSWORD_ARK_SET_CALLBACK_RULES | 0x880 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlSetRulesHandler | shared/driver/KswordArkCallbackIoctl.h:27 |
| IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE | 0x881 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlGetRuntimeStateHandler | shared/driver/KswordArkCallbackIoctl.h:34 |
| IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT | 0x882 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlWaitEventHandler | shared/driver/KswordArkCallbackIoctl.h:41 |
| IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT | 0x883 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlAnswerEventHandler | shared/driver/KswordArkCallbackIoctl.h:48 |
| IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS | 0x884 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlCancelAllPendingHandler | shared/driver/KswordArkCallbackIoctl.h:55 |
| IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK | 0x885 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKCallbackIoctlRemoveExternalCallbackHandler | shared/driver/KswordArkCallbackIoctl.h:62 |
| IOCTL_KSWORD_ARK_ENUM_CALLBACKS | 0x886 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlEnumCallbacksHandler | shared/driver/KswordArkCallbackIoctl.h:69 |
| IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX | 0x887 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKCallbackIoctlRemoveExternalCallbackExHandler | shared/driver/KswordArkCallbackIoctl.h:76 |
| IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS | 0x888 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlSetMinifilterBypassPidsHandler | shared/driver/KswordArkCallbackIoctl.h:83 |
| IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS | 0x889 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCallbackIoctlQueryMinifilterBypassPidsHandler | shared/driver/KswordArkCallbackIoctl.h:90 |
| IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES | 0x80A | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKCapabilityIoctlQueryDriverCapabilities | shared/driver/KswordArkCapabilityIoctl.h:19 |
| IOCTL_KSWORD_ARK_QUERY_CPU_POWER | 0x8F2 | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKCpuPowerIoctlQuery | shared/driver/KswordArkCpuPowerIoctl.h:19 |
| IOCTL_KSWORD_ARK_CONTROL_CPU_POWER | 0x8F3 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKCpuPowerIoctlControl | shared/driver/KswordArkCpuPowerIoctl.h:26 |
| IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL | 0x8F8 | METHOD_BUFFERED | FILE_READ_ACCESS\|FILE_WRITE_ACCESS | yes | KswordARKDebugOutputIoctlControl | shared/driver/KswordArkDebugOutputIoctl.h:27 |
| IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN | 0x8F9 | METHOD_BUFFERED | FILE_READ_ACCESS\|FILE_WRITE_ACCESS | yes | KswordARKDebugOutputIoctlDrain | shared/driver/KswordArkDebugOutputIoctl.h:34 |
| IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT | 0x8E0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDeviceAuditIoctlQueryDeviceStack | shared/driver/KswordArkDeviceAuditIoctl.h:20 |
| IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT | 0x8E1 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDeviceAuditIoctlQueryInputStack | shared/driver/KswordArkDeviceAuditIoctl.h:27 |
| IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT | 0x8E2 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDeviceAuditIoctlQueryUsbTopology | shared/driver/KswordArkDeviceAuditIoctl.h:34 |
| IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT | 0x8E3 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDeviceAuditIoctlQueryGpuDisplayWatchdog | shared/driver/KswordArkDeviceAuditIoctl.h:41 |
| IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION | 0x8A7 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlControlDriverCommunication | shared/driver/KswordArkDriverBlindIoctl.h:10 |
| IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH | 0x8CC | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlControlDriverDispatch | shared/driver/KswordArkDriverDispatchIoctl.h:10 |
| IOCTL_KSWORD_ARK_CONTROL_DRIVER_IMAGE | 0x8CE | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlControlDriverImage | shared/driver/KswordArkDriverImageEditorIoctl.h:10 |
| IOCTL_KSWORD_ARK_QUERY_DYN_STATUS | 0x807 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryStatus | shared/driver/KswordArkDynDataIoctl.h:26 |
| IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS | 0x808 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryFields | shared/driver/KswordArkDynDataIoctl.h:33 |
| IOCTL_KSWORD_ARK_QUERY_CAPABILITIES | 0x809 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryCapabilities | shared/driver/KswordArkDynDataIoctl.h:40 |
| IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE | 0x82F | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKDynDataIoctlApplyProfile | shared/driver/KswordArkDynDataIoctl.h:47 |
| IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX | 0x830 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKDynDataIoctlApplyProfileEx | shared/driver/KswordArkDynDataIoctl.h:54 |
| IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4 | 0x860 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlApplyProfileV4 | shared/driver/KswordArkDynDataIoctl.h:61 |
| IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES | 0x861 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryV4Modules | shared/driver/KswordArkDynDataIoctl.h:68 |
| IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS | 0x862 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryV4CapabilityGroups | shared/driver/KswordArkDynDataIoctl.h:75 |
| IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS | 0x863 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryV4MissingItems | shared/driver/KswordArkDynDataIoctl.h:82 |
| IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS | 0x864 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKDynDataIoctlQueryV4Items | shared/driver/KswordArkDynDataIoctl.h:89 |
| IOCTL_KSWORD_ARK_DELETE_PATH | 0x804 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKFileIoctlDeletePath | shared/driver/KswordArkFileIoctl.h:21 |
| IOCTL_KSWORD_ARK_QUERY_FILE_INFO | 0x812 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKFileIoctlQueryFileInfo | shared/driver/KswordArkFileIoctl.h:28 |
| IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY | 0x84D | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKFileIoctlSetIntegrity | shared/driver/KswordArkFileIoctl.h:35 |
| IOCTL_KSWORD_ARK_ENUM_DIRECTORY | 0x8CF | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKFileIoctlEnumDirectory | shared/driver/KswordArkFileIoctl.h:42 |
| IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL | 0x815 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKFileMonitorIoctlControl | shared/driver/KswordArkFileMonitorIoctl.h:67 |
| IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN | 0x816 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKFileMonitorIoctlDrain | shared/driver/KswordArkFileMonitorIoctl.h:74 |
| IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS | 0x817 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKFileMonitorIoctlQueryStatus | shared/driver/KswordArkFileMonitorIoctl.h:81 |
| IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY | 0x8B0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMinifilterIoctlQueryInventory | shared/driver/KswordArkFilterIoctl.h:18 |
| IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES | 0x80C | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKHandleIoctlEnumProcessHandles | shared/driver/KswordArkHandleIoctl.h:18 |
| IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT | 0x80D | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKHandleIoctlQueryHandleObject | shared/driver/KswordArkHandleIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_HVM | 0x8CA | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKHvmIoctlQuery | shared/driver/KswordArkHvmIoctl.h:14 |
| IOCTL_KSWORD_ARK_CONTROL_HVM | 0x8CB | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKHvmIoctlControl | shared/driver/KswordArkHvmIoctl.h:16 |
| IOCTL_KSWORD_ARK_HVM_EPT_RULE | 0x8B8 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKHvmIoctlEptRule | shared/driver/KswordArkHvmIoctl.h:18 |
| IOCTL_KSWORD_ARK_HVM_EVENTS | 0x8B9 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKHvmIoctlEvents | shared/driver/KswordArkHvmIoctl.h:20 |
| IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY | 0x8F0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKHwidIoctlQueryDispatch | shared/driver/KswordArkHwidIoctl.h:18 |
| IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL | 0x8F1 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKHwidIoctlControlDispatch | shared/driver/KswordArkHwidIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_I8042_AUDIT | 0x8E5 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKI8042AuditIoctlQuery | shared/driver/KswordArkI8042AuditIoctl.h:17 |
| IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE | 0x8C7 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlRestoreIdtBaseline | shared/driver/KswordArkKernelBaselineIoctl.h:9 |
| IOCTL_KSWORD_ARK_ENUM_SSDT | 0x806 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlEnumSsdt | shared/driver/KswordArkKernelIoctl.h:29 |
| IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT | 0x811 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryDriverObject | shared/driver/KswordArkKernelIoctl.h:36 |
| IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY | 0x8A4 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryIoctlRegistry | shared/driver/KswordArkKernelIoctl.h:44 |
| IOCTL_KSWORD_ARK_ENUM_TIMER_DPC | 0x8A5 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlEnumTimerDpc | shared/driver/KswordArkKernelIoctl.h:52 |
| IOCTL_KSWORD_ARK_CONTROL_IO_TIMER | 0x8AB | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlControlIoTimer | shared/driver/KswordArkKernelIoctl.h:61 |
| IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE | 0x8A6 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlExperimentalReturnToFirmware | shared/driver/KswordArkKernelIoctl.h:70 |
| IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT | 0x81E | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlEnumShadowSsdt | shared/driver/KswordArkKernelIoctl.h:134 |
| IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS | 0x81F | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlScanInlineHooks | shared/driver/KswordArkKernelIoctl.h:141 |
| IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK | 0x820 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlPatchInlineHook | shared/driver/KswordArkKernelIoctl.h:148 |
| IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS | 0x821 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlEnumIatEatHooks | shared/driver/KswordArkKernelIoctl.h:155 |
| IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER | 0x826 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlForceUnloadDriver | shared/driver/KswordArkKernelIoctl.h:162 |
| IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY | 0x849 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryDriverIntegrity | shared/driver/KswordArkKernelIoctl.h:169 |
| IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE | 0x84A | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryCpuHardware | shared/driver/KswordArkKernelIoctl.h:176 |
| IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT | 0x84B | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryPhysicalMemoryLayout | shared/driver/KswordArkKernelIoctl.h:183 |
| IOCTL_KSWORD_ARK_ENUM_CID_TABLE | 0x878 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelObjectIoctlEnumCidTable | shared/driver/KswordArkKernelObjectIoctl.h:20 |
| IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY | 0x879 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelObjectIoctlQueryObjectSummary | shared/driver/KswordArkKernelObjectIoctl.h:27 |
| IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY | 0x87A | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelObjectIoctlQueryIpcSummary | shared/driver/KswordArkKernelObjectIoctl.h:34 |
| IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE | 0x87B | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelObjectIoctlEnumTypeTable | shared/driver/KswordArkKernelObjectIoctl.h:41 |
| IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS | 0x847 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKeyboardIoctlEnumHotkeys | shared/driver/KswordArkKeyboardIoctl.h:18 |
| IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS | 0x848 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKeyboardIoctlEnumHooks | shared/driver/KswordArkKeyboardIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY | 0x813 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlQueryVirtualMemory | shared/driver/KswordArkMemoryIoctl.h:30 |
| IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY | 0x814 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlReadVirtualMemory | shared/driver/KswordArkMemoryIoctl.h:37 |
| IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY | 0x81D | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKMemoryIoctlWriteVirtualMemory | shared/driver/KswordArkMemoryIoctl.h:44 |
| IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY | 0x82B | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlReadPhysicalMemory | shared/driver/KswordArkMemoryIoctl.h:51 |
| IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY | 0x82C | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKMemoryIoctlWritePhysicalMemory | shared/driver/KswordArkMemoryIoctl.h:58 |
| IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS | 0x82D | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlTranslateVirtualAddress | shared/driver/KswordArkMemoryIoctl.h:65 |
| IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY | 0x82E | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlQueryPageTableEntry | shared/driver/KswordArkMemoryIoctl.h:72 |
| IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY | 0x831 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlScanKernelExecutableMemory | shared/driver/KswordArkMemoryIoctl.h:79 |
| IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE | 0x832 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKMemoryIoctlScanKernelMemoryEvidence | shared/driver/KswordArkMemoryIoctl.h:86 |
| IOCTL_KSWORD_ARK_MUTATION_PREPARE | 0x838 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKMutationIoctlPrepare | shared/driver/KswordArkMutationIoctl.h:25 |
| IOCTL_KSWORD_ARK_MUTATION_COMMIT | 0x839 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKMutationIoctlCommit | shared/driver/KswordArkMutationIoctl.h:32 |
| IOCTL_KSWORD_ARK_MUTATION_ROLLBACK | 0x83A | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKMutationIoctlRollback | shared/driver/KswordArkMutationIoctl.h:39 |
| IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT | 0x83B | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKMutationIoctlQueryAudit | shared/driver/KswordArkMutationIoctl.h:46 |
| IOCTL_KSWORD_ARK_NETWORK_SET_RULES | 0x829 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKNetworkIoctlSetRules | shared/driver/KswordArkNetworkIoctl.h:26 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS | 0x82A | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryStatus | shared/driver/KswordArkNetworkIoctl.h:33 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS | 0x8A0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryTcpEndpoints | shared/driver/KswordArkNetworkIoctl.h:40 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS | 0x8A1 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryUdpEndpoints | shared/driver/KswordArkNetworkIoctl.h:47 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY | 0x8A2 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryWfpInventory | shared/driver/KswordArkNetworkIoctl.h:54 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN | 0x8A3 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryNdisChain | shared/driver/KswordArkNetworkIoctl.h:61 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS | 0x8A9 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryWfpEvents | shared/driver/KswordArkNetworkIoctl.h:68 |
| IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS | 0x8AA | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKNetworkIoctlQueryTrafficPackets | shared/driver/KswordArkNetworkIoctl.h:75 |
| IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE | 0x8AC | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKNetworkIoctlControlTrafficCapture | shared/driver/KswordArkNetworkIoctl.h:82 |
| IOCTL_KSWORD_ARK_QUERY_PIDDB | 0x8C8 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryPiDdb | shared/driver/KswordArkPiDdbIoctl.h:10 |
| IOCTL_KSWORD_ARK_DELETE_PIDDB | 0x8C9 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKKernelIoctlDeletePiDdb | shared/driver/KswordArkPiDdbIoctl.h:12 |
| IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT | 0x8E4 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKPlatformAuditIoctlQuery | shared/driver/KswordArkPlatformAuditIoctl.h:18 |
| IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT | 0x8E6 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKPlatformAuditIoctlControl | shared/driver/KswordArkPlatformAuditIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_PREFLIGHT | 0x81C | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKPreflightIoctlQuery | shared/driver/KswordArkPreflightIoctl.h:19 |
| IOCTL_KSWORD_ARK_TERMINATE_PROCESS | 0x801 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlTerminate | shared/driver/KswordArkProcessIoctl.h:54 |
| IOCTL_KSWORD_ARK_SUSPEND_PROCESS | 0x802 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlSuspend | shared/driver/KswordArkProcessIoctl.h:67 |
| IOCTL_KSWORD_ARK_SET_PPL_LEVEL | 0x803 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlSetPplLevel | shared/driver/KswordArkProcessIoctl.h:79 |
| IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY | 0x84C | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKProcessIoctlSetIntegrity | shared/driver/KswordArkProcessIoctl.h:93 |
| IOCTL_KSWORD_ARK_ENUM_PROCESS | 0x805 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlEnumProcess | shared/driver/KswordArkProcessIoctl.h:128 |
| IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW | 0x836 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlQueryCrossView | shared/driver/KswordArkProcessIoctl.h:359 |
| IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL | 0x83C | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlQueryDetail | shared/driver/KswordArkProcessIoctl.h:370 |
| IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS | 0x83E | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKProcessIoctlQueryRuntimeFields | shared/driver/KswordArkProcessIoctl.h:377 |
| IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY | 0x822 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKProcessIoctlSetVisibility | shared/driver/KswordArkProcessIoctl.h:654 |
| IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS | 0x824 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKProcessIoctlSetSpecialFlags | shared/driver/KswordArkProcessIoctl.h:679 |
| IOCTL_KSWORD_ARK_DKOM_PROCESS | 0x825 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKProcessIoctlDkomProcess | shared/driver/KswordArkProcessIoctl.h:720 |
| IOCTL_KSWORD_ARK_INJECT_PROCESS | 0x833 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKProcessIoctlInjectProcess | shared/driver/KswordArkProcessIoctl.h:758 |
| IOCTL_KSWORD_ARK_REDIRECT_SET_RULES | 0x827 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRedirectIoctlSetRules | shared/driver/KswordArkRedirectIoctl.h:18 |
| IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS | 0x828 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKRedirectIoctlQueryStatus | shared/driver/KswordArkRedirectIoctl.h:25 |
| IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE | 0x823 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKRegistryIoctlReadValue | shared/driver/KswordArkRegistryIoctl.h:23 |
| IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY | 0x840 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKRegistryIoctlEnumKey | shared/driver/KswordArkRegistryIoctl.h:30 |
| IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE | 0x841 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlSetValue | shared/driver/KswordArkRegistryIoctl.h:37 |
| IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE | 0x842 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlDeleteValue | shared/driver/KswordArkRegistryIoctl.h:44 |
| IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY | 0x843 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlCreateKey | shared/driver/KswordArkRegistryIoctl.h:51 |
| IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY | 0x844 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlDeleteKey | shared/driver/KswordArkRegistryIoctl.h:58 |
| IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE | 0x845 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlRenameValue | shared/driver/KswordArkRegistryIoctl.h:65 |
| IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY | 0x846 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRegistryIoctlRenameKey | shared/driver/KswordArkRegistryIoctl.h:72 |
| IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT | 0x900 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlQuerySupport | shared/driver/KswordArkRxPfIoctl.h:19 |
| IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE | 0x901 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlRegisterPage | shared/driver/KswordArkRxPfIoctl.h:21 |
| IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE | 0x902 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlChangePage | shared/driver/KswordArkRxPfIoctl.h:23 |
| IOCTL_KSWORD_ARK_RXPF_QUERY_PAGE | 0x903 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlQueryPage | shared/driver/KswordArkRxPfIoctl.h:25 |
| IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE | 0x904 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlWritePage | shared/driver/KswordArkRxPfIoctl.h:27 |
| IOCTL_KSWORD_ARK_RXPF_SET_EMULATION | 0x905 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlSetEmulation | shared/driver/KswordArkRxPfIoctl.h:29 |
| IOCTL_KSWORD_ARK_RXPF_QUERY_STATS | 0x906 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlQueryStats | shared/driver/KswordArkRxPfIoctl.h:31 |
| IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS | 0x907 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlDrainEvents | shared/driver/KswordArkRxPfIoctl.h:33 |
| IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE | 0x908 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlUnregisterPage | shared/driver/KswordArkRxPfIoctl.h:35 |
| IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST | 0x909 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKRxpfIoctlRunSelfTest | shared/driver/KswordArkRxPfIoctl.h:37 |
| IOCTL_KSWORD_ARK_QUERY_SAFETY_POLICY | 0x81A | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSafetyIoctlQueryPolicy | shared/driver/KswordArkSafetyIoctl.h:18 |
| IOCTL_KSWORD_ARK_SET_SAFETY_POLICY | 0x81B | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKSafetyIoctlSetPolicy | shared/driver/KswordArkSafetyIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION | 0x80F | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSectionIoctlQueryProcessSection | shared/driver/KswordArkSectionIoctl.h:18 |
| IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS | 0x810 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSectionIoctlQueryFileSectionMappings | shared/driver/KswordArkSectionIoctl.h:25 |
| IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS | 0x8D0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSecurityAuditIoctlQuerySecurityStatus | shared/driver/KswordArkSecurityAuditIoctl.h:20 |
| IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW | 0x8D1 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSecurityAuditIoctlQueryDriverTrustView | shared/driver/KswordArkSecurityAuditIoctl.h:27 |
| IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY | 0x8D2 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSecurityAuditIoctlQueryHyperVSummary | shared/driver/KswordArkSecurityAuditIoctl.h:34 |
| IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS | 0x8D3 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSecurityAuditIoctlQueryAppControlStatus | shared/driver/KswordArkSecurityAuditIoctl.h:41 |
| IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT | 0x8CD | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQuerySlatIommuAudit | shared/driver/KswordArkSlatIommuAuditIoctl.h:10 |
| IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND | 0x8C4 | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKStorageIoctlQueryRawDiskBackend | shared/driver/KswordArkStorageForensicsIoctl.h:19 |
| IOCTL_KSWORD_ARK_READ_RAW_DISK | 0x8C5 | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKStorageIoctlReadRawDisk | shared/driver/KswordArkStorageForensicsIoctl.h:26 |
| IOCTL_KSWORD_ARK_WRITE_RAW_DISK | 0x8C6 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKStorageIoctlWriteRawDisk | shared/driver/KswordArkStorageForensicsIoctl.h:33 |
| IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT | 0x8C0 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKStorageIoctlQueryVolumeStackAudit | shared/driver/KswordArkStorageIoctl.h:23 |
| IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT | 0x8C1 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKStorageIoctlQueryBitLockerFveAudit | shared/driver/KswordArkStorageIoctl.h:30 |
| IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT | 0x8C2 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKStorageIoctlQueryMountMgrMappingAudit | shared/driver/KswordArkStorageIoctl.h:37 |
| IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT | 0x8C3 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKStorageIoctlQueryFileSystemIntegrityAudit | shared/driver/KswordArkStorageIoctl.h:44 |
| IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME | 0x865 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKSystemTimeIoctlQuery | shared/driver/KswordArkSystemTimeIoctl.h:12 |
| IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME | 0x866 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKSystemTimeIoctlControl | shared/driver/KswordArkSystemTimeIoctl.h:19 |
| IOCTL_KSWORD_ARK_ENUM_THREAD | 0x80B | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKThreadIoctlEnumThread | shared/driver/KswordArkThreadIoctl.h:23 |
| IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW | 0x837 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKThreadIoctlQueryCrossView | shared/driver/KswordArkThreadIoctl.h:30 |
| IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL | 0x83D | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKThreadIoctlQueryDetail | shared/driver/KswordArkThreadIoctl.h:41 |
| IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS | 0x83F | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKThreadIoctlQueryRuntimeFields | shared/driver/KswordArkThreadIoctl.h:48 |
| IOCTL_KSWORD_ARK_TERMINATE_THREAD | 0x84F | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKThreadIoctlTerminate | shared/driver/KswordArkThreadIoctl.h:59 |
| IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED | 0x850 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKThreadIoctlSetSuspended | shared/driver/KswordArkThreadIoctl.h:78 |
| IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD | 0x851 | METHOD_BUFFERED | FILE_WRITE_ACCESS | yes | KswordARKThreadIoctlControlDriverThread | shared/driver/KswordArkThreadIoctl.h:101 |
| IOCTL_KSWORD_ARK_QUERY_IMAGE_TRUST | 0x819 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKTrustIoctlQueryImageTrust | shared/driver/KswordArkTrustIoctl.h:20 |
| IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE | 0x84E | METHOD_BUFFERED | FILE_READ_ACCESS\|FILE_WRITE_ACCESS | yes | KswordARKTrustIoctlQueryImageSignature | shared/driver/KswordArkTrustIoctl.h:27 |
| IOCTL_KSWORD_ARK_QUERY_UNLOADED_DRIVERS | 0x8A8 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKKernelIoctlQueryUnloadedDrivers | shared/driver/KswordArkUnloadedDriverIoctl.h:16 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS | 0x890 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryProfileStatus | shared/driver/KswordArkWin32kIoctl.h:24 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS | 0x891 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryWindows | shared/driver/KswordArkWin32kIoctl.h:31 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS | 0x892 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryGuiThreads | shared/driver/KswordArkWin32kIoctl.h:38 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB | 0x893 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryHotkeysPdb | shared/driver/KswordArkWin32kIoctl.h:45 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB | 0x894 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryHooksPdb | shared/driver/KswordArkWin32kIoctl.h:52 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL | 0x895 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryWindowDetail | shared/driver/KswordArkWin32kIoctl.h:63 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_TIMERS | 0x896 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryTimers | shared/driver/KswordArkWin32kIoctl.h:71 |
| IOCTL_KSWORD_ARK_QUERY_WIN32K_EVENT_HOOKS | 0x897 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWin32kIoctlQueryEventHooks | shared/driver/KswordArkWin32kIoctl.h:79 |
| IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE | 0x852 | METHOD_BUFFERED | FILE_READ_ACCESS | yes | KswordARKWorkQueueIoctlEnum | shared/driver/KswordArkWorkQueueIoctl.h:16 |
| IOCTL_KSWORD_ARK_QUERY_WSL_SILO | 0x818 | METHOD_BUFFERED | FILE_ANY_ACCESS | yes | KswordARKWslSiloIoctlQuery | shared/driver/KswordArkWslSiloIoctl.h:17 |

## Rule notes

```json
{
  "allowedAnyAccess": [],
  "mutatingKeywords": [
    "SET",
    "WRITE",
    "PATCH",
    "TERMINATE",
    "KILL",
    "UNLOAD",
    "DELETE",
    "CREATE",
    "RENAME",
    "HIDE",
    "PROTECT",
    "APPLY",
    "SUSPEND",
    "CONTROL",
    "CANCEL",
    "REMOVE",
    "ANSWER",
    "DKOM"
  ],
  "queryKeywords": [
    "QUERY",
    "READ",
    "ENUM",
    "GET",
    "SCAN",
    "WAIT",
    "DRAIN",
    "TRANSLATE",
    "STATUS"
  ],
  "ignoredHeaders": [],
  "notes": {
    "purpose": "Policy file for the KswordARKDriver IOCTL static auditor.",
    "allowedAnyAccess": "Add a full IOCTL_KSWORD_ARK_* name here only when FILE_ANY_ACCESS is intentional and documented.",
    "mutatingKeywords": "Tokens that usually indicate state-changing or destructive operations and should not stay FILE_ANY_ACCESS by default.",
    "queryKeywords": "Tokens that usually indicate read-only/query operations and should not require FILE_WRITE_ACCESS unless there is a documented reason.",
    "ignoredHeaders": "Use repository-relative paths or basenames for protocols owned by a different driver project."
  }
}
```
