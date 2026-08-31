#pragma once

#include "ark/ark_bugcheck.h"

#define KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT 512UL
#define KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS 64UL
#define KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT 1024UL
#define KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS 16UL
#define KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS 64UL
#define KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS 192UL
#define KSWORD_ARK_BUGCHECK_DRAW_MILLISECONDS 10000ULL

#define KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN 0UL
#define KSWORD_ARK_BUGCHECK_MODULE_OURS 1UL
#define KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT 2UL
#define KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY 3UL

#define KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE 0UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_LOW 1UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM 2UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH 3UL

#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_NONE 0UL
#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CONTEXT 1UL
#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CRITICAL 2UL

#define KSWORD_ARK_VMWARE_VENDOR_ID 0x15AD
#define KSWORD_ARK_PCI_BAR_COUNT 6UL

typedef struct _KSWORD_ARK_BUGCHECK_MODULE_ENTRY
{
    volatile LONG Sequence;
    ULONG_PTR Base;
    ULONG Size;
    ULONG Classification;
    CHAR Name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];
} KSWORD_ARK_BUGCHECK_MODULE_ENTRY, *PKSWORD_ARK_BUGCHECK_MODULE_ENTRY;

typedef struct _KSWORD_ARK_BUGCHECK_PROCESS_ENTRY
{
    volatile LONG Sequence;
    PVOID Object;
    ULONG_PTR ProcessId;
    BOOLEAN Exiting;
    UCHAR Reserved[3];
    CHAR Name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
} KSWORD_ARK_BUGCHECK_PROCESS_ENTRY, *PKSWORD_ARK_BUGCHECK_PROCESS_ENTRY;

typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS
{
    volatile LONG Captured;
    ULONG BugCheckCode;
    ULONG_PTR Parameter1;
    ULONG_PTR Parameter2;
    ULONG_PTR Parameter3;
    ULONG_PTR Parameter4;
    ULONG_PTR FaultAddress;
    ULONG FaultParameter;
    CHAR FaultMeaning[KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS];
    ULONG LastReason;
    ULONG LastDumpType;
    ULONG DumpBufferLength;
    ULONG64 DumpOffset;
    ULONG Irql;
    ULONG Cpu;
    LARGE_INTEGER PerfCounter;
    ULONG_PTR ProcessObject;
    ULONG_PTR ProcessId;
    ULONG ProcessSource;
    CHAR ProcessName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
    ULONG_PTR CandidateAddress;
    ULONG_PTR CandidateModuleBase;
    ULONG_PTR CandidateModuleOffset;
    ULONG CandidateModuleSize;
    ULONG CandidateParameter;
    ULONG CandidateClass;
    ULONG CandidateConfidence;
    CHAR CandidateModule[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];
    CHAR CandidateSource[KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS];
} KSWORD_ARK_BUGCHECK_DIAGNOSTICS, *PKSWORD_ARK_BUGCHECK_DIAGNOSTICS;

typedef struct _KSWORD_ARK_SVGA_CONTEXT
{
    BOOLEAN Found;
    BOOLEAN Mapped;
    BOOLEAN FifoMapped;
    ULONG Bus;
    ULONG Device;
    ULONG Function;
    USHORT VendorId;
    USHORT DeviceId;
    ULONG IoBase;
    PHYSICAL_ADDRESS FramebufferPhysical;
    SIZE_T FramebufferLength;
    PHYSICAL_ADDRESS FifoPhysical;
    SIZE_T FifoLength;
    ULONG Width;
    ULONG Height;
    ULONG Bpp;
    ULONG Depth;
    ULONG Pitch;
    ULONG FbOffset;
    ULONG FbSize;
    ULONG VramSize;
    ULONG RedMask;
    ULONG GreenMask;
    ULONG BlueMask;
    ULONG Capabilities;
    volatile UCHAR* Framebuffer;
    volatile ULONG* Fifo;
} KSWORD_ARK_SVGA_CONTEXT, *PKSWORD_ARK_SVGA_CONTEXT;

typedef struct _KSWORD_ARK_BUGCHECK_BITMAP_CACHE
{
    volatile LONG Valid;
    volatile LONG Uploading;
    ULONG Width;
    ULONG Height;
    ULONG Stride;
    ULONG BrandColorRgb;
    ULONG DataLength;
} KSWORD_ARK_BUGCHECK_BITMAP_CACHE, *PKSWORD_ARK_BUGCHECK_BITMAP_CACHE;

typedef struct _KSWORD_ARK_BUGCHECK_STATE
{
    volatile LONG Active;
    volatile LONG ClassicDisplayStarted;
    volatile LONG DumpDisplayStarted;
    volatile LONG ModeSetDone;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT DeviceObject;
    KBUGCHECK_CALLBACK_RECORD ClassicRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD SecondaryRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD DumpIoRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD TriageRecord;
    BOOLEAN ClassicRegistered;
    BOOLEAN SecondaryRegistered;
    BOOLEAN DumpIoRegistered;
    BOOLEAN TriageRegistered;
    volatile LONG TrackingReady;
    KSPIN_LOCK ModuleCacheLock;
    KSPIN_LOCK ProcessCacheLock;
    KSWORD_ARK_BUGCHECK_BITMAP_CACHE Bitmap;
    KSWORD_ARK_BUGCHECK_MODULE_ENTRY Modules[KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT];
    ULONG ModuleCount;
    ULONG ModuleNextSlot;
    KSWORD_ARK_BUGCHECK_PROCESS_ENTRY Processes[KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT];
    ULONG ProcessCount;
    ULONG ProcessNextSlot;
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics;
    KSWORD_ARK_SVGA_CONTEXT Svga;
} KSWORD_ARK_BUGCHECK_STATE, *PKSWORD_ARK_BUGCHECK_STATE;

extern KSWORD_ARK_BUGCHECK_STATE g_KswordArkBugcheckState;
extern UCHAR g_KswordArkBugcheckBitmapPixels[KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES];

// 控制器在 DriverEntry 只建立同步状态；配置 IOCTL 明确请求后才启动完整 BGP 诊断。
NTSTATUS
KswordARKBugcheckControlConfigure(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST* Request,
    _Out_ KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* Response
    );

// 耗时准备阶段在安全边界调用此函数；返回 STATUS_CANCELLED 表示驱动正在卸载，
// STATUS_IO_TIMEOUT 表示本次安装已超过 R0 的 30 秒预算。
NTSTATUS
KswordARKBugcheckControlCheckAbort(
    VOID
    );

NTSTATUS
KswordARKBugcheckSvgaInitialize(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    );

VOID
KswordARKBugcheckSvgaShutdown(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    );

VOID
KswordARKBugcheckSvgaModeSetNoLog(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    );

VOID
KswordARKBugcheckSvgaDrawPanelNoLog(
    _Inout_ PKSWORD_ARK_BUGCHECK_STATE State
    );

PCSTR
KswordARKBugcheckName(
    _In_ ULONG BugCheckCode
    );

PCSTR
KswordARKBugcheckModuleClassText(
    _In_ ULONG Classification
    );

PCSTR
KswordARKBugcheckConfidenceText(
    _In_ ULONG Confidence
    );

PCSTR
KswordARKBugcheckVerdictText(
    _In_ ULONG Classification
    );

PCSTR
KswordARKBugcheckReasonText(
    _In_ ULONG Reason
    );

PCSTR
KswordARKBugcheckDumpTypeText(
    _In_ ULONG DumpType
    );
