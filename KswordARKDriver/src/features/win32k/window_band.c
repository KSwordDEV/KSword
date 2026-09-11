// Exact-build USER transaction adapter. No code patch, token change, raw band
// write, or Explorer injection. See docs/窗口输入控制.md for the verified ABI.
#include <ntifs.h>
#include "win32k_support.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/runtime_signature_scan.h"
#include "driver/KswordArkWindowBandIoctl.h"

typedef PVOID (*KSW_BAND_ENTER)(ULONG, ULONG);
typedef VOID (*KSW_BAND_LEAVE)(VOID);
typedef PVOID (*KSW_BAND_VALIDATE)(PVOID);
typedef PVOID (*KSW_BAND_BEGIN)(ULONG);
typedef PVOID (*KSW_BAND_DEFER)(PVOID, PVOID, PVOID, INT, INT, INT, INT, ULONG, ULONG);
typedef LONG (*KSW_BAND_END)(PVOID, LONG);
typedef VOID (*KSW_BAND_LOCK)(PVOID, PVOID, PVOID);
typedef VOID (*KSW_BAND_UNLOCK)(PVOID, PVOID);
typedef PVOID (*KSW_BAND_ROOT_OWNER)(PVOID);
typedef ULONGLONG (NTAPI *KSW_BAND_CREATE_TIME)(PEPROCESS);

typedef struct _KSW_BAND_RUNTIME {
    KSW_BAND_ENTER Enter;
    KSW_BAND_LEAVE Leave;
    KSW_BAND_VALIDATE Validate;
    KSW_BAND_BEGIN Begin;
    KSW_BAND_DEFER Defer;
    KSW_BAND_END End;
    KSW_BAND_LOCK Lock;
    KSW_BAND_UNLOCK Unlock;
    KSW_BAND_ROOT_OWNER RootOwner;
    KSW_BAND_CREATE_TIME CreateTime;
} KSW_BAND_RUNTIME;

typedef struct _KSW_BAND_VIEW {
    ULONG_PTR Handle, ThreadInfo, Desktop, Shared, Next, Previous, Parent;
    ULONG Band;
} KSW_BAND_VIEW;

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID, PCSTR);

static BOOLEAN KswBandRead(ULONG_PTR Address, PVOID Out, SIZE_T Bytes)
{
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        Address <= MAXULONG_PTR - Bytes &&
        KswordARKRuntimeReadMemory((PVOID)Address, Out, Bytes);
}

// Each private hop is read through MmCopyMemory, including pointers returned
// by USER. Exception handling is NOT used as a kernel memory-read primitive.
static BOOLEAN KswBandView(PVOID Window, KSW_BAND_VIEW* View)
{
    ULONG_PTR words[14];
    RtlZeroMemory(View, sizeof(*View));
    if (!KswBandRead((ULONG_PTR)Window, words, sizeof(words))) return FALSE;
    View->Handle = words[0]; View->ThreadInfo = words[2];
    View->Desktop = words[3]; View->Shared = words[5];
    View->Next = words[11]; View->Previous = words[12]; View->Parent = words[13];
    return KswBandRead(View->Shared + 0xEC, &View->Band, sizeof(View->Band));
}

static BOOLEAN KswBandExactImage(PVOID Base, ULONG Size)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DEBUG_DIRECTORY debug;
    ULONG i;
    struct { ULONG signature; GUID guid; ULONG age; } rsds;
    static const GUID expected = {0x80DB0813,0x4711,0x330D,{0xD7,0x06,0x8D,0x82,0x6F,0xF8,0xE1,0xB0}};
    if (Size != 0x428000 || !KswBandRead((ULONG_PTR)Base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        (ULONG)dos.e_lfanew > Size - sizeof(nt) ||
        !KswBandRead((ULONG_PTR)Base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage != Size || nt.FileHeader.TimeDateStamp != 0x5CD0A4AF)
        return FALSE;
    {
        const IMAGE_DATA_DIRECTORY d = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (!d.VirtualAddress || d.VirtualAddress > Size || d.Size > Size - d.VirtualAddress ||
            d.Size / sizeof(debug) > 64) return FALSE;
        for (i = 0; i < d.Size / sizeof(debug); ++i) {
            if (!KswBandRead((ULONG_PTR)Base + d.VirtualAddress + i * sizeof(debug), &debug, sizeof(debug))) return FALSE;
            if (debug.Type != IMAGE_DEBUG_TYPE_CODEVIEW || debug.SizeOfData < sizeof(rsds) ||
                debug.AddressOfRawData > Size - sizeof(rsds)) continue;
            if (KswBandRead((ULONG_PTR)Base + debug.AddressOfRawData, &rsds, sizeof(rsds)) &&
                rsds.signature == 0x53445352 && rsds.age == 1 &&
                RtlCompareMemory(&rsds.guid, &expected, sizeof(expected)) == sizeof(expected)) return TRUE;
        }
    }
    return FALSE;
}

static PVOID KswBandRoutine(const KSW_RUNTIME_IMAGE_VIEW* Image, ULONG Rva, const UCHAR* Bytes, SIZE_T Length)
{
    UCHAR actual[32];
    const ULONG_PTR address = Image->Base + Rva;
    if (Length > sizeof(actual) || !KswordARKRuntimeAddressIsExecutable(Image, address, Length) ||
        !KswBandRead(address, actual, Length) || RtlCompareMemory(actual, Bytes, Length) != Length) return NULL;
    return (PVOID)address;
}

static NTSTATUS KswBandResolve(KSW_BAND_RUNTIME* Runtime)
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* modules = NULL;
    KSW_HOOK_SYSTEM_MODULE_ENTRY full, base;
    KSW_RUNTIME_IMAGE_VIEW image;
    ULONG bytes = 0;
    UNICODE_STRING name;
    NTSTATUS status;
    // Full, position-independent prefixes, backed by exact PE + RSDS identity.
    static const UCHAR begin[] = {0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x8b,0xf9};
    static const UCHAR defer[] = {0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8b,0xec,0x48,0x83,0xec,0x50};
    static const UCHAR end[] = {0x48,0x89,0x5c,0x24,0x10,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xd9,0x48,0x81,0xec,0xc0,0,0,0};
    static const UCHAR lock[] = {0x48,0x83,0xec,0x28,0x48,0x8b,0x81,0xc8,1,0,0,0x49,0x89,0,0x4c,0x89,0x81,0xc8,1,0,0};
    static const UCHAR unlock[] = {0x48,0x83,0xec,0x38,0x4c,0x8b,0x81,0xc8,1,0,0,0x4c,0x3b,0xc2,0x75,0x20};
    static const UCHAR owner[] = {0x48,0x83,0xec,0x28,0x4c,0x8b,0xc1,0xe8,0x6c,0xfa,0xff,0xff,0x48,0x85,0xc0,0x75,0x09};
    RtlZeroMemory(Runtime, sizeof(*Runtime));
    status = KswordARKHookBuildModuleSnapshot(&modules, &bytes);
    if (!NT_SUCCESS(status)) return status;
    if (!KswordARKWin32kFindModuleByName(modules, "win32kfull.sys", &full) ||
        !KswordARKWin32kFindModuleByName(modules, "win32kbase.sys", &base)) {
        ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
        return STATUS_NOT_FOUND;
    }
    ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
    if (!KswBandExactImage(full.ImageBase, full.ImageSize) ||
        !KswordARKRuntimeInitializeImageView(full.ImageBase, full.ImageSize, &image)) return STATUS_REVISION_MISMATCH;
    Runtime->Begin = (KSW_BAND_BEGIN)KswBandRoutine(&image, 0x980D0, begin, sizeof(begin));
    Runtime->Defer = (KSW_BAND_DEFER)KswBandRoutine(&image, 0x98894, defer, sizeof(defer));
    Runtime->End = (KSW_BAND_END)KswBandRoutine(&image, 0x9731C, end, sizeof(end));
    Runtime->Lock = (KSW_BAND_LOCK)KswBandRoutine(&image, 0x26DE0, lock, sizeof(lock));
    Runtime->Unlock = (KSW_BAND_UNLOCK)KswBandRoutine(&image, 0x26170, unlock, sizeof(unlock));
    Runtime->RootOwner = (KSW_BAND_ROOT_OWNER)KswBandRoutine(&image, 0x742B8, owner, sizeof(owner));
    Runtime->Enter = (KSW_BAND_ENTER)RtlFindExportedRoutineByName(base.ImageBase, "EnterCrit");
    Runtime->Leave = (KSW_BAND_LEAVE)RtlFindExportedRoutineByName(base.ImageBase, "UserSessionSwitchLeaveCrit");
    Runtime->Validate = (KSW_BAND_VALIDATE)RtlFindExportedRoutineByName(base.ImageBase, "ValidateHwnd");
    RtlInitUnicodeString(&name, L"PsGetProcessCreateTimeQuadPart");
    Runtime->CreateTime = (KSW_BAND_CREATE_TIME)MmGetSystemRoutineAddress(&name);
    if (!Runtime->Begin || !Runtime->Defer || !Runtime->End || !Runtime->Lock || !Runtime->Unlock ||
        !Runtime->Enter || !Runtime->Leave || !Runtime->Validate || !Runtime->RootOwner || !Runtime->CreateTime)
        return STATUS_NOT_SUPPORTED;
    // The base exports must also resolve to executable code in the loaded base.
    if (!KswordARKRuntimeInitializeImageView(base.ImageBase, base.ImageSize, &image) ||
        !KswordARKRuntimeAddressIsExecutable(&image, (ULONG_PTR)Runtime->Enter, 1) ||
        !KswordARKRuntimeAddressIsExecutable(&image, (ULONG_PTR)Runtime->Leave, 1) ||
        !KswordARKRuntimeAddressIsExecutable(&image, (ULONG_PTR)Runtime->Validate, 1)) return STATUS_REVISION_MISMATCH;
    return STATUS_SUCCESS;
}

static BOOLEAN KswBandAllowed(ULONG Band) { return Band == 1 || Band == 2; }

// These six private routines are absent from this exact image's GFIDS table.
// Keep the CFG exception confined to wrappers fed only by KswBandResolve's
// exact, kernel-stack-local bindings. Never accept a call address from R3.
__declspec(noinline) __declspec(guard(nocf))
static PVOID KswBandRoot(KSW_BAND_RUNTIME* R, PVOID Window)
{ return R->RootOwner(Window); }

__declspec(noinline) __declspec(guard(nocf))
static VOID KswBandLockWindow(KSW_BAND_RUNTIME* R, PVOID Pti, PVOID Window, PVOID Lock)
{ R->Lock(Pti, Window, Lock); }

__declspec(noinline) __declspec(guard(nocf))
static VOID KswBandUnlockWindow(KSW_BAND_RUNTIME* R, PVOID Pti, PVOID Lock)
{ R->Unlock(Pti, Lock); }

// Require a top-level target with no owned popup group on the selected desktop.
// The native transaction is responsible for the complete sibling-chain update.
static BOOLEAN KswBandTarget(KSW_BAND_RUNTIME* R, PVOID Window, const KSW_BAND_VIEW* V)
{
    ULONG_PTR deskInfo, desktopWindow;
    if (!KswBandAllowed(V->Band) || KswBandRoot(R, Window) != Window ||
        !KswBandRead(V->Desktop + 8, &deskInfo, sizeof(deskInfo)) ||
        !KswBandRead(deskInfo + 0x18, &desktopWindow, sizeof(desktopWindow)) ||
        V->Parent != desktopWindow) return FALSE;
    // The old implementation treated an undocumented THREADINFO slot as a
    // CoreWindow marker. That slot is not part of the validated profile and is
    // populated for ordinary active threads, which rejected normal Explorer
    // windows with STATUS_NOT_SUPPORTED. Root-owner and desktop-parent checks
    // still exclude owned groups and non-desktop windows without guessing at a
    // private THREADINFO field.
    return TRUE;
}

__declspec(noinline) __declspec(guard(nocf))
static BOOLEAN KswBandCommit(KSW_BAND_RUNTIME* R, PVOID Window, ULONG Band, ULONG Position)
{
    PVOID transaction = R->Begin(1);
    if (!transaction) return FALSE;
    // 0x60000 is the native band-change transaction mask; the other flags are
    // SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE, as in xxxSetWindowBand.
    transaction = R->Defer(transaction, Window, Position == KSW_BAND_BOTTOM ? (PVOID)1 : NULL,
        0, 0, 0, 0, 0x60013, Band);
    // _DeferWindowPos destroys the transaction itself on allocation failure.
    if (!transaction) return FALSE;
    // Synchronous commit: verify the actual chain before acknowledging success.
    // End owns/frees SMWP; it can return TRUE even for a discarded transaction.
    return R->End(transaction, 0) != 0;
}

static BOOLEAN KswBandPosition(KSW_BAND_RUNTIME* R, PVOID Window, ULONG Band, ULONG Position)
{
    KSW_BAND_VIEW view, adjacent;
    ULONG_PTR node;
    if (!KswBandView(Window, &view) || view.Band != Band) return FALSE;
    node = Position == KSW_BAND_BOTTOM ? view.Next : view.Previous;
    if (!node) return TRUE;
    if (!KswBandView((PVOID)node, &adjacent) || R->Validate((PVOID)adjacent.Handle) != (PVOID)node ||
        adjacent.Parent != view.Parent ||
        (Position == KSW_BAND_BOTTOM ? adjacent.Previous : adjacent.Next) != (ULONG_PTR)Window) return FALSE;
    return adjacent.Band != Band;
}

NTSTATUS KswordARKWindowBandIoctl(WDFDEVICE Device, WDFREQUEST Request,
    size_t InputLength, size_t OutputLength, size_t* BytesReturned)
{
    KSWORD_ARK_WINDOW_BAND_REQUEST* input;
    KSWORD_ARK_WINDOW_BAND_REQUEST q;
    KSWORD_ARK_WINDOW_BAND_RESPONSE* out;
    KSW_BAND_RUNTIME runtime;
    KSW_BAND_VIEW view, caller, after;
    PVOID target = NULL, pti = NULL;
    PETHREAD thread = NULL;
    ULONG_PTR threadPointer = 0, targetLock[2];
    BOOLEAN entered = FALSE, locked = FALSE;
    NTSTATUS status;
    size_t bytes;
    KSWORD_WIN32K_PS_GET_THREAD_WIN32_THREAD_FN getGuiThread;
    UNREFERENCED_PARAMETER(InputLength); UNREFERENCED_PARAMETER(OutputLength);
    *BytesReturned = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || WdfRequestGetRequestorMode(Request) != UserMode)
        return STATUS_INVALID_DEVICE_STATE;
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) return status;
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(q), (PVOID*)&input, &bytes);
    if (!NT_SUCCESS(status)) return status;
    RtlCopyMemory(&q, input, sizeof(q)); // METHOD_BUFFERED input/output may alias.
    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(*out), (PVOID*)&out, &bytes);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(out, sizeof(*out));
    out->size = sizeof(*out); out->version = KSWORD_ARK_WINDOW_BAND_VERSION;
    out->lastStatus = STATUS_INVALID_PARAMETER; *BytesReturned = sizeof(*out);
    if (q.size != sizeof(q) || q.version != KSWORD_ARK_WINDOW_BAND_VERSION || q.reserved ||
        q.operation > KSW_BAND_SET || q.position > KSW_BAND_BOTTOM ||
        (q.operation == KSW_BAND_SET && (q.confirmation != KSW_BAND_CONFIRMED ||
            !q.expectedObject || !KswBandAllowed(q.expectedBand) || !KswBandAllowed(q.newBand)))) return STATUS_SUCCESS;
    status = KswBandResolve(&runtime);
    if (!NT_SUCCESS(status)) { out->lastStatus = status; return STATUS_SUCCESS; }
    out->imageTimeDateStamp = 0x5CD0A4AF; out->imageSize = 0x428000;
    if (q.operation == KSW_BAND_PROBE) {
        out->lastStatus = STATUS_SUCCESS; out->flags = KSW_BAND_VERIFIED; return STATUS_SUCCESS;
    }
    if (!q.hwnd || !q.callerHwnd || !q.processCreated || !q.processId || !q.threadId) return STATUS_SUCCESS;
    getGuiThread = KswordARKWin32kResolvePsGetThreadWin32Thread();
    if (!getGuiThread || !getGuiThread(PsGetCurrentThread()) || KeAreAllApcsDisabled()) {
        out->lastStatus = STATUS_INVALID_DEVICE_STATE; return STATUS_SUCCESS;
    }
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)q.threadId, &thread);
    if (!NT_SUCCESS(status)) { out->lastStatus = status; return STATUS_SUCCESS; }
    if ((ULONG_PTR)PsGetThreadProcessId(thread) != q.processId ||
        runtime.CreateTime(IoThreadToProcess(thread)) != q.processCreated ||
        PsIsThreadTerminating(thread)) { status = STATUS_INVALID_CID; goto done; }
    if (q.operation == KSW_BAND_SET) {
        KSWORD_ARK_SAFETY_CONTEXT safety = {0};
        safety.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safety.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safety.TargetText = L"win32k native window band transaction";
        safety.TargetTextChars = RTL_NUMBER_OF(L"win32k native window band transaction") - 1;
        status = KswordARKSafetyEvaluate(Device, &safety);
        if (!NT_SUCCESS(status)) goto done;
    }
    __try {
        pti = runtime.Enter(0, 1); entered = TRUE;
        target = runtime.Validate((PVOID)(ULONG_PTR)q.hwnd);
        if (!pti || !target || !KswBandView(target, &view) ||
            !KswBandView(runtime.Validate((PVOID)(ULONG_PTR)q.callerHwnd), &caller) ||
            caller.ThreadInfo != (ULONG_PTR)pti || caller.Desktop != view.Desktop ||
            !KswBandRead(view.ThreadInfo, &threadPointer, sizeof(threadPointer)) || threadPointer != (ULONG_PTR)thread ||
            !KswBandTarget(&runtime, target, &view)) { status = STATUS_NOT_SUPPORTED; __leave; }
        out->windowObject = (ULONG64)(ULONG_PTR)target;
        out->previousBand = out->currentBand = view.Band;
        if (q.operation == KSW_BAND_QUERY) {
            out->flags = KSW_BAND_VERIFIED;
            if (KswBandPosition(&runtime, target, view.Band, q.position)) out->flags |= KSW_BAND_POSITION_VERIFIED;
            status = STATUS_SUCCESS; __leave;
        }
        if ((ULONG64)(ULONG_PTR)target != q.expectedObject || view.Band != q.expectedBand) {
            status = STATUS_REVISION_MISMATCH; __leave;
        }
        KswBandLockWindow(&runtime, pti, target, targetLock); locked = TRUE;
        if (KswBandCommit(&runtime, target, q.newBand, q.position) &&
            runtime.Validate((PVOID)(ULONG_PTR)q.hwnd) == target &&
            KswBandPosition(&runtime, target, q.newBand, q.position)) {
            out->currentBand = q.newBand;
            out->flags = KSW_BAND_VERIFIED | KSW_BAND_CHANGED | KSW_BAND_POSITION_VERIFIED; status = STATUS_SUCCESS;
        } else {
            status = STATUS_UNSUCCESSFUL;
            // Revalidate after native callbacks, which can destroy the target.
            if (runtime.Validate((PVOID)(ULONG_PTR)q.hwnd) == target && KswBandView(target, &after)) {
                out->currentBand = after.Band;
                if (after.Band != view.Band) {
                    out->flags |= KSW_BAND_CHANGED;
                    if (KswBandCommit(&runtime, target, view.Band, KSW_BAND_TOP) &&
                        runtime.Validate((PVOID)(ULONG_PTR)q.hwnd) == target &&
                        KswBandView(target, &after) && after.Band == view.Band) {
                        out->currentBand = after.Band;
                        out->flags |= KSW_BAND_ROLLED_BACK;
                    }
                }
            }
        }
    } __finally {
        if (locked) KswBandUnlockWindow(&runtime, pti, targetLock);
        if (entered) runtime.Leave();
    }
done:
    ObDereferenceObject(thread);
    out->lastStatus = status;
    return STATUS_SUCCESS;
}
