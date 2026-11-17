#!/usr/bin/env python3
"""Compile the production candidate-reference functions against safe API mocks.

This offline regression never loads the driver. Invalid candidate addresses are
opaque sentinels: the mocked object-manager API rejects any access unless an
ID lookup has already supplied a reference to that exact address.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid


ROOT = Path(__file__).resolve().parents[1]


def function(source_path: str, name: str) -> str:
    text = (ROOT / source_path).read_text(encoding="utf-8-sig")
    signature = re.search(rf"(?m)^(?:static\s+)?(?:NTSTATUS|VOID|BOOLEAN|LONG|ULONG|PVOID)\s+{re.escape(name)}\(", text)
    if signature is None:
        raise ValueError(f"Production function unavailable: {name}")
    start = signature.start()
    body_start = text.index("\n{", signature.end()) + 1
    depth = 0
    for index in range(body_start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise ValueError(f"Unterminated production function: {name}")


HARNESS = r"""
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_
using NTSTATUS = int;
using VOID = void;
using BOOLEAN = bool;
using PVOID = void*;
using HANDLE = void*;
using ULONG_PTR = uintptr_t;
using PEPROCESS = void*;
using PETHREAD = void*;
using ULONG = unsigned long;
using PUCHAR = unsigned char*;
struct Type {};
using POBJECT_TYPE = Type*;
constexpr BOOLEAN TRUE = true, FALSE = false;
constexpr NTSTATUS STATUS_SUCCESS = 0, STATUS_INVALID_PARAMETER = -1;
constexpr NTSTATUS STATUS_INVALID_DEVICE_STATE = -2, STATUS_OBJECT_TYPE_MISMATCH = -3;
constexpr NTSTATUS STATUS_DATA_ERROR = -4, STATUS_REVISION_MISMATCH = -5;
constexpr NTSTATUS STATUS_INVALID_CID = -6;
constexpr NTSTATUS STATUS_PROCEDURE_NOT_FOUND = -7, STATUS_BUFFER_OVERFLOW = -8;
constexpr NTSTATUS STATUS_DATATYPE_MISALIGNMENT = -9;
constexpr NTSTATUS STATUS_PARTIAL_COPY = -10;
constexpr int APC_LEVEL = 1;
#define NT_SUCCESS(status) ((status) >= 0)
static Type processType, threadType, otherType;
static POBJECT_TYPE processTypePointer = &processType, threadTypePointer = &threadType;
static POBJECT_TYPE* PsProcessType = &processTypePointer;
static POBJECT_TYPE* PsThreadType = &threadTypePointer;
static PVOID lookupObject, lastLookupObject;
static POBJECT_TYPE actualType;
static NTSTATUS lookupStatus;
static int currentIrql, lookupCalls, typeCalls, dereferenceCalls, ownedReferences, cases;
static HANDLE lastLookupId;
struct LIST_ENTRY { LIST_ENTRY* Flink; LIST_ENTRY* Blink; };
struct FixtureProcess { HANDLE id; LIST_ENTRY links; };
static FixtureProcess headProcess, nodeProcess;
static PEPROCESS PsInitialSystemProcess = &headProcess;
static bool listMode;
static int KeGetCurrentIrql() { return currentIrql; }
static NTSTATUS lookup(HANDLE id, PVOID* out) {
    if (listMode) lookupObject = id == headProcess.id ? &headProcess : &nodeProcess;
    ++lookupCalls;
    lastLookupId = id;
    *out = NT_SUCCESS(lookupStatus) ? lookupObject : nullptr;
    if (*out != nullptr) { ++ownedReferences; lastLookupObject = *out; }
    return lookupStatus;
}
static NTSTATUS PsLookupProcessByProcessId(HANDLE id, PEPROCESS* out) { return lookup(id, out); }
static NTSTATUS PsLookupThreadByThreadId(HANDLE id, PETHREAD* out) { return lookup(id, out); }
static POBJECT_TYPE ObGetObjectType(PVOID object) {
    assert(ownedReferences > 0 && object == lastLookupObject);
    ++typeCalls;
    return actualType;
}
static void ObDereferenceObject(PVOID object) {
    assert(ownedReferences > 0 && object == lastLookupObject);
    --ownedReferences;
    ++dereferenceCalls;
}
static BOOLEAN KswordARKCrossViewPointerAligned(ULONG_PTR address) {
    return address != 0 && (address & 7U) == 0;
}
struct KSW_DYN_STATE { struct { ULONG EpActiveProcessLinks, EpUniqueProcessId; ULONG KtProcess = 0xFFFFFFFFUL; } Kernel; };
struct KSW_CROSSVIEW_VISITED_SET { std::set<ULONG_PTR>* addresses; };
#define RtlZeroMemory(target, bytes) std::memset(target, 0, bytes)
static bool KswordARKCrossViewOffsetPresent(ULONG offset) { return offset != 0xFFFFFFFFUL; }
static NTSTATUS KswordARKCrossViewVisitedInitialize(KSW_CROSSVIEW_VISITED_SET* state, ULONG) {
    state->addresses = new std::set<ULONG_PTR>; return STATUS_SUCCESS;
}
static void KswordARKCrossViewVisitedDestroy(KSW_CROSSVIEW_VISITED_SET* state) { delete state->addresses; }
static bool KswordARKCrossViewVisitedCheckAndAdd(KSW_CROSSVIEW_VISITED_SET* state, ULONG_PTR address) {
    return !state->addresses->insert(address).second;
}
static NTSTATUS KswordARKCrossViewReadPointerAddress(const void* address, PVOID* out) {
    std::memcpy(out, address, sizeof(*out)); return STATUS_SUCCESS;
}
static NTSTATUS KswordARKCrossViewReadPointerField(const void* object, ULONG offset, PVOID* out) {
    return KswordARKCrossViewReadPointerAddress(static_cast<const unsigned char*>(object) + offset, out);
}
static HANDLE PsGetProcessId(PEPROCESS object) { assert(object == &headProcess); return headProcess.id; }
struct KSW_CROSSVIEW_CID_ENTRY {
    PVOID Object; std::uint64_t ObjectAddress; ULONG CidValue;
    BOOLEAN Referenced, TypeMatched; NTSTATUS ReferenceStatus; std::uint64_t ObservedOwnerAddress;
};
using CidCallback = void(*)(const KSW_CROSSVIEW_CID_ENTRY*, PVOID);
struct KSW_CROSSVIEW_CID_WALK_CONTEXT {
    POBJECT_TYPE ExpectedObjectType; NTSTATUS LastStatus; CidCallback Callback;
    PVOID CallbackContext; ULONG ReportedEntries; const KSW_DYN_STATE* DynState = nullptr;
};
using ULONG64 = std::uint64_t;
using ULONGLONG = std::uint64_t;
using UCHAR = unsigned char;
#define KSW_DYN_OFFSET_UNAVAILABLE 0xFFFFFFFFUL
struct DISPATCHER_HEADER { UCHAR Type; int SignalState; };
static DISPATCHER_HEADER observedHeader{};
static bool dispatcherReadable;
static int threadAnchor;
static UCHAR processDispatcherKind = 3, threadDispatcherKind = 6;
static PVOID observedOwner = reinterpret_cast<PVOID>(uintptr_t(0xFFFF90000000A000ULL));
static bool ownerReadable;
static PVOID KeGetCurrentThread() { return &threadAnchor; }
static bool KswordARKRuntimeReadMemory(PVOID object, PVOID out, size_t bytes) {
    if (object == PsInitialSystemProcess) { std::memcpy(out, &processDispatcherKind, bytes); return true; }
    if (object == &threadAnchor) { std::memcpy(out, &threadDispatcherKind, bytes); return true; }
    if (reinterpret_cast<uintptr_t>(object) == uintptr_t(0xFFFF900000008020ULL)) {
        if (!ownerReadable) return false;
        std::memcpy(out, &observedOwner, bytes); return true;
    }
    if (!dispatcherReadable) return false;
    std::memcpy(out, &observedHeader, bytes); return true;
}
using LONGLONG = std::int64_t;
static PVOID MmSystemRangeStart = reinterpret_cast<PVOID>(uintptr_t(0xFFFF800000000000ULL));
static NTSTATUS KswordARKCrossViewReadUlong64Address(const void* address, ULONGLONG* out) { std::memcpy(out, address, sizeof(*out)); return STATUS_SUCCESS; }
#define ULongToHandle(value) reinterpret_cast<HANDLE>(uintptr_t(value))
constexpr ULONG KSWORD_ARK_PROCESS_EXIT_CID_THREADS_QUIET = 128;
struct LifeRow { std::uint64_t processObjectAddress; ULONG exitEvidence; };
using KSWORD_ARK_PROCESS_ENTRY = LifeRow;
struct KSWORD_ARK_ENUM_PROCESS_RESPONSE { ULONG returnedCount; LifeRow entries[2]; };
struct KSW_LIFE_CID_CONTEXT { KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response; };
static NTSTATUS threadWait;
static PVOID threadOwner;
static NTSTATUS KswLifePoll(PVOID) { return threadWait; }
static PVOID PsGetThreadProcess(PETHREAD) { return threadOwner; }
/*PRODUCTION*/
using Wrapper = NTSTATUS(*)(PVOID, HANDLE, POBJECT_TYPE, BOOLEAN*, BOOLEAN*);
static PVOID candidate = reinterpret_cast<PVOID>(uintptr_t(0xFFFF900000008000ULL));
static HANDLE candidateId = reinterpret_cast<HANDLE>(uintptr_t(88));
static void reset(POBJECT_TYPE type) {
    lookupObject = candidate;
    lastLookupObject = nullptr;
    actualType = type;
    lookupStatus = STATUS_SUCCESS;
    currentIrql = lookupCalls = typeCalls = dereferenceCalls = ownedReferences = 0;
    lastLookupId = nullptr;
}
static void expect(Wrapper wrapper, PVOID object, HANDLE id, POBJECT_TYPE type,
                   NTSTATUS status, int expectedLookups, int expectedTypes, int expectedDerefs) {
    BOOLEAN typeMatched = true, referenced = true;
    assert(wrapper(object, id, type, &typeMatched, &referenced) == status);
    assert(typeMatched == NT_SUCCESS(status) && referenced == NT_SUCCESS(status));
    assert(lookupCalls == expectedLookups && typeCalls == expectedTypes);
    assert(dereferenceCalls == expectedDerefs);
    if (NT_SUCCESS(status)) {
        assert(lastLookupId == id && ownedReferences == 1);
        ObDereferenceObject(object);
    }
    assert(ownedReferences == 0);
    ++cases;
}
static void run(Wrapper wrapper, POBJECT_TYPE type) {
    reset(type);
    expect(wrapper, candidate, candidateId, type, STATUS_SUCCESS, 1, 1, 0);
    reset(type); lookupStatus = STATUS_INVALID_CID;
    expect(wrapper, candidate, candidateId, type, STATUS_INVALID_CID, 1, 0, 0);
    reset(type); lookupObject = reinterpret_cast<PVOID>(uintptr_t(0xFFFF900000009000ULL));
    expect(wrapper, candidate, candidateId, type, STATUS_REVISION_MISMATCH, 1, 0, 1);
    reset(type); actualType = &otherType;
    expect(wrapper, candidate, candidateId, type, STATUS_OBJECT_TYPE_MISMATCH, 1, 1, 1);
    reset(type); currentIrql = APC_LEVEL + 1;
    expect(wrapper, candidate, candidateId, type, STATUS_INVALID_DEVICE_STATE, 0, 0, 0);
    reset(type);
    expect(wrapper, nullptr, candidateId, type, STATUS_INVALID_PARAMETER, 0, 0, 0);
    reset(type);
    expect(wrapper, candidate, nullptr, type, STATUS_INVALID_PARAMETER, 0, 0, 0);
    reset(type);
    expect(wrapper, candidate, candidateId, nullptr, STATUS_INVALID_PARAMETER, 0, 0, 0);
    reset(type);
    expect(wrapper, reinterpret_cast<PVOID>(uintptr_t(3)), candidateId, type, STATUS_INVALID_PARAMETER, 0, 0, 0);
    reset(type); lookupObject = nullptr;
    expect(wrapper, candidate, candidateId, type, STATUS_DATA_ERROR, 1, 0, 0);
    reset(type);
    expect(wrapper, candidate, candidateId, &otherType, STATUS_OBJECT_TYPE_MISMATCH, 0, 0, 0);
    reset(type); BOOLEAN out = true;
    assert(wrapper(candidate, candidateId, type, nullptr, &out) == STATUS_INVALID_PARAMETER);
    assert(lookupCalls == 0 && typeCalls == 0); ++cases;
    reset(type);
    assert(wrapper(candidate, candidateId, type, &out, nullptr) == STATUS_INVALID_PARAMETER);
    assert(lookupCalls == 0 && typeCalls == 0); ++cases;
}
static void runActiveList() {
    KSW_DYN_STATE dyn{{offsetof(FixtureProcess, links), offsetof(FixtureProcess, id)}};
    const auto setup = [] {
        reset(&processType); listMode = true;
        headProcess.id = reinterpret_cast<HANDLE>(uintptr_t(4));
        nodeProcess.id = reinterpret_cast<HANDLE>(uintptr_t(88));
        headProcess.links = {&nodeProcess.links, &nodeProcess.links};
        nodeProcess.links = {&headProcess.links, &headProcess.links};
    };
    ULONG visited = 999;
    setup(); headProcess.links = {&headProcess.links, &headProcess.links};
    assert(KswordARKCrossViewValidateActiveProcessLinks(&dyn, 8, &visited) == STATUS_SUCCESS);
    assert(visited == 0 && lastLookupId == headProcess.id && ownedReferences == 0); ++cases;
    setup();
    assert(KswordARKCrossViewValidateActiveProcessLinks(&dyn, 8, &visited) == STATUS_SUCCESS);
    assert(visited == 1 && lastLookupId == nodeProcess.id && ownedReferences == 0); ++cases;
    setup(); nodeProcess.id = nullptr;
    assert(KswordARKCrossViewValidateActiveProcessLinks(&dyn, 8, &visited) == STATUS_INVALID_PARAMETER);
    assert(ownedReferences == 0); ++cases;
    setup(); nodeProcess.links.Blink = &nodeProcess.links;
    assert(KswordARKCrossViewValidateActiveProcessLinks(&dyn, 8, &visited) == STATUS_DATA_ERROR);
    assert(ownedReferences == 0); ++cases;
    setup();
    assert(KswordARKCrossViewValidateActiveProcessLinks(&dyn, 0, &visited) == STATUS_PROCEDURE_NOT_FOUND);
    assert(ownedReferences == 0); ++cases;
    listMode = false;
}
static void runCidCompleteness() {
    const auto callback = [](const KSW_CROSSVIEW_CID_ENTRY* entry, PVOID count) {
        assert(entry->Referenced && entry->TypeMatched && ownedReferences == 1);
        ++*static_cast<int*>(count);
    };
    int reported = 0;
    KSW_CROSSVIEW_CID_WALK_CONTEXT ctx{&threadType, STATUS_SUCCESS, callback, &reported, 0};
    reset(&threadType);
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, nullptr);
    assert(reported == 1 && ctx.LastStatus == STATUS_SUCCESS && ownedReferences == 0); ++cases;
    reported = 0; ctx.ReportedEntries = 0;
    reset(&processType);
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, nullptr);
    assert(reported == 0 && ctx.LastStatus == STATUS_SUCCESS && ownedReferences == 0 && lookupCalls == 2); ++cases;
    reset(&threadType); lookupStatus = STATUS_INVALID_CID;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, nullptr);
    assert(reported == 0 && ctx.LastStatus == STATUS_PARTIAL_COPY && ownedReferences == 0 && typeCalls == 0); ++cases;
    ctx.LastStatus = STATUS_SUCCESS;
    reset(&threadType); lookupObject = reinterpret_cast<PVOID>(uintptr_t(0xFFFF900000009000ULL));
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, nullptr);
    assert(reported == 0 && ctx.LastStatus == STATUS_PARTIAL_COPY && ownedReferences == 0 && typeCalls == 0); ++cases;
    ctx.LastStatus = STATUS_SUCCESS; reset(&threadType); lookupStatus = STATUS_INVALID_CID;
    ULONGLONG emptySlot = 0;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &emptySlot);
    assert(ctx.LastStatus == STATUS_SUCCESS && ownedReferences == 0 && reported == 0); ++cases;
    ULONGLONG freeSlot = 0x1000000001ULL;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &freeSlot);
    assert(ctx.LastStatus == STATUS_SUCCESS && ownedReferences == 0 && reported == 0); ++cases;
    ULONGLONG occupiedSlot = static_cast<ULONGLONG>(reinterpret_cast<uintptr_t>(candidate)) << 16;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_PARTIAL_COPY && ownedReferences == 0 && reported == 0); ++cases;
    dispatcherReadable = true; observedHeader = {3, 0}; ctx.LastStatus = STATUS_SUCCESS;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_SUCCESS && reported == 0 && ownedReferences == 0); ++cases;
    observedHeader = {6, 0};
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_PARTIAL_COPY && reported == 0 && ownedReferences == 0); ++cases;
    observedHeader = {6, 1}; ctx.LastStatus = STATUS_SUCCESS;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_SUCCESS && reported == 0 && ownedReferences == 0); ++cases;
    dispatcherReadable = false;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_PARTIAL_COPY && reported == 0 && ownedReferences == 0); ++cases;
    KSW_DYN_STATE dyn{}; dyn.Kernel.KtProcess = 0x20;
    ctx.DynState = &dyn; ctx.LastStatus = STATUS_SUCCESS;
    ctx.Callback = [](const KSW_CROSSVIEW_CID_ENTRY* entry, PVOID count) {
        assert(!entry->Referenced && !entry->TypeMatched && entry->Object == nullptr);
        assert(entry->ObservedOwnerAddress == reinterpret_cast<uintptr_t>(observedOwner));
        ++*static_cast<int*>(count);
    };
    dispatcherReadable = ownerReadable = true; observedHeader = {6, 0};
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_SUCCESS && reported == 1 && ownedReferences == 0); ++cases;
    reported = 0; ownerReadable = false;
    KswordARKCrossViewReportCidCandidate(&ctx, candidate, 88, STATUS_SUCCESS, &occupiedSlot);
    assert(ctx.LastStatus == STATUS_PARTIAL_COPY && reported == 0 && ownedReferences == 0); ++cases;
}
static void runLifetimeVeto() {
    KSWORD_ARK_ENUM_PROCESS_RESPONSE response{2, {{16, 128}, {32, 128}}};
    KSW_LIFE_CID_CONTEXT ctx{&response};
    KSW_CROSSVIEW_CID_ENTRY entry{}; entry.ObservedOwnerAddress = 16;
    KswLifeCidThread(&entry, &ctx);
    assert(response.entries[0].exitEvidence == 0 && response.entries[1].exitEvidence == 128); ++cases;
    response.entries[0].exitEvidence = 128; entry.ObservedOwnerAddress = 48;
    KswLifeCidThread(&entry, &ctx);
    assert(response.entries[0].exitEvidence == 128 && response.entries[1].exitEvidence == 128); ++cases;
    entry.ObservedOwnerAddress = 0; KswLifeCidThread(&entry, &ctx);
    assert(response.entries[0].exitEvidence == 0 && response.entries[1].exitEvidence == 0); ++cases;
    response.entries[0].exitEvidence = response.entries[1].exitEvidence = 128;
    entry.Referenced = true; entry.Object = candidate; threadWait = 258; threadOwner = reinterpret_cast<PVOID>(uintptr_t(32));
    KswLifeCidThread(&entry, &ctx);
    assert(response.entries[0].exitEvidence == 128 && response.entries[1].exitEvidence == 0); ++cases;
    response.entries[1].exitEvidence = 128; threadWait = STATUS_SUCCESS;
    KswLifeCidThread(&entry, &ctx);
    assert(response.entries[0].exitEvidence == 128 && response.entries[1].exitEvidence == 128); ++cases;
}
int main() {
    run(KswordARKCrossViewTryReferenceTypedObject, &processType);
    run(KswordARKCrossViewTryReferenceTypedObject, &threadType);
    run(KswordARKThreadCrossViewTryReferenceTypedObject, &threadType);
    runActiveList();
    runCidCompleteness();
    runLifetimeVeto();
    std::printf("candidate-reference regression: %d cases passed\n", cases);
}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default="g++", help="C++ compiler path")
    args = parser.parse_args()
    cxx = shutil.which(args.cxx)
    if not cxx:
        raise SystemExit(f"C++ compiler unavailable: {args.cxx}")
    production = "\n\n".join([
        function("KswordARKDriver/src/features/kernel/object_header_fallback.c", "KswordARKObjectHeaderReferenceObjectSafe"),
        function("KswordARKDriver/src/features/process/process_crossview.c", "KswordARKCrossViewTryReferenceTypedObject"),
        function("KswordARKDriver/src/features/thread/thread_crossview.c", "KswordARKThreadCrossViewTryReferenceTypedObject"),
        function("KswordARKDriver/src/features/process/process_crossview.c", "KswordARKCrossViewValidateActiveProcessLinks"),
        function("KswordARKDriver/src/features/process/process_crossview.c", "KswordARKCrossViewDecodeCidEntryObject"),
        function("KswordARKDriver/src/features/process/process_crossview.c", "KswordARKCrossViewCidSlotQuiet"),
        function("KswordARKDriver/src/features/process/process_crossview.c", "KswordARKCrossViewReportCidCandidate"),
        function("KswordARKDriver/src/features/process/process_lifetime.c", "KswLifeCidThread"),
    ])
    environment = os.environ.copy()
    environment["PATH"] = str(Path(cxx).parent) + os.pathsep + environment.get("PATH", "")
    temporary_root = ROOT / ".codex-tmp" / "candidate-reference-tests"
    if not temporary_root.resolve().is_relative_to(ROOT.resolve()):
        raise SystemExit("Regression temporary directory must remain inside the repository.")
    temporary_root.mkdir(parents=True, exist_ok=True)
    temporary = temporary_root / f"case-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        source = temporary / "regression.cpp"
        binary = temporary / ("regression.exe" if os.name == "nt" else "regression")
        source.write_text(HARNESS.replace("/*PRODUCTION*/", production), encoding="utf-8")
        subprocess.run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
                       check=True, env=environment)
        subprocess.run([str(binary)], check=True, env=environment)
    finally:
        if temporary.resolve().is_relative_to(temporary_root.resolve()):
            shutil.rmtree(temporary)


if __name__ == "__main__":
    main()
