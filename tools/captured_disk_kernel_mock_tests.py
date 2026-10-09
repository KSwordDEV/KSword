#!/usr/bin/env python3
"""Strict MSVC regression of production captured-disk code with memory mocks.

Only extracted production business/adapter functions run. All handles, devices,
WDF requests and storage contents are in-process mocks; no driver is loaded and
no physical disk, registry or kernel API is called. Generated source and output
stay in the repository's already-existing .codex-build-logs directory.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STORAGE = ROOT / "KswordARKDriver/src/features/storage"


def function(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8-sig")
    signature = re.search(
        rf"(?m)^(?:static\s+)?(?:NTSTATUS|VOID|BOOLEAN|ULONG|PDEVICE_OBJECT)\s+{re.escape(name)}\(",
        source,
    )
    if signature is None:
        raise ValueError(f"Production function unavailable: {path.name}:{name}")
    start = signature.start()
    opening = source.index("\n{", signature.end()) + 1
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if not depth:
                return source[start:index + 1]
    raise ValueError(f"Unterminated production function: {name}")


def structure(path: Path, name: str) -> str:
    source = path.read_text(encoding="utf-8-sig")
    match = re.search(rf"typedef struct _{name}\b.*?\}}[^;]+;", source, re.DOTALL)
    if match is None:
        raise ValueError(f"Production structure unavailable: {path}:{name}")
    return match.group()


HARNESS = r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define WIN32_NO_STATUS
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <algorithm>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <limits>
#include <map>
#include <vector>
#include "driver/KswordArkStorageForensicsIoctl.h"
#include "driver/KswordArkSafetyIoctl.h"
using NTSTATUS = LONG;
using std::min;
#define NT_SUCCESS(value) ((value) >= 0)
#define ALIGN_UP_BY(value, alignment) (((value) + (alignment) - 1) & ~((ULONG_PTR)(alignment) - 1))
#ifndef MAXULONG
#define MAXULONG 0xffffffffUL
#endif
// 这些句柄选项来自WDK契约；仅供离线调用生产选择函数。
#ifndef FILE_WRITE_THROUGH
#define FILE_WRITE_THROUGH 0x00000002UL
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif
// The SDK declares an imported RtlCompareMemory; redirect only this mock TU.
#define RtlCompareMemory mockCompareMemory
constexpr UCHAR IRP_MJ_READ = 3, IRP_MJ_WRITE = 4;
constexpr ULONG KSW_STORAGE_FORENSICS_POOL_TAG = 0x6672534bUL;
constexpr ULONG KSW_STORAGE_FORENSICS_IOCTL_POOL_TAG = 0x6966534bUL;
struct IO_STATUS_BLOCK { NTSTATUS Status; ULONG_PTR Information; };
struct Disk;
struct FakeDevice { Disk* owner; ULONG backend; };
using PDEVICE_OBJECT = FakeDevice*;
using PFILE_OBJECT = Disk*;
using WDFDEVICE = void*;
/*CONTEXT*/
/*SAFETY_CONTEXT*/
/*OPEN_OPTIONS*/
struct Disk {
    GUID guid = {};
    std::vector<UCHAR> bytes;
    FakeDevice port{this, KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT};
    FakeDevice controller{this, KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER};
    ULONG number = 0;
    ULONG caps = KSWORD_ARK_RAW_DISK_CAP_CONTROLLER | KSWORD_ARK_RAW_DISK_CAP_OFFLINE;
};
struct FakeRequest {
    std::vector<UCHAR> buffer;
    size_t inputLength, outputLength;
    explicit FakeRequest(const std::vector<UCHAR>& input, size_t output)
        : buffer(std::max(input.size(), output) + 32, 0xCD),
          inputLength(input.size()), outputLength(output) {
        std::copy(input.begin(), input.end(), buffer.begin());
    }
};
using WDFREQUEST = FakeRequest*;
static Disk diskA, diskB;
static Disk* diskMap;
static bool swapOnIdentity, shortRead, shortWrite, denySafety, failPool;
// 完成量异常与部分失败都只改变内存端口，不访问真实设备。
static bool oversizedRead, oversizedWrite, partialReadFailure, partialWriteFailure;
static NTSTATUS identityStatus, readStatus, writeStatus, openStatus;
static ULONG identityBytes, identityVersion, identitySize, identityType;
static bool zeroIdentity;
static unsigned opens, releases, reads, writeAttempts, writes, guidQueries, safetyCalls;
static unsigned assertions, scenarios;
static std::map<PVOID, ULONG> pools;
static Disk* lastReadDisk;
static Disk* lastWriteDisk;
static ULONG lastReadBackend, lastWriteBackend;
static ULONG lastOpenOptions;
static bool lastWriteFua;
static void require(bool condition, const char* message) {
    ++assertions;
    if (!condition) { std::fprintf(stderr, "FAIL: %s\n", message); std::abort(); }
}
static SIZE_T RtlCompareMemory(const void* left, const void* right, SIZE_T size) {
    return std::memcmp(left, right, size) == 0 ? size : 0;
}
static NTSTATUS RtlStringCchPrintfW(WCHAR* output, size_t size, const WCHAR* format, ...) {
    va_list args; va_start(args, format);
    const int result = vswprintf_s(output, size, format, args);
    va_end(args); return result >= 0 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
static NTSTATUS RtlStringCchLengthW(const WCHAR* text, size_t bound, size_t* out) {
    *out = wcsnlen_s(text, bound);
    return *out < bound ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
static PVOID KswordARKAllocateNonPagedPool(SIZE_T size, ULONG tag) {
    if (failPool) return nullptr;
    auto* result = new UCHAR[size]; pools.emplace(result, tag); return result;
}
static void ExFreePoolWithTag(PVOID block, ULONG tag) {
    require(pools.contains(block) && pools.at(block) == tag, "pool owner/tag retained");
    pools.erase(block); delete[] static_cast<UCHAR*>(block);
}
static NTSTATUS KswordStorageOpenContext(ULONG number, ACCESS_MASK access, BOOLEAN fua,
    KSW_STORAGE_DISK_CONTEXT* out) {
    ++opens; std::memset(out, 0, sizeof(*out));
    lastOpenOptions = KswordStorageOpenOptions(access, fua);
    if (!NT_SUCCESS(openStatus)) return openStatus;
    require(number == 0 && diskMap != nullptr, "mock only resolves the declared disk number");
    out->Handle = diskMap; out->FileObject = diskMap;
    out->NamedDevice = out->TopDevice = out->PortDevice = &diskMap->port;
    out->ControllerDevice = &diskMap->controller;
    out->LogicalSectorSize = out->PhysicalSectorSize = 512;
    out->DiskSizeBytes = diskMap->bytes.size(); out->CapabilityFlags = diskMap->caps;
    return STATUS_SUCCESS;
}
static void KswordStorageReleaseContext(KSW_STORAGE_DISK_CONTEXT* context) {
    require(context->Handle != nullptr, "context released exactly once");
    ++releases; std::memset(context, 0, sizeof(*context));
}
static NTSTATUS KswordStorageSendHandleIoctl(HANDLE handle, ULONG code, PVOID input,
    ULONG inputSize, PVOID output, ULONG outputSize, PULONG_PTR count) {
    require(code == IOCTL_STORAGE_GET_DEVICE_NUMBER_EX && input == nullptr && inputSize == 0,
        "identity query is the documented storage IOCTL");
    require(outputSize == sizeof(STORAGE_DEVICE_NUMBER_EX), "identity uses actual SDK layout");
    auto* disk = static_cast<Disk*>(handle);
    require(disk == &diskA || disk == &diskB, "identity query uses captured handle");
    ++guidQueries;
    auto* identity = static_cast<STORAGE_DEVICE_NUMBER_EX*>(output);
    std::memset(identity, 0, sizeof(*identity));
    identity->Version = identityVersion; identity->Size = identitySize;
    identity->DeviceType = identityType; identity->DeviceNumber = disk->number;
    if (!zeroIdentity) identity->DeviceGuid = disk->guid;
    *count = identityBytes;
    if (swapOnIdentity) diskMap = &diskB;
    return identityStatus;
}
static NTSTATUS readMemory(Disk* disk, ULONG backend, ULONGLONG offset, PVOID buffer,
    ULONG length, ULONG_PTR* completed) {
    ++reads; lastReadDisk = disk; lastReadBackend = backend;
    require(offset + length <= disk->bytes.size(), "mock read has validated range");
    *completed = NT_SUCCESS(readStatus)
        ? (oversizedRead ? length + 1U : shortRead ? length - 1U : length)
        : partialReadFailure ? length / 2U : 0U;
    // 异常回执不得让夹具本身越界；实际拷贝仍严格限于请求范围。
    if (*completed) std::memcpy(buffer, disk->bytes.data() + offset,
        min(*completed, static_cast<ULONG_PTR>(length)));
    return readStatus;
}
static NTSTATUS writeMemory(Disk* disk, ULONG backend, ULONGLONG offset, PVOID buffer,
    ULONG length, ULONG_PTR* completed, bool fua) {
    ++writeAttempts; lastWriteDisk = disk; lastWriteBackend = backend; lastWriteFua = fua;
    require(offset + length <= disk->bytes.size(), "mock write has validated range");
    *completed = NT_SUCCESS(writeStatus)
        ? (oversizedWrite ? length + 1U : shortWrite ? length - 1U : length)
        : partialWriteFailure ? length / 2U : 0U;
    // 常规短写/失败用于检查调度回执；显式部分失败另外模拟已发生的字节修改。
    if (NT_SUCCESS(writeStatus) && !shortWrite && !oversizedWrite) {
        std::memcpy(disk->bytes.data() + offset, buffer, length); ++writes;
    }
    if (!NT_SUCCESS(writeStatus) && partialWriteFailure)
        std::memcpy(disk->bytes.data() + offset, buffer, *completed);
    return writeStatus;
}
static NTSTATUS ZwReadFile(HANDLE handle, PVOID, PVOID, PVOID, IO_STATUS_BLOCK* io,
    PVOID buffer, ULONG length, LARGE_INTEGER* offset, PVOID) {
    io->Status = readMemory(static_cast<Disk*>(handle), KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK,
        static_cast<ULONGLONG>(offset->QuadPart), buffer, length, &io->Information);
    return io->Status;
}
static NTSTATUS ZwWriteFile(HANDLE handle, PVOID, PVOID, PVOID, IO_STATUS_BLOCK* io,
    PVOID buffer, ULONG length, LARGE_INTEGER* offset, PVOID) {
    io->Status = writeMemory(static_cast<Disk*>(handle), KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK,
        static_cast<ULONGLONG>(offset->QuadPart), buffer, length, &io->Information, false);
    return io->Status;
}
/*SELECT_BACKEND*/
// 下层读写执行真实生产函数；只模拟IRP创建和完成API，覆盖共享完成量校验。
struct KEVENT { bool signaled = false; };
struct IO_STACK_LOCATION { UCHAR Flags = 0; };
using PIO_STACK_LOCATION = IO_STACK_LOCATION*;
struct FakeIrp {
    UCHAR major;
    PDEVICE_OBJECT device;
    PVOID buffer;
    ULONG length;
    ULONGLONG offset;
    KEVENT* completion;
    IO_STATUS_BLOCK* status;
    IO_STACK_LOCATION stack;
};
using PIRP = FakeIrp*;
constexpr int NotificationEvent = 0, Executive = 0, KernelMode = 0;
constexpr UCHAR SL_OVERRIDE_VERIFY_VOLUME = 1, SL_WRITE_THROUGH = 2;
constexpr LONGLONG KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS = -300000000LL;
static void KeInitializeEvent(KEVENT* event, int, BOOLEAN signaled) {
    event->signaled = signaled != FALSE;
}
static PIRP IoBuildSynchronousFsdRequest(UCHAR major, PDEVICE_OBJECT device, PVOID buffer,
    ULONG length, LARGE_INTEGER* offset, KEVENT* completion, IO_STATUS_BLOCK* status) {
    require(device != nullptr, "referenced lower device remains available");
    return new FakeIrp{major, device, buffer, length, static_cast<ULONGLONG>(offset->QuadPart),
        completion, status, {}};
}
static PIO_STACK_LOCATION IoGetNextIrpStackLocation(PIRP irp) { return &irp->stack; }
static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp) {
    require(irp->device == device, "production lower request uses its held target");
    require((irp->stack.Flags & SL_OVERRIDE_VERIFY_VOLUME) != 0,
        "production lower request preserves volume verification override");
    const NTSTATUS status = irp->major == IRP_MJ_READ
        ? readMemory(device->owner, device->backend, irp->offset, irp->buffer, irp->length,
            &irp->status->Information)
        : writeMemory(device->owner, device->backend, irp->offset, irp->buffer, irp->length,
            &irp->status->Information, (irp->stack.Flags & SL_WRITE_THROUGH) != 0);
    irp->status->Status = status;
    irp->completion->signaled = true;
    delete irp;
    return status;
}
static NTSTATUS KeWaitForSingleObject(KEVENT* event, int, int, BOOLEAN, LARGE_INTEGER*) {
    require(event->signaled, "memory mock only provides already completed synchronous IRPs");
    return STATUS_SUCCESS;
}
static BOOLEAN IoCancelIrp(PIRP) { return TRUE; }
/*DEVICE_READ_WRITE*/
/*PRODUCTION*/
static NTSTATUS WdfRequestRetrieveInputBuffer(WDFREQUEST request, size_t minimum,
    PVOID* buffer, size_t* actual) {
    *buffer = request->buffer.data(); *actual = request->inputLength;
    return *actual >= minimum ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}
static NTSTATUS WdfRequestRetrieveOutputBuffer(WDFREQUEST request, size_t minimum,
    PVOID* buffer, size_t* actual) {
    *buffer = request->buffer.data(); *actual = request->outputLength;
    return *actual >= minimum ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}
static NTSTATUS KswordARKSafetyEvaluate(WDFDEVICE, const KSWORD_ARK_SAFETY_CONTEXT* context) {
    ++safetyCalls;
    require(context->Operation == KSWORD_ARK_SAFETY_OPERATION_RAW_DISK_WRITE,
        "WDF write retains the central dangerous-operation policy");
    require(context->TargetText != nullptr && context->TargetTextChars > 0,
        "safety audit target remains bounded and populated");
    return denySafety || !(context->ContextFlags & KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED)
        ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}
/*ADAPTERS*/
static void reset() {
    require(pools.empty(), "every prior operation freed its pool snapshot");
    diskA.guid = {0x12345678, 0x1357, 0x2468, {1,2,3,4,5,6,7,8}};
    diskB.guid = {0xaabbccdd, 0x1122, 0x3344, {8,7,6,5,4,3,2,1}};
    diskA.bytes.assign(1024 * 1024, 0x31); diskB.bytes.assign(1024 * 1024, 0xB2);
    diskA.caps = diskB.caps = KSWORD_ARK_RAW_DISK_CAP_CONTROLLER | KSWORD_ARK_RAW_DISK_CAP_OFFLINE;
    diskA.number = diskB.number = 0; diskMap = &diskA;
    swapOnIdentity = shortRead = shortWrite = denySafety = failPool = zeroIdentity = false;
    oversizedRead = oversizedWrite = partialReadFailure = partialWriteFailure = false;
    identityStatus = readStatus = writeStatus = openStatus = STATUS_SUCCESS;
    identityBytes = identityVersion = identitySize = sizeof(STORAGE_DEVICE_NUMBER_EX);
    identityType = FILE_DEVICE_DISK;
    opens = releases = reads = writeAttempts = writes = guidQueries = safetyCalls = 0;
    lastReadDisk = lastWriteDisk = nullptr; lastReadBackend = lastWriteBackend = 0;
    lastOpenOptions = 0;
    lastWriteFua = false;
}
static std::vector<UCHAR> writePacket(ULONG backend, bool captured = true, ULONG length = 512) {
    const size_t header = captured ? KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE
                                  : KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE;
    std::vector<UCHAR> bytes(header + length * (captured ? 2U : 1U));
    auto* request = reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data());
    request->version = captured ? KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_VERSION
                               : KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    request->size = static_cast<ULONG>(bytes.size()); request->diskNumber = 0;
    request->backend = backend; request->flags = KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE;
    request->length = length; request->confirmationToken = KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN;
    request->offset = 512;
    if (captured) {
        auto* capture = reinterpret_cast<KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(request);
        std::memcpy(capture->expectedDeviceGuid, &diskA.guid, sizeof(GUID));
        std::memcpy(capture->data, diskA.bytes.data() + request->offset, length);
    }
    for (ULONG i = 0; i < length; ++i)
        bytes[header + (captured ? length : 0) + i] = static_cast<UCHAR>(0x60 + i % 31);
    return bytes;
}
static std::vector<UCHAR> readPacket(ULONG backend, bool captured = true) {
    std::vector<UCHAR> bytes(captured ? sizeof(KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST)
                                     : sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST));
    auto* request = reinterpret_cast<KSWORD_ARK_RAW_DISK_READ_REQUEST*>(bytes.data());
    request->version = captured ? KSWORD_ARK_RAW_DISK_CAPTURED_READ_VERSION
                               : KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    request->size = static_cast<ULONG>(bytes.size()); request->backend = backend;
    request->length = 512; request->offset = 512;
    if (captured) {
        auto* capture = reinterpret_cast<KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST*>(request);
        std::memcpy(capture->expectedDeviceGuid, &diskA.guid, sizeof(GUID));
    }
    return bytes;
}
static void noWrite(const std::vector<UCHAR>& beforeA, const std::vector<UCHAR>& beforeB) {
    require(writes == 0, "rejected case completed no mock write");
    require(diskA.bytes == beforeA && diskB.bytes == beforeB, "rejected case changed neither disk");
    require(pools.empty(), "rejected case released independent snapshots");
    require(opens == releases || !NT_SUCCESS(openStatus), "rejected case released captured context");
}
static void businessReject(std::vector<UCHAR>& bytes, NTSTATUS expected, ULONG protocol,
    unsigned expectedAttempts = 0) {
    const auto beforeA = diskA.bytes, beforeB = diskB.bytes;
    KSWORD_ARK_RAW_DISK_WRITE_RESPONSE response{};
    const NTSTATUS status = KswordARKStorageWriteRawDisk(
        reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data()), bytes.size(), &response);
    require(status == expected && response.lastStatus == expected, "business returns precise failure status");
    require(response.version == 1 && response.size == 32 && response.status == protocol,
        "business rejection preserves V1 fixed response ABI");
    require(writeAttempts == expectedAttempts, "only the short/error completion reaches a write attempt");
    noWrite(beforeA, beforeB); ++scenarios;
}
static void runBusiness() {
    for (ULONG backend = 1; backend <= 3; ++backend) {
        reset(); auto bytes = writePacket(backend); const auto beforeB = diskB.bytes;
        swapOnIdentity = true;
        reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data())->flags |= KSWORD_ARK_RAW_DISK_FLAG_FUA;
        KSWORD_ARK_RAW_DISK_WRITE_RESPONSE response{};
        require(KswordARKStorageWriteRawDisk(reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data()),
            bytes.size(), &response) == STATUS_SUCCESS, "captured write survives disk-number reuse");
        require(diskMap == &diskB && opens == 1 && releases == 1 && guidQueries == 1,
            "capture identity swapped path A to B without another open");
        require(reads == 1 && writeAttempts == 1 && writes == 1,
            "each backend validates once and writes once");
        require(lastReadDisk == &diskA && lastWriteDisk == &diskA
            && lastReadBackend == backend && lastWriteBackend == backend,
            "GUID, original read and replacement write stay on captured A/backend");
        require(diskB.bytes == beforeB, "reused disk-number target B remains unchanged");
        const auto* captured = reinterpret_cast<const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(bytes.data());
        require(std::memcmp(diskA.bytes.data() + 512, captured->data + 512, 512) == 0,
            "A received replacement payload rather than original or GUID");
        require(response.version == 1 && response.size == 32 && response.bytesTransferred == 512,
            "captured write keeps response version/length and exact completion");
        require(backend == 1 || lastWriteFua, "lower-backend FUA gate is preserved");
        require((lastOpenOptions & FILE_WRITE_THROUGH) != 0,
            "requested FUA is also passed to the writable Windows-stack handle");
        require(pools.empty(), "successful write freed every pool block"); ++scenarios;

        reset(); bytes = writePacket(backend); diskMap = &diskB;
        businessReject(bytes, STATUS_WRONG_VOLUME, KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED);
        require(guidQueries == 1 && reads == 0, "B identity is rejected before original read");
        reset(); bytes = writePacket(backend); diskA.bytes[700] ^= 1;
        businessReject(bytes, STATUS_REVISION_MISMATCH, KSWORD_ARK_RAW_DISK_STATUS_ORIGINAL_CHANGED);
        reset(); bytes = writePacket(backend); shortRead = true;
        businessReject(bytes, STATUS_DEVICE_DATA_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED);
        reset(); bytes = writePacket(backend); oversizedRead = true;
        businessReject(bytes, STATUS_DEVICE_DATA_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED);
        reset(); bytes = writePacket(backend); readStatus = STATUS_IO_DEVICE_ERROR;
        businessReject(bytes, STATUS_IO_DEVICE_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED);
        reset(); bytes = writePacket(backend); shortWrite = true;
        businessReject(bytes, STATUS_DEVICE_DATA_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED, 1);
        reset(); bytes = writePacket(backend); oversizedWrite = true;
        businessReject(bytes, STATUS_DEVICE_DATA_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED, 1);
        reset(); bytes = writePacket(backend); writeStatus = STATUS_IO_DEVICE_ERROR;
        businessReject(bytes, STATUS_IO_DEVICE_ERROR, KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED, 1);
    }
    for (unsigned mode = 0; mode < 12; ++mode) {
        reset(); auto bytes = writePacket(1);
        ULONG protocol = KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED;
        NTSTATUS expected = STATUS_NOT_SUPPORTED;
        if (mode == 0) identityBytes -= 1;
        if (mode == 1) identityVersion -= 1;
        if (mode == 2) identitySize -= 1;
        if (mode == 3) identityType = FILE_DEVICE_UNKNOWN;
        if (mode == 4) identityStatus = STATUS_NOT_SUPPORTED;
        if (mode == 5) { zeroIdentity = true; protocol = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED; expected = STATUS_WRONG_VOLUME; }
        if (mode == 6) { diskA.number = 1; protocol = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED; expected = STATUS_WRONG_VOLUME; }
        if (mode == 7) { identityStatus = expected = STATUS_NO_SUCH_DEVICE; protocol = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED; }
        if (mode == 8) { identityStatus = expected = STATUS_ACCESS_DENIED; protocol = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED; }
        if (mode == 9) { identityStatus = expected = STATUS_INVALID_DEVICE_REQUEST; }
        if (mode == 10) { identityStatus = expected = STATUS_INVALID_PARAMETER; }
        if (mode == 11) {
            zeroIdentity = true;
            auto* captured = reinterpret_cast<KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(bytes.data());
            std::memset(captured->expectedDeviceGuid, 0, sizeof(GUID));
            protocol = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED; expected = STATUS_WRONG_VOLUME;
        }
        businessReject(bytes, expected, protocol);
        require(reads == 0, "unavailable/mismatched identity blocks all data I/O");
    }
    for (unsigned mode = 0; mode < 7; ++mode) {
        reset(); auto bytes = writePacket(mode == 3 ? 3UL : 1UL);
        auto* request = reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data());
        NTSTATUS expected = STATUS_INVALID_PARAMETER; ULONG protocol = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        if (mode == 0) request->flags = 0;
        if (mode == 1) request->confirmationToken = 0;
        if (mode == 2) { diskA.caps |= KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK; expected = STATUS_ACCESS_DENIED; protocol = KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED; }
        if (mode == 3) { diskA.caps &= ~KSWORD_ARK_RAW_DISK_CAP_CONTROLLER; expected = STATUS_NOT_SUPPORTED; protocol = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE; }
        if (mode == 4) { request->offset = 513; expected = STATUS_DATATYPE_MISALIGNMENT; protocol = KSWORD_ARK_RAW_DISK_STATUS_ALIGNMENT_REQUIRED; }
        if (mode == 5) { request->offset = diskA.bytes.size(); expected = STATUS_END_OF_FILE; protocol = KSWORD_ARK_RAW_DISK_STATUS_RANGE_INVALID; }
        if (mode == 6) { failPool = true; expected = STATUS_INSUFFICIENT_RESOURCES; protocol = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED; }
        businessReject(bytes, expected, protocol);
        require(guidQueries == 0 && reads == 0, "existing gates run before captured data validation");
    }
    reset(); auto bytes = writePacket(1);
    diskA.caps |= KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK;
    reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data())->flags |= KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE;
    KSWORD_ARK_RAW_DISK_WRITE_RESPONSE response{};
    require(KswordARKStorageWriteRawDisk(reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(bytes.data()),
        bytes.size(), &response) == STATUS_SUCCESS && writes == 1, "explicit stronger system-disk authorization remains available");
    ++scenarios;
}
static NTSTATUS invokeWrite(FakeRequest& request, size_t input, size_t* returned) {
    const NTSTATUS status = KswordARKStorageIoctlWriteRawDisk(nullptr, &request, input, request.outputLength, returned);
    require(pools.empty(), "WDF handler frees request copy and transfer pool");
    for (size_t i = std::max(request.inputLength, request.outputLength); i < request.buffer.size(); ++i)
        require(request.buffer[i] == 0xCD, "write adapter leaves buffer guard intact");
    return status;
}
static void runWriteAdapter() {
    for (bool captured : {false, true}) {
        reset(); const auto bytes = writePacket(1, captured); FakeRequest request(bytes, 32); size_t returned = 0;
        require(invokeWrite(request, request.inputLength, &returned) == STATUS_SUCCESS,
            "V1 and V2 METHOD_BUFFERED write packets succeed");
        const size_t header = captured ? 56U : 40U;
        require(std::memcmp(diskA.bytes.data() + 512, bytes.data() + header + (captured ? 512 : 0), 512) == 0,
            "aliased response initialization preserves the entire replacement payload");
        const auto* response = reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*>(request.buffer.data());
        require(returned == 32 && response->version == 1 && response->bytesTransferred == 512,
            "WDF write publishes unchanged response ABI");
        require(safetyCalls == 1 && writes == 1 && guidQueries == (captured ? 1U : 0U),
            "both protocols retain policy, and only V2 invokes strong identity"); ++scenarios;
        require((lastOpenOptions & FILE_WRITE_THROUGH) == 0,
            "ordinary V1/V2 writes do not silently acquire FUA semantics");
    }
    for (unsigned mode = 0; mode < 16; ++mode) {
        reset(); auto bytes = writePacket(1); FakeRequest request(bytes, 32); size_t returned = 99;
        auto* header = reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(request.buffer.data());
        size_t declared = request.inputLength; NTSTATUS expected = STATUS_INFO_LENGTH_MISMATCH;
        if (mode == 0) { header->length = 0; expected = STATUS_INVALID_PARAMETER; }
        if (mode == 1) { header->length = KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES + 1; expected = STATUS_INVALID_PARAMETER; }
        if (mode == 2) { request.inputLength = declared = 55; }
        if (mode == 3) { --request.inputLength; --declared; }
        if (mode == 4) { --declared; }
        if (mode == 5) { --header->size; }
        if (mode == 6) { ++header->size; }
        if (mode == 7) { header->reserved = 1; }
        if (mode == 8) { header->version = 99; expected = STATUS_REVISION_MISMATCH; }
        if (mode == 9) { header->version = 0; expected = STATUS_REVISION_MISMATCH; }
        if (mode == 10) { ++request.inputLength; ++declared; request.buffer[bytes.size()] = 0; }
        if (mode == 11) { request.inputLength = declared = 39; expected = STATUS_BUFFER_TOO_SMALL; }
        if (mode == 12) { request.outputLength = 31; expected = STATUS_BUFFER_TOO_SMALL; }
        if (mode == 13) { failPool = true; expected = STATUS_INSUFFICIENT_RESOURCES; }
        if (mode == 14) { denySafety = true; expected = STATUS_ACCESS_DENIED; }
        if (mode == 15) { header->flags = 0; expected = STATUS_ACCESS_DENIED; }
        const auto beforeA = diskA.bytes, beforeB = diskB.bytes;
        // Truncated declared input keeps the original buffer tail; guard only covers
        // storage beyond the original maximum, not still-present inaccessible input.
        const auto status = KswordARKStorageIoctlWriteRawDisk(nullptr, &request, declared, request.outputLength, &returned);
        require(status == expected, "malformed/denied V2 write returns exact expected failure");
        require(returned == (mode >= 14 ? 32U : 0U), "early rejection cannot claim successful payload completion");
        require(writeAttempts == 0 && opens == 0, "malformed/policy-denied V2 never opens or writes a disk");
        noWrite(beforeA, beforeB); ++scenarios;
    }
    reset(); auto large = writePacket(2, true, KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES);
    FakeRequest request(large, 32); size_t returned = 0;
    require(invokeWrite(request, request.inputLength, &returned) == STATUS_SUCCESS && writes == 1,
        "V2 exact maximum header plus two 256KiB payloads succeeds");
    require(std::memcmp(diskA.bytes.data() + 512, large.data() + 56 + KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES,
        KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) == 0, "maximum replacement tail survives buffered aliasing");
    ++scenarios;
}
static void runReadAdapter() {
    for (ULONG backend = 1; backend <= 3; ++backend) {
        for (bool captured : {false, true}) {
            reset(); auto bytes = readPacket(backend, captured); FakeRequest request(bytes, 544); size_t returned = 0;
            swapOnIdentity = captured;
            require(KswordARKStorageIoctlReadRawDisk(nullptr, &request, request.inputLength, request.outputLength,
                &returned) == STATUS_SUCCESS, "V1/V2 buffered read succeeds through each backend");
            const auto* response = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(request.buffer.data());
            require(returned == 544 && response->version == 1 && response->size == 544 && response->bytesTransferred == 512,
                "captured read response remains V1 32-byte header plus bytes");
            require(lastReadDisk == &diskA && lastReadBackend == backend && opens == 1 && releases == 1,
                "captured read remains on A after identity-time number reuse");
            require(std::memcmp(response->data, diskA.bytes.data() + 512, 512) == 0,
                "buffered read aliasing preserves GUID and returns A evidence");
            require(writeAttempts == 0 && writes == 0 && pools.empty(), "read path never writes and releases allocation");
            require((lastOpenOptions & FILE_WRITE_THROUGH) == 0,
                "read-only opens do not inherit write-through semantics");
            ++scenarios;
        }
    }
    for (unsigned mode = 0; mode < 13; ++mode) {
        reset(); auto bytes = readPacket(1); FakeRequest request(bytes, 544); size_t returned = 99;
        auto* header = reinterpret_cast<KSWORD_ARK_RAW_DISK_READ_REQUEST*>(request.buffer.data());
        size_t declared = request.inputLength; NTSTATUS expected = STATUS_INFO_LENGTH_MISMATCH;
        if (mode == 0) header->length = 0;
        if (mode == 1) header->length = KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES + 1;
        if (mode == 2) request.inputLength = declared = 55;
        if (mode == 3) --declared;
        if (mode == 4) --header->size;
        if (mode == 5) ++header->size;
        if (mode == 6) header->reserved0 = 1;
        if (mode == 7) header->reserved1 = 1;
        if (mode == 8) { header->version = 99; expected = STATUS_REVISION_MISMATCH; }
        if (mode == 9) { header->version = 0; expected = STATUS_REVISION_MISMATCH; }
        if (mode == 10) { request.inputLength = declared = 57; }
        if (mode == 11) { request.inputLength = declared = 39; expected = STATUS_BUFFER_TOO_SMALL; }
        if (mode == 12) { request.outputLength = 31; expected = STATUS_BUFFER_TOO_SMALL; }
        const auto beforeA = diskA.bytes, beforeB = diskB.bytes;
        require(KswordARKStorageIoctlReadRawDisk(nullptr, &request, declared, request.outputLength, &returned)
            == expected, "malformed V2 read returns exact expected failure");
        require(returned == 0 && opens == 0 && reads == 0 && writeAttempts == 0,
            "malformed captured read never opens, reads or writes a disk");
        noWrite(beforeA, beforeB); ++scenarios;
    }
    reset(); auto bytes = readPacket(1); FakeRequest changed(bytes, 544); size_t returned = 0; diskMap = &diskB;
    const auto beforeA = diskA.bytes, beforeB = diskB.bytes;
    require(KswordARKStorageIoctlReadRawDisk(nullptr, &changed, changed.inputLength, changed.outputLength,
        &returned) == STATUS_WRONG_VOLUME, "captured read refuses a newly opened B");
    const auto* response = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(changed.buffer.data());
    require(returned == 32 && response->status == KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED && reads == 0,
        "source-change read provides no misattributed bytes");
    noWrite(beforeA, beforeB); ++scenarios;

    for (ULONG backend = 1; backend <= 3; ++backend) {
        for (unsigned mode = 0; mode < 6; ++mode) {
            reset(); auto packet = readPacket(backend); FakeRequest request(packet, 544); returned = 0;
            NTSTATUS expected = STATUS_NO_SUCH_DEVICE; ULONG protocol = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
            if (mode == 0) identityStatus = STATUS_NO_SUCH_DEVICE;
            if (mode == 1) identityStatus = expected = STATUS_ACCESS_DENIED;
            if (mode == 2) { identityStatus = expected = STATUS_NOT_SUPPORTED; protocol = KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED; }
            if (mode == 3) { identityBytes -= 1; expected = STATUS_NOT_SUPPORTED; protocol = KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED; }
            if (mode == 4) { zeroIdentity = true; expected = STATUS_WRONG_VOLUME; protocol = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED; }
            if (mode == 5) { diskMap = &diskB; expected = STATUS_WRONG_VOLUME; protocol = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED; }
            const auto unchangedA = diskA.bytes, unchangedB = diskB.bytes;
            require(KswordARKStorageIoctlReadRawDisk(nullptr, &request, request.inputLength, request.outputLength,
                &returned) == expected, "failed GUID read preserves exact backend status");
            const auto* failed = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(request.buffer.data());
            require(returned == 32 && failed->status == protocol && failed->bytesTransferred == 0 && reads == 0,
                "failed GUID query never publishes data or triggers a compatibility read");
            require(guidQueries == 1 && opens == 1 && releases == 1 && writeAttempts == 0,
                "failed GUID read ends the captured context without reopening");
            noWrite(unchangedA, unchangedB); ++scenarios;
        }
    }
    for (unsigned mode = 0; mode < 2; ++mode) {
        reset(); auto packet = readPacket(mode == 0 ? 2UL : 3UL); FakeRequest request(packet, 544); returned = 0;
        const auto unchangedA = diskA.bytes, unchangedB = diskB.bytes;
        if (mode == 0) diskA.caps |= KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK;
        else diskA.caps &= ~KSWORD_ARK_RAW_DISK_CAP_CONTROLLER;
        const NTSTATUS expected = mode == 0 ? STATUS_ACCESS_DENIED : STATUS_NOT_SUPPORTED;
        const ULONG protocol = mode == 0 ? KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED
                                       : KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        require(KswordARKStorageIoctlReadRawDisk(nullptr, &request, request.inputLength, request.outputLength,
            &returned) == expected, "captured read retains system-disk/controller authorization gate");
        const auto* failed = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(request.buffer.data());
        require(returned == 32 && failed->status == protocol && reads == 0 && guidQueries == 0,
            "read backend authorization is evaluated before captured identity/data");
        noWrite(unchangedA, unchangedB); ++scenarios;
    }
}
static void runCompletionReceipts() {
    const ULONG ordinary = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
    for (bool writable : {false, true}) {
        for (bool fua : {false, true}) {
            const ACCESS_MASK access = FILE_READ_DATA | (writable ? FILE_WRITE_DATA : 0U);
            require(KswordStorageOpenOptions(access, fua ? TRUE : FALSE)
                == (ordinary | (writable && fua ? FILE_WRITE_THROUGH : 0U)),
                "production open selection applies FUA only to explicitly requested writable handles");
            ++scenarios;
        }
    }
    for (ULONG backend = 1; backend <= 3; ++backend) {
        for (bool captured : {false, true}) {
            reset(); auto packet = readPacket(backend, captured);
            FakeRequest readRequest(packet, 544); size_t returned = 0; oversizedRead = true;
            const auto unchangedA = diskA.bytes, unchangedB = diskB.bytes;
            require(KswordARKStorageIoctlReadRawDisk(nullptr, &readRequest, readRequest.inputLength,
                readRequest.outputLength, &returned) == STATUS_DEVICE_DATA_ERROR,
                "oversized successful read receipt is rejected through every backend and protocol");
            const auto* readResponse = reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(readRequest.buffer.data());
            require(returned == 32 && readResponse->size == 32 && readResponse->bytesTransferred == 0
                && readResponse->status == KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED,
                "oversized read receipt publishes no falsely complete evidence");
            require(reads == 1 && writeAttempts == 0, "oversized read performs no mutation");
            noWrite(unchangedA, unchangedB); ++scenarios;

            reset(); packet = writePacket(backend, captured); FakeRequest writeRequest(packet, 32);
            const auto beforeA = diskA.bytes, beforeB = diskB.bytes; oversizedWrite = true;
            require(invokeWrite(writeRequest, writeRequest.inputLength, &returned) == STATUS_DEVICE_DATA_ERROR,
                "oversized successful write receipt is rejected through every backend and protocol");
            const auto* writeResponse = reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*>(writeRequest.buffer.data());
            require(returned == 32 && writeResponse->bytesTransferred == 0
                && writeResponse->status == KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED,
                "oversized write cannot be truncated into a complete success receipt");
            require(writeAttempts == 1, "oversized write error comes from the actual completion path");
            noWrite(beforeA, beforeB); ++scenarios;

            reset(); packet = writePacket(backend, captured); FakeRequest partialRequest(packet, 32);
            const auto oldA = diskA.bytes, oldB = diskB.bytes;
            partialWriteFailure = true; writeStatus = STATUS_IO_DEVICE_ERROR;
            require(invokeWrite(partialRequest, partialRequest.inputLength, &returned) == STATUS_IO_DEVICE_ERROR,
                "partial write failure retains the backend error rather than claiming success");
            const auto* partial = reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*>(partialRequest.buffer.data());
            const size_t replacement = captured ? 56U + 512U : 40U;
            require(returned == 32 && partial->bytesTransferred == 256
                && partial->status == KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED,
                "partial write failure preserves its actual completed byte count");
            require(std::memcmp(diskA.bytes.data() + 512, packet.data() + replacement, 256) == 0
                && std::memcmp(diskA.bytes.data() + 768, oldA.data() + 768, 256) == 0
                && diskB.bytes == oldB, "receipt matches the exact mock bytes that changed before failure");
            require(writeAttempts == 1 && writes == 0 && opens == releases && pools.empty(),
                "partial failure releases resources without a retry or rollback"); ++scenarios;

            reset(); packet = writePacket(backend, captured); FakeRequest shortRequest(packet, 32); shortWrite = true;
            require(invokeWrite(shortRequest, shortRequest.inputLength, &returned)
                == (captured ? STATUS_DEVICE_DATA_ERROR : STATUS_SUCCESS),
                "V1 short-write compatibility and V2 full-write requirement remain distinct");
            const auto* shortResponse = reinterpret_cast<const KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*>(shortRequest.buffer.data());
            require(shortResponse->bytesTransferred == 511,
                "short-write receipt retains the actual count for both protocols"); ++scenarios;
        }
        if (backend != KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
            reset(); partialReadFailure = true; readStatus = STATUS_IO_DEVICE_ERROR;
            std::vector<UCHAR> bytes(512); ULONG completed = 0;
            PDEVICE_OBJECT device = backend == KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT
                ? &diskA.port : &diskA.controller;
            require(KswordStorageSendDeviceReadWrite(device, IRP_MJ_READ,
                512, bytes.data(), 512, FALSE, &completed) == STATUS_IO_DEVICE_ERROR && completed == 256,
                "production lower completion preserves the actual partial read count on failure");
            ++scenarios;
        }
    }
}
int main() {
    static_assert(sizeof(KSWORD_ARK_RAW_DISK_READ_REQUEST) == 40);
    static_assert(sizeof(KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST) == 56);
    static_assert(KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE == 40);
    static_assert(KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE == 56);
    static_assert(KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE == 32);
    static_assert(sizeof(KSWORD_ARK_RAW_DISK_WRITE_RESPONSE) == 32);
    runBusiness(); runWriteAdapter(); runReadAdapter(); runCompletionReceipts();
    require(pools.empty(), "no pool allocations remain after all regressions");
    std::printf("CAPTURED_DISK_KERNEL_MOCK_TESTS=PASS scenarios=%u assertions=%u SDK_identity=%zu\n",
        scenarios, assertions, sizeof(STORAGE_DEVICE_NUMBER_EX));
    std::puts("BOUNDARY=extracted production business/helpers/WDF adapters; memory-only handles/devices; no driver or physical I/O");
}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vc-root", type=Path, default=Path(
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207"))
    parser.add_argument("--sdk-root", type=Path, default=Path("C:/Program Files (x86)/Windows Kits/10"))
    parser.add_argument("--sdk-version", default="10.0.26100.0")
    args = parser.parse_args()
    output = ROOT / ".codex-build-logs"
    if not output.is_dir():
        raise SystemExit("The established .codex-build-logs directory is required; no new build directory is created.")
    compiler = args.vc_root / "bin/Hostx64/x64/cl.exe"
    if not compiler.is_file():
        raise SystemExit(f"Required HostX64 MSVC is unavailable: {compiler}")
    production = STORAGE / "storage_forensics.c"
    open_context = function(production, "KswordStorageOpenContext")
    open_code = re.sub(r"/\*.*?\*/|//[^\n]*", "", open_context, flags=re.DOTALL)
    assert re.search(r"ObReferenceObjectByHandle\(\s*Context->Handle", open_code)
    assert re.search(r"IoGetRelatedDeviceObject\(Context->FileObject\)", open_code)
    assert not re.search(r"\bIoGetDeviceObjectPointer\s*\(", open_code)
    assert re.search(r"KswordStorageOpenOptions\(DesiredAccess,\s*ForceUnitAccess\)", open_code)
    write_code = function(production, "KswordARKStorageWriteRawDisk")
    assert re.search(r"KswordStorageOpenContext\(\s*Request->diskNumber,\s*"
        r"FILE_READ_DATA\s*\|\s*FILE_WRITE_DATA\s*\|\s*FILE_READ_ATTRIBUTES,\s*"
        r"\(Request->flags\s*&\s*KSWORD_ARK_RAW_DISK_FLAG_FUA\)\s*!=\s*0U,", write_code)
    helpers = "\n\n".join(function(production, name) for name in [
        "KswordStorageAllocateAlignedBuffer", "KswordStorageValidateTransfer", "KswordStorageMapStatus"])
    helpers += "\n\n" + "\n\n".join(function(STORAGE / "storage_forensics_capture.c", name)
        for name in ["KswordStorageValidateCapturedIdentity", "KswordStorageValidateCapturedWrite"])
    helpers += "\n\n" + "\n\n".join(function(production, name)
        for name in ["KswordARKStorageReadRawDisk", "KswordARKStorageWriteRawDisk"])
    adapters = "\n\n".join(function(STORAGE / "storage_forensics_ioctl.c", name)
        for name in ["KswordARKStorageIoctlReadRawDisk", "KswordARKStorageIoctlWriteRawDisk"])
    source = output / "captured_disk_kernel_mock_tests.cpp"
    executable = output / "captured_disk_kernel_mock_tests.exe"
    text = HARNESS.replace("/*CONTEXT*/", structure(STORAGE / "storage_forensics_internal.h", "KSW_STORAGE_DISK_CONTEXT"))
    text = text.replace("/*SAFETY_CONTEXT*/", structure(ROOT / "KswordARKDriver/include/ark/ark_safety.h", "KSWORD_ARK_SAFETY_CONTEXT"))
    text = text.replace("/*OPEN_OPTIONS*/", function(production, "KswordStorageOpenOptions"))
    text = text.replace("/*SELECT_BACKEND*/", function(production, "KswordStorageSelectBackendDevice"))
    text = text.replace("/*DEVICE_READ_WRITE*/", function(production, "KswordStorageSendDeviceReadWrite"))
    text = text.replace("/*PRODUCTION*/", helpers).replace("/*ADAPTERS*/", adapters)
    source.write_text(text, encoding="utf-8")
    command = [str(compiler), "/nologo", "/std:c++20", "/Zc:__cplusplus", "/permissive-", "/utf-8",
        "/EHsc", "/MD", "/W4", "/WX", "/external:W0", "/I" + str(ROOT / "shared"),
        "/I" + str(args.vc_root / "include")]
    for part in ["ucrt", "shared", "um"]:
        command.append("/external:I" + str(args.sdk_root / "Include" / args.sdk_version / part))
    command += [str(source), "/Fo" + str(output / "captured_disk_kernel_mock_tests.obj"),
        "/Fe" + str(executable), "/link", "/INCREMENTAL:NO", "/LIBPATH:" + str(args.vc_root / "lib/x64")]
    for part in ["ucrt", "um"]:
        command.append("/LIBPATH:" + str(args.sdk_root / "Lib" / args.sdk_version / part / "x64"))
    environment = os.environ.copy()
    environment["PATH"] = str(compiler.parent) + os.pathsep + environment.get("PATH", "")
    log = output / "captured-disk-kernel-mock-tests.log"
    with log.open("w", encoding="utf-8") as stream:
        stream.write("STATIC_CONTEXT_CHAIN=PASS same-handle file reference and related device; no second path lookup\n")
        stream.flush()
        compiled = subprocess.run(command, cwd=ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        stream.write(compiled.stdout); stream.flush(); print(compiled.stdout, end="")
        if compiled.returncode:
            raise SystemExit(compiled.returncode)
        tested = subprocess.run([str(executable)], cwd=ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        stream.write(tested.stdout); print(tested.stdout, end="")
        if tested.returncode:
            raise SystemExit(tested.returncode)
    print(f"LOG={log.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
