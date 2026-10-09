#pragma once
#include "../Common.h"
#include "ProcessDetailTypes.h"
#include "ThreadActions.h"
#include <psapi.h>
#include <cstdint>
#include <cstddef>
#include <limits>
namespace ks::r3::process_detail::peb {
constexpr ULONG kProcessBasicInformationClass = 0U;
constexpr ULONG kProcessWow64InformationClass = 26U;
constexpr std::size_t kMaxRemoteUnicodeBytes = 256U * 1024U;
constexpr std::size_t kMaxEnvironmentBytes = 128U * 1024U;
constexpr std::size_t kEnvironmentChunkBytes = 4096U;
constexpr std::size_t kMaxEnvironmentLines = 20U;
constexpr std::uint64_t kMaxRegionCount = 60000U;
constexpr std::uint64_t kMaxPreviewRegions = 40U;
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct ProcessBasicInformationLite final {
    PVOID reserved1 = nullptr;
    PVOID pebBaseAddress = nullptr;
    PVOID reserved2[2]{};
    ULONG_PTR uniqueProcessId = 0;
    PVOID reserved3 = nullptr;
};
struct RemoteUnicodeString32 final {
    USHORT length = 0;
    USHORT maximumLength = 0;
    std::uint32_t buffer = 0;
};
struct RemoteUnicodeString64 final {
    USHORT length = 0;
    USHORT maximumLength = 0;
    std::uint32_t padding = 0;
    std::uint64_t buffer = 0;
};
struct Curdir32 final {
    RemoteUnicodeString32 dosPath{};
    std::uint32_t handle = 0;
};
struct Curdir64 final {
    RemoteUnicodeString64 dosPath{};
    std::uint64_t handle = 0;
};
struct Peb32Lite final {
    BYTE reserved1[2]{};
    BYTE beingDebugged = 0;
    BYTE reserved2[1]{};
    std::uint32_t mutant = 0;
    std::uint32_t imageBaseAddress = 0;
    std::uint32_t ldr = 0;
    std::uint32_t processParameters = 0;
};
struct Peb64Lite final {
    BYTE reserved1[2]{};
    BYTE beingDebugged = 0;
    BYTE reserved2[1]{};
    std::uint32_t padding = 0;
    std::uint64_t mutant = 0;
    std::uint64_t imageBaseAddress = 0;
    std::uint64_t ldr = 0;
    std::uint64_t processParameters = 0;
};
struct RtlUserProcessParameters32Lite final {
    BYTE reservedBeforeCurrentDirectory[0x24]{};
    Curdir32 currentDirectory{};
    RemoteUnicodeString32 dllPath{};
    RemoteUnicodeString32 imagePathName{};
    RemoteUnicodeString32 commandLine{};
    std::uint32_t environment = 0;
};
struct RtlUserProcessParameters64Lite final {
    BYTE reservedBeforeCurrentDirectory[0x38]{};
    Curdir64 currentDirectory{};
    RemoteUnicodeString64 dllPath{};
    RemoteUnicodeString64 imagePathName{};
    RemoteUnicodeString64 commandLine{};
    std::uint64_t environment = 0;
};
struct PebReadResult final {
    std::wstring name;
    bool ok = false;
    bool wow64 = false;
    bool beingDebugged = false;
    std::uint64_t pebAddress = 0;
    std::uint64_t imageBaseAddress = 0;
    std::uint64_t processParametersAddress = 0;
    std::uint64_t environmentAddress = 0;
    std::wstring commandLine;
    std::wstring imagePath;
    std::wstring currentDirectory;
    std::wstring diagnostic;
};
std::wstring FormatHex(const std::uint64_t value);
std::wstring TrimCopy(std::wstring text);
bool ReadRemoteExact(
    HANDLE process,
    const std::uint64_t address,
    void* buffer,
    const SIZE_T bufferSize);
template <typename T>
bool ReadRemoteStructure(HANDLE process, const std::uint64_t address, T& value) {
    value = {};
    return ReadRemoteExact(process, address, &value, sizeof(value));
}
std::wstring ReadRemoteUnicode(
    HANDLE process,
    const std::uint64_t address,
    const USHORT byteLength);
PebReadResult ReadPeb64(HANDLE process, const std::uint64_t pebAddress);
PebReadResult ReadPeb32(HANDLE process, const std::uint64_t pebAddress);
std::vector<std::wstring> ReadEnvironmentPreview(
    HANDLE process,
    const std::uint64_t address,
    std::wstring& diagnostic);
std::wstring PriorityClassText(const DWORD priorityClass);
DWORD PriorityClassByComboIndex(const int index);
int ComboIndexByPriorityClass(const DWORD priorityClass);
bool ParseUnsigned(const std::wstring& source, std::uint64_t& value);
std::wstring MemoryStateText(const DWORD state);
std::wstring MemoryTypeText(const DWORD type);
std::wstring MemoryProtectText(const DWORD protect);
ProcessPebSnapshot CollectPebSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns,
    const int selectedTarget);
ProcessDetailActionResult ApplyPebAttributes(DWORD processId, ULONGLONG expectedProcessCreationTime100ns, const std::wstring& commandLine, const std::wstring& imagePath, const std::wstring& currentDirectory, const std::wstring& environmentName, const std::wstring& imageBase, const std::wstring& affinityText, int priorityIndex);
static_assert(offsetof(Peb32Lite, imageBaseAddress) == 0x08);
static_assert(offsetof(Peb32Lite, processParameters) == 0x10);
static_assert(offsetof(Peb64Lite, imageBaseAddress) == 0x10);
static_assert(offsetof(Peb64Lite, processParameters) == 0x20);
static_assert(offsetof(RtlUserProcessParameters32Lite, currentDirectory) == 0x24);
static_assert(offsetof(RtlUserProcessParameters32Lite, imagePathName) == 0x38);
static_assert(offsetof(RtlUserProcessParameters32Lite, commandLine) == 0x40);
static_assert(offsetof(RtlUserProcessParameters32Lite, environment) == 0x48);
static_assert(offsetof(RtlUserProcessParameters64Lite, currentDirectory) == 0x38);
static_assert(offsetof(RtlUserProcessParameters64Lite, imagePathName) == 0x60);
static_assert(offsetof(RtlUserProcessParameters64Lite, commandLine) == 0x70);
static_assert(offsetof(RtlUserProcessParameters64Lite, environment) == 0x80);
}
