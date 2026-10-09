#pragma once
#include "../Common.h"
#include "KernelTypes.h"
#include <winternl.h>
#include <array>
#include <deque>
#include <functional>
#include <set>
#include <string_view>
#include <unordered_map>
#include "ObjectNamespace.h"
#include "ObjectDirectory.h"
#include "SymbolicLinks.h"
#include "DeviceDriverObjects.h"
#include "BaseNamedObjects.h"
#include "CommunicationEndpoints.h"
#include "ObjectTypes.h"
namespace ks::r3::kernel {
constexpr ULONG kFileDirectoryInformation = 1;
struct KFILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
};
std::wstring FileTimeText(const LARGE_INTEGER& value);
void QueryNamedPipeDirectory(const NtRuntime& runtime, const std::wstring& path, const std::wstring& filter, QueryPacket& packet);
KernelOperationResult QueryNamedPipes(const KernelRequest& request);
KernelOperationResult ExecuteNativeNamedPipeProbe(const KernelActionRequest& request);
}
