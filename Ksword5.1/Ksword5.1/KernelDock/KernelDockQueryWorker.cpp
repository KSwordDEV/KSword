#include "KernelDockQueryWorker.h"

// ============================================================
// KernelDockQueryWorker.cpp
// 作用说明：
// 1) 承担 KernelDock 的后台数据采集；
// 2) 把 NtQuery 相关耗时逻辑与 UI 渲染分离；
// 3) 保证主界面线程只负责显示，避免阻塞。
// ============================================================

#include "../Framework.h"

#include <QStringList>

#include <algorithm>  // std::max/std::sort：缓冲扩容与排序。
#include <array>      // std::array：FormatMessage 固定缓冲。
#include <cstdint>    // std::uintXX_t：明确位宽。
#include <functional> // std::function：统一查询回调签名。
#include <unordered_set> // std::unordered_set：检测 TypeIndex 冲突并兜底修复。
#include <vector>     // std::vector：承载二进制与结果。

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    // NTSTATUS 常量：统一本地定义，避免宏缺失导致编译错误。
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);

    // NtQueryObject 信息类常量：避免散落魔法数字。
    constexpr ULONG kObjectNameInformationClass = 1;
    constexpr ULONG kObjectBasicInformationClass = 0;
    constexpr ULONG kObjectTypeInformationClass = 2;
    constexpr ULONG kObjectTypesInformationClass = 3;

    // Nt API 函数指针类型：统一 Query 调用入口签名。
    using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // NtApi：缓存 ntdll 句柄与函数地址，避免重复 GetProcAddress。
    struct NtApi
    {
        HMODULE ntdllModule = nullptr;                      // ntdll 模块句柄。
        NtQueryObjectFn queryObject = nullptr;              // NtQueryObject。
        NtQuerySystemInformationFn querySystem = nullptr;   // NtQuerySystemInformation。
        NtQueryInformationProcessFn queryProcess = nullptr; // NtQueryInformationProcess。
        NtQueryInformationThreadFn queryThread = nullptr;   // NtQueryInformationThread。
        NtQueryInformationTokenFn queryToken = nullptr;     // NtQueryInformationToken。
    };

    // RawObjectTypesHeader：ObjectTypesInformation 返回头。
    struct RawObjectTypesHeader
    {
        ULONG numberOfTypes = 0; // 类型记录总数。
    };

    // RawObjectTypeInformation：对象类型记录结构。
    struct RawObjectTypeInformation
    {
        UNICODE_STRING typeName{};
        ULONG totalNumberOfObjects = 0;
        ULONG totalNumberOfHandles = 0;
        ULONG totalPagedPoolUsage = 0;
        ULONG totalNonPagedPoolUsage = 0;
        ULONG totalNamePoolUsage = 0;
        ULONG totalHandleTableUsage = 0;
        ULONG highWaterNumberOfObjects = 0;
        ULONG highWaterNumberOfHandles = 0;
        ULONG highWaterPagedPoolUsage = 0;
        ULONG highWaterNonPagedPoolUsage = 0;
        ULONG highWaterNamePoolUsage = 0;
        ULONG highWaterHandleTableUsage = 0;
        ULONG invalidAttributes = 0;
        GENERIC_MAPPING genericMapping{};
        ULONG validAccessMask = 0;
        BOOLEAN securityRequired = FALSE;
        BOOLEAN maintainHandleCount = FALSE;
        UCHAR typeIndex = 0;
        CHAR reservedByte = 0;
        ULONG poolType = 0;
        ULONG defaultPagedPoolCharge = 0;
        ULONG defaultNonPagedPoolCharge = 0;
    };

    // loadNtApi：
    // - 作用：加载 ntdll 并解析常见 NtQuery* API 地址。
    bool loadNtApi(NtApi& api, QString& errorTextOut)
    {
        errorTextOut.clear();
        api.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (api.ntdllModule == nullptr)
        {
            api.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (api.ntdllModule == nullptr)
        {
            errorTextOut = QStringLiteral("加载 ntdll.dll 失败。");
            return false;
        }

        api.queryObject = reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(api.ntdllModule, "NtQueryObject"));
        api.querySystem = reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(api.ntdllModule, "NtQuerySystemInformation"));
        api.queryProcess = reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationProcess"));
        api.queryThread = reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationThread"));
        api.queryToken = reinterpret_cast<NtQueryInformationTokenFn>(::GetProcAddress(api.ntdllModule, "NtQueryInformationToken"));

        if (api.queryObject == nullptr
            || api.querySystem == nullptr
            || api.queryProcess == nullptr
            || api.queryThread == nullptr
            || api.queryToken == nullptr)
        {
            errorTextOut = QStringLiteral("解析 NtQuery* 入口失败。");
            return false;
        }
        return true;
    }

    // isNeedGrowBufferStatus：
    // - 作用：判断是否需要扩容重试。
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    // ntStatusToText：
    // - 作用：把状态码转换成十六进制+状态文本，方便 UI 展示。
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
        const QString hexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();
        const QString successText = NT_SUCCESS(statusCode) ? QStringLiteral("SUCCESS") : QStringLiteral("FAILED");

        std::array<wchar_t, 256> buffer{};
        const DWORD length = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(statusCode),
            0,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr);
        if (length == 0)
        {
            return QStringLiteral("%1 (%2)").arg(hexText, successText);
        }
        return QStringLiteral("%1 (%2) %3")
            .arg(hexText, successText, QString::fromWCharArray(buffer.data()).trimmed());
    }

    // bytesPreview：
    // - 作用：输出前 32 字节十六进制预览，避免 UI 详情过长。
    QString bytesPreview(const std::vector<std::uint8_t>& bytes)
    {
        const std::size_t previewSize = std::min<std::size_t>(bytes.size(), 32);
        if (previewSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        QStringList parts;
        parts.reserve(static_cast<int>(previewSize));
        for (std::size_t index = 0; index < previewSize; ++index)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(static_cast<unsigned>(bytes[index]), 2, 16, QChar('0'))
                .toUpper());
        }
        return parts.join(' ');
    }

    // alignUp：
    // - 作用：用于变长结构指针向上按平台对齐。
    std::size_t alignUp(const std::size_t value, const std::size_t alignment)
    {
        if (alignment == 0)
        {
            return value;
        }
        const std::size_t mask = alignment - 1;
        return (value + mask) & ~mask;
    }

    // isReadableMemoryRange：
    // - 作用：检测一段内存是否可读，避免盲读指针导致访问冲突。
    // - 说明：ObjectTypesInformation 在不同系统里可能返回缓冲区外指针，
    //         这里先做可读性检测，再尝试解析类型名。
    bool isReadableMemoryRange(const void* beginAddress, const std::size_t length)
    {
        // 空地址或零长度直接判定不可读，避免无意义的 VirtualQuery 调用。
        if (beginAddress == nullptr || length == 0)
        {
            return false;
        }

        // 使用 uintptr_t 做地址计算，避免 32/64 位差异带来的截断问题。
        std::uintptr_t currentAddress = reinterpret_cast<std::uintptr_t>(beginAddress);
        const std::uintptr_t endAddress = currentAddress + length;
        if (endAddress < currentAddress)
        {
            return false;
        }

        // 按内存区域逐段检查，确保整段范围都处于可读状态。
        while (currentAddress < endAddress)
        {
            MEMORY_BASIC_INFORMATION memoryInfo{};
            const SIZE_T querySize = ::VirtualQuery(
                reinterpret_cast<LPCVOID>(currentAddress),
                &memoryInfo,
                sizeof(memoryInfo));
            if (querySize != sizeof(memoryInfo))
            {
                return false;
            }

            // 仅允许已提交页；保护属性为 NOACCESS/GUARD 的区域视为不可读。
            if (memoryInfo.State != MEM_COMMIT)
            {
                return false;
            }
            const DWORD protect = (memoryInfo.Protect & 0xFFU);
            if (protect == PAGE_NOACCESS || protect == PAGE_GUARD)
            {
                return false;
            }

            // 跳转到当前区域末尾，继续检查下一个区域。
            const std::uintptr_t regionBegin = reinterpret_cast<std::uintptr_t>(memoryInfo.BaseAddress);
            const std::uintptr_t regionEnd = regionBegin + memoryInfo.RegionSize;
            if (regionEnd <= currentAddress)
            {
                return false;
            }
            currentAddress = std::min(regionEnd, endAddress);
        }
        return true;
    }

    // parseUnicodeStringBuffer：
    // - 作用：按 UNICODE_STRING 描述从返回缓冲区取出文本。
    QString parseUnicodeStringBuffer(const std::vector<std::uint8_t>& buffer, const UNICODE_STRING& unicodeText)
    {
        if (buffer.empty() || unicodeText.Length == 0)
        {
            return QString();
        }

        const std::uint8_t* begin = buffer.data();
        const std::uint8_t* end = buffer.data() + buffer.size();
        const std::uint8_t* ptr = reinterpret_cast<const std::uint8_t*>(unicodeText.Buffer);
        if (ptr >= begin && (ptr + unicodeText.Length) <= end)
        {
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(ptr), unicodeText.Length / sizeof(wchar_t));
        }

        if (buffer.size() >= sizeof(UNICODE_STRING) + unicodeText.Length)
        {
            const wchar_t* fallbackText = reinterpret_cast<const wchar_t*>(begin + sizeof(UNICODE_STRING));
            return QString::fromWCharArray(fallbackText, unicodeText.Length / sizeof(wchar_t));
        }
        return QString();
    }

    // queryAutoBuffer：
    // - 作用：自动扩容并重试查询，隐藏长度不足细节。
    bool queryAutoBuffer(
        const std::function<NTSTATUS(void*, ULONG, ULONG*)>& queryFunction,
        std::vector<std::uint8_t>& outputBuffer,
        NTSTATUS& statusCodeOut,
        const ULONG initialSize = 4096)
    {
        statusCodeOut = kStatusUnsuccessful;
        ULONG bufferSize = std::max<ULONG>(initialSize, 256);

        for (int retry = 0; retry < 8; ++retry)
        {
            outputBuffer.assign(bufferSize, 0);
            ULONG returnLength = 0;
            const NTSTATUS statusCode = queryFunction(outputBuffer.data(), bufferSize, &returnLength);
            statusCodeOut = statusCode;

            if (NT_SUCCESS(statusCode))
            {
                if (returnLength > 0 && returnLength <= outputBuffer.size())
                {
                    outputBuffer.resize(returnLength);
                }
                return true;
            }

            if (!isNeedGrowBufferStatus(statusCode))
            {
                return false;
            }
            bufferSize = std::max(bufferSize * 2U, returnLength + 512U);
        }
        return false;
    }

    // enumerateNtQueryExports：
    // - 作用：从 ntdll 导出表提取 NtQuery*Information 名称。
    QStringList enumerateNtQueryExports(HMODULE ntdllModule)
    {
        QStringList result;
        if (ntdllModule == nullptr)
        {
            return result;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdllModule);
        if (dosHeader == nullptr || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return result;
        }
        const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + dosHeader->e_lfanew);
        if (ntHeader == nullptr || ntHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return result;
        }

        const IMAGE_DATA_DIRECTORY exportDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
        {
            return result;
        }

        const auto* exportInfo = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + exportDir.VirtualAddress);
        const auto* nameRvaArray = reinterpret_cast<const DWORD*>(
            reinterpret_cast<const std::uint8_t*>(ntdllModule) + exportInfo->AddressOfNames);
        if (exportInfo == nullptr || nameRvaArray == nullptr || exportInfo->NumberOfNames == 0)
        {
            return result;
        }

        for (DWORD index = 0; index < exportInfo->NumberOfNames; ++index)
        {
            const char* name = reinterpret_cast<const char*>(
                reinterpret_cast<const std::uint8_t*>(ntdllModule) + nameRvaArray[index]);
            if (name == nullptr)
            {
                continue;
            }

            const QString nameText = QString::fromLatin1(name);
            if (nameText.startsWith(QStringLiteral("NtQuery"), Qt::CaseInsensitive)
                && nameText.contains(QStringLiteral("Information"), Qt::CaseInsensitive))
            {
                result.push_back(nameText);
            }
        }

        result.sort(Qt::CaseInsensitive);
        return result;
    }

    // appendResult：
    // - 作用：填充一行 NtQuery 结果，统一字段写入逻辑。
    void appendResult(
        std::vector<KernelNtQueryResultEntry>& resultList,
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const NTSTATUS statusCode,
        const QString& statusText,
        const QString& summaryText,
        const QString& detailText)
    {
        KernelNtQueryResultEntry entry;
        entry.categoryText = categoryText;
        entry.functionNameText = functionText;
        entry.queryItemText = itemText;
        entry.statusCode = statusCode;
        entry.statusText = statusText;
        entry.summaryText = summaryText;
        entry.detailDocument.field(QStringLiteral("详细输出"), detailText);
        resultList.push_back(std::move(entry));
    }
}

bool runKernelTypeSnapshotTask(std::vector<KernelObjectTypeEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    kLogEvent beginEvent;
    info << beginEvent << "[KernelDockWorker] 开始采集内核对象类型。" << eol;

    NtApi api;
    if (!loadNtApi(api, errorTextOut))
    {
        kLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 加载 NtApi 失败: " << errorTextOut.toStdString() << eol;
        return false;
    }

    std::vector<std::uint8_t> buffer;
    NTSTATUS statusCode = kStatusUnsuccessful;
    const bool success = queryAutoBuffer(
        [&api](void* out, ULONG len, ULONG* ret) -> NTSTATUS {
            return api.queryObject(nullptr, kObjectTypesInformationClass, out, len, ret);
        },
        buffer,
        statusCode,
        64 * 1024U);
    if (!success || !NT_SUCCESS(statusCode))
    {
        errorTextOut = QStringLiteral("NtQueryObject(ObjectTypesInformation)失败: %1")
            .arg(ntStatusToText(api.ntdllModule, statusCode));
        kLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 查询对象类型失败: " << errorTextOut.toStdString() << eol;
        return false;
    }
    if (buffer.size() < sizeof(RawObjectTypesHeader))
    {
        errorTextOut = QStringLiteral("返回数据长度不足。");
        kLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 查询对象类型失败: 返回缓冲区长度不足。" << eol;
        return false;
    }

    std::vector<KernelObjectTypeEntry> resultRows;
    resultRows.reserve(reinterpret_cast<const RawObjectTypesHeader*>(buffer.data())->numberOfTypes);

    // 这里按旧版本 Ksword5.0 的逻辑先做“头后指针对齐”，
    // 这是修复乱码/错位的关键：x64 下 NumberOfTypes 后通常有 4 字节填充。
    const std::uintptr_t bufferBase = reinterpret_cast<std::uintptr_t>(buffer.data());
    const std::uintptr_t bufferEnd = bufferBase + buffer.size();
    const auto* header = reinterpret_cast<const RawObjectTypesHeader*>(buffer.data());
    std::uintptr_t entryAddress = alignUp(
        bufferBase + sizeof(RawObjectTypesHeader),
        sizeof(void*));

    // usedTypeIndex 用于处理旧系统/特殊结构下 TypeIndex 无效或重复的情况。
    std::unordered_set<std::uint32_t> usedTypeIndex;
    usedTypeIndex.reserve(header->numberOfTypes);

    for (ULONG index = 0; index < header->numberOfTypes; ++index)
    {
        // 边界检查：剩余空间不足一个结构体时直接停止，避免越界。
        if (entryAddress + sizeof(RawObjectTypeInformation) > bufferEnd)
        {
            kLogEvent boundaryEvent;
            warn << boundaryEvent
                << "[KernelDockWorker] 解析对象类型提前结束：entryAddress越界，index="
                << static_cast<unsigned long long>(index)
                << eol;
            break;
        }

        const auto* raw = reinterpret_cast<const RawObjectTypeInformation*>(entryAddress);
        QString typeName;

        // 先按旧项目逻辑优先使用 TypeName.Buffer 直接解码。
        if (raw->typeName.Buffer != nullptr && raw->typeName.Length > 0)
        {
            const std::size_t nameByteLength = raw->typeName.Length;
            const auto* directBuffer = raw->typeName.Buffer;

            // 若 Buffer 指向返回缓冲区内，直接读取；否则做可读性探测后再读取。
            const std::uintptr_t directAddress = reinterpret_cast<std::uintptr_t>(directBuffer);
            const bool inReplyBuffer =
                directAddress >= bufferBase &&
                directAddress <= bufferEnd &&
                nameByteLength <= (bufferEnd - directAddress);
            const bool externalReadable = !inReplyBuffer &&
                isReadableMemoryRange(directBuffer, nameByteLength);
            if (inReplyBuffer || externalReadable)
            {
                typeName = QString::fromWCharArray(
                    directBuffer,
                    raw->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }

        // 兼容回退：若 directBuffer 方案失败，尝试按“结构体后紧跟字符串”解析。
        if (typeName.trimmed().isEmpty() && raw->typeName.Length > 0)
        {
            const std::uintptr_t inlineNameAddress = entryAddress + sizeof(RawObjectTypeInformation);
            if (inlineNameAddress + raw->typeName.Length <= bufferEnd)
            {
                typeName = QString::fromWCharArray(
                    reinterpret_cast<const wchar_t*>(inlineNameAddress),
                    raw->typeName.Length / static_cast<USHORT>(sizeof(wchar_t)));
            }
        }
        if (typeName.trimmed().isEmpty())
        {
            typeName = QStringLiteral("<UnknownType_%1>").arg(index);
        }

        // 读取 TypeIndex：
        // - 新系统一般可直接得到正确值；
        // - 若为 0 或发生冲突，则按枚举序号分配兜底编号，保证“所有类型都有编号”。
        std::uint32_t resolvedTypeIndex = static_cast<std::uint32_t>(raw->typeIndex);
        if (resolvedTypeIndex == 0 || usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
        {
            resolvedTypeIndex = static_cast<std::uint32_t>(index + 1);
            while (usedTypeIndex.find(resolvedTypeIndex) != usedTypeIndex.end())
            {
                ++resolvedTypeIndex;
            }
        }
        usedTypeIndex.insert(resolvedTypeIndex);

        KernelObjectTypeEntry entry;
        entry.typeIndex = resolvedTypeIndex;
        entry.typeNameText = typeName;
        entry.totalObjectCount = raw->totalNumberOfObjects;
        entry.totalHandleCount = raw->totalNumberOfHandles;
        entry.validAccessMask = raw->validAccessMask;
        entry.securityRequired = raw->securityRequired != FALSE;
        entry.maintainHandleCount = raw->maintainHandleCount != FALSE;
        entry.poolType = raw->poolType;
        entry.defaultPagedPoolCharge = raw->defaultPagedPoolCharge;
        entry.defaultNonPagedPoolCharge = raw->defaultNonPagedPoolCharge;
        resultRows.push_back(std::move(entry));

        // 按结构体 + TypeName.MaximumLength 前进，并按指针大小对齐到下一个条目。
        const std::size_t entrySpan = alignUp(
            sizeof(RawObjectTypeInformation) + static_cast<std::size_t>(raw->typeName.MaximumLength),
            sizeof(void*));
        if (entrySpan < sizeof(RawObjectTypeInformation))
        {
            kLogEvent spanEvent;
            warn << spanEvent
                << "[KernelDockWorker] 解析对象类型提前结束：entrySpan异常，index="
                << static_cast<unsigned long long>(index)
                << eol;
            break;
        }

        entryAddress += entrySpan;
        if (entryAddress >= bufferEnd)
        {
            break;
        }
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelObjectTypeEntry& left, const KernelObjectTypeEntry& right) {
        if (left.typeIndex == right.typeIndex)
        {
            return QString::compare(left.typeNameText, right.typeNameText, Qt::CaseInsensitive) < 0;
        }
        return left.typeIndex < right.typeIndex;
    });

    rowsOut = std::move(resultRows);
    kLogEvent finishEvent;
    info << finishEvent << "[KernelDockWorker] 内核对象类型采集完成，数量=" << rowsOut.size() << eol;
    return true;
}

bool runNtQuerySnapshotTask(std::vector<KernelNtQueryResultEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    kLogEvent beginEvent;
    info << beginEvent << "[KernelDockWorker] 开始采集 NtQuery 信息。" << eol;

    NtApi api;
    if (!loadNtApi(api, errorTextOut))
    {
        kLogEvent failEvent;
        err << failEvent << "[KernelDockWorker] 加载 NtApi 失败: " << errorTextOut.toStdString() << eol;
        return false;
    }

    const QStringList exportList = enumerateNtQueryExports(api.ntdllModule);
    for (const QString& exportName : exportList)
    {
        appendResult(
            rowsOut,
            QStringLiteral("导出"),
            exportName,
            QStringLiteral("导出入口"),
            kStatusSuccess,
            QStringLiteral("已枚举"),
            QStringLiteral("未直接调用"),
            QStringLiteral("该 NtQuery*Information 导出已发现，部分接口需专用参数结构。"));
    }

    auto appendQueryResult = [&rowsOut, &api](
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const NTSTATUS statusCode,
        const std::vector<std::uint8_t>& buffer)
        {
            const QString statusText = ntStatusToText(api.ntdllModule, statusCode);
            const QString summaryText = NT_SUCCESS(statusCode)
                ? QStringLiteral("返回 %1 字节").arg(buffer.size())
                : QStringLiteral("调用失败");
            const QString detailText = NT_SUCCESS(statusCode)
                ? bytesPreview(buffer)
                : statusText;
            appendResult(rowsOut, categoryText, functionText, itemText, statusCode, statusText, summaryText, detailText);

            kLogEvent event;
            dbg << event
                << "[KernelDockWorker] 查询完成 category="
                << categoryText.toStdString()
                << ", func="
                << functionText.toStdString()
                << ", item="
                << itemText.toStdString()
                << ", status="
                << statusText.toStdString()
                << ", bytes="
                << buffer.size()
                << eol;
        };

    auto callQuery = [&appendQueryResult](
        const QString& categoryText,
        const QString& functionText,
        const QString& itemText,
        const std::function<NTSTATUS(void*, ULONG, ULONG*)>& queryFunction,
        const ULONG initialSize = 4096)
        {
            std::vector<std::uint8_t> buffer;
            NTSTATUS statusCode = kStatusUnsuccessful;
            queryAutoBuffer(queryFunction, buffer, statusCode, initialSize);
            appendQueryResult(categoryText, functionText, itemText, statusCode, buffer);
        };

    // 系统级 NtQuerySystemInformation。
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(0, out, len, ret); }, 2048);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemPerformanceInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(2, out, len, ret); }, 4096);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemTimeOfDayInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(3, out, len, ret); }, 2048);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemProcessInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(5, out, len, ret); }, 64 * 1024U);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemModuleInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(11, out, len, ret); }, 64 * 1024U);
    callQuery(QStringLiteral("系统"), QStringLiteral("NtQuerySystemInformation"), QStringLiteral("SystemHandleInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.querySystem(16, out, len, ret); }, 64 * 1024U);

    // 进程级 NtQueryInformationProcess。
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 0, out, len, ret); }, 512);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessHandleCount"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 20, out, len, ret); }, 256);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessImageFileName"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 27, out, len, ret); }, 2048);
    callQuery(QStringLiteral("进程"), QStringLiteral("NtQueryInformationProcess"), QStringLiteral("ProcessDebugPort"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryProcess(::GetCurrentProcess(), 7, out, len, ret); }, 64);

    // 线程级 NtQueryInformationThread。
    callQuery(QStringLiteral("线程"), QStringLiteral("NtQueryInformationThread"), QStringLiteral("ThreadBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryThread(::GetCurrentThread(), 0, out, len, ret); }, 512);
    callQuery(QStringLiteral("线程"), QStringLiteral("NtQueryInformationThread"), QStringLiteral("ThreadTimes"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryThread(::GetCurrentThread(), 1, out, len, ret); }, 512);

    // 令牌级 NtQueryInformationToken。
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenUser"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenUser), out, len, ret); }, 512);
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenIntegrityLevel"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenIntegrityLevel), out, len, ret); }, 512);
        callQuery(QStringLiteral("令牌"), QStringLiteral("NtQueryInformationToken"), QStringLiteral("TokenStatistics"),
            [&api, tokenHandle](void* out, ULONG len, ULONG* ret) { return api.queryToken(tokenHandle, static_cast<ULONG>(TokenStatistics), out, len, ret); }, 512);
        ::CloseHandle(tokenHandle);
    }
    else
    {
        kLogEvent warnEvent;
        warn << warnEvent << "[KernelDockWorker] OpenProcessToken 失败，跳过令牌类查询。" << eol;
        appendResult(
            rowsOut,
            QStringLiteral("令牌"),
            QStringLiteral("OpenProcessToken"),
            QStringLiteral("TOKEN_QUERY"),
            kStatusUnsuccessful,
            QStringLiteral("OpenProcessToken失败"),
            QStringLiteral("跳过令牌查询"),
            QStringLiteral("无法打开当前进程令牌，令牌类 NtQuery 未执行。"));
    }

    // 对象级 NtQueryObject。
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectBasicInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectBasicInformationClass, out, len, ret); }, 512);
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectNameInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectNameInformationClass, out, len, ret); }, 2048);
    callQuery(QStringLiteral("对象"), QStringLiteral("NtQueryObject"), QStringLiteral("ObjectTypeInformation"),
        [&api](void* out, ULONG len, ULONG* ret) { return api.queryObject(::GetCurrentProcess(), kObjectTypeInformationClass, out, len, ret); }, 1024);

    kLogEvent finishEvent;
    info << finishEvent
        << "[KernelDockWorker] NtQuery 信息采集完成，结果条目="
        << rowsOut.size()
        << ", 导出函数数="
        << exportList.size()
        << eol;
    return true;
}
