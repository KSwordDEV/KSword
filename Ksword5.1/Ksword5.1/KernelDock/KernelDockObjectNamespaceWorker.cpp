
#include "KernelDockObjectNamespaceWorker.h"

// ============================================================
// KernelDockObjectNamespaceWorker.cpp
// 作用说明：
// 1) 枚举对象管理器命名空间关键目录；
// 2) 为符号链接对象解析目标路径；
// 3) 为设备路径提供 DOS 盘符映射候选。
// ============================================================

#include "../Framework.h"

#include <QStringList>

#include <algorithm> // std::sort/std::max：排序与扩容。
#include <array>     // std::array：FormatMessage 固定缓冲。
#include <cstdint>   // std::uintXX_t：固定宽度整数。
#include <limits>    // std::numeric_limits：限制 UNICODE_STRING 长度。
#include <vector>    // std::vector：结果容器。

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// 兼容性常量定义：
// - 某些 Windows SDK 组合下 Winternl.h 不导出对象目录/符号链接访问掩码；
// - 这里按 NT 内核对象定义补齐，避免编译器报“未声明标识符”。
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

namespace
{
    // NTSTATUS 常量：统一管理，避免魔法数字散落。
    constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000L);
    constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001L);
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
    constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr NTSTATUS kStatusNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);

    // 查询控制常量：统一控制枚举上限与缓冲区。
    constexpr std::size_t kMaxEntriesPerDirectory = 8192; // 单目录最多抓取 8192 项，防止极端卡顿。
    constexpr ULONG kInitialDirectoryQueryBuffer = 16 * 1024U; // 目录枚举初始缓冲区大小。
    constexpr ULONG kInitialSymbolicLinkChars = 1024U; // 符号链接目标初始字符缓冲大小。

    // 访问掩码常量：仅申请查询权限，避免过度授权。
    constexpr ACCESS_MASK kDirectoryQueryAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    constexpr ACCESS_MASK kSymbolicLinkQueryAccess = SYMBOLIC_LINK_QUERY;

    // Nt API 函数指针类型：统一签名，便于动态装载。
    using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
    using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);

    // NtObjectNamespaceApi：缓存 ntdll 句柄与对象管理器相关入口。
    struct NtObjectNamespaceApi
    {
        HMODULE ntdllModule = nullptr;                           // ntdllModule：ntdll 模块句柄。
        NtOpenDirectoryObjectFn openDirectoryObject = nullptr;   // openDirectoryObject：NtOpenDirectoryObject。
        NtQueryDirectoryObjectFn queryDirectoryObject = nullptr; // queryDirectoryObject：NtQueryDirectoryObject。
        NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;   // openSymbolicLinkObject：NtOpenSymbolicLinkObject。
        NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr; // querySymbolicLinkObject：NtQuerySymbolicLinkObject。
    };

    // ScopedNtHandle：
    // - 用途：自动托管 Nt 打开的 HANDLE，避免遗漏 CloseHandle。
    struct ScopedNtHandle
    {
        HANDLE handle = nullptr; // handle：托管的内核对象句柄。

        ~ScopedNtHandle()
        {
            if (handle != nullptr)
            {
                ::CloseHandle(handle);
                handle = nullptr;
            }
        }

        ScopedNtHandle() = default;
        ScopedNtHandle(const ScopedNtHandle&) = delete;
        ScopedNtHandle& operator=(const ScopedNtHandle&) = delete;
    };

    // DirectoryRecord：保存目录枚举得到的对象名和类型名。
    struct DirectoryRecord
    {
        QString objectNameText; // objectNameText：对象名。
        QString objectTypeText; // objectTypeText：对象类型名。
    };

    // NamespaceRootSpec：定义要枚举的根目录与语义元数据。
    struct NamespaceRootSpec
    {
        QString queryPathText;         // queryPathText：实际调用 NtOpenDirectoryObject 的目录路径。
        QString displayPathText;       // displayPathText：UI 展示路径文本。
        QString scopeDescriptionText;  // scopeDescriptionText：根目录语义说明。
        QString enumApiText;           // enumApiText：该根目录默认枚举 API。
    };

    // KsObjectDirectoryInformation：
    // - 作用：解析 NtQueryDirectoryObject 的单条返回。
    // - 说明：这里只使用 Name 与 TypeName 两个字段即可满足需求。
    struct KsObjectDirectoryInformation
    {
        UNICODE_STRING Name;
        UNICODE_STRING TypeName;
    };

    // normalizePathText：
    // - 作用：把路径标准化到 "\\xxx" 样式。
    QString normalizePathText(const QString& rawPathText)
    {
        QString normalizedPathText = rawPathText.trimmed();
        normalizedPathText.replace('/', '\\');

        while (normalizedPathText.contains(QStringLiteral("\\\\")))
        {
            normalizedPathText.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }

        if (normalizedPathText.isEmpty())
        {
            return QStringLiteral("\\");
        }

        if (!normalizedPathText.startsWith('\\'))
        {
            normalizedPathText.prepend('\\');
        }
        return normalizedPathText;
    }

    // joinObjectPath：
    // - 作用：把目录路径与对象名拼为完整对象路径。
    QString joinObjectPath(const QString& directoryPathText, const QString& objectNameText)
    {
        const QString normalizedDirectoryPathText = normalizePathText(directoryPathText);
        if (normalizedDirectoryPathText == QStringLiteral("\\"))
        {
            return QStringLiteral("\\%1").arg(objectNameText);
        }
        if (normalizedDirectoryPathText.endsWith('\\'))
        {
            return normalizedDirectoryPathText + objectNameText;
        }
        return normalizedDirectoryPathText + QStringLiteral("\\") + objectNameText;
    }

    // unicodeStringToQString：
    // - 作用：把 UNICODE_STRING 转成 QString。
    QString unicodeStringToQString(const UNICODE_STRING& unicodeText)
    {
        if (unicodeText.Buffer == nullptr || unicodeText.Length == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(
            unicodeText.Buffer,
            unicodeText.Length / static_cast<USHORT>(sizeof(wchar_t)));
    }

    // initializeUnicodeString：
    // - 作用：从 std::wstring 填充 UNICODE_STRING。
    void initializeUnicodeString(UNICODE_STRING& unicodeTextOut, const std::wstring& sourceText)
    {
        unicodeTextOut.Buffer = const_cast<PWSTR>(sourceText.c_str());
        unicodeTextOut.Length = static_cast<USHORT>(
            std::min<std::size_t>(
                sourceText.size() * sizeof(wchar_t),
                static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));
        unicodeTextOut.MaximumLength = static_cast<USHORT>(unicodeTextOut.Length + sizeof(wchar_t));
    }

    // isNeedGrowBufferStatus：
    // - 作用：判断状态码是否表示“缓冲不足，需要扩容重试”。
    bool isNeedGrowBufferStatus(const NTSTATUS statusCode)
    {
        return statusCode == kStatusInfoLengthMismatch
            || statusCode == kStatusBufferTooSmall
            || statusCode == kStatusBufferOverflow;
    }

    // ntStatusToText：
    // - 作用：把 NTSTATUS 转成十六进制 + 可读文本。
    QString ntStatusToText(const HMODULE ntdllModule, const NTSTATUS statusCode)
    {
        const QString hexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();

        std::array<wchar_t, 256> messageBuffer{};
        const DWORD messageLength = ::FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            ntdllModule,
            static_cast<DWORD>(statusCode),
            0,
            messageBuffer.data(),
            static_cast<DWORD>(messageBuffer.size()),
            nullptr);

        if (messageLength == 0)
        {
            return hexText;
        }

        return QStringLiteral("%1 %2")
            .arg(hexText, QString::fromWCharArray(messageBuffer.data()).trimmed());
    }

    // loadNtObjectNamespaceApi：
    // - 作用：解析对象命名空间枚举需要的 Nt API。
    bool loadNtObjectNamespaceApi(NtObjectNamespaceApi& apiOut, QString& errorTextOut)
    {
        errorTextOut.clear();

        apiOut.ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (apiOut.ntdllModule == nullptr)
        {
            apiOut.ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (apiOut.ntdllModule == nullptr)
        {
            errorTextOut = QStringLiteral("加载 ntdll.dll 失败。");
            return false;
        }

        apiOut.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenDirectoryObject"));
        apiOut.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQueryDirectoryObject"));
        apiOut.openSymbolicLinkObject = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtOpenSymbolicLinkObject"));
        apiOut.querySymbolicLinkObject = reinterpret_cast<NtQuerySymbolicLinkObjectFn>(
            ::GetProcAddress(apiOut.ntdllModule, "NtQuerySymbolicLinkObject"));

        if (apiOut.openDirectoryObject == nullptr
            || apiOut.queryDirectoryObject == nullptr
            || apiOut.openSymbolicLinkObject == nullptr
            || apiOut.querySymbolicLinkObject == nullptr)
        {
            errorTextOut = QStringLiteral("解析 NtOpen/NtQuery Directory 或 SymbolicLink API 失败。");
            return false;
        }
        return true;
    }

    // openDirectoryHandle：
    // - 作用：按目录路径打开对象目录句柄。
    NTSTATUS openDirectoryHandle(
        const NtObjectNamespaceApi& api,
        const QString& directoryPathText,
        HANDLE& directoryHandleOut)
    {
        directoryHandleOut = nullptr;

        const QString normalizedPathText = normalizePathText(directoryPathText);
        const std::wstring pathWideText = normalizedPathText.toStdWString();

        UNICODE_STRING objectPath{};
        initializeUnicodeString(objectPath, pathWideText);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        return api.openDirectoryObject(&directoryHandleOut, kDirectoryQueryAccess, &objectAttributes);
    }

    // openSymbolicLinkHandle：
    // - 作用：按对象路径打开符号链接句柄。
    NTSTATUS openSymbolicLinkHandle(
        const NtObjectNamespaceApi& api,
        const QString& symbolicLinkPathText,
        HANDLE& symbolicLinkHandleOut)
    {
        symbolicLinkHandleOut = nullptr;

        const QString normalizedPathText = normalizePathText(symbolicLinkPathText);
        const std::wstring pathWideText = normalizedPathText.toStdWString();

        UNICODE_STRING objectPath{};
        initializeUnicodeString(objectPath, pathWideText);

        OBJECT_ATTRIBUTES objectAttributes{};
        InitializeObjectAttributes(&objectAttributes, &objectPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        return api.openSymbolicLinkObject(&symbolicLinkHandleOut, kSymbolicLinkQueryAccess, &objectAttributes);
    }

    // enumerateDirectoryEntries：
    // - 作用：枚举目录中的对象名与类型。
    bool enumerateDirectoryEntries(
        const NtObjectNamespaceApi& api,
        const QString& directoryPathText,
        std::vector<DirectoryRecord>& recordsOut,
        NTSTATUS& statusCodeOut,
        bool& truncatedOut)
    {
        recordsOut.clear();
        statusCodeOut = kStatusUnsuccessful;
        truncatedOut = false;

        ScopedNtHandle directoryHandle;
        statusCodeOut = openDirectoryHandle(api, directoryPathText, directoryHandle.handle);
        if (!NT_SUCCESS(statusCodeOut))
        {
            return false;
        }

        ULONG queryContext = 0; // queryContext：NtQueryDirectoryObject 的游标。
        BOOLEAN restartScan = TRUE; // restartScan：首轮查询为 TRUE，后续固定 FALSE。
        ULONG queryBufferSize = kInitialDirectoryQueryBuffer; // queryBufferSize：目录查询缓冲区大小。

        for (std::size_t entryIndex = 0; entryIndex < kMaxEntriesPerDirectory; ++entryIndex)
        {
            std::vector<std::uint8_t> queryBuffer;
            NTSTATUS queryStatus = kStatusUnsuccessful;
            ULONG returnLength = 0;
            bool queryFinished = false;

            for (int retryIndex = 0; retryIndex < 6; ++retryIndex)
            {
                queryBuffer.assign(queryBufferSize, 0);
                queryStatus = api.queryDirectoryObject(
                    directoryHandle.handle,
                    queryBuffer.data(),
                    queryBufferSize,
                    TRUE,
                    restartScan,
                    &queryContext,
                    &returnLength);

                if (queryStatus == kStatusNoMoreEntries)
                {
                    statusCodeOut = kStatusSuccess;
                    return true;
                }

                if (isNeedGrowBufferStatus(queryStatus))
                {
                    queryBufferSize = std::max(queryBufferSize * 2U, returnLength + 512U);
                    continue;
                }

                queryFinished = true;
                break;
            }

            restartScan = FALSE;

            if (!queryFinished)
            {
                statusCodeOut = queryStatus;
                return false;
            }

            if (!NT_SUCCESS(queryStatus))
            {
                statusCodeOut = queryStatus;
                return false;
            }

            if (queryBuffer.size() < sizeof(KsObjectDirectoryInformation))
            {
                statusCodeOut = kStatusBufferTooSmall;
                return false;
            }

            const auto* recordInfo = reinterpret_cast<const KsObjectDirectoryInformation*>(queryBuffer.data());
            const QString objectNameText = unicodeStringToQString(recordInfo->Name).trimmed();
            const QString objectTypeText = unicodeStringToQString(recordInfo->TypeName).trimmed();

            if (objectNameText.isEmpty())
            {
                continue;
            }

            DirectoryRecord record;
            record.objectNameText = objectNameText;
            record.objectTypeText = objectTypeText;
            recordsOut.push_back(std::move(record));
        }

        truncatedOut = true;
        statusCodeOut = kStatusSuccess;
        return true;
    }

    // querySymbolicLinkTargetInternal：
    // - 作用：内部复用函数，按路径解析符号链接目标。
    bool querySymbolicLinkTargetInternal(
        const NtObjectNamespaceApi& api,
        const QString& symbolicLinkPathText,
        QString& targetTextOut,
        QString& statusTextOut)
    {
        targetTextOut.clear();
        statusTextOut.clear();

        ScopedNtHandle symbolicLinkHandle;
        const NTSTATUS openStatus = openSymbolicLinkHandle(api, symbolicLinkPathText, symbolicLinkHandle.handle);
        if (!NT_SUCCESS(openStatus))
        {
            statusTextOut = ntStatusToText(api.ntdllModule, openStatus);
            return false;
        }

        ULONG targetChars = kInitialSymbolicLinkChars; // targetChars：目标路径缓冲字符数。
        for (int retryIndex = 0; retryIndex < 6; ++retryIndex)
        {
            std::vector<wchar_t> targetBuffer(targetChars, L'\0');
            UNICODE_STRING targetUnicode{};
            targetUnicode.Buffer = targetBuffer.data();
            targetUnicode.Length = 0;
            targetUnicode.MaximumLength = static_cast<USHORT>(
                std::min<std::size_t>(
                    targetChars * sizeof(wchar_t),
                    static_cast<std::size_t>(std::numeric_limits<USHORT>::max() - sizeof(wchar_t))));

            ULONG returnLength = 0;
            const NTSTATUS queryStatus = api.querySymbolicLinkObject(
                symbolicLinkHandle.handle,
                &targetUnicode,
                &returnLength);

            if (NT_SUCCESS(queryStatus))
            {
                targetTextOut = QString::fromWCharArray(
                    targetUnicode.Buffer,
                    targetUnicode.Length / static_cast<USHORT>(sizeof(wchar_t)));
                statusTextOut = ntStatusToText(api.ntdllModule, queryStatus);
                return true;
            }

            if (!isNeedGrowBufferStatus(queryStatus))
            {
                statusTextOut = ntStatusToText(api.ntdllModule, queryStatus);
                return false;
            }

            targetChars = std::max<ULONG>(
                targetChars * 2U,
                static_cast<ULONG>(returnLength / sizeof(wchar_t) + 8U));
        }

        statusTextOut = QStringLiteral("符号链接目标解析重试达到上限。");
        return false;
    }

    // isNumericString：
    // - 作用：判断字符串是否全为数字字符。
    bool isNumericString(const QString& valueText)
    {
        if (valueText.trimmed().isEmpty())
        {
            return false;
        }

        for (const QChar singleChar : valueText)
        {
            if (!singleChar.isDigit())
            {
                return false;
            }
        }
        return true;
    }

    // querySessionIdList：
    // - 作用：枚举 \Sessions 目录，提取会话 ID 列表。
    std::vector<unsigned long> querySessionIdList(const NtObjectNamespaceApi& api)
    {
        std::vector<unsigned long> sessionIdList;

        std::vector<DirectoryRecord> sessionsDirectoryRecords;
        NTSTATUS queryStatus = kStatusUnsuccessful;
        bool truncated = false;
        if (enumerateDirectoryEntries(
            api,
            QStringLiteral("\\Sessions"),
            sessionsDirectoryRecords,
            queryStatus,
            truncated))
        {
            for (const DirectoryRecord& record : sessionsDirectoryRecords)
            {
                if (record.objectTypeText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) != 0)
                {
                    continue;
                }
                if (!isNumericString(record.objectNameText))
                {
                    continue;
                }

                bool parseOk = false;
                const unsigned long parsedSessionId = record.objectNameText.toULong(&parseOk);
                if (parseOk)
                {
                    sessionIdList.push_back(parsedSessionId);
                }
            }
        }

        if (sessionIdList.empty())
        {
            DWORD currentSessionId = 0;
            if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId))
            {
                sessionIdList.push_back(static_cast<unsigned long>(currentSessionId));
            }
            sessionIdList.push_back(0UL);
        }

        std::sort(sessionIdList.begin(), sessionIdList.end());
        sessionIdList.erase(std::unique(sessionIdList.begin(), sessionIdList.end()), sessionIdList.end());
        return sessionIdList;
    }

    // buildRootSpecList：
    // - 作用：构建本次任务需要遍历的目录规格。
    std::vector<NamespaceRootSpec> buildRootSpecList(const NtObjectNamespaceApi& api)
    {
        std::vector<NamespaceRootSpec> rootSpecList;

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\"),
            QStringLiteral("\\"),
            QStringLiteral("对象管理器根目录"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\BaseNamedObjects"),
            QStringLiteral("\\BaseNamedObjects"),
            QStringLiteral("跨会话全局对象（互斥体、事件、信号量、节区等）"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        const std::vector<unsigned long> sessionIdList = querySessionIdList(api);
        for (const unsigned long sessionId : sessionIdList)
        {
            const QString sessionPathText = QStringLiteral("\\Sessions\\%1\\BaseNamedObjects").arg(sessionId);
            rootSpecList.push_back(NamespaceRootSpec{
                sessionPathText,
                sessionPathText,
                QStringLiteral("会话 %1 私有命名对象").arg(sessionId),
                QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
                });
        }

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\GLOBAL??"),
            QStringLiteral("\\Global")
                + QStringLiteral("\\?\\?")
                + QStringLiteral(" (即 ")
                + QStringLiteral("\\\\?\\?)"),
            QStringLiteral("设备符号链接（DOS 设备名映射）"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject + NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Device"),
            QStringLiteral("\\Device"),
            QStringLiteral("设备对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Driver"),
            QStringLiteral("\\Driver"),
            QStringLiteral("已加载驱动对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\ObjectTypes"),
            QStringLiteral("\\ObjectTypes"),
            QStringLiteral("系统中所有对象类型定义"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Callback"),
            QStringLiteral("\\Callback"),
            QStringLiteral("内核回调对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\KnownDlls"),
            QStringLiteral("\\KnownDlls"),
            QStringLiteral("已知 DLL 的节区对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\RPC Control"),
            QStringLiteral("\\RPC Control"),
            QStringLiteral("RPC 端口/接口"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        rootSpecList.push_back(NamespaceRootSpec{
            QStringLiteral("\\Windows"),
            QStringLiteral("\\Windows"),
            QStringLiteral("WindowStation 对象"),
            QStringLiteral("NtOpenDirectoryObject + NtQueryDirectoryObject")
            });

        return rootSpecList;
    }
}

bool runObjectNamespaceSnapshotTask(std::vector<KernelObjectNamespaceEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    kLogEvent taskEvent;
    info << taskEvent << "[KernelDockObjectNamespaceWorker] 开始枚举对象命名空间。" << eol;

    NtObjectNamespaceApi api;
    if (!loadNtObjectNamespaceApi(api, errorTextOut))
    {
        err << taskEvent
            << "[KernelDockObjectNamespaceWorker] Nt API 装载失败: "
            << errorTextOut.toStdString()
            << eol;
        return false;
    }

    const std::vector<NamespaceRootSpec> rootSpecList = buildRootSpecList(api);
    std::vector<KernelObjectNamespaceEntry> resultRows;

    for (const NamespaceRootSpec& rootSpec : rootSpecList)
    {
        std::vector<DirectoryRecord> directoryRecords;
        NTSTATUS directoryStatus = kStatusUnsuccessful;
        bool truncated = false;
        const bool enumerateOk = enumerateDirectoryEntries(
            api,
            rootSpec.queryPathText,
            directoryRecords,
            directoryStatus,
            truncated);

        if (!enumerateOk)
        {
            KernelObjectNamespaceEntry failedEntry;
            failedEntry.rootPathText = rootSpec.displayPathText;
            failedEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            failedEntry.directoryPathText = rootSpec.queryPathText;
            failedEntry.objectNameText = QStringLiteral("<打开失败>");
            failedEntry.objectTypeText = QStringLiteral("<错误>");
            failedEntry.fullPathText = rootSpec.queryPathText;
            failedEntry.enumApiText = rootSpec.enumApiText;
            failedEntry.symbolicLinkTargetText = QString();
            failedEntry.statusCode = directoryStatus;
            failedEntry.statusText = ntStatusToText(api.ntdllModule, directoryStatus);
            failedEntry.querySucceeded = false;
            failedEntry.isDirectory = false;
            failedEntry.isSymbolicLink = false;

            resultRows.push_back(std::move(failedEntry));
            continue;
        }

        std::sort(directoryRecords.begin(), directoryRecords.end(), [](const DirectoryRecord& left, const DirectoryRecord& right) {
            const int typeCompare = QString::compare(left.objectTypeText, right.objectTypeText, Qt::CaseInsensitive);
            if (typeCompare != 0)
            {
                return typeCompare < 0;
            }
            return QString::compare(left.objectNameText, right.objectNameText, Qt::CaseInsensitive) < 0;
        });

        if (directoryRecords.empty())
        {
            KernelObjectNamespaceEntry emptyEntry;
            emptyEntry.rootPathText = rootSpec.displayPathText;
            emptyEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            emptyEntry.directoryPathText = rootSpec.queryPathText;
            emptyEntry.objectNameText = QStringLiteral("<空目录>");
            emptyEntry.objectTypeText = QStringLiteral("Directory");
            emptyEntry.fullPathText = rootSpec.queryPathText;
            emptyEntry.enumApiText = rootSpec.enumApiText;
            emptyEntry.symbolicLinkTargetText = QString();
            emptyEntry.statusCode = kStatusSuccess;
            emptyEntry.statusText = QStringLiteral("SUCCESS");
            emptyEntry.querySucceeded = true;
            emptyEntry.isDirectory = true;
            emptyEntry.isSymbolicLink = false;

            resultRows.push_back(std::move(emptyEntry));
            continue;
        }

        for (const DirectoryRecord& record : directoryRecords)
        {
            KernelObjectNamespaceEntry entry;
            entry.rootPathText = rootSpec.displayPathText;
            entry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            entry.directoryPathText = rootSpec.queryPathText;
            entry.objectNameText = record.objectNameText;
            entry.objectTypeText = record.objectTypeText;
            entry.fullPathText = joinObjectPath(rootSpec.queryPathText, record.objectNameText);
            entry.enumApiText = rootSpec.enumApiText;
            entry.symbolicLinkTargetText = QString();
            entry.statusCode = kStatusSuccess;
            entry.statusText = QStringLiteral("SUCCESS");
            entry.querySucceeded = true;
            entry.isDirectory = record.objectTypeText.compare(QStringLiteral("Directory"), Qt::CaseInsensitive) == 0;
            entry.isSymbolicLink = record.objectTypeText.compare(QStringLiteral("SymbolicLink"), Qt::CaseInsensitive) == 0;

            if (entry.isSymbolicLink)
            {
                QString targetText;
                QString linkStatusText;
                const bool resolveOk = querySymbolicLinkTargetInternal(api, entry.fullPathText, targetText, linkStatusText);
                entry.symbolicLinkTargetText = resolveOk ? targetText : QStringLiteral("<解析失败>");
                entry.statusText = QStringLiteral("%1 | Link: %2").arg(entry.statusText, linkStatusText);

                if (!entry.enumApiText.contains(QStringLiteral("NtOpenSymbolicLinkObject"), Qt::CaseInsensitive))
                {
                    entry.enumApiText += QStringLiteral(" + NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject");
                }
            }


            resultRows.push_back(std::move(entry));
        }

        if (truncated)
        {
            KernelObjectNamespaceEntry truncatedEntry;
            truncatedEntry.rootPathText = rootSpec.displayPathText;
            truncatedEntry.scopeDescriptionText = rootSpec.scopeDescriptionText;
            truncatedEntry.directoryPathText = rootSpec.queryPathText;
            truncatedEntry.objectNameText = QStringLiteral("<已截断>");
            truncatedEntry.objectTypeText = QStringLiteral("<Info>");
            truncatedEntry.fullPathText = rootSpec.queryPathText;
            truncatedEntry.enumApiText = rootSpec.enumApiText;
            truncatedEntry.symbolicLinkTargetText = QString();
            truncatedEntry.statusCode = kStatusSuccess;
            truncatedEntry.statusText = QStringLiteral("达到单目录上限 %1 项").arg(kMaxEntriesPerDirectory);
            truncatedEntry.querySucceeded = true;
            truncatedEntry.isDirectory = false;
            truncatedEntry.isSymbolicLink = false;
            truncatedEntry.detailDocument.note(QStringLiteral("为避免 UI 卡顿，单目录结果已截断到 %1 项。").arg(kMaxEntriesPerDirectory));
            resultRows.push_back(std::move(truncatedEntry));
        }
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelObjectNamespaceEntry& left, const KernelObjectNamespaceEntry& right) {
        const int rootCompare = QString::compare(left.rootPathText, right.rootPathText, Qt::CaseInsensitive);
        if (rootCompare != 0)
        {
            return rootCompare < 0;
        }

        const int directoryCompare = QString::compare(left.directoryPathText, right.directoryPathText, Qt::CaseInsensitive);
        if (directoryCompare != 0)
        {
            return directoryCompare < 0;
        }

        const int typeCompare = QString::compare(left.objectTypeText, right.objectTypeText, Qt::CaseInsensitive);
        if (typeCompare != 0)
        {
            return typeCompare < 0;
        }

        return QString::compare(left.objectNameText, right.objectNameText, Qt::CaseInsensitive) < 0;
    });

    rowsOut = std::move(resultRows);

    std::size_t failedCount = 0;
    for (const KernelObjectNamespaceEntry& row : rowsOut)
    {
        if (!row.querySucceeded)
        {
            ++failedCount;
        }
    }

    info << taskEvent
        << "[KernelDockObjectNamespaceWorker] 枚举完成, rowCount="
        << rowsOut.size()
        << ", failedCount="
        << failedCount
        << eol;
    return true;
}

bool queryObjectNamespaceSymbolicLinkTarget(
    const QString& symbolicLinkPathText,
    QString& targetTextOut,
    QString& statusTextOut)
{
    targetTextOut.clear();
    statusTextOut.clear();

    NtObjectNamespaceApi api;
    QString errorText;
    if (!loadNtObjectNamespaceApi(api, errorText))
    {
        statusTextOut = errorText;
        return false;
    }

    return querySymbolicLinkTargetInternal(api, symbolicLinkPathText, targetTextOut, statusTextOut);
}

std::vector<QString> queryDosPathCandidatesByNtPath(const QString& ntPathText)
{
    std::vector<QString> resultList;

    const QString normalizedNtPathText = normalizePathText(ntPathText);
    if (!normalizedNtPathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
    {
        return resultList;
    }

    QStringList uniqueCandidateList;
    for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
    {
        wchar_t driveName[3]{ driveLetter, L':', L'\0' };
        wchar_t mappingBuffer[4096]{};
        const DWORD mappingLength = ::QueryDosDeviceW(
            driveName,
            mappingBuffer,
            static_cast<DWORD>(std::size(mappingBuffer)));
        if (mappingLength == 0)
        {
            continue;
        }

        const wchar_t* mappingCursor = mappingBuffer;
        while (*mappingCursor != L'\0')
        {
            const QString mappingText = QString::fromWCharArray(mappingCursor).trimmed();
            if (!mappingText.isEmpty()
                && normalizedNtPathText.startsWith(mappingText, Qt::CaseInsensitive))
            {
                const QString suffixText = normalizedNtPathText.mid(mappingText.size());
                QString candidateText = QString::fromWCharArray(driveName);
                if (suffixText.isEmpty())
                {
                    candidateText += QStringLiteral("\\");
                }
                else
                {
                    candidateText += suffixText;
                }

                if (!uniqueCandidateList.contains(candidateText, Qt::CaseInsensitive))
                {
                    uniqueCandidateList.push_back(candidateText);
                }
            }

            mappingCursor += (wcslen(mappingCursor) + 1);
        }
    }

    for (const QString& candidateText : uniqueCandidateList)
    {
        resultList.push_back(candidateText);
    }
    return resultList;
}
