#include "ProcessDetailWindow.InternalCommon.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Internationalization/LanguageManager.h"

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.AdvancedInfo.cpp
// 作用：
// - 线程细节异步刷新；
// - 令牌详情异步刷新；
// - 令牌开关读取与应用（NtSetInformationToken）；
// - PEB/内存摘要异步刷新。
// ============================================================

namespace
{
    // NtQueryInformationThread 函数签名：
    // - 第二个参数直接用 ULONG，规避 SDK 枚举差异。
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // NtQueryInformationProcess 函数签名：
    // - 这里统一使用 ULONG 信息类，避免 SDK 版本差异导致的编译问题。
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    // NtSetInformationToken 函数签名：
    // - Windows Native API 入口名为 NtSetInformationToken；
    // - 本文件把它作为“NtSetTokenInformation”语义来驱动令牌开关写入。
    using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

    // PROCESSINFOCLASS 关键常量：
    // - 这些值用于补齐令牌页/PEB页的深度信息读取；
    // - 若目标系统不支持对应信息类，查询会返回失败并自动降级。
    constexpr ULONG kProcessInfoClassDebugPort = 7;
    constexpr ULONG kProcessInfoClassBreakOnTermination = 29;
    constexpr ULONG kProcessInfoClassExecuteFlags = 34;
    constexpr ULONG kProcessInfoClassCommandLine = 60;
    constexpr ULONG kProcessInfoClassProtection = 61;
    constexpr ULONG kProcessInfoClassSubsystem = 75;

    // MandatoryPolicy 位常量：
    // - 某些 SDK 版本可能没有导出宏；
    // - 这里做本地 constexpr 兜底，保证工程可编译。
#ifndef TOKEN_MANDATORY_POLICY_NO_WRITE_UP
    constexpr DWORD kTokenMandatoryPolicyNoWriteUp = 0x1;
#else
    constexpr DWORD kTokenMandatoryPolicyNoWriteUp = TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
#endif
#ifndef TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
    constexpr DWORD kTokenMandatoryPolicyNewProcessMin = 0x2;
#else
    constexpr DWORD kTokenMandatoryPolicyNewProcessMin = TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
#endif

    // TOKEN_ADJUST_SESSIONID 兜底常量：
    // - 某些旧 SDK 可能未定义该访问位；
    // - 这里统一给出数值兜底，避免编译差异。
#ifndef TOKEN_ADJUST_SESSIONID
    constexpr DWORD kTokenAdjustSessionIdAccess = 0x0100;
#else
    constexpr DWORD kTokenAdjustSessionIdAccess = TOKEN_ADJUST_SESSIONID;
#endif

    // 布尔语义 TokenInformationClass 常量：
    // - 使用数值常量规避不同 SDK 头文件的枚举可见性差异；
    // - 与“令牌开关页”新增复选框一一对应。
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassHasRestrictions =
        static_cast<TOKEN_INFORMATION_CLASS>(21);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsAppContainer =
        static_cast<TOKEN_INFORMATION_CLASS>(29);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsRestricted =
        static_cast<TOKEN_INFORMATION_CLASS>(40);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsLessPrivilegedAppContainer =
        static_cast<TOKEN_INFORMATION_CLASS>(46);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsSandboxed =
        static_cast<TOKEN_INFORMATION_CLASS>(47);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsAppSilo =
        static_cast<TOKEN_INFORMATION_CLASS>(51);

    // GetProcessInformation(ProcessPowerThrottling) 所需结构：
    // - 采用本地定义，避免依赖高版本 SDK 才可见的类型声明。
    struct ProcessPowerThrottlingStateNative
    {
        ULONG version = 0;      // 结构版本号。
        ULONG controlMask = 0;  // 可控位掩码。
        ULONG stateMask = 0;    // 当前状态位掩码。
    };

    // GetProcessInformation 动态函数签名：
    // - 第二个参数用 ULONG 表示信息类，兼容不同头文件环境。
    using GetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);

    // ProcessWow64Information：
    // - NtQueryInformationProcess 信息类 26；
    // - 64 位控制端读取 32 位目标时，需要先拿到 Wow64 PEB，再按 32 位结构解析。
    constexpr ULONG kProcessInfoClassWow64Information = 26;

    // PEB 文本读取上限：
    // - UNICODE_STRING 长度来自远程进程，必须先做边界限制；
    // - 防止损坏/伪造的 ProcessParameters 让 UI 后台线程分配超大内存。
    constexpr std::size_t kMaxRemoteUnicodeBytes = 256 * 1024;

    // 环境块预览上限：
    // - PEB 内没有稳定可跨版本依赖的环境块长度字段；
    // - 采用分块读取并在双 NUL 结束或达到上限时停止。
    constexpr std::size_t kMaxEnvironmentPreviewBytes = 128 * 1024;
    constexpr std::size_t kEnvironmentReadChunkBytes = 4096;
    constexpr std::size_t kMaxEnvironmentPreviewLines = 20;
    constexpr std::size_t kMaxEnvironmentLineChars = 4096;

    // RemoteUnicodeString32：
    // - 32 位目标进程内的 UNICODE_STRING 布局；
    // - Buffer 是远程 32 位地址，不能直接使用当前进程的 UNICODE_STRING。
    struct RemoteUnicodeString32 final
    {
        USHORT length = 0;        // 字节长度，不含终止 NUL。
        USHORT maximumLength = 0; // 字节容量，可能大于 length。
        std::uint32_t buffer = 0; // 远程 32 位 PWSTR 地址。
    };

    // Curdir32/Curdir64：
    // - 对应 RTL_USER_PROCESS_PARAMETERS.CurrentDirectory；
    // - 只保留 DosPath 与 Handle，满足详情页显示当前目录。
    struct Curdir32 final
    {
        RemoteUnicodeString32 dosPath{};
        std::uint32_t handle = 0;
    };

    struct Curdir64 final
    {
        UNICODE_STRING dosPath{};
        PVOID handle = nullptr;
    };

    // Peb32Lite/Peb64Lite：
    // - 只覆盖 PEB 起始字段到 ProcessParameters；
    // - 避免读取 SDK PEB 全结构，降低跨版本字段变化带来的失败概率。
    struct Peb32Lite final
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        std::uint32_t mutant = 0;
        std::uint32_t imageBaseAddress = 0;
        std::uint32_t ldr = 0;
        std::uint32_t processParameters = 0;
    };

    struct Peb64Lite final
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        PVOID mutant = nullptr;
        PVOID imageBaseAddress = nullptr;
        PVOID ldr = nullptr;
        PVOID processParameters = nullptr;
    };

    // RtlUserProcessParameters32Lite/RtlUserProcessParameters64Lite：
    // - 按公开稳定偏移覆盖 CurrentDirectory/ImagePathName/CommandLine/Environment；
    // - 32 位与 64 位的指针和 UNICODE_STRING 大小不同，必须分开定义。
    struct RtlUserProcessParameters32Lite final
    {
        BYTE reservedBeforeCurrentDirectory[0x24]{};
        Curdir32 currentDirectory{};
        RemoteUnicodeString32 dllPath{};
        RemoteUnicodeString32 imagePathName{};
        RemoteUnicodeString32 commandLine{};
        std::uint32_t environment = 0;
    };

    struct RtlUserProcessParameters64Lite final
    {
        BYTE reservedBeforeCurrentDirectory[0x38]{};
        Curdir64 currentDirectory{};
        UNICODE_STRING dllPath{};
        UNICODE_STRING imagePathName{};
        UNICODE_STRING commandLine{};
        PVOID environment = nullptr;
    };

    // RemotePebProcessParametersRead：
    // - 承载一次 PEB->ProcessParameters 解析结果；
    // - readOk 表示参数块结构读取成功，字符串为空不一定代表读取失败。
    struct RemotePebProcessParametersRead final
    {
        QString labelText;                         // Native PEB / Wow64 PEB。
        bool readOk = false;                       // 是否成功读到 ProcessParameters。
        std::uint64_t pebAddress = 0;              // PEB 地址。
        std::uint64_t imageBaseAddress = 0;         // PEB.ImageBaseAddress。
        std::uint64_t processParametersAddress = 0;// ProcessParameters 地址。
        std::uint64_t environmentAddress = 0;      // Environment 地址。
        QString commandLineText;                   // PEB 内命令行。
        QString imagePathText;                     // PEB 内映像路径。
        QString currentDirectoryText;              // PEB 内当前目录。
        QString diagnosticText;                    // 失败/降级原因。
    };

    // queryNtProcessInfoFixed：
    // - 读取“固定大小”的 NtQueryInformationProcess 输出结构；
    // - 成功返回 true，失败返回 false。
    template<typename T>
    bool queryNtProcessInfoFixed(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle,
        const ULONG infoClass,
        T& outValue)
    {
        if (queryFunction == nullptr || processHandle == nullptr)
        {
            return false;
        }

        std::memset(&outValue, 0, sizeof(T));
        const NTSTATUS status = queryFunction(
            processHandle,
            infoClass,
            &outValue,
            static_cast<ULONG>(sizeof(T)),
            nullptr);
        return NT_SUCCESS(status);
    }

    // queryNtProcessInfoBuffer：
    // - 读取“变长缓冲区”类型的 NtQueryInformationProcess 输出；
    // - 例如 ProcessCommandLineInformation 等场景。
    bool queryNtProcessInfoBuffer(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle,
        const ULONG infoClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        if (queryFunction == nullptr || processHandle == nullptr)
        {
            return false;
        }

        ULONG requiredLength = 0;
        NTSTATUS firstStatus = queryFunction(
            processHandle,
            infoClass,
            nullptr,
            0,
            &requiredLength);

        if (!NT_SUCCESS(firstStatus) && requiredLength == 0)
        {
            return false;
        }

        if (requiredLength < sizeof(UNICODE_STRING))
        {
            requiredLength = static_cast<ULONG>(sizeof(UNICODE_STRING) + 512);
        }

        bufferOut.resize(requiredLength + sizeof(wchar_t), 0);
        NTSTATUS secondStatus = queryFunction(
            processHandle,
            infoClass,
            bufferOut.data(),
            static_cast<ULONG>(bufferOut.size()),
            &requiredLength);
        if (!NT_SUCCESS(secondStatus))
        {
            bufferOut.clear();
            return false;
        }
        return true;
    }

    // queryCommandLineTextByNt：
    // - 通过 ProcessCommandLineInformation 读取命令行；
    // - 同时兼容“返回内嵌字符串”与“返回远程指针”两种实现。
    QString queryCommandLineTextByNt(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle)
    {
        std::vector<std::uint8_t> commandBuffer;
        if (!queryNtProcessInfoBuffer(
            queryFunction,
            processHandle,
            kProcessInfoClassCommandLine,
            commandBuffer))
        {
            return QString();
        }

        const auto* commandUnicode = reinterpret_cast<const UNICODE_STRING*>(commandBuffer.data());
        if (commandUnicode == nullptr || commandUnicode->Length == 0 || commandUnicode->Buffer == nullptr)
        {
            return QString();
        }

        const std::uintptr_t bufferBegin = reinterpret_cast<std::uintptr_t>(commandBuffer.data());
        const std::uintptr_t bufferSize = commandBuffer.size();
        const std::uintptr_t stringPtr = reinterpret_cast<std::uintptr_t>(commandUnicode->Buffer);
        const std::size_t stringLengthBytes = static_cast<std::size_t>(commandUnicode->Length);
        if ((stringLengthBytes % sizeof(wchar_t)) != 0 || stringLengthBytes > kMaxRemoteUnicodeBytes)
        {
            return QString();
        }

        // 情况A：字符串直接位于返回缓冲区中。
        if (stringPtr >= bufferBegin &&
            stringPtr - bufferBegin <= bufferSize &&
            stringLengthBytes <= bufferSize - (stringPtr - bufferBegin))
        {
            return QString::fromWCharArray(
                reinterpret_cast<const wchar_t*>(stringPtr),
                static_cast<int>(commandUnicode->Length / sizeof(wchar_t)));
        }

        // 情况B：返回的是远程指针，需二次 ReadProcessMemory。
        std::vector<wchar_t> remoteChars(
            static_cast<std::size_t>(commandUnicode->Length / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL readOk = ReadProcessMemory(
            processHandle,
            commandUnicode->Buffer,
            remoteChars.data(),
            commandUnicode->Length,
            &bytesRead);
        if (readOk == FALSE || bytesRead == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(remoteChars.data());
    }

    // appendPebDiagnostic：
    // - 把 PEB 解析阶段的非致命错误追加到诊断文本；
    // - 入参 target 为可变诊断文本，message 为本次追加内容；
    // - 返回：无，调用方继续执行后续降级路径。
    void appendPebDiagnostic(QString& target, const QString& message)
    {
        if (message.trimmed().isEmpty())
        {
            return;
        }

        if (!target.trimmed().isEmpty())
        {
            target += QStringLiteral(" | ");
        }
        target += message;
    }

    // readRemoteMemoryExact：
    // - 从远程进程读取固定长度内存；
    // - 入参 processHandle 是目标进程句柄，remoteAddress 是目标地址；
    // - 入参 localBuffer/localSize 是本地接收缓冲；
    // - 返回 true 表示完整读取 localSize 字节，false 表示地址无效或只读到部分数据。
    bool readRemoteMemoryExact(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        void* localBuffer,
        const SIZE_T localSize)
    {
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            return false;
        }

        SIZE_T bytesRead = 0;
        const BOOL readOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesRead);
        return readOk != FALSE && bytesRead == localSize;
    }

    // readRemoteStructure：
    // - 按模板类型读取一个远程结构体；
    // - 读取前先清零输出，避免失败后遗留旧数据；
    // - 返回 true 表示结构体完整读取，false 表示远程页不可读或长度不足。
    template<typename T>
    bool readRemoteStructure(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        T& valueOut)
    {
        std::memset(&valueOut, 0, sizeof(T));
        return readRemoteMemoryExact(
            processHandle,
            remoteAddress,
            &valueOut,
            static_cast<SIZE_T>(sizeof(T)));
    }

    // readRemoteUnicodeStringByAddress：
    // - 按“远程地址 + 字节长度”读取 UTF-16 字符串；
    // - 对长度做偶数校验和上限限制，避免坏 PEB 触发超大分配；
    // - 返回读取到的 QString，失败或空串时返回空 QString。
    QString readRemoteUnicodeStringByAddress(
        HANDLE processHandle,
        const std::uint64_t bufferAddress,
        const USHORT lengthBytes)
    {
        if (processHandle == nullptr || bufferAddress == 0 || lengthBytes == 0)
        {
            return QString();
        }

        if ((lengthBytes % sizeof(wchar_t)) != 0 ||
            static_cast<std::size_t>(lengthBytes) > kMaxRemoteUnicodeBytes)
        {
            return QString();
        }

        std::vector<wchar_t> stringBuffer(
            static_cast<std::size_t>(lengthBytes / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL readOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(bufferAddress)),
            stringBuffer.data(),
            static_cast<SIZE_T>(lengthBytes),
            &bytesRead);
        if (readOk == FALSE || bytesRead < sizeof(wchar_t))
        {
            return QString();
        }

        if (bytesRead > lengthBytes)
        {
            bytesRead = lengthBytes;
        }

        const int charCount = static_cast<int>(bytesRead / sizeof(wchar_t));
        if (charCount <= 0)
        {
            return QString();
        }
        stringBuffer[static_cast<std::size_t>(charCount)] = L'\0';
        return QString::fromWCharArray(stringBuffer.data(), charCount);
    }

    // readRemoteUnicodeString64：
    // - 读取 64 位目标结构中的 UNICODE_STRING；
    // - 输入是当前进程位宽的 UNICODE_STRING 快照；
    // - 返回字符串文本，失败返回空。
    QString readRemoteUnicodeString64(
        HANDLE processHandle,
        const UNICODE_STRING& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            reinterpret_cast<std::uint64_t>(remoteUnicode.Buffer),
            remoteUnicode.Length);
    }

    // readRemoteUnicodeString32：
    // - 读取 32 位目标结构中的 UNICODE_STRING；
    // - 输入是手工定义的 32 位布局，Buffer 按 32 位地址提升为 64 位再读取；
    // - 返回字符串文本，失败返回空。
    QString readRemoteUnicodeString32(
        HANDLE processHandle,
        const RemoteUnicodeString32& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            static_cast<std::uint64_t>(remoteUnicode.buffer),
            remoteUnicode.length);
    }

    // readRemoteEnvironmentPreviewLines：
    // - 分块读取远程环境变量块，直到双 NUL、读取失败或达到上限；
    // - 只返回前 kMaxEnvironmentPreviewLines 行，避免 UI 文本过大；
    // - diagnosticTextOut 可选输出截断/失败提示；
    // - 返回环境变量预览行列表，读取不到时返回空列表。
    QStringList readRemoteEnvironmentPreviewLines(
        HANDLE processHandle,
        const std::uint64_t environmentAddress,
        QString* diagnosticTextOut)
    {
        if (diagnosticTextOut != nullptr)
        {
            diagnosticTextOut->clear();
        }
        if (processHandle == nullptr || environmentAddress == 0)
        {
            return {};
        }

        std::vector<wchar_t> environmentChars;
        environmentChars.reserve(kEnvironmentReadChunkBytes / sizeof(wchar_t));

        bool foundDoubleNull = false;
        bool readStoppedByError = false;
        std::size_t offsetBytes = 0;
        while (offsetBytes < kMaxEnvironmentPreviewBytes)
        {
            const std::size_t bytesRemaining = kMaxEnvironmentPreviewBytes - offsetBytes;
            const std::size_t requestBytes = std::min<std::size_t>(
                kEnvironmentReadChunkBytes,
                bytesRemaining);
            std::vector<std::uint8_t> chunkBuffer(requestBytes, 0);

            SIZE_T bytesRead = 0;
            const BOOL readOk = ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(
                    static_cast<std::uintptr_t>(environmentAddress + offsetBytes)),
                chunkBuffer.data(),
                static_cast<SIZE_T>(chunkBuffer.size()),
                &bytesRead);
            if (readOk == FALSE || bytesRead < sizeof(wchar_t))
            {
                readStoppedByError = true;
                break;
            }

            const std::size_t charCount = static_cast<std::size_t>(bytesRead / sizeof(wchar_t));
            const std::size_t scanStartIndex = environmentChars.empty()
                ? 1
                : environmentChars.size();
            const auto* chunkChars = reinterpret_cast<const wchar_t*>(chunkBuffer.data());
            environmentChars.insert(environmentChars.end(), chunkChars, chunkChars + charCount);

            for (std::size_t index = scanStartIndex; index < environmentChars.size(); ++index)
            {
                if (environmentChars[index - 1] == L'\0' && environmentChars[index] == L'\0')
                {
                    environmentChars.resize(index);
                    foundDoubleNull = true;
                    break;
                }
            }
            if (foundDoubleNull)
            {
                break;
            }

            const std::size_t consumedBytes = charCount * sizeof(wchar_t);
            if (consumedBytes == 0 || consumedBytes < requestBytes)
            {
                readStoppedByError = true;
                break;
            }
            offsetBytes += consumedBytes;
        }

        QStringList lines;
        std::size_t cursorIndex = 0;
        while (cursorIndex < environmentChars.size() &&
            lines.size() < static_cast<int>(kMaxEnvironmentPreviewLines))
        {
            const wchar_t* currentLine = environmentChars.data() + cursorIndex;
            std::size_t currentLength = 0;
            while (cursorIndex + currentLength < environmentChars.size() &&
                environmentChars[cursorIndex + currentLength] != L'\0')
            {
                ++currentLength;
            }
            if (currentLength == 0)
            {
                break;
            }

            const int visibleLength = static_cast<int>(
                std::min<std::size_t>(currentLength, kMaxEnvironmentLineChars));
            QString lineText = QString::fromWCharArray(currentLine, visibleLength);
            if (currentLength > kMaxEnvironmentLineChars)
            {
                lineText += QStringLiteral(" ...<truncated>");
            }
            lines.push_back(lineText);
            cursorIndex += currentLength + 1;
        }

        if (diagnosticTextOut != nullptr)
        {
            if (!foundDoubleNull && offsetBytes >= kMaxEnvironmentPreviewBytes)
            {
                *diagnosticTextOut = QStringLiteral("环境变量块预览达到128KB上限，已截断。");
            }
            else if (readStoppedByError && lines.empty())
            {
                *diagnosticTextOut = QStringLiteral("环境变量块地址不可完整读取。");
            }
        }

        return lines;
    }

    // readPebProcessParameters64：
    // - 按 64 位布局解析 PEB->RTL_USER_PROCESS_PARAMETERS；
    // - 输出命令行、映像路径、当前目录、环境块地址；
    // - 返回结构体携带 readOk 与诊断文本，不直接抛出异常。
    RemotePebProcessParametersRead readPebProcessParameters64(
        HANDLE processHandle,
        const std::uint64_t pebAddress,
        const QString& labelText)
    {
        RemotePebProcessParametersRead result{};
        result.labelText = labelText;
        result.pebAddress = pebAddress;

        Peb64Lite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot))
        {
            result.diagnosticText = QStringLiteral("读取64位PEB头失败。");
            return result;
        }

        result.processParametersAddress = reinterpret_cast<std::uint64_t>(
            pebSnapshot.processParameters);
        result.imageBaseAddress = reinterpret_cast<std::uint64_t>(
            pebSnapshot.imageBaseAddress);
        if (result.processParametersAddress == 0)
        {
            result.diagnosticText = QStringLiteral("64位PEB.ProcessParameters为空。");
            return result;
        }

        RtlUserProcessParameters64Lite processParameters{};
        if (!readRemoteStructure(
            processHandle,
            result.processParametersAddress,
            processParameters))
        {
            result.diagnosticText = QStringLiteral("读取64位RTL_USER_PROCESS_PARAMETERS失败。");
            return result;
        }

        result.readOk = true;
        result.environmentAddress = reinterpret_cast<std::uint64_t>(
            processParameters.environment);
        result.commandLineText = readRemoteUnicodeString64(
            processHandle,
            processParameters.commandLine);
        result.imagePathText = readRemoteUnicodeString64(
            processHandle,
            processParameters.imagePathName);
        result.currentDirectoryText = readRemoteUnicodeString64(
            processHandle,
            processParameters.currentDirectory.dosPath);
        return result;
    }

    // readPebProcessParameters32：
    // - 按 Wow64 32 位布局解析 PEB->RTL_USER_PROCESS_PARAMETERS；
    // - 解决 64 位程序读取 32 位目标时按 64 位结构偏移解析失败的问题；
    // - 返回结构体携带 readOk 与诊断文本，不直接抛出异常。
    RemotePebProcessParametersRead readPebProcessParameters32(
        HANDLE processHandle,
        const std::uint64_t pebAddress,
        const QString& labelText)
    {
        RemotePebProcessParametersRead result{};
        result.labelText = labelText;
        result.pebAddress = pebAddress;

        Peb32Lite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot))
        {
            result.diagnosticText = QStringLiteral("读取32位PEB头失败。");
            return result;
        }

        result.processParametersAddress = static_cast<std::uint64_t>(
            pebSnapshot.processParameters);
        result.imageBaseAddress = static_cast<std::uint64_t>(
            pebSnapshot.imageBaseAddress);
        if (result.processParametersAddress == 0)
        {
            result.diagnosticText = QStringLiteral("32位PEB.ProcessParameters为空。");
            return result;
        }

        RtlUserProcessParameters32Lite processParameters{};
        if (!readRemoteStructure(
            processHandle,
            result.processParametersAddress,
            processParameters))
        {
            result.diagnosticText = QStringLiteral("读取32位RTL_USER_PROCESS_PARAMETERS失败。");
            return result;
        }

        result.readOk = true;
        result.environmentAddress = static_cast<std::uint64_t>(
            processParameters.environment);
        result.commandLineText = readRemoteUnicodeString32(
            processHandle,
            processParameters.commandLine);
        result.imagePathText = readRemoteUnicodeString32(
            processHandle,
            processParameters.imagePathName);
        result.currentDirectoryText = readRemoteUnicodeString32(
            processHandle,
            processParameters.currentDirectory.dosPath);
        return result;
    }

    // PebEditTargetSnapshot：
    // - 表示一次“准备写 PEB”的目标上下文；
    // - isWow64Target=true 时按 32 位 PEB/ProcessParameters 布局写入；
    // - 返回给 UI 写入流程使用，不直接持有句柄生命周期。
    struct PebEditTargetSnapshot final
    {
        bool valid = false;                         // 是否成功解析到目标 PEB。
        bool isWow64Target = false;                 // true=Wow64PEB/32位布局，false=NativePEB/64位布局。
        std::uint64_t pebAddress = 0;               // 远程 PEB 地址。
        std::uint64_t processParametersAddress = 0; // 远程 RTL_USER_PROCESS_PARAMETERS 地址。
        std::uint64_t imageBaseAddress = 0;         // 当前 PEB.ImageBaseAddress。
        std::uint64_t environmentAddress = 0;       // 当前 Environment 指针。
        RtlUserProcessParameters64Lite params64{};  // 64 位参数块快照。
        RtlUserProcessParameters32Lite params32{};  // 32 位参数块快照。
        QString errorText;                          // 失败原因。
    };

    // parseUnsignedIntegerText：
    // - 解析 UI 输入中的十六进制/十进制无符号整数；
    // - 支持 0x 前缀（大小写不敏感）和纯十进制；
    // - 成功时写入 valueOut 并返回 true，失败返回 false。
    bool parseUnsignedIntegerText(const QString& inputText, std::uint64_t& valueOut)
    {
        QString text = inputText.trimmed();
        if (text.isEmpty())
        {
            return false;
        }

        bool ok = false;
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        valueOut = text.toULongLong(&ok, base);
        return ok;
    }

    // writeRemoteBytesWithProtect：
    // - 向目标进程写入一段远程内存；
    // - 先直接 WriteProcessMemory，失败时临时改 PAGE_READWRITE 再重试；
    // - 返回 true 表示完整写入，false 表示地址不可写或权限不足。
    bool writeRemoteBytesWithProtect(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        const void* localBuffer,
        const SIZE_T localSize,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入参数为空。");
            }
            return false;
        }

        SIZE_T bytesWritten = 0;
        BOOL writeOk = WriteProcessMemory(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesWritten);
        if (writeOk != FALSE && bytesWritten == localSize)
        {
            return true;
        }

        const DWORD firstError = GetLastError();
        DWORD oldProtect = 0;
        if (VirtualProtectEx(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localSize,
            PAGE_READWRITE,
            &oldProtect) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("WriteProcessMemory失败(%1)，VirtualProtectEx失败(%2)。")
                    .arg(firstError)
                    .arg(GetLastError());
            }
            return false;
        }

        bytesWritten = 0;
        writeOk = WriteProcessMemory(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesWritten);
        const DWORD secondError = GetLastError();

        DWORD ignoredProtect = 0;
        VirtualProtectEx(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localSize,
            oldProtect,
            &ignoredProtect);

        if (writeOk != FALSE && bytesWritten == localSize)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("WriteProcessMemory失败(%1)，重试失败(%2)，written=%3/%4。")
                .arg(firstError)
                .arg(secondError)
                .arg(static_cast<qulonglong>(bytesWritten))
                .arg(static_cast<qulonglong>(localSize));
        }
        return false;
    }

    // buildRemoteUtf16Buffer：
    // - 把 QString 转成远程 UNICODE_STRING 可用的 UTF-16LE 缓冲；
    // - 输出包含结尾 NUL，Length 字段仍由调用者使用“不含 NUL”的字节数。
    std::vector<wchar_t> buildRemoteUtf16Buffer(const QString& text)
    {
        std::vector<wchar_t> buffer(static_cast<std::size_t>(text.size()) + 1, L'\0');
        if (!text.isEmpty())
        {
            std::memcpy(
                buffer.data(),
                text.utf16(),
                static_cast<std::size_t>(text.size()) * sizeof(wchar_t));
        }
        return buffer;
    }

    // allocateRemoteUnicodeBuffer：
    // - 在目标进程分配 UTF-16 字符串缓冲并写入内容；
    // - wow64Required=true 时要求返回地址能放入 32 位指针；
    // - 成功时输出远程地址，失败返回 false。
    bool allocateRemoteUnicodeBuffer(
        HANDLE processHandle,
        const QString& text,
        const bool wow64Required,
        std::uint64_t& remoteBufferOut,
        QString* errorTextOut)
    {
        remoteBufferOut = 0;
        const std::vector<wchar_t> buffer = buildRemoteUtf16Buffer(text);
        const SIZE_T byteSize = static_cast<SIZE_T>(buffer.size() * sizeof(wchar_t));
        LPVOID remoteBuffer = VirtualAllocEx(
            processHandle,
            nullptr,
            byteSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (remoteBuffer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("VirtualAllocEx字符串缓冲失败(%1)。").arg(GetLastError());
            }
            return false;
        }

        remoteBufferOut = reinterpret_cast<std::uint64_t>(remoteBuffer);
        if (wow64Required && remoteBufferOut > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Wow64字符串新缓冲区地址超过32位范围：%1。")
                    .arg(uint64ToHex(remoteBufferOut));
            }
            return false;
        }

        if (!writeRemoteBytesWithProtect(
            processHandle,
            remoteBufferOut,
            buffer.data(),
            byteSize,
            errorTextOut))
        {
            return false;
        }
        return true;
    }

    // updateRemoteUnicodeString64：
    // - 更新 64 位 RTL_USER_PROCESS_PARAMETERS 内的 UNICODE_STRING 字段；
    // - 新字符串能放入原缓冲时原地覆盖，否则远程分配新缓冲并改写描述符；
    // - 返回 true 表示描述符与字符串写入完成。
    bool updateRemoteUnicodeString64(
        HANDLE processHandle,
        const std::uint64_t descriptorAddress,
        const UNICODE_STRING& currentDescriptor,
        const QString& newText,
        QString* errorTextOut)
    {
        if (newText.size() > (std::numeric_limits<USHORT>::max() / static_cast<int>(sizeof(wchar_t)) - 1))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("字符串超过UNICODE_STRING长度上限。");
            }
            return false;
        }
        const std::vector<wchar_t> newBuffer = buildRemoteUtf16Buffer(newText);
        const USHORT newLengthBytes = static_cast<USHORT>(newText.size() * sizeof(wchar_t));
        const USHORT newMaximumBytes = static_cast<USHORT>(newBuffer.size() * sizeof(wchar_t));

        UNICODE_STRING updatedDescriptor = currentDescriptor;
        const std::uint64_t currentBufferAddress = reinterpret_cast<std::uint64_t>(currentDescriptor.Buffer);
        if (currentBufferAddress != 0 && currentDescriptor.MaximumLength >= newMaximumBytes)
        {
            if (!writeRemoteBytesWithProtect(
                processHandle,
                currentBufferAddress,
                newBuffer.data(),
                static_cast<SIZE_T>(newMaximumBytes),
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.Length = newLengthBytes;
        }
        else
        {
            std::uint64_t allocatedAddress = 0;
            if (!allocateRemoteUnicodeBuffer(
                processHandle,
                newText,
                false,
                allocatedAddress,
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.Length = newLengthBytes;
            updatedDescriptor.MaximumLength = newMaximumBytes;
            updatedDescriptor.Buffer = reinterpret_cast<PWSTR>(static_cast<std::uintptr_t>(allocatedAddress));
        }

        return writeRemoteBytesWithProtect(
            processHandle,
            descriptorAddress,
            &updatedDescriptor,
            static_cast<SIZE_T>(sizeof(updatedDescriptor)),
            errorTextOut);
    }

    // updateRemoteUnicodeString32：
    // - 更新 Wow64/32 位 RTL_USER_PROCESS_PARAMETERS 内的 UNICODE_STRING 字段；
    // - Buffer/Length/MaximumLength 按 32 位布局写回；
    // - 返回 true 表示描述符与字符串写入完成。
    bool updateRemoteUnicodeString32(
        HANDLE processHandle,
        const std::uint64_t descriptorAddress,
        const RemoteUnicodeString32& currentDescriptor,
        const QString& newText,
        QString* errorTextOut)
    {
        if (newText.size() > (std::numeric_limits<USHORT>::max() / static_cast<int>(sizeof(wchar_t)) - 1))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("字符串超过UNICODE_STRING长度上限。");
            }
            return false;
        }
        const std::vector<wchar_t> newBuffer = buildRemoteUtf16Buffer(newText);
        const USHORT newLengthBytes = static_cast<USHORT>(newText.size() * sizeof(wchar_t));
        const USHORT newMaximumBytes = static_cast<USHORT>(newBuffer.size() * sizeof(wchar_t));

        RemoteUnicodeString32 updatedDescriptor = currentDescriptor;
        if (currentDescriptor.buffer != 0 && currentDescriptor.maximumLength >= newMaximumBytes)
        {
            if (!writeRemoteBytesWithProtect(
                processHandle,
                static_cast<std::uint64_t>(currentDescriptor.buffer),
                newBuffer.data(),
                static_cast<SIZE_T>(newMaximumBytes),
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.length = newLengthBytes;
        }
        else
        {
            std::uint64_t allocatedAddress = 0;
            if (!allocateRemoteUnicodeBuffer(
                processHandle,
                newText,
                true,
                allocatedAddress,
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.length = newLengthBytes;
            updatedDescriptor.maximumLength = newMaximumBytes;
            updatedDescriptor.buffer = static_cast<std::uint32_t>(allocatedAddress);
        }

        return writeRemoteBytesWithProtect(
            processHandle,
            descriptorAddress,
            &updatedDescriptor,
            static_cast<SIZE_T>(sizeof(updatedDescriptor)),
            errorTextOut);
    }

    // readRemoteEnvironmentBlock：
    // - 完整读取远程环境变量块，直到双 NUL 或达到安全上限；
    // - 返回 QStringList，每项为原始 "NAME=value" 文本；
    // - 失败时 errorTextOut 给出具体原因。
    bool readRemoteEnvironmentBlock(
        HANDLE processHandle,
        const std::uint64_t environmentAddress,
        QStringList& environmentLinesOut,
        QString* errorTextOut)
    {
        environmentLinesOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (processHandle == nullptr || environmentAddress == 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Environment指针为空。");
            }
            return false;
        }

        std::vector<wchar_t> environmentChars;
        bool foundDoubleNull = false;
        std::size_t offsetBytes = 0;
        while (offsetBytes < kMaxEnvironmentPreviewBytes)
        {
            const std::size_t requestBytes = std::min<std::size_t>(
                kEnvironmentReadChunkBytes,
                kMaxEnvironmentPreviewBytes - offsetBytes);
            std::vector<std::uint8_t> chunkBuffer(requestBytes, 0);
            SIZE_T bytesRead = 0;
            const BOOL readOk = ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(
                    static_cast<std::uintptr_t>(environmentAddress + offsetBytes)),
                chunkBuffer.data(),
                static_cast<SIZE_T>(chunkBuffer.size()),
                &bytesRead);
            if (readOk == FALSE || bytesRead < sizeof(wchar_t))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("读取Environment块失败(%1)，offset=%2。")
                        .arg(GetLastError())
                        .arg(static_cast<qulonglong>(offsetBytes));
                }
                return false;
            }

            const std::size_t charCount = static_cast<std::size_t>(bytesRead / sizeof(wchar_t));
            const std::size_t scanStart = environmentChars.empty() ? 1 : environmentChars.size();
            const auto* chunkChars = reinterpret_cast<const wchar_t*>(chunkBuffer.data());
            environmentChars.insert(environmentChars.end(), chunkChars, chunkChars + charCount);
            for (std::size_t index = scanStart; index < environmentChars.size(); ++index)
            {
                if (environmentChars[index - 1] == L'\0' && environmentChars[index] == L'\0')
                {
                    environmentChars.resize(index + 1);
                    foundDoubleNull = true;
                    break;
                }
            }
            if (foundDoubleNull)
            {
                break;
            }

            const std::size_t consumedBytes = charCount * sizeof(wchar_t);
            if (consumedBytes == 0)
            {
                break;
            }
            offsetBytes += consumedBytes;
        }

        if (!foundDoubleNull)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Environment块超过128KB或缺少双NUL终止。");
            }
            return false;
        }

        std::size_t cursorIndex = 0;
        while (cursorIndex < environmentChars.size())
        {
            const wchar_t* lineBegin = environmentChars.data() + cursorIndex;
            std::size_t lineLength = 0;
            while (cursorIndex + lineLength < environmentChars.size() &&
                environmentChars[cursorIndex + lineLength] != L'\0')
            {
                ++lineLength;
            }
            if (lineLength == 0)
            {
                break;
            }
            environmentLinesOut << QString::fromWCharArray(lineBegin, static_cast<int>(lineLength));
            cursorIndex += lineLength + 1;
        }
        return true;
    }

    // updateRemoteEnvironmentVariable：
    // - 在远程环境变量块中新增或替换单个 NAME=value；
    // - 通过分配新环境块并更新 ProcessParameters.Environment 指针完成；
    // - 不释放旧环境块，避免破坏目标进程自身分配器元数据。
    bool updateRemoteEnvironmentVariable(
        HANDLE processHandle,
        const PebEditTargetSnapshot& targetSnapshot,
        const QString& variableName,
        const QString& variableValue,
        QString* errorTextOut)
    {
        const QString normalizedName = variableName.trimmed();
        if (normalizedName.isEmpty() || normalizedName.contains('='))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("环境变量名为空或包含等号。");
            }
            return false;
        }

        QStringList environmentLines;
        if (!readRemoteEnvironmentBlock(
            processHandle,
            targetSnapshot.environmentAddress,
            environmentLines,
            errorTextOut))
        {
            return false;
        }

        const QString replacementLine = normalizedName + QLatin1Char('=') + variableValue;
        bool replaced = false;
        for (QString& lineText : environmentLines)
        {
            const int equalIndex = lineText.indexOf('=');
            if (equalIndex <= 0)
            {
                continue;
            }
            const QString existingName = lineText.left(equalIndex);
            if (existingName.compare(normalizedName, Qt::CaseInsensitive) == 0)
            {
                lineText = replacementLine;
                replaced = true;
                break;
            }
        }
        if (!replaced)
        {
            environmentLines << replacementLine;
        }

        std::vector<wchar_t> environmentBuffer;
        for (const QString& lineText : environmentLines)
        {
            const int oldSize = static_cast<int>(environmentBuffer.size());
            environmentBuffer.resize(environmentBuffer.size() + static_cast<std::size_t>(lineText.size()) + 1, L'\0');
            if (!lineText.isEmpty())
            {
                std::memcpy(
                    environmentBuffer.data() + oldSize,
                    lineText.utf16(),
                    static_cast<std::size_t>(lineText.size()) * sizeof(wchar_t));
            }
        }
        environmentBuffer.push_back(L'\0');

        const SIZE_T byteSize = static_cast<SIZE_T>(environmentBuffer.size() * sizeof(wchar_t));
        LPVOID remoteBuffer = VirtualAllocEx(
            processHandle,
            nullptr,
            byteSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (remoteBuffer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("VirtualAllocEx环境块失败(%1)。").arg(GetLastError());
            }
            return false;
        }

        const std::uint64_t remoteAddress = reinterpret_cast<std::uint64_t>(remoteBuffer);
        if (targetSnapshot.isWow64Target && remoteAddress > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Wow64环境块新地址超过32位范围：%1。")
                    .arg(uint64ToHex(remoteAddress));
            }
            return false;
        }

        if (!writeRemoteBytesWithProtect(
            processHandle,
            remoteAddress,
            environmentBuffer.data(),
            byteSize,
            errorTextOut))
        {
            return false;
        }

        if (targetSnapshot.isWow64Target)
        {
            const std::uint32_t remoteAddress32 = static_cast<std::uint32_t>(remoteAddress);
            const std::uint64_t fieldAddress =
                targetSnapshot.processParametersAddress + offsetof(RtlUserProcessParameters32Lite, environment);
            return writeRemoteBytesWithProtect(
                processHandle,
                fieldAddress,
                &remoteAddress32,
                static_cast<SIZE_T>(sizeof(remoteAddress32)),
                errorTextOut);
        }

        const std::uint64_t fieldAddress =
            targetSnapshot.processParametersAddress + offsetof(RtlUserProcessParameters64Lite, environment);
        const PVOID remotePointer = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(remoteAddress));
        return writeRemoteBytesWithProtect(
            processHandle,
            fieldAddress,
            &remotePointer,
            static_cast<SIZE_T>(sizeof(remotePointer)),
            errorTextOut);
    }

    // queryPebEditTargetSnapshot：
    // - 根据 UI 目标选择解析 NativePEB 或 Wow64PEB；
    // - 同时读取 ProcessParameters 快照，供后续写字段计算偏移；
    // - 返回 valid=false 表示目标不可用。
    PebEditTargetSnapshot queryPebEditTargetSnapshot(
        HANDLE processHandle,
        const QString& targetName)
    {
        PebEditTargetSnapshot snapshot{};
        if (processHandle == nullptr)
        {
            snapshot.errorText = QStringLiteral("进程句柄为空。");
            return snapshot;
        }

        HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
        const NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
        if (ntQueryProcess == nullptr)
        {
            snapshot.errorText = QStringLiteral("无法定位NtQueryInformationProcess。");
            return snapshot;
        }

        PROCESS_BASIC_INFORMATION basicInfo{};
        const NTSTATUS basicStatus = ntQueryProcess(
            processHandle,
            static_cast<ULONG>(ProcessBasicInformation),
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (!NT_SUCCESS(basicStatus))
        {
            snapshot.errorText = QStringLiteral("NtQueryInformationProcess(ProcessBasicInformation)失败：%1。")
                .arg(QStringLiteral("0x%1")
                    .arg(static_cast<unsigned long>(basicStatus), 8, 16, QChar('0'))
                    .toUpper());
            return snapshot;
        }

        const bool wantWow64 = targetName.compare(QStringLiteral("Wow64PEB"), Qt::CaseInsensitive) == 0;
        if (wantWow64)
        {
            ULONG_PTR wow64PebAddress = 0;
            if (!queryNtProcessInfoFixed(
                ntQueryProcess,
                processHandle,
                kProcessInfoClassWow64Information,
                wow64PebAddress) ||
                wow64PebAddress == 0)
            {
                snapshot.errorText = QStringLiteral("目标没有可用Wow64PEB。");
                return snapshot;
            }

            Peb32Lite peb32{};
            if (!readRemoteStructure(processHandle, static_cast<std::uint64_t>(wow64PebAddress), peb32))
            {
                snapshot.errorText = QStringLiteral("读取Wow64PEB头失败。");
                return snapshot;
            }
            if (peb32.processParameters == 0)
            {
                snapshot.errorText = QStringLiteral("Wow64PEB.ProcessParameters为空。");
                return snapshot;
            }
            if (!readRemoteStructure(
                processHandle,
                static_cast<std::uint64_t>(peb32.processParameters),
                snapshot.params32))
            {
                snapshot.errorText = QStringLiteral("读取32位ProcessParameters失败。");
                return snapshot;
            }

            snapshot.valid = true;
            snapshot.isWow64Target = true;
            snapshot.pebAddress = static_cast<std::uint64_t>(wow64PebAddress);
            snapshot.processParametersAddress = static_cast<std::uint64_t>(peb32.processParameters);
            snapshot.imageBaseAddress = static_cast<std::uint64_t>(peb32.imageBaseAddress);
            snapshot.environmentAddress = static_cast<std::uint64_t>(snapshot.params32.environment);
            return snapshot;
        }

        if (basicInfo.PebBaseAddress == nullptr)
        {
            snapshot.errorText = QStringLiteral("NativePEB地址为空。");
            return snapshot;
        }

        Peb64Lite peb64{};
        snapshot.pebAddress = reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress);
        if (!readRemoteStructure(processHandle, snapshot.pebAddress, peb64))
        {
            snapshot.errorText = QStringLiteral("读取NativePEB头失败。");
            return snapshot;
        }
        if (peb64.processParameters == nullptr)
        {
            snapshot.errorText = QStringLiteral("NativePEB.ProcessParameters为空。");
            return snapshot;
        }
        snapshot.processParametersAddress = reinterpret_cast<std::uint64_t>(peb64.processParameters);
        if (!readRemoteStructure(processHandle, snapshot.processParametersAddress, snapshot.params64))
        {
            snapshot.errorText = QStringLiteral("读取64位ProcessParameters失败。");
            return snapshot;
        }

        snapshot.valid = true;
        snapshot.isWow64Target = false;
        snapshot.imageBaseAddress = reinterpret_cast<std::uint64_t>(peb64.imageBaseAddress);
        snapshot.environmentAddress = reinterpret_cast<std::uint64_t>(snapshot.params64.environment);
        return snapshot;
    }

    // updatePebImageBaseAddress：
    // - 只改 PEB.ImageBaseAddress 字段；
    // - 不重映射镜像，也不修复 LDR 链表，属于高级欺骗/测试能力。
    bool updatePebImageBaseAddress(
        HANDLE processHandle,
        const PebEditTargetSnapshot& targetSnapshot,
        const std::uint64_t newImageBaseAddress,
        QString* errorTextOut)
    {
        if (targetSnapshot.isWow64Target)
        {
            if (newImageBaseAddress > 0xFFFFFFFFULL)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("Wow64PEB.ImageBaseAddress不能超过32位。");
                }
                return false;
            }
            const std::uint32_t imageBase32 = static_cast<std::uint32_t>(newImageBaseAddress);
            const std::uint64_t fieldAddress = targetSnapshot.pebAddress + offsetof(Peb32Lite, imageBaseAddress);
            return writeRemoteBytesWithProtect(
                processHandle,
                fieldAddress,
                &imageBase32,
                static_cast<SIZE_T>(sizeof(imageBase32)),
                errorTextOut);
        }

        const PVOID imageBasePointer = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(newImageBaseAddress));
        const std::uint64_t fieldAddress = targetSnapshot.pebAddress + offsetof(Peb64Lite, imageBaseAddress);
        return writeRemoteBytesWithProtect(
            processHandle,
            fieldAddress,
            &imageBasePointer,
            static_cast<SIZE_T>(sizeof(imageBasePointer)),
            errorTextOut);
    }

    // memoryStateToText：
    // - 内存区域 State 字段文本化。
    QString memoryStateToText(const DWORD stateValue)
    {
        switch (stateValue)
        {
        case MEM_COMMIT: return QStringLiteral("Commit");
        case MEM_RESERVE: return QStringLiteral("Reserve");
        case MEM_FREE: return QStringLiteral("Free");
        default: return QString("State(0x%1)").arg(stateValue, 0, 16).toUpper();
        }
    }

    // memoryTypeToText：
    // - 内存区域 Type 字段文本化。
    QString memoryTypeToText(const DWORD typeValue)
    {
        switch (typeValue)
        {
        case MEM_IMAGE: return QStringLiteral("Image");
        case MEM_MAPPED: return QStringLiteral("Mapped");
        case MEM_PRIVATE: return QStringLiteral("Private");
        default: return QString("Type(0x%1)").arg(typeValue, 0, 16).toUpper();
        }
    }

    // memoryProtectToText：
    // - 内存区域保护属性文本化，便于列表审计。
    QString memoryProtectToText(const DWORD protectValue)
    {
        if (protectValue == 0)
        {
            return QStringLiteral("-");
        }

        QStringList flags;
        const DWORD baseProtect = protectValue & 0xFF;
        switch (baseProtect)
        {
        case PAGE_NOACCESS: flags << QStringLiteral("NOACCESS"); break;
        case PAGE_READONLY: flags << QStringLiteral("R"); break;
        case PAGE_READWRITE: flags << QStringLiteral("RW"); break;
        case PAGE_WRITECOPY: flags << QStringLiteral("WC"); break;
        case PAGE_EXECUTE: flags << QStringLiteral("X"); break;
        case PAGE_EXECUTE_READ: flags << QStringLiteral("XR"); break;
        case PAGE_EXECUTE_READWRITE: flags << QStringLiteral("XRW"); break;
        case PAGE_EXECUTE_WRITECOPY: flags << QStringLiteral("XWC"); break;
        default: flags << QString("0x%1").arg(baseProtect, 0, 16).toUpper(); break;
        }

        if ((protectValue & PAGE_GUARD) != 0) flags << QStringLiteral("GUARD");
        if ((protectValue & PAGE_NOCACHE) != 0) flags << QStringLiteral("NOCACHE");
        if ((protectValue & PAGE_WRITECOMBINE) != 0) flags << QStringLiteral("WRITECOMBINE");
        return flags.join('|');
    }

    // Windows 当前公开符号中的 KERNEL_CALLBACK_TABLE 字段顺序：
    // - PEB 只保存表指针，不保存表长；
    // - 字段顺序用于给索引提供可读名称，旧系统会通过连续不可用尾项自动缩短结果；
    // - 最大读取数量始终受本数组长度限制，避免沿远程内存无界扫描。
    constexpr const char* kKernelCallbackNames[] =
    {
        "__fnCOPYDATA",
        "__fnCOPYGLOBALDATA",
        "__fnEMPTY1",
        "__fnNCDESTROY",
        "__fnDWORDOPTINLPMSG",
        "__fnINOUTDRAG",
        "__fnGETTEXTLENGTHS1",
        "__fnINCNTOUTSTRING",
        "__fnINCNTOUTSTRINGNULL",
        "__fnINLPCOMPAREITEMSTRUCT",
        "__fnINLPCREATESTRUCT",
        "__fnINLPDELETEITEMSTRUCT",
        "__fnINLPDRAWITEMSTRUCT",
        "__fnPOPTINLPUINT1",
        "__fnPOPTINLPUINT2",
        "__fnINLPMDICREATESTRUCT",
        "__fnINOUTLPMEASUREITEMSTRUCT",
        "__fnINLPWINDOWPOS",
        "__fnINOUTLPPOINT51",
        "__fnINOUTLPSCROLLINFO",
        "__fnINOUTLPRECT",
        "__fnINOUTNCCALCSIZE",
        "__fnINOUTLPPOINT52",
        "__fnINPAINTCLIPBRD",
        "__fnINSIZECLIPBRD",
        "__fnINDESTROYCLIPBRD",
        "__fnINSTRINGNULL1",
        "__fnINSTRINGNULL2",
        "__fnINDEVICECHANGE",
        "__fnPOWERBROADCAST",
        "__fnINLPUAHDRAWMENU1",
        "__fnOPTOUTLPDWORDOPTOUTLPDWORD1",
        "__fnOPTOUTLPDWORDOPTOUTLPDWORD2",
        "__fnOUTDWORDINDWORD",
        "__fnOUTLPRECT",
        "__fnOUTSTRING",
        "__fnPOPTINLPUINT3",
        "__fnPOUTLPINT",
        "__fnSENTDDEMSG",
        "__fnINOUTSTYLECHANGE1",
        "__fnHkINDWORD",
        "__fnHkINLPCBTACTIVATESTRUCT",
        "__fnHkINLPCBTCREATESTRUCT",
        "__fnHkINLPDEBUGHOOKSTRUCT",
        "__fnHkINLPMOUSEHOOKSTRUCTEX1",
        "__fnHkINLPKBDLLHOOKSTRUCT",
        "__fnHkINLPMSLLHOOKSTRUCT",
        "__fnHkINLPMSG",
        "__fnHkINLPRECT",
        "__fnHkOPTINLPEVENTMSG",
        "__xxxClientCallDelegateThread",
        "__ClientCallDummyCallback1",
        "__ClientCallDummyCallback2",
        "__fnSHELLWINDOWMANAGEMENTCALLOUT",
        "__fnSHELLWINDOWMANAGEMENTNOTIFY",
        "__ClientCallDummyCallback3",
        "__xxxClientCallDitThread",
        "__xxxClientEnableMMCSS",
        "__xxxClientUpdateDpi",
        "__xxxClientExpandStringW",
        "__ClientCopyDDEIn1",
        "__ClientCopyDDEIn2",
        "__ClientCopyDDEOut1",
        "__ClientCopyDDEOut2",
        "__ClientCopyImage",
        "__ClientEventCallback",
        "__ClientFindMnemChar",
        "__ClientFreeDDEHandle",
        "__ClientFreeLibrary",
        "__ClientGetCharsetInfo",
        "__ClientGetDDEFlags",
        "__ClientGetDDEHookData",
        "__ClientGetListboxString",
        "__ClientGetMessageMPH",
        "__ClientLoadImage",
        "__ClientLoadLibrary",
        "__ClientLoadMenu",
        "__ClientLoadLocalT1Fonts",
        "__ClientPSMTextOut",
        "__ClientLpkDrawTextEx",
        "__ClientExtTextOutW",
        "__ClientGetTextExtentPointW",
        "__ClientCharToWchar",
        "__ClientAddFontResourceW",
        "__ClientThreadSetup",
        "__ClientDeliverUserApc",
        "__ClientNoMemoryPopup",
        "__ClientMonitorEnumProc",
        "__ClientCallWinEventProc",
        "__ClientWaitMessageExMPH",
        "__ClientCallDummyCallback4",
        "__ClientCallDummyCallback5",
        "__ClientImmLoadLayout",
        "__ClientImmProcessKey",
        "__fnIMECONTROL",
        "__fnINWPARAMDBCSCHAR",
        "__fnGETTEXTLENGTHS2",
        "__ClientCallDummyCallback6",
        "__ClientLoadStringW",
        "__ClientLoadOLE",
        "__ClientRegisterDragDrop",
        "__ClientRevokeDragDrop",
        "__fnINOUTMENUGETOBJECT",
        "__ClientPrinterThunk",
        "__fnOUTLPCOMBOBOXINFO",
        "__fnOUTLPSCROLLBARINFO",
        "__fnINLPUAHDRAWMENU2",
        "__fnINLPUAHDRAWMENUITEM",
        "__fnINLPUAHDRAWMENU3",
        "__fnINOUTLPUAHMEASUREMENUITEM",
        "__fnINLPUAHDRAWMENU4",
        "__fnOUTLPTITLEBARINFOEX",
        "__fnTOUCH",
        "__fnGESTURE",
        "__fnPOPTINLPUINT4",
        "__fnPOPTINLPUINT5",
        "__xxxClientCallDefaultInputHandler",
        "__fnEMPTY2",
        "__ClientRimDevCallback",
        "__xxxClientCallMinTouchHitTestingCallback",
        "__ClientCallLocalMouseHooks",
        "__xxxClientBroadcastThemeChange",
        "__xxxClientCallDevCallbackSimple",
        "__xxxClientAllocWindowClassExtraBytes",
        "__xxxClientFreeWindowClassExtraBytes",
        "__fnGETWINDOWDATA",
        "__fnINOUTSTYLECHANGE2",
        "__fnHkINLPMOUSEHOOKSTRUCTEX2",
        "__xxxClientCallDefWindowProc",
        "__fnSHELLSYNCDISPLAYCHANGED",
        "__fnHkINLPCHARHOOKSTRUCT",
        "__fnINTERCEPTEDWINDOWACTION",
        "__xxxTooltipCallback",
        "__xxxClientInitPSBInfo",
        "__xxxClientDoScrollMenu",
        "__xxxClientEndScroll",
        "__xxxClientDrawSize",
        "__xxxClientDrawScrollBar",
        "__xxxClientHitTestScrollBar",
        "__xxxClientTrackInit"
    };

    constexpr std::size_t kKernelCallbackMinimumProbeCount = 64;
    constexpr std::size_t kKernelCallbackBoundaryRunLength = 8;

    // isExecutableMemoryProtection：判断页面基础保护位是否允许执行。
    bool isExecutableMemoryProtection(const DWORD protectionValue)
    {
        switch (protectionValue & 0xFFU)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    // protectionLevelToText：
    // - ProcessProtectionInformation 的单字节级别文本化。
    QString protectionLevelToText(const std::uint8_t protectionLevel)
    {
        if (protectionLevel == 0)
        {
            return QStringLiteral("None");
        }

        const std::uint8_t signer = protectionLevel >> 4;
        const std::uint8_t type = protectionLevel & 0x07;
        return QStringLiteral("Level=0x%1 (Signer=%2, Type=%3)")
            .arg(protectionLevel, 2, 16, QChar('0'))
            .arg(signer)
            .arg(type);
    }

    // countTopLevelWindowsByPid：
    // - 枚举所有顶层窗口并统计目标 PID 持有数量。
    std::uint32_t countTopLevelWindowsByPid(const std::uint32_t pid)
    {
        struct EnumContext final
        {
            std::uint32_t targetPid = 0;   // 目标进程 PID。
            std::uint32_t windowCount = 0; // 统计结果。
        };

        EnumContext context{};
        context.targetPid = pid;

        EnumWindows(
            [](HWND hwnd, LPARAM param) -> BOOL
            {
                auto* ctx = reinterpret_cast<EnumContext*>(param);
                if (ctx == nullptr)
                {
                    return FALSE;
                }

                DWORD ownerPid = 0;
                GetWindowThreadProcessId(hwnd, &ownerPid);
                if (ownerPid == ctx->targetPid)
                {
                    ++ctx->windowCount;
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        return context.windowCount;
    }

    // queryDesktopNameByProcessThreads：
    // - 通过目标进程线程 ID 获取其桌面对象名称（可用时）。
    QString queryDesktopNameByProcessThreads(const std::uint32_t pid)
    {
        HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }

        QString desktopName;
        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        BOOL hasThread = Thread32First(snapshotHandle, &threadEntry);
        while (hasThread != FALSE)
        {
            if (threadEntry.th32OwnerProcessID == pid)
            {
                HDESK desktopHandle = GetThreadDesktop(threadEntry.th32ThreadID);
                if (desktopHandle != nullptr)
                {
                    wchar_t desktopBuffer[256] = {};
                    DWORD bytesNeeded = 0;
                    const BOOL queryOk = GetUserObjectInformationW(
                        desktopHandle,
                        UOI_NAME,
                        desktopBuffer,
                        static_cast<DWORD>(sizeof(desktopBuffer)),
                        &bytesNeeded);
                    if (queryOk != FALSE)
                    {
                        desktopName = QString::fromWCharArray(desktopBuffer);
                    }
                }
                break;
            }
            hasThread = Thread32Next(snapshotHandle, &threadEntry);
        }

        CloseHandle(snapshotHandle);
        return desktopName;
    }

    // ThreadBasicInformationNative：
    // - 对应线程基础信息结构；
    // - 只保留当前页面渲染需要的字段。
    struct ThreadBasicInformationNative
    {
        NTSTATUS exitStatus = 0;           // 线程退出状态。
        PVOID tebBaseAddress = nullptr;    // TEB 地址。
        CLIENT_ID clientId{};              // 客户端 ID。
        ULONG_PTR affinityMask = 0;        // 亲和性掩码。
        LONG priority = 0;                 // 当前优先级。
        LONG basePriority = 0;             // 基础优先级。
    };

    // threadInspectR0StatusText：
    // - 把 R0 线程扩展状态转换为详情页短文本；
    // - 与 ProcessDock 线程总览页保持相同语义。
    QString threadInspectR0StatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_THREAD_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // runtimeDetailStatusText：
    // - 输入 detail IOCTL 返回的 KSWORD_ARK_DETAIL_STATUS_*；
    // - 处理：转换为稳定、可读的中文/英文混合状态；
    // - 返回：短文本，供 Process/Thread runtime detail 展示。
    QString runtimeDetailStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DETAIL_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DETAIL_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段可用）");
        case KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported（驱动未启用该详情协议）");
        case KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED:
            return QStringLiteral("Lookup failed（目标对象不存在或不可引用）");
        case KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING:
            return QStringLiteral("Capability missing（动态偏移能力不足）");
        case KSWORD_ARK_DETAIL_STATUS_READ_FAILED:
            return QStringLiteral("Read failed（字段读取失败）");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // fixedRuntimeWideText：
    // - 输入 shared/driver 固定 wchar_t 缓冲区；
    // - 处理：按 NUL 截断，避免把填充区展示到详情页；
    // - 返回：空文本统一说明“无额外说明”。
    QString fixedRuntimeWideText(const wchar_t* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("无额外说明");
        }

        std::size_t length = 0U;
        while (length < maxChars && bufferPointer[length] != L'\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return QStringLiteral("无额外说明");
        }
        return QString::fromWCharArray(bufferPointer, static_cast<int>(length));
    }

    // fixedRuntimeImageName：
    // - 输入 shared/driver 固定 char[16] 进程名；
    // - 处理：按 NUL 截断并按本地 8-bit 文本显示；
    // - 返回：空值显示 <empty>，便于区分未读取与 UI 空白。
    QString fixedRuntimeImageName(const char* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("<empty>");
        }

        std::size_t length = 0U;
        while (length < maxChars && bufferPointer[length] != '\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromLocal8Bit(bufferPointer, static_cast<int>(length));
    }

    // runtimeCapabilityMaskText：
    // - 输入 mask：DynData capability 或 missing capability 位图；
    // - 处理：把每个能力位翻译成用户能理解的字段组名称；
    // - 返回：用于最后一列/tooltip 的短文本，保留十六进制便于和日志对照。
    QString runtimeCapabilityMaskText(const std::uint64_t mask, const bool missingMode)
    {
        QStringList names;
        const auto appendName =
            [&names, mask](const std::uint64_t bit, const QString& nameText)
            {
                if ((mask & bit) != 0ULL)
                {
                    names.push_back(nameText);
                }
            };

        appendName(KSW_CAP_DYN_NTOS_ACTIVE, QStringLiteral("ntoskrnl profile"));
        appendName(KSW_CAP_DYN_LXCORE_ACTIVE, QStringLiteral("lxcore profile"));
        appendName(KSW_CAP_OBJECT_TYPE_FIELDS, QStringLiteral("对象类型字段"));
        appendName(KSW_CAP_HANDLE_TABLE_DECODE, QStringLiteral("句柄表解码"));
        appendName(KSW_CAP_PROCESS_OBJECT_TABLE, QStringLiteral("进程 ObjectTable"));
        appendName(KSW_CAP_THREAD_STACK_FIELDS, QStringLiteral("线程栈边界"));
        appendName(KSW_CAP_THREAD_IO_COUNTERS, QStringLiteral("线程 I/O 计数"));
        appendName(KSW_CAP_ALPC_FIELDS, QStringLiteral("ALPC 字段"));
        appendName(KSW_CAP_SECTION_CONTROL_AREA, QStringLiteral("Section/ControlArea"));
        appendName(KSW_CAP_PROCESS_PROTECTION_PATCH, QStringLiteral("进程保护字段"));
        appendName(KSW_CAP_WSL_LXCORE_FIELDS, QStringLiteral("WSL/lxcore 字段"));
        appendName(KSW_CAP_ETW_GUID_FIELDS, QStringLiteral("ETW 字段"));
        appendName(KSW_CAP_CALLBACK_NOTIFY_GLOBALS, QStringLiteral("进程/线程/镜像回调全局"));
        appendName(KSW_CAP_CALLBACK_REGISTRY_GLOBALS, QStringLiteral("注册表回调全局"));
        appendName(KSW_CAP_CALLBACK_OBJECT_FIELDS, QStringLiteral("对象回调字段"));
        appendName(KSW_CAP_PROCESS_LIST_FIELDS, QStringLiteral("进程链表字段"));
        appendName(KSW_CAP_THREAD_LIST_FIELDS, QStringLiteral("线程链表字段"));
        appendName(KSW_CAP_CID_TABLE_WALK, QStringLiteral("CID 表遍历"));
        appendName(KSW_CAP_KERNEL_MODULE_LIST_FIELDS, QStringLiteral("内核模块链表字段"));
        appendName(KSW_CAP_DRIVER_OBJECT_FIELDS, QStringLiteral("驱动对象字段"));
        appendName(KSW_CAP_KERNEL_GLOBALS, QStringLiteral("内核全局 RVA"));

        if (names.isEmpty())
        {
            return missingMode
                ? QStringLiteral("无缺失能力（0x0）")
                : QStringLiteral("无已知能力（0x0）");
        }

        return QStringLiteral("%1（0x%2）")
            .arg(names.join(QStringLiteral("、")))
            .arg(static_cast<qulonglong>(mask), 0, 16)
            .toUpper();
    }

    // processRuntimeFieldListText：
    // - 输入 fieldFlags：进程 detail IOCTL 返回的字段覆盖位图；
    // - 处理：展开为 _EPROCESS/对象字段名，避免界面只展示 0x 位图；
    // - 返回：可读字段清单。
    QString processRuntimeFieldListText(const std::uint32_t fieldFlags)
    {
        QStringList fields;
        const auto appendField =
            [&fields, fieldFlags](const std::uint32_t bit, const QString& fieldText)
            {
                if ((fieldFlags & bit) != 0U)
                {
                    fields.push_back(fieldText);
                }
            };

        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY, QStringLiteral("PID/镜像名"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_ADDRESS, QStringLiteral("EPROCESS 地址"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID, QStringLiteral("_EPROCESS.UniqueProcessId"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_ACTIVE_PROCESS_LINKS, QStringLiteral("_EPROCESS.ActiveProcessLinks"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_THREAD_LIST_HEAD, QStringLiteral("_EPROCESS.ThreadListHead"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_IMAGE_FILE_NAME, QStringLiteral("_EPROCESS.ImageFileName"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_TOKEN_FASTREF, QStringLiteral("_EPROCESS.Token"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_TABLE, QStringLiteral("_EPROCESS.ObjectTable"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_OBJECT, QStringLiteral("_EPROCESS.SectionObject"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_PROTECTION, QStringLiteral("_EPROCESS.Protection"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SIGNATURE_LEVEL, QStringLiteral("_EPROCESS.SignatureLevel"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_SIGNATURE, QStringLiteral("_EPROCESS.SectionSignatureLevel"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OFFSET_SOURCES, QStringLiteral("偏移来源"));
        appendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_KERNEL_GLOBALS, QStringLiteral("ntoskrnl 全局 RVA"));

        return fields.isEmpty()
            ? QStringLiteral("未采集到进程运行时字段")
            : fields.join(QStringLiteral("、"));
    }

    // threadRuntimeFieldListText：
    // - 输入 fieldFlags：线程 detail IOCTL 返回的字段覆盖位图；
    // - 处理：展开为 ETHREAD/KTHREAD 字段名称；
    // - 返回：可读字段清单。
    QString threadRuntimeFieldListText(const std::uint32_t fieldFlags)
    {
        QStringList fields;
        const auto appendField =
            [&fields, fieldFlags](const std::uint32_t bit, const QString& fieldText)
            {
                if ((fieldFlags & bit) != 0U)
                {
                    fields.push_back(fieldText);
                }
            };

        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY, QStringLiteral("TID/PID"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS, QStringLiteral("ETHREAD 地址"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID, QStringLiteral("_ETHREAD.Cid"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY, QStringLiteral("_ETHREAD.ThreadListEntry"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS, QStringLiteral("_ETHREAD.StartAddress"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS, QStringLiteral("_ETHREAD.Win32StartAddress"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS, QStringLiteral("_KTHREAD.Process"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS, QStringLiteral("_KTHREAD 栈边界"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS, QStringLiteral("_KTHREAD I/O 计数"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES, QStringLiteral("偏移来源"));
        appendField(KSWORD_ARK_THREAD_DETAIL_FIELD_KERNEL_GLOBALS, QStringLiteral("ntoskrnl 全局 RVA"));

        return fields.isEmpty()
            ? QStringLiteral("未采集到线程运行时字段")
            : fields.join(QStringLiteral("、"));
    }

    // runtimeFieldSourceText：
    // - 输入 source：KSW_DYN_FIELD_SOURCE_* 来源值；
    // - 处理：转换为中文来源名称，避免 UI 展示裸数字；
    // - 返回：PDB profile/System Informer/runtime pattern 等可读文本。
    QString runtimeFieldSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer DynData");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("运行时模式识别");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword 扩展表");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        case KSW_DYN_FIELD_SOURCE_UNAVAILABLE:
        default:
            return QStringLiteral("不可用");
        }
    }

    // runtimeOffsetPresent：
    // - 输入 offset：shared 协议中的 offset/RVA；
    // - 处理：过滤 unavailable/0xffff sentinel；
    // - 返回：TRUE 表示可展示为有效偏移。
    bool runtimeOffsetPresent(const unsigned long offset)
    {
        return offset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL;
    }

    // runtimeOffsetText：
    // - 输入 offset：shared 协议中的 offset/RVA；
    // - 处理：可用时转十六进制，不可用时明确标注；
    // - 返回：面向详情文本的稳定显示值。
    QString runtimeOffsetText(const unsigned long offset)
    {
        if (!runtimeOffsetPresent(offset))
        {
            return QStringLiteral("<不可用>");
        }
        return uint64ToHex(static_cast<std::uint64_t>(offset));
    }

    // runtimeOffsetSourceItemText：
    // - 输入 name/offset/source：单个字段名、偏移和来源；
    // - 处理：组合成人可读证据片段；
    // - 返回：例如 “_EPROCESS.Token=0x4B8(PDB profile)”。
    QString runtimeOffsetSourceItemText(
        const QString& name,
        const unsigned long offset,
        const unsigned long source)
    {
        return QStringLiteral("%1=%2(%3)")
            .arg(name)
            .arg(runtimeOffsetText(offset))
            .arg(runtimeFieldSourceText(source));
    }

    // processRuntimeOffsetSourceText：
    // - 输入 response：进程 runtime detail 响应；
    // - 处理：展开进程相关 offset 与来源；
    // - 返回：一行可读来源清单。
    QString processRuntimeOffsetSourceText(const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response)
    {
        QStringList parts;
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.UniqueProcessId"),
            response.offsets.epUniqueProcessId,
            response.sources.epUniqueProcessId));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ActiveProcessLinks"),
            response.offsets.epActiveProcessLinks,
            response.sources.epActiveProcessLinks));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ThreadListHead"),
            response.offsets.epThreadListHead,
            response.sources.epThreadListHead));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ImageFileName"),
            response.offsets.epImageFileName,
            response.sources.epImageFileName));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.Token"),
            response.offsets.epToken,
            response.sources.epToken));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ObjectTable"),
            response.offsets.epObjectTable,
            response.sources.epObjectTable));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SectionObject"),
            response.offsets.epSectionObject,
            response.sources.epSectionObject));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.Protection"),
            response.offsets.epProtection,
            response.sources.epProtection));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SignatureLevel"),
            response.offsets.epSignatureLevel,
            response.sources.epSignatureLevel));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SectionSignatureLevel"),
            response.offsets.epSectionSignatureLevel,
            response.sources.epSectionSignatureLevel));
        return parts.join(QStringLiteral("；"));
    }

    // threadRuntimeOffsetSourceText：
    // - 输入 response：线程 runtime detail 响应；
    // - 处理：展开线程相关 offset 与来源；
    // - 返回：一行可读来源清单。
    QString threadRuntimeOffsetSourceText(const KSWORD_ARK_THREAD_DETAIL_RESPONSE& response)
    {
        QStringList parts;
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.Cid"),
            response.offsets.etCid,
            response.sources.etCid));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.ThreadListEntry"),
            response.offsets.etThreadListEntry,
            response.sources.etThreadListEntry));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.StartAddress"),
            response.offsets.etStartAddress,
            response.sources.etStartAddress));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.Win32StartAddress"),
            response.offsets.etWin32StartAddress,
            response.sources.etWin32StartAddress));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.Process"),
            response.offsets.ktProcess,
            response.sources.ktProcess));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.InitialStack"),
            response.offsets.ktInitialStack,
            response.sources.ktInitialStack));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.StackLimit"),
            response.offsets.ktStackLimit,
            response.sources.ktStackLimit));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.StackBase"),
            response.offsets.ktStackBase,
            response.sources.ktStackBase));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.KernelStack"),
            response.offsets.ktKernelStack,
            response.sources.ktKernelStack));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.ReadOperationCount"),
            response.offsets.ktReadOperationCount,
            response.sources.ktReadOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.WriteOperationCount"),
            response.offsets.ktWriteOperationCount,
            response.sources.ktWriteOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.OtherOperationCount"),
            response.offsets.ktOtherOperationCount,
            response.sources.ktOtherOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.ReadTransferCount"),
            response.offsets.ktReadTransferCount,
            response.sources.ktReadTransferCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.WriteTransferCount"),
            response.offsets.ktWriteTransferCount,
            response.sources.ktWriteTransferCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.OtherTransferCount"),
            response.offsets.ktOtherTransferCount,
            response.sources.ktOtherTransferCount));
        return parts.join(QStringLiteral("；"));
    }

    // runtimeKernelGlobalItemText：
    // - 输入 name/rva/source/address：全局符号名称、RVA、来源和当前 VA；
    // - 处理：把 PDB profile 的全局符号转换成人可读证据；
    // - 返回：单个全局符号的可读片段。
    QString runtimeKernelGlobalItemText(
        const QString& name,
        const unsigned long rva,
        const unsigned long source,
        const std::uint64_t address)
    {
        return QStringLiteral("%1: RVA=%2, VA=%3, 来源=%4")
            .arg(name)
            .arg(runtimeOffsetText(rva))
            .arg(address == 0ULL ? QStringLiteral("<不可用>") : uint64ToHex(address))
            .arg(runtimeFieldSourceText(source));
    }

    // runtimeKernelGlobalsText：
    // - 输入 globals：detail 响应内 ntoskrnl 全局 RVA 包；
    // - 处理：列出 CID/模块链表/卸载驱动/PiDDB/SSDT shadow 等关键全局符号；
    // - 返回：可直接进入详情页或 tooltip 的多项文本。
    QString runtimeKernelGlobalsText(const KSWORD_ARK_RUNTIME_KERNEL_GLOBALS& globals)
    {
        QStringList parts;
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PspCidTable"),
            globals.pspCidTableRva,
            globals.pspCidTableSource,
            globals.pspCidTableAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PsLoadedModuleList"),
            globals.psLoadedModuleListRva,
            globals.psLoadedModuleListSource,
            globals.psLoadedModuleListAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("MmUnloadedDrivers"),
            globals.mmUnloadedDriversRva,
            globals.mmUnloadedDriversSource,
            globals.mmUnloadedDriversAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PiDDBCacheTable"),
            globals.piDdbCacheTableRva,
            globals.piDdbCacheTableSource,
            globals.piDdbCacheTableAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("KeServiceDescriptorTableShadow"),
            globals.keServiceDescriptorTableShadowRva,
            globals.keServiceDescriptorTableShadowSource,
            globals.keServiceDescriptorTableShadowAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("MmLastUnloadedDriver"),
            globals.mmLastUnloadedDriverRva,
            globals.mmLastUnloadedDriverSource,
            globals.mmLastUnloadedDriverAddress));
        return parts.join(QStringLiteral("；"));
    }

    // runtimeSamplingSummaryText：
    // - 输入 rawDetailText：驱动固定 detail 文本；
    // - 处理：把常见英文采样日志折叠成中文说明，未知文本才保留摘要；
    // - 返回：面向用户的采样说明，避免表格最后一列直接塞 IOCTL 日志。
    QString runtimeSamplingSummaryText(const QString& rawDetailText, const QString& subjectText)
    {
        const QString trimmedText = rawDetailText.trimmed();
        if (trimmedText.isEmpty() || trimmedText == QStringLiteral("无额外说明"))
        {
            return QStringLiteral("%1运行时详情无额外驱动说明。").arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("sampled by"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1运行时字段已由驱动只读采样；字段覆盖、缺失能力和失败状态已在本行展开。")
                .arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情协议版本不匹配，请同步 R3/R0/shared 协议。").arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情受 DynData capability 限制，缺失能力已在本行列出。").arg(subjectText);
        }
        return trimmedText;
    }

    // readableRuntimeIoMessage：
    // - 输入 rawMessage：ArkDriverClient::IoResult::message，subjectText：页面/能力名称；
    // - 处理：把常见 DeviceIoControl/unsupported/capability/version/buffer 文本转换成中文说明；
    // - 返回：适合放入详情页、状态栏或表格最后一列的可读文本。
    QString readableRuntimeIoMessage(
        const QString& rawMessage,
        const QString& subjectText,
        const QString& fallbackText,
        const bool unsupported = false)
    {
        if (unsupported)
        {
            return QStringLiteral("%1当前驱动未提供对应只读详情入口。").arg(subjectText);
        }

        const QString trimmedText = rawMessage.trimmed();
        if (trimmedText.isEmpty())
        {
            return fallbackText;
        }
        if (trimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1当前驱动/协议暂不支持该只读详情入口。").arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            trimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1动态偏移能力未满足，请查看内核 DynData/Capability 状态。").arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情协议版本不匹配，请同步 R3/R0/shared 协议。").arg(subjectText);
        }
        if (trimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1驱动调用失败。原始错误：%2").arg(subjectText, trimmedText);
        }
        if (trimmedText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) &&
            trimmedText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1返回结果过多，当前只展示截断后的可用证据。").arg(subjectText);
        }
        return trimmedText;
    }

    // ntStatusHexText：
    // - 输入 NTSTATUS/Win32 状态值；
    // - 处理：统一补零大写十六进制；
    // - 返回：可复制到调试器或日志中的稳定文本。
    QString ntStatusHexText(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    // runtimeFieldSampleStatusText：
    // - 输入 sampler 响应级状态；
    // - 处理：转换为中文/英文混合短状态，避免 UI 展示裸数字；
    // - 返回：适合标题行的状态文本。
    QString runtimeFieldSampleStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段读取失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED:
            return QStringLiteral("LookupFailed（对象查找失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_INVALID_REQUEST:
            return QStringLiteral("InvalidRequest（请求无效）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_TRUNCATED:
            return QStringLiteral("Truncated（结果被截断）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(statusValue);
        }
    }

    // runtimeFieldSampleRowStatusText：
    // - 输入 sampler 行级状态；
    // - 处理：说明单字段读取是否成功、被拒绝还是读取失败；
    // - 返回：适合逐字段证据行展示的文本。
    QString runtimeFieldSampleRowStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK:
            return QStringLiteral("OK（已读取）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED:
            return QStringLiteral("OffsetRejected（偏移超过安全范围）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_SIZE_REJECTED:
            return QStringLiteral("SizeRejected（字段长度不适合采样）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed（对象字段读取失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(statusValue);
        }
    }

    // runtimeFieldSampleBytesText：
    // - 输入小字段原始字节；
    // - 处理：按十六进制紧凑拼接，避免不可打印字符污染详情页；
    // - 返回：例如 "40 04 00 00"，空值返回 <empty>。
    QString runtimeFieldSampleBytesText(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
        {
            return QStringLiteral("<empty>");
        }
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t byteValue : bytes)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(static_cast<unsigned int>(byteValue), 2, 16, QChar('0'))
                .toUpper());
        }
        return parts.join(QChar(' '));
    }

    // runtimeFieldSampleReadLeValue：
    // - 输入 bytes/offset/byteCount：sampler 返回的小字段原始字节；
    // - 处理：按 Windows x64 小端序解释为最多 8 字节无符号值；
    // - 返回：成功时 valueOut 写入整数，失败返回 false。
    bool runtimeFieldSampleReadLeValue(
        const std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::size_t byteCount,
        std::uint64_t& valueOut)
    {
        valueOut = 0ULL;
        if (byteCount == 0U || byteCount > sizeof(std::uint64_t))
        {
            return false;
        }
        if (offset > bytes.size() || bytes.size() - offset < byteCount)
        {
            return false;
        }

        for (std::size_t byteIndex = 0; byteIndex < byteCount; ++byteIndex)
        {
            valueOut |= static_cast<std::uint64_t>(bytes[offset + byteIndex]) << (byteIndex * 8U);
        }
        return true;
    }

    // runtimeFieldSampleDecimalHexText：
    // - 输入 value：已经解释出的整数或句柄值；
    // - 处理：同时输出十进制和十六进制，便于 PID/TID 与地址双向核对；
    // - 返回：例如 "1234 (0x00000000000004D2)"。
    QString runtimeFieldSampleDecimalHexText(const std::uint64_t value)
    {
        return QStringLiteral("%1 (%2)")
            .arg(QString::number(static_cast<qulonglong>(value)))
            .arg(uint64ToHex(value));
    }

    // runtimeFieldSampleAsciiText：
    // - 输入 bytes：PDB sampler 返回的 char[] 字节；
    // - 处理：截断到 NUL，非可打印字符用 "." 占位；
    // - 返回：适合展示 _EPROCESS.ImageFileName 等短 ASCII 字段。
    QString runtimeFieldSampleAsciiText(const std::vector<std::uint8_t>& bytes)
    {
        QString text;
        for (const std::uint8_t byteValue : bytes)
        {
            if (byteValue == 0U)
            {
                break;
            }
            if (byteValue >= 0x20U && byteValue <= 0x7EU)
            {
                text.append(QChar(static_cast<ushort>(byteValue)));
            }
            else
            {
                text.append(QChar('.'));
            }
        }

        if (text.isEmpty())
        {
            return QStringLiteral("<空字符串或不可打印>");
        }
        return QStringLiteral("\"%1\"").arg(text);
    }

    // runtimeFieldSampleTypeOrUnknown：
    // - 输入 entry：R3 sampler 行；
    // - 处理：把 PDB 字段类型转换为 QString，并为空类型补占位；
    // - 返回：用于字段标题和解释器判断的类型文本。
    QString runtimeFieldSampleTypeOrUnknown(const ksword::ark::RuntimeFieldSampleEntry& entry)
    {
        const QString typeText = QString::fromStdString(entry.type).trimmed();
        if (typeText.isEmpty())
        {
            return QStringLiteral("<unknown>");
        }
        return typeText;
    }

    // runtimeFieldSampleNameOrId：
    // - 输入 entry：R0 sampler 行和 R3 请求元数据；
    // - 处理：优先使用 PDB qualifiedName，缺失时退回 runtimeItemId；
    // - 返回：人读字段名。
    QString runtimeFieldSampleNameOrId(const ksword::ark::RuntimeFieldSampleEntry& entry)
    {
        const QString nameText = QString::fromStdString(entry.name).trimmed();
        if (!nameText.isEmpty())
        {
            return nameText;
        }
        return QStringLiteral("runtimeItemId=%1").arg(uint64ToHex(entry.runtimeItemId));
    }

    // runtimeFieldSampleUnicodeStringText：
    // - 输入 bytes：_UNICODE_STRING 结构头采样，x64 下 Buffer 位于偏移 8；
    // - 处理：只解释结构头，不跟随读取远程字符串，避免 UI 触发额外内核读取；
    // - 返回：Length/MaximumLength/Buffer 三元组。
    QString runtimeFieldSampleUnicodeStringText(const std::vector<std::uint8_t>& bytes)
    {
        std::uint64_t lengthValue = 0ULL;
        std::uint64_t maximumLengthValue = 0ULL;
        std::uint64_t bufferValue = 0ULL;
        const bool lengthOk = runtimeFieldSampleReadLeValue(bytes, 0U, sizeof(std::uint16_t), lengthValue);
        const bool maximumOk = runtimeFieldSampleReadLeValue(bytes, 2U, sizeof(std::uint16_t), maximumLengthValue);
        const bool bufferOk = runtimeFieldSampleReadLeValue(bytes, 8U, sizeof(std::uint64_t), bufferValue);
        if (!lengthOk || !maximumOk || !bufferOk)
        {
            return QStringLiteral("UNICODE_STRING 头部字节不足，无法解释。");
        }

        return QStringLiteral("UNICODE_STRING Length=%1, MaximumLength=%2, Buffer=%3")
            .arg(static_cast<unsigned long long>(lengthValue))
            .arg(static_cast<unsigned long long>(maximumLengthValue))
            .arg(uint64ToHex(bufferValue));
    }

    // runtimeFieldSamplePairPointersText：
    // - 输入 bytes/nameA/nameB：两个连续 x64 指针或句柄字段；
    // - 处理：解释 CLIENT_ID、LIST_ENTRY 这类 16 字节小结构；
    // - 返回：带字段名的双值摘要。
    QString runtimeFieldSamplePairPointersText(
        const std::vector<std::uint8_t>& bytes,
        const QString& nameA,
        const QString& nameB,
        const bool decimalHint)
    {
        std::uint64_t firstValue = 0ULL;
        std::uint64_t secondValue = 0ULL;
        const bool firstOk = runtimeFieldSampleReadLeValue(bytes, 0U, sizeof(std::uint64_t), firstValue);
        const bool secondOk = runtimeFieldSampleReadLeValue(bytes, 8U, sizeof(std::uint64_t), secondValue);
        if (!firstOk || !secondOk)
        {
            return QStringLiteral("%1/%2 字节不足，无法解释。").arg(nameA).arg(nameB);
        }

        const QString firstText = decimalHint
            ? runtimeFieldSampleDecimalHexText(firstValue)
            : uint64ToHex(firstValue);
        const QString secondText = decimalHint
            ? runtimeFieldSampleDecimalHexText(secondValue)
            : uint64ToHex(secondValue);
        return QStringLiteral("%1=%2, %3=%4")
            .arg(nameA)
            .arg(firstText)
            .arg(nameB)
            .arg(secondText);
    }

    // runtimeFieldSampleFastRefText：
    // - 输入 rawValue：_EX_FAST_REF 原始 64 位值；
    // - 处理：拆分低 4 位 fast-ref 计数和对齐后的对象地址；
    // - 返回：Token/ObjectTable 等 fast reference 字段的人读解释。
    QString runtimeFieldSampleFastRefText(const std::uint64_t rawValue)
    {
        const std::uint64_t objectAddress = rawValue & ~0xFULL;
        const std::uint64_t refCount = rawValue & 0xFULL;
        return QStringLiteral("EX_FAST_REF raw=%1, object=%2, refBits=%3")
            .arg(uint64ToHex(rawValue))
            .arg(uint64ToHex(objectAddress))
            .arg(static_cast<unsigned long long>(refCount));
    }

    // runtimeFieldSampleProtectionText：
    // - 输入 rawValue：_PS_PROTECTION/UCHAR 原始保护位；
    // - 处理：按 Type/Audit/Signer 位域拆解，方便直接看 PPL/保护等级；
    // - 返回：进程保护字段的人读解释。
    QString runtimeFieldSampleProtectionText(const std::uint64_t rawValue)
    {
        const std::uint64_t typeValue = rawValue & 0x7ULL;
        const std::uint64_t auditValue = (rawValue >> 3U) & 0x1ULL;
        const std::uint64_t signerValue = (rawValue >> 4U) & 0xFULL;
        return QStringLiteral("PS_PROTECTION raw=%1, Type=%2, Audit=%3, Signer=%4")
            .arg(uint64ToHex(rawValue & 0xFFULL))
            .arg(static_cast<unsigned long long>(typeValue))
            .arg(static_cast<unsigned long long>(auditValue))
            .arg(static_cast<unsigned long long>(signerValue));
    }

    // runtimeFieldSamplePointerLike：
    // - 输入 name/type：PDB 字段名和字段类型；
    // - 处理：判断当前字段更适合按地址/句柄展示还是按普通整数展示；
    // - 返回：true 表示首选 uint64ToHex 地址样式。
    bool runtimeFieldSamplePointerLike(const QString& nameText, const QString& typeText)
    {
        const QString combinedText = QStringLiteral("%1 %2")
            .arg(nameText)
            .arg(typeText)
            .toLower();
        return combinedText.contains(QChar('*')) ||
            combinedText.contains(QStringLiteral("ptr")) ||
            combinedText.contains(QStringLiteral("pvoid")) ||
            combinedText.contains(QStringLiteral("handle")) ||
            combinedText.contains(QStringLiteral("address")) ||
            combinedText.contains(QStringLiteral("objecttable")) ||
            combinedText.contains(QStringLiteral("sectionobject")) ||
            combinedText.contains(QStringLiteral("startaddress")) ||
            combinedText.contains(QStringLiteral("kernelstack")) ||
            combinedText.contains(QStringLiteral("initialstack")) ||
            combinedText.contains(QStringLiteral("stackbase")) ||
            combinedText.contains(QStringLiteral("stacklimit")) ||
            combinedText.contains(QStringLiteral(".process"));
    }

    // runtimeFieldSampleInterpretedValue：
    // - 输入 entry/name/type：sampler 单行和 PDB 元数据；
    // - 处理：按常见内核结构字段解释短字节，避免只展示 valueU64/hex bytes；
    // - 返回：人读解释；无法识别时仍返回整数或原始字节摘要。
    QString runtimeFieldSampleInterpretedValue(
        const ksword::ark::RuntimeFieldSampleEntry& entry,
        const QString& nameText,
        const QString& typeText)
    {
        const QString lowerName = nameText.toLower();
        const QString lowerType = typeText.toLower();
        const std::vector<std::uint8_t>& bytes = entry.sampleBytes;
        if (entry.status != KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK)
        {
            return QStringLiteral("未解释：字段未成功读取。");
        }
        if (bytes.empty() || entry.bytesRead == 0U)
        {
            return QStringLiteral("未解释：R0 未返回字段字节。");
        }

        if (lowerName.contains(QStringLiteral("imagefilename")) ||
            lowerType.contains(QStringLiteral("char[")))
        {
            return QStringLiteral("ASCII=%1").arg(runtimeFieldSampleAsciiText(bytes));
        }
        if (lowerType.contains(QStringLiteral("_client_id")) ||
            lowerName.endsWith(QStringLiteral(".cid")))
        {
            return runtimeFieldSamplePairPointersText(
                bytes,
                QStringLiteral("UniqueProcess"),
                QStringLiteral("UniqueThread"),
                true);
        }
        if (lowerType.contains(QStringLiteral("_list_entry")) ||
            lowerName.contains(QStringLiteral("activeprocesslinks")) ||
            lowerName.contains(QStringLiteral("threadlistentry")) ||
            lowerName.contains(QStringLiteral("threadlisthead")) ||
            lowerName.contains(QStringLiteral("inloadorderlinks")))
        {
            return runtimeFieldSamplePairPointersText(
                bytes,
                QStringLiteral("Flink"),
                QStringLiteral("Blink"),
                false);
        }
        if (lowerType.contains(QStringLiteral("_unicode_string")))
        {
            return runtimeFieldSampleUnicodeStringText(bytes);
        }

        std::uint64_t rawValue = 0ULL;
        const std::size_t readableSize = std::min<std::size_t>(
            bytes.size(),
            std::min<std::size_t>(entry.size, sizeof(std::uint64_t)));
        const bool rawOk = runtimeFieldSampleReadLeValue(bytes, 0U, readableSize, rawValue);
        if (!rawOk)
        {
            return QStringLiteral("原始字节=%1").arg(runtimeFieldSampleBytesText(bytes));
        }
        if (lowerType.contains(QStringLiteral("_ex_fast_ref")) ||
            lowerName.endsWith(QStringLiteral(".token")))
        {
            return runtimeFieldSampleFastRefText(rawValue);
        }
        if (lowerType.contains(QStringLiteral("_ps_protection")) ||
            lowerName.contains(QStringLiteral("protection")))
        {
            return runtimeFieldSampleProtectionText(rawValue);
        }
        if (lowerName.contains(QStringLiteral("uniqueprocessid")))
        {
            return QStringLiteral("PID=%1").arg(runtimeFieldSampleDecimalHexText(rawValue));
        }
        if (runtimeFieldSamplePointerLike(nameText, typeText))
        {
            return QStringLiteral("Pointer=%1").arg(uint64ToHex(rawValue));
        }
        return QStringLiteral("Integer=%1").arg(runtimeFieldSampleDecimalHexText(rawValue));
    }

    // runtimeFieldSampleResultText：
    // - 输入 ArkDriverClient sampler 结果和标题；
    // - 处理：展开 response header 与每个字段的 offset/value/status；
    // - 返回：可直接写入 CodeEditorWidget 的人读文本。
    QString runtimeFieldSampleResultText(
        const ksword::ark::RuntimeFieldSampleResult& result,
        const QString& titleText)
    {
        QStringList lines;
        lines << QStringLiteral("[%1]").arg(titleText);
        if (!result.io.ok)
        {
            lines << readableRuntimeIoMessage(
                QString::fromStdString(result.io.message),
                titleText,
                QStringLiteral("PDB deep runtime sampler 暂不可用。"),
                result.unsupported);
            return lines.join(QChar('\n'));
        }

        lines << QStringLiteral("Status: %1").arg(runtimeFieldSampleStatusText(result.status));
        lines << QStringLiteral("Object: %1").arg(uint64ToHex(result.objectAddress));
        lines << QStringLiteral("Returned/Total: %1/%2").arg(result.returnedCount).arg(result.totalCount);
        lines << QStringLiteral("DynDataCapability: %1").arg(uint64ToHex(result.dynDataCapabilityMask));
        lines << QStringLiteral("LastStatus: %1").arg(ntStatusHexText(result.lastStatus));
        if (result.entries.empty())
        {
            lines << QStringLiteral("  <没有返回字段行>");
            return lines.join(QChar('\n'));
        }

        for (const ksword::ark::RuntimeFieldSampleEntry& entry : result.entries)
        {
            const QString nameText = runtimeFieldSampleNameOrId(entry);
            const QString typeText = runtimeFieldSampleTypeOrUnknown(entry);
            lines << QStringLiteral("  - %1").arg(nameText);
            lines << QStringLiteral("      Type: %1").arg(typeText);
            lines << QStringLiteral("      Offset/Size: %1 / %2 bytes, BytesRead=%3")
                .arg(uint64ToHex(entry.offset))
                .arg(entry.size)
                .arg(entry.bytesRead);
            lines << QStringLiteral("      Status: %1, LastStatus=%2")
                .arg(runtimeFieldSampleRowStatusText(entry.status))
                .arg(ntStatusHexText(entry.lastStatus));
            lines << QStringLiteral("      Value: %1")
                .arg(runtimeFieldSampleInterpretedValue(entry, nameText, typeText));
            lines << QStringLiteral("      Raw: valueU64=%1, bytes=[%2], runtimeItemId=%3, flags=%4")
                .arg(uint64ToHex(entry.valueU64))
                .arg(runtimeFieldSampleBytesText(entry.sampleBytes))
                .arg(uint64ToHex(entry.runtimeItemId))
                .arg(uint64ToHex(entry.flags));
        }
        return lines.join(QChar('\n'));
    }

    // readThreadUserStackFromTeb：
    // - 从目标进程 TEB 的 NT_TIB 起始字段读取用户栈边界；
    // - 失败只影响调用栈窗口的边界提示，不影响线程行本身展示。
    bool readThreadUserStackFromTeb(
        HANDLE processHandle,
        const std::uint64_t tebAddress,
        std::uint64_t& stackBaseOut,
        std::uint64_t& stackLimitOut)
    {
        stackBaseOut = 0;
        stackLimitOut = 0;
        if (processHandle == nullptr || tebAddress == 0)
        {
            return false;
        }

        NT_TIB tibSnapshot{};
        SIZE_T bytesRead = 0;
        const BOOL readOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(tebAddress)),
            &tibSnapshot,
            sizeof(tibSnapshot),
            &bytesRead);
        if (readOk == FALSE || bytesRead < sizeof(PVOID) * 2)
        {
            return false;
        }

        stackBaseOut = reinterpret_cast<std::uint64_t>(tibSnapshot.StackBase);
        stackLimitOut = reinterpret_cast<std::uint64_t>(tibSnapshot.StackLimit);
        return true;
    }

    // queryTokenInfoBuffer：
    // - 统一读取令牌信息；
    // - 成功时把字节内容写入 bufferOut。
    bool queryTokenInfoBuffer(
        HANDLE tokenHandle,
        TOKEN_INFORMATION_CLASS infoClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        DWORD requiredLength = 0;
        GetTokenInformation(tokenHandle, infoClass, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            return false;
        }

        bufferOut.resize(requiredLength);
        const BOOL queryOk = GetTokenInformation(
            tokenHandle,
            infoClass,
            bufferOut.data(),
            requiredLength,
            &requiredLength);
        return queryOk != FALSE;
    }

    // formatNtStatusHex：
    // - 把 NTSTATUS 转成 0xXXXXXXXX 十六进制文本；
    // - 供令牌开关应用失败时拼接可审计的错误细节。
    QString formatNtStatusHex(const NTSTATUS statusCode)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();
    }

    // queryTokenBoolFlag：
    // - 读取“ULONG 布尔位”类型令牌字段；
    // - 成功时输出 bool 值，失败返回 false。
    bool queryTokenBoolFlag(
        HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS infoClass,
        bool& valueOut)
    {
        ULONG rawValue = 0;
        DWORD returnLength = 0;
        const BOOL queryOk = GetTokenInformation(
            tokenHandle,
            infoClass,
            &rawValue,
            static_cast<DWORD>(sizeof(rawValue)),
            &returnLength);
        if (queryOk == FALSE || returnLength < sizeof(rawValue))
        {
            return false;
        }
        valueOut = (rawValue != 0);
        return true;
    }

    // queryTokenMandatoryPolicyBits：
    // - 读取 TokenMandatoryPolicy 并拆分两个复选框位；
    // - 输出 NoWriteUp / NewProcessMin 两个布尔值。
    bool queryTokenMandatoryPolicyBits(
        HANDLE tokenHandle,
        bool& noWriteUpOut,
        bool& newProcessMinOut)
    {
        TOKEN_MANDATORY_POLICY mandatoryPolicy{};
        DWORD returnLength = 0;
        const BOOL queryOk = GetTokenInformation(
            tokenHandle,
            TokenMandatoryPolicy,
            &mandatoryPolicy,
            static_cast<DWORD>(sizeof(mandatoryPolicy)),
            &returnLength);
        if (queryOk == FALSE || returnLength < sizeof(mandatoryPolicy))
        {
            return false;
        }
        noWriteUpOut = (mandatoryPolicy.Policy & kTokenMandatoryPolicyNoWriteUp) != 0;
        newProcessMinOut = (mandatoryPolicy.Policy & kTokenMandatoryPolicyNewProcessMin) != 0;
        return true;
    }

    // applyTokenBoolFlag：
    // - 使用 NtSetInformationToken 写入 ULONG 布尔位；
    // - 返回 NTSTATUS 以便调用者记录逐项失败原因。
    NTSTATUS applyTokenBoolFlag(
        const NtSetInformationTokenFn setInformationToken,
        HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS infoClass,
        const bool enabled)
    {
        if (setInformationToken == nullptr || tokenHandle == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000000DL);
        }
        ULONG rawValue = enabled ? 1UL : 0UL;
        return setInformationToken(
            tokenHandle,
            infoClass,
            &rawValue,
            static_cast<ULONG>(sizeof(rawValue)));
    }

    // applyTokenMandatoryPolicyBits：
    // - 把两个策略复选框合成为 TOKEN_MANDATORY_POLICY；
    // - 使用 NtSetInformationToken 一次性写入策略位。
    NTSTATUS applyTokenMandatoryPolicyBits(
        const NtSetInformationTokenFn setInformationToken,
        HANDLE tokenHandle,
        const bool noWriteUpEnabled,
        const bool newProcessMinEnabled)
    {
        if (setInformationToken == nullptr || tokenHandle == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000000DL);
        }

        TOKEN_MANDATORY_POLICY mandatoryPolicy{};
        mandatoryPolicy.Policy = 0;
        if (noWriteUpEnabled)
        {
            mandatoryPolicy.Policy |= kTokenMandatoryPolicyNoWriteUp;
        }
        if (newProcessMinEnabled)
        {
            mandatoryPolicy.Policy |= kTokenMandatoryPolicyNewProcessMin;
        }
        return setInformationToken(
            tokenHandle,
            TokenMandatoryPolicy,
            &mandatoryPolicy,
            static_cast<ULONG>(sizeof(mandatoryPolicy)));
    }

    // describeIntegrityLevel：
    // - 完整性 RID 转文本。
    QString describeIntegrityLevel(const DWORD integrityRid)
    {
        switch (integrityRid)
        {
        case SECURITY_MANDATORY_UNTRUSTED_RID: return QStringLiteral("Untrusted");
        case SECURITY_MANDATORY_LOW_RID: return QStringLiteral("Low");
        case SECURITY_MANDATORY_MEDIUM_RID: return QStringLiteral("Medium");
        case SECURITY_MANDATORY_HIGH_RID: return QStringLiteral("High");
        case SECURITY_MANDATORY_SYSTEM_RID: return QStringLiteral("System");
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return QStringLiteral("ProtectedProcess");
        default: return QString("RID=%1").arg(integrityRid);
        }
    }

    // describePriorityClass：
    // - 优先级类常量转文本。
    QString describePriorityClass(const DWORD priorityClass)
    {
        switch (priorityClass)
        {
        case IDLE_PRIORITY_CLASS: return QStringLiteral("IDLE");
        case BELOW_NORMAL_PRIORITY_CLASS: return QStringLiteral("BELOW_NORMAL");
        case NORMAL_PRIORITY_CLASS: return QStringLiteral("NORMAL");
        case ABOVE_NORMAL_PRIORITY_CLASS: return QStringLiteral("ABOVE_NORMAL");
        case HIGH_PRIORITY_CLASS: return QStringLiteral("HIGH");
        case REALTIME_PRIORITY_CLASS: return QStringLiteral("REALTIME");
        default: return QString("UNKNOWN(%1)").arg(priorityClass);
        }
    }

    // tokenInfoClassNameById：
    // - 把 TokenInformationClass 数值映射到名称；
    // - 未知编号统一显示 TokenClassN，避免信息丢失。
    QString tokenInfoClassNameById(const ULONG classId)
    {
        switch (classId)
        {
        case 1: return QStringLiteral("TokenUser");
        case 2: return QStringLiteral("TokenGroups");
        case 3: return QStringLiteral("TokenPrivileges");
        case 4: return QStringLiteral("TokenOwner");
        case 5: return QStringLiteral("TokenPrimaryGroup");
        case 6: return QStringLiteral("TokenDefaultDacl");
        case 7: return QStringLiteral("TokenSource");
        case 8: return QStringLiteral("TokenType");
        case 9: return QStringLiteral("TokenImpersonationLevel");
        case 10: return QStringLiteral("TokenStatistics");
        case 11: return QStringLiteral("TokenRestrictedSids");
        case 12: return QStringLiteral("TokenSessionId");
        case 13: return QStringLiteral("TokenGroupsAndPrivileges");
        case 14: return QStringLiteral("TokenSessionReference");
        case 15: return QStringLiteral("TokenSandBoxInert");
        case 16: return QStringLiteral("TokenAuditPolicy");
        case 17: return QStringLiteral("TokenOrigin");
        case 18: return QStringLiteral("TokenElevationType");
        case 19: return QStringLiteral("TokenLinkedToken");
        case 20: return QStringLiteral("TokenElevation");
        case 21: return QStringLiteral("TokenHasRestrictions");
        case 22: return QStringLiteral("TokenAccessInformation");
        case 23: return QStringLiteral("TokenVirtualizationAllowed");
        case 24: return QStringLiteral("TokenVirtualizationEnabled");
        case 25: return QStringLiteral("TokenIntegrityLevel");
        case 26: return QStringLiteral("TokenUIAccess");
        case 27: return QStringLiteral("TokenMandatoryPolicy");
        case 28: return QStringLiteral("TokenLogonSid");
        case 29: return QStringLiteral("TokenIsAppContainer");
        case 30: return QStringLiteral("TokenCapabilities");
        case 31: return QStringLiteral("TokenAppContainerSid");
        case 32: return QStringLiteral("TokenAppContainerNumber");
        case 33: return QStringLiteral("TokenUserClaimAttributes");
        case 34: return QStringLiteral("TokenDeviceClaimAttributes");
        case 35: return QStringLiteral("TokenRestrictedUserClaimAttributes");
        case 36: return QStringLiteral("TokenRestrictedDeviceClaimAttributes");
        case 37: return QStringLiteral("TokenDeviceGroups");
        case 38: return QStringLiteral("TokenRestrictedDeviceGroups");
        case 39: return QStringLiteral("TokenSecurityAttributes");
        case 40: return QStringLiteral("TokenIsRestricted");
        case 41: return QStringLiteral("TokenProcessTrustLevel");
        case 42: return QStringLiteral("TokenPrivateNameSpace");
        case 43: return QStringLiteral("TokenSingletonAttributes");
        case 44: return QStringLiteral("TokenBnoIsolation");
        case 45: return QStringLiteral("TokenChildProcessFlags");
        case 46: return QStringLiteral("TokenIsLessPrivilegedAppContainer");
        case 47: return QStringLiteral("TokenIsSandboxed");
        case 48: return QStringLiteral("TokenOriginatingProcessTrustLevel");
        case 49: return QStringLiteral("TokenLoggingInformation");
        case 50: return QStringLiteral("TokenLearningMode");
        case 51: return QStringLiteral("TokenIsAppSilo");
        default: return QStringLiteral("TokenClass%1").arg(classId);
        }
    }

    // formatTokenRawPreview：
    // - 把原始字节缓冲区前 N 字节格式化为十六进制预览；
    // - 输出形如 "01 00 FF ..."，便于快速比对当前值。
    QString formatTokenRawPreview(const std::vector<std::uint8_t>& rawBuffer, const std::size_t maxBytes)
    {
        if (rawBuffer.empty() || maxBytes == 0)
        {
            return QStringLiteral("-");
        }

        QStringList byteTextList;
        const std::size_t previewCount = std::min<std::size_t>(rawBuffer.size(), maxBytes);
        byteTextList.reserve(static_cast<int>(previewCount) + 1);
        for (std::size_t index = 0; index < previewCount; ++index)
        {
            byteTextList << QStringLiteral("%1")
                .arg(static_cast<unsigned int>(rawBuffer[index]), 2, 16, QChar('0'))
                .toUpper();
        }
        if (rawBuffer.size() > previewCount)
        {
            byteTextList << QStringLiteral("...");
        }
        return byteTextList.join(QStringLiteral(" "));
    }
}

void ProcessDetailWindow::updateThreadInspectStatusLabel(const QString& statusText, const bool refreshing)
{
    // 状态标签刷新：
    // - refreshing=true 显示蓝色进行中；
    // - false 显示灰色完成态。
    if (m_threadInspectStatusLabel == nullptr)
    {
        return;
    }

    m_threadInspectStatusLabel->setText(statusText);
    m_threadInspectStatusLabel->setStyleSheet(
        refreshing
        ? buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700)
        : buildStateLabelStyle(statusSecondaryColor(), 600));
}

void ProcessDetailWindow::requestAsyncThreadInspectRefresh()
{
    // 防重入与非法 PID 保护。
    if (m_threadInspectRefreshing || m_baseRecord.pid == 0)
    {
        return;
    }

    // 线程细节刷新一旦真正排队，即认为线程页已完成首刷调度。
    // 用户手动刷新和自动懒加载共享这个标记，避免重复排队。
    m_threadInspectInitialRefreshStarted = true;

    m_threadInspectRefreshing = true;
    const std::uint64_t ticketValue = ++m_threadInspectRefreshTicket;
    updateThreadInspectStatusLabel(QStringLiteral("● 正在刷新线程细节..."), true);
    if (m_refreshThreadInspectButton != nullptr)
    {
        m_refreshThreadInspectButton->setEnabled(false);
    }

    if (m_threadInspectRefreshProgressPid == 0)
    {
        m_threadInspectRefreshProgressPid = kPro.addReusable(this, "进程详情", "刷新线程细节");
    }
    kPro.set(m_threadInspectRefreshProgressPid, "扫描线程信息", 0, 20.0f);

    const std::uint32_t pidValue = m_baseRecord.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, pidValue, ticketValue]()
        {
            ThreadInspectRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();
            std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0ThreadByTid;
            const ksword::ark::DriverClient driverClient;

            // R0 线程扩展是可选增强：驱动未加载或 DynData 不满足时，R3 线程枚举继续展示。
            const ksword::ark::ThreadEnumResult r0ThreadResult =
                driverClient.enumerateThreads(
                    KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL,
                    pidValue);
            if (r0ThreadResult.io.ok)
            {
                r0ThreadByTid.reserve(r0ThreadResult.entries.size());
                for (const ksword::ark::ThreadEntry& r0Entry : r0ThreadResult.entries)
                {
                    if (r0Entry.threadId != 0U)
                    {
                        r0ThreadByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
                    }
                }
            }
            else
            {
                const QString rawThreadIoMessage =
                    QString::fromStdString(r0ThreadResult.io.message).trimmed();
                const QString readableThreadIoMessage = readableRuntimeIoMessage(
                    rawThreadIoMessage,
                    QStringLiteral("R0线程扩展"),
                    QStringLiteral("无额外驱动消息。"),
                    false);
                refreshResult.diagnosticText = QStringLiteral("R0线程扩展不可用: %1")
                    .arg(readableThreadIoMessage);
            }

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pidValue);
            if (processHandle == nullptr)
            {
                if (!refreshResult.diagnosticText.trimmed().isEmpty())
                {
                    refreshResult.diagnosticText += QStringLiteral(" | ");
                }
                refreshResult.diagnosticText += QStringLiteral("OpenProcess读取TEB失败(%1)").arg(GetLastError());
            }

            HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshotHandle == INVALID_HANDLE_VALUE)
            {
                if (!refreshResult.diagnosticText.trimmed().isEmpty())
                {
                    refreshResult.diagnosticText += QStringLiteral(" | ");
                }
                refreshResult.diagnosticText += QString("CreateToolhelp32Snapshot失败(%1)").arg(GetLastError());
            }
            else
            {
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationThreadFn ntQueryThread = nullptr;
                if (ntdllModule != nullptr)
                {
                    ntQueryThread = reinterpret_cast<NtQueryInformationThreadFn>(
                        GetProcAddress(ntdllModule, "NtQueryInformationThread"));
                }

                THREADENTRY32 threadEntry{};
                threadEntry.dwSize = sizeof(threadEntry);
                BOOL hasThread = Thread32First(snapshotHandle, &threadEntry);
                while (hasThread != FALSE)
                {
                    if (threadEntry.th32OwnerProcessID == pidValue)
                    {
                        ThreadInspectItem rowItem{};
                        rowItem.threadId = threadEntry.th32ThreadID;
                        rowItem.processId = pidValue;
                        rowItem.stateText = QStringLiteral("Unknown");
                        rowItem.priorityValue = 0;
                        rowItem.switchCount = 0;
                        rowItem.startAddressText = QStringLiteral("-");
                        rowItem.tebAddressText = QStringLiteral("-");
                        rowItem.affinityText = QStringLiteral("-");
                        rowItem.registerSummaryText = QStringLiteral("-");

                        HANDLE threadHandle = OpenThread(
                            THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                            FALSE,
                            threadEntry.th32ThreadID);
                        if (threadHandle != nullptr)
                        {
                            FILETIME createTime{};
                            FILETIME exitTime{};
                            FILETIME kernelTime{};
                            FILETIME userTime{};
                            if (GetThreadTimes(
                                threadHandle,
                                &createTime,
                                &exitTime,
                                &kernelTime,
                                &userTime) != FALSE)
                            {
                                rowItem.createTime100ns =
                                    (static_cast<std::uint64_t>(createTime.dwHighDateTime) << 32U) |
                                    static_cast<std::uint64_t>(createTime.dwLowDateTime);
                            }
                            rowItem.priorityValue = GetThreadPriority(threadHandle);
                            if (ntQueryThread != nullptr)
                            {
                                ThreadBasicInformationNative basicInfo{};
                                NTSTATUS basicStatus = ntQueryThread(
                                    threadHandle,
                                    0,
                                    &basicInfo,
                                    static_cast<ULONG>(sizeof(basicInfo)),
                                    nullptr);
                                if (NT_SUCCESS(basicStatus))
                                {
                                    rowItem.tebAddress =
                                        reinterpret_cast<std::uint64_t>(basicInfo.tebBaseAddress);
                                    rowItem.tebAddressText = uint64ToHex(
                                        rowItem.tebAddress);
                                    rowItem.affinityText = uint64ToHex(basicInfo.affinityMask);
                                    rowItem.stateText = (basicInfo.exitStatus == STATUS_PENDING)
                                        ? QStringLiteral("Running")
                                        : QStringLiteral("Exited");
                                    std::uint64_t userStackBase = 0;
                                    std::uint64_t userStackLimit = 0;
                                    if (readThreadUserStackFromTeb(
                                        processHandle,
                                        rowItem.tebAddress,
                                        userStackBase,
                                        userStackLimit))
                                    {
                                        rowItem.userStackBase = userStackBase;
                                        rowItem.userStackLimit = userStackLimit;
                                    }
                                }

                                PVOID startAddress = nullptr;
                                NTSTATUS startStatus = ntQueryThread(
                                    threadHandle,
                                    9,
                                    &startAddress,
                                    static_cast<ULONG>(sizeof(startAddress)),
                                    nullptr);
                                if (NT_SUCCESS(startStatus))
                                {
                                    rowItem.startAddress =
                                        reinterpret_cast<std::uint64_t>(startAddress);
                                    rowItem.win32StartAddress = rowItem.startAddress;
                                    rowItem.startAddressText = uint64ToHex(
                                        rowItem.startAddress);
                                }
                            }

                            CONTEXT threadContext{};
                            threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                            const DWORD suspendCount = SuspendThread(threadHandle);
                            if (suspendCount != static_cast<DWORD>(-1))
                            {
                                const BOOL contextOk = GetThreadContext(threadHandle, &threadContext);
                                ResumeThread(threadHandle);
                                if (contextOk != FALSE)
                                {
#if defined(_M_X64)
                                    rowItem.registerSummaryText = QString("RIP=%1 RSP=%2")
                                        .arg(uint64ToHex(threadContext.Rip))
                                        .arg(uint64ToHex(threadContext.Rsp));
#elif defined(_M_IX86)
                                    rowItem.registerSummaryText = QString("EIP=%1 ESP=%2")
                                        .arg(uint64ToHex(threadContext.Eip))
                                        .arg(uint64ToHex(threadContext.Esp));
#else
                                    rowItem.registerSummaryText = QStringLiteral("当前架构未实现");
#endif
                                }
                            }
                            CloseHandle(threadHandle);
                        }
                        else
                        {
                            rowItem.stateText = QStringLiteral("AccessDenied");
                        }

                        const auto r0It = r0ThreadByTid.find(rowItem.threadId);
                        if (r0It != r0ThreadByTid.end() && r0It->second != nullptr)
                        {
                            // 合并 R0 KTHREAD 扩展：
                            // - 这些字段仅用于边界诊断；
                            // - 不把内核地址作为后续 IOCTL 的输入凭据。
                            rowItem.r0ThreadStatus = r0It->second->r0Status;
                            rowItem.r0CapabilityMask = r0It->second->dynDataCapabilityMask;
                            rowItem.r0KernelStack = r0It->second->kernelStack;
                            rowItem.r0StackBase = r0It->second->stackBase;
                            rowItem.r0StackLimit = r0It->second->stackLimit;
                            rowItem.r0InitialStack = r0It->second->initialStack;
                        }

                        // 固定线程详情 IOCTL：
                        // - 输入仅为 TID/PID，驱动重新引用 ETHREAD；
                        // - 输出用于补齐 Cid、链表、启动地址、栈边界和 I/O 计数；
                        // - 本页只渲染结果，不把返回的内核地址作为后续操作凭据。
                        const ksword::ark::ThreadRuntimeDetailResult detailResult =
                            driverClient.queryThreadRuntimeDetail(rowItem.threadId, pidValue);
                        if (detailResult.io.ok)
                        {
                            const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detailResponse =
                                detailResult.response;
                            rowItem.r0DetailStatus = detailResponse.status;
                            rowItem.r0DetailFieldFlags = detailResponse.fieldFlags;
                            rowItem.r0MissingCapabilityMask = detailResponse.missingCapabilityMask;
                            rowItem.r0DetailLastStatus = detailResponse.lastStatus;
                            rowItem.r0CapabilityMask = detailResponse.dynDataCapabilityMask != 0U
                                ? detailResponse.dynDataCapabilityMask
                                : rowItem.r0CapabilityMask;

                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0U)
                            {
                                rowItem.startAddress = detailResponse.startAddress;
                                rowItem.startAddressText = uint64ToHex(detailResponse.startAddress);
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0U)
                            {
                                rowItem.win32StartAddress = detailResponse.win32StartAddress;
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS) != 0U)
                            {
                                rowItem.r0InitialStack = detailResponse.initialStack;
                                rowItem.r0StackLimit = detailResponse.stackLimit;
                                rowItem.r0StackBase = detailResponse.stackBase;
                                rowItem.r0KernelStack = detailResponse.kernelStack;
                                rowItem.r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_OK;
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS) != 0U)
                            {
                                rowItem.r0ReadOperationCount = detailResponse.readOperationCount;
                                rowItem.r0WriteOperationCount = detailResponse.writeOperationCount;
                                rowItem.r0OtherOperationCount = detailResponse.otherOperationCount;
                                rowItem.r0ReadTransferCount = detailResponse.readTransferCount;
                                rowItem.r0WriteTransferCount = detailResponse.writeTransferCount;
                                rowItem.r0OtherTransferCount = detailResponse.otherTransferCount;
                            }

                            rowItem.r0RuntimeDetailText = QStringLiteral(
                                "线程详情=%1；已采集=%2；缺失能力=%3；LastStatus=%4；"
                                "CID=%5/%6；Start=%7；Win32Start=%8；I/O=%9/%10/%11 ops, %12/%13/%14 bytes；"
                                "偏移来源=%15；内核全局=%16；采样说明=%17")
                                .arg(runtimeDetailStatusText(detailResponse.status))
                                .arg(threadRuntimeFieldListText(detailResponse.fieldFlags))
                                .arg(runtimeCapabilityMaskText(detailResponse.missingCapabilityMask, true))
                                .arg(ntStatusHexText(detailResponse.lastStatus))
                                .arg(static_cast<qulonglong>(detailResponse.cidUniqueProcess))
                                .arg(static_cast<qulonglong>(detailResponse.cidUniqueThread))
                                .arg(uint64ToHex(detailResponse.startAddress))
                                .arg(uint64ToHex(detailResponse.win32StartAddress))
                                .arg(static_cast<qulonglong>(detailResponse.readOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.writeOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.otherOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.readTransferCount))
                                .arg(static_cast<qulonglong>(detailResponse.writeTransferCount))
                                .arg(static_cast<qulonglong>(detailResponse.otherTransferCount))
                                .arg(threadRuntimeOffsetSourceText(detailResponse))
                                .arg(runtimeKernelGlobalsText(detailResponse.kernelGlobals))
                                .arg(runtimeSamplingSummaryText(
                                    fixedRuntimeWideText(
                                        detailResponse.detail,
                                        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS),
                                    QStringLiteral("线程")));
                        }
                        else
                        {
                            const QString rawMessage =
                                QString::fromStdString(detailResult.io.message).trimmed();
                            const QString readableMessage = readableRuntimeIoMessage(
                                rawMessage,
                                QStringLiteral("线程详情"),
                                QStringLiteral("线程详情暂不可用。"),
                                detailResult.unsupported);
                            rowItem.r0RuntimeDetailText = readableMessage;
                        }

                        refreshResult.rows.push_back(std::move(rowItem));
                    }

                    hasThread = Thread32Next(snapshotHandle, &threadEntry);
                }
                CloseHandle(snapshotHandle);
            }
            if (processHandle != nullptr)
            {
                CloseHandle(processHandle);
            }

            std::sort(
                refreshResult.rows.begin(),
                refreshResult.rows.end(),
                [](const ThreadInspectItem& left, const ThreadInspectItem& right)
                {
                    return left.threadId < right.threadId;
                });

            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, ticketValue]()
                {
                    if (guardThis == nullptr || guardThis->m_threadInspectRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyThreadInspectResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyThreadInspectResult(const ThreadInspectRefreshResult& refreshResult)
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_threadRuntimeSampleOutput);
    m_threadInspectRefreshing = false;
    if (m_refreshThreadInspectButton != nullptr)
    {
        m_refreshThreadInspectButton->setEnabled(true);
    }

    m_threadInspectRows = refreshResult.rows;

    if (m_threadInspectTable != nullptr)
    {
        // 栈边界列文本生成：
        // - 在成员函数内部访问 ThreadInspectItem，保持类型仍为窗口私有实现细节；
        // - 文本同时呈现 R3 用户栈和 R0 KTHREAD 边界。
        const auto stackBoundaryText = [](const ThreadInspectItem& rowItem) -> QString
        {
            const QString userText =
                (rowItem.userStackBase != 0 || rowItem.userStackLimit != 0)
                ? QStringLiteral("U:%1-%2")
                    .arg(uint64ToHex(rowItem.userStackLimit))
                    .arg(uint64ToHex(rowItem.userStackBase))
                : QStringLiteral("U:Unavailable");
            const QString kernelText =
                (rowItem.r0KernelStack != 0 ||
                    rowItem.r0StackBase != 0 ||
                    rowItem.r0StackLimit != 0 ||
                    rowItem.r0InitialStack != 0)
                ? QStringLiteral("K:%1/%2-%3 I=%4")
                    .arg(uint64ToHex(rowItem.r0KernelStack))
                    .arg(uint64ToHex(rowItem.r0StackLimit))
                    .arg(uint64ToHex(rowItem.r0StackBase))
                    .arg(uint64ToHex(rowItem.r0InitialStack))
                : QStringLiteral("K:Unavailable");
            return QStringLiteral("%1 | %2 | %3")
                .arg(userText)
                .arg(kernelText)
                .arg(threadInspectR0StatusText(rowItem.r0ThreadStatus));
        };

        m_threadInspectTable->setSortingEnabled(false);
        m_threadInspectTable->setRowCount(0);
        for (std::size_t cacheIndex = 0; cacheIndex < m_threadInspectRows.size(); ++cacheIndex)
        {
            const ThreadInspectItem& rowItem = m_threadInspectRows[cacheIndex];
            const int row = m_threadInspectTable->rowCount();
            m_threadInspectTable->insertRow(row);
            auto* threadIdItem = new QTableWidgetItem(QString::number(rowItem.threadId));
            threadIdItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
            threadIdItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(rowItem.threadId));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::ThreadId), threadIdItem);
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::State), new QTableWidgetItem(rowItem.stateText));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::Priority), new QTableWidgetItem(QString::number(rowItem.priorityValue)));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::SwitchCount), new QTableWidgetItem(QString::number(rowItem.switchCount)));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::StartAddress), new QTableWidgetItem(rowItem.startAddressText));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::TebAddress), new QTableWidgetItem(rowItem.tebAddressText));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::Affinity), new QTableWidgetItem(rowItem.affinityText));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::RegisterSummary), new QTableWidgetItem(rowItem.registerSummaryText));
            auto* stackBoundaryItem = new QTableWidgetItem(stackBoundaryText(rowItem));
            stackBoundaryItem->setToolTip(QStringLiteral("UserStackBase=%1\nUserStackLimit=%2\nR0KernelStack=%3\nR0StackBase=%4\nR0StackLimit=%5\nR0InitialStack=%6\nR0Status=%7\nCapability=0x%8")
                .arg(uint64ToHex(rowItem.userStackBase))
                .arg(uint64ToHex(rowItem.userStackLimit))
                .arg(uint64ToHex(rowItem.r0KernelStack))
                .arg(uint64ToHex(rowItem.r0StackBase))
                .arg(uint64ToHex(rowItem.r0StackLimit))
                .arg(uint64ToHex(rowItem.r0InitialStack))
                .arg(threadInspectR0StatusText(rowItem.r0ThreadStatus))
                .arg(static_cast<qulonglong>(rowItem.r0CapabilityMask), 0, 16));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::StackBoundary), stackBoundaryItem);

            auto* runtimeDetailItem = new QTableWidgetItem(
                rowItem.r0RuntimeDetailText.trimmed().isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("线程 runtime detail 暂不可用。"))
                : rowItem.r0RuntimeDetailText);
            runtimeDetailItem->setToolTip(QStringLiteral(
                "DetailStatus=%1\n"
                "已采集字段=%2\n"
                "缺失能力=%3\n"
                "LastStatus=%4\n"
                "Read/Write/Other Ops=%5/%6/%7\n"
                "Read/Write/Other Bytes=%8/%9/%10\n\n"
                "%11")
                .arg(runtimeDetailStatusText(rowItem.r0DetailStatus))
                .arg(threadRuntimeFieldListText(rowItem.r0DetailFieldFlags))
                .arg(runtimeCapabilityMaskText(rowItem.r0MissingCapabilityMask, true))
                .arg(ntStatusHexText(rowItem.r0DetailLastStatus))
                .arg(static_cast<qulonglong>(rowItem.r0ReadOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0WriteOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0OtherOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0ReadTransferCount))
                .arg(static_cast<qulonglong>(rowItem.r0WriteTransferCount))
                .arg(static_cast<qulonglong>(rowItem.r0OtherTransferCount))
                .arg(runtimeDetailItem->text()));
            m_threadInspectTable->setItem(row, toThreadColumnIndex(ThreadRowColumn::RuntimeDetail), runtimeDetailItem);
        }
        m_threadInspectTable->setSortingEnabled(true);
    }

    QString statusText = QString("● 刷新完成 %1 ms | 线程数 %2")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.rows.size());
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
        kLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[ProcessDetailWindow] thread inspection completed with diagnostics, rowCount="
            << refreshResult.rows.size()
            << ", diagnostic="
            << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    updateThreadInspectStatusLabel(statusText, false);
    kPro.set(m_threadInspectRefreshProgressPid, "线程细节刷新完成", 0, 100.0f);
}

void ProcessDetailWindow::requestAsyncSelectedThreadRuntimeSample()
{
    // 当前线程 PDB deep runtime 采样：
    // - 输入来自线程表当前选中 TID 与窗口 PID；
    // - 后台只传 TID/PID/runtimeItemId/offset/size，不传 ETHREAD 地址；
    // - 返回文本写入 CodeEditorWidget，便于审计人员复制和比对字段。
    if (m_threadRuntimeSampleRefreshing)
    {
        if (m_threadInspectStatusLabel != nullptr)
        {
            m_threadInspectStatusLabel->setText(QStringLiteral("● 当前线程 PDB 字段采样仍在进行..."));
        }
        return;
    }
    if (m_threadInspectTable == nullptr || m_threadRuntimeSampleOutput == nullptr)
    {
        return;
    }

    const int currentRow = m_threadInspectTable->currentRow();
    if (currentRow < 0)
    {
        m_threadRuntimeSampleOutput->setText(QStringLiteral("请先在线程表中选择一条线程记录。"));
        return;
    }

    const QTableWidgetItem* threadIdItem =
        m_threadInspectTable->item(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId));
    const std::uint32_t threadId = threadIdItem != nullptr
        ? static_cast<std::uint32_t>(threadIdItem->data(Qt::UserRole + 1).toULongLong())
        : 0U;
    const std::size_t cacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(m_threadInspectRows.size());
    if (threadId == 0U || cacheIndex >= m_threadInspectRows.size())
    {
        m_threadRuntimeSampleOutput->setText(QStringLiteral("当前线程行缺少 TID 或缓存索引，请先刷新线程页。"));
        return;
    }

    const ThreadInspectItem selectedRow = m_threadInspectRows[cacheIndex];
    const std::uint32_t processId = selectedRow.processId != 0U
        ? selectedRow.processId
        : m_baseRecord.pid;
    if (processId == 0U)
    {
        m_threadRuntimeSampleOutput->setText(QStringLiteral("当前进程 PID 不可用，无法执行线程 PDB 字段采样。"));
        return;
    }

    m_threadRuntimeSampleRefreshing = true;
    const std::uint64_t ticketValue = ++m_threadRuntimeSampleTicket;
    if (m_sampleThreadRuntimeButton != nullptr)
    {
        m_sampleThreadRuntimeButton->setEnabled(false);
    }
    if (m_threadInspectStatusLabel != nullptr)
    {
        m_threadInspectStatusLabel->setText(QStringLiteral("● 正在采样 TID=%1 的 PDB deep 字段...").arg(threadId));
        m_threadInspectStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }
    m_threadRuntimeSampleOutput->setText(QStringLiteral(
        "正在后台执行 thread_detail PDB deep runtime 字段采样...\n"
        "请求只包含 TID/PID/offset/size，不提交 ETHREAD 地址。"));

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* sampleTask = QRunnable::create(
        [guardThis, ticketValue, processId, threadId, selectedRow]()
        {
            const auto beginTime = std::chrono::steady_clock::now();
            QStringList lines;
            lines << QStringLiteral("[Selected Thread Runtime Context]");
            lines << QStringLiteral("TID/PID: %1/%2").arg(threadId).arg(processId);
            lines << QStringLiteral("Start/Win32Start: %1 / %2")
                .arg(uint64ToHex(selectedRow.startAddress))
                .arg(uint64ToHex(selectedRow.win32StartAddress));
            lines << QStringLiteral("TEB: %1").arg(uint64ToHex(selectedRow.tebAddress));
            lines << QStringLiteral("R0 fixed detail: %1")
                .arg(selectedRow.r0RuntimeDetailText.trimmed().isEmpty()
                    ? QStringLiteral("线程 runtime detail 暂不可用。")
                    : selectedRow.r0RuntimeDetailText);
            lines << QString();

            const ksword::ark::DriverClient driverClient;
            const ksword::ark::DynDataStatusResult dynDataStatusResult =
                driverClient.queryDynDataStatus();
            QString deepIdentityGuardText;
            bool deepIdentityMatched = false;
            if (dynDataStatusResult.io.ok)
            {
                deepIdentityMatched = pdbRuntimeCatalogMatchesKernelIdentity(
                    dynDataStatusResult.ntoskrnl.timeDateStamp,
                    dynDataStatusResult.ntoskrnl.sizeOfImage,
                    &deepIdentityGuardText);
            }
            else
            {
                const QString readableDynDataMessage = readableRuntimeIoMessage(
                    QString::fromStdString(dynDataStatusResult.io.message),
                    QStringLiteral("DynData状态"),
                    QStringLiteral("DynData status 查询没有返回额外说明。"),
                    false);
                deepIdentityGuardText = QStringLiteral(
                    "[PDB Deep Runtime Identity Guard]\n"
                    "结论: 不匹配，跳过只读采样\n"
                    "原因: DynData status 查询不可用，无法校验 deep offset 与当前内核 identity。%1")
                    .arg(readableDynDataMessage);
            }

            lines << deepIdentityGuardText;
            lines << QString();
            const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> sampleItems =
                deepIdentityMatched
                ? buildPdbRuntimeSampleItems(QStringLiteral("thread_detail"), 64)
                : std::vector<ksword::ark::RuntimeFieldSampleRequestItem>{};
            if (!deepIdentityMatched)
            {
                lines << QStringLiteral("[PDB Deep Runtime Sample - thread_detail]");
                lines << QStringLiteral("deep catalog identity 未与当前 ntoskrnl 匹配，已跳过 R0 字段采样，避免错误偏移。");
            }
            else if (sampleItems.empty())
            {
                lines << QStringLiteral("[PDB Deep Runtime Sample - thread_detail]");
                lines << QStringLiteral("profiles/pdb_deep_offsets 中没有找到可安全采样的 thread_detail 小字段。");
            }
            else
            {
                const ksword::ark::RuntimeFieldSampleResult sampleResult =
                    driverClient.queryThreadRuntimeFieldSamples(threadId, processId, sampleItems);
                lines << runtimeFieldSampleResultText(
                    sampleResult,
                    QStringLiteral("线程 PDB deep 字段采样"));
            }

            lines << QString();
            lines << QStringLiteral("[PDB Deep Runtime Catalog - thread_detail preview]");
            lines << buildPdbRuntimeCatalogPreview(QStringLiteral("thread_detail"), 16, 64);

            const std::uint64_t elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());
            lines << QString();
            lines << QStringLiteral("ElapsedMs: %1").arg(elapsedMs);
            const QString outputText = lines.join(QChar('\n'));

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticketValue, threadId, outputText, elapsedMs]()
                {
                    if (guardThis == nullptr || guardThis->m_threadRuntimeSampleTicket != ticketValue)
                    {
                        return;
                    }

                    guardThis->m_threadRuntimeSampleRefreshing = false;
                    if (guardThis->m_sampleThreadRuntimeButton != nullptr)
                    {
                        guardThis->m_sampleThreadRuntimeButton->setEnabled(true);
                    }
                    if (guardThis->m_threadRuntimeSampleOutput != nullptr)
                    {
                        guardThis->m_threadRuntimeSampleOutput->setText(outputText);
                    }
                    if (guardThis->m_threadInspectStatusLabel != nullptr)
                    {
                        guardThis->m_threadInspectStatusLabel->setText(
                            QStringLiteral("● TID=%1 PDB 字段采样完成 %2 ms")
                            .arg(threadId)
                            .arg(elapsedMs));
                        guardThis->m_threadInspectStatusLabel->setStyleSheet(
                            buildStateLabelStyle(statusIdleColor(), 600));
                    }
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(sampleTask);
}

void ProcessDetailWindow::requestAsyncTokenRefresh()
{
    // 令牌页异步刷新：
    // - 解析用户 SID、完整性级别、组和特权；
    // - 全流程在后台线程执行，避免阻塞窗口交互。
    if (m_tokenRefreshing || m_baseRecord.pid == 0)
    {
        return;
    }

    // 令牌文本页刷新较重，首刷标记用于阻止切页后重复自动刷新。
    m_tokenInitialRefreshStarted = true;

    m_tokenRefreshing = true;
    const std::uint64_t ticketValue = ++m_tokenRefreshTicket;
    if (m_refreshTokenButton != nullptr)
    {
        m_refreshTokenButton->setEnabled(false);
    }
    if (m_tokenStatusLabel != nullptr)
    {
        m_tokenStatusLabel->setText(QStringLiteral("● 正在刷新令牌..."));
        m_tokenStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }

    if (m_tokenRefreshProgressPid == 0)
    {
        m_tokenRefreshProgressPid = kPro.addReusable(this, "进程详情", "刷新令牌信息");
    }
    kPro.set(m_tokenRefreshProgressPid, "读取令牌字段", 0, 20.0f);

    const std::uint32_t pidValue = m_baseRecord.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, pidValue, ticketValue]()
        {
            TextRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();
            std::wostringstream textBuilder;
            textBuilder << L"[Token / Security Information]\n";
            textBuilder << L"PID: " << pidValue << L"\n";

            // 打开进程句柄：
            // - 令牌信息需要 PROCESS_QUERY_LIMITED_INFORMATION；
            // - 安全扩展字段与虚拟内存摘要需要 PROCESS_QUERY_INFORMATION / VM_READ。
            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pidValue);
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pidValue);
            }
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QString("OpenProcess失败(%1)").arg(GetLastError());
            }
            else
            {
                // 动态加载 NtQueryInformationProcess：
                // - 用于读取 DebugPort/保护级别/DEP/关键进程等原生字段。
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);

                HANDLE tokenHandle = nullptr;
                if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
                {
                    refreshResult.diagnosticText = QString("OpenProcessToken失败(%1)").arg(GetLastError());
                }
                else
                {
                    std::vector<std::uint8_t> tokenBuffer;

                    // TokenUser：输出用户 SID 与账户名。
                    if (queryTokenInfoBuffer(tokenHandle, TokenUser, tokenBuffer))
                    {
                        const auto* tokenUserInfo = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
                        textBuilder << L"User: " << convertSidToText(tokenUserInfo->User.Sid).toStdWString() << L"\n";
                    }

                    // TokenIntegrityLevel：输出完整性级别。
                    if (queryTokenInfoBuffer(tokenHandle, TokenIntegrityLevel, tokenBuffer))
                    {
                        const auto* mandatoryLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
                        DWORD integrityRid = 0;
                        if (mandatoryLabel->Label.Sid != nullptr &&
                            *GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) > 0)
                        {
                            integrityRid = *GetSidSubAuthority(
                                mandatoryLabel->Label.Sid,
                                *GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1);
                        }
                        textBuilder << L"Integrity: " << describeIntegrityLevel(integrityRid).toStdWString() << L"\n";
                    }

                    // TokenElevationType：输出提升类型（Default/Full/Limited）。
                    TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
                    if (queryTokenInfoBuffer(tokenHandle, TokenElevationType, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_ELEVATION_TYPE))
                    {
                        elevationType = *reinterpret_cast<const TOKEN_ELEVATION_TYPE*>(tokenBuffer.data());
                    }
                    const wchar_t* elevationTypeText = L"Default";
                    if (elevationType == TokenElevationTypeFull)
                    {
                        elevationTypeText = L"Full";
                    }
                    else if (elevationType == TokenElevationTypeLimited)
                    {
                        elevationTypeText = L"Limited";
                    }
                    textBuilder << L"ElevationType: " << elevationTypeText << L"\n";

                    // TokenElevation：输出是否已提升。
                    if (queryTokenInfoBuffer(tokenHandle, TokenElevation, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_ELEVATION))
                    {
                        const auto* elevation = reinterpret_cast<const TOKEN_ELEVATION*>(tokenBuffer.data());
                        textBuilder << L"IsElevated: " << (elevation->TokenIsElevated != 0 ? L"true" : L"false") << L"\n";
                    }

                    // TokenLinkedToken：输出链接令牌是否存在（管理员拆分令牌场景）。
                    if (queryTokenInfoBuffer(tokenHandle, TokenLinkedToken, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_LINKED_TOKEN))
                    {
                        const auto* linkedTokenInfo = reinterpret_cast<const TOKEN_LINKED_TOKEN*>(tokenBuffer.data());
                        const bool hasLinkedToken =
                            linkedTokenInfo->LinkedToken != nullptr &&
                            linkedTokenInfo->LinkedToken != INVALID_HANDLE_VALUE;
                        textBuilder << L"LinkedToken: " << (hasLinkedToken ? L"Present" : L"None") << L"\n";
                        if (hasLinkedToken)
                        {
                            CloseHandle(linkedTokenInfo->LinkedToken);
                        }
                    }
                    else
                    {
                        textBuilder << L"LinkedToken: Unavailable\n";
                    }

                    // TokenRestrictedSids：输出限制 SID 数量。
                    if (queryTokenInfoBuffer(tokenHandle, TokenRestrictedSids, tokenBuffer))
                    {
                        const auto* restrictedSids = reinterpret_cast<const TOKEN_GROUPS*>(tokenBuffer.data());
                        textBuilder << L"RestrictedSidCount: " << restrictedSids->GroupCount << L"\n";
                    }
                    else
                    {
                        textBuilder << L"RestrictedSidCount: 0\n";
                    }

                    // TokenGroups：输出组数量与预览。
                    if (queryTokenInfoBuffer(tokenHandle, TokenGroups, tokenBuffer))
                    {
                        const auto* groupsInfo = reinterpret_cast<const TOKEN_GROUPS*>(tokenBuffer.data());
                        textBuilder << L"GroupCount: " << groupsInfo->GroupCount << L"\n";
                        const DWORD previewCount = std::min<DWORD>(groupsInfo->GroupCount, 16);
                        for (DWORD index = 0; index < previewCount; ++index)
                        {
                            textBuilder << L"  - "
                                << convertSidToText(groupsInfo->Groups[index].Sid).toStdWString()
                                << L"\n";
                        }
                    }

                    // TokenPrivileges：输出特权数量与启用状态。
                    if (queryTokenInfoBuffer(tokenHandle, TokenPrivileges, tokenBuffer))
                    {
                        const auto* privilegesInfo =
                            reinterpret_cast<const TOKEN_PRIVILEGES*>(tokenBuffer.data());
                        textBuilder << L"PrivilegeCount: " << privilegesInfo->PrivilegeCount << L"\n";
                        const DWORD previewCount = std::min<DWORD>(privilegesInfo->PrivilegeCount, 24);
                        for (DWORD index = 0; index < previewCount; ++index)
                        {
                            const LUID_AND_ATTRIBUTES& privilegeEntry = privilegesInfo->Privileges[index];
                            WCHAR privilegeName[256] = {};
                            DWORD nameLength = static_cast<DWORD>(std::size(privilegeName));
                            const BOOL nameOk = LookupPrivilegeNameW(
                                nullptr,
                                const_cast<LUID*>(&privilegeEntry.Luid),
                                privilegeName,
                                &nameLength);
                            textBuilder << L"  - "
                                << (nameOk != FALSE ? std::wstring(privilegeName) : L"<Unknown>")
                                << ((privilegeEntry.Attributes & SE_PRIVILEGE_ENABLED) != 0 ? L" [Enabled]" : L" [Disabled]")
                                << L"\n";
                        }
                    }

                    // 全信息类快照：
                    // - 枚举 TokenInformationClass 1..80；
                    // - 对每个类输出是否可读、字节长度与原始预览，避免遗漏关键字段。
                    textBuilder << L"\n[All TokenInformationClass Snapshot]\n";
                    for (ULONG classId = 1; classId <= 80; ++classId)
                    {
                        std::vector<std::uint8_t> classRawBuffer;
                        const TOKEN_INFORMATION_CLASS infoClass = static_cast<TOKEN_INFORMATION_CLASS>(classId);
                        const bool queryOk = queryTokenInfoBuffer(tokenHandle, infoClass, classRawBuffer);
                        if (queryOk)
                        {
                            textBuilder << L"  ["
                                << classId
                                << L"] "
                                << tokenInfoClassNameById(classId).toStdWString()
                                << L": size="
                                << classRawBuffer.size()
                                << L", raw="
                                << formatTokenRawPreview(classRawBuffer, 24).toStdWString()
                                << L"\n";
                        }
                        else
                        {
                            const DWORD queryError = GetLastError();
                            textBuilder << L"  ["
                                << classId
                                << L"] "
                                << tokenInfoClassNameById(classId).toStdWString()
                                << L": queryFailed("
                                << queryError
                                << L")\n";
                        }
                    }

                    CloseHandle(tokenHandle);
                }

                // 原生进程安全字段：
                // - DebugPort / DEP / Critical / Protection / Subsystem。
                if (ntQueryProcess != nullptr)
                {
                    ULONG_PTR debugPort = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassDebugPort, debugPort))
                    {
                        textBuilder << L"DebugPort: " << uint64ToHex(debugPort).toStdWString() << L"\n";
                    }

                    ULONG executeFlags = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassExecuteFlags, executeFlags))
                    {
                        textBuilder << L"DEPFlags: 0x"
                            << QString::number(executeFlags, 16).toUpper().toStdWString()
                            << L"\n";
                    }

                    ULONG breakOnTermination = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassBreakOnTermination, breakOnTermination))
                    {
                        textBuilder << L"ProcessCriticalFlag(BreakOnTermination): "
                            << (breakOnTermination != 0 ? L"true" : L"false")
                            << L"\n";
                    }

                    std::uint8_t protectionLevel = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassProtection, protectionLevel))
                    {
                        textBuilder << L"Protection: "
                            << protectionLevelToText(protectionLevel).toStdWString()
                            << L"\n";
                    }

                    ULONG subsystemType = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassSubsystem, subsystemType))
                    {
                        textBuilder << L"SubsystemType: " << subsystemType << L"\n";
                    }
                }

                // GUI 资源统计：GDI / USER 对象计数。
                const DWORD gdiObjectCount = GetGuiResources(processHandle, GR_GDIOBJECTS);
                const DWORD userObjectCount = GetGuiResources(processHandle, GR_USEROBJECTS);
                textBuilder << L"GDIObjectCount: " << gdiObjectCount << L"\n";
                textBuilder << L"USERObjectCount: " << userObjectCount << L"\n";

                // IO 计数器：读写次数与字节数。
                IO_COUNTERS ioCounters{};
                if (GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
                {
                    textBuilder << L"IoReadOps: " << ioCounters.ReadOperationCount << L"\n";
                    textBuilder << L"IoWriteOps: " << ioCounters.WriteOperationCount << L"\n";
                    textBuilder << L"IoReadBytes: " << ioCounters.ReadTransferCount << L"\n";
                    textBuilder << L"IoWriteBytes: " << ioCounters.WriteTransferCount << L"\n";
                }

                // Job 关联信息：是否在 Job 对象中。
                BOOL inJobObject = FALSE;
                if (IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
                {
                    textBuilder << L"InJobObject: " << (inJobObject != FALSE ? L"true" : L"false") << L"\n";
                }

                // 节能状态：动态查询 GetProcessInformation(ProcessPowerThrottling=4)。
                HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
                GetProcessInformationFn getProcessInformation = reinterpret_cast<GetProcessInformationFn>(
                    kernel32Module != nullptr ? GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
                if (getProcessInformation != nullptr)
                {
                    ProcessPowerThrottlingStateNative powerState{};
                    powerState.version = 1;
                    const BOOL powerOk = getProcessInformation(
                        processHandle,
                        4,
                        &powerState,
                        static_cast<DWORD>(sizeof(powerState)));
                    if (powerOk != FALSE)
                    {
                        textBuilder << L"PowerThrottlingControlMask: 0x"
                            << QString::number(powerState.controlMask, 16).toUpper().toStdWString()
                            << L"\n";
                        textBuilder << L"PowerThrottlingStateMask: 0x"
                            << QString::number(powerState.stateMask, 16).toUpper().toStdWString()
                            << L"\n";
                    }
                }

                // 窗口相关信息：窗口数量 + 线程桌面名称 + 当前窗口站名称。
                const std::uint32_t windowCount = countTopLevelWindowsByPid(pidValue);
                textBuilder << L"TopLevelWindowCount: " << windowCount << L"\n";

                const QString desktopName = queryDesktopNameByProcessThreads(pidValue);
                if (!desktopName.trimmed().isEmpty())
                {
                    textBuilder << L"ThreadDesktop: " << desktopName.toStdWString() << L"\n";
                }

                HWINSTA processWindowStation = GetProcessWindowStation();
                if (processWindowStation != nullptr)
                {
                    wchar_t stationNameBuffer[256] = {};
                    DWORD stationNameBytes = 0;
                    const BOOL stationOk = GetUserObjectInformationW(
                        processWindowStation,
                        UOI_NAME,
                        stationNameBuffer,
                        static_cast<DWORD>(sizeof(stationNameBuffer)),
                        &stationNameBytes);
                    if (stationOk != FALSE)
                    {
                        textBuilder << L"ProcessWindowStation: " << stationNameBuffer << L"\n";
                    }
                }

                // 会话 ID 与句柄数补充输出。
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pidValue, &sessionId) != FALSE)
                {
                    textBuilder << L"SessionId: " << sessionId << L"\n";
                }
                DWORD handleCount = 0;
                if (GetProcessHandleCount(processHandle, &handleCount) != FALSE)
                {
                    textBuilder << L"HandleCount: " << handleCount << L"\n";
                }

                CloseHandle(processHandle);
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, ticketValue]()
                {
                    if (guardThis == nullptr || guardThis->m_tokenRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyTokenRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::refreshTokenSwitchStates()
{
    // 令牌开关回读日志：
    // - 本次回读链路复用同一个 kLogEvent；
    // - 便于把“打开句柄 -> 读取字段 -> 回填UI”串成一条可追踪链路。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] refreshTokenSwitchStates: pid="
        << m_baseRecord.pid
        << eol;

    // 开关页回读属于该页首刷动作；手动刷新也复用此标记。
    m_tokenSwitchInitialRefreshStarted = true;

    // setStatusLabel 作用：
    // - 统一写入状态文本与颜色；
    // - 避免多处分支重复 setText/setStyleSheet。
    const auto setStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (m_tokenSwitchStatusLabel == nullptr)
        {
            return;
        }
        m_tokenSwitchStatusLabel->setText(statusText);
        m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (m_baseRecord.pid == 0)
    {
        setStatusLabel(QStringLiteral("● 刷新失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: PID 无效。"
            << eol;
        return;
    }

    if (m_refreshTokenSwitchButton != nullptr)
    {
        m_refreshTokenSwitchButton->setEnabled(false);
    }
    setStatusLabel(QStringLiteral("● 正在读取令牌开关..."), KswordTheme::PrimaryBlueColor, 700);

    // 打开进程和令牌句柄：
    // - 读取开关只需要 TOKEN_QUERY；
    // - 进程句柄先用 QUERY_LIMITED，尽量降低权限要求。
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_baseRecord.pid);
    if (processHandle == nullptr)
    {
        const DWORD openProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), openProcessError);
        setStatusLabel(
            QStringLiteral("● 刷新失败：OpenProcess(%1)").arg(openProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: OpenProcess 失败, error="
            << openProcessError
            << eol;
        if (m_refreshTokenSwitchButton != nullptr)
        {
            m_refreshTokenSwitchButton->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD openTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("读取目标进程令牌"), openTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        setStatusLabel(
            QStringLiteral("● 刷新失败：OpenProcessToken(%1)").arg(openTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: OpenProcessToken 失败, error="
            << openTokenError
            << eol;
        if (m_refreshTokenSwitchButton != nullptr)
        {
            m_refreshTokenSwitchButton->setEnabled(true);
        }
        return;
    }

    // queryBoolToCheckBox 作用：
    // - 从令牌读取一个 ULONG 布尔位并写入对应复选框；
    // - 失败项写入 failItemList，便于最终状态栏汇总。
    int successCount = 0;
    QStringList failItemList;
    const auto queryBoolToCheckBox =
        [tokenHandle, &successCount, &failItemList](
            QCheckBox* checkBox,
            const TOKEN_INFORMATION_CLASS infoClass,
            const QString& itemName)
    {
        if (checkBox == nullptr)
        {
            failItemList << QStringLiteral("%1(控件为空)").arg(itemName);
            return;
        }

        bool flagValue = false;
        if (!queryTokenBoolFlag(tokenHandle, infoClass, flagValue))
        {
            const DWORD queryError = GetLastError();
            failItemList << QStringLiteral("%1(%2)").arg(itemName).arg(queryError);
            return;
        }
        checkBox->setChecked(flagValue);
        ++successCount;
    };

    queryBoolToCheckBox(m_tokenSandboxInertCheck, TokenSandBoxInert, QStringLiteral("SandboxInert"));
    queryBoolToCheckBox(m_tokenVirtualizationAllowedCheck, TokenVirtualizationAllowed, QStringLiteral("VirtualizationAllowed"));
    queryBoolToCheckBox(m_tokenVirtualizationEnabledCheck, TokenVirtualizationEnabled, QStringLiteral("VirtualizationEnabled"));
    queryBoolToCheckBox(m_tokenUiAccessCheck, TokenUIAccess, QStringLiteral("UIAccess"));
    queryBoolToCheckBox(
        m_tokenHasRestrictionsCheck,
        kTokenInfoClassHasRestrictions,
        QStringLiteral("HasRestrictions"));
    queryBoolToCheckBox(
        m_tokenIsAppContainerCheck,
        kTokenInfoClassIsAppContainer,
        QStringLiteral("IsAppContainer"));
    queryBoolToCheckBox(
        m_tokenIsRestrictedCheck,
        kTokenInfoClassIsRestricted,
        QStringLiteral("IsRestricted"));
    queryBoolToCheckBox(
        m_tokenIsLessPrivilegedAppContainerCheck,
        kTokenInfoClassIsLessPrivilegedAppContainer,
        QStringLiteral("IsLessPrivilegedAppContainer"));
    queryBoolToCheckBox(
        m_tokenIsSandboxedCheck,
        kTokenInfoClassIsSandboxed,
        QStringLiteral("IsSandboxed"));
    queryBoolToCheckBox(
        m_tokenIsAppSiloCheck,
        kTokenInfoClassIsAppSilo,
        QStringLiteral("IsAppSilo"));

    // MandatoryPolicy 读取：
    // - 一次读取两个位，分别同步到两个策略复选框；
    // - 失败同样记录到 failItemList 中。
    if (m_tokenMandatoryNoWriteUpCheck == nullptr || m_tokenMandatoryNewProcessMinCheck == nullptr)
    {
        failItemList << QStringLiteral("MandatoryPolicy(控件为空)");
    }
    else
    {
        bool noWriteUpEnabled = false;
        bool newProcessMinEnabled = false;
        if (queryTokenMandatoryPolicyBits(tokenHandle, noWriteUpEnabled, newProcessMinEnabled))
        {
            m_tokenMandatoryNoWriteUpCheck->setChecked(noWriteUpEnabled);
            m_tokenMandatoryNewProcessMinCheck->setChecked(newProcessMinEnabled);
            ++successCount;
        }
        else
        {
            const DWORD queryError = GetLastError();
            failItemList << QStringLiteral("MandatoryPolicy(%1)").arg(queryError);
        }
    }

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (m_refreshTokenSwitchButton != nullptr)
    {
        m_refreshTokenSwitchButton->setEnabled(true);
    }

    // 最终状态栏：
    // - 全部成功显示绿色；
    // - 有失败项显示橙色摘要，完整失败清单仅写入日志。
    if (failItemList.isEmpty())
    {
        setStatusLabel(
            QStringLiteral("● 刷新完成：%1 项开关已同步").arg(successCount),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: 完成, successCount="
            << successCount
            << eol;
    }
    else
    {
        setStatusLabel(
            QStringLiteral("● 刷新完成：成功%1，失败%2；详情已写入日志。")
            .arg(successCount)
            .arg(failItemList.size()),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: 部分失败, successCount="
            << successCount
            << ", failItems="
            << failItemList.join(QStringLiteral(" | ")).toStdString()
            << eol;
    }
}

void ProcessDetailWindow::applyTokenSwitchStates()
{
    // 令牌开关应用日志：
    // - 使用同一个 kLogEvent 贯穿整个应用流程；
    // - 每个字段单独记录结果，便于定位哪一项权限不足。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] applyTokenSwitchStates: pid="
        << m_baseRecord.pid
        << eol;

    // setStatusLabel 作用：
    // - 统一写入状态文本与颜色；
    // - 与 refreshTokenSwitchStates 保持一致的反馈风格。
    const auto setStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (m_tokenSwitchStatusLabel == nullptr)
        {
            return;
        }
        m_tokenSwitchStatusLabel->setText(statusText);
        m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (m_baseRecord.pid == 0)
    {
        setStatusLabel(QStringLiteral("● 应用失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: PID 无效。"
            << eol;
        return;
    }

    if (m_applyTokenSwitchButton != nullptr)
    {
        m_applyTokenSwitchButton->setEnabled(false);
    }
    setStatusLabel(QStringLiteral("● 正在应用令牌开关..."), KswordTheme::PrimaryBlueColor, 700);

    // 动态解析 NtSetInformationToken：
    // - 用户需求中提到 NtSetTokenInformation，这里对应 ntdll 导出的 NtSetInformationToken；
    // - 若导出不可用则直接终止并给出错误说明。
    HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
    if (ntdllModule == nullptr)
    {
        ntdllModule = LoadLibraryW(L"ntdll.dll");
    }
    const auto setInformationToken = reinterpret_cast<NtSetInformationTokenFn>(
        ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtSetInformationToken") : nullptr);
    if (setInformationToken == nullptr)
    {
        setStatusLabel(QStringLiteral("● 应用失败：NtSetInformationToken 不可用"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: NtSetInformationToken 不可用。"
            << eol;
        if (m_applyTokenSwitchButton != nullptr)
        {
            m_applyTokenSwitchButton->setEnabled(true);
        }
        return;
    }

    // 打开目标令牌：
    // - 写开关需要 TOKEN_ADJUST_DEFAULT；
    // - 同时保留 TOKEN_QUERY 用于后续回读和诊断。
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_baseRecord.pid);
    if (processHandle == nullptr)
    {
        const DWORD openProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), openProcessError);
        setStatusLabel(
            QStringLiteral("● 应用失败：OpenProcess(%1)").arg(openProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: OpenProcess 失败, error="
            << openProcessError
            << eol;
        if (m_applyTokenSwitchButton != nullptr)
        {
            m_applyTokenSwitchButton->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(processHandle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD openTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), openTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        setStatusLabel(
            QStringLiteral("● 应用失败：OpenProcessToken(%1)").arg(openTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: OpenProcessToken 失败, error="
            << openTokenError
            << eol;
        if (m_applyTokenSwitchButton != nullptr)
        {
            m_applyTokenSwitchButton->setEnabled(true);
        }
        return;
    }

    // applyBoolFromCheckBox 作用：
    // - 读取复选框状态并调用 NtSetInformationToken；
    // - 每项失败都会记录 NTSTATUS，最终统一汇总到状态栏。
    int successCount = 0;
    long privilegeDeniedStatus = 0;
    QStringList failItemList;
    const auto applyBoolFromCheckBox =
        [setInformationToken, tokenHandle, &successCount, &failItemList, &privilegeDeniedStatus](
            QCheckBox* checkBox,
            const TOKEN_INFORMATION_CLASS infoClass,
            const QString& itemName)
    {
        if (checkBox == nullptr)
        {
            failItemList << QStringLiteral("%1(控件为空)").arg(itemName);
            return;
        }

        const NTSTATUS setStatus = applyTokenBoolFlag(
            setInformationToken,
            tokenHandle,
            infoClass,
            checkBox->isChecked());
        if (!NT_SUCCESS(setStatus))
        {
            if (static_cast<unsigned long>(setStatus) == 0xC0000022UL)
            {
                privilegeDeniedStatus = static_cast<long>(setStatus);
            }
            failItemList << QStringLiteral("%1(%2)").arg(itemName).arg(formatNtStatusHex(setStatus));
            return;
        }
        ++successCount;
    };

    applyBoolFromCheckBox(m_tokenSandboxInertCheck, TokenSandBoxInert, QStringLiteral("SandboxInert"));
    applyBoolFromCheckBox(m_tokenVirtualizationAllowedCheck, TokenVirtualizationAllowed, QStringLiteral("VirtualizationAllowed"));
    applyBoolFromCheckBox(m_tokenVirtualizationEnabledCheck, TokenVirtualizationEnabled, QStringLiteral("VirtualizationEnabled"));
    applyBoolFromCheckBox(m_tokenUiAccessCheck, TokenUIAccess, QStringLiteral("UIAccess"));
    applyBoolFromCheckBox(
        m_tokenHasRestrictionsCheck,
        kTokenInfoClassHasRestrictions,
        QStringLiteral("HasRestrictions"));
    applyBoolFromCheckBox(
        m_tokenIsAppContainerCheck,
        kTokenInfoClassIsAppContainer,
        QStringLiteral("IsAppContainer"));
    applyBoolFromCheckBox(
        m_tokenIsRestrictedCheck,
        kTokenInfoClassIsRestricted,
        QStringLiteral("IsRestricted"));
    applyBoolFromCheckBox(
        m_tokenIsLessPrivilegedAppContainerCheck,
        kTokenInfoClassIsLessPrivilegedAppContainer,
        QStringLiteral("IsLessPrivilegedAppContainer"));
    applyBoolFromCheckBox(
        m_tokenIsSandboxedCheck,
        kTokenInfoClassIsSandboxed,
        QStringLiteral("IsSandboxed"));
    applyBoolFromCheckBox(
        m_tokenIsAppSiloCheck,
        kTokenInfoClassIsAppSilo,
        QStringLiteral("IsAppSilo"));

    // MandatoryPolicy 写入：
    // - 由两个策略复选框合成一个 POLICY 位掩码；
    // - 使用 NtSetInformationToken(TokenMandatoryPolicy) 一次提交。
    if (m_tokenMandatoryNoWriteUpCheck == nullptr || m_tokenMandatoryNewProcessMinCheck == nullptr)
    {
        failItemList << QStringLiteral("MandatoryPolicy(控件为空)");
    }
    else
    {
        const NTSTATUS policyStatus = applyTokenMandatoryPolicyBits(
            setInformationToken,
            tokenHandle,
            m_tokenMandatoryNoWriteUpCheck->isChecked(),
            m_tokenMandatoryNewProcessMinCheck->isChecked());
        if (NT_SUCCESS(policyStatus))
        {
            ++successCount;
        }
        else
        {
            if (static_cast<unsigned long>(policyStatus) == 0xC0000022UL)
            {
                privilegeDeniedStatus = static_cast<long>(policyStatus);
            }
            failItemList << QStringLiteral("MandatoryPolicy(%1)").arg(formatNtStatusHex(policyStatus));
        }
    }

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (m_applyTokenSwitchButton != nullptr)
    {
        m_applyTokenSwitchButton->setEnabled(true);
    }

    if (privilegeDeniedStatus != 0)
    {
        (void)ks::ui::promptForPrivilegeNtStatus(
            this,
            QStringLiteral("修改目标进程令牌"),
            privilegeDeniedStatus);
    }

    // 应用结果反馈：
    // - 全成功时刷新文本令牌页与开关页；
    // - 部分失败时也刷新开关页，确保 UI 与真实状态尽量一致。
    if (failItemList.isEmpty())
    {
        setStatusLabel(
            QStringLiteral("● 应用完成：成功%1项").arg(successCount),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: 全部成功, successCount="
            << successCount
            << eol;
    }
    else
    {
        setStatusLabel(
            QStringLiteral("● 应用完成：成功%1，失败%2；详情已写入日志。")
            .arg(successCount)
            .arg(failItemList.size()),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: 部分失败, successCount="
            << successCount
            << ", failItems="
            << failItemList.join(QStringLiteral(" | ")).toStdString()
            << eol;
    }

    requestAsyncTokenRefresh();
    refreshTokenSwitchStates();
}

void ProcessDetailWindow::applyRawTokenInformation()
{
    // 原始设置应用日志：
    // - 同一条 kLogEvent 贯穿“解析输入 -> 打开令牌 -> NtSetInformationToken”；
    // - 保证失败点可在日志中准确定位。
    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] applyRawTokenInformation: pid="
        << m_baseRecord.pid
        << eol;

    // setStatusLabel 作用：
    // - 统一设置令牌设置页状态文本和颜色；
    // - 减少多分支重复 setText/setStyleSheet 代码。
    const auto setStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (m_tokenSwitchStatusLabel == nullptr)
        {
            return;
        }
        m_tokenSwitchStatusLabel->setText(statusText);
        m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (m_baseRecord.pid == 0)
    {
        setStatusLabel(QStringLiteral("● 原始设置失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: PID 无效。"
            << eol;
        return;
    }
    if (m_tokenRawInfoClassCombo == nullptr || m_tokenRawInputModeCombo == nullptr || m_tokenRawPayloadEdit == nullptr)
    {
        setStatusLabel(QStringLiteral("● 原始设置失败：控件未初始化"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 原始设置控件为空。"
            << eol;
        return;
    }

    const int classId = m_tokenRawInfoClassCombo->currentData().toInt();
    const QString modeKey = m_tokenRawInputModeCombo->currentData().toString().trimmed().toLower();
    const QString payloadText = m_tokenRawPayloadEdit->text().trimmed();
    if (classId <= 0)
    {
        setStatusLabel(QStringLiteral("● 原始设置失败：信息类无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: classId 无效="
            << classId
            << eol;
        return;
    }
    if (payloadText.isEmpty())
    {
        setStatusLabel(QStringLiteral("● 原始设置失败：负载为空"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: payload 为空。"
            << eol;
        return;
    }

    // 输入解析：
    // - UInt32/UInt64 使用 Qt 自动进制（支持 0x 前缀）；
    // - HexBytes 按空格/逗号分隔字节序列。
    std::vector<std::uint8_t> payloadBuffer;
    QString parseErrorText;
    if (modeKey == QStringLiteral("u32"))
    {
        bool parseOk = false;
        const qulonglong parsedValue = payloadText.toULongLong(&parseOk, 0);
        if (!parseOk || parsedValue > 0xFFFFFFFFULL)
        {
            parseErrorText = QStringLiteral("UInt32 解析失败");
        }
        else
        {
            const std::uint32_t value32 = static_cast<std::uint32_t>(parsedValue);
            payloadBuffer.resize(sizeof(value32));
            std::memcpy(payloadBuffer.data(), &value32, sizeof(value32));
        }
    }
    else if (modeKey == QStringLiteral("u64"))
    {
        bool parseOk = false;
        const qulonglong parsedValue = payloadText.toULongLong(&parseOk, 0);
        if (!parseOk)
        {
            parseErrorText = QStringLiteral("UInt64 解析失败");
        }
        else
        {
            const std::uint64_t value64 = static_cast<std::uint64_t>(parsedValue);
            payloadBuffer.resize(sizeof(value64));
            std::memcpy(payloadBuffer.data(), &value64, sizeof(value64));
        }
    }
    else if (modeKey == QStringLiteral("hex"))
    {
        QString normalizedText = payloadText;
        normalizedText.replace(',', ' ');
        const QStringList tokenList = normalizedText.split(' ', Qt::SkipEmptyParts);
        if (tokenList.isEmpty())
        {
            parseErrorText = QStringLiteral("HexBytes 解析失败：没有字节");
        }
        else
        {
            payloadBuffer.reserve(static_cast<std::size_t>(tokenList.size()));
            for (const QString& tokenText : tokenList)
            {
                QString oneByteText = tokenText.trimmed();
                if (oneByteText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
                {
                    oneByteText = oneByteText.mid(2);
                }
                bool oneByteOk = false;
                const uint oneByteValue = oneByteText.toUInt(&oneByteOk, 16);
                if (!oneByteOk || oneByteValue > 0xFFU)
                {
                    parseErrorText = QStringLiteral("HexBytes 解析失败：非法字节 '%1'").arg(tokenText);
                    payloadBuffer.clear();
                    break;
                }
                payloadBuffer.push_back(static_cast<std::uint8_t>(oneByteValue));
            }
        }
    }
    else
    {
        parseErrorText = QStringLiteral("未知输入模式");
    }

    if (!parseErrorText.isEmpty() || payloadBuffer.empty())
    {
        setStatusLabel(
            QStringLiteral("● 原始设置失败：%1").arg(parseErrorText.isEmpty() ? QStringLiteral("负载为空") : parseErrorText),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 负载解析失败, mode="
            << modeKey.toStdString()
            << ", payload="
            << payloadText.toStdString()
            << ", error="
            << parseErrorText.toStdString()
            << eol;
        return;
    }

    if (m_tokenRawApplyButton != nullptr)
    {
        m_tokenRawApplyButton->setEnabled(false);
    }
    setStatusLabel(QStringLiteral("● 正在应用原始令牌设置..."), KswordTheme::PrimaryBlueColor, 700);

    // 动态解析 NtSetInformationToken：
    // - 用户选择的信息类和值将直接透传到原生 API；
    // - 此路径用于覆盖快捷开关之外的全部可尝试设置项。
    HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
    if (ntdllModule == nullptr)
    {
        ntdllModule = LoadLibraryW(L"ntdll.dll");
    }
    const auto setInformationToken = reinterpret_cast<NtSetInformationTokenFn>(
        ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtSetInformationToken") : nullptr);
    if (setInformationToken == nullptr)
    {
        setStatusLabel(QStringLiteral("● 原始设置失败：NtSetInformationToken 不可用"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: NtSetInformationToken 不可用。"
            << eol;
        if (m_tokenRawApplyButton != nullptr)
        {
            m_tokenRawApplyButton->setEnabled(true);
        }
        return;
    }

    // 打开目标令牌：
    // - TOKEN_ADJUST_DEFAULT 覆盖大部分设置项；
    // - TOKEN_ADJUST_SESSIONID 用于 TokenSessionId 等特例信息类。
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_baseRecord.pid);
    if (processHandle == nullptr)
    {
        const DWORD openProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("应用原始进程令牌设置"), openProcessError);
        setStatusLabel(
            QStringLiteral("● 原始设置失败：OpenProcess(%1)").arg(openProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: OpenProcess 失败, error="
            << openProcessError
            << eol;
        if (m_tokenRawApplyButton != nullptr)
        {
            m_tokenRawApplyButton->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(
        processHandle,
        TOKEN_ADJUST_DEFAULT | kTokenAdjustSessionIdAccess | TOKEN_QUERY,
        &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD openTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("应用原始进程令牌设置"), openTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        setStatusLabel(
            QStringLiteral("● 原始设置失败：OpenProcessToken(%1)").arg(openTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: OpenProcessToken 失败, error="
            << openTokenError
            << eol;
        if (m_tokenRawApplyButton != nullptr)
        {
            m_tokenRawApplyButton->setEnabled(true);
        }
        return;
    }

    const TOKEN_INFORMATION_CLASS infoClass = static_cast<TOKEN_INFORMATION_CLASS>(classId);
    const NTSTATUS setStatus = setInformationToken(
        tokenHandle,
        infoClass,
        payloadBuffer.data(),
        static_cast<ULONG>(payloadBuffer.size()));

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (m_tokenRawApplyButton != nullptr)
    {
        m_tokenRawApplyButton->setEnabled(true);
    }

    if (NT_SUCCESS(setStatus))
    {
        setStatusLabel(
            QStringLiteral("● 原始设置成功：[%1] %2, size=%3")
            .arg(classId)
            .arg(tokenInfoClassNameById(static_cast<ULONG>(classId)))
            .arg(payloadBuffer.size()),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 成功, classId="
            << classId
            << ", className="
            << tokenInfoClassNameById(static_cast<ULONG>(classId)).toStdString()
            << ", payloadSize="
            << payloadBuffer.size()
            << ", payloadPreview="
            << formatTokenRawPreview(payloadBuffer, 24).toStdString()
            << eol;
    }
    else
    {
        (void)ks::ui::promptForPrivilegeNtStatus(this, QStringLiteral("应用原始进程令牌设置"), static_cast<long>(setStatus));
        setStatusLabel(
            QStringLiteral("● 原始设置失败：[%1] %2, status=%3")
            .arg(classId)
            .arg(tokenInfoClassNameById(static_cast<ULONG>(classId)))
            .arg(formatNtStatusHex(setStatus)),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 失败, classId="
            << classId
            << ", className="
            << tokenInfoClassNameById(static_cast<ULONG>(classId)).toStdString()
            << ", status="
            << formatNtStatusHex(setStatus).toStdString()
            << ", payloadSize="
            << payloadBuffer.size()
            << ", payloadPreview="
            << formatTokenRawPreview(payloadBuffer, 24).toStdString()
            << eol;
    }

    // 提交后统一刷新：
    // - 令牌详情页会重新抓取完整信息类快照；
    // - 快捷开关页会重新回读可见复选框状态。
    requestAsyncTokenRefresh();
    refreshTokenSwitchStates();
}

void ProcessDetailWindow::requestAsyncKernelCallbackRefresh()
{
    // 回调表页独立于 PEB 摘要页刷新：
    // - 只读取 PEB 指针、回调表和模块快照；
    // - 不扫描整个虚拟地址空间，避免用户仅查看回调表时承担 PEB 页的全量开销。
    if (m_kernelCallbackRefreshing || m_baseRecord.pid == 0U)
    {
        return;
    }

    m_kernelCallbackInitialRefreshStarted = true;
    m_kernelCallbackRefreshing = true;
    const std::uint64_t ticketValue = ++m_kernelCallbackRefreshTicket;
    const std::uint32_t pidValue = m_baseRecord.pid;

    if (m_refreshKernelCallbackButton != nullptr)
    {
        m_refreshKernelCallbackButton->setEnabled(false);
    }
    if (m_kernelCallbackStatusLabel != nullptr)
    {
        m_kernelCallbackStatusLabel->setText(QStringLiteral("● 正在读取内核回调表..."));
        m_kernelCallbackStatusLabel->setStyleSheet(
            buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }
    if (m_kernelCallbackRefreshProgressPid == 0)
    {
        m_kernelCallbackRefreshProgressPid = kPro.addReusable(this, "进程详情", "读取内核回调表");
    }
    kPro.set(m_kernelCallbackRefreshProgressPid, "打开目标进程", 0, 15.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    QRunnable* refreshTask = QRunnable::create([guardThis, pidValue, ticketValue]()
        {
            KernelCallbackRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();
            const auto deliverResult = [&refreshResult, beginTime, guardThis, ticketValue]()
                {
                    refreshResult.elapsedMs = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - beginTime).count());
                    QMetaObject::invokeMethod(
                        guardThis,
                        [guardThis, ticketValue, refreshResult]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_kernelCallbackRefreshTicket != ticketValue)
                            {
                                return;
                            }
                            guardThis->applyKernelCallbackRefreshResult(refreshResult);
                        },
                        Qt::QueuedConnection);
                };

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_QUERY_LIMITED_INFORMATION |
                PROCESS_VM_READ,
                FALSE,
                pidValue);
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QStringLiteral("OpenProcess失败(%1)。")
                    .arg(GetLastError());
                deliverResult();
                return;
            }

            HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
            const NtQueryInformationProcessFn ntQueryProcess =
                reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr
                        ? GetProcAddress(ntdllModule, "NtQueryInformationProcess")
                        : nullptr);
            if (ntQueryProcess == nullptr)
            {
                refreshResult.diagnosticText = QStringLiteral("无法定位NtQueryInformationProcess。");
                CloseHandle(processHandle);
                deliverResult();
                return;
            }

            PROCESS_BASIC_INFORMATION basicInformation{};
            const NTSTATUS basicStatus = ntQueryProcess(
                processHandle,
                0,
                &basicInformation,
                static_cast<ULONG>(sizeof(basicInformation)),
                nullptr);

            ULONG_PTR wow64PebAddress = 0;
            const NTSTATUS wow64Status = ntQueryProcess(
                processHandle,
                kProcessInfoClassWow64Information,
                &wow64PebAddress,
                static_cast<ULONG>(sizeof(wow64PebAddress)),
                nullptr);
            const bool useWow64Peb = NT_SUCCESS(wow64Status) && wow64PebAddress != 0U;

            std::uint64_t pebAddress = 0;
            std::uint64_t callbackTableAddress = 0;
            std::size_t pointerSize = sizeof(std::uint64_t);
            if (useWow64Peb)
            {
                refreshResult.pebKindText = QStringLiteral("Wow64PEB");
                pebAddress = static_cast<std::uint64_t>(wow64PebAddress);
                pointerSize = sizeof(std::uint32_t);

                std::uint32_t callbackTableAddress32 = 0;
                if (!readRemoteStructure(
                    processHandle,
                    pebAddress + 0x2CU,
                    callbackTableAddress32))
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "读取Wow64PEB.KernelCallbackTable失败。");
                    CloseHandle(processHandle);
                    deliverResult();
                    return;
                }
                callbackTableAddress = static_cast<std::uint64_t>(callbackTableAddress32);
            }
            else
            {
                if (!NT_SUCCESS(basicStatus) || basicInformation.PebBaseAddress == nullptr)
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "NtQueryInformationProcess(ProcessBasicInformation)失败：%1。")
                        .arg(formatNtStatusHex(basicStatus));
                    CloseHandle(processHandle);
                    deliverResult();
                    return;
                }

                refreshResult.pebKindText = QStringLiteral("NativePEB");
                pebAddress = reinterpret_cast<std::uint64_t>(basicInformation.PebBaseAddress);
                std::uint64_t callbackTableAddress64 = 0;
                if (!readRemoteStructure(
                    processHandle,
                    pebAddress + 0x58U,
                    callbackTableAddress64))
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "读取NativePEB.KernelCallbackTable失败。");
                    CloseHandle(processHandle);
                    deliverResult();
                    return;
                }
                callbackTableAddress = callbackTableAddress64;
            }

            refreshResult.pebAddressText = uint64ToHex(pebAddress);
            refreshResult.tableAddressText = uint64ToHex(callbackTableAddress);
            if (callbackTableAddress == 0U)
            {
                refreshResult.diagnosticText = QStringLiteral(
                    "KernelCallbackTable为空；目标进程可能尚未加载User32。");
                CloseHandle(processHandle);
                deliverResult();
                return;
            }
            if ((callbackTableAddress % pointerSize) != 0U)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("KernelCallbackTable地址未按指针宽度对齐。"));
            }

            MEMORY_BASIC_INFORMATION tableMemoryInfo{};
            const SIZE_T tableQuerySize = VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(callbackTableAddress)),
                &tableMemoryInfo,
                sizeof(tableMemoryInfo));
            if (tableQuerySize != sizeof(tableMemoryInfo) ||
                tableMemoryInfo.State != MEM_COMMIT ||
                (tableMemoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0U)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("KernelCallbackTable所在内存区域不可安全读取。"));
                CloseHandle(processHandle);
                deliverResult();
                return;
            }

            const ks::process::ProcessModuleSnapshot moduleSnapshot =
                ks::process::EnumerateProcessModulesAndThreads(pidValue, false);
            if (!moduleSnapshot.diagnosticText.empty())
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QString::fromStdString(moduleSnapshot.diagnosticText));
            }

            std::size_t trailingUnusableCount = 0;
            bool oldTableBoundaryDetected = false;
            for (std::size_t index = 0; index < std::size(kKernelCallbackNames); ++index)
            {
                KernelCallbackInspectItem row{};
                row.index = static_cast<std::uint32_t>(index);
                row.callbackName = QString::fromLatin1(kKernelCallbackNames[index]);
                row.moduleText = QStringLiteral("-");
                row.moduleOffsetText = QStringLiteral("-");
                row.protectionText = QStringLiteral("-");

                const std::uint64_t entryAddress =
                    callbackTableAddress + static_cast<std::uint64_t>(index * pointerSize);
                std::uint64_t callbackAddress = 0;
                bool entryReadOk = false;
                if (pointerSize == sizeof(std::uint32_t))
                {
                    std::uint32_t callbackAddress32 = 0;
                    entryReadOk = readRemoteStructure(processHandle, entryAddress, callbackAddress32);
                    callbackAddress = static_cast<std::uint64_t>(callbackAddress32);
                }
                else
                {
                    entryReadOk = readRemoteStructure(processHandle, entryAddress, callbackAddress);
                }

                bool plausibleCallback = false;
                if (!entryReadOk)
                {
                    row.addressText = QStringLiteral("-");
                    row.statusText = QStringLiteral("读取失败");
                    row.suspicious = true;
                }
                else if (callbackAddress == 0U)
                {
                    row.addressText = uint64ToHex(0);
                    row.statusText = QStringLiteral("空");
                    row.suspicious = true;
                }
                else
                {
                    row.addressText = uint64ToHex(callbackAddress);
                    MEMORY_BASIC_INFORMATION callbackMemoryInfo{};
                    const SIZE_T callbackQuerySize = VirtualQueryEx(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(callbackAddress)),
                        &callbackMemoryInfo,
                        sizeof(callbackMemoryInfo));
                    if (callbackQuerySize != sizeof(callbackMemoryInfo))
                    {
                        row.statusText = QStringLiteral("地址不可查询");
                        row.suspicious = true;
                    }
                    else
                    {
                        row.protectionText = memoryProtectToText(callbackMemoryInfo.Protect);
                        const bool committed = callbackMemoryInfo.State == MEM_COMMIT;
                        const bool guarded =
                            (callbackMemoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0U;
                        const bool executable =
                            committed && !guarded &&
                            isExecutableMemoryProtection(callbackMemoryInfo.Protect);

                        bool moduleMatched = false;
                        for (const ks::process::ProcessModuleRecord& moduleRecord : moduleSnapshot.modules)
                        {
                            if (moduleRecord.moduleBaseAddress == 0U ||
                                moduleRecord.moduleSizeBytes == 0U ||
                                callbackAddress < moduleRecord.moduleBaseAddress)
                            {
                                continue;
                            }
                            const std::uint64_t moduleOffset =
                                callbackAddress - moduleRecord.moduleBaseAddress;
                            if (moduleOffset >= static_cast<std::uint64_t>(moduleRecord.moduleSizeBytes))
                            {
                                continue;
                            }

                            row.modulePath = QString::fromStdString(moduleRecord.modulePath);
                            row.moduleText = QString::fromStdString(moduleRecord.moduleName).trimmed();
                            if (row.moduleText.isEmpty())
                            {
                                row.moduleText = QFileInfo(row.modulePath).fileName();
                            }
                            row.moduleOffsetText = uint64ToHex(moduleOffset);
                            moduleMatched = true;
                            break;
                        }

                        plausibleCallback = executable;
                        if (!committed)
                        {
                            row.statusText = QStringLiteral("未提交");
                            row.suspicious = true;
                        }
                        else if (!executable && moduleMatched)
                        {
                            row.statusText = QStringLiteral("模块内非可执行地址");
                            row.suspicious = true;
                        }
                        else if (!executable)
                        {
                            row.statusText = QStringLiteral("非模块且不可执行");
                            row.suspicious = true;
                        }
                        else if (!moduleMatched)
                        {
                            row.statusText = QStringLiteral("非模块可执行内存");
                            row.suspicious = true;
                        }
                        else
                        {
                            row.statusText = QStringLiteral("正常");
                        }
                    }
                }

                refreshResult.rows.push_back(std::move(row));
                if (plausibleCallback)
                {
                    trailingUnusableCount = 0;
                }
                else
                {
                    ++trailingUnusableCount;
                }

                if ((index + 1U) >= kKernelCallbackMinimumProbeCount &&
                    trailingUnusableCount >= kKernelCallbackBoundaryRunLength)
                {
                    refreshResult.rows.resize(
                        refreshResult.rows.size() - trailingUnusableCount);
                    oldTableBoundaryDetected = true;
                    break;
                }
            }

            if (oldTableBoundaryDetected)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("检测到连续不可用尾项，已按目标系统实际表长截断。"));
            }
            if (refreshResult.rows.empty())
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("未识别到可用的内核回调表条目。"));
            }

            CloseHandle(processHandle);
            deliverResult();
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyKernelCallbackRefreshResult(
    const KernelCallbackRefreshResult& refreshResult)
{
    m_kernelCallbackRefreshing = false;
    if (m_refreshKernelCallbackButton != nullptr)
    {
        m_refreshKernelCallbackButton->setEnabled(true);
    }

    m_kernelCallbackRows = refreshResult.rows;
    rebuildKernelCallbackTable();

    const std::size_t suspiciousCount = static_cast<std::size_t>(std::count_if(
        m_kernelCallbackRows.cbegin(),
        m_kernelCallbackRows.cend(),
        [](const KernelCallbackInspectItem& row)
        {
            return row.suspicious;
        }));

    if (m_kernelCallbackStatusLabel != nullptr)
    {
        QString statusText = QStringLiteral("● 刷新完成 %1 ms | %2 | PEB:%3 | 表:%4 | 条目:%5 | 异常:%6")
            .arg(refreshResult.elapsedMs)
            .arg(refreshResult.pebKindText.isEmpty() ? QStringLiteral("未知PEB") : refreshResult.pebKindText)
            .arg(refreshResult.pebAddressText.isEmpty() ? QStringLiteral("-") : refreshResult.pebAddressText)
            .arg(refreshResult.tableAddressText.isEmpty() ? QStringLiteral("-") : refreshResult.tableAddressText)
            .arg(m_kernelCallbackRows.size())
            .arg(suspiciousCount);
        QColor statusColor = suspiciousCount > 0U ? statusWarningColor() : statusIdleColor();
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusColor = m_kernelCallbackRows.empty() ? statusErrorColor() : statusWarningColor();
        }
        m_kernelCallbackStatusLabel->setText(statusText);
        m_kernelCallbackStatusLabel->setStyleSheet(buildStateLabelStyle(statusColor, 700));
    }

    kPro.set(m_kernelCallbackRefreshProgressPid, "内核回调表读取完成", 0, 100.0f);

    kLogEvent event;
    info << event
        << "[ProcessDetailWindow] applyKernelCallbackRefreshResult: pid="
        << m_baseRecord.pid
        << ", rows="
        << m_kernelCallbackRows.size()
        << ", suspicious="
        << suspiciousCount
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildKernelCallbackTable()
{
    if (m_kernelCallbackTable == nullptr)
    {
        return;
    }

    const bool sortingEnabled = m_kernelCallbackTable->isSortingEnabled();
    m_kernelCallbackTable->setSortingEnabled(false);
    m_kernelCallbackTable->clearContents();
    m_kernelCallbackTable->setRowCount(static_cast<int>(m_kernelCallbackRows.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(m_kernelCallbackRows.size()); ++rowIndex)
    {
        const KernelCallbackInspectItem& row = m_kernelCallbackRows[static_cast<std::size_t>(rowIndex)];
        auto* indexItem = new QTableWidgetItem();
        indexItem->setData(Qt::DisplayRole, row.index);
        auto* nameItem = new QTableWidgetItem(row.callbackName);
        auto* addressItem = new QTableWidgetItem(row.addressText);
        auto* moduleItem = new QTableWidgetItem(row.moduleText);
        auto* moduleOffsetItem = new QTableWidgetItem(row.moduleOffsetText);
        auto* protectionItem = new QTableWidgetItem(row.protectionText);
        auto* statusItem = new QTableWidgetItem(row.statusText);
        if (!row.modulePath.isEmpty())
        {
            moduleItem->setToolTip(row.modulePath);
        }

        QTableWidgetItem* items[] =
        {
            indexItem,
            nameItem,
            addressItem,
            moduleItem,
            moduleOffsetItem,
            protectionItem,
            statusItem
        };
        for (int columnIndex = 0; columnIndex < static_cast<int>(std::size(items)); ++columnIndex)
        {
            if (row.suspicious)
            {
                items[columnIndex]->setForeground(statusWarningColor());
            }
            m_kernelCallbackTable->setItem(rowIndex, columnIndex, items[columnIndex]);
        }
    }

    m_kernelCallbackTable->setSortingEnabled(sortingEnabled);
    filterKernelCallbackTable(
        m_kernelCallbackFilterEdit != nullptr ? m_kernelCallbackFilterEdit->text() : QString());
}

void ProcessDetailWindow::filterKernelCallbackTable(const QString& filterText)
{
    if (m_kernelCallbackTable == nullptr)
    {
        return;
    }

    const QString normalizedFilter = filterText.trimmed();
    for (int rowIndex = 0; rowIndex < m_kernelCallbackTable->rowCount(); ++rowIndex)
    {
        bool matched = normalizedFilter.isEmpty();
        if (!matched)
        {
            for (int columnIndex = 0; columnIndex < m_kernelCallbackTable->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* const item = m_kernelCallbackTable->item(rowIndex, columnIndex);
                if (item != nullptr && item->text().contains(normalizedFilter, Qt::CaseInsensitive))
                {
                    matched = true;
                    break;
                }
            }
        }
        m_kernelCallbackTable->setRowHidden(rowIndex, !matched);
    }
}

void ProcessDetailWindow::requestAsyncPebRefresh()
{
    // PEB页异步刷新：
    // - 展示 PEB 地址、优先级、亲和性、内存与 IO 计数；
    // - 额外输出虚拟地址空间统计摘要。
    if (m_pebRefreshing || m_baseRecord.pid == 0)
    {
        return;
    }

    // PEB/地址空间扫描只在用户进入该页或手动刷新时执行。
    m_pebInitialRefreshStarted = true;

    {
        kLogEvent event;
        info << event
            << "[ProcessDetailWindow] requestAsyncPebRefresh: 开始异步刷新, pid="
            << m_baseRecord.pid
            << eol;
    }

    m_pebRefreshing = true;
    const std::uint64_t ticketValue = ++m_pebRefreshTicket;
    if (m_refreshPebButton != nullptr)
    {
        m_refreshPebButton->setEnabled(false);
    }
    if (m_pebStatusLabel != nullptr)
    {
        m_pebStatusLabel->setText(QStringLiteral("● 正在刷新PEB..."));
        m_pebStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }

    if (m_pebRefreshProgressPid == 0)
    {
        m_pebRefreshProgressPid = kPro.addReusable(this, "进程详情", "刷新PEB信息");
    }
    kPro.set(m_pebRefreshProgressPid, "读取PEB与地址空间", 0, 20.0f);

    const std::uint32_t pidValue = m_baseRecord.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, pidValue, ticketValue]()
        {
            TextRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();
            const auto progressDispatcher = [guardThis, ticketValue](const QString& stepText, const float progressValue)
                {
                    QMetaObject::invokeMethod(
                        guardThis,
                        [guardThis, ticketValue, stepText, progressValue]()
                        {
                            if (guardThis == nullptr || guardThis->m_pebRefreshTicket != ticketValue)
                            {
                                return;
                            }
                            if (guardThis->m_pebRefreshProgressPid != 0)
                            {
                                kPro.set(
                                    guardThis->m_pebRefreshProgressPid,
                                    stepText.toStdString(),
                                    0,
                                    progressValue);
                            }
                        },
                        Qt::QueuedConnection);
                };

            progressDispatcher(QStringLiteral("打开目标进程"), 28.0f);
            std::wostringstream textBuilder;
            textBuilder << L"[PEB / Process Summary]\n";
            textBuilder << L"PID: " << pidValue << L"\n";

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pidValue);
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pidValue);
            }
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QString("OpenProcess失败(%1)").arg(GetLastError());
                textBuilder << L"OpenProcess: <failed>\n";
                progressDispatcher(QStringLiteral("打开进程失败"), 100.0f);
            }
            else
            {
                progressDispatcher(QStringLiteral("读取PEB与基础信息"), 40.0f);
                PROCESS_BASIC_INFORMATION basicInfo{};
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
                if (ntQueryProcess != nullptr)
                {
                    NTSTATUS basicStatus = ntQueryProcess(
                        processHandle,
                        static_cast<ULONG>(ProcessBasicInformation),
                        &basicInfo,
                        static_cast<ULONG>(sizeof(basicInfo)),
                        nullptr);
                    if (NT_SUCCESS(basicStatus))
                    {
                        textBuilder << L"PEB Address: "
                            << uint64ToHex(reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress)).toStdWString()
                            << L"\n";
                    }
                }

                // 命令行读取：
                // - 优先使用 ProcessCommandLineInformation；
                // - 失败时回退到已缓存的 m_baseRecord.commandLine。
                const QString commandLineText = queryCommandLineTextByNt(ntQueryProcess, processHandle);
                textBuilder << L"CommandLine: "
                    << (commandLineText.trimmed().isEmpty()
                        ? L"-"
                        : commandLineText.toStdWString())
                    << L"\n";

                // 当前目录：
                // - Nt 层当前目录在不同系统结构布局不稳定；
                // - 这里先给出“映像目录”作为稳定可得的近似值。
                QString imagePathText = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue));
                QString currentDirectoryText;
                if (!imagePathText.trimmed().isEmpty())
                {
                    currentDirectoryText = QFileInfo(imagePathText).absolutePath();
                }
                textBuilder << L"CurrentDirectory(approx): "
                    << (currentDirectoryText.trimmed().isEmpty()
                        ? L"-"
                        : currentDirectoryText.toStdWString())
                    << L"\n";

                ULONG_PTR processAffinityMask = 0;
                ULONG_PTR systemAffinityMask = 0;
                if (GetProcessAffinityMask(processHandle, &processAffinityMask, &systemAffinityMask) != FALSE)
                {
                    textBuilder << L"ProcessAffinity: " << uint64ToHex(processAffinityMask).toStdWString() << L"\n";
                    std::wostringstream coreTextBuilder;
                    bool firstCore = true;
                    for (int bitIndex = 0; bitIndex < static_cast<int>(sizeof(ULONG_PTR) * 8); ++bitIndex)
                    {
                        const ULONG_PTR mask = static_cast<ULONG_PTR>(1ULL) << bitIndex;
                        if ((processAffinityMask & mask) == 0)
                        {
                            continue;
                        }
                        if (!firstCore)
                        {
                            coreTextBuilder << L",";
                        }
                        coreTextBuilder << bitIndex;
                        firstCore = false;
                    }
                    textBuilder << L"CpuCoreAffinity: " << coreTextBuilder.str() << L"\n";
                }

                const DWORD priorityClass = GetPriorityClass(processHandle);
                textBuilder << L"PriorityClass: " << describePriorityClass(priorityClass).toStdWString() << L"\n";

                // Wow64 状态：
                // - 输出当前进程机器架构与 Wow64 来宾架构。
                USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                if (IsWow64Process2(processHandle, &processMachine, &nativeMachine) != FALSE)
                {
                    textBuilder << L"Wow64ProcessMachine: 0x"
                        << QString::number(processMachine, 16).toUpper().toStdWString()
                        << L"\n";
                    textBuilder << L"Wow64NativeMachine: 0x"
                        << QString::number(nativeMachine, 16).toUpper().toStdWString()
                        << L"\n";
                }

                // 启动时间与 CPU 时间（内核 + 用户）。
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (GetProcessTimes(
                    processHandle,
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE)
                {
                    ULARGE_INTEGER kernelValue{};
                    kernelValue.LowPart = kernelTime.dwLowDateTime;
                    kernelValue.HighPart = kernelTime.dwHighDateTime;
                    ULARGE_INTEGER userValue{};
                    userValue.LowPart = userTime.dwLowDateTime;
                    userValue.HighPart = userTime.dwHighDateTime;
                    const double kernelMs = static_cast<double>(kernelValue.QuadPart) / 10000.0;
                    const double userMs = static_cast<double>(userValue.QuadPart) / 10000.0;
                    textBuilder << L"KernelCpuMs: " << kernelMs << L"\n";
                    textBuilder << L"UserCpuMs: " << userMs << L"\n";
                }

                PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
                if (GetProcessMemoryInfo(
                    processHandle,
                    reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&memoryCounters),
                    sizeof(memoryCounters)) != FALSE)
                {
                    textBuilder << L"WorkingSet: " << memoryCounters.WorkingSetSize << L" bytes\n";
                    textBuilder << L"PrivateUsage: " << memoryCounters.PrivateUsage << L" bytes\n";
                    textBuilder << L"PeakWorkingSet: " << memoryCounters.PeakWorkingSetSize << L" bytes\n";
                    textBuilder << L"QuotaPagedPool: " << memoryCounters.QuotaPagedPoolUsage << L" bytes\n";
                    textBuilder << L"QuotaNonPagedPool: " << memoryCounters.QuotaNonPagedPoolUsage << L" bytes\n";
                    textBuilder << L"PageFaultCount: " << memoryCounters.PageFaultCount << L"\n";
                }

                IO_COUNTERS ioCounters{};
                if (GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
                {
                    textBuilder << L"ReadOps: " << ioCounters.ReadOperationCount << L"\n";
                    textBuilder << L"WriteOps: " << ioCounters.WriteOperationCount << L"\n";
                    textBuilder << L"ReadBytes: " << ioCounters.ReadTransferCount << L"\n";
                    textBuilder << L"WriteBytes: " << ioCounters.WriteTransferCount << L"\n";
                }

                progressDispatcher(QStringLiteral("解析PEB参数块"), 55.0f);

                // 子系统信息：ProcessSubsystemInformation（可用时）。
                if (ntQueryProcess != nullptr)
                {
                    ULONG subsystemInfo = 0;
                    if (queryNtProcessInfoFixed(
                        ntQueryProcess,
                        processHandle,
                        kProcessInfoClassSubsystem,
                        subsystemInfo))
                    {
                        textBuilder << L"SubsystemInformation: " << subsystemInfo << L"\n";
                    }
                }

                // PEB 参数块解析：
                // - Native PEB 按 64 位布局读取；
                // - Wow64 PEB 按 32 位布局读取，避免 32 位进程在 64 位工具里偏移错位。
                QString pebDiagnosticText;
                std::vector<RemotePebProcessParametersRead> pebReadList;
                if (basicInfo.PebBaseAddress != nullptr)
                {
                    pebReadList.push_back(readPebProcessParameters64(
                        processHandle,
                        reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress),
                        QStringLiteral("NativePEB")));
                }
                else
                {
                    appendPebDiagnostic(pebDiagnosticText, QStringLiteral("ProcessBasicInformation 未返回 PEB 地址。"));
                }

                ULONG_PTR wow64PebAddress = 0;
                if (ntQueryProcess != nullptr &&
                    queryNtProcessInfoFixed(
                        ntQueryProcess,
                        processHandle,
                        kProcessInfoClassWow64Information,
                        wow64PebAddress) &&
                    wow64PebAddress != 0 &&
                    wow64PebAddress != reinterpret_cast<ULONG_PTR>(basicInfo.PebBaseAddress))
                {
                    pebReadList.push_back(readPebProcessParameters32(
                        processHandle,
                        static_cast<std::uint64_t>(wow64PebAddress),
                        QStringLiteral("Wow64PEB")));
                }

                std::uint64_t imageBaseAddress = 0;
                for (const RemotePebProcessParametersRead& pebRead : pebReadList)
                {
                    if (!pebRead.readOk)
                    {
                        appendPebDiagnostic(
                            pebDiagnosticText,
                            QStringLiteral("%1: %2")
                            .arg(pebRead.labelText)
                            .arg(pebRead.diagnosticText));
                        continue;
                    }

                    textBuilder << L"["
                        << pebRead.labelText.toStdWString()
                        << L"]\n";
                    textBuilder << L"  PebAddress: "
                        << uint64ToHex(pebRead.pebAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  ProcessParameters: "
                        << uint64ToHex(pebRead.processParametersAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  ImageBaseAddress: "
                        << uint64ToHex(pebRead.imageBaseAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  Environment: "
                        << uint64ToHex(pebRead.environmentAddress).toStdWString()
                        << L"\n";

                    if (!pebRead.commandLineText.trimmed().isEmpty())
                    {
                        textBuilder << L"CommandLine("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.commandLineText.toStdWString()
                            << L"\n";
                    }
                    if (!pebRead.imagePathText.trimmed().isEmpty())
                    {
                        imagePathText = pebRead.imagePathText;
                        textBuilder << L"ImagePath("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.imagePathText.toStdWString()
                            << L"\n";
                    }
                    if (!pebRead.currentDirectoryText.trimmed().isEmpty())
                    {
                        currentDirectoryText = pebRead.currentDirectoryText;
                        textBuilder << L"CurrentDirectory("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.currentDirectoryText.toStdWString()
                            << L"\n";
                    }
                    if (imageBaseAddress == 0 && pebRead.imageBaseAddress != 0)
                    {
                        imageBaseAddress = pebRead.imageBaseAddress;
                    }
                }

                if (!pebDiagnosticText.trimmed().isEmpty())
                {
                    appendPebDiagnostic(refreshResult.diagnosticText, pebDiagnosticText);
                }

                // 映像入口点：
                // - 优先使用 PEB.ImageBaseAddress，避免 ToolHelp 模块快照在部分进程上阻塞；
                // - 只读取 PE 头部，不枚举模块列表。
                progressDispatcher(QStringLiteral("解析映像入口点"), 60.0f);
                if (imageBaseAddress != 0)
                {
                    textBuilder << L"ImageBaseAddress: "
                        << uint64ToHex(imageBaseAddress).toStdWString()
                        << L"\n";
                    IMAGE_DOS_HEADER dosHeader{};
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(imageBaseAddress)),
                        &dosHeader,
                        sizeof(dosHeader),
                        &bytesRead) != FALSE &&
                        bytesRead == sizeof(dosHeader) &&
                        dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
                        dosHeader.e_lfanew > 0 &&
                        dosHeader.e_lfanew < 0x100000)
                    {
                        IMAGE_NT_HEADERS64 ntHeader64{};
                        if (ReadProcessMemory(
                            processHandle,
                            reinterpret_cast<LPCVOID>(
                                static_cast<std::uintptr_t>(
                                    imageBaseAddress + static_cast<std::uint64_t>(dosHeader.e_lfanew))),
                            &ntHeader64,
                            sizeof(ntHeader64),
                            &bytesRead) != FALSE &&
                            bytesRead >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) &&
                            ntHeader64.Signature == IMAGE_NT_SIGNATURE)
                        {
                            const WORD optionalMagic = ntHeader64.OptionalHeader.Magic;
                            if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
                                optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                            {
                                const std::uint32_t entryRva = ntHeader64.OptionalHeader.AddressOfEntryPoint;
                                textBuilder << L"EntryPointRva: 0x"
                                    << QString::number(entryRva, 16).toUpper().toStdWString()
                                    << L"\n";
                                textBuilder << L"EntryPointAddress: "
                                    << uint64ToHex(imageBaseAddress + entryRva).toStdWString()
                                    << L"\n";
                            }
                        }
                    }
                }
                else
                {
                    appendPebDiagnostic(refreshResult.diagnosticText, QStringLiteral("PEB 未提供可用映像基址。"));
                }

                // 环境变量块预览：
                // - 从已成功解析的 PEB 参数块里选择第一个环境地址；
                // - 分块读取并设置 128KB 上限，避免环境块损坏时卡住后台任务。
                progressDispatcher(QStringLiteral("读取环境变量预览"), 64.0f);
                bool environmentPreviewOk = false;
                for (const RemotePebProcessParametersRead& pebRead : pebReadList)
                {
                    if (!pebRead.readOk || pebRead.environmentAddress == 0)
                    {
                        continue;
                    }

                    QString environmentDiagnosticText;
                    const QStringList environmentLines = readRemoteEnvironmentPreviewLines(
                        processHandle,
                        pebRead.environmentAddress,
                        &environmentDiagnosticText);
                    if (!environmentDiagnosticText.trimmed().isEmpty())
                    {
                        appendPebDiagnostic(refreshResult.diagnosticText, environmentDiagnosticText);
                    }
                    if (environmentLines.isEmpty())
                    {
                        continue;
                    }

                    environmentPreviewOk = true;
                    textBuilder << L"[EnvironmentPreview:"
                        << pebRead.labelText.toStdWString()
                        << L"]\n";
                    for (const QString& lineText : environmentLines)
                    {
                        textBuilder << L"  " << lineText.toStdWString() << L"\n";
                    }
                    break;
                }
                if (!environmentPreviewOk)
                {
                    textBuilder << L"[EnvironmentPreview]\n";
                    textBuilder << L"  <unavailable>\n";
                }

                SYSTEM_INFO systemInfo{};
                GetSystemInfo(&systemInfo);
                MEMORY_BASIC_INFORMATION memoryInfo{};
                std::uint64_t commitBytes = 0;
                std::uint64_t mappedBytes = 0;
                std::uint64_t imageBytes = 0;
                std::uint64_t privateBytes = 0;
                std::uint64_t regionCount = 0;
                std::uint64_t previewRegionCount = 0;
                constexpr std::uint64_t kMaxRegionScanCount = 60000;
                const std::uintptr_t minAddress =
                    reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
                const std::uintptr_t maxAddress =
                    reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
                std::uintptr_t cursorAddress = minAddress;
                bool regionScanTruncated = false;
                bool regionScanTimeout = false;
                const auto regionScanDeadline = beginTime + std::chrono::seconds(8);

                progressDispatcher(QStringLiteral("扫描虚拟地址空间"), 68.0f);
                textBuilder << L"[VirtualAddressRegionPreview]\n";
                while (cursorAddress < maxAddress)
                {
                    if (std::chrono::steady_clock::now() > regionScanDeadline)
                    {
                        regionScanTimeout = true;
                        break;
                    }

                    const SIZE_T querySize = VirtualQueryEx(
                        processHandle,
                        reinterpret_cast<LPCVOID>(cursorAddress),
                        &memoryInfo,
                        sizeof(memoryInfo));
                    if (querySize == 0)
                    {
                        break;
                    }
                    if (memoryInfo.RegionSize == 0)
                    {
                        appendPebDiagnostic(
                            refreshResult.diagnosticText,
                            QStringLiteral("虚拟内存枚举遇到零长度区域，已提前终止。"));
                        break;
                    }

                    ++regionCount;
                    if (regionCount >= kMaxRegionScanCount)
                    {
                        regionScanTruncated = true;
                        break;
                    }

                    if ((regionCount % 2000) == 0)
                    {
                        const float progressValue = std::min(
                            90.0f,
                            60.0f + static_cast<float>(regionCount) * 0.0005f);
                        progressDispatcher(QStringLiteral("扫描虚拟地址空间"), progressValue);
                    }

                    if (memoryInfo.State == MEM_COMMIT)
                    {
                        commitBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_MAPPED)
                    {
                        mappedBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_IMAGE)
                    {
                        imageBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_PRIVATE)
                    {
                        privateBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }

                    // 预览输出：最多列出 40 个 committed 区域，包含状态/保护/类型/映射文件。
                    if (memoryInfo.State == MEM_COMMIT && previewRegionCount < 40)
                    {
                        QString mappedPathText;
                        wchar_t mappedPathBuffer[1024] = {};
                        if ((memoryInfo.Type == MEM_MAPPED || memoryInfo.Type == MEM_IMAGE) &&
                            GetMappedFileNameW(
                                processHandle,
                                memoryInfo.BaseAddress,
                                mappedPathBuffer,
                                static_cast<DWORD>(std::size(mappedPathBuffer))) > 0)
                        {
                            mappedPathText = QString::fromWCharArray(mappedPathBuffer);
                        }

                        const std::uint64_t baseAddress = reinterpret_cast<std::uint64_t>(memoryInfo.BaseAddress);
                        const std::uint64_t endAddress = baseAddress + static_cast<std::uint64_t>(memoryInfo.RegionSize);
                        textBuilder << L"  "
                            << uint64ToHex(baseAddress).toStdWString()
                            << L"-"
                            << uint64ToHex(endAddress).toStdWString()
                            << L" | "
                            << memoryStateToText(memoryInfo.State).toStdWString()
                            << L" | "
                            << memoryProtectToText(memoryInfo.Protect).toStdWString()
                            << L" | "
                            << memoryTypeToText(memoryInfo.Type).toStdWString();
                        if (!mappedPathText.trimmed().isEmpty())
                        {
                            textBuilder << L" | " << mappedPathText.toStdWString();
                        }
                        textBuilder << L"\n";
                        ++previewRegionCount;
                    }

                    const std::uintptr_t nextAddress =
                        cursorAddress + static_cast<std::uintptr_t>(memoryInfo.RegionSize);
                    if (nextAddress <= cursorAddress)
                    {
                        appendPebDiagnostic(
                            refreshResult.diagnosticText,
                            QStringLiteral("虚拟内存枚举地址发生回绕，已提前终止。"));
                        break;
                    }
                    cursorAddress = nextAddress;
                }
                if (regionScanTruncated)
                {
                    appendPebDiagnostic(
                        refreshResult.diagnosticText,
                        QString("虚拟内存枚举达到上限(%1)，结果为部分数据。")
                        .arg(kMaxRegionScanCount));
                }
                if (regionScanTimeout)
                {
                    appendPebDiagnostic(
                        refreshResult.diagnosticText,
                        QStringLiteral("虚拟内存枚举超过8秒，已返回部分结果。"));
                }
                textBuilder << L"RegionCount: " << regionCount << L"\n";
                textBuilder << L"CommitBytes: " << commitBytes << L"\n";
                textBuilder << L"MappedBytes: " << mappedBytes << L"\n";
                textBuilder << L"ImageBytes: " << imageBytes << L"\n";
                textBuilder << L"PrivateBytes: " << privateBytes << L"\n";

                // 堆信息：只统计 HeapList 数量。
                // - 旧实现继续调用 Heap32First/Heap32Next 遍历全部堆块；
                // - 这些 API 在大进程、受保护进程或堆损坏场景下可能在内部长时间阻塞；
                // - PEB 页首要目标是 ProcessParameters/环境块解析，因此这里主动跳过堆块全量枚举。
                progressDispatcher(QStringLiteral("跳过堆块枚举"), 90.0f);
                textBuilder << L"HeapCount: <skipped>\n";
                textBuilder << L"HeapBlockCount: <skipped>\n";
                textBuilder << L"HeapBlockEnumeration: <skipped to keep PEB refresh bounded>\n";

                progressDispatcher(QStringLiteral("汇总PEB结果"), 95.0f);

                CloseHandle(processHandle);
            }

            if (!refreshResult.diagnosticText.trimmed().isEmpty())
            {
                textBuilder << L"[Diagnostic]\n";
                textBuilder << L"  " << refreshResult.diagnosticText.toStdWString() << L"\n";
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, ticketValue]()
                {
                    if (guardThis == nullptr || guardThis->m_pebRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyPebRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyTokenRefreshResult(const TextRefreshResult& refreshResult)
{
    m_tokenRefreshing = false;
    if (m_refreshTokenButton != nullptr)
    {
        m_refreshTokenButton->setEnabled(true);
    }
    if (m_tokenDetailOutput != nullptr)
    {
        m_tokenDetailOutput->setText(refreshResult.detailText);
    }
    if (m_tokenStatusLabel != nullptr)
    {
        m_tokenStatusLabel->setText(QString("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs));
        m_tokenStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
    kPro.set(m_tokenRefreshProgressPid, "令牌信息刷新完成", 0, 100.0f);
}

void ProcessDetailWindow::applyPebRefreshResult(const TextRefreshResult& refreshResult)
{
    m_pebRefreshing = false;
    if (m_refreshPebButton != nullptr)
    {
        m_refreshPebButton->setEnabled(true);
    }
    if (m_pebDetailOutput != nullptr)
    {
        m_pebDetailOutput->setText(refreshResult.detailText);
    }
    populatePebEditableFieldsFromText(refreshResult.detailText);
    if (m_pebStatusLabel != nullptr)
    {
        QString statusText = QString("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs);
        QString statusStyle = buildStateLabelStyle(statusIdleColor(), 600);
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusStyle = buildStateLabelStyle(statusWarningColor(), 700);
        }
        m_pebStatusLabel->setText(statusText);
        m_pebStatusLabel->setStyleSheet(statusStyle);
    }
    kPro.set(m_pebRefreshProgressPid, "PEB信息刷新完成", 0, 100.0f);

    kLogEvent event;
    info << event
        << "[ProcessDetailWindow] applyPebRefreshResult: 完成, pid="
        << m_baseRecord.pid
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::applyPebEditableFields()
{
    // PEB可编辑字段应用：
    // - 字符串字段写 RTL_USER_PROCESS_PARAMETERS 内的 UNICODE_STRING；
    // - 环境变量通过替换 Environment 指针指向的新环境块完成；
    // - 亲和性/优先级走 Win32 API，属于真实进程属性而非 PEB 字段。
    if (m_baseRecord.pid == 0)
    {
        QMessageBox::warning(this, QStringLiteral("PEB 修改"), QStringLiteral("PID 为 0，不能修改。"));
        return;
    }

    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        QStringLiteral("确认修改远程 PEB"),
        QStringLiteral(
            "即将写入目标进程的 PEB/ProcessParameters 或修改进程运行属性。\n\n"
            "错误的 CommandLine/ImagePath/CurrentDirectory/ImageBaseAddress 可能导致目标进程自身逻辑或第三方工具误判。\n"
            "建议只对测试进程执行。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    const QString targetName = (m_pebTargetCombo != nullptr)
        ? m_pebTargetCombo->currentData().toString()
        : QStringLiteral("NativePEB");
    QStringList resultLines;
    int successCount = 0;
    int failCount = 0;
    int skipCount = 0;

    HANDLE processHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_SET_INFORMATION,
        FALSE,
        m_baseRecord.pid);
    if (processHandle == nullptr)
    {
        const DWORD errorCode = GetLastError();
        // privilegePromptHandled：记录权限恢复入口是否已完整处理 OpenProcess 失败。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改远程进程 PEB"), errorCode);
        if (!privilegePromptHandled)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("PEB 修改失败"),
                QStringLiteral("OpenProcess失败：%1").arg(errorCode));
        }
        return;
    }

    PebEditTargetSnapshot targetSnapshot = queryPebEditTargetSnapshot(processHandle, targetName);
    if (!targetSnapshot.valid)
    {
        CloseHandle(processHandle);
        QMessageBox::critical(
            this,
            QStringLiteral("PEB 修改失败"),
            QStringLiteral("%1不可用：%2").arg(targetName, targetSnapshot.errorText));
        return;
    }

    const auto appendApplyResult = [&resultLines, &successCount, &failCount, &skipCount](
        const QString& fieldName,
        const bool attempted,
        const bool success,
        const QString& detailText)
        {
            if (!attempted)
            {
                ++skipCount;
                resultLines << QStringLiteral("[跳过] %1：%2").arg(fieldName, detailText);
                return;
            }
            if (success)
            {
                ++successCount;
                resultLines << QStringLiteral("[成功] %1：%2").arg(fieldName, detailText);
            }
            else
            {
                ++failCount;
                resultLines << QStringLiteral("[失败] %1：%2").arg(fieldName, detailText);
            }
        };

    const auto applyStringField = [&](const QString& fieldName, const QString& inputText) {
        if (inputText.isEmpty())
        {
            appendApplyResult(fieldName, false, false, QStringLiteral("输入为空。"));
            return;
        }

        QString currentText;
        std::uint64_t descriptorAddress = 0;
        QString errorText;
        bool writeOk = false;
        if (targetSnapshot.isWow64Target)
        {
            RemoteUnicodeString32 descriptor{};
            if (fieldName == QStringLiteral("CommandLine"))
            {
                descriptor = targetSnapshot.params32.commandLine;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, commandLine);
            }
            else if (fieldName == QStringLiteral("ImagePathName"))
            {
                descriptor = targetSnapshot.params32.imagePathName;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, imagePathName);
            }
            else
            {
                descriptor = targetSnapshot.params32.currentDirectory.dosPath;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, currentDirectory) +
                    offsetof(Curdir32, dosPath);
            }
            currentText = readRemoteUnicodeString32(processHandle, descriptor);
            if (currentText == inputText)
            {
                appendApplyResult(fieldName, false, false, QStringLiteral("未变化。"));
                return;
            }
            writeOk = updateRemoteUnicodeString32(
                processHandle,
                descriptorAddress,
                descriptor,
                inputText,
                &errorText);
        }
        else
        {
            UNICODE_STRING descriptor{};
            if (fieldName == QStringLiteral("CommandLine"))
            {
                descriptor = targetSnapshot.params64.commandLine;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, commandLine);
            }
            else if (fieldName == QStringLiteral("ImagePathName"))
            {
                descriptor = targetSnapshot.params64.imagePathName;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, imagePathName);
            }
            else
            {
                descriptor = targetSnapshot.params64.currentDirectory.dosPath;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, currentDirectory) +
                    offsetof(Curdir64, dosPath);
            }
            currentText = readRemoteUnicodeString64(processHandle, descriptor);
            if (currentText == inputText)
            {
                appendApplyResult(fieldName, false, false, QStringLiteral("未变化。"));
                return;
            }
            writeOk = updateRemoteUnicodeString64(
                processHandle,
                descriptorAddress,
                descriptor,
                inputText,
                &errorText);
        }

        appendApplyResult(
            fieldName,
            true,
            writeOk,
            writeOk
                ? QStringLiteral("已写入 %1 字符。").arg(inputText.size())
                : errorText);
    };

    if (m_pebCommandLineEdit != nullptr)
    {
        applyStringField(QStringLiteral("CommandLine"), m_pebCommandLineEdit->text());
    }
    if (m_pebImagePathEdit != nullptr)
    {
        applyStringField(QStringLiteral("ImagePathName"), m_pebImagePathEdit->text());
    }
    if (m_pebCurrentDirectoryEdit != nullptr)
    {
        applyStringField(QStringLiteral("CurrentDirectory"), m_pebCurrentDirectoryEdit->text());
    }

    if (m_pebEnvironmentNameEdit != nullptr && !m_pebEnvironmentNameEdit->text().trimmed().isEmpty())
    {
        QString errorText;
        const bool envOk = updateRemoteEnvironmentVariable(
            processHandle,
            targetSnapshot,
            m_pebEnvironmentNameEdit->text(),
            (m_pebEnvironmentValueEdit != nullptr) ? m_pebEnvironmentValueEdit->text() : QString(),
            &errorText);
        appendApplyResult(
            QStringLiteral("Environment"),
            true,
            envOk,
            envOk
                ? QStringLiteral("已新增/替换 %1。").arg(m_pebEnvironmentNameEdit->text().trimmed())
                : errorText);
    }
    else
    {
        appendApplyResult(QStringLiteral("Environment"), false, false, QStringLiteral("未填写变量名。"));
    }

    if (m_pebImageBaseEdit != nullptr && !m_pebImageBaseEdit->text().trimmed().isEmpty())
    {
        std::uint64_t imageBaseValue = 0;
        if (!parseUnsignedIntegerText(m_pebImageBaseEdit->text(), imageBaseValue))
        {
            appendApplyResult(QStringLiteral("ImageBaseAddress"), true, false, QStringLiteral("数值格式无效。"));
        }
        else if (imageBaseValue == targetSnapshot.imageBaseAddress)
        {
            appendApplyResult(QStringLiteral("ImageBaseAddress"), false, false, QStringLiteral("未变化。"));
        }
        else
        {
            QString errorText;
            const bool imageBaseOk = updatePebImageBaseAddress(
                processHandle,
                targetSnapshot,
                imageBaseValue,
                &errorText);
            appendApplyResult(
                QStringLiteral("ImageBaseAddress"),
                true,
                imageBaseOk,
                imageBaseOk ? QStringLiteral("已写入 %1。").arg(uint64ToHex(imageBaseValue)) : errorText);
        }
    }
    else
    {
        appendApplyResult(QStringLiteral("ImageBaseAddress"), false, false, QStringLiteral("输入为空。"));
    }

    if (m_pebAffinityMaskEdit != nullptr && !m_pebAffinityMaskEdit->text().trimmed().isEmpty())
    {
        std::uint64_t affinityValue = 0;
        if (!parseUnsignedIntegerText(m_pebAffinityMaskEdit->text(), affinityValue) || affinityValue == 0)
        {
            appendApplyResult(QStringLiteral("AffinityMask"), true, false, QStringLiteral("亲和性掩码格式无效或为0。"));
        }
        else
        {
            ULONG_PTR processAffinity = 0;
            ULONG_PTR systemAffinity = 0;
            const bool queryAffinityOk = GetProcessAffinityMask(processHandle, &processAffinity, &systemAffinity) != FALSE;
            if (queryAffinityOk && static_cast<std::uint64_t>(processAffinity) == affinityValue)
            {
                appendApplyResult(QStringLiteral("AffinityMask"), false, false, QStringLiteral("未变化。"));
            }
            else if (affinityValue > static_cast<std::uint64_t>(std::numeric_limits<ULONG_PTR>::max()))
            {
                appendApplyResult(QStringLiteral("AffinityMask"), true, false, QStringLiteral("掩码超过当前进程位宽。"));
            }
            else if (SetProcessAffinityMask(processHandle, static_cast<ULONG_PTR>(affinityValue)) == FALSE)
            {
                appendApplyResult(
                    QStringLiteral("AffinityMask"),
                    true,
                    false,
                    QStringLiteral("SetProcessAffinityMask失败(%1)。").arg(GetLastError()));
            }
            else
            {
                appendApplyResult(
                    QStringLiteral("AffinityMask"),
                    true,
                    true,
                    QStringLiteral("已设置为 %1。").arg(uint64ToHex(affinityValue)));
            }
        }
    }
    else
    {
        appendApplyResult(QStringLiteral("AffinityMask"), false, false, QStringLiteral("输入为空。"));
    }

    if (m_pebPriorityClassCombo != nullptr)
    {
        const DWORD priorityClass = static_cast<DWORD>(m_pebPriorityClassCombo->currentData().toUInt());
        if (priorityClass == 0)
        {
            appendApplyResult(QStringLiteral("PriorityClass"), false, false, QStringLiteral("选择为不修改。"));
        }
        else
        {
            const DWORD currentPriority = GetPriorityClass(processHandle);
            if (currentPriority == priorityClass)
            {
                appendApplyResult(QStringLiteral("PriorityClass"), false, false, QStringLiteral("未变化。"));
            }
            else if (SetPriorityClass(processHandle, priorityClass) == FALSE)
            {
                appendApplyResult(
                    QStringLiteral("PriorityClass"),
                    true,
                    false,
                    QStringLiteral("SetPriorityClass失败(%1)。").arg(GetLastError()));
            }
            else
            {
                appendApplyResult(
                    QStringLiteral("PriorityClass"),
                    true,
                    true,
                    QStringLiteral("已设置为 %1。").arg(describePriorityClass(priorityClass)));
            }
        }
    }

    CloseHandle(processHandle);

    const QString summaryText = QStringLiteral("成功 %1，失败 %2，跳过 %3")
        .arg(successCount)
        .arg(failCount)
        .arg(skipCount);
    if (m_pebStatusLabel != nullptr)
    {
        m_pebStatusLabel->setText(QStringLiteral("● PEB修改完成：%1").arg(summaryText));
        m_pebStatusLabel->setStyleSheet(buildStateLabelStyle(
            failCount == 0 ? statusIdleColor() : statusWarningColor(),
            700));
    }

    QMessageBox::information(
        this,
        QStringLiteral("PEB 修改结果"),
        summaryText + QStringLiteral("\n\n") + resultLines.join('\n'));
    requestAsyncPebRefresh();
}

void ProcessDetailWindow::populatePebEditableFieldsFromText(const QString& detailText)
{
    // PEB编辑区自动填充：
    // - 从刷新文本中抽取当前选中 PEB 的字符串字段；
    // - 数值类字段优先取全局 ProcessAffinity/PriorityClass/ImageBaseAddress；
    // - 只更新编辑框内容，不触发任何远程写入。
    if (detailText.trimmed().isEmpty())
    {
        return;
    }

    const QString targetName = (m_pebTargetCombo != nullptr)
        ? m_pebTargetCombo->currentData().toString()
        : QStringLiteral("NativePEB");
    const QString escapedTarget = QRegularExpression::escape(targetName);

    const auto captureSingleLine = [&detailText](const QString& patternText) -> QString
        {
            const QRegularExpression pattern(
                patternText,
                QRegularExpression::MultilineOption);
            const QRegularExpressionMatch match = pattern.match(detailText);
            if (!match.hasMatch())
            {
                return QString();
            }
            return match.captured(1).trimmed();
        };

    const QString commandLineText = captureSingleLine(
        QStringLiteral("^CommandLine\\(%1\\):\\s*(.*)$").arg(escapedTarget));
    const QString imagePathText = captureSingleLine(
        QStringLiteral("^ImagePath\\(%1\\):\\s*(.*)$").arg(escapedTarget));
    const QString currentDirectoryText = captureSingleLine(
        QStringLiteral("^CurrentDirectory\\(%1\\):\\s*(.*)$").arg(escapedTarget));
    const QString imageBaseText = captureSingleLine(
        QStringLiteral("^\\s*ImageBaseAddress:\\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\\s*$"));
    const QString affinityText = captureSingleLine(
        QStringLiteral("^ProcessAffinity:\\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\\s*$"));
    const QString priorityText = captureSingleLine(QStringLiteral("^PriorityClass:\\s*([^\\r\\n]+)\\s*$"));

    if (m_pebCommandLineEdit != nullptr)
    {
        m_pebCommandLineEdit->setText(commandLineText);
    }
    if (m_pebImagePathEdit != nullptr)
    {
        m_pebImagePathEdit->setText(imagePathText);
    }
    if (m_pebCurrentDirectoryEdit != nullptr)
    {
        m_pebCurrentDirectoryEdit->setText(currentDirectoryText);
    }
    if (m_pebImageBaseEdit != nullptr && !imageBaseText.isEmpty())
    {
        m_pebImageBaseEdit->setText(imageBaseText);
    }
    if (m_pebAffinityMaskEdit != nullptr && !affinityText.isEmpty())
    {
        m_pebAffinityMaskEdit->setText(affinityText);
    }
    if (m_pebPriorityClassCombo != nullptr && !priorityText.isEmpty())
    {
        const QString normalizedPriority = priorityText.section('(', 0, 0).trimmed();
        for (int index = 0; index < m_pebPriorityClassCombo->count(); ++index)
        {
            if (m_pebPriorityClassCombo->itemText(index).compare(normalizedPriority, Qt::CaseInsensitive) == 0)
            {
                m_pebPriorityClassCombo->setCurrentIndex(index);
                break;
            }
        }
    }
}

void ProcessDetailWindow::requestAsyncSectionRefresh()
{
    // Section/ControlArea 查询入口：
    // - 不把 m_baseRecord.r0SectionObjectAddress 传给驱动；
    // - 驱动侧根据 PID 重新查 EPROCESS.SectionObject，避免诊断地址成为凭据。
    if (m_sectionInfoRefreshing)
    {
        return;
    }
    if (m_baseRecord.pid == 0)
    {
        return;
    }

    // Section/ControlArea 查询依赖驱动 IOCTL，使用首刷标记避免切页重复触发。
    m_sectionInfoInitialRefreshStarted = true;

    m_sectionInfoRefreshing = true;
    ++m_sectionInfoRefreshTicket;
    const std::uint64_t ticketValue = m_sectionInfoRefreshTicket;
    const std::uint32_t processId = m_baseRecord.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    if (m_refreshSectionInfoButton != nullptr)
    {
        m_refreshSectionInfoButton->setEnabled(false);
    }
    if (m_sectionInfoStatusLabel != nullptr)
    {
        m_sectionInfoStatusLabel->setText(QStringLiteral("● 正在查询 Section/ControlArea..."));
        m_sectionInfoStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }

    // kProgress 当前只暴露 add/set 两阶段接口：
    // - add 创建任务卡片并返回任务 ID；
    // - set 刷新步骤文本与进度，最终由 100% 触发自动隐藏。
    if (m_sectionInfoRefreshProgressPid == 0)
    {
        m_sectionInfoRefreshProgressPid = kPro.addReusable(this, "进程详情", "查询 Section/ControlArea");
    }
    kPro.set(m_sectionInfoRefreshProgressPid, QStringLiteral("查询 PID=%1 的 Section/ControlArea").arg(processId).toStdString(), 0, 5.0f);

    auto* refreshTask = QRunnable::create(
        [guardThis, ticketValue, processId]()
        {
            const auto beginTime = std::chrono::steady_clock::now();
            SectionRefreshResult refreshResult{};
            std::wstringstream textBuilder;
            const ksword::ark::DriverClient driverClient;

            const ksword::ark::ProcessRuntimeDetailResult processDetailResult =
                driverClient.queryProcessRuntimeDetail(processId);
            const ksword::ark::DynDataStatusResult dynDataStatusResult =
                driverClient.queryDynDataStatus();
            QString deepIdentityGuardText;
            bool deepIdentityMatched = false;
            if (dynDataStatusResult.io.ok)
            {
                deepIdentityMatched = pdbRuntimeCatalogMatchesKernelIdentity(
                    dynDataStatusResult.ntoskrnl.timeDateStamp,
                    dynDataStatusResult.ntoskrnl.sizeOfImage,
                    &deepIdentityGuardText);
            }
            else
            {
                const QString readableDynDataMessage = readableRuntimeIoMessage(
                    QString::fromStdString(dynDataStatusResult.io.message),
                    QStringLiteral("DynData状态"),
                    QStringLiteral("DynData status 查询没有返回额外说明。"),
                    false);
                deepIdentityGuardText = QStringLiteral(
                    "[PDB Deep Runtime Identity Guard]\n"
                    "结论: 不匹配，跳过只读采样\n"
                    "原因: DynData status 查询不可用，无法校验 deep offset 与当前内核 identity。%1")
                    .arg(readableDynDataMessage);
            }
            const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> processSampleItems =
                deepIdentityMatched
                ? buildPdbRuntimeSampleItems(QStringLiteral("process_detail"), 64)
                : std::vector<ksword::ark::RuntimeFieldSampleRequestItem>{};
            const ksword::ark::RuntimeFieldSampleResult processSampleResult = (!deepIdentityMatched || processSampleItems.empty())
                ? ksword::ark::RuntimeFieldSampleResult{}
                : driverClient.queryProcessRuntimeFieldSamples(processId, processSampleItems);
            const auto sectionResult = driverClient.queryProcessSection(
                processId,
                KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL,
                KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);

            const auto statusHex = [](const long status) -> QString
                {
                    return QStringLiteral("0x%1")
                        .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
                        .toUpper();
                };
            const auto sectionStatusText = [](const std::uint32_t statusValue) -> QString
                {
                    switch (statusValue)
                    {
                    case KSWORD_ARK_SECTION_QUERY_STATUS_OK:
                        return QStringLiteral("OK");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_PARTIAL:
                        return QStringLiteral("Partial");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_DYNDATA_MISSING:
                        return QStringLiteral("DynData Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_PROCESS_LOOKUP_FAILED:
                        return QStringLiteral("Process Lookup Failed");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_SECTION_OBJECT_MISSING:
                        return QStringLiteral("SectionObject Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING:
                        return QStringLiteral("ControlArea Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_REMOTE_UNSUPPORTED:
                        return QStringLiteral("Remote Mapping Unsupported");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED:
                        return QStringLiteral("Mapping Query Failed");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL:
                        return QStringLiteral("Buffer Too Small");
                    default:
                        return QStringLiteral("Unavailable");
                    }
                };
            const auto mappingTypeText = [](const std::uint32_t typeValue) -> QString
                {
                    switch (typeValue)
                    {
                    case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS:
                        return QStringLiteral("Process");
                    case KSWORD_ARK_SECTION_MAP_TYPE_SESSION:
                        return QStringLiteral("Session");
                    case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE:
                        return QStringLiteral("SystemCache");
                    default:
                        return QStringLiteral("Unknown");
                    }
                };

            textBuilder << L"[R0 Process Runtime Detail]\n";
            if (processDetailResult.io.ok)
            {
                const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& processDetail =
                    processDetailResult.response;
                textBuilder << L"Status: "
                    << runtimeDetailStatusText(processDetail.status).toStdWString()
                    << L"\n";
                textBuilder << L"PID/Image: "
                    << processDetail.processId
                    << L" / "
                    << fixedRuntimeImageName(
                        processDetail.imageName,
                        KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS).toStdWString()
                    << L"\n";
                textBuilder << L"Object/UniqueProcessId: "
                    << uint64ToHex(processDetail.processObjectAddress).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.uniqueProcessIdValue).toStdWString()
                    << L"\n";
                textBuilder << L"ActiveProcessLinks: Flink="
                    << uint64ToHex(processDetail.activeProcessLinksFlink).toStdWString()
                    << L", Blink="
                    << uint64ToHex(processDetail.activeProcessLinksBlink).toStdWString()
                    << L"\n";
                textBuilder << L"ThreadListHead: Flink="
                    << uint64ToHex(processDetail.threadListHeadFlink).toStdWString()
                    << L", Blink="
                    << uint64ToHex(processDetail.threadListHeadBlink).toStdWString()
                    << L"\n";
                textBuilder << L"ObjectTable/SectionObject: "
                    << uint64ToHex(processDetail.objectTableAddress).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.sectionObjectAddress).toStdWString()
                    << L"\n";
                textBuilder << L"TokenFastRef/TokenObject: "
                    << uint64ToHex(processDetail.tokenFastRef).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.tokenObjectAddress).toStdWString()
                    << L"\n";
                textBuilder << L"Protection/Signature/SectionSignature: 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.protection), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L" / 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.signatureLevel), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L" / 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.sectionSignatureLevel), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L"\n";
                textBuilder << L"已采集字段: "
                    << processRuntimeFieldListText(processDetail.fieldFlags).toStdWString()
                    << L"\n";
                textBuilder << L"Offsets: UniquePid="
                    << uint64ToHex(processDetail.offsets.epUniqueProcessId).toStdWString()
                    << L", ActiveLinks="
                    << uint64ToHex(processDetail.offsets.epActiveProcessLinks).toStdWString()
                    << L", ThreadList="
                    << uint64ToHex(processDetail.offsets.epThreadListHead).toStdWString()
                    << L", ImageFileName="
                    << uint64ToHex(processDetail.offsets.epImageFileName).toStdWString()
                    << L", Token="
                    << uint64ToHex(processDetail.offsets.epToken).toStdWString()
                    << L", ObjectTable="
                    << uint64ToHex(processDetail.offsets.epObjectTable).toStdWString()
                    << L", SectionObject="
                    << uint64ToHex(processDetail.offsets.epSectionObject).toStdWString()
                    << L"\n";
                textBuilder << L"OffsetSources: "
                    << processRuntimeOffsetSourceText(processDetail).toStdWString()
                    << L"\n";
                textBuilder << L"KernelGlobals: "
                    << runtimeKernelGlobalsText(processDetail.kernelGlobals).toStdWString()
                    << L"\n";
                textBuilder << L"DynData已具备能力: "
                    << runtimeCapabilityMaskText(processDetail.dynDataCapabilityMask, false).toStdWString()
                    << L"\n";
                textBuilder << L"DynData缺失能力: "
                    << runtimeCapabilityMaskText(processDetail.missingCapabilityMask, true).toStdWString()
                    << L"\n";
                textBuilder << L"LastStatus: "
                    << ntStatusHexText(processDetail.lastStatus).toStdWString()
                    << L"\n";
                textBuilder << L"说明: "
                    << runtimeSamplingSummaryText(
                        fixedRuntimeWideText(
                            processDetail.detail,
                            KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS),
                        QStringLiteral("进程")).toStdWString()
                    << L"\n\n";
            }
            else
            {
                const QString rawMessage =
                    QString::fromStdString(processDetailResult.io.message).trimmed();
                const QString readableMessage = readableRuntimeIoMessage(
                    rawMessage,
                    QStringLiteral("进程详情"),
                    QStringLiteral("进程 runtime detail 暂不可用。"),
                    processDetailResult.unsupported);
                textBuilder << L"Status: unavailable\n";
                textBuilder << L"说明: " << readableMessage.toStdWString() << L"\n\n";
            }

            textBuilder << L"[PDB Deep Runtime Sample - process_detail]\n";
            textBuilder << deepIdentityGuardText.toStdWString() << L"\n";
            if (!deepIdentityMatched)
            {
                textBuilder << L"deep catalog identity 未与当前 ntoskrnl 匹配，已跳过 R0 字段采样，避免错误偏移。\n\n";
            }
            else if (processSampleItems.empty())
            {
                textBuilder << L"PDB deep offset JSON 未提供可安全采样的小字段，或 profiles\\pdb_deep_offsets 未找到。\n\n";
            }
            else
            {
                textBuilder << runtimeFieldSampleResultText(
                    processSampleResult,
                    QStringLiteral("进程 PDB deep 字段采样")).toStdWString()
                    << L"\n\n";
            }

            textBuilder << L"[PDB Deep Runtime Catalog - process_detail]\n"
                << buildPdbRuntimeCatalogPreview(QStringLiteral("process_detail"), 64, 1024).toStdWString()
                << L"\n\n";
            textBuilder << L"[PDB Deep Runtime Catalog - thread_detail]\n"
                << buildPdbRuntimeCatalogPreview(QStringLiteral("thread_detail"), 64, 1024).toStdWString()
                << L"\n\n";

            // 追加更广的 PDB deep offset domain：
            // - 输入：ntkrnlmp deep JSON 中已批量生成的 handle/module/memory/ipc/callback/common domain；
            // - 处理：只展示目录预览，不发起额外 R0 调用，不扩大当前查询的权限面；
            // - 返回：写入 CodeEditorWidget 文本，让进程详情页能直接看到备用偏移库不只是摘要。
            const auto appendDeepCatalogPreviewDomain =
                [&textBuilder](const QString& domainName, const QString& titleText)
            {
                textBuilder << L"[PDB Deep Runtime Catalog - "
                    << titleText.toStdWString()
                    << L"]\n"
                    << buildPdbRuntimeCatalogPreview(domainName, 32, 256).toStdWString()
                    << L"\n\n";
            };
            appendDeepCatalogPreviewDomain(QStringLiteral("handle_object_detail"), QStringLiteral("handle_object_detail"));
            appendDeepCatalogPreviewDomain(QStringLiteral("memory_section_detail"), QStringLiteral("memory_section_detail"));
            appendDeepCatalogPreviewDomain(QStringLiteral("module_driver_detail"), QStringLiteral("module_driver_detail"));
            appendDeepCatalogPreviewDomain(QStringLiteral("ipc_alpc_detail"), QStringLiteral("ipc_alpc_detail"));
            appendDeepCatalogPreviewDomain(QStringLiteral("callback_registry_security"), QStringLiteral("callback_registry_security"));
            appendDeepCatalogPreviewDomain(QStringLiteral("common_kernel_primitives"), QStringLiteral("common_kernel_primitives"));
            appendDeepCatalogPreviewDomain(QStringLiteral("kernel_global_detail"), QStringLiteral("kernel_global_detail"));

            const QString rawSectionIoMessage =
                QString::fromStdString(sectionResult.io.message).trimmed();
            const QString readableSectionIoMessage = readableRuntimeIoMessage(
                rawSectionIoMessage,
                QStringLiteral("Section/ControlArea"),
                QStringLiteral("无额外驱动消息。"),
                false);

            textBuilder << L"[R0 Section Query]\n";
            textBuilder << L"IO说明: " << readableSectionIoMessage.toStdWString() << L"\n";
            if (!sectionResult.io.ok)
            {
                refreshResult.diagnosticText = readableSectionIoMessage;
            }
            else
            {
                textBuilder << L"Status: " << sectionStatusText(sectionResult.queryStatus).toStdWString() << L"\n";
                textBuilder << L"LastStatus: " << statusHex(sectionResult.lastStatus).toStdWString() << L"\n";
                textBuilder << L"FieldFlags: " << uint64ToHex(sectionResult.fieldFlags).toStdWString() << L"\n";
                textBuilder << L"DynDataCapability: " << uint64ToHex(sectionResult.dynDataCapabilityMask).toStdWString() << L"\n";
                textBuilder << L"SectionObject: " << uint64ToHex(sectionResult.sectionObjectAddress).toStdWString() << L"\n";
                textBuilder << L"ControlArea: " << uint64ToHex(sectionResult.controlAreaAddress).toStdWString() << L"\n";
                textBuilder << L"EpSectionObjectOffset: " << uint64ToHex(sectionResult.epSectionObjectOffset).toStdWString() << L"\n";
                textBuilder << L"MmSectionControlAreaOffset: " << uint64ToHex(sectionResult.mmSectionControlAreaOffset).toStdWString() << L"\n";
                textBuilder << L"MmControlAreaListHeadOffset: " << uint64ToHex(sectionResult.mmControlAreaListHeadOffset).toStdWString() << L"\n";
                textBuilder << L"MmControlAreaLockOffset: " << uint64ToHex(sectionResult.mmControlAreaLockOffset).toStdWString() << L"\n";
                textBuilder << L"Mappings: total=" << sectionResult.totalCount
                    << L", returned=" << sectionResult.returnedCount
                    << L", parsed=" << sectionResult.mappings.size() << L"\n";

                if ((sectionResult.fieldFlags & KSWORD_ARK_SECTION_FIELD_REMOTE_MAPPING_UNSUPPORTED) != 0U)
                {
                    textBuilder << L"RemoteMapping: unsupported by current ControlArea marker\n";
                }
                if ((sectionResult.fieldFlags & KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED) != 0U)
                {
                    textBuilder << L"MappingList: truncated\n";
                }

                textBuilder << L"[Mappings]\n";
                if (sectionResult.mappings.empty())
                {
                    textBuilder << L"  <empty or unavailable>\n";
                }
                else
                {
                    for (const auto& mappingEntry : sectionResult.mappings)
                    {
                        textBuilder << L"  "
                            << mappingTypeText(mappingEntry.viewMapType).toStdWString()
                            << L" | PID=" << mappingEntry.processId
                            << L" | "
                            << uint64ToHex(mappingEntry.startVa).toStdWString()
                            << L"-"
                            << uint64ToHex(mappingEntry.endVa).toStdWString()
                            << L"\n";
                    }
                }
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, ticketValue]()
                {
                    if (guardThis == nullptr || guardThis->m_sectionInfoRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applySectionRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applySectionRefreshResult(const SectionRefreshResult& refreshResult)
{
    m_sectionInfoRefreshing = false;
    if (m_refreshSectionInfoButton != nullptr)
    {
        m_refreshSectionInfoButton->setEnabled(true);
    }
    if (m_sectionInfoOutput != nullptr)
    {
        m_sectionInfoOutput->setText(refreshResult.detailText);
    }
    if (m_sectionInfoStatusLabel != nullptr)
    {
        QString statusText = QStringLiteral("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs);
        QString statusStyle = buildStateLabelStyle(statusIdleColor(), 600);
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusStyle = buildStateLabelStyle(statusWarningColor(), 700);
            kLogEvent diagnosticEvent;
            warn << diagnosticEvent
                << "[ProcessDetailWindow] section refresh completed with diagnostics, pid="
                << m_baseRecord.pid
                << ", diagnostic="
                << refreshResult.diagnosticText.toStdString()
                << eol;
        }
        m_sectionInfoStatusLabel->setText(statusText);
        m_sectionInfoStatusLabel->setStyleSheet(statusStyle);
    }
    kPro.set(m_sectionInfoRefreshProgressPid, "Section/ControlArea 查询完成", 0, 100.0f);
}
