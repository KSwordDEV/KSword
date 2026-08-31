// DisableDseBackend.cpp
// 说明见 DisableDseBackend.h。本文件只做定位与 R0 访问，不含任何 UI。

#include "DisableDseBackend.h"

#include "../../ArkDriverClient/ArkDriverClient.h"

#include <windows.h>

#include <Zydis.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace
{
    // kSystemModuleInformationClass：
    // - SystemModuleInformation 的类号，用于枚举内核模块拿 CI 模块基址。
    constexpr unsigned long kSystemModuleInformationClass = 11UL;

    // kSystemCodeIntegrityInformationClass：
    // - SystemCodeIntegrityInformation 的类号，R3 回退通道读 CodeIntegrityOptions。
    constexpr unsigned long kSystemCodeIntegrityInformationClass = 103UL;

    // kStatusInfoLengthMismatch：
    // - STATUS_INFO_LENGTH_MISMATCH，缓冲区不够时的返回值。
    constexpr long kStatusInfoLengthMismatch = static_cast<long>(0xC0000004L);

    // kFirstCiDllBuild：
    // - Win8（build 9200）起 DSE 开关搬进 CI.dll!g_CiOptions；更早的系统在 nt!g_CiEnabled。
    constexpr std::uint32_t kFirstCiDllBuild = 9200U;

    // kCipInitializeCallBuild：
    // - build 16299 起 CiInitialize 用 call 进 CipInitialize，更早是 jmp。
    constexpr std::uint32_t kCipInitializeCallBuild = 16299U;

    // kScanLimit：
    // - 两段反汇编扫描的字节上限；目标指令都在函数开头很近的位置。
    constexpr std::size_t kScanLimit = 256U;

    // kCiOptionsSize：
    // - g_CiOptions 是 ULONG，读写宽度固定 4 字节。
    constexpr std::uint32_t kCiOptionsSize = 4U;

    // NtQuerySystemInformationFunction：
    // - NtQuerySystemInformation 的调用约定签名。
    using NtQuerySystemInformationFunction = long(NTAPI*)(
        unsigned long systemInformationClass,
        void* systemInformation,
        unsigned long systemInformationLength,
        unsigned long* returnLength);

    // KernelModuleRow / KernelModuleList：
    // - RTL_PROCESS_MODULE_INFORMATION 与其列表头的本地定义，避免依赖 DDK 头。
    struct KernelModuleRow
    {
        void* section;
        void* mappedBase;
        void* imageBase;
        unsigned long imageSize;
        unsigned long flags;
        unsigned short loadOrderIndex;
        unsigned short initOrderIndex;
        unsigned short loadCount;
        unsigned short fileNameOffset;
        unsigned char fullPathName[256];
    };

    struct KernelModuleList
    {
        unsigned long count;
        KernelModuleRow rows[1];
    };

    // SystemCodeIntegrityInformationBlock：
    // - SYSTEM_CODEINTEGRITY_INFORMATION 的本地定义。
    struct SystemCodeIntegrityInformationBlock
    {
        unsigned long length;
        unsigned long codeIntegrityOptions;
    };

    // CodeIntegrity 选项位。名称沿用 Windows SDK 的 CODEINTEGRITY_OPTION_*。
    constexpr std::uint32_t kOptionEnabled = 0x00000001U;
    constexpr std::uint32_t kOptionTestSign = 0x00000002U;
    constexpr std::uint32_t kOptionUmciEnabled = 0x00000004U;
    constexpr std::uint32_t kOptionHvciKmciEnabled = 0x00000400U;
    constexpr std::uint32_t kOptionHvciKmciStrictMode = 0x00001000U;

    // resolveNtQuerySystemInformation：
    // - 作用：取 ntdll 里的 NtQuerySystemInformation；
    // - 返回：函数指针，失败返回 nullptr。
    NtQuerySystemInformationFunction resolveNtQuerySystemInformation()
    {
        const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(ntdll, "NtQuerySystemInformation"));
    }

    // currentBuildNumber：
    // - 作用：从 PEB 读当前系统内部版本号，避免受兼容性清单影响；
    // - 返回：build 号；读不到时返回 0。
    std::uint32_t currentBuildNumber()
    {
        // x64 下 PEB 在 gs:[0x60]，OSBuildNumber 位于 PEB+0x120。
        const auto peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
        if (peb == nullptr)
        {
            return 0U;
        }
        return *reinterpret_cast<const unsigned short*>(peb + 0x120);
    }

    // ntHeadersOf：
    // - 输入 base：SEC_IMAGE 映射基址；
    // - 作用：校验 DOS/NT 签名并返回 64 位 NT 头；
    // - 返回：NT 头指针，非 PE64 时返回 nullptr。
    const IMAGE_NT_HEADERS64* ntHeadersOf(const unsigned char* base)
    {
        if (base == nullptr)
        {
            return nullptr;
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return nullptr;
        }
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE
            || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return nullptr;
        }
        return nt;
    }

    // sectionNameOfRva：
    // - 输入 base：映射基址；rva：待判定的 RVA；
    // - 作用：找出该 RVA 落在哪个节；
    // - 返回：节名；不在任何节内时返回空串。
    QString sectionNameOfRva(const unsigned char* base, const std::uint64_t rva)
    {
        const IMAGE_NT_HEADERS64* const nt = ntHeadersOf(base);
        if (nt == nullptr)
        {
            return QString();
        }
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
        {
            const DWORD virtualSize = section->Misc.VirtualSize != 0U
                ? section->Misc.VirtualSize
                : section->SizeOfRawData;
            if (rva >= section->VirtualAddress
                && rva < static_cast<std::uint64_t>(section->VirtualAddress) + virtualSize)
            {
                char name[9] = {};
                std::memcpy(name, section->Name, 8);
                return QString::fromLatin1(name);
            }
        }
        return QString();
    }

    // rvaIsInSection：
    // - 输入 base：映射基址；rva：待判定 RVA；name：目标节名；
    // - 作用：判定 RVA 是否落在指定节内；
    // - 返回：true 表示落在该节。
    bool rvaIsInSection(
        const unsigned char* const base,
        const std::uint64_t rva,
        const char* const name)
    {
        return sectionNameOfRva(base, rva).compare(
            QString::fromLatin1(name), Qt::CaseInsensitive) == 0;
    }

    // findExportRva：
    // - 输入 base：SEC_IMAGE 映射基址；name：导出函数名；
    // - 作用：手工解析导出表按名字查 RVA，映射是只读资源映射，不能用 GetProcAddress；
    // - 返回：导出项 RVA；未找到返回 0。
    std::uint32_t findExportRva(const unsigned char* const base, const char* const name)
    {
        const IMAGE_NT_HEADERS64* const nt = ntHeadersOf(base);
        if (nt == nullptr)
        {
            return 0U;
        }
        const IMAGE_DATA_DIRECTORY& directory =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress == 0U || directory.Size == 0U)
        {
            return 0U;
        }

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base + directory.VirtualAddress);
        if (exports->AddressOfNames == 0U
            || exports->AddressOfNameOrdinals == 0U
            || exports->AddressOfFunctions == 0U)
        {
            return 0U;
        }

        const auto* nameRvas =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto* ordinals =
            reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto* functionRvas =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD index = 0; index < exports->NumberOfNames; ++index)
        {
            const auto* exportName =
                reinterpret_cast<const char*>(base + nameRvas[index]);
            if (std::strcmp(exportName, name) != 0)
            {
                continue;
            }
            const WORD ordinal = ordinals[index];
            if (ordinal >= exports->NumberOfFunctions)
            {
                return 0U;
            }
            const DWORD functionRva = functionRvas[ordinal];
            // 落在导出目录内说明是转发导出，本用途不接受。
            if (functionRva >= directory.VirtualAddress
                && functionRva < directory.VirtualAddress + directory.Size)
            {
                return 0U;
            }
            return functionRva;
        }
        return 0U;
    }

    // ImageMapping：
    // - 作用：把一个磁盘 PE 按 SEC_IMAGE 只读映射进本进程，析构自动释放。
    class ImageMapping final
    {
    public:
        ImageMapping() = default;

        ~ImageMapping()
        {
            if (m_base != nullptr)
            {
                ::UnmapViewOfFile(m_base);
            }
            if (m_mapping != nullptr)
            {
                ::CloseHandle(m_mapping);
            }
            if (m_file != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(m_file);
            }
        }

        ImageMapping(const ImageMapping&) = delete;
        ImageMapping& operator=(const ImageMapping&) = delete;

        // open：
        // - 输入 path：PE 文件路径；
        // - 作用：以 SEC_IMAGE 建立只读节视图，节按 RVA 布局，可直接用 RVA 寻址；
        // - 返回：true 表示映射成功。
        bool open(const std::wstring& path)
        {
            m_file = ::CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (m_file == INVALID_HANDLE_VALUE)
            {
                m_lastError = ::GetLastError();
                return false;
            }
            m_mapping = ::CreateFileMappingW(
                m_file,
                nullptr,
                PAGE_READONLY | SEC_IMAGE,
                0U,
                0U,
                nullptr);
            if (m_mapping == nullptr)
            {
                m_lastError = ::GetLastError();
                return false;
            }
            m_base = ::MapViewOfFile(m_mapping, FILE_MAP_READ, 0U, 0U, 0U);
            if (m_base == nullptr)
            {
                m_lastError = ::GetLastError();
                return false;
            }
            return true;
        }

        // base：返回映射基址；未映射时为 nullptr。
        const unsigned char* base() const
        {
            return static_cast<const unsigned char*>(m_base);
        }

        // lastError：返回最近一次失败的 Win32 错误码。
        DWORD lastError() const { return m_lastError; }

    private:
        HANDLE m_file = INVALID_HANDLE_VALUE; // m_file：PE 文件句柄。
        HANDLE m_mapping = nullptr;           // m_mapping：节对象句柄。
        void* m_base = nullptr;               // m_base：映射视图基址。
        DWORD m_lastError = 0U;               // m_lastError：失败时的 Win32 错误码。
    };

    // KernelModuleInfo：
    // - 作用：内核模块表里的一行，只保留定位需要的字段。
    struct KernelModuleInfo
    {
        bool found = false;         // found：是否命中目标模块。
        std::uint64_t base = 0;     // base：模块加载基址。
        std::uint32_t size = 0;     // size：模块映像大小。
        QString name;               // name：模块文件名。
        QString path;               // path：模块 NT 路径。
        QString failureText;        // failureText：枚举失败时的原因。
    };

    // findKernelModule：
    // - 输入 candidateNames：候选模块文件名，按顺序匹配（不区分大小写）；
    // - 作用：枚举内核模块表找出目标模块的基址与大小；
    // - 返回：KernelModuleInfo；需要管理员权限，否则枚举会失败。
    KernelModuleInfo findKernelModule(const std::vector<QString>& candidateNames)
    {
        KernelModuleInfo info;

        const NtQuerySystemInformationFunction query = resolveNtQuerySystemInformation();
        if (query == nullptr)
        {
            info.failureText = QStringLiteral("无法解析系统模块枚举入口 NtQuerySystemInformation。");
            return info;
        }

        unsigned long required = 0U;
        query(kSystemModuleInformationClass, nullptr, 0U, &required);
        if (required < sizeof(KernelModuleList))
        {
            required = 1024U * 1024U;
        }

        for (int attempt = 0; attempt < 4; ++attempt)
        {
            std::vector<unsigned char> buffer(
                static_cast<std::size_t>(required) + 64U * 1024U, 0U);
            unsigned long returned = 0U;
            const long status = query(
                kSystemModuleInformationClass,
                buffer.data(),
                static_cast<unsigned long>(buffer.size()),
                &returned);
            if (status == kStatusInfoLengthMismatch)
            {
                required = std::max<unsigned long>(
                    returned, static_cast<unsigned long>(buffer.size() * 2U));
                continue;
            }
            if (status < 0)
            {
                info.failureText = QStringLiteral(
                    "内核模块枚举失败，NTSTATUS=0x%1；该接口需要管理员权限。")
                    .arg(static_cast<unsigned long>(status), 8, 16, QChar('0'));
                return info;
            }

            const auto* list = reinterpret_cast<const KernelModuleList*>(buffer.data());
            const std::size_t maximumRows =
                (buffer.size() - offsetof(KernelModuleList, rows)) / sizeof(KernelModuleRow);
            const std::size_t rows =
                std::min<std::size_t>(list->count, maximumRows);
            for (std::size_t index = 0; index < rows; ++index)
            {
                const KernelModuleRow& row = list->rows[index];
                const auto* fullPath = reinterpret_cast<const char*>(row.fullPathName);
                const std::size_t pathLength =
                    ::strnlen_s(fullPath, sizeof(row.fullPathName));
                const QString ntPath = QString::fromLocal8Bit(
                    fullPath, static_cast<int>(pathLength));
                const int nameOffset =
                    std::min<int>(row.fileNameOffset, ntPath.size());
                const QString fileName = ntPath.mid(nameOffset);

                const bool matched = std::any_of(
                    candidateNames.cbegin(),
                    candidateNames.cend(),
                    [&fileName](const QString& candidate) {
                        return fileName.compare(candidate, Qt::CaseInsensitive) == 0;
                    });
                if (!matched)
                {
                    continue;
                }

                info.found = true;
                info.base = reinterpret_cast<std::uint64_t>(row.imageBase);
                info.size = row.imageSize;
                info.name = fileName;
                info.path = ntPath;
                return info;
            }

            info.failureText = QStringLiteral("内核模块表里没有找到 CI 模块。");
            return info;
        }

        info.failureText = QStringLiteral("内核模块列表在多次重试后仍在变化。");
        return info;
    }

    // systemCiDllPath：
    // - 作用：拼出 %SystemRoot%\System32\CI.dll 的完整路径；
    // - 返回：路径；取不到系统目录时返回空串。
    std::wstring systemCiDllPath()
    {
        std::array<wchar_t, MAX_PATH> directory{};
        const UINT length = ::GetSystemDirectoryW(
            directory.data(), static_cast<UINT>(directory.size()));
        if (length == 0U || length >= directory.size())
        {
            return std::wstring();
        }
        std::wstring path(directory.data(), length);
        path.append(L"\\CI.dll");
        return path;
    }

    // decodeAt：
    // - 输入 code：指令首字节；available：可读字节数；
    // - 作用：用 Zydis 解一条 64 位指令；runtimeAddress 传映射内地址，
    //   这样 ZydisCalcAbsoluteAddress 直接给出映射内的绝对地址；
    // - 返回：true 表示解码成功。
    bool decodeAt(
        const unsigned char* const code,
        const std::size_t available,
        ZydisDisassembledInstruction& instruction)
    {
        return ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            reinterpret_cast<ZyanU64>(code),
            code,
            available,
            &instruction));
    }

    // isRelativeBranch：
    // - 作用：判断该指令的第一个操作数是不是相对立即数（call/jmp rel32）；
    // - 返回：true 表示是相对跳转/调用。
    bool isRelativeBranch(const ZydisDisassembledInstruction& instruction)
    {
        return instruction.info.operand_count_visible >= 1
            && instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
            && instruction.operands[0].imm.is_relative != 0;
    }

    // isGpr32：
    // - 作用：判断寄存器是否为 32 位通用寄存器，用来排除 16/64 位写；
    // - 返回：true 表示 32 位通用寄存器。
    bool isGpr32(const ZydisRegister reg)
    {
        return reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D;
    }

    // driverStatusText：
    // - 输入 io：一次 IOCTL 的传输结果；
    // - 作用：把通信层错误拼成可读文本；
    // - 返回：说明文本。
    QString driverStatusText(const ksword::ark::IoResult& io)
    {
        QString message = QString::fromStdString(io.message);
        if (message.isEmpty())
        {
            message = QStringLiteral("无附加信息");
        }
        return QStringLiteral("Win32=%1 NT=0x%2 信息=%3")
            .arg(io.win32Error)
            .arg(static_cast<unsigned long>(io.ntStatus), 8, 16, QChar('0'))
            .arg(message);
    }
}

namespace ks::misc::disable_dse
{
    bool driverAvailable()
    {
        const ksword::ark::DriverClient client;
        const ksword::ark::DriverHandle handle =
            client.open(GENERIC_READ | GENERIC_WRITE);
        return handle.isValid();
    }

    CodeIntegrityPosture queryPosture()
    {
        CodeIntegrityPosture posture;
        posture.buildNumber = currentBuildNumber();

        // 优先走 R0：字段最全，还能顺带确认 CI 模块确实在内核模块表里。
        const ksword::ark::DriverClient client;
        const ksword::ark::SecurityStatusAuditResult audit = client.querySecurityStatus();
        if (audit.io.ok && !audit.unsupported)
        {
            const auto& response = audit.response;
            posture.queried = true;
            posture.source = PostureSource::Driver;
            posture.options = static_cast<std::uint32_t>(response.codeIntegrityOptions);
            posture.ciEnabled = response.ciEnabled != 0UL;
            posture.testSigningEnabled = response.testSigningEnabled != 0UL;
            posture.umciEnabled = response.umciEnabled != 0UL;
            posture.hvciEnabled = response.hvciKmciEnabled != 0UL;
            posture.hvciStrictMode = response.hvciStrictMode != 0UL;
            posture.secureBootEnabled = response.secureBootEnabled != 0UL;
            posture.ciModuleLoaded = response.ciModuleLoaded != 0UL;
            return posture;
        }

        // R0 不可用时回退 R3。这条通道拿不到安全启动与模块加载状态，但足够显示当前姿态。
        const NtQuerySystemInformationFunction query = resolveNtQuerySystemInformation();
        if (query == nullptr)
        {
            posture.failureText =
                QStringLiteral("R0 未上线，且无法解析 NtQuerySystemInformation。");
            return posture;
        }

        SystemCodeIntegrityInformationBlock block{};
        block.length = sizeof(block);
        unsigned long returned = 0U;
        const long status = query(
            kSystemCodeIntegrityInformationClass, &block, sizeof(block), &returned);
        if (status < 0)
        {
            posture.failureText = QStringLiteral(
                "代码完整性状态查询失败，NTSTATUS=0x%1。")
                .arg(static_cast<unsigned long>(status), 8, 16, QChar('0'));
            return posture;
        }

        posture.queried = true;
        posture.source = PostureSource::Win32;
        posture.options = block.codeIntegrityOptions;
        posture.ciEnabled = (posture.options & kOptionEnabled) != 0U;
        posture.testSigningEnabled = (posture.options & kOptionTestSign) != 0U;
        posture.umciEnabled = (posture.options & kOptionUmciEnabled) != 0U;
        posture.hvciEnabled = (posture.options & kOptionHvciKmciEnabled) != 0U;
        posture.hvciStrictMode = (posture.options & kOptionHvciKmciStrictMode) != 0U;
        return posture;
    }

    BlockReason evaluateBlockReason(
        const CodeIntegrityPosture& posture,
        const TargetLocation& location)
    {
        if (posture.queried && posture.buildNumber != 0U
            && posture.buildNumber < kFirstCiDllBuild)
        {
            return BlockReason::UnsupportedBuild;
        }
        if (posture.queried && posture.hvciEnabled)
        {
            return BlockReason::HvciEnabled;
        }
        if (!driverAvailable())
        {
            return BlockReason::DriverUnavailable;
        }
        if (!location.ok)
        {
            return BlockReason::NotLocated;
        }
        return BlockReason::None;
    }

    QString blockReasonText(const BlockReason reason)
    {
        switch (reason)
        {
        case BlockReason::DriverUnavailable:
            return QStringLiteral("KswordARK 驱动未上线。g_CiOptions 位于内核，只能由 R0 修改，请先加载驱动。");
        case BlockReason::UnsupportedBuild:
            return QStringLiteral("当前系统早于 Windows 8，DSE 开关在 nt!g_CiEnabled 而不是 CI.dll!g_CiOptions，本页不支持。");
        case BlockReason::HvciEnabled:
            return QStringLiteral("已开启内存完整性（HVCI）。此时 g_CiOptions 所在页由 Hypervisor 通过 SLAT 保护，R0 写入不会生效，必须先在“Windows 安全中心 → 设备安全性 → 内核隔离”里关闭内存完整性并重启。");
        case BlockReason::NotLocated:
            return QStringLiteral("尚未定位到 g_CiOptions，请先执行定位。");
        case BlockReason::ValueMismatch:
            return QStringLiteral("定位地址读回值的强制签名位与系统自报的驱动签名强制状态矛盾，地址存疑，已拒绝写入。");
        case BlockReason::None:
        default:
            break;
        }
        return QString();
    }

    TargetLocation locateCiOptions()
    {
        TargetLocation location;

        const std::uint32_t build = currentBuildNumber();
        location.traceLines.append(
            QStringLiteral("系统内部版本号：%1").arg(build));
        if (build != 0U && build < kFirstCiDllBuild)
        {
            location.failureText = QStringLiteral(
                "当前系统早于 Windows 8，DSE 开关不在 CI.dll 中，本页不支持。");
            return location;
        }

        // 第一步：把磁盘上的 CI.dll 按 SEC_IMAGE 只读映射进来。
        // 只读资源式映射不会把内核模块变成本进程的可执行页，也不会跑 DllMain。
        const std::wstring path = systemCiDllPath();
        if (path.empty())
        {
            location.failureText = QStringLiteral("无法取得系统目录路径。");
            return location;
        }
        location.traceLines.append(
            QStringLiteral("映射镜像：%1").arg(QString::fromStdWString(path)));

        ImageMapping mapping;
        if (!mapping.open(path))
        {
            location.failureText = QStringLiteral(
                "映射 CI.dll 失败，Win32 错误=%1。").arg(mapping.lastError());
            return location;
        }
        const unsigned char* const base = mapping.base();
        if (ntHeadersOf(base) == nullptr)
        {
            location.failureText = QStringLiteral("CI.dll 不是有效的 64 位 PE 映像。");
            return location;
        }

        // 第二步：从导出表找 CiInitialize。
        const std::uint32_t ciInitializeRva = findExportRva(base, "CiInitialize");
        if (ciInitializeRva == 0U)
        {
            location.failureText = QStringLiteral("CI.dll 未导出 CiInitialize。");
            return location;
        }
        location.traceLines.append(
            QStringLiteral("CiInitialize RVA = 0x%1")
                .arg(ciInitializeRva, 0, 16));
        location.ciInitializeRva = ciInitializeRva;

        // 第三步：CiInitialize 里找到进入 CipInitialize 的那条分支。
        // build 16299 起是 call，且前面还有若干 INIT 节里的初始化调用要跳过，
        // 判据是调用目标必须落在 PAGE 节；更早的版本直接是一条 jmp。
        const unsigned char* const ciInitialize = base + ciInitializeRva;
        const unsigned char* cipInitialize = nullptr;
        {
            std::size_t offset = 0;
            int callCount = 0;
            ZydisDisassembledInstruction instruction{};
            while (offset < kScanLimit)
            {
                if (!decodeAt(ciInitialize + offset, kScanLimit - offset, instruction))
                {
                    break;
                }
                if (build >= kCipInitializeCallBuild)
                {
                    if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL
                        && isRelativeBranch(instruction))
                    {
                        ++callCount;
                        ZyanU64 target = 0;
                        ZydisCalcAbsoluteAddress(
                            &instruction.info,
                            &instruction.operands[0],
                            reinterpret_cast<ZyanU64>(ciInitialize + offset),
                            &target);
                        const auto* candidate =
                            reinterpret_cast<const unsigned char*>(target);
                        if (callCount > 1
                            && rvaIsInSection(
                                base,
                                static_cast<std::uint64_t>(candidate - base),
                                "PAGE"))
                        {
                            cipInitialize = candidate;
                            break;
                        }
                    }
                }
                else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP
                    && isRelativeBranch(instruction))
                {
                    ZyanU64 target = 0;
                    ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &instruction.operands[0],
                        reinterpret_cast<ZyanU64>(ciInitialize + offset),
                        &target);
                    cipInitialize = reinterpret_cast<const unsigned char*>(target);
                    break;
                }
                offset += instruction.info.length;
            }
        }

        if (cipInitialize == nullptr)
        {
            location.failureText = QStringLiteral("在 CiInitialize 里没有找到进入 CipInitialize 的分支；该系统版本的 CI.dll 可能改了实现。");
            return location;
        }

        const std::uint64_t cipRva =
            static_cast<std::uint64_t>(cipInitialize - base);
        if (!rvaIsInSection(base, cipRva, "PAGE"))
        {
            location.failureText = QStringLiteral(
                "定位到的 CipInitialize（RVA 0x%1）不在 PAGE 节，判定为误匹配。")
                .arg(cipRva, 0, 16);
            return location;
        }
        location.traceLines.append(
            QStringLiteral("CipInitialize RVA = 0x%1").arg(cipRva, 0, 16));

        // 第四步：CipInitialize 开头把首参写进 g_CiOptions，
        // 对应 `mov dword ptr [rip+disp32], r32`。
        std::uint64_t optionsRva = 0;
        {
            std::size_t offset = 0;
            ZydisDisassembledInstruction instruction{};
            while (offset < kScanLimit)
            {
                if (!decodeAt(cipInitialize + offset, kScanLimit - offset, instruction))
                {
                    break;
                }
                if (instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV
                    && instruction.info.operand_count_visible == 2
                    && instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instruction.operands[0].mem.base == ZYDIS_REGISTER_RIP
                    && instruction.operands[0].size == 32
                    && instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && isGpr32(instruction.operands[1].reg.value))
                {
                    ZyanU64 target = 0;
                    ZydisCalcAbsoluteAddress(
                        &instruction.info,
                        &instruction.operands[0],
                        reinterpret_cast<ZyanU64>(cipInitialize + offset),
                        &target);
                    optionsRva = static_cast<std::uint64_t>(
                        reinterpret_cast<const unsigned char*>(target) - base);
                    location.matchedInstruction =
                        QStringLiteral("CipInitialize+0x%1  %2")
                            .arg(offset, 0, 16)
                            .arg(QString::fromLatin1(instruction.text));
                    location.traceLines.append(
                        QStringLiteral("命中指令：%1")
                            .arg(location.matchedInstruction));
                    break;
                }
                offset += instruction.info.length;
            }
        }

        if (optionsRva == 0)
        {
            location.failureText = QStringLiteral(
                "在 CipInitialize 里没有找到写 g_CiOptions 的指令。");
            return location;
        }

        // 第五步：节校验。g_CiOptions 在旧版本位于 .data，新版本被挪到了 CiPolicy。
        const QString sectionName = sectionNameOfRva(base, optionsRva);
        if (sectionName.compare(QStringLiteral(".data"), Qt::CaseInsensitive) != 0
            && sectionName.compare(QStringLiteral("CiPolicy"), Qt::CaseInsensitive) != 0)
        {
            location.failureText = QStringLiteral(
                "候选地址 RVA 0x%1 落在节“%2”，不是 .data 或 CiPolicy，判定为误匹配。")
                .arg(optionsRva, 0, 16)
                .arg(sectionName.isEmpty() ? QStringLiteral("<无>") : sectionName);
            return location;
        }
        location.sectionName = sectionName;
        location.traceLines.append(
            QStringLiteral("g_CiOptions RVA = 0x%1（节 %2）")
                .arg(optionsRva, 0, 16)
                .arg(sectionName));

        // 第六步：拿内核里 CI 模块的真实基址，把 RVA 换算成内核虚拟地址。
        const KernelModuleInfo module = findKernelModule(
            { QStringLiteral("ci.dll"), QStringLiteral("ci.sys") });
        if (!module.found)
        {
            location.failureText = module.failureText.isEmpty()
                ? QStringLiteral("未能取得内核中 CI 模块的基址。")
                : module.failureText;
            return location;
        }
        if (optionsRva >= module.size)
        {
            location.failureText = QStringLiteral(
                "RVA 0x%1 超出内核模块大小 0x%2，磁盘上的 CI.dll 与内核中已加载的版本不一致。")
                .arg(optionsRva, 0, 16)
                .arg(module.size, 0, 16);
            return location;
        }

        location.ok = true;
        location.moduleBase = module.base;
        location.moduleSize = module.size;
        location.moduleName = module.name;
        location.rva = static_cast<std::uint32_t>(optionsRva);
        location.kernelAddress = module.base + optionsRva;
        location.traceLines.append(
            QStringLiteral("内核模块 %1 基址 = 0x%2，大小 = 0x%3")
                .arg(module.name)
                .arg(module.base, 16, 16, QChar('0'))
                .arg(module.size, 0, 16));
        location.traceLines.append(
            QStringLiteral("g_CiOptions 内核地址 = 0x%1")
                .arg(location.kernelAddress, 16, 16, QChar('0')));
        return location;
    }

    ReadbackResult readCiOptions(const TargetLocation& location)
    {
        ReadbackResult result;
        if (!location.ok || location.kernelAddress == 0U)
        {
            result.failureText = QStringLiteral("目标尚未定位，无法读取。");
            return result;
        }

        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualMemoryReadResult readResult =
            client.readVirtualMemory(
                0U,
                location.kernelAddress,
                kCiOptionsSize,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
        if (!readResult.io.ok
            || readResult.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK
            || readResult.data.size() < kCiOptionsSize)
        {
            result.failureText = QStringLiteral(
                "R0 读取 g_CiOptions 失败：读取状态=%1 %2")
                .arg(readResult.readStatus)
                .arg(driverStatusText(readResult.io));
            return result;
        }

        std::uint32_t value = 0U;
        std::memcpy(&value, readResult.data.data(), kCiOptionsSize);
        result.ok = true;
        result.value = value;
        return result;
    }

    ApplyResult writeCiOptions(
        const TargetLocation& location,
        const std::uint32_t expectedValue,
        const std::uint32_t desiredValue)
    {
        ApplyResult result;
        result.previousValue = expectedValue;
        result.writtenValue = desiredValue;

        if (!location.ok || location.kernelAddress == 0U)
        {
            result.detailText = QStringLiteral("目标尚未定位，拒绝写入。");
            return result;
        }
        if (expectedValue == desiredValue)
        {
            result.ok = true;
            result.detailText = QStringLiteral("目标值与当前值相同，无需写入。");
            return result;
        }

        std::vector<std::uint8_t> expectedBytes(kCiOptionsSize, 0U);
        std::vector<std::uint8_t> desiredBytes(kCiOptionsSize, 0U);
        std::memcpy(expectedBytes.data(), &expectedValue, kCiOptionsSize);
        std::memcpy(desiredBytes.data(), &desiredValue, kCiOptionsSize);

        const ksword::ark::DriverClient client;

        // PREPARE：带 expected-before，R0 侧会先读回目标字节并与之比对。
        ksword::ark::MutationPrepareInput prepareInput{};
        prepareInput.flags =
            KSWORD_ARK_MUTATION_FLAG_DRY_RUN |
            KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
        prepareInput.targetKind = KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
        prepareInput.bytes = kCiOptionsSize;
        prepareInput.targetAddress = location.kernelAddress;
        prepareInput.afterBytes = desiredBytes;
        prepareInput.expectedBeforeBytes = expectedBytes;

        const ksword::ark::MutationResponseResult prepareResult =
            client.prepareMutation(prepareInput);
        if (!prepareResult.io.ok
            || prepareResult.status != KSWORD_ARK_MUTATION_STATUS_PREPARED
            || prepareResult.transactionId == 0U
            || prepareResult.bytes != kCiOptionsSize
            || prepareResult.beforeBytes.size() < kCiOptionsSize
            || !std::equal(
                expectedBytes.cbegin(),
                expectedBytes.cend(),
                prepareResult.beforeBytes.cbegin()))
        {
            result.detailText = QStringLiteral(
                "内核字节事务 PREPARE 失败：状态=%1 NT=0x%2 %3")
                .arg(prepareResult.status)
                .arg(static_cast<unsigned long>(prepareResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(prepareResult.io));
            return result;
        }

        const std::uint64_t transactionId = prepareResult.transactionId;
        result.transactionId = transactionId;
        result.traceLines.append(
            QStringLiteral("PREPARE 通过，事务号 = %1").arg(transactionId));

        // DRY-RUN：让 R0 先把安全策略与可写性走一遍，不落笔。
        const ksword::ark::MutationResponseResult dryRunResult =
            client.commitMutation(transactionId, KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
        if (!dryRunResult.io.ok
            || dryRunResult.status != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
        {
            result.detailText = QStringLiteral(
                "内核字节事务 dry-run 失败：状态=%1 NT=0x%2 %3")
                .arg(dryRunResult.status)
                .arg(static_cast<unsigned long>(dryRunResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(dryRunResult.io));
            client.rollbackMutation(
                transactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
            return result;
        }
        result.traceLines.append(QStringLiteral("dry-run 通过"));

        // COMMIT：真正写入。R0 侧走 MDL 可写别名，不改 CR0.WP。
        const ksword::ark::MutationResponseResult commitResult =
            client.commitMutation(
                transactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
        if (!commitResult.io.ok
            || commitResult.status != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
        {
            result.detailText = QStringLiteral(
                "内核字节事务提交失败：状态=%1 NT=0x%2 %3")
                .arg(commitResult.status)
                .arg(static_cast<unsigned long>(commitResult.lastStatus), 8, 16, QChar('0'))
                .arg(driverStatusText(commitResult.io));
            client.rollbackMutation(
                transactionId,
                KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
            return result;
        }
        result.traceLines.append(QStringLiteral("COMMIT 完成"));

        // 复读：提交成功不等于值真的变了，HVCI 之类的保护会让写入被静默丢弃。
        const ReadbackResult verify = readCiOptions(location);
        if (!verify.ok)
        {
            result.detailText = QStringLiteral("提交后复读失败：%1").arg(verify.failureText);
            return result;
        }
        if (verify.value != desiredValue)
        {
            result.detailText = QStringLiteral("提交后复读不一致：期望 0x%1，实际 0x%2。写入很可能被 Hypervisor 或其他保护拦截，系统状态未改变。")
                .arg(desiredValue, 8, 16, QChar('0'))
                .arg(verify.value, 8, 16, QChar('0'));
            return result;
        }

        result.ok = true;
        result.traceLines.append(
            QStringLiteral("复读校验通过：0x%1").arg(verify.value, 8, 16, QChar('0')));
        return result;
    }

    QString describeOptions(const std::uint32_t options)
    {
        if (options == 0U)
        {
            return QStringLiteral("0（代码完整性全部关闭）");
        }

        struct OptionBit
        {
            std::uint32_t bit;
            const char* name;
        };
        static constexpr OptionBit kBits[] = {
            { 0x00000001U, "ENABLED" },
            { 0x00000002U, "TESTSIGN" },
            { 0x00000004U, "UMCI_ENABLED" },
            { 0x00000008U, "UMCI_AUDITMODE_ENABLED" },
            { 0x00000010U, "UMCI_EXCLUSIONPATHS_ENABLED" },
            { 0x00000020U, "TEST_BUILD" },
            { 0x00000040U, "PREPRODUCTION_BUILD" },
            { 0x00000080U, "DEBUGMODE_ENABLED" },
            { 0x00000100U, "FLIGHT_BUILD" },
            { 0x00000200U, "FLIGHTING_ENABLED" },
            { 0x00000400U, "HVCI_KMCI_ENABLED" },
            { 0x00000800U, "HVCI_KMCI_AUDITMODE_ENABLED" },
            { 0x00001000U, "HVCI_KMCI_STRICTMODE_ENABLED" },
            { 0x00002000U, "HVCI_IUM_ENABLED" },
            { 0x00004000U, "WHQL_ENFORCEMENT_ENABLED" },
            { 0x00008000U, "WHQL_AUDITMODE_ENABLED" }
        };

        QStringList names;
        std::uint32_t remaining = options;
        for (const OptionBit& entry : kBits)
        {
            if ((options & entry.bit) != 0U)
            {
                names.append(QString::fromLatin1(entry.name));
                remaining &= ~entry.bit;
            }
        }
        if (remaining != 0U)
        {
            names.append(QStringLiteral("未知位 0x%1").arg(remaining, 0, 16));
        }
        return names.join(QStringLiteral(" | "));
    }

    QString describeCiOptions(const std::uint32_t value)
    {
        if (value == 0U)
        {
            return QStringLiteral("0：驱动签名强制已完全关闭");
        }

        QStringList parts;
        if ((value & kCiOptionEnforceMask) == kCiOptionEnforceMask)
        {
            parts.append(QStringLiteral("强制驱动签名"));
        }
        else if ((value & kCiOptionEnforceMask) != 0U)
        {
            parts.append(QStringLiteral("强制位部分置位"));
        }
        else
        {
            parts.append(QStringLiteral("未强制驱动签名"));
        }
        if ((value & kCiOptionTestSign) != 0U)
        {
            parts.append(QStringLiteral("放行测试签名"));
        }

        const std::uint32_t high = value & ~(kCiOptionEnforceMask | kCiOptionTestSign);
        if (high != 0U)
        {
            // 高位是 CI 的内部策略标志（HVCI/WHQL 等），随版本变化，只如实显示不做解释。
            parts.append(QStringLiteral("其余内部标志 0x%1").arg(high, 0, 16));
        }
        return parts.join(QStringLiteral("，"));
    }

    bool ciOptionsAgreesWithPosture(
        const std::uint32_t value,
        const CodeIntegrityPosture& posture)
    {
        if (!posture.queried)
        {
            return false;
        }
        // 明显的读取垃圾直接否掉。
        if (value == 0xFFFFFFFFU)
        {
            return false;
        }
        const bool enforcing = (value & kCiOptionEnforceMask) != 0U;
        return enforcing == posture.ciEnabled;
    }
}
