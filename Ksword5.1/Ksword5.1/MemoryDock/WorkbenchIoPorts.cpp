#include "WorkbenchIoPorts.h"

#include <QByteArray>
#include <QString>

#include <mutex>
#include <utility>
#include <limits>
#include <memory>

// ============================================================
// WorkbenchIoPorts.cpp
// 作用：
// - 实现 WorkbenchIoPort（ksword::memwb::IMemoryIoPort 的真实端口）：按
//   通道/范围分发到门面或驱动客户端，问完一次就把结果转手交给
//   WorkbenchIoMapping.h 的纯映射函数（MapFacadeReadOutcome /
//   MapFacadeWriteOutcome / MapStandardDriverVirtualRead，M-1 已拆出去）。
// - 本文件只做"调门面/调驱动客户端一次"与两个前置拒绝闸门（R-3：用户态
//   通道没有物理地址访问手段；标准驱动+内核虚拟地址必须走分步字节事务），
//   不包含任何分块、重试、确认或回滚策略；那些策略已经在 shared/evidence/
//   memory_workbench/ 里实现并测试过。
// ============================================================

namespace
{
    // DDMA serialization belongs to MemoryAccessBackend so legacy and workbench
    // callers share the same transaction owner. No second port-local lock.

    // VectorToQByteArray：std::vector<uint8_t> -> QByteArray 的转换只在本文件
    // 做（WorkbenchIoPort 是 Qt-free 逻辑层与 Qt 门面之间唯一的边界）。
    // 传入：bytes 待转换的字节序列（可为空）。
    // 传出：等长的 QByteArray；bytes 为空时返回空数组，不解引用 data()。
    QByteArray VectorToQByteArray(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
        {
            return QByteArray();
        }
        return QByteArray(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<qsizetype>(bytes.size()));
    }

    // 注：QByteArray -> std::vector<uint8_t> 的反向转换（原 QByteArrayToVector）
    // 只被下面已经搬走的 MapFacadeReadOutcome 用过，M-1 拆分后那份实现（与它
    // 自己的小工具）已经一起移到 WorkbenchIoMapping.cpp，本文件不再需要它，
    // 留着会变成 /W4 下的"未引用的本地函数"警告，因此直接删掉而不是留一份
    // 没人调用的拷贝。

    // MapChannelToBackend：
    // - 作用：把 Qt-free 会话里的 Channel（ksword::memwb::Channel）翻译成门面
    //   的 MemoryAccessBackend。两个枚举当前数值顺序一致，但本函数刻意写成
    //   逐项 switch 而不是 static_cast——枚举定义分别维护在两个不同模块里，
    //   任何一边单独改动顺序都不应该在这里悄悄产生错配。
    // - 传入：channel 会话声明的通道；传出：对应的门面后端枚举值；越界值
    //   （协议损坏或新增枚举项遗漏翻译）兜底返回 UserMode——四个后端里权限
    //   最低、失败面最窄的一个，不会因为误判而越权访问。
    ksword::memory_backend::MemoryAccessBackend MapChannelToBackend(
        const ksword::memwb::Channel channel)
    {
        switch (channel)
        {
        case ksword::memwb::Channel::UserMode:
            return ksword::memory_backend::MemoryAccessBackend::UserMode;
        case ksword::memwb::Channel::StandardDriver:
            return ksword::memory_backend::MemoryAccessBackend::StandardDriver;
        case ksword::memwb::Channel::Hvm:
            return ksword::memory_backend::MemoryAccessBackend::Hvm;
        case ksword::memwb::Channel::Ddma:
            return ksword::memory_backend::MemoryAccessBackend::Ddma;
        }
        return ksword::memory_backend::MemoryAccessBackend::UserMode;
    }

    // MapFacadeReadOutcome / MapFacadeWriteOutcome / MapStandardDriverVirtualRead：
    // M-1（主会话审核拆分）已经把这三个纯映射函数搬进 WorkbenchIoMapping.h/
    // .cpp，本文件只在下面的 ReadViaFacade / WriteViaFacade 里调用它们
    // （命名空间 ksword::memwb_ports_detail），不再各自保留一份实现。

}

namespace ksword::memwb_ports
{
    // Limits：见 WorkbenchIoPorts.h 类声明处注释；StandardDriver 通道有明确
    // 的协议上限（KswordArkMemoryIoctl.h 定义）。R-2/R-3（主会话审核发现）：
    // 用户态通道的虚拟读写没有协议层上限，但调用方（MemoryPageReader 等）
    // 会按这个上限切块分配缓冲——一直返回 0（不限）等于放任调用方对任意大
    // length 一次性分配一块缓冲，这里同样套用标准驱动虚拟读写的 1 MiB/
    // 256 KiB，纯粹是"分配安全阀"，数值借用标准驱动的常量只是省得另起一对
    // 魔数，两者的真实限制来源完全不同。用户态+物理范围这个组合本身会被
    // 下面的 Read/Write 直接拒绝（R-3），这里的上限值对它没有意义，不特殊
    // 处理；私有页表窗口（Hvm）与磁盘传输（Ddma）通道继续保持 0，门面内部
    // 自己按各自的粒度切片，这里不重复决定第二份切片规则。
    ksword::memwb::IoLimits WorkbenchIoPort::Limits(
        const ksword::memwb::MemoryTargetSession& session) const
    {
        ksword::memwb::IoLimits limits;
        if (session.channel == ksword::memwb::Channel::StandardDriver)
        {
            if (session.scope == ksword::memwb::Scope::Physical)
            {
                limits.maxReadBytes = KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES;
                limits.maxWriteBytes = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES;
            }
            else
            {
                limits.maxReadBytes = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
                limits.maxWriteBytes = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;
            }
        }
        else if (session.channel == ksword::memwb::Channel::UserMode
            && session.scope != ksword::memwb::Scope::Physical)
        {
            limits.maxReadBytes = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
            limits.maxWriteBytes = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;
        }
        return limits;
    }

    // ReadUserModeVirtual：R3 通道虚拟读。自行实现（不经门面）的原因见
    // WorkbenchIoPorts.h 类注释与文件头 FACTS 第 3 条：门面把"打开进程失败"
    // 与"读到 0 字节"都报成同一种失败文本，而 IoReadStatus 需要把它们分别
    // 判成 Failed 与 Unreadable 两种不同的事实。
    ksword::memwb::IoReadResult WorkbenchIoPort::ReadUserModeVirtual(
        const std::uint32_t pid,
        const std::uint64_t address,
        const std::uint64_t length)
    {
        ksword::memwb::IoReadResult result;

        // 内核半区地址：R3 的 ReadProcessMemory 只能访问目标进程的用户态
        // 地址空间，这里先行拒绝，不发起任何系统调用。
        if (ksword::memwb::IsKernelVirtualAddress(address))
        {
            result.status = ksword::memwb::IoReadStatus::Failed;
            result.failure =
                "用户态通道（R3 ReadProcessMemory）无法访问内核虚拟地址，请切换到标准驱动（R0）通道。";
            return result;
        }

        // 每次调用各自 OpenProcess/CloseHandle，不借用调用方句柄：理由与
        // 门面 userModeReadVirtual 一致——四个页面对同一个 PID 得到的权限
        // 应当完全一致，不随调用方当初打开句柄时要的权限而变化。
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
        if (processHandle == nullptr)
        {
            result.status = ksword::memwb::IoReadStatus::Failed;
            result.failure =
                "R3 通道打开进程失败，win32=" + std::to_string(::GetLastError()) + "。";
            return result;
        }

        std::vector<std::uint8_t> buffer(static_cast<std::size_t>(length), 0U);
        SIZE_T bytesRead = 0;
        const BOOL readOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(),
            static_cast<SIZE_T>(length),
            &bytesRead);
        // 错误码必须紧挨着调用取一次，后面的 CloseHandle 会改写它。
        const DWORD readError = (readOk == FALSE) ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(processHandle);

        if (bytesRead == 0U)
        {
            result.status = ksword::memwb::IoReadStatus::Unreadable;
            result.failure =
                "R3 通道读取 0 字节，win32=" + std::to_string(readError) +
                "，目标地址可能未提交或无读权限。";
            return result;
        }

        buffer.resize(static_cast<std::size_t>(bytesRead));
        result.data = std::move(buffer);
        result.status = (static_cast<std::uint64_t>(bytesRead) == length)
            ? ksword::memwb::IoReadStatus::Ok
            : ksword::memwb::IoReadStatus::Partial;
        return result;
    }

    // ReadStandardDriverVirtual：标准驱动通道虚拟读，绕开门面直接调用
    // DriverClient::readVirtualMemory，不带 ZERO_FILL_UNREADABLE（门面固定
    // 带这个标志，会把未读到的字节伪造成 0，FACTS 第 2 条）。
    ksword::memwb::IoReadResult WorkbenchIoPort::ReadStandardDriverVirtual(
        const std::uint32_t pid,
        const std::uint64_t address,
        const std::uint64_t length)
    {
        // 内核虚拟地址判据只认 MemoryTargetSession.h 的 IsKernelVirtualAddress
        // 这一份，不新引入第二份阈值；内核地址时 processId 由驱动忽略，这里
        // 仍传 0，不传调用方的 pid，避免遗留值造成误解。
        const bool kernelAddress = ksword::memwb::IsKernelVirtualAddress(address);
        unsigned long flags = 0UL;
        if (kernelAddress)
        {
            flags |= KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::VirtualMemoryReadResult driverResult = driverClient.readVirtualMemory(
            kernelAddress ? 0U : pid,
            address,
            static_cast<std::uint32_t>(length),
            flags);
        return ksword::memwb_ports_detail::MapStandardDriverVirtualRead(driverResult);
    }

    // ReadViaFacade：物理范围的任意通道、虚拟范围的 Hvm/Ddma 通道共用这一条
    // 路径。Ddma 通道先做 isDdmaUsable 预检（门面返回值事后无法区分"会话
    // 不可用"与"目标不可读"，必须在调用门面之前判断），预检通过后持进程级
    // 互斥闸再调用门面，持锁范围只包住门面调用本身。
    ksword::memwb::IoReadResult WorkbenchIoPort::ReadViaFacade(
        const ksword::memwb::MemoryTargetSession& session,
        const std::uint64_t address,
        const std::uint64_t length)
    {
        const ksword::memory_backend::MemoryAccessBackend backend =
            MapChannelToBackend(session.channel);
        const bool isDdmaChannel = session.channel == ksword::memwb::Channel::Ddma;
        const auto sessionSnapshot = ksword::memory_backend::captureDdmaSession();
        const auto& ddmaSession = sessionSnapshot.session;

        if (isDdmaChannel)
        {
            QString unusableReason;
            if (!ksword::memory_backend::isDdmaUsable(ddmaSession, &unusableReason))
            {
                ksword::memwb::IoReadResult result;
                result.status = ksword::memwb::IoReadStatus::Failed;
                result.failure = unusableReason.toStdString();
                return result;
            }
        }

        // invoke：真正发起门面调用的那一下，按范围选 readPhysical 还是
        // readVirtual；写成局部可调用对象是为了让"是否持 Ddma 闸"这一条
        // 分支只在外层判断一次，不在物理/虚拟两条路径各写一遍锁。
        const auto invoke = [&]() -> ksword::memory_backend::AccessOutcome
        {
            if (session.scope == ksword::memwb::Scope::Physical)
            {
                return ksword::memory_backend::readPhysical(
                    backend, ddmaSession, address, length);
            }
            return ksword::memory_backend::readVirtual(
                backend, ddmaSession, session.pid, address, length);
        };

        ksword::memory_backend::AccessOutcome outcome;
        if (isDdmaChannel)
        {
            std::lock_guard<std::recursive_mutex> guard(ksword::memory_backend::ddmaTransactionMutex());
            if (sessionSnapshot.generation != session.ddmaGeneration
                || sessionSnapshot.generation != ksword::memory_backend::ddmaSessionGeneration())
            {
                outcome.failureText = QStringLiteral("DDMA session changed; read a new snapshot before retrying.");
            }
            else
            {
                outcome = invoke();
            }
        }
        else
        {
            outcome = invoke();
        }
        return ksword::memwb_ports_detail::MapFacadeReadOutcome(outcome);
    }

    // Read：按范围/通道分发到上面三条路径之一，规则见 WorkbenchIoPorts.h
    // 类声明处的详细注释。R-3（主会话审核发现）：用户态通道 + 物理范围必须
    // 在进门面之前就直接拒绝——用户态通道没有任何访问物理地址的手段（沿用
    // 门面 userModeRejectPhysical 的原文含义），这个组合本该是 Failed（通道
    // 自身做不到），而不是经门面得到 Unreadable（那会被 MemoryPageReader 当
    // 成"问过了，目标本身读不到"，把这一页永久标成 ??，实际上是问错了通道）。
    ksword::memwb::IoReadResult WorkbenchIoPort::Read(
        const ksword::memwb::MemoryTargetSession& session,
        const std::uint64_t address,
        const std::uint64_t length)
    {
        if (session.scope == ksword::memwb::Scope::Physical)
        {
            if (session.channel == ksword::memwb::Channel::UserMode)
            {
                ksword::memwb::IoReadResult result;
                result.status = ksword::memwb::IoReadStatus::Failed;
                result.failure = "用户态通道没有访问物理地址的手段，请改用驱动或磁盘传输通道";
                return result;
            }
            // 物理范围的其余通道没有"伪造零字节"的问题，统一经门面。
            return ReadViaFacade(session, address, length);
        }

        switch (session.channel)
        {
        case ksword::memwb::Channel::UserMode:
            return ReadUserModeVirtual(session.pid, address, length);
        case ksword::memwb::Channel::StandardDriver:
            return ReadStandardDriverVirtual(session.pid, address, length);
        case ksword::memwb::Channel::Hvm:
        case ksword::memwb::Channel::Ddma:
        default:
            return ReadViaFacade(session, address, length);
        }
    }

    // WriteViaFacade：除"标准驱动+内核虚拟地址"之外的全部写入组合共用这一
    // 条路径；结构与 ReadViaFacade 对称。
    ksword::memwb::IoWriteResult WorkbenchIoPort::WriteViaFacade(
        const ksword::memwb::MemoryTargetSession& session,
        const std::uint64_t address,
        const std::vector<std::uint8_t>& bytes,
        const bool approved)
    {
        const ksword::memory_backend::MemoryAccessBackend backend =
            MapChannelToBackend(session.channel);
        const bool isDdmaChannel = session.channel == ksword::memwb::Channel::Ddma;
        const auto sessionSnapshot = ksword::memory_backend::captureDdmaSession();
        const auto& ddmaSession = sessionSnapshot.session;

        if (isDdmaChannel)
        {
            QString unusableReason;
            if (!ksword::memory_backend::isDdmaUsable(ddmaSession, &unusableReason))
            {
                ksword::memwb::IoWriteResult result;
                result.failure = unusableReason.toStdString();
                return result;
            }
        }

        const QByteArray payload = VectorToQByteArray(bytes);
        const auto invoke = [&]() -> ksword::memory_backend::AccessOutcome
        {
            if (session.scope == ksword::memwb::Scope::Physical)
            {
                return ksword::memory_backend::writePhysical(
                    backend, ddmaSession, address, payload, approved);
            }
            return ksword::memory_backend::writeVirtual(
                backend, ddmaSession, session.pid, address, payload, approved);
        };

        ksword::memory_backend::AccessOutcome outcome;
        if (isDdmaChannel)
        {
            std::lock_guard<std::recursive_mutex> guard(ksword::memory_backend::ddmaTransactionMutex());
            if (sessionSnapshot.generation != session.ddmaGeneration
                || sessionSnapshot.generation != ksword::memory_backend::ddmaSessionGeneration())
            {
                outcome.failureText = QStringLiteral("DDMA session changed; read a new snapshot before retrying.");
            }
            else
            {
                outcome = invoke();
            }
        }
        else
        {
            outcome = invoke();
        }
        return ksword::memwb_ports_detail::MapFacadeWriteOutcome(outcome);
    }

    // Write：先挡掉两个必须直接拒绝、不进门面的组合，其余一律经
    // WriteViaFacade：
    //   - 用户态通道 + 物理范围（R-3）：用户态通道没有任何访问物理地址的
    //     手段，理由与上面 Read 的同一条防线完全一致。
    //   - 标准驱动 + 内核虚拟地址（FACTS 第 5/6 条）：必须经
    //     IKernelMutationPort 分步字节事务，不在本类处理；判据三个条件
    //     （通道、范围、地址数值）同时成立才拒绝，与 MemoryIoByteStore.h 里
    //     IsKernelMutationRoute 的判据完全一致，避免物理地址数值恰好落进
    //     内核半区被误判。
    ksword::memwb::IoWriteResult WorkbenchIoPort::Write(
        const ksword::memwb::MemoryTargetSession& session,
        const std::uint64_t address,
        const std::vector<std::uint8_t>& bytes,
        const bool approved)
    {
        if (session.scope == ksword::memwb::Scope::Physical
            && session.channel == ksword::memwb::Channel::UserMode)
        {
            ksword::memwb::IoWriteResult result;
            result.failure = "用户态通道没有访问物理地址的手段，请改用驱动或磁盘传输通道";
            return result;
        }

        const bool isStandardKernelMutationRoute =
            session.channel == ksword::memwb::Channel::StandardDriver &&
            session.scope == ksword::memwb::Scope::KernelVirtual &&
            ksword::memwb::IsKernelVirtualAddress(address);
        if (isStandardKernelMutationRoute)
        {
            ksword::memwb::IoWriteResult result;
            result.failure =
                "标准驱动通道的内核虚拟地址写入必须经 IKernelMutationPort 分步字节事务，"
                "WorkbenchIoPort 不直接处理该组合。";
            return result;
        }

        return WriteViaFacade(session, address, bytes, approved);
    }
    std::optional<ksword::memwb::IMemoryIoPort::UnreadableExtent> WorkbenchIoPort::QueryUnreadableExtent(
        const ksword::memwb::MemoryTargetSession& session, std::uint64_t address)
    {
        using ksword::memwb::Scope;
        using ksword::memwb::Channel;
        if (session.scope != Scope::ProcessVirtual || session.pid == 0 || session.processCreateTime100ns == 0)
            return std::nullopt;
        const HANDLE process = ::OpenProcess(session.channel == Channel::UserMode
            ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION, FALSE, session.pid);
        if (!process) return std::nullopt;
        const std::unique_ptr<void, decltype(&::CloseHandle)> lease(process, &::CloseHandle);
        const auto sameInstance = [&]() {
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!::GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
            return ((static_cast<std::uint64_t>(created.dwHighDateTime) << 32U) | created.dwLowDateTime)
                    == session.processCreateTime100ns
                && exited.dwLowDateTime == 0 && exited.dwHighDateTime == 0;
        };
        if (!sameInstance()) return std::nullopt;
        std::uint64_t first = 0, size = 0;
        DWORD state = 0, protect = 0;
        if (session.channel == Channel::StandardDriver)
        {
            const ksword::ark::DriverClient client;
            auto driver = client.openSilently();
            if (!driver.isValid()) return std::nullopt;
            const auto query = client.queryVirtualMemory(session.pid, address, 0, &driver);
            if (!query.io.ok || !(query.fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT)
                || query.basicStatus < 0 || query.openStatus < 0 || query.processId != session.pid) return std::nullopt;
            first = query.baseAddress; size = query.regionSize; state = query.state; protect = query.protect;
        }
        else
        {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) != sizeof(info))
                return std::nullopt;
            first = reinterpret_cast<std::uint64_t>(info.BaseAddress); size = info.RegionSize;
            state = info.State; protect = info.Protect;
        }
        const bool ordinaryRead = session.channel == Channel::UserMode;
        const bool unavailable = state == MEM_FREE || state == MEM_RESERVE
            || (ordinaryRead && state == MEM_COMMIT && ((protect & 0xFFU) == PAGE_NOACCESS || (protect & PAGE_GUARD)));
        if (!unavailable || size == 0 || size - 1 > std::numeric_limits<std::uint64_t>::max() - first
            || address < first || address - first >= size || !sameInstance()) return std::nullopt;
        return UnreadableExtent{first, first + size - 1};
    }
}
