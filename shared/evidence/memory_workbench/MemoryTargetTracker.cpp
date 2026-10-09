// ============================================================
// MemoryTargetTracker.cpp
// 作用：
// - 实现 MemoryTargetTracker.h 声明的目标会话状态机。
// - 全部是纯逻辑，不依赖 Qt 与 Win32。
// - 核心思路：会话是派生值。每个修改函数只改"六项原始状态"之一，然后统一调用
//   ApplyDerivedSession 重新派生并比较，由它决定是否 bump 来源代次，因此不可能出现
//   "身份变了却忘了 bump"或"bump 了两次"的分支遗漏。
// ============================================================

#include "MemoryTargetTracker.h"

namespace ksword::memwb
{
    namespace
    {
        // kPinnedGenerationCounterMask：钉住代次里自增计数占用的低 63 位掩码。
        constexpr std::uint64_t kPinnedGenerationCounterMask = ~kPinnedAttachGenerationBit;

        // IsKnownScopeValue：判断 scope 是否是三个合法取值之一。
        // 传入：scope 待判断的范围。传出：合法为 true。逐个列出而不比较区间，新增枚举值时会被迫来改这里。
        bool IsKnownScopeValue(const Scope scope) noexcept
        {
            const bool isProcess = (scope == Scope::ProcessVirtual);
            const bool isKernel = (scope == Scope::KernelVirtual);
            const bool isPhysical = (scope == Scope::Physical);
            return isProcess || isKernel || isPhysical;
        }

        // IsKnownChannelValue：判断 channel 是否是四个合法取值之一。
        // 传入：channel 待判断的通道。传出：合法为 true。
        bool IsKnownChannelValue(const Channel channel) noexcept
        {
            const bool isUser = (channel == Channel::UserMode);
            const bool isDriver = (channel == Channel::StandardDriver);
            const bool isHvm = (channel == Channel::Hvm);
            const bool isDdma = (channel == Channel::Ddma);
            return isUser || isDriver || isHvm || isDdma;
        }

        // IsValidBits：地址宽度只能是 32 或 64，其它值不做就近取整。
        // 传入：bits 待判断的宽度。传出：合法为 true。
        bool IsValidBits(const std::uint32_t bits) noexcept
        {
            return (bits == 32U) || (bits == 64U);
        }

        // DescribeSessionDifference：逐字段比较两个会话，给出变更掩码里的身份位。
        // 传入：before 旧会话；after 新会话。传出：Scope/Process/Channel/Ddma/Bits 的并集，
        // 七个字段全等时为 None。这里刻意不调用 SameTarget，以便知道具体是哪一项变了。
        TargetChange DescribeSessionDifference(
            const MemoryTargetSession& before,
            const MemoryTargetSession& after) noexcept
        {
            // mask：累积的变更位，从空开始逐项并入。
            TargetChange mask = TargetChange::None;

            // 范围。
            if (before.scope != after.scope)
            {
                mask |= TargetChange::Scope;
            }

            // 进程：pid、创建时间、附加代次任一项变化都算"进程变了"。
            const bool pidChanged = (before.pid != after.pid);
            const bool createTimeChanged =
                (before.processCreateTime100ns != after.processCreateTime100ns);
            const bool generationChanged = (before.attachGeneration != after.attachGeneration);
            if (pidChanged || createTimeChanged || generationChanged)
            {
                mask |= TargetChange::Process;
            }

            // 通道。
            if (before.channel != after.channel)
            {
                mask |= TargetChange::Channel;
            }

            // DDMA 暂存扇区代次。
            if (before.ddmaGeneration != after.ddmaGeneration)
            {
                mask |= TargetChange::Ddma;
            }

            // 地址宽度。
            if (before.addressBits != after.addressBits)
            {
                mask |= TargetChange::Bits;
            }
            return mask;
        }

        // IsSameProcessIdentity：记录是否与给定进程同身份。
        // 传入：pid/createTime/bits 要比较的进程。传出：记录有效且三项全等为 true。
        // 不比较附加代次：代次是"这一次附加"的标识，不是进程身份的一部分。
        template <typename RecordType>
        bool IsSameProcessIdentity(
            const RecordType& record,
            const std::uint32_t pid,
            const std::uint64_t createTime,
            const std::uint32_t bits) noexcept
        {
            if (!record.present)
            {
                return false;
            }
            if (record.pid != pid)
            {
                return false;
            }
            if (record.createTime100ns != createTime)
            {
                return false;
            }
            return record.addressBits == bits;
        }
    }

    // 构造：两个计数器取调用方给定的初值，其余状态取"尚无目标"的初值。
    MemoryTargetTracker::MemoryTargetTracker(const SessionRevisions& initialRevisions) noexcept
        : revisions_(initialRevisions)
    {
        // 初始会话也由派生得到，保证"默认状态"与"任何调用之后的状态"走同一份规则。
        session_ = DeriveSession();
    }

    // Session：返回最近一次派生出的会话。
    const MemoryTargetSession& MemoryTargetTracker::Session() const noexcept
    {
        return session_;
    }

    // Revisions：返回两个代次计数器。
    const SessionRevisions& MemoryTargetTracker::Revisions() const noexcept
    {
        return revisions_;
    }

    // FollowMode：返回当前跟随模式。
    MemoryTargetTracker::Follow MemoryTargetTracker::FollowMode() const noexcept
    {
        return follow_;
    }

    // WouldChangeOnDockAttach：跟随 Dock 且范围=进程时，Dock 的附加/分离才会改会话。
    bool MemoryTargetTracker::WouldChangeOnDockAttach() const noexcept
    {
        const bool followingDock = (follow_ == Follow::Dock);
        const bool processScope = (scope_ == Scope::ProcessVirtual);
        return followingDock && processScope;
    }

    // DeriveSession：由六项原始状态算出会话。
    MemoryTargetSession MemoryTargetTracker::DeriveSession() const noexcept
    {
        // derived：正在拼装的会话，字段默认值就是"无目标"的安全初值（pid 0、位宽 64）。
        MemoryTargetSession derived;
        derived.scope = scope_;
        derived.channel = channel_;

        // DDMA 代次只在通道为 Ddma 时才有意义，离开 Ddma 后恒为 0。
        if (channel_ == Channel::Ddma)
        {
            derived.ddmaGeneration = ddmaGeneration_;
        }

        // 进程字段只在进程范围下才有意义；内核/物理范围保持默认的零值与 64 位。
        if (scope_ == Scope::ProcessVirtual)
        {
            // 取当前生效的进程记录：跟随 Dock 时用 Dock 记录，钉住时用钉住记录。
            const ProcessRecord& active = (follow_ == Follow::Pinned) ? pinned_ : dock_;
            if (active.present)
            {
                derived.pid = active.pid;
                derived.processCreateTime100ns = active.createTime100ns;
                derived.attachGeneration = active.attachGeneration;
                derived.addressBits = active.addressBits;
            }
        }
        return derived;
    }

    // ApplyDerivedSession：重新派生、比较、必要时 bump。所有修改函数的统一出口。
    TargetChange MemoryTargetTracker::ApplyDerivedSession(const TargetChange extraBits) noexcept
    {
        // 先派生新会话，再与旧会话逐字段比较得到身份位。
        const MemoryTargetSession next = DeriveSession();
        TargetChange mask = DescribeSessionDifference(session_, next);
        session_ = next;

        // 身份位非空即来源代次 +1，且只加一次，无论同时变了几项。
        if (IsIdentityChange(mask))
        {
            revisions_.BumpSource();
        }

        // 非身份位（如 Policy）并入返回值，但不参与 bump 的判断。
        mask |= extraBits;
        return mask;
    }

    // NextPinnedGeneration：2^63 置位 + 低 63 位自增计数。
    std::uint64_t MemoryTargetTracker::NextPinnedGeneration() noexcept
    {
        // 先加一再用，第一个钉住代次是 2^63 + 1；低 63 位回绕不可达（需要 2^63 次钉住），
        // 但仍用掩码保证标记位不会被进位冲掉。
        pinCounter_ = (pinCounter_ + 1ULL) & kPinnedGenerationCounterMask;
        return kPinnedAttachGenerationBit | pinCounter_;
    }

    // FollowAttach：Dock 附加了进程。
    TargetChange MemoryTargetTracker::FollowAttach(
        const std::uint32_t pid,
        const std::uint64_t createTime,
        const std::uint64_t attachGen,
        const std::uint32_t bits)
    {
        // 参数校验：pid 为 0、位宽非法、Dock 代次带钉住标记位都拒绝，状态完全不变。
        if (pid == 0U || !IsValidBits(bits) || IsPinnedAttachGeneration(attachGen))
        {
            return TargetChange::Rejected;
        }

        // Dock 记录无条件更新（记账）。是否影响会话由派生规则决定：
        // 只有跟随 Dock 且范围=进程时，派生结果才会变。
        dock_.present = true;
        dock_.pid = pid;
        dock_.createTime100ns = createTime;
        dock_.attachGeneration = attachGen;
        dock_.addressBits = bits;
        return ApplyDerivedSession(TargetChange::None);
    }

    // FollowDetach：Dock 分离了进程。
    TargetChange MemoryTargetTracker::FollowDetach()
    {
        // 清空 Dock 记录（记账）。之前就没有记录时派生结果不变，自然返回 None。
        dock_ = ProcessRecord();
        return ApplyDerivedSession(TargetChange::None);
    }

    // Pin：钉住一个进程。
    TargetChange MemoryTargetTracker::Pin(
        const std::uint32_t pid,
        const std::uint64_t createTime,
        const std::uint32_t bits)
    {
        // 参数校验。
        if (pid == 0U || !IsValidBits(bits))
        {
            return TargetChange::Rejected;
        }

        // 已经钉住同一个进程：什么都不变，也不消耗新的钉住代次。
        const bool alreadyPinnedSame =
            (follow_ == Follow::Pinned) && IsSameProcessIdentity(pinned_, pid, createTime, bits);
        if (alreadyPinnedSame)
        {
            return TargetChange::None;
        }

        // 决定钉住代次：与 Dock 当前进程同身份就沿用 Dock 的代次，这样会话不变、不 bump；
        // 否则分配新的钉住代次（2^63 置位），保证不与任何 Dock 代次相撞。
        std::uint64_t generation = 0;
        if (IsSameProcessIdentity(dock_, pid, createTime, bits))
        {
            generation = dock_.attachGeneration;
        }
        else
        {
            generation = NextPinnedGeneration();
        }

        // 原本跟随 Dock 才算"跟随模式变了"，需要带 Policy 位；钉住→换钉另一个进程不带。
        const TargetChange policyBit =
            (follow_ == Follow::Dock) ? TargetChange::Policy : TargetChange::None;

        // 写入钉住记录并切换模式，再统一派生。
        pinned_.present = true;
        pinned_.pid = pid;
        pinned_.createTime100ns = createTime;
        pinned_.attachGeneration = generation;
        pinned_.addressBits = bits;
        follow_ = Follow::Pinned;
        return ApplyDerivedSession(policyBit);
    }

    // Unpin：回到跟随 Dock。
    TargetChange MemoryTargetTracker::Unpin()
    {
        // 本来就在跟随：没有任何变化。
        if (follow_ == Follow::Dock)
        {
            return TargetChange::None;
        }

        // 清掉钉住记录并回到跟随，统一派生；跟随模式变了，必带 Policy 位。
        pinned_ = ProcessRecord();
        follow_ = Follow::Dock;
        return ApplyDerivedSession(TargetChange::Policy);
    }

    TargetChange MemoryTargetTracker::ClearPinnedTarget()
    {
        // 两份记录一起清除，避免稍后显式回到跟随时复活旧 Dock 目标。
        dock_ = ProcessRecord();
        pinned_ = ProcessRecord();
        const TargetChange policyBit = follow_ == Follow::Dock
            ? TargetChange::Policy : TargetChange::None;
        follow_ = Follow::Pinned;
        return ApplyDerivedSession(policyBit);
    }

    // SetScope：换范围，不联动通道。
    TargetChange MemoryTargetTracker::SetScope(const Scope scope)
    {
        // 越界值拒绝，状态不变。
        if (!IsKnownScopeValue(scope))
        {
            return TargetChange::Rejected;
        }

        // 同范围：无事发生，不 bump（同参数重复调用必须幂等）。
        if (scope == scope_)
        {
            return TargetChange::None;
        }

        // 换范围：只改范围这一项，其余（含通道）原样保留，由派生规则决定 pid 等是否归零。
        scope_ = scope;
        return ApplyDerivedSession(TargetChange::None);
    }

    // SetChannel：换通道，不联动范围。
    TargetChange MemoryTargetTracker::SetChannel(const Channel channel, const std::uint64_t ddmaGeneration)
    {
        // 越界值拒绝，状态不变。
        if (!IsKnownChannelValue(channel))
        {
            return TargetChange::Rejected;
        }

        // 非 Ddma 通道忽略传入的代次，统一记成 0：这样"离开 Ddma 后代次归零"是结构性的，
        // 而不是靠调用方记得传 0。
        const std::uint64_t normalizedGeneration = (channel == Channel::Ddma) ? ddmaGeneration : 0ULL;
        channel_ = channel;
        ddmaGeneration_ = normalizedGeneration;
        return ApplyDerivedSession(TargetChange::None);
    }

    // ObserveDdma：观察 DDMA 暂存扇区代次。
    TargetChange MemoryTargetTracker::ObserveDdma(const std::uint64_t currentGeneration)
    {
        // 通道不是 Ddma 时这个观察没有意义，忽略（会话里的代次本来就是 0）。
        if (channel_ != Channel::Ddma)
        {
            return TargetChange::None;
        }

        // 记下新代次；与旧值相同时派生结果不变，自然返回 None。
        ddmaGeneration_ = currentGeneration;
        return ApplyDerivedSession(TargetChange::None);
    }

    // Reload：无条件重读，来源代次 +1。
    TargetChange MemoryTargetTracker::Reload()
    {
        // 唯一一个"来源代次变而会话身份不变"的事件，用独立的 Reload 位标出。
        revisions_.BumpSource();
        return TargetChange::Reload;
    }

    // NoteContentChanged：内容代次 +1，其余不动。
    void MemoryTargetTracker::NoteContentChanged() noexcept
    {
        revisions_.BumpContent();
    }
}
