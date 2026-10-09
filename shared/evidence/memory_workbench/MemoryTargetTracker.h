#pragma once

// ============================================================
// MemoryTargetTracker.h
// 作用：
// - 内存工作台"当前目标"的唯一持有者（Qt-free 的纯逻辑层）。它持有一份
//   MemoryTargetSession 与一份 SessionRevisions，并把"什么事件会让来源代次 +1"
//   的全部转移规则写成可测的纯函数式状态机。Qt 侧的 WorkbenchTarget 只是它的包装。
// - 解决的缺陷类别：目标状态散落在十余个控件里、换目标时漏改其中一处，界面照样显示、
//   驱动照样去读，读的却是上一个目标。这里把"目标是什么"与"何时换了"收敛成一处。
//
// 冻结接口摘要（后续 E-K 各包依赖，改动须经主会话批准）：
//   enum class TargetChange : uint32_t     变更位掩码。None=0 Scope=1 Process=2 Channel=4
//                                          Ddma=8 Bits=16 Policy=32 Reload=64 Rejected=128。
//                                          前五位是"身份位"（会话字段变了），Policy 是跟随模式变了、
//                                          Reload 是用户重读（来源代次变而身份不变的唯一事件）、
//                                          Rejected 是参数非法而被拒绝（状态未变）。
//   operator| / operator& / operator|=     掩码运算。
//   HasChange(mask, bit)                   mask 是否含 bit 的全部位（bit 为 None 恒假）。
//   kIdentityChangeMask / IsIdentityChange(mask)   五个身份位的并集 / 掩码里有没有身份位。
//   kPinnedAttachGenerationBit / IsPinnedAttachGeneration(gen)   钉住代次的标记位 2^63。
//   class MemoryTargetTracker
//     enum class Follow { Dock, Pinned }   跟随 Dock 附加 / 钉住某个进程。
//     MemoryTargetTracker(SessionRevisions initial = {})   构造；默认会话故意无效（NeedsPid）。
//     const MemoryTargetSession& Session() const   当前会话（引用在下一次调用后可能变）。
//     const SessionRevisions& Revisions() const    当前两个代次计数器。
//     Follow FollowMode() const                    当前跟随模式。
//     bool WouldChangeOnDockAttach() const         Dock 附加/分离是否会改会话：跟随 Dock 且范围=进程。
//     TargetChange FollowAttach(pid, createTime, attachGen, bits)   Dock 附加了一个进程。
//     TargetChange FollowDetach()                  Dock 分离了进程。
//     TargetChange Pin(pid, createTime, bits)      钉住某个进程，不再随 Dock。
//     TargetChange Unpin()                         回到跟随 Dock。
//     TargetChange SetScope(Scope)                 换范围，不联动通道。
//     TargetChange SetChannel(Channel, ddmaGen)    换通道，不联动范围；仅 Ddma 通道带 ddmaGen。
//     TargetChange ObserveDdma(currentGen)         DDMA 暂存扇区代次变化的观察，仅通道=Ddma 有效。
//     TargetChange Reload()                        用户重读：来源代次 +1，返回 Reload。
//     void NoteContentChanged()                    编辑/撤销/提交：内容代次 +1，其余不动。
//
// 规则（实现与测试共同遵守）：
// - 会话是**派生值**：由 范围、通道、DDMA 代次、跟随模式、Dock 记录、钉住记录 六项算出。
//   每次调用结束后会话被重新派生，与旧会话逐字段比较得到变更掩码；掩码里有身份位，
//   来源代次恰好 +1（多个身份位同时变也只 +1 一次）。因此恒成立两条性质：
//     (1) 会话身份（SameTarget）变了 => 来源代次必变；
//     (2) 来源代次变而身份没变 => 该次调用只能是 Reload。
// - Kernel/Physical 会话把 pid、创建时间、附加代次归零，地址宽度固定 64：这些项对它们
//   无意义，否则每次 Dock 重附加都会让 SameTarget 变假。因此内核/物理范围下 Dock 的
//   附加/分离不会 bump 来源代次。
// - SetScope 与 SetChannel **不联动**：没有任何自动回退或自动换通道。"每个范围记住的通道"
//   由界面层（MemoryChannelGate 的 ChannelMemory）显式再调一次 SetChannel。
// - 离开 Ddma 通道后会话的 ddmaGeneration 归零；换到 Ddma 通道时取调用方传入的当前代次。
// - 钉住的 attachGeneration 取 2^63 置位再加自增计数，Dock 代次必须小于 2^63，两者不会撞。
//   钉住的进程与 Dock 当前进程同身份（pid/创建时间/地址宽度全等）时沿用 Dock 的代次，
//   这样"钉住同一个进程"只改 Policy 位、不 bump，不会无谓地丢弃已读的页。
// - 参数非法（pid 为 0、地址宽度不是 32/64、范围/通道越界、Dock 代次带钉住标记位）一律
//   返回 Rejected 且状态完全不变，不做就近取整；调用方应把 Rejected 当作自身缺陷记日志。
// - 两个计数器按无符号回绕定义；回绕后旧快照仍判陈旧（见 MemoryTargetSession.h）。
// - 仅使用标准库，不包含 Windows.h，不包含任何 Qt 头，非线程安全（调用方在 UI 线程使用）。
// ============================================================

#include <cstdint>

#include "MemoryTargetSession.h"

namespace ksword::memwb
{
    // TargetChange：一次调用造成的变更位掩码，可按位或组合。
    // 数值固定：它会经 Qt 信号以整数形式传出，改动数值等于改动信号契约。
    enum class TargetChange : std::uint32_t
    {
        // None：什么都没变。
        None = 0,
        // Scope：会话的范围变了。
        Scope = 1,
        // Process：pid、进程创建时间、附加代次三者至少一项变了。
        Process = 2,
        // Channel：会话的通道变了。
        Channel = 4,
        // Ddma：会话的 DDMA 暂存扇区代次变了。
        Ddma = 8,
        // Bits：会话的地址宽度变了。
        Bits = 16,
        // Policy：跟随模式变了（钉住/回到跟随），会话身份不一定变。
        Policy = 32,
        // Reload：用户重读。来源代次因它 +1，但会话身份不变。
        Reload = 64,
        // Rejected：参数非法而被拒绝，tracker 状态完全没有变化。
        Rejected = 128,
    };

    // operator|：把两个掩码按位或。传入：两个掩码。传出：并集。
    constexpr TargetChange operator|(const TargetChange left, const TargetChange right) noexcept
    {
        const std::uint32_t merged = static_cast<std::uint32_t>(left) | static_cast<std::uint32_t>(right);
        return static_cast<TargetChange>(merged);
    }

    // operator&：把两个掩码按位与。传入：两个掩码。传出：交集。
    constexpr TargetChange operator&(const TargetChange left, const TargetChange right) noexcept
    {
        const std::uint32_t common = static_cast<std::uint32_t>(left) & static_cast<std::uint32_t>(right);
        return static_cast<TargetChange>(common);
    }

    // operator|=：把 right 并入 left。传入：被修改的掩码、要并入的掩码。传出：left 的引用。
    constexpr TargetChange& operator|=(TargetChange& left, const TargetChange right) noexcept
    {
        left = left | right;
        return left;
    }

    // HasChange：判断掩码是否包含某个（组）位。
    // 传入：mask 被检查的掩码；bit 要找的位（可以是多位组合）。
    // 传出：bit 的每一位都在 mask 里才为 true；bit 为 None 时恒为 false（避免空检查恒真）。
    constexpr bool HasChange(const TargetChange mask, const TargetChange bit) noexcept
    {
        if (bit == TargetChange::None)
        {
            return false;
        }
        return (mask & bit) == bit;
    }

    // kIdentityChangeMask：五个"身份位"的并集。掩码里出现其中任一位，说明会话身份变了。
    inline constexpr TargetChange kIdentityChangeMask =
        TargetChange::Scope | TargetChange::Process | TargetChange::Channel
        | TargetChange::Ddma | TargetChange::Bits;

    // IsIdentityChange：掩码里是否含身份位。传入：mask。传出：含任一身份位为 true。
    constexpr bool IsIdentityChange(const TargetChange mask) noexcept
    {
        return (mask & kIdentityChangeMask) != TargetChange::None;
    }

    // kPinnedAttachGenerationBit：钉住代次的标记位（第 63 位）。Dock 的附加代次必须小于它。
    inline constexpr std::uint64_t kPinnedAttachGenerationBit = 1ULL << 63;

    // IsPinnedAttachGeneration：判断一个附加代次是否出自钉住。传入：generation。传出：标记位置位为 true。
    constexpr bool IsPinnedAttachGeneration(const std::uint64_t generation) noexcept
    {
        return (generation & kPinnedAttachGenerationBit) != 0ULL;
    }

    // MemoryTargetTracker：目标会话的状态机。全部公开函数只在 UI 线程调用。
    class MemoryTargetTracker
    {
    public:
        // Follow：当前目标进程的来源。Dock = 跟随 Dock 附加的进程；Pinned = 钉住的进程。
        enum class Follow : std::uint32_t
        {
            // Dock：跟随 Dock 的附加/分离。
            Dock = 0,
            // Pinned：钉住了某个进程，Dock 的附加/分离只记账、不影响会话。
            Pinned = 1,
        };

        // 构造。传入：initialRevisions 两个代次计数器的初值（默认都是 0；测试回绕时传最大值）。
        // 初始状态：范围=进程、通道=UserMode、跟随 Dock、Dock 未附加，会话故意无效（NeedsPid）。
        explicit MemoryTargetTracker(const SessionRevisions& initialRevisions = SessionRevisions()) noexcept;

        // Session：当前会话。传出：只读引用，下一次调用任何修改函数后内容可能变化，需要持有请拷贝。
        const MemoryTargetSession& Session() const noexcept;

        // Revisions：当前两个代次计数器。传出：只读引用；要带去异步任务请用 Capture() 拷贝快照。
        const SessionRevisions& Revisions() const noexcept;

        // FollowMode：当前跟随模式。
        Follow FollowMode() const noexcept;

        // WouldChangeOnDockAttach：Dock 的附加/分离此刻是否会改会话。
        // 传出：跟随 Dock 且范围=进程时为 true；钉住、内核/物理范围下为 false。
        bool WouldChangeOnDockAttach() const noexcept;

        // FollowAttach：Dock 附加了一个进程（含重新附加同一个进程）。
        // 传入：pid 非零；createTime 进程创建时间（100ns，0 表示身份未锚定）；
        //       attachGen Dock 的附加代次，必须小于 2^63；bits 地址宽度 32 或 64。
        // 传出：变更掩码。只有跟随 Dock 且范围=进程时会话才会变；否则只记账并返回 None。
        //       参数非法返回 Rejected，状态不变。
        TargetChange FollowAttach(
            std::uint32_t pid,
            std::uint64_t createTime,
            std::uint64_t attachGen,
            std::uint32_t bits);

        // FollowDetach：Dock 分离了进程。
        // 传出：只有跟随 Dock 且范围=进程且之前有目标时才会变（Process，若原为 32 位另含 Bits）；否则 None。
        TargetChange FollowDetach();

        // Pin：钉住某个进程，之后 Dock 的附加/分离不再影响会话。
        // 传入：pid 非零；createTime 进程创建时间（0 表示未锚定）；bits 地址宽度 32 或 64。
        // 传出：变更掩码。原为跟随时含 Policy；会话身份变了才含身份位并 bump 来源代次。
        //       已钉住同一个进程返回 None；参数非法返回 Rejected。
        TargetChange Pin(std::uint32_t pid, std::uint64_t createTime, std::uint32_t bits);

        // Unpin：回到跟随 Dock。传出：本来就在跟随返回 None；否则含 Policy，
        // 目标进程不同时再含身份位并 bump。
        TargetChange Unpin();

        // ClearPinnedTarget：关闭独立会话，清两份进程记录但保持钉住策略。
        // 不回到 Dock、不访问目标；身份清空时来源代次由统一出口推进一次。
        TargetChange ClearPinnedTarget();

        // SetScope：换范围。不联动通道，不做任何自动回退。
        // 传入：scope 新范围。传出：范围相同返回 None；越界值返回 Rejected；否则含 Scope，
        //       pid 等随之归零/恢复时另含 Process/Bits，并 bump 来源代次一次。
        TargetChange SetScope(Scope scope);

        // SetChannel：换通道。不联动范围，不做任何自动回退。
        // 传入：channel 新通道；ddmaGeneration 仅当 channel 为 Ddma 时使用，其余通道忽略（会话里归零）。
        // 传出：通道与 DDMA 代次都没变返回 None；越界值返回 Rejected；否则含 Channel/Ddma 并 bump 一次。
        TargetChange SetChannel(Channel channel, std::uint64_t ddmaGeneration);

        // ObserveDdma：观察到 DDMA 暂存扇区的当前代次。
        // 传入：currentGeneration 当前代次。传出：通道不是 Ddma 或代次没变返回 None；否则 Ddma 并 bump。
        TargetChange ObserveDdma(std::uint64_t currentGeneration);

        // Reload：用户刷新/整窗重读。无条件把来源代次 +1，返回 Reload。会话身份不变。
        TargetChange Reload();

        // NoteContentChanged：暂存/丢弃/撤销/写入提交之后调用。只让内容代次 +1，来源代次与会话不动。
        void NoteContentChanged() noexcept;

    private:
        // ProcessRecord：一个进程目标的记录（Dock 的附加记录或钉住记录）。
        struct ProcessRecord
        {
            // present：是否有记录。Dock 未附加时为 false。
            bool present = false;
            // pid：进程号。
            std::uint32_t pid = 0;
            // createTime100ns：进程创建时间（100ns），0 表示身份未锚定。
            std::uint64_t createTime100ns = 0;
            // attachGeneration：附加代次（Dock 的取自 Dock，钉住的见 NextPinnedGeneration）。
            std::uint64_t attachGeneration = 0;
            // addressBits：地址宽度，32 或 64。
            std::uint32_t addressBits = 64;
        };

        // DeriveSession：由六项状态算出当前应有的会话。传出：派生出的会话。
        MemoryTargetSession DeriveSession() const noexcept;

        // ApplyDerivedSession：重新派生会话并与旧会话比较，身份变了则 bump 来源代次。
        // 传入：extraBits 要并入返回掩码的非身份位（如 Policy）。传出：完整变更掩码。
        TargetChange ApplyDerivedSession(TargetChange extraBits) noexcept;

        // NextPinnedGeneration：分配一个新的钉住代次（2^63 置位 + 自增计数）。传出：新代次。
        std::uint64_t NextPinnedGeneration() noexcept;

        // scope_：当前范围。
        Scope scope_ = Scope::ProcessVirtual;
        // channel_：当前通道。
        Channel channel_ = Channel::UserMode;
        // ddmaGeneration_：DDMA 暂存扇区代次；通道不是 Ddma 时恒为 0。
        std::uint64_t ddmaGeneration_ = 0;
        // follow_：跟随模式。
        Follow follow_ = Follow::Dock;
        // dock_：Dock 附加记录，始终记账，不论当前是否跟随。
        ProcessRecord dock_;
        // pinned_：钉住记录，仅 follow_ 为 Pinned 时有意义。
        ProcessRecord pinned_;
        // pinCounter_：钉住代次的自增计数（低 63 位），按需分配时先加一再用。
        std::uint64_t pinCounter_ = 0;
        // session_：最近一次派生出的会话。
        MemoryTargetSession session_;
        // revisions_：两个代次计数器。
        SessionRevisions revisions_;
    };
}
