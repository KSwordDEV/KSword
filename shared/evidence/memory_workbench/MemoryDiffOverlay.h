#pragma once

// ============================================================
// MemoryDiffOverlay.h
// 作用：
// - 内存编辑器的"暂存编辑叠加层"。取代旧编辑器里四份易混的字节副本
//   （原始 / 观察 / 上次读取 / 最近变化），把它们收敛成：
//     一份基线窗口 + 一份"上次读取" + 一组按绝对地址存储的暂存补丁。
// - 纯 C++20 标准库实现，不依赖 Qt，不依赖 Win32，不做任何 I/O。
//   控件只能经由本类暂存编辑，本类自己永远不写目标内存（不变式 1）。
//
// 数据模型：
// - 基线窗口：一次读取得到的 [baseAddress, baseAddress + 长度) 字节，
//   配一份 validMask（1 = 真实读到，0 = 没读到）。没读到的字节不补零冒充真实数据。
// - 上次读取：同一目标、同一基址、同一长度重读时，被顶替下来的上一份基线。
//   只用来判断"外部变化"，只读。
// - 暂存补丁：std::map<起始地址, DiffBlock>，**按绝对地址存储，与当前窗口无关**，
//   因此翻页 / 重读不会丢用户的编辑。块之间既不重叠也不相邻（相邻会被合并）。
//   每个补丁字节记录 before（暂存时刻基线里的原字节）与 after（用户想写入的值）。
// - 自己写入标记：AcceptWrite 之后，被写入的字节在下一次读取之前显示为"自己写入"，
//   不得被当成外部篡改。
//
// 三种载入语义：
// - LoadBaseline    新目标 / 新快照。清空全部暂存补丁。
// - RefreshBaseline 同一目标重读。保留暂存补丁。
// - 两者对"上次读取"的处理相同：identityKey、baseAddress、长度三者与上一次完全
//   相同才把上一份基线留作上次读取，否则清空。两者都会清掉"自己写入"标记。
//   被拒绝的载入不改任何状态（含补丁）。
// - 安全例外：RefreshBaseline 时 identityKey 与当前基线不同，说明已不是同一目标
//   （换进程 / 换通道 / 重新附加），补丁按绝对地址存储，留着会被写进另一个目标，
//   所以此时和 LoadBaseline 一样清空补丁。只有 baseAddress / 长度变化（翻页、
//   窗口扩展）才保留补丁。
//
// Stage 的检查顺序（决定返回哪个原因，调用方可据此给用户提示）：
//   Empty -> AddressOverflow -> OutOfWindow -> UnreadBytes -> TooLarge。
// - 范围必须完整落在当前基线窗口内且每个字节都被真实读到，不能编辑从没读到的字节。
// - 没有载入基线时按 OutOfWindow 处理。
// - 暂存总量（PendingByteCount）上限 64 MiB，超限拒绝 TooLarge；改写已暂存的字节
//   不增加总量，所以在上限处仍可以覆盖。
// - 新写入的字节恰好等于当前基线时，该处补丁消失（空操作编辑不留痕），可能把
//   一个补丁拆成两个，也可能让整个补丁消失。
// - 与已有补丁重叠 / 相邻时合并；重叠部分的 before 保留**最早**那次的原字节。
// - 被拒绝的 Stage 不改任何状态。
//
// 地址溢出规则（全类统一）：
// - 范围 [address, address + length) 要求 address + length <= 0xFFFFFFFFFFFFFFFF，
//   即"终点（不含）"必须能用 uint64 表示。换句话说地址空间最末一个字节
//   0xFFFFFFFFFFFFFFFF 永远不可编辑；这是有意取的保守边界，换来所有区间算术
//   都不会回绕。
//
// ChangeKind 优先级：Pending > SelfWritten > Unreadable > ExternalChange > Unchanged。
// - Pending：该字节有暂存补丁，且补丁值不同于当前基线（基线未知时视为不同）。
// - SelfWritten：AcceptWrite 刚写入的字节，显示成自己写入而不是外部变化。
// - Unreadable：窗口外或基线里没读到，且没有补丁。
// - ExternalChange：上次读取存在、大小与基线一致，且两边都真实读到、字节不同。
//   引用与缓冲尺寸不符时绝不产生 ExternalChange（旧控件的既有规则，防止误导
//   篡改检测）。
// - Unchanged：其余。
//
// 公开接口摘要：
//   LoadBaseline / RefreshBaseline  载入基线
//   Stage / Discard / DiscardAll    暂存与丢弃
//   AcceptWrite                     写事务确认写入并回读后调用
//   Materialize / EffectiveByte     取叠加后的视图
//   DiffBlocks                      按地址升序列出补丁，供写前复核原字节
//   ChangeKind                      单字节变化种类
//   HasPendingPatches / PendingByteCount / BaselineByte / PreviousByte 等查询
// ============================================================

#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ksword::memwb
{
    // 暂存总量上限：64 MiB。Stage 会让总量超过它时拒绝（TooLarge）。
    inline constexpr std::uint64_t kMemoryDiffOverlayMaxPendingBytes = 64ULL * 1024ULL * 1024ULL;

    // Materialize 单次最多生成的字节数（64 MiB）。这是防御上限：避免调用方误传一个
    // 巨大长度让进程在这里 bad_alloc。驱动单次读取上限只有 1 MiB，正常使用碰不到。
    inline constexpr std::uint64_t kMemoryDiffOverlayMaxMaterializeBytes = 64ULL * 1024ULL * 1024ULL;

    // uint64 地址空间的最大值，区间溢出判据统一用它。
    inline constexpr std::uint64_t kMemoryDiffOverlayAddressMax = 0xFFFFFFFFFFFFFFFFULL;

    // StageStatus：一次暂存的结果。每一种拒绝都是独立原因，调用方据此告诉用户该改什么。
    enum class StageStatus
    {
        Ok,              // 已暂存（可能因为全是空操作而没有留下任何补丁）
        Empty,           // 没有给任何字节
        AddressOverflow, // address + length 超过 uint64 上限
        OutOfWindow,     // 范围没有完整落在当前基线窗口内（含尚未载入基线）
        UnreadBytes,     // 范围内含从没真实读到的字节
        TooLarge         // 暂存总量会超过上限
    };

    // BaselineLoadStatus：载入基线的结果。非 Ok 时对象状态完全不变。
    enum class BaselineLoadStatus
    {
        Ok,
        MaskLengthMismatch, // validMask 长度与 bytes 不同
        AddressOverflow     // baseAddress + 长度 超过 uint64 上限
    };

    // AcceptWriteStatus：写事务确认写入的结果。非 Ok 时对象状态完全不变。
    enum class AcceptWriteStatus
    {
        Ok,
        Empty,                 // 块里没有任何字节
        ReadBackLengthMismatch, // 回读长度与块长度不符
        AddressOverflow         // 块的 address + 长度 超过 uint64 上限
    };

    // ByteChangeKind：单字节的变化种类，供控件上色。控件只管上色，不做判断。
    enum class ByteChangeKind
    {
        Unreadable,     // 没读到（或窗口之外）
        Unchanged,      // 与基线、上次读取都一致
        Pending,        // 橙：已暂存且不同于基线
        ExternalChange, // 青：基线与上次读取不同
        SelfWritten     // 自己刚写入的，不得显示成外部变化
    };

    // DiffBlock：一个暂存补丁块。同时用作 AcceptWrite 的入参。
    struct DiffBlock
    {
        // 块的起始绝对地址。
        std::uint64_t address = 0;
        // 暂存时刻基线里的原字节（保留最早一次），供写事务做"写前复核"。
        std::vector<std::uint8_t> before;
        // 用户想写入的字节。长度即块长度，与 before 等长。
        std::vector<std::uint8_t> after;

        // 逐字段比较，测试与调用方做整体相等判断时用。
        bool operator==(const DiffBlock& other) const = default;
    };

    // MaterializedBytes：Materialize 的结果。
    struct MaterializedBytes
    {
        // 请求是否合法（地址溢出或超过防御上限时为 false，其余字段为空）。
        bool ok = false;
        // 叠加后的字节。没读到又没补丁的位置固定为 0，真假以 validMask 为准。
        std::vector<std::uint8_t> bytes;
        // 与 bytes 等长，1 = 有效（读到或被补丁覆盖），0 = 无效。
        std::vector<std::uint8_t> validMask;
    };

    // MemoryDiffOverlay：暂存编辑叠加层。不是线程安全的，调用方在同一线程使用。
    class MemoryDiffOverlay
    {
    public:
        // 构造一个空叠加层。
        // maxPendingBytes 默认是 64 MiB 常量；参数只为让测试能用小上限验证边界。
        explicit MemoryDiffOverlay(std::uint64_t maxPendingBytes = kMemoryDiffOverlayMaxPendingBytes);

        // Copies and rvalue transfers keep both snapshot handles valid. Their
        // immutable storage is shared; the first subsequent mutator detaches.
        MemoryDiffOverlay(const MemoryDiffOverlay&) noexcept = default;
        MemoryDiffOverlay& operator=(const MemoryDiffOverlay&) noexcept = default;

        // 载入新目标 / 新快照的基线，并清空全部暂存补丁。
        // 入参：identityKey 目标身份串（scope+pid+channel 等由调用方拼好）；
        //       baseAddress 窗口起始绝对地址；bytes 读到的字节；
        //       validMask 与 bytes 等长，每字节 1 = 真实读到、0 = 没读到（非零按 1 处理）。
        // 返回：Ok 或拒绝原因；拒绝时所有状态（含补丁）保持不变。
        BaselineLoadStatus LoadBaseline(
            const std::string& identityKey,
            std::uint64_t baseAddress,
            std::vector<std::uint8_t> bytes,
            std::vector<std::uint8_t> validMask);

        // 同一目标重读：与 LoadBaseline 的区别只有**保留暂存补丁**
        // （identityKey 变了则不再是同一目标，补丁照样清空，见文件头）。
        // 入参与返回同 LoadBaseline。
        BaselineLoadStatus RefreshBaseline(
            const std::string& identityKey,
            std::uint64_t baseAddress,
            std::vector<std::uint8_t> bytes,
            std::vector<std::uint8_t> validMask);

        // 暂存一次编辑。
        // 入参：address 起始绝对地址；bytes 想写入的字节。
        // 返回：Ok 或拒绝原因；拒绝时不改任何状态。
        StageStatus Stage(std::uint64_t address, const std::vector<std::uint8_t>& bytes);

        // 丢弃 [address, address + length) 内的暂存补丁，可能把一个补丁拆成两个。
        // 不要求范围在窗口内；length 为 0 或区间溢出时什么也不做。
        // 返回：实际丢弃的补丁字节数。
        std::uint64_t Discard(std::uint64_t address, std::uint64_t length);

        // 丢弃全部暂存补丁。
        void DiscardAll();

        // 写事务确认写入并回读之后调用。
        // 作用：用回读字节更新基线对应范围（窗口外的部分忽略）；移除该补丁；把窗口内
        //       这些字节标记为"自己写入"。如果用户在写入过程中又把同一处暂存成了
        //       别的值，新的暂存保留，其 before 改为回读值（目标上现在就是它）。
        // 入参：block 刚写入的块（取 address 与 after 长度）；readBackBytes 回读字节，
        //       长度必须等于 block.after.size()。
        // 返回：Ok 或拒绝原因；拒绝时不改任何状态。
        AcceptWriteStatus AcceptWrite(const DiffBlock& block, const std::vector<std::uint8_t>& readBackBytes);

        // 取 [address, address + length) 叠加补丁之后的视图（补丁覆盖处视为有效）。
        // 入参：address 起始绝对地址；length 字节数（0 合法，返回空视图）。
        // 返回：MaterializedBytes，ok 为 false 表示请求不合法。
        MaterializedBytes Materialize(std::uint64_t address, std::uint64_t length) const;

        // 取单字节的叠加后取值；该字节无效（没读到、窗口外且无补丁）时返回 nullopt。
        std::optional<std::uint8_t> EffectiveByte(std::uint64_t address) const;

        // 按地址升序列出全部补丁块的副本，供写事务做"写前复核原字节"。
        std::vector<DiffBlock> DiffBlocks() const;

        // 是否存在暂存补丁（D1 模式切换确认用）。
        bool HasPendingPatches() const;

        // 暂存补丁总字节数。
        std::uint64_t PendingByteCount() const;

        // 单字节变化种类，规则见文件头。
        ByteChangeKind ChangeKind(std::uint64_t address) const;

        // 基线里该字节的原值（不含补丁）；窗口外或没读到返回 nullopt。
        std::optional<std::uint8_t> BaselineByte(std::uint64_t address) const;

        // 上次读取里该字节的值；没有上次读取或该字节没读到返回 nullopt。
        std::optional<std::uint8_t> PreviousByte(std::uint64_t address) const;

        // 是否已载入过基线。
        bool HasBaseline() const;

        // 是否存在可用于比对的"上次读取"。
        bool HasPreviousRead() const;

        // 当前基线的身份串。
        const std::string& IdentityKey() const;

        // 当前基线窗口的起始地址。
        std::uint64_t BaseAddress() const;

        // 当前基线窗口的字节数。
        std::uint64_t BaselineSize() const;

        // 本实例使用的暂存总量上限。
        std::uint64_t MaxPendingBytes() const;

        // Value copies share an immutable revision until a mutator detaches.
        // A worker may mutate its own copy while the GUI reads the original.
        // The same instance must never be used concurrently by two threads.
        // A projection witness keeps the storage control-block identity, not
        // the large state itself. Unlock hooks may refresh the baseline without
        // inheriting a full-map GUI detach from a finished value disposer.
        struct Revision
        {
            std::weak_ptr<const void> storage;
            std::uint64_t serial = 0;
        };
        Revision CaptureRevision() const noexcept { return {state_, mutationSerial_}; }
        bool MatchesRevision(const Revision& revision) const noexcept
        { return mutationSerial_ == revision.serial && revision.storage.lock() == state_; }
        std::uint64_t MutationSerial() const noexcept { return mutationSerial_; }
        std::size_t PendingBlockCount() const noexcept { return state_->patches_.size(); }
        struct PendingAddressRange { std::uint64_t first = 0, last = 0; };
        std::optional<PendingAddressRange> FirstPendingRange(std::uint64_t first, std::uint64_t last) const noexcept
        {
            if (first > last) return std::nullopt;
            auto it = state_->patches_.upper_bound(first);
            if (it != state_->patches_.begin())
            {
                const auto previous = std::prev(it);
                if (!previous->second.after.empty() && first - previous->first < previous->second.after.size()) it = previous;
            }
            if (it == state_->patches_.end() || it->first > last || it->second.after.empty()) return std::nullopt;
            return PendingAddressRange{it->first, it->first + (it->second.after.size() - 1)};
        }
        bool HasPendingInRange(std::uint64_t first, std::uint64_t last) const noexcept
        {
            if (first > last) return false;
            auto it = state_->patches_.upper_bound(last);
            if (it == state_->patches_.begin()) return false;
            --it;
            return !it->second.after.empty() && (it->first >= first
                || first - it->first < it->second.after.size());
        }
        bool SameRevision(const MemoryDiffOverlay& other) const noexcept
        { return mutationSerial_ == other.mutationSerial_ && state_ == other.state_; }
        // Constant-time projection into this same overlay object. The prepared
        // owner retains the displaced revision for disposal on its worker.
        bool TryAdoptPrepared(const MemoryDiffOverlay& original, MemoryDiffOverlay& prepared) noexcept
        {
            if (!SameRevision(original)) return false;
            state_.swap(prepared.state_);
            ++mutationSerial_;
            return true;
        }

        // 区间 [address, address + length) 的终点是否能用 uint64 表示（全类统一的溢出判据）。
        static bool RangeRepresentable(std::uint64_t address, std::uint64_t length);

    private:
        // ByteState：改写引擎里单个字节的补丁状态。
        struct ByteState
        {
            // 该字节是否有补丁。
            bool patched = false;
            // 补丁记录的原字节。
            std::uint8_t before = 0;
            // 补丁记录的目标字节。
            std::uint8_t after = 0;
        };

        // ByteRule：改写规则。输入绝对地址与旧状态，输出新状态。
        using ByteRule = std::function<ByteState(std::uint64_t, const ByteState&)>;

        // 载入基线的共用实现，keepPatches 决定是否保留补丁。
        BaselineLoadStatus InstallBaseline(
            const std::string& identityKey,
            std::uint64_t baseAddress,
            std::vector<std::uint8_t> bytes,
            std::vector<std::uint8_t> validMask,
            bool keepPatches);

        // 改写 [start, endExclusive) 的补丁：逐字节套规则，再与左右相接的块合并重切。
        // 新总量超过 maxTotal 时返回 false 且不改任何状态。只用于范围长度有界的调用
        // （Stage 与 AcceptWrite）。
        bool RewriteRange(
            std::uint64_t start,
            std::uint64_t endExclusive,
            const ByteRule& rule,
            std::uint64_t maxTotal);

        // 找到覆盖 address 的补丁块，offsetInBlock 回填块内偏移；没有则返回 end()。
        std::map<std::uint64_t, DiffBlock>::const_iterator FindPatch(
            std::uint64_t address,
            std::uint64_t& offsetInBlock) const;

        // address 是否落在当前基线窗口内。
        bool InWindow(std::uint64_t address) const;

        struct State
        {
            // 暂存总量上限。
            std::uint64_t maxPendingBytes_ = kMemoryDiffOverlayMaxPendingBytes;
            // 是否已载入基线。
            bool hasBaseline_ = false;
            // 当前基线的身份串。
            std::string identityKey_;
            // 窗口起始绝对地址。
            std::uint64_t baseAddress_ = 0;
            // 基线字节。
            std::vector<std::uint8_t> baseline_;
            // 基线有效掩码，与 baseline_ 等长，0 = 没读到，非零 = 真实读到。
            std::vector<std::uint8_t> validMask_;
            // 是否存在上次读取。
            bool hasPrevious_ = false;
            // 上次读取的字节（与 baseline_ 等长）。
            std::vector<std::uint8_t> previous_;
            // 上次读取的有效掩码。
            std::vector<std::uint8_t> previousMask_;
            // 自己写入标记，与 baseline_ 等长，1 = 刚被 AcceptWrite 写入。
            std::vector<std::uint8_t> selfWritten_;
            // 暂存补丁：键为块起始地址，值的 address 与键相同。块互不重叠也不相邻。
            std::map<std::uint64_t, DiffBlock> patches_;
            // 暂存补丁总字节数，等于各块 after.size() 之和。
            std::uint64_t pendingBytes_ = 0;
        };
        void Detach();
        std::shared_ptr<State> state_;
        std::uint64_t mutationSerial_ = 0;

    };
}
