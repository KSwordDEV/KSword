#pragma once

// ============================================================
// HexViewport.h
// 作用：
// - "虚拟滚动十六进制视图"的纯模型层：地址空间几何、页缓存、选区、滚动目标。
//   不含任何绘制、不做任何 I/O，取代旧 HexEditorWidget 那种"每字节一个表格单元格、
//   每次变更全表重建"的做法（对象数 O(字节数) -> 本模型 O(缓存页数)）。
// - Qt-free、Win32-free，只用 C++20 标准库，可在离线套件里直接跑。
//
// 线程模型：
// - 非线程安全，只能在 UI 线程使用。异步读取线程拿到结果后必须回到 UI 线程再调用
//   InsertPage / MarkUnreadable（它们自带代次校验，晚到的陈旧结果会被丢弃）。
//
// ------------------------------------------------------------
// 一、地址空间与行列几何
// ------------------------------------------------------------
// - 地址空间是闭区间 [firstAddress, lastAddress]。用闭区间而不是"起点+长度"，
//   是因为长度在整个 2^64 空间上本身就会溢出。
// - 每行 bytesPerRow 字节，只接受 8/16/32/48/64。其它值被拒绝：构造时 Status() 报
//   InvalidBytesPerRow 且整个视图退化为"空"；SetBytesPerRow 返回 false 且不改动。
// - 行按"绝对地址"对齐：第 0 行起始地址 = firstAddress 向下对齐到 bytesPerRow 的倍数。
//   因此首行的前几列是"补空位"（地址早于 firstAddress，不属于空间，不可选中、不可读取），
//   列头 00..0F 与地址低位永远一致。48 不是 2 的幂，对齐用取模而不是掩码。
// - 末行同理可能只有前几列有效；而且 bytesPerRow=48 时 2^64 不是 48 的倍数，
//   最高一行的后几列对应 >= 2^64 的"地址"。这些格子同样是空位，**绝不回绕成小地址**。
// - 全部算术都按"先比较、后加减"书写，在 firstAddress 靠近 0、lastAddress 靠近
//   UINT64_MAX 时都不会溢出。行号是 uint64：最小行宽 8 时最多 2^61 行，装得下。
//
// ------------------------------------------------------------
// 二、页缓存（LRU，来源代次守卫）
// ------------------------------------------------------------
// - 页大小 kPageBytes、最多缓存页数 kMaxCachedPages 都是**暂定值**：在 Phase 1 渲染
//   基准确认前不得视为定稿（纯 C++ 的命中计数基准已在测试里，但涉及 Qt 绘制的离屏
//   基准要随 HexCanvas 一起做）。构造函数允许覆盖缓存页数，测试靠它覆盖淘汰路径。
// - 每页携带：字节、有效掩码（每字节一个 0/1，1=读到了）、来源代次。
// - 一个字节只有四种状态，且**绝不让不可读/未加载的字节冒充数据**：
//     NotLoaded  没读过（也没在途）；
//     Pending    已登记在途，结果还没回来；
//     Unreadable 读过了但读不到（整页读失败，或部分读里掩码为 0 的字节）；
//     Valid      读到了，value 才有意义。
//   state 不是 Valid 时 value 恒为 0，调用方不得把它显示成数据。地址不在空间内也返回
//   NotLoaded——想区分"补空位"请先用 ContainsAddress/AddressAt，渲染层本来就应该这样做。
// - 来源代次 sourceRevision：InvalidateAll(新代次) 清空缓存与在途登记并更新代次；之后
//   凡是带着旧代次回来的 InsertPage/MarkUnreadable 一律拒绝（陈旧异步结果丢弃）。
//   "不符"包括比当前更小也包括比当前更大，所以换目标时必须换一个新的代次，
//   只清缓存不换代次会让在途的旧结果被当成新数据接收。
// - PlanFetch 为纯查询：给出"还需要读哪些页范围"，已缓存（含已知不可读）或已在途的页不重复
//   请求；范围夹取在地址空间内；按距离视口由近到远排序；总页数不超过缓存容量
//   （否则预取会把可见页自己挤出缓存）。登记在途要调用方显式 MarkInFlight。
// - 读取命中会刷新 LRU；PeekByte 是不改变 LRU 与计数的只读版本。
//
// ------------------------------------------------------------
// 三、选区
// ------------------------------------------------------------
// - 单一选区 Selection{anchor, caret, pane}。线性"文本式"：端点含、跨行连续、
//   夹取到地址空间两端，不是矩形。
// - 构造后插入点在 firstAddress（单字节选区），有效视图任何时刻都有插入点。
// - 补空位地址不可成为插入点：SetCaret 把它吸附到该行第一个有效地址（即 firstAddress）。
//   补空位只出现在首行开头与末行结尾，所以"吸附"与"夹取到 [first,last]"是同一个动作。
// - 所有移动先夹取、不回绕。extend 为真时锚点不动（Shift 扩选），否则锚点跟随插入点。
// - 选区只由选区方法改变：滚动、InsertPage、InvalidateAll、SetBytesPerRow 都不碰它。
//
// ------------------------------------------------------------
// 四、滚动
// ------------------------------------------------------------
// - 模型不持有滚动位置（滚动条是绘制层的）。ScrollToAddress 根据"当前首行 + 可见行数"
//   算出目标首行，供绘制层使用；结果夹取到 [0, MaxFirstVisibleRow]，不会滚出末尾空白。
// ============================================================

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace ksword::memwb {

class HexViewport {
public:
    // kPageBytes：页缓存的页大小。暂定，待 Phase 1 渲染基准确认前不得视为定稿。
    static constexpr std::uint64_t kPageBytes = 4096ULL;

    // kMaxCachedPages：默认最多缓存页数。暂定，待 Phase 1 渲染基准确认前不得视为定稿。
    static constexpr std::size_t kMaxCachedPages = 256U;

    // kDefaultBytesPerRow：默认每行字节数。
    static constexpr std::uint32_t kDefaultBytesPerRow = 16U;

    // InitStatus：构造结果。非 Ok 时整个视图为空（IsValid()==false），所有查询返回空/0，
    // 所有写操作返回拒绝，调用方哪怕忘了看状态也拿不到半截数据。
    enum class InitStatus : int {
        Ok = 0,                 // 参数合法
        InvalidRange,           // firstAddress > lastAddress
        InvalidBytesPerRow,     // 行宽不是 8/16/32/48/64
        InvalidCacheCapacity,   // 缓存页数为 0
    };

    // ActivePane：选区当前所在的面板。
    enum class ActivePane : int {
        Hex = 0,    // 十六进制面板
        Ascii,      // ASCII 面板
    };

    // ScrollAlign：ScrollToAddress 的对齐方式。
    enum class ScrollAlign : int {
        Center = 0, // 目标行尽量落在视口中央
        Top,        // 目标行尽量落在视口第一行
        Nearest,    // 已可见则不动，否则滚到最近的边（上方对齐顶、下方对齐底）
    };

    // ByteState：单个字节的缓存状态，含义见文件头第二节。
    enum class ByteState : int {
        NotLoaded = 0,  // 未加载
        Pending,        // 在途
        Unreadable,     // 不可读
        Valid,          // 有效
    };

    // PageResult：页缓存写操作（登记/插入/标不可读）的结果。拒绝时缓存状态完全不变。
    enum class PageResult : int {
        Accepted = 0,           // 已接受
        RejectedStaleRevision,  // 来源代次与当前代次不符（陈旧或超前的异步结果）
        RejectedMisaligned,     // 页起始地址不是 kPageBytes 的整数倍
        RejectedOutsideSpace,   // 页（范围）不与地址空间相交，或视图无效
        RejectedBadSize,        // 缓冲/掩码长度不是一页，或范围页数为 0 / 超过缓存容量
    };

    // AddressRange：地址闭区间 [first, last]。
    struct AddressRange {
        std::uint64_t first = 0;    // 起始地址（含）
        std::uint64_t last = 0;     // 结束地址（含）
        bool operator==(const AddressRange&) const = default;
    };

    // Selection：选区。anchor 与 caret 可以任意先后（反向选区时 anchor > caret）。
    struct Selection {
        std::uint64_t anchor = 0;               // 锚点：选区固定的一端
        std::uint64_t caret = 0;                // 插入点：随移动变化的一端
        ActivePane pane = ActivePane::Hex;      // 当前面板
        bool operator==(const Selection&) const = default;
    };

    // ByteLookup：LookupByte/PeekByte 的结果。
    struct ByteLookup {
        ByteState state = ByteState::NotLoaded; // 状态
        std::uint8_t value = 0;                 // 字节值，仅 state==Valid 时有意义，否则恒为 0
    };

    // FetchRange：一段连续的页。用"起点 + 页数"而不是"起点 + 结束"，因为最后一页的
    // 结束地址（+1）会在 2^64 处溢出。
    struct FetchRange {
        std::uint64_t firstPageStart = 0;   // 第一页的起始地址，必须页对齐
        std::uint64_t pageCount = 0;        // 页数（>= 1）
        std::uint64_t distancePages = 0;    // 与视口相距多少页（0=含可见页）；仅 PlanFetch 填写，Mark* 忽略
        bool operator==(const FetchRange&) const = default;
    };

    // CacheStats：缓存计数，供基准与诊断使用，不影响任何行为。
    struct CacheStats {
        std::uint64_t hits = 0;                 // LookupByte 命中已缓存页（含已知不可读页）的次数
        std::uint64_t misses = 0;               // LookupByte 落在未缓存页（NotLoaded 或 Pending）的次数
        std::uint64_t evictions = 0;            // 因容量满而淘汰的页数
        std::uint64_t staleRejections = 0;      // 因来源代次不符被丢弃的写入次数
    };

    // 构造：给定闭区间、每行字节数、缓存页数。参数非法时 Status() 不是 Ok 且视图为空。
    HexViewport(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress,
        std::uint32_t bytesPerRow = kDefaultBytesPerRow,
        std::size_t maxCachedPages = kMaxCachedPages);

    // ---------------- 基本信息 ----------------

    // 构造结果。
    InitStatus Status() const;

    // 视图是否有效（Status()==Ok）。
    bool IsValid() const;

    // 地址空间起点（含）。
    std::uint64_t FirstAddress() const;

    // 地址空间终点（含）。
    std::uint64_t LastAddress() const;

    // 当前每行字节数。
    std::uint32_t BytesPerRow() const;

    // 缓存页数上限。
    std::size_t MaxCachedPages() const;

    // 是否是受支持的行宽（8/16/32/48/64）。
    static bool IsSupportedBytesPerRow(std::uint32_t bytesPerRow);

    // 改行宽。返回 false（且不改动）表示视图无效或行宽不受支持。
    // 页缓存与选区都按绝对地址存放，不受影响；滚动位置由调用方用 RowOfAddress 重算。
    bool SetBytesPerRow(std::uint32_t bytesPerRow);

    // 地址是否属于空间（补空位与空间之外都不属于）。
    bool ContainsAddress(std::uint64_t address) const;

    // ---------------- 行列几何 ----------------

    // 总行数；视图无效时为 0。
    std::uint64_t RowCount() const;

    // 某行的起始地址（已向下对齐，首行可能小于 firstAddress，即含补空位）。越界返回空。
    std::optional<std::uint64_t> RowStartAddress(std::uint64_t row) const;

    // 某行内属于地址空间的闭区间（去掉首行开头与末行结尾的补空位）。越界返回空。
    std::optional<AddressRange> RowValidSpan(std::uint64_t row) const;

    // 地址所在行；地址不属于空间（含补空位）返回空。
    std::optional<std::uint64_t> RowOfAddress(std::uint64_t address) const;

    // 地址所在列（0..bytesPerRow-1）；地址不属于空间返回空。
    std::optional<std::uint32_t> ColumnOfAddress(std::uint64_t address) const;

    // 行列对应的地址；行/列越界、补空位、超出 2^64 都返回空。
    std::optional<std::uint64_t> AddressAt(std::uint64_t row, std::uint32_t column) const;

    // ---------------- 滚动 ----------------

    // 可滚动的最大首行：RowCount - visibleRowCount，不足一屏时为 0。供滚动条量程使用。
    std::uint64_t MaxFirstVisibleRow(std::uint64_t visibleRowCount) const;

    // Opt-in projection only: byte addresses, selection and exported data stay physical.
    // Unknown ranges contain confirmed unreadable bytes, never NotLoaded/Pending bytes.
    void SetFoldUnknown(bool enabled);
    bool FoldUnknown() const { return foldUnknown_; }
    bool HasFoldedRows() const { return !hiddenRows_.empty(); }
    std::uint64_t FoldRevision() const { return foldRevision_; }
    void NoteUnreadableRange(std::uint64_t first, std::uint64_t last);
    bool IsKnownUnreadable(std::uint64_t address) const;
    void RevealAddress(std::uint64_t address);
    void SetFoldProtection(std::function<bool(std::uint64_t, std::uint64_t)> predicate)
    { foldProtection_ = std::move(predicate); RebuildFolds(); }
    void RefreshFoldProtection() { if (foldUnknown_) RebuildFolds(); }

    // 计算让 address 可见所需的目标首行。address 不属于空间、visibleRowCount 为 0、
    // 视图无效时返回空（调用方保持当前位置）。结果夹取到 [0, MaxFirstVisibleRow]。
    std::optional<std::uint64_t> ScrollToAddress(
        std::uint64_t address,
        ScrollAlign align,
        std::uint64_t currentFirstRow,
        std::uint64_t visibleRowCount) const;

    // ---------------- 页缓存 ----------------

    // 地址所在页的起始地址（向下对齐到 kPageBytes）。
    static std::uint64_t PageStartOf(std::uint64_t address);

    // 规划需要读取的页范围：可见页 + 前后各 prefetchPages 页的预取，夹取在空间内，
    // 剔除已缓存/已在途的页，总页数不超过缓存容量；结果按距离由近到远排序，距离相等时
    // 向后（更高地址）的在前、同侧按地址升序。可见行会夹取到末行之内；起始行越界或
    // visibleRowCount 为 0 返回空。纯查询，不登记在途。
    std::vector<FetchRange> PlanFetch(
        std::uint64_t firstVisibleRow,
        std::uint64_t visibleRowCount,
        std::uint64_t prefetchPages,
        bool ignoreCache = false) const;
    std::vector<FetchRange> PlanAddressFetch(std::uint64_t first, std::uint64_t last,
        std::uint64_t prefetchPages, bool ignoreCache = false) const;

    // 把范围内尚未缓存的页登记为在途（Pending）。已缓存的页不降级。拒绝时不登记任何页。
    PageResult MarkInFlight(const FetchRange& range);

    // 撤销在途登记（读取整体失败又不想判不可读、想允许重试时用）。不动已缓存的页。
    PageResult CancelInFlight(const FetchRange& range);

    // 插入一页读取结果。bytes 与 validMask 都必须正好 kPageBytes 字节，validMask 非 0 表示该字节读到了。
    // sourceRevision 与当前代次不符时拒绝（先于其它校验）。已存在的页被替换，容量满时淘汰最久未用的页。
    PageResult InsertPage(
        std::uint64_t pageStart,
        const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& validMask,
        std::uint64_t sourceRevision);

    // 把范围内整页标成不可读（覆盖已有内容）。与"还没读"区分：PlanFetch 不会再请求它们。
    // 同样要带来源代次，陈旧的失败结果不能把新读到的页标坏。
    PageResult MarkUnreadable(const FetchRange& range, std::uint64_t sourceRevision);

    // 清空缓存与在途登记，并把当前来源代次改成 newSourceRevision。选区不变。
    void InvalidateAll(std::uint64_t newSourceRevision);

    // 当前来源代次。
    std::uint64_t SourceRevision() const;

    // 读一个字节并刷新 LRU、累计命中计数。
    ByteLookup LookupByte(std::uint64_t address);

    // 只读版本：不刷新 LRU、不计数。
    ByteLookup PeekByte(std::uint64_t address) const;

    // 已缓存页数（含已知不可读页，不含在途）。
    std::size_t CachedPageCount() const;

    // 已缓存页的起始地址，从最久未用到最近使用排序（淘汰次序）。
    std::vector<std::uint64_t> CachedPageStartsLeastRecentFirst() const;

    // 某页是否已缓存（含已知不可读）。
    bool IsPageCached(std::uint64_t pageStart) const;

    // 某页是否在途。
    bool IsPageInFlight(std::uint64_t pageStart) const;

    // 在途页数。
    std::size_t InFlightPageCount() const;

    // 缓存计数。
    const CacheStats& Stats() const;

    // 清零缓存计数（不影响缓存内容）。
    void ResetStats();

    // ---------------- 选区 ----------------

    // 当前选区（含面板）。
    Selection GetSelection() const;

    // 选区的闭区间：[min(anchor,caret), max(anchor,caret)]；视图无效返回空。
    std::optional<AddressRange> SelectedRange() const;

    // 设置插入点。extend 为真时锚点不动。address 是补空位/越界时吸附到最近的有效地址。
    // 返回 true 表示插入点正好落在 address；false 表示被吸附或视图无效。
    bool SetCaret(std::uint64_t address, bool extend);

    // 按字节移动（正数向高地址）。夹取不回绕。返回选区是否发生变化。
    bool MoveCaretByBytes(std::int64_t deltaBytes, bool extend);

    // 按行移动，保持列；目标列是补空位时吸附。返回选区是否发生变化。
    bool MoveCaretByRows(std::int64_t deltaRows, bool extend);

    // 按页移动：一页 = visibleRows 行。visibleRows 为 0 视为无效返回 false。
    bool MoveCaretByPages(std::int64_t deltaPages, std::uint64_t visibleRows, bool extend);

    // Home：移到插入点所在行的第一个有效地址。
    bool MoveCaretHome(bool extend);

    // End：移到插入点所在行的最后一个有效地址。
    bool MoveCaretEnd(bool extend);

    // 全选：锚点=firstAddress，插入点=lastAddress。
    bool SelectAll();

    // 当前面板。
    ActivePane Pane() const;

    // 设置面板（不改变选区地址）。
    void SetPane(ActivePane pane);

    // 切换 Hex/Ascii 并返回切换后的面板。
    ActivePane TogglePane();

private:
    // CachedPage：一页缓存。
    struct CachedPage {
        std::vector<std::uint8_t> bytes;        // 页内字节（不可读页为空）
        std::vector<std::uint8_t> validMask;    // 有效掩码，每字节一个 0/1（不可读页为空）
        std::uint64_t sourceRevision = 0;       // 读取时的来源代次
        bool unreadable = false;                // 整页不可读
        mutable std::uint64_t lastUsedTick = 0; // 最近使用序号，越小越久未用；读缓存命中时刷新
    };

    // 校验页范围（对齐、页数、与空间相交）。返回 Accepted 表示合法。
    PageResult ValidateRange(const FetchRange& range) const;

    // 判定地址的状态；若命中已缓存页，经 pageOut 返回该页指针。
    ByteLookup Classify(std::uint64_t address, const CachedPage** pageOut) const;

    // 淘汰最久未用的一页。
    void EvictOldestPage();

    // 写入（或替换）一页，必要时先淘汰；返回新页引用供调用方填内容。
    CachedPage& AcquirePageSlot(std::uint64_t pageStart);

    // 应用新的插入点。返回选区是否变化。
    bool ApplyCaret(std::uint64_t target, bool extend);
    void RebuildFolds();
    std::vector<FetchRange> PlanFetchRaw(std::uint64_t firstRow, std::uint64_t rows,
        std::uint64_t prefetch, bool ignoreCache, bool skipKnownUnknown) const;
    void TrackUnknownPage(std::uint64_t pageStart, const std::vector<std::uint8_t>& mask);
    void EraseUnknownRange(std::uint64_t first, std::uint64_t last);
    void AddUnknownRange(std::uint64_t first, std::uint64_t last);
    std::uint64_t RawRowCount() const;
    std::uint64_t RawToVisual(std::uint64_t row) const;
    std::uint64_t VisualToRaw(std::uint64_t row) const;
    struct HiddenRows {
        std::uint64_t first = 0, last = 0, before = 0, visual = 0;
        bool operator==(const HiddenRows&) const = default;
    };
    bool foldUnknown_ = false;
    std::uint64_t foldRevision_ = 0, hiddenRowCount_ = 0;
    // Bounded projection metadata; exceeding it leaves additional rows unfolded.
    std::map<std::uint64_t, std::uint64_t> unknownRanges_;
    std::vector<HiddenRows> hiddenRows_;
    std::function<bool(std::uint64_t, std::uint64_t)> foldProtection_;
    std::optional<std::uint64_t> foldRevealedAddress_;

    // 按字节数量级移动（forward 为真向高地址）。
    bool MoveBytesByMagnitude(bool forward, std::uint64_t magnitude, bool extend);

    // 按行数量级移动。
    bool MoveRowsByMagnitude(bool forward, std::uint64_t magnitude, bool extend);

    // 把地址夹取到 [firstAddress, lastAddress]。
    std::uint64_t ClampToSpace(std::uint64_t address) const;

    InitStatus status_;                         // 构造结果
    std::uint64_t firstAddress_;                // 空间起点（含）
    std::uint64_t lastAddress_;                 // 空间终点（含）
    std::uint32_t bytesPerRow_;                 // 每行字节数
    std::size_t maxCachedPages_;                // 缓存页数上限
    std::uint64_t rowBase_;                     // 第 0 行起始地址 = firstAddress 向下对齐
    std::uint64_t sourceRevision_;              // 当前来源代次
    std::uint64_t useTick_;                     // LRU 序号发生器，每次使用自增
    std::map<std::uint64_t, CachedPage> pages_; // 已缓存页，键为页起始地址
    std::set<std::uint64_t> inFlight_;          // 在途页，键为页起始地址
    CacheStats stats_;                          // 缓存计数
    Selection selection_;                       // 当前选区
};

} // namespace ksword::memwb
