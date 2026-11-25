#pragma once

#include <array>
#include <optional>
#include <vector>

#include "ApiMonitorClue.h"

namespace Ksword::Evidence {

// 从调用方冻结的授权来源取得这些值。归档内同名字段只用于一致性校验。
struct PassiveApiSource {
    std::uint64_t sessionIdentity = 0; // 现有 WinAPI 采集会话标识。
    std::uint32_t readerPid = 0; // 授权调用方的进程 ID。
    std::uint64_t readerCreation = 0; // 同一个进程实例的 FILETIME 创建时间。
};

enum class PassiveApiTailState {
    Unopened,
    Reading, // 读块用完，仍有已知积压。
    AtTail, // 已读到当前可见末尾，写入方可能继续追加。
    PartialLine, // 当前暂存半行，等待写入方追加。
    Sealed,
    UnconfirmedEnd,
    TruncatedTail,
    WriterFailed,
    ReceiptMismatch,
    SourceChanged,
    IdentityMismatch,
    InvalidRecord,
    ReadFailed,
    Cutoff, // 跟随方读到已冻结的字节边界，原写入方仍可继续追加。
};

enum class PassiveApiWriterEnd {
    UnknownCount, // 持有者已确认文件结束，但缺少成功写入回执。
    Flushed, // 持有者已确认成功刷盘并关闭文件。
    Failed, // 持有者报告写入或刷盘失败并停止追加。
};

struct PassiveApiWriterReceipt {
    PassiveApiWriterEnd end = PassiveApiWriterEnd::UnknownCount; // 来自同一次采集的归档持有者。
    std::uint64_t writtenRows = 0; // Flushed 时取关闭后的最终 written()。
};

struct PassiveApiTailStatus {
    PassiveApiSource source; // 打开时冻结的授权来源。
    PassiveApiTailState state = PassiveApiTailState::Unopened; // 最近一轮实际读取状态。
    std::uint64_t validatedRows = 0; // 已校验前缀中的连续归档行数，包含控制和覆盖包。
    std::uint64_t validatedBytes = 0; // 上述前缀在文件中的末尾偏移，包含换行。
    std::size_t partialLineBytes = 0; // 等待续写的半行字节数，也保留失败时的截断长度。
    std::optional<std::uint64_t> reportedAgentDrops; // 来源通知的累计下界，缺失时为未知。
    std::optional<PassiveApiWriterReceipt> writerReceipt; // 保留写入方回执，即使尾部验证失败。
    DWORD win32Error = ERROR_SUCCESS; // 读取失败或排斥写入失败的底层错误码。
    std::optional<std::uint64_t> cutoffBytes; // 本端停止跟随时冻结的源文件字节边界。
    std::optional<std::uint64_t> visibleBytes; // 最近一次从同源句柄读回的文件长度。
};

// Qt-free 的只读数据适配器。由调用方在同一串行工作队列内拥有和调用。
class PassiveApiArchiveTail final {
public:
    static constexpr std::size_t kReadBytes = 64u << 10; // 每轮最多读取 64 KiB。
    static constexpr std::size_t kLineBytes = 8192; // 与现有离线导入器一致。
    static constexpr std::size_t kPacketTextBytes = ((sizeof(ks::winapi_monitor::ApiMonitorEventPacket) + 2) / 3) * 4; // Base64 正文长度。
    static constexpr std::size_t kMaxPollRows = 1 + kReadBytes / kPacketTextBytes; // 一行跨块，其余每条至少含完整 Base64 包。

    PassiveApiArchiveTail() = default;
    ~PassiveApiArchiveTail(); // 仅关闭自己的只读句柄。
    PassiveApiArchiveTail(const PassiveApiArchiveTail&) = delete;
    PassiveApiArchiveTail& operator=(const PassiveApiArchiveTail&) = delete;

    // 从调用方显式授权的本地磁盘文件句柄重新打开独立的只读游标，从第一个字节开始。
    // 调用方可在返回后释放原句柄。返回 Win32 代码，首次成功后不得换源。
    [[nodiscard]] DWORD Open(HANDLE authorizedFile, PassiveApiSource source);

    // 每轮返回新校验的完整前缀行，原包及可空分类直接复用已有数据结构。
    // 失败状态仍可返回本轮此前已通过的行。调用方消费当前批次后再发起下一轮。
    [[nodiscard]] std::vector<ArchivedApiMonitorClue> Poll();

    // 在授权写入方停止追加后，可向同一串行队列提交一次回执。
    // 返回是否记录成功。下一轮继续排空，结束才会比较完整行数及尾部。
    [[nodiscard]] bool SetWriterReceipt(PassiveApiWriterReceipt receipt) noexcept;

    // 冻结同一文件的当前可见大小。后续 Poll 不消费超过边界的追加数据。
    // 已有写入方回执时不改变读端的封存流程。失败原因通过 Status 返回。
    [[nodiscard]] bool FreezeVisibleEnd() noexcept;

    // 返回最近状态的借用引用，下一轮读取可更新值。
    [[nodiscard]] const PassiveApiTailStatus& Status() const noexcept { return status_; }

    // 判断当前实例是否继续接受 Poll 或写入方回执。
    [[nodiscard]] bool CanPoll() const noexcept;

private:
    // 对已读取的一块字节验证行并追加输出，失败停于首个损坏位置。
    void ConsumeBlock(std::string_view block, std::vector<ArchivedApiMonitorClue>& rows);

    // 处理已到当前文件末尾的状态转换。
    void SetTailState() noexcept;

    HANDLE file_ = INVALID_HANDLE_VALUE; // 独占的只读游标，阻止在会话内替换文件名。
    HANDLE sealedFile_ = INVALID_HANDLE_VALUE; // 按结束回执打开的同一只读文件，排斥写入直到销毁。
    PassiveApiTailStatus status_; // 实际读取状态以及累计前缀和丢失计数。
    std::array<char, kLineBytes> partialLine_; // 固定容量的跨块行。
    std::uint64_t fileOffset_ = 0; // 从文件读入的字节数，可大于已核对前缀。
    std::uint64_t lastVisibleSize_ = 0; // 检出采样间已可见文件长度发生倒退。
};

} // namespace Ksword::Evidence
