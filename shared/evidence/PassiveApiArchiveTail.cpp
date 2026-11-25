#include "PassiveApiArchiveTail.h"

#include <limits>
#include <new>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace Ksword::Evidence {
namespace {
namespace Monitor = ks::winapi_monitor;
using State = PassiveApiTailState;

// 核对固定大小包中的当前事件类型，避免把保留区值作为已知业务事件发布。
bool HasKnownKinds(const Monitor::ApiMonitorEventPacket& packet) noexcept
{
    return (packet.eventKind <= static_cast<std::uint32_t>(Monitor::EventKind::IoCancel) ||
            Monitor::isCoverageEvent(packet.eventKind)) &&
        packet.category <= static_cast<std::uint32_t>(Monitor::EventCategory::Gui) &&
        packet.resultKind <= static_cast<std::uint32_t>(Monitor::EventResultKind::StatusUnknown);
}

// 读取一个完整归档行。成功填充 row 并返回 Reading，其余结果指明拒绝原因。
State DecodeLine(std::string_view line, std::uint64_t expectedSequence,
    const PassiveApiSource& source, ArchivedApiMonitorClue& row)
{
    JsonLimits limits; // 生产写入器输出平坦对象，每行有一份原包与若干标量摘要。
    limits.maxDepth = 4;
    limits.maxContainerItems = 32;
    limits.maxTotalNodes = 64;
    limits.maxStringBytes = PassiveApiArchiveTail::kLineBytes;
    limits.maxTotalBytes = PassiveApiArchiveTail::kLineBytes;
    const auto parsed = ParseJson(line, limits); // 拒绝重复 JSON 键和无效 UTF-8。
    if (!parsed.ok()) {
        return State::InvalidRecord;
    }

    // 连续序号属于归档文件。分类、会话和事件值全部取自解包后的原始证据。
    const auto* sequence = parsed.value.find("sequence"); // 当前文件中的序号。
    const auto* encoded = parsed.value.find("packetBase64"); // 当前记录的原包。
    std::string base64; // 仅在当前行解码期间持有的文本。
    if (!sequence || !sequence->tryGetU64(row.sourceSequence) || row.sourceSequence != expectedSequence ||
        !encoded || !encoded->tryGetString(base64) || base64.size() != PassiveApiArchiveTail::kPacketTextBytes) {
        return State::InvalidRecord;
    }
    auto& packet = row.packet; // 输出行内的原包缓冲区。
    DWORD bytes = sizeof(packet); // 解码后必须仍等于当前协议包长度。
    if (!::CryptStringToBinaryA(base64.data(), static_cast<DWORD>(base64.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, reinterpret_cast<BYTE*>(&packet), &bytes, nullptr, nullptr) ||
        bytes != sizeof(packet) || packet.size != sizeof(packet) || packet.version != Monitor::kProtocolVersion ||
        !HasKnownKinds(packet)) {
        return State::InvalidRecord;
    }

    // 可信选择来自调用方。只接受与冻结来源逐项一致的单一进程实例。
    const auto* reader = parsed.value.find("readerPid"); // 已有写入器保存的读取者 PID。
    const auto* caller = parsed.value.find("pid"); // 写入器复制的包头 PID。
    const auto* creation = parsed.value.find("processCreation100ns"); // 写入器可选的创建时间声明。
    std::uint64_t readerPid = 0; // 先以无损整数解析，再与冻结 PID 比较。
    std::uint64_t callerPid = 0; // 外层包头摘要与原始包必须一致。
    if (!reader || !reader->tryGetU64(readerPid) || readerPid != source.readerPid ||
        !caller || !caller->tryGetU64(callerPid) || callerPid != source.readerPid || packet.pid != source.readerPid ||
        !creation || !creation->tryGetU64(row.readerCreation) || row.readerCreation != source.readerCreation ||
        packet.sessionIdentity != source.sessionIdentity) {
        return State::IdentityMismatch;
    }
    row.clue = ClassifyApiMonitorClue(packet);
    return State::Reading;
}

// 识别生产 Agent 的累计 EventsDropped 通知。普通包不改计数，损坏或倒退的通知返回失败。
bool UpdateAgentDrops(const Monitor::ApiMonitorEventPacket& packet, std::optional<std::uint64_t>& observed) noexcept
{
    if (packet.eventKind != static_cast<std::uint32_t>(Monitor::EventKind::ApiCall) ||
        packet.category != static_cast<std::uint32_t>(Monitor::EventCategory::Internal) ||
        ApiMonitorPacketText(packet.moduleName) != L"Agent" || ApiMonitorPacketText(packet.apiName) != L"EventsDropped") {
        return true;
    }

    // 通知由写入方用十进制表示，逐位验证以拒绝负号、尾随文本和溢出。
    const auto text = ApiMonitorPacketText(packet.detailText); // 已受定长包字段约束。
    std::uint64_t count = 0; // 当前通知中的累计值。
    if (text.empty()) {
        return false;
    }
    for (const wchar_t digit : text) {
        if (digit < L'0' || digit > L'9') {
            return false;
        }
        const auto value = static_cast<std::uint64_t>(digit - L'0'); // 当前十进制位。
        if (count > ((std::numeric_limits<std::uint64_t>::max)() - value) / 10) {
            return false;
        }
        count = count * 10 + value;
    }
    if (observed && count < *observed) {
        return false;
    }
    observed = count;
    return true;
}
} // namespace

PassiveApiArchiveTail::~PassiveApiArchiveTail()
{
    if (sealedFile_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(sealedFile_);
    }
    if (file_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(file_);
    }
}

DWORD PassiveApiArchiveTail::Open(HANDLE authorizedFile, PassiveApiSource source)
{
    if (status_.state != State::Unopened) {
        return ERROR_ALREADY_INITIALIZED;
    }
    if (!source.sessionIdentity || !source.readerPid || !source.readerCreation ||
        !authorizedFile || authorizedFile == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_PARAMETER;
    }
    if (::GetFileType(authorizedFile) != FILE_TYPE_DISK) {
        return ERROR_INVALID_DATA;
    }

    // 通过句柄绑定同一个文件，自己持有独立游标并允许现有写入方继续追加。
    FILE_STANDARD_INFO info{}; // 排除目录等不能按归档读入的对象。
    if (!::GetFileInformationByHandleEx(authorizedFile, FileStandardInfo, &info, sizeof(info))) {
        return ::GetLastError();
    }
    if (info.Directory || info.DeletePending) {
        return ERROR_INVALID_DATA;
    }
    file_ = ::ReOpenFile(authorizedFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_SEQUENTIAL_SCAN);
    if (file_ == INVALID_HANDLE_VALUE) {
        return ::GetLastError();
    }
    status_.source = source;
    status_.state = State::Reading;
    return ERROR_SUCCESS;
}

bool PassiveApiArchiveTail::CanPoll() const noexcept
{
    return status_.state == State::Reading || status_.state == State::AtTail || status_.state == State::PartialLine;
}

bool PassiveApiArchiveTail::SetWriterReceipt(PassiveApiWriterReceipt receipt) noexcept
{
    if (!CanPoll() || status_.writerReceipt || status_.cutoffBytes) {
        return false;
    }
    status_.writerReceipt = receipt;
    return true;
}

bool PassiveApiArchiveTail::FreezeVisibleEnd() noexcept
{
    if (!CanPoll() || status_.writerReceipt || status_.cutoffBytes) {
        return false;
    }
    LARGE_INTEGER size{}; // 截止前最后一次从原文件句柄读取的大小。
    if (!::GetFileSizeEx(file_, &size)) {
        status_.win32Error = ::GetLastError();
        status_.state = State::ReadFailed;
        return false;
    }
    const auto visible = static_cast<std::uint64_t>(size.QuadPart); // 本次跟随允许读到的最后字节。
    status_.visibleBytes = visible;
    if (visible < lastVisibleSize_) {
        status_.state = State::SourceChanged;
        return false;
    }
    status_.cutoffBytes = visible;
    lastVisibleSize_ = visible;
    if (visible == fileOffset_) {
        SetTailState();
    }
    return true;
}

std::vector<ArchivedApiMonitorClue> PassiveApiArchiveTail::Poll()
{
    std::vector<ArchivedApiMonitorClue> rows; // 由调用方持有新批次，适配器不累计历史数据。
    if (!CanPoll()) {
        return rows;
    }

    // 结束回执必须与实际文件共享状态一致。取得拒绝写入的同文件句柄，排空时沿用原游标。
    if (status_.writerReceipt && sealedFile_ == INVALID_HANDLE_VALUE) {
        sealedFile_ = ::ReOpenFile(file_, GENERIC_READ, FILE_SHARE_READ, FILE_FLAG_SEQUENTIAL_SCAN);
        if (sealedFile_ == INVALID_HANDLE_VALUE) {
            status_.win32Error = ::GetLastError();
            status_.state = status_.win32Error == ERROR_SHARING_VIOLATION ? State::ReceiptMismatch : State::ReadFailed;
            return rows;
        }
    }

    // 一轮只消费读取开始时可见的前缀，检测后续轮次中已可见范围的缩短。
    LARGE_INTEGER size{}; // OS 从同一个持有句柄采得的文件大小。
    if (!::GetFileSizeEx(file_, &size)) {
        status_.win32Error = ::GetLastError();
        status_.state = State::ReadFailed;
        return rows;
    }
    const auto actualSize = static_cast<std::uint64_t>(size.QuadPart); // 同源文件的实际可见长度。
    status_.visibleBytes = actualSize;
    if (actualSize < lastVisibleSize_) {
        status_.state = State::SourceChanged;
        return rows;
    }
    lastVisibleSize_ = actualSize;
    const auto visible = status_.cutoffBytes.value_or(actualSize); // 截止后只准读已冻结的前缀。
    if (visible == fileOffset_) {
        SetTailState();
        return rows;
    }

    // 固定大小读块和有界结果。记录不完整时最多暂存一行，等待下次 Poll。
    std::array<char, kReadBytes> block; // 本轮磁盘读缓冲区。
    const auto requested = static_cast<DWORD>((std::min)(visible - fileOffset_, static_cast<std::uint64_t>(block.size())));
    DWORD read = 0; // 实际从文件读取的字节数。
    try {
        rows.reserve(1 + requested / kPacketTextBytes);
    } catch (const std::bad_alloc&) {
        status_.win32Error = ERROR_NOT_ENOUGH_MEMORY;
        status_.state = State::ReadFailed;
        return rows;
    }
    if (!::ReadFile(file_, block.data(), requested, &read, nullptr)) {
        status_.win32Error = ::GetLastError();
        status_.state = State::ReadFailed;
        return rows;
    }
    if (!read) {
        status_.state = State::SourceChanged;
        return rows;
    }
    fileOffset_ += read;
    status_.state = State::Reading;
    try {
        ConsumeBlock({block.data(), read}, rows);
    } catch (const std::bad_alloc&) {
        status_.win32Error = ERROR_NOT_ENOUGH_MEMORY;
        status_.state = State::ReadFailed;
    }
    if (status_.state == State::Reading && fileOffset_ == visible) {
        SetTailState();
    }
    return rows;
}

void PassiveApiArchiveTail::ConsumeBlock(std::string_view block, std::vector<ArchivedApiMonitorClue>& rows)
{
    while (!block.empty()) {
        const auto end = block.find('\n'); // 当前块中的行边界。
        auto line = block.substr(0, end); // 当前行或跨块行的后半段。
        const auto pending = status_.partialLineBytes; // 前一块遗留的半行长度。
        if (line.size() > kLineBytes - pending) {
            status_.state = State::InvalidRecord;
            return;
        }
        if (pending || end == std::string_view::npos) {
            std::memcpy(partialLine_.data() + pending, line.data(), line.size());
            status_.partialLineBytes += line.size();
            line = {partialLine_.data(), status_.partialLineBytes};
        }
        if (end == std::string_view::npos) {
            return;
        }

        // 每行独立校验并提交。后续无效记录保留此前已确认的连续前缀。
        ArchivedApiMonitorClue row; // 验证结束前不放入对外结果。
        status_.state = DecodeLine(line, status_.validatedRows + 1, status_.source, row);
        if (status_.state == State::Reading && !UpdateAgentDrops(row.packet, status_.reportedAgentDrops)) {
            status_.state = State::InvalidRecord;
        }
        if (status_.state != State::Reading) {
            return;
        }
        rows.push_back(row);
        ++status_.validatedRows;
        status_.validatedBytes += line.size() + 1;
        status_.partialLineBytes = 0;
        block.remove_prefix(end + 1);
    }
}

void PassiveApiArchiveTail::SetTailState() noexcept
{
    if (status_.cutoffBytes) {
        status_.state = State::Cutoff;
    } else if (!status_.writerReceipt) {
        status_.state = status_.partialLineBytes ? State::PartialLine : State::AtTail;
    } else if (status_.writerReceipt->end == PassiveApiWriterEnd::Failed) {
        status_.state = State::WriterFailed;
    } else if (status_.partialLineBytes) {
        status_.state = State::TruncatedTail;
    } else if (status_.writerReceipt->end == PassiveApiWriterEnd::UnknownCount) {
        status_.state = State::UnconfirmedEnd;
    } else if (status_.writerReceipt->writtenRows != status_.validatedRows) {
        status_.state = State::ReceiptMismatch;
    } else {
        status_.state = State::Sealed;
    }
}

} // namespace Ksword::Evidence
