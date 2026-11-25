#include "../../../shared/evidence/PassiveApiArchiveTail.h"
#include "../../../shared/evidence/PassiveApiSourceDiagnosis.h"

#include <cstdio>
#include <stdexcept>
#include <wincrypt.h>

namespace {
namespace Evidence = Ksword::Evidence;
namespace Monitor = ks::winapi_monitor;
using Packet = Monitor::ApiMonitorEventPacket;
using State = Evidence::PassiveApiTailState;
using End = Evidence::PassiveApiWriterEnd;
using Tail = Evidence::PassiveApiArchiveTail;
using Json = Evidence::JsonValue;

unsigned assertions = 0; // 通过的断言计数，失败时报告对应判据。

// 连续执行断言，第一项失败抛出其标签，自动释放夹具文件。
void Check(bool ok, const char* label)
{
    if (!ok) {
        throw std::runtime_error(label);
    }
    ++assertions;
}

// 使用与 WinAPIDiskArchive 相同的文件共享模式，只追加本验证进程生成的字节。
class FixtureFile final {
public:
    explicit FixtureFile(const wchar_t* path) : path_(path)
    {
        writer_ = ::CreateFileW(path_, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        Check(writer_ != INVALID_HANDLE_VALUE, "create owned fixture");
    }

    ~FixtureFile()
    {
        CloseWriter();
        ::DeleteFileW(path_);
    }
    FixtureFile(const FixtureFile&) = delete;
    FixtureFile& operator=(const FixtureFile&) = delete;

    // 从夹具写入句柄打开独立只读游标，保留写入端的追加位置。
    void Attach(Tail& tail, Evidence::PassiveApiSource source) const
    {
        Check(tail.Open(writer_, source) == ERROR_SUCCESS, "attach with collector sharing");
    }

    // 向文件写入完整记录或部分记录，不涉及外部进程。
    void Append(std::string_view content) const
    {
        DWORD written = 0; // Win32 回报的实际写入字节数。
        Check(::WriteFile(writer_, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) &&
            written == content.size(), "append fixture bytes");
    }

    // 提前关闭写入端后，可以通过公开接口回报结束原因。
    void CloseWriter() noexcept
    {
        if (writer_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(writer_);
            writer_ = INVALID_HANDLE_VALUE;
        }
    }

    // 成功关闭前确认夹具刷盘。用于生成真实的成功回执。
    void FlushAndClose()
    {
        Check(::FlushFileBuffers(writer_) != FALSE, "flush fixture");
        CloseWriter();
    }

    // 仅对当前测试拥有的文件模拟违反只追加约定的写入者。
    void Truncate() const
    {
        LARGE_INTEGER start{}; // 将写入端偏移设回文件起始。
        Check(::SetFilePointerEx(writer_, start, nullptr, FILE_BEGIN) && ::SetEndOfFile(writer_), "truncate owned fixture");
    }

private:
    const wchar_t* path_; // 由调用方提供的固定且本次独占的测试路径。
    HANDLE writer_ = INVALID_HANDLE_VALUE; // 只写端，按现有归档 writer 的共享模式打开。
};

// 为本进程制作一条测试包，API 名称只是编解码夹具的合成标签。
Packet MakePacket(Evidence::PassiveApiSource source)
{
    Packet packet{}; // 与生产归档使用同一 ABI。
    packet.pid = source.readerPid;
    packet.tid = ::GetCurrentThreadId();
    packet.sessionIdentity = source.sessionIdentity;
    packet.timestamp100ns = source.readerCreation + 1;
    packet.category = static_cast<std::uint32_t>(Monitor::EventCategory::Memory);
    wcscpy_s(packet.moduleName, L"KernelBase.dll");
    wcscpy_s(packet.apiName, L"WriteProcessMemory");
    return packet;
}

// 从固定包生成现有归档格式的 JSONL；伪造显示摘要用于证明分类取自原包。
std::string MakeLine(const Packet& packet, std::uint64_t sequence, std::uint64_t creation)
{
    std::array<char, Tail::kPacketTextBytes + 1> encoded; // Windows Base64 输出留一位终止符。
    DWORD length = static_cast<DWORD>(encoded.size()); // 编码前为容量，成功后为正文长度。
    if (!::CryptBinaryToStringA(reinterpret_cast<const BYTE*>(&packet), sizeof(packet),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &length) || length != Tail::kPacketTextBytes) {
        throw std::runtime_error("encode fixture packet");
    }
    Evidence::JsonObject fields{
        {"packetBase64", Json::makeString(std::string(encoded.data(), length))},
        {"sequence", Json::makeString(std::to_string(sequence))},
        {"readerPid", Json::makeUInt(packet.pid)},
        {"pid", Json::makeUInt(packet.pid)},
        {"clueFamily", Json::makeString("misleading-text")},
    }; // 生产写入器中创建身份可能缺失；负控使用零来省略该字段。
    if (creation) {
        fields.emplace_back("processCreation100ns", Json::makeString(std::to_string(creation)));
    }
    return Evidence::WriteJson(Json::makeObject(std::move(fields))) + '\n';
}

// 生成与 Agent 相同封装的丢失通知，只包含测试用计数。
Packet MakeDrop(Evidence::PassiveApiSource source, const wchar_t* count)
{
    auto packet = MakePacket(source); // 从同一授权源报告丢失。
    packet.category = static_cast<std::uint32_t>(Monitor::EventCategory::Internal);
    wcscpy_s(packet.moduleName, L"Agent");
    wcscpy_s(packet.apiName, L"EventsDropped");
    wcscpy_s(packet.detailText, count);
    return packet;
}

// 分片追加、多轮读取和有效关闭。比对原包、归类、覆盖以及累计丢失状态。
void TestLive(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 先声明写文件夹具，保证只读句柄先销毁。
    Tail tail; // 待测的生产数据模块。
    Check(!tail.CanPoll() && tail.Poll().empty(), "unopened");
    auto invalidSource = source; // 故意缺少创建身份，打开必须失败。
    invalidSource.readerCreation = 0;
    Check(tail.Open(INVALID_HANDLE_VALUE, invalidSource) == ERROR_INVALID_PARAMETER, "reject missing source identity");
    file.Attach(tail, source);
    Check(tail.Poll().empty() && tail.Status().state == State::AtTail, "empty archive still open");
    Check(!tail.Status().reportedAgentDrops, "absence does not imply zero losses");

    const auto packet = MakePacket(source); // 合成线索的原始包。
    const auto line = MakeLine(packet, 1, source.readerCreation); // 一条合法记录拆成三次写入。
    const auto prefix = std::string_view(line).substr(0, 45); // 第一段不足一行。
    file.Append(prefix);
    Check(tail.Poll().empty() && tail.Status().state == State::PartialLine, "do not publish a partial line");
    Check(tail.Status().partialLineBytes == prefix.size(), "partial byte accounting");
    file.Append(std::string_view(line).substr(prefix.size(), line.size() - prefix.size() - 1));
    Check(tail.Poll().empty() && tail.Status().validatedBytes == 0, "no record before newline");
    file.Append("\n");

    const auto first = tail.Poll(); // 已完成第一行，返回逐字节相同的原包。
    Check(first.size() == 1 && first.front().sourceSequence == 1, "publish one completed row");
    Check(std::memcmp(&packet, &first.front().packet, sizeof(packet)) == 0, "exact raw packet");
    Check(first.front().clue && first.front().clue->family == "memory-write", "reuse raw classifier");
    Check(first.front().readerCreation == source.readerCreation, "retain verified identity match");
    Check(tail.Status().validatedBytes == line.size() && tail.Status().partialLineBytes == 0, "committed byte prefix");

    auto coverage = packet; // 覆盖包保留原始记录，但不归为业务线索。
    coverage.eventKind = static_cast<std::uint32_t>(Monitor::EventKind::CoverageBegin);
    file.Append(MakeLine(MakeDrop(source, L"4"), 2, source.readerCreation));
    file.Append(MakeLine(MakeDrop(source, L"4"), 3, source.readerCreation));
    file.Append(MakeLine(MakeDrop(source, L"8"), 4, source.readerCreation));
    file.Append(MakeLine(coverage, 5, source.readerCreation));
    const auto controls = tail.Poll(); // 通知与覆盖帧以原本顺序交付。
    Check(controls.size() == 4 && !controls.front().clue && !controls.back().clue, "preserve non-clue records");
    Check(tail.Status().reportedAgentDrops == 8, "cumulative reports are not summed");
    Check(tail.Status().state == State::AtTail && tail.CanPoll(), "EOF remains temporary");

    file.FlushAndClose();
    Check(tail.Poll().empty() && tail.Status().state == State::AtTail, "closed handle without receipt does not seal");
    Check(tail.SetWriterReceipt({End::Flushed, 5}), "accept final flushed count");
    Check(!tail.SetWriterReceipt({End::Failed, 0}), "reject competing receipt");
    Check(tail.Poll().empty() && tail.Status().state == State::Sealed && !tail.CanPoll(), "seal verified row count");
    Check(tail.Status().reportedAgentDrops == 8, "sealed file retains reported losses");
}

// 快速量验证多个固定字节块与跨块行，确保每批有界且序号完整。
void TestBacklog(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 自有追加源。
    Tail tail; // 逐块排空的读取器。
    file.Attach(tail, source);
    constexpr std::uint64_t total = 150; // 确保输入跨过几个 64 KiB 读取边界。
    std::string input; // 合成写入批次，生产适配器不持有它。
    for (std::uint64_t sequence = 1; sequence <= total; ++sequence) {
        input += MakeLine(MakePacket(source), sequence, source.readerCreation);
    }
    file.Append(input);
    file.FlushAndClose();
    Check(tail.SetWriterReceipt({End::Flushed, total}), "set receipt before backlog drain");
    std::uint64_t consumed = 0; // 本用例核验下一行及总数。
    unsigned rounds = 0; // 实际执行的固定大小读批数。
    while (tail.CanPoll() && rounds < 10) {
        const auto rows = tail.Poll(); // 每轮最多提供一个读块的完整记录。
        ++rounds;
        Check(!rows.empty() && rows.size() <= Tail::kMaxPollRows, "bounded row batch");
        for (const auto& row : rows) {
            Check(row.sourceSequence == ++consumed, "cross-block sequence");
        }
    }
    Check(rounds > 1 && consumed == total && tail.Status().state == State::Sealed, "drain before seal");
    Check(tail.Status().validatedBytes == input.size(), "full verified byte count");
}

// 关闭夹具并检查单行或半行尾部，回执与结果是独立参数。
void TestEnd(const wchar_t* path, Evidence::PassiveApiSource source, Evidence::PassiveApiWriterReceipt receipt,
    State expected, bool partial)
{
    FixtureFile file(path); // 用例专属写入者。
    Tail tail; // 当前文件只读游标。
    file.Attach(tail, source);
    auto line = MakeLine(MakePacket(source), 1, source.readerCreation); // 末尾仅一行。
    if (partial) {
        line.pop_back();
    }
    file.Append(line);
    file.FlushAndClose();
    Check(tail.SetWriterReceipt(receipt), "store external end receipt");
    const auto rows = tail.Poll(); // 先完成可用前缀再判断尾部。
    Check(rows.size() == (partial ? 0u : 1u), "preserve only complete rows");
    Check(tail.Status().state == expected && !tail.CanPoll(), "expected sealed tail result");
    Check(tail.Status().partialLineBytes == (partial ? line.size() : 0), "retain truncated byte count");
}

// 追加坏行及随后的一条合法行。看到坏行后停止，不跨过坏行输出后续记录。
void TestBadRow(const wchar_t* path, Evidence::PassiveApiSource source, std::string badRow, State expected)
{
    FixtureFile file(path); // 用例专属写入者。
    Tail tail; // 当前文件只读游标。
    file.Attach(tail, source);
    const auto first = MakeLine(MakeDrop(source, L"5"), 1, source.readerCreation); // 保留丢失下界的有效前缀。
    file.Append(first + badRow + MakeLine(MakePacket(source), 3, source.readerCreation));
    const auto rows = tail.Poll(); // 首批中出现故障，仍可得到有效前缀。
    Check(rows.size() == 1 && rows.front().sourceSequence == 1, "return verified prefix before rejection");
    Check(tail.Status().state == expected && tail.Status().validatedBytes == first.size(), "stop at first bad record");
    Check(tail.Status().reportedAgentDrops == 5 && tail.Poll().empty(), "keep prior drop count without resuming");
}

// 文件回退之后从原来的绑定中结束，拒绝把新行误认作此前不可见的续写。
void TestSourceChange(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 用例专属写入者，允许模拟截短。
    Tail tail; // 当前文件只读游标。
    file.Attach(tail, source);
    file.Append(MakeLine(MakePacket(source), 1, source.readerCreation));
    Check(tail.Poll().size() == 1, "accept row before truncation");
    file.Truncate();
    Check(tail.Poll().empty() && tail.Status().state == State::SourceChanged, "detect source size regression");
    Check(tail.Status().validatedRows == 1, "preserve pre-truncate prefix receipt");
}

// 对当前打开的写入者报告提前结束，验证读端拒绝确认归档完成。
void TestEarlyReceipt(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 保留写入句柄以模拟过早的回执。
    Tail tail; // 打开待验证的读端。
    file.Attach(tail, source);
    file.Append(MakeLine(MakePacket(source), 1, source.readerCreation));
    Check(tail.Poll().size() == 1, "consume before early receipt");
    Check(tail.SetWriterReceipt({End::Flushed, 1}), "stage early receipt");
    Check(tail.Poll().empty() && tail.Status().state == State::ReceiptMismatch, "writer blocks early receipt");
    Check(tail.Status().win32Error == ERROR_SHARING_VIOLATION && tail.Status().validatedRows == 1,
        "preserve read prefix and native sharing error");
}

// 零行文件可以完整结束，计数状态继续清楚地保留未知丢失量。
void TestEmptyReceipt(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 空文件，写者会正常刷盘关闭。
    Tail tail; // 持有当前文件的读取端。
    file.Attach(tail, source);
    file.FlushAndClose();
    Check(tail.SetWriterReceipt({End::Flushed, 0}), "stage empty receipt");
    Check(tail.Poll().empty() && tail.Status().state == State::Sealed, "seal confirmed empty archive");
    Check(tail.Status().validatedRows == 0 && !tail.Status().reportedAgentDrops, "empty archive has unknown coverage");
}

// 读取诊断对象中的固定文本项。缺失、类型错误和值错误都让调用方的判据失败。
bool HasText(const Json& report, std::string_view key, std::string_view expected)
{
    const auto* field = report.find(key); // 由当前快照持有的诊断字段。
    std::string actual; // 不把 null 或数值转成文本。
    return field && field->tryGetString(actual) && actual == expected;
}

// 用自有文件和生产格式的合成通知验诊断。生产方连接始终由独立来源确认。
void TestDiagnosis(const wchar_t* path, Evidence::PassiveApiSource source)
{
    FixtureFile file(path); // 本用例独占的追加文件。
    Tail tail; // 使用生产尾读器校验归档行和身份。
    Evidence::PassiveApiSourceDiagnosis diagnosis; // 只消费已核验行。
    file.Attach(tail, source);
    Check(HasText(diagnosis.Report(tail.Status(), false), "input", "awaiting-first-read"), "opened before first read");
    Check(tail.Poll().empty(), "no rows in empty file");
    auto report = diagnosis.Report(tail.Status(), false); // 本轮报告在下一次附加写入之前生成。
    Check(HasText(report, "input", "idle-at-tail") && HasText(report, "prefixIdentity", "unverified"), "idle and unverified are independent");
    Check(HasText(report, "agentLoss", "unknown"), "unreported loss stays unknown");

    // 向文件追加一条来源声明，再让诊断模块读取报告。默认成功码与实际生产方一致。
    const auto notice = [&](const wchar_t* name, std::uint64_t sequence, std::int32_t result = 0) {
        auto packet = MakeDrop(source, L""); // 借用相同模块与分类的内部原包结构。
        wcscpy_s(packet.apiName, name);
        packet.resultCode = result;
        file.Append(MakeLine(packet, sequence, source.readerCreation));
        for (const auto& row : tail.Poll()) { // 只交付尾读器验过的连续原始行。
            diagnosis.Observe(row);
        }
        return diagnosis.Report(tail.Status(), false);
    };
    report = notice(L"SessionReady", 1);
    Check(HasText(report, "sessionReadySequence", "1") && HasText(report, "producerConnection", "unknown"), "historical ready notice only");
    Check(HasText(report, "prefixIdentity", "prefix-consistent"), "first row validates prefix identity claims");
    Check(report.find("captureNotice") && report.find("captureNotice")->isNull(), "session handshake did not declare capture readiness");

    // 生命周期成功、部分覆盖和终止声明各自保留与原包的坐标。
    (void)notice(L"HooksPartial", 2);
    report = notice(L"HooksInstalled", 3);
    Check(HasText(report, "captureNotice", "HooksInstalled") && HasText(report, "partialNoticeSequence", "2"), "success retains historical partial report");
    report = notice(L"HooksRemoved", 4, 1);
    Check(HasText(report, "captureNoticeSequence", "3"), "ignore unexpected removal status code");
    report = notice(L"HooksRemoved", 5);
    Check(HasText(report, "captureNotice", "HooksRemoved") && HasText(report, "producerConnection", "unknown"), "removal does not report pipe disconnect");
    report = notice(L"SessionReady", 6);
    Check(report.find("captureNotice") && report.find("captureNotice")->isNull(), "new handshake does not reuse old capture notice");

    // 对确定错误和普通读错采用不同标签。只有提供的源统计可以被称为零上报。
    auto status = tail.Status(); // 保留真实前缀，模拟不能从当前文件强制触发的读错误。
    status.state = State::ReadFailed;
    status.win32Error = ERROR_DEVICE_NOT_CONNECTED;
    Check(HasText(diagnosis.Report(status, true), "input", "device-disconnected"), "explicit device disconnect");
    status.win32Error = ERROR_CRC;
    Check(HasText(diagnosis.Report(status, true), "input", "read-failed"), "CRC read fails without inferred disconnect");
    status.reportedAgentDrops = 0;
    Check(HasText(diagnosis.Report(status, true), "agentLoss", "zero-reported"), "reported zero is separately labeled");
    status.reportedAgentDrops = 7;
    Check(HasText(diagnosis.Report(status, true), "agentLoss", "loss-reported"), "known lower bound survives error");
    status.state = State::Cutoff;
    status.partialLineBytes = 5;
    Check(HasText(diagnosis.Report(status, true), "input", "cutoff-partial-line"), "cutoff can include an incomplete row");
    status.state = State::PartialLine;
    Check(HasText(diagnosis.Report(status, false), "input", "waiting-for-line-end"), "partial tail waits for data while reader follows");
    Check(HasText(diagnosis.Report(status, true), "input", "stopped-before-cutoff"), "local stop while waiting for data");
    Check(Evidence::PassiveApiOpenFailureName(ERROR_PATH_NOT_FOUND) == "source-missing", "missing source at open");
    Check(Evidence::PassiveApiOpenFailureName(ERROR_ACCESS_DENIED) == "source-access-denied", "source access denied at open");
}
} // namespace

// 用命令行的一条固定夹具路径运行所有自有来源测试。成功返回零，失败打印首个断言。
int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) {
        return 2;
    }
    try {
        FILETIME creation{}, exit{}, kernel{}, user{}; // 系统返回本夹具自身进程时钟。
        Check(::GetProcessTimes(::GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE, "own creation time");
        const Evidence::PassiveApiSource source{0x1234, ::GetCurrentProcessId(),
            (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime}; // 自有来源。
        auto packet = MakePacket(source); // 用于逐项更换错误字段的合成原包。
        TestLive(argv[1], source);
        TestBacklog(argv[1], source);
        TestEnd(argv[1], source, {End::Flushed, 1}, State::TruncatedTail, true);
        TestEnd(argv[1], source, {End::Flushed, 2}, State::ReceiptMismatch, false);
        TestEnd(argv[1], source, {End::Failed, 0}, State::WriterFailed, true);
        TestEnd(argv[1], source, {End::UnknownCount, 0}, State::UnconfirmedEnd, false);
        TestEarlyReceipt(argv[1], source);
        TestEmptyReceipt(argv[1], source);
        TestDiagnosis(argv[1], source);

        // 各负控均从新文件开始，避免上一用例的终态掩盖失败。
        TestBadRow(argv[1], source, MakeLine(packet, 2, 0), State::IdentityMismatch);
        TestBadRow(argv[1], source, MakeLine(packet, 2, source.readerCreation + 1), State::IdentityMismatch);
        TestBadRow(argv[1], source, MakeLine(packet, 1, source.readerCreation), State::InvalidRecord);
        TestBadRow(argv[1], source, MakeLine(packet, 3, source.readerCreation), State::InvalidRecord);
        TestBadRow(argv[1], source, MakeLine(MakeDrop(source, L"4"), 2, source.readerCreation), State::InvalidRecord);
        TestBadRow(argv[1], source, MakeLine(MakeDrop(source, L"18446744073709551616"), 2, source.readerCreation), State::InvalidRecord);
        TestBadRow(argv[1], source, std::string(Tail::kLineBytes + 1, 'x'), State::InvalidRecord);
        TestBadRow(argv[1], source, "{\"sequence\":\"2\",\"sequence\":\"2\"}\n", State::InvalidRecord);
        auto badBase64 = MakeLine(packet, 2, source.readerCreation); // 在合成 Base64 字段正文中加入非法字符。
        const auto base64Offset = badBase64.find("\":\""); // 第一个键为 packetBase64。
        Check(base64Offset != std::string::npos, "locate synthetic base64");
        badBase64[base64Offset + 3] = '!';
        TestBadRow(argv[1], source, badBase64, State::InvalidRecord);
        ++packet.sessionIdentity;
        TestBadRow(argv[1], source, MakeLine(packet, 2, source.readerCreation), State::IdentityMismatch);
        packet = MakePacket(source);
        ++packet.pid;
        TestBadRow(argv[1], source, MakeLine(packet, 2, source.readerCreation), State::IdentityMismatch);
        packet = MakePacket(source);
        ++packet.version;
        TestBadRow(argv[1], source, MakeLine(packet, 2, source.readerCreation), State::InvalidRecord);
        TestSourceChange(argv[1], source);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL after %u assertions: %s\n", assertions, error.what());
        return 1;
    }
    std::printf("PASS %u assertions\n", assertions);
    return 0;
}
