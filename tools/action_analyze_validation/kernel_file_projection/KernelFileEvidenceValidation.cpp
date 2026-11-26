#include "../../../shared/usermode/backend/monitor/KernelFileEvidenceProjection.h"

#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

void ValidatePassiveEtw(bool live);

namespace {

namespace Monitor = ks::r3::monitor;
using Ksword::Evidence::JsonType;
using Ksword::Evidence::JsonValue;
using Ksword::Evidence::ParseJson;
using Ksword::Evidence::WriteJson;
using Kind = Monitor::KernelFileObservationKind;
using Status = Monitor::KernelFileProjectionStatus;

constexpr auto kFileTime = 134084736000000017ULL; // 大于 JSON 双精度整数范围的时间向量。
constexpr auto kMaxU64 = (std::numeric_limits<std::uint64_t>::max)(); // 无损序列化的上界。
unsigned checks = 0; // 已通过的断言数。

// 断言失败立即中断夹具，并在异常中保留用例名称。
void Check(bool passed, const char* label)
{
    if (!passed) {
        throw std::runtime_error(label);
    }
    ++checks;
}

// 读取对象中必须存在的字段。缺字段给出明确的失败位置。
const JsonValue& Field(const JsonValue& object, std::string_view key)
{
    const auto* field = object.find(key); // 对象拥有此字段。
    if (!field) {
        throw std::runtime_error("Missing field: " + std::string(key));
    }
    return *field;
}

// 比较字符串字段的确切字节，包括 64 位十进制值。
bool TextIs(const JsonValue& value, std::string_view expected)
{
    std::string actual; // JSON 字符串的解码结果。
    return value.tryGetString(actual) && actual == expected;
}

// 比较 JSON 整数，不接受等值字符串代替整数 token。
bool UIntIs(const JsonValue& value, std::uint64_t expected)
{
    std::uint64_t actual = 0; // JSON 整数的无损解码结果。
    return value.type() == JsonType::UInt && value.tryGetU64(actual) && actual == expected;
}

// 比较布尔值并检查类型保持。
bool BoolIs(const JsonValue& value, bool expected)
{
    bool actual = false; // JSON 布尔值的解码结果。
    return value.tryGetBool(actual) && actual == expected;
}

// 创建通用的良性内存观察。默认不提供文件字段、负载或接收时钟。
Monitor::KernelFileObservationView Observation(std::uint16_t id)
{
    Monitor::KernelFileObservationView input; // 待返回的基线观察。
    input.providerId = Monitor::kKernelFileProviderId;
    input.source = {"test-file-session", "d55b5f45-8f35-4cea-83c4-c74c188daae2", "test-boot", "source-clock"};
    input.descriptor = {id, 1, 2, 5, 7, id, kMaxU64};
    input.sourceFileTime100ns = kFileTime;
    input.headerPid = 0;
    input.headerTid = 42;
    return input;
}

// 通过实际投影和共享 JSON 编解码检查产物可独立持有并按原精度读回。
void RequestRoundTrip()
{
    auto input = Observation(15); // 一次 Read 请求，负载只保留前缀。
    std::array<std::uint8_t, 3> bytes{0x00, 0x80, 0xff}; // 合成的原始观察前缀。
    std::string path = "C:\\test\\\xe6\x96\x87.txt"; // 合成 Unicode 路径。
    input.originalPayloadBytes = 7;
    input.payloadPrefix = bytes;
    input.pathUtf8 = path;
    input.fileObject = 0;
    input.fileKey = kMaxU64;
    input.irp = 17;
    input.requestedBytes = 0;
    input.byteOffset = kMaxU64;
    input.receiveQpc = Monitor::KernelFileReceiveQpcView{"receive-qpc", 0, 10'000'000};

    const auto output = Monitor::ProjectKernelFileObservation(input); // 应拥有输入内容的副本。
    Check(output.status == Status::Ok && output.evidence.has_value(), "Read projection");
    bytes.fill(0);
    path[0] = 'X';
    const auto& evidence = *output.evidence; // 一对原始证据和规范事件。
    Check(evidence.raw.inlineBytes == std::vector<std::uint8_t>{0x00, 0x80, 0xff}, "Owned raw bytes");
    const auto raw = ParseJson(WriteJson(evidence.raw.metadata)); // RawRecord v1 的严格 JSON 对象。
    const auto canonical = ParseJson(WriteJson(evidence.canonical.fields)); // 基础字段区。
    Check(raw.ok() && canonical.ok(), "JSON round trip");
    const auto& metadata = raw.value; // 解码后的原始元数据。
    const auto& fields = canonical.value; // 解码后的规范字段。

    Check(evidence.canonical.kind == Kind::ReadRequest, "Read kind");
    Check(evidence.canonical.sourceTimestamp == kFileTime, "Source core time");
    Check(evidence.canonical.receiveQpc == 0, "Known zero receive tick in core");
    Check(TextIs(Field(metadata, "providerId"), Monitor::kKernelFileProviderId), "Provider GUID");
    Check(TextIs(Field(metadata, "sourceId"), input.source.sourceId), "Source instance");
    Check(TextIs(Field(metadata, "sourceEpoch"), input.source.sourceEpoch), "Source epoch");
    Check(TextIs(Field(metadata, "originalPayloadBytes"), "7"), "Original length");
    Check(TextIs(Field(metadata, "capturedPayloadBytes"), "3"), "Captured length");
    Check(BoolIs(Field(metadata, "payloadTruncated"), true), "Truncated prefix");

    const auto& descriptor = Field(metadata, "descriptor"); // 原生值与规范事件枚举独立。
    Check(UIntIs(Field(descriptor, "id"), 15) && UIntIs(Field(descriptor, "task"), 15), "Descriptor ID and task");
    Check(UIntIs(Field(descriptor, "version"), 1) && UIntIs(Field(descriptor, "channel"), 2), "Descriptor version and channel");
    Check(UIntIs(Field(descriptor, "level"), 5) && UIntIs(Field(descriptor, "opcode"), 7), "Descriptor level and opcode");
    Check(TextIs(Field(descriptor, "keyword"), "18446744073709551615"), "Lossless descriptor keyword");

    const auto& file = Field(metadata, "file"); // 事件直接观察到的文件字段。
    Check(TextIs(Field(file, "path"), "C:\\test\\\xe6\x96\x87.txt"), "Owned UTF-8 path");
    Check(TextIs(Field(file, "fileObject"), "0"), "Known zero file object");
    Check(TextIs(Field(file, "fileKey"), "18446744073709551615"), "Lossless file key");
    Check(TextIs(Field(file, "irp"), "17"), "IRP hint");
    Check(TextIs(Field(file, "requestedBytes"), "0"), "Known zero request length");
    Check(TextIs(Field(file, "byteOffset"), "18446744073709551615"), "Lossless file offset");
    Check(file.find("ntStatus") == nullptr, "Request has no completion status");

    const auto& headerPid = Field(fields, "source.headerPid"); // 单独保存报头 PID。
    const auto& headerTid = Field(fields, "source.headerTid"); // 单独保存报头 TID。
    Check(TextIs(Field(headerPid, "type"), "u32") && TextIs(Field(headerPid, "state"), "known"), "Typed header PID");
    Check(UIntIs(Field(headerPid, "value"), 0) && UIntIs(Field(headerTid, "value"), 42), "Header PID/TID values");
    Check(fields.asObject()->size() == 4, "Only current catalog fields, no invented roles or producer sequence");
    const auto& sourceClock = Field(fields, "time.rawClock"); // FILETIME 使用 rawClock 对象。
    const auto& receiveClock = Field(metadata, "receiveClock"); // QPC 保留自己专用的身份与频率。
    const auto& receiveField = Field(fields, "time.receivedQpc"); // 规范字段只保存 tick。
    Check(WriteJson(sourceClock) == WriteJson(Field(metadata, "sourceClock")), "Source clock matches raw metadata");
    Check(TextIs(Field(sourceClock, "domain"), "filetime100ns") &&
          TextIs(Field(sourceClock, "value"), "134084736000000017"), "Lossless FILETIME source clock");
    Check(TextIs(Field(sourceClock, "clockId"), "source-clock") && sourceClock.find("frequencyHz") == nullptr,
          "Source clock identity");
    Check(TextIs(Field(receiveClock, "domain"), "qpc") && TextIs(Field(receiveClock, "clockId"), "receive-qpc"),
          "Independent QPC identity");
    Check(TextIs(Field(sourceClock, "bootId"), "test-boot") && TextIs(Field(receiveClock, "bootId"), "test-boot"),
          "Common boot identity");
    Check(TextIs(Field(receiveClock, "frequencyHz"), "10000000"), "QPC frequency");
    Check(TextIs(Field(receiveField, "type"), "u64") && TextIs(Field(receiveField, "state"), "known") &&
          TextIs(Field(receiveField, "value"), "0"), "Typed known zero QPC");
}

// 写请求与独立完成观察各自保留真实字段。相同 IRP 不触发跨条记录推断。
void WriteAndCompletion()
{
    auto write = Observation(16); // 无接收时钟的 Write 请求。
    write.pathUtf8 = "C:\\test\\notes.txt";
    write.irp = 42;
    write.requestedBytes = 12;
    const auto projectedWrite = Monitor::ProjectKernelFileObservation(write); // 独立写请求投影。
    Check(projectedWrite.evidence && projectedWrite.evidence->canonical.kind == Kind::WriteRequest, "Write kind");
    Check(!projectedWrite.evidence->canonical.receiveQpc &&
          !projectedWrite.evidence->canonical.fields.find("time.receivedQpc") &&
          !projectedWrite.evidence->raw.metadata.find("receiveClock"), "Absent receive clock");
    Check(BoolIs(Field(projectedWrite.evidence->raw.metadata, "payloadTruncated"), false), "Complete zero-byte payload");

    auto completion = Observation(24); // 来自另一个报头上下文的 OperationEnd。
    completion.headerPid = 4;
    completion.headerTid = 99;
    completion.irp = 42;
    completion.ntStatus = 0;
    const auto projected = Monitor::ProjectKernelFileObservation(completion); // 未配对的完成也保留。
    Check(projected.evidence && projected.evidence->canonical.kind == Kind::OperationEnd, "Completion kind");
    const auto& file = Field(projected.evidence->raw.metadata, "file"); // 此次完成本身的字段。
    Check(UIntIs(Field(file, "ntStatus"), 0), "Known zero completion status");
    Check(!file.find("path") && !file.find("requestedBytes"), "No fields inferred from an earlier request");
    Check(UIntIs(Field(Field(projected.evidence->canonical.fields, "source.headerPid"), "value"), 4), "Completion header context");
    completion.ntStatus.reset();
    const auto missing = Monitor::ProjectKernelFileObservation(completion); // 无状态字段的完成。
    Check(missing.evidence && !Field(missing.evidence->raw.metadata, "file").find("ntStatus"), "Missing completion status");
}

// 失败检查只认可精确的状态，错误观察不能生成半条证据。
void Reject(const Monitor::KernelFileObservationView& input, Status status, const char* label)
{
    const auto projected = Monitor::ProjectKernelFileObservation(input); // 检查的投影结果。
    Check(projected.status == status && !projected.evidence, label);
}

// 通过负控固定来源、描述符、时钟、字段和字节约束。
void InvalidObservations()
{
    auto input = Observation(15); // 每个负控从合成基线调整单独的字段。
    input.providerId = "90cbdc39-4a3e-11d1-84f4-0000f80464e3";
    Reject(input, Status::UnsupportedProvider, "Classic FileIO is a different provider");
    Reject(Observation(12), Status::UnsupportedEvent, "Create event outside this slice");
    input = Observation(15);
    input.descriptor.task = 24;
    Reject(input, Status::UnsupportedEvent, "Conflicting descriptor task");
    input = Observation(15);
    input.source.sourceEpoch = "D55B5F45-8F35-4CEA-83C4-C74C188DAAE2";
    Reject(input, Status::InvalidSource, "Noncanonical source epoch");
    input = Observation(15);
    input.source.bootId = {};
    Reject(input, Status::InvalidSource, "Absent source boot");
    input = Observation(15);
    input.receiveQpc = Monitor::KernelFileReceiveQpcView{"receive-qpc", 9, 0};
    Reject(input, Status::InvalidReceiveClock, "Zero QPC frequency");
    input.receiveQpc = Monitor::KernelFileReceiveQpcView{input.source.fileTimeClockId, 9, 10'000'000};
    Reject(input, Status::InvalidReceiveClock, "Clock identity conflation");

    const std::array<std::uint8_t, 1> bytes{0}; // 前缀不能超出申报的原始负载。
    input = Observation(15);
    input.payloadPrefix = bytes;
    Reject(input, Status::InvalidPayloadLength, "Prefix longer than original payload");
    input = Observation(15);
    input.pathUtf8 = "\xed\xa0\x80";
    Reject(input, Status::InvalidPath, "UTF-8 surrogate");
    input.pathUtf8 = "\xf4\x90\x80\x80";
    Reject(input, Status::InvalidPath, "UTF-8 scalar above Unicode limit");
    input.pathUtf8 = "\xf0\x9f\x8c";
    Reject(input, Status::InvalidPath, "Truncated UTF-8");
    input.pathUtf8 = std::string_view("a\0b", 3);
    Reject(input, Status::InvalidPath, "NUL in path");
    const std::string oversizedPath(65537, 'p'); // 超过 Stored 单字符串上限。
    input.pathUtf8 = oversizedPath;
    Reject(input, Status::InvalidPath, "Oversized path");
    input = Observation(24);
    input.requestedBytes = 0;
    Reject(input, Status::InvalidFileFields, "Completion carrying request length");
    input = Observation(16);
    input.ntStatus = 0;
    Reject(input, Status::InvalidFileFields, "Request carrying completion status");
}

} // namespace

// 默认运行内存向量。--live 另开自有 ETW 测试会话。
int main(int argc, char** argv)
{
    try {
        RequestRoundTrip();
        WriteAndCompletion();
        InvalidObservations();
        std::cout << "Kernel-File projection checks passed: " << checks << '\n';
        ValidatePassiveEtw(argc == 2 && std::string_view(argv[1]) == "--live");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
