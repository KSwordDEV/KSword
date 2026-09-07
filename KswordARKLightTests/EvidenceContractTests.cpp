// F 模块（现有能力复用与证据基础）的离线自动测试。
//
// 全部断言直接调用 shared/evidence 的生产实现，没有把实现复制进测试。
//
// 覆盖范围（照实写，不虚报）：
//   * 完整覆盖：F-03 F-04 F-05 F-06 F-08 F-11，以及 Q-12 的 JSON 不可信输入边界。
//   * 只覆盖纯策略部分：F-09 F-10 F-12。这三条的最终通过条件落在 UI / 会话行为上，
//     而本文件断言的判定函数（DecideNavigation / ResolveProcessNavigation /
//     DecideRefresh / LatestRequestGate / ValidateRange / EvaluateBudget /
//     BuildTrustStatement / Match* / fullyCovered / describeRemaining）在生产侧
//     目前**没有调用方** —— 唯一的生产接入点是 DriverDock.cpp 里的
//     toCollectionOutcome。接入层落地前，这里的绿灯只说明判据本身正确。

#include "TestSupport.h"

#include "../shared/evidence/EvidenceEnvelope.h"
#include "../shared/evidence/EvidenceJson.h"
#include "../shared/evidence/LiveNavigation.h"
#include "../shared/evidence/LosslessValue.h"
#include "../shared/evidence/ObjectIdentity.h"
#include "../shared/evidence/ScanBudget.h"

// F-05 归一层的生产实现（Qt 主程序 / Light / CLI 共用的驱动客户端里）。
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverEvidence.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

// IoResult::ntStatus 是 long；测试里的 NTSTATUS 常量按 32 位无符号写，转换集中在这里。
long AsNtStatus(std::uint32_t status) noexcept {
    return static_cast<long>(status);
}

// ---------------------------------------------------------------------------
// F-08：64 位数据不丢失
// ---------------------------------------------------------------------------
void TestLosslessValues(KswordTests::Suite& s) {
    constexpr std::uint64_t kAbove2p53 = 9007199254740993ULL;  // 2^53 + 1，double 无法表示
    constexpr std::uint64_t kMaxU64 = (std::numeric_limits<std::uint64_t>::max)();
    constexpr std::uint64_t kMaxCanonicalKernel = 0xFFFFFFFFFFFFFFFFULL;

    s.expect(FormatU64(kAbove2p53, U64Format::Decimal) == "9007199254740993",
             L"F-08 2^53+1 decimal is exact");

    std::uint64_t parsed = 0U;
    s.expect(ParseU64("9007199254740993", parsed) && parsed == kAbove2p53,
             L"F-08 2^53+1 round-trips through decimal text");

    s.expect(FormatU64(kMaxU64, U64Format::Decimal) == "18446744073709551615",
             L"F-08 max u64 decimal is exact");
    s.expect(ParseU64("18446744073709551615", parsed) && parsed == kMaxU64,
             L"F-08 max u64 parses back exactly");
    s.expect(!ParseU64("18446744073709551616", parsed),
             L"F-08 u64 overflow is rejected, not truncated");

    s.expect(FormatU64(0x00007FFE12340000ULL, U64Format::HexAddress) == "0x00007FFE12340000",
             L"F-08 address keeps a fixed 16-digit hex form");
    s.expect(ParseU64("0x00007FFE12340000", parsed) && parsed == 0x00007FFE12340000ULL,
             L"F-08 hex address round-trips");
    s.expect(FormatU64(kMaxCanonicalKernel, U64Format::HexAddress) == "0xFFFFFFFFFFFFFFFF",
             L"F-08 highest address formats without loss");

    // 空值不是 0
    OptionalU64 empty;
    s.expect(!empty.present && FormatOptionalU64(empty, U64Format::Decimal).empty(),
             L"F-08 unset optional formats to empty, not 0");
    OptionalU64 roundTripped = OptionalU64::of(7U);
    s.expect(ParseOptionalU64("", roundTripped) && !roundTripped.present,
             L"F-08 empty text parses back to unset, not 0");
    s.expect(ParseOptionalU64("0", roundTripped) && roundTripped.present && roundTripped.value == 0U,
             L"F-08 zero stays a present zero");
    s.expect(OptionalU64::of(0U) != OptionalU64::unset(),
             L"F-08 present-zero and unset are distinct values");

    std::int64_t signedValue = 0;
    s.expect(FormatI64((std::numeric_limits<std::int64_t>::min)()) == "-9223372036854775808" &&
                 ParseI64("-9223372036854775808", signedValue) &&
                 signedValue == (std::numeric_limits<std::int64_t>::min)(),
             L"F-08 int64 min round-trips without UB");
}

// ---------------------------------------------------------------------------
// F-08：JSON 往返；解析器绝不接受浮点
// ---------------------------------------------------------------------------
void TestJsonRoundTrip(KswordTests::Suite& s) {
    constexpr std::uint64_t kBig = 9007199254740993ULL;

    JsonObject members;
    members.emplace_back("address", JsonValue::makeU64Text(0xFFFFF80312345678ULL, U64Format::HexAddress));
    members.emplace_back("count", JsonValue::makeU64Text(kBig, U64Format::Decimal));
    members.emplace_back("missing", JsonValue::makeOptionalU64Text(OptionalU64::unset(), U64Format::Decimal));
    members.emplace_back("zero", JsonValue::makeOptionalU64Text(OptionalU64::of(0U), U64Format::Decimal));
    members.emplace_back("label", JsonValue::makeString("C:\\a\"b\\\nc"));
    const JsonValue document = JsonValue::makeObject(std::move(members));

    const std::string text = WriteJson(document);
    const JsonParseResult reparsed = ParseJson(text);
    s.expect(reparsed.ok(), L"F-08 evidence JSON reparses");

    std::uint64_t address = 0U;
    std::uint64_t count = 0U;
    OptionalU64 missing = OptionalU64::of(123U);
    OptionalU64 zero;
    std::string label;
    const JsonValue* addressNode = reparsed.value.find("address");
    const JsonValue* countNode = reparsed.value.find("count");
    const JsonValue* missingNode = reparsed.value.find("missing");
    const JsonValue* zeroNode = reparsed.value.find("zero");
    const JsonValue* labelNode = reparsed.value.find("label");
    s.expect(addressNode != nullptr && addressNode->tryGetU64(address) && address == 0xFFFFF80312345678ULL,
             L"F-08 kernel address survives JSON round-trip bit-for-bit");
    s.expect(countNode != nullptr && countNode->tryGetU64(count) && count == kBig,
             L"F-08 2^53+1 survives JSON round-trip");
    s.expect(missingNode != nullptr && missingNode->isNull() &&
                 missingNode->tryGetOptionalU64(missing) && !missing.present,
             L"F-08 null stays unset after import and never becomes 0");
    s.expect(zeroNode != nullptr && zeroNode->tryGetOptionalU64(zero) && zero.present && zero.value == 0U,
             L"F-08 explicit zero stays zero after import");
    s.expect(labelNode != nullptr && labelNode->tryGetString(label) && label == "C:\\a\"b\\\nc",
             L"F-08 escaped text round-trips exactly");

    // 浮点必须被显式拒绝，而不是悄悄降精度
    s.expect(ParseJson("{\"v\":9007199254740993.0}").status == JsonParseStatus::FloatingPointRejected,
             L"F-08 floating point numbers are rejected");
    s.expect(ParseJson("{\"v\":1e3}").status == JsonParseStatus::FloatingPointRejected,
             L"F-08 exponent form is rejected");

    // Q-12：不可信输入的边界
    s.expect(ParseJson("{\"a\":1,\"a\":2}").status == JsonParseStatus::DuplicateKey,
             L"Q-12 duplicate object keys are rejected, not silently overwritten");
    s.expect(ParseJson("{} trailing").status == JsonParseStatus::TrailingData,
             L"Q-12 trailing data is rejected");
    s.expect(ParseJson("").status == JsonParseStatus::Empty, L"Q-12 empty input is reported as empty");
    {
        JsonLimits shallow;
        shallow.maxDepth = 4;
        std::string deep;
        for (int i = 0; i < 40; ++i) {
            deep += "[";
        }
        for (int i = 0; i < 40; ++i) {
            deep += "]";
        }
        s.expect(ParseJson(deep, shallow).status == JsonParseStatus::DepthLimit,
                 L"Q-12 deep nesting hits the depth limit instead of recursing away");
    }
    s.expect(ParseJson("{\"v\":\"\x01\"}").status != JsonParseStatus::Ok,
             L"Q-12 raw control characters in strings are rejected");

    // F-08：数组与标量类型的往返（makeArray / asArray / tryGetI64 / tryGetBool）
    JsonArray items;
    items.push_back(JsonValue::makeInt(-9007199254740993LL));  // -(2^53+1)
    items.push_back(JsonValue::makeBool(true));
    items.push_back(JsonValue::makeBool(false));
    items.push_back(JsonValue::makeNull());
    items.push_back(JsonValue::makeUInt(kBig));
    const std::string arrayText = WriteJson(JsonValue::makeArray(std::move(items)));
    const JsonParseResult arrayBack = ParseJson(arrayText);
    const JsonArray* reparsedArray = arrayBack.ok() ? arrayBack.value.asArray() : nullptr;
    s.expect(reparsedArray != nullptr && reparsedArray->size() == 5U,
             L"F-08 a JSON array round-trips with its element count intact");
    if (reparsedArray != nullptr && reparsedArray->size() == 5U) {
        std::int64_t negative = 0;
        bool flagTrue = false;
        bool flagFalse = true;
        std::uint64_t big = 0U;
        s.expect((*reparsedArray)[0].tryGetI64(negative) && negative == -9007199254740993LL,
                 L"F-08 a negative value past 2^53 survives the array round-trip");
        s.expect((*reparsedArray)[1].tryGetBool(flagTrue) && flagTrue &&
                     (*reparsedArray)[2].tryGetBool(flagFalse) && !flagFalse,
                 L"F-08 booleans round-trip as booleans, not as 0/1");
        s.expect((*reparsedArray)[3].isNull() && !(*reparsedArray)[3].tryGetBool(flagTrue),
                 L"F-08 null in an array stays null and is not readable as a bool");
        s.expect((*reparsedArray)[4].tryGetU64(big) && big == kBig,
                 L"F-08 an unsigned value past 2^53 survives the array round-trip");
    }

    // F-07 / Q-12：节点上限按"个数"给管不住内存 —— 再按估算字节数卡一道。
    {
        std::string manyNodes("[");
        for (int i = 0; i < 6; ++i) {
            manyNodes += (i == 0) ? "1" : ",1";
        }
        manyNodes += "]";  // 1 个数组节点 + 6 个元素节点

        JsonLimits tinyNodeBytes;
        tinyNodeBytes.maxEstimatedNodeBytes = 1U;  // 连一个 JsonValue 都放不下
        s.expect(ParseJson(manyNodes, tinyNodeBytes).status == JsonParseStatus::SizeLimit,
                 L"F-07 a node-memory budget smaller than one node reports SizeLimit, not Ok");

        JsonLimits roomyNodeBytes;
        roomyNodeBytes.maxEstimatedNodeBytes = 16U * 1024U * 1024U;
        s.expect(ParseJson(manyNodes, roomyNodeBytes).ok(),
                 L"F-07 the same input parses once the node-memory budget is raised");
    }

    // Q-12：输入总字节上限。
    {
        JsonLimits tinyInput;
        tinyInput.maxTotalBytes = 4U;
        s.expect(ParseJson("[1,2]", tinyInput).status == JsonParseStatus::SizeLimit,
                 L"Q-12 input larger than maxTotalBytes is refused before parsing");
        s.expect(ParseJson("[1]", tinyInput).ok(),
                 L"Q-12 input inside maxTotalBytes still parses");
    }

    // Q-12：默认节点上限对超大扁平数组生效（避免几 MB 输入撑出几百 MB 常驻）。
    {
        std::string wide("[0");
        wide.reserve(1300000U);
        for (int i = 0; i < 600000; ++i) {
            wide += ",0";
        }
        wide += "]";
        s.expect(ParseJson(wide).status == JsonParseStatus::NodeLimit,
                 L"F-07 600k array elements exceed the default node budget instead of being accepted");
    }

    // Q-12：重复键检测必须是均摊 O(1)。旧实现按成员数线性扫，128,000 个成员实测
    // 15.3 秒，按默认成员上限外推约 17 分钟 —— 导入侧的一条 DoS 通道。
    // 这里用 200,000 个合法成员钉住：O(n²) 实现跑不完这个时限。
    {
        std::string wideObject("{");
        wideObject.reserve(4000000U);
        for (int i = 0; i < 200000; ++i) {
            if (i != 0) {
                wideObject += ',';
            }
            wideObject += "\"k";
            wideObject += std::to_string(i);
            wideObject += "\":1";
        }
        wideObject += '}';

        const auto started = std::chrono::steady_clock::now();
        const JsonParseResult wideResult = ParseJson(wideObject);
        const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now() - started)
                                   .count();
        s.expect(wideResult.ok(), L"Q-12 a 200k-member object is accepted, not rejected outright");
        s.expect(elapsedMs < 2000,
                 L"Q-12 duplicate-key detection stays near-linear on a 200k-member object");

        // 同样规模下的重复键仍然必须被抓住。
        std::string duplicated = wideObject;
        duplicated.pop_back();
        duplicated += ",\"k0\":2}";
        s.expect(ParseJson(duplicated).status == JsonParseStatus::DuplicateKey,
                 L"Q-12 the fast duplicate-key index still rejects a late duplicate");
    }
}

// ---------------------------------------------------------------------------
// F-03：稳定对象身份
// ---------------------------------------------------------------------------
void TestObjectIdentity(KswordTests::Suite& s) {
    ProcessInstanceId first;
    first.bootId = "boot-A";
    first.pid = OptionalU64::of(4321U);
    first.createTime100ns = OptionalU64::of(133000000000000000ULL);
    first.eprocessAddress = OptionalU64::of(0xFFFFA00112340000ULL);
    first.imageName = "target.exe";

    ProcessInstanceId sameAgain = first;
    ProcessInstanceId pidReused = first;
    pidReused.createTime100ns = OptionalU64::of(133000000099999999ULL);
    pidReused.eprocessAddress = OptionalU64::of(0xFFFFA00112340000ULL);  // 地址复用

    ProcessInstanceId otherBoot = first;
    otherBoot.bootId = "boot-B";

    ProcessInstanceId noCreateTime = first;
    noCreateTime.createTime100ns = OptionalU64::unset();

    s.expect(MatchProcessInstance(first, sameAgain) == MatchResult::Confirmed,
             L"F-03 identical process instance confirms");
    s.expect(MatchProcessInstance(first, pidReused) == MatchResult::NoMatch,
             L"F-03 same PID + different creation time is a different instance");
    s.expect(MatchProcessInstance(first, otherBoot) == MatchResult::NoMatch,
             L"F-03 same PID across boots is a different instance");
    s.expect(MatchProcessInstance(first, noCreateTime) == MatchResult::Candidate,
             L"F-03 missing creation time stays a candidate and is never auto-merged");
    s.expect(noCreateTime.strength() == IdentityStrength::Weak && noCreateTime.crossSessionKey().empty(),
             L"F-03 weak process identity yields no cross-session key");
    s.expect(first.crossSessionKey() != pidReused.crossSessionKey(),
             L"F-03 PID reuse produces distinct cross-session keys");

    // 地址相同但对象不同
    ProcessInstanceId addressTwin;
    addressTwin.bootId = "boot-A";
    addressTwin.pid = OptionalU64::of(9999U);
    addressTwin.createTime100ns = OptionalU64::of(133000000000000000ULL);
    addressTwin.eprocessAddress = first.eprocessAddress;
    s.expect(MatchProcessInstance(first, addressTwin) == MatchResult::NoMatch,
             L"F-03 same address different PID is not the same object");

    // 线程绑定进程实例
    ThreadInstanceId thread;
    thread.process = first;
    thread.tid = OptionalU64::of(777U);
    thread.createTime100ns = OptionalU64::of(133000000000500000ULL);

    ThreadInstanceId threadOnReusedPid = thread;
    threadOnReusedPid.process = pidReused;
    s.expect(MatchThreadInstance(thread, threadOnReusedPid) == MatchResult::NoMatch,
             L"F-03 thread does not attach to a new process on a reused PID");

    ThreadInstanceId tidReuse = thread;
    tidReuse.createTime100ns = OptionalU64::of(133000000900000000ULL);
    s.expect(MatchThreadInstance(thread, tidReuse) == MatchResult::NoMatch,
             L"F-03 TID reuse is a different thread instance");

    ThreadInstanceId threadNoCreate = thread;
    threadNoCreate.createTime100ns = OptionalU64::unset();
    s.expect(MatchThreadInstance(thread, threadNoCreate) == MatchResult::Candidate &&
                 threadNoCreate.crossSessionKey().empty(),
             L"F-03 thread without creation stamp stays a candidate");

    // 同路径不同文件
    FileIdentity fileA;
    fileA.path = "C:\\Windows\\System32\\drivers\\test.sys";
    fileA.volumeSerial = OptionalU64::of(0x1234ABCDULL);
    fileA.fileId = "0x0000000000000000000200000000AAAA";
    FileIdentity fileB = fileA;
    fileB.fileId = "0x0000000000000000000200000000BBBB";
    s.expect(MatchFileIdentity(fileA, fileB) == MatchResult::NoMatch,
             L"F-03 same path different file id is a different file");
    FileIdentity pathOnly;
    pathOnly.path = fileA.path;
    s.expect(MatchFileIdentity(fileA, pathOnly) == MatchResult::Candidate &&
                 pathOnly.crossSessionKey().empty(),
             L"F-03 path alone is not a cross-session file key");

    // F-03：同哈希异路径是"同样的字节"，不是"同一个文件对象"。
    // System32 下的正版驱动 vs 被投放到用户目录的同字节副本。
    FileIdentity systemCopy;
    systemCopy.path = "C:\\Windows\\System32\\drivers\\good.sys";
    systemCopy.contentHash = "sha256:AA";
    FileIdentity droppedCopy;
    droppedCopy.path = "C:\\Users\\Public\\dropped_copy.sys";
    droppedCopy.contentHash = "sha256:AA";
    s.expect(MatchFileIdentity(systemCopy, droppedCopy) == MatchResult::Candidate,
             L"F-03 the same content at two different paths is a candidate, never one file");
    s.expect(!systemCopy.crossSessionKey().empty() && !droppedCopy.crossSessionKey().empty() &&
                 systemCopy.crossSessionKey() != droppedCopy.crossSessionKey(),
             L"F-03 two paths holding identical bytes get two different cross-session keys");
    FileIdentity caseVariant = systemCopy;
    caseVariant.path = "c:/windows/system32/drivers/good.sys";
    s.expect(caseVariant.crossSessionKey() == systemCopy.crossSessionKey(),
             L"F-03 the content key normalises case and separators so one file keeps one key");

    // 硬链接：两条路径共享 (volumeSerial, fileId)，那才是同一个文件对象。
    FileIdentity linkedA;
    linkedA.path = "C:\\Windows\\System32\\drivers\\linked.sys";
    linkedA.volumeSerial = OptionalU64::of(0x1234ABCDULL);
    linkedA.fileId = "0x0000000000000000000200000000CCCC";
    FileIdentity linkedB = linkedA;
    linkedB.path = "C:\\Windows\\System32\\drivers\\other-name.sys";
    s.expect(MatchFileIdentity(linkedA, linkedB) == MatchResult::Confirmed &&
                 linkedA.crossSessionKey() == linkedB.crossSessionKey(),
             L"F-03 a shared volume+fileId still confirms one object across two paths");

    // 相同五元组不同时段
    ConnectionIdentity connEarly;
    connEarly.bootId = "boot-A";
    connEarly.protocol = 6U;
    connEarly.localAddress = "127.0.0.1";
    connEarly.localPort = 50001U;
    connEarly.remoteAddress = "127.0.0.1";
    connEarly.remotePort = 9;
    connEarly.observedFirstUtc100ns = OptionalU64::of(1000U);
    connEarly.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity connLate = connEarly;
    connLate.observedFirstUtc100ns = OptionalU64::of(5000U);
    connLate.observedLastUtc100ns = OptionalU64::of(6000U);
    s.expect(connEarly.fiveTupleKey() == connLate.fiveTupleKey(),
             L"F-03 the two connections share a five-tuple");
    s.expect(MatchConnectionIdentity(connEarly, connLate) == MatchResult::NoMatch,
             L"F-03 same five-tuple in disjoint windows is a different connection");
    ConnectionIdentity connNoWindow = connEarly;
    connNoWindow.observedFirstUtc100ns = OptionalU64::unset();
    connNoWindow.observedLastUtc100ns = OptionalU64::unset();
    s.expect(MatchConnectionIdentity(connEarly, connNoWindow) == MatchResult::Candidate,
             L"F-03 connection without an observation window stays a candidate");

    // F-03：缺 bootId 时跨启动保护不得被绕过。两侧都为空是"缺失"，不是"相同"。
    ConnectionIdentity noBootA = connEarly;
    noBootA.bootId.clear();
    noBootA.observedFirstUtc100ns = OptionalU64::of(1000U);
    noBootA.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity noBootB = noBootA;
    noBootB.observedFirstUtc100ns = OptionalU64::of(1500U);
    noBootB.observedLastUtc100ns = OptionalU64::of(2500U);
    s.expect(MatchConnectionIdentity(noBootA, noBootB) == MatchResult::Candidate,
             L"F-03 overlapping windows without any boot id cannot confirm one connection");
    s.expect(noBootA.crossSessionKey().empty(),
             L"F-03 a connection without a boot id gets no cross-session key");

    // 有 bootId、区间相交，但所属进程完全未知：端口会被下一个进程重新绑上。
    ConnectionIdentity overlapA = connEarly;
    overlapA.observedFirstUtc100ns = OptionalU64::of(1000U);
    overlapA.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity overlapB = overlapA;
    overlapB.observedFirstUtc100ns = OptionalU64::of(1500U);
    overlapB.observedLastUtc100ns = OptionalU64::of(2500U);
    s.expect(MatchConnectionIdentity(overlapA, overlapB) == MatchResult::Candidate,
             L"F-03 an unknown owning process holds an overlapping connection at candidate");

    ConnectionIdentity ownedA = overlapA;
    ownedA.owner = first;
    ConnectionIdentity ownedB = overlapB;
    ownedB.owner = first;
    s.expect(MatchConnectionIdentity(ownedA, ownedB) == MatchResult::Confirmed,
             L"F-03 same boot + overlapping window + confirmed owner does confirm one connection");

    // 驱动：同名异版不得混为一谈
    DriverInstanceId loaded;
    loaded.bootId = "boot-A";
    loaded.imagePath = "C:\\Windows\\System32\\drivers\\ksword.sys";
    loaded.timeDateStamp = OptionalU64::of(0x65000000ULL);
    loaded.imageSize = OptionalU64::of(0x30000ULL);
    loaded.pdbSignature = "GUID-1/1";
    DriverInstanceId otherVersion = loaded;
    otherVersion.pdbSignature = "GUID-2/1";
    s.expect(MatchDriverInstance(loaded, otherVersion) == MatchResult::NoMatch,
             L"I-01 same driver path with a different PDB identity is a different image");

    // F-03：身份不足（R0 枚举拿不到镜像路径：unbacked / 已卸载 / 路径被抹）时，
    // 剩下的 stamp+size 不足以确认。strength()/crossSessionKey() 说"不给主键"，
    // matcher 就不能说"确定是同一个"。
    DriverInstanceId stampOnly;
    stampOnly.timeDateStamp = OptionalU64::of(0x65000000ULL);
    stampOnly.imageSize = OptionalU64::of(0x30000ULL);
    const DriverInstanceId stampOnlyTwin = stampOnly;
    s.expect(stampOnly.strength() == IdentityStrength::Unusable &&
                 stampOnly.crossSessionKey().empty(),
             L"F-03 timestamp+size without a path or PDB is an unusable driver identity");
    s.expect(MatchDriverInstance(stampOnly, stampOnlyTwin) == MatchResult::Candidate,
             L"F-03 an unusable driver identity can never confirm, only stay a candidate");

    // 单调性：补上信息不得让结论变强又变弱。路径相同 -> Confirmed；
    // 路径不同但映像身份一致 -> Candidate；两者都比"什么都没有"更明确。
    DriverInstanceId pathedA = stampOnly;
    pathedA.imagePath = "C:\\Windows\\System32\\drivers\\a.sys";
    DriverInstanceId pathedSame = pathedA;
    DriverInstanceId pathedB = stampOnly;
    pathedB.imagePath = "C:\\Users\\Public\\a.sys";
    s.expect(MatchDriverInstance(pathedA, pathedSame) == MatchResult::Confirmed,
             L"F-03 timestamp+size confirm once both sides carry the same image path");
    s.expect(MatchDriverInstance(pathedA, pathedB) == MatchResult::Candidate,
             L"F-03 the same image identity at two paths is a candidate copy, not a mismatch");

    // 通用不变式：任一侧身份不可用时，六个 Match* 一个都不许给 Confirmed。
    const ProcessInstanceId noPid{};               // pid 缺失 -> Unusable
    const ThreadInstanceId noTid{};                // tid 缺失 -> Unusable
    const FileIdentity nothingKnown{};             // 三个字段全空 -> Unusable
    const HandleIdentity noHandle{};               // handleValue 缺失 -> Unusable
    const ConnectionIdentity noProtocol{};         // 地址/协议缺失 -> Unusable
    s.expect(noPid.strength() == IdentityStrength::Unusable &&
                 noTid.strength() == IdentityStrength::Unusable &&
                 nothingKnown.strength() == IdentityStrength::Unusable &&
                 noHandle.strength() == IdentityStrength::Unusable &&
                 noProtocol.strength() == IdentityStrength::Unusable,
             L"F-03 the five empty identities all report as unusable");
    s.expect(MatchProcessInstance(noPid, noPid) != MatchResult::Confirmed &&
                 MatchThreadInstance(noTid, noTid) != MatchResult::Confirmed &&
                 MatchDriverInstance(stampOnly, stampOnlyTwin) != MatchResult::Confirmed &&
                 MatchFileIdentity(nothingKnown, nothingKnown) != MatchResult::Confirmed &&
                 MatchHandleIdentity(noHandle, noHandle) != MatchResult::Confirmed &&
                 MatchConnectionIdentity(noProtocol, noProtocol) != MatchResult::Confirmed,
             L"F-03 no matcher confirms when either side's identity is unusable");

    // 句柄
    HandleIdentity handle;
    handle.owner = first;
    handle.handleValue = OptionalU64::of(0x1F0ULL);
    handle.objectAddress = OptionalU64::of(0xFFFFA00155550000ULL);
    handle.typeName = "File";
    HandleIdentity recycled = handle;
    recycled.objectAddress = OptionalU64::of(0xFFFFA00166660000ULL);
    s.expect(MatchHandleIdentity(handle, recycled) == MatchResult::Candidate,
             L"F-03 recycled handle value on a different object is not confirmed");
    HandleIdentity foreign = handle;
    foreign.owner = pidReused;
    s.expect(MatchHandleIdentity(handle, foreign) == MatchResult::NoMatch,
             L"F-03 handle value is scoped to its owning process instance");
}

// ---------------------------------------------------------------------------
// F-04：来源和时间
// ---------------------------------------------------------------------------
void TestSourceAndTime(KswordTests::Suite& s) {
    CaptureWindow bootA;
    bootA.machineId = "machine-1";
    bootA.bootId = "boot-A";
    bootA.monotonicFrequency = OptionalU64::of(10000000ULL);  // 10 MHz QPC
    CaptureWindow bootB = bootA;
    bootB.bootId = "boot-B";

    s.expect(MonotonicComparable(bootA, bootA), L"F-04 same boot monotonic values compare");
    s.expect(!MonotonicComparable(bootA, bootB),
             L"F-04 monotonic values from two boot cycles are not comparable");

    std::int64_t nanos = 0;
    s.expect(MonotonicDeltaNanos(bootA, 1000ULL, 1000ULL + 10000000ULL, nanos) && nanos == 1000000000LL,
             L"F-04 monotonic delta converts to nanoseconds without floating point");
    CaptureWindow noFrequency = bootA;
    noFrequency.monotonicFrequency = OptionalU64::unset();
    s.expect(!MonotonicDeltaNanos(noFrequency, 0ULL, 1ULL, nanos),
             L"F-04 missing QPC frequency refuses to produce a duration");
    CaptureWindow noBoot = bootA;
    noBoot.bootId.clear();
    s.expect(!MonotonicDeltaNanos(noBoot, 0ULL, 1ULL, nanos),
             L"F-04 raw QPC without a boot identity cannot be subtracted");
}

// ---------------------------------------------------------------------------
// F-05 / F-06：可用性与结论分离、不完整采集的账目
// ---------------------------------------------------------------------------
void TestStatusAndCoverage(KswordTests::Suite& s) {
    // 成功的空集合：账目必须显式写"总数 0、成功 0"，那才是一次真的看全了的枚举。
    EvidenceEnvelope emptyButSuccessful;
    emptyButSuccessful.outcome = CollectionOutcome::success();
    emptyButSuccessful.coverage.totalKnown = OptionalU64::of(0U);
    emptyButSuccessful.coverage.succeeded = 0U;
    s.expect(emptyButSuccessful.coverage.fullyCovered() &&
                 emptyButSuccessful.deriveConclusion(false) == AnalysisConclusion::NoDifferenceObserved,
             L"F-05 a correct empty result with a declared total of 0 is an observation, not a failure");

    // F-06 / BLOCKER：空账目不是完整覆盖。忘了填账目的采集方不许白得一个
    // "100% 完整扫描 + 未发现差异"。
    const CoverageAccount blank{};
    s.expect(!blank.fullyCovered(),
             L"F-06 a blank coverage account is unknown coverage, never full coverage");
    s.expect(blank.describeRemaining() == "remaining:unknown",
             L"F-06 a blank coverage account reports its remainder as unknown");
    EvidenceEnvelope successNoAccount;
    successNoAccount.outcome = CollectionOutcome::success();
    s.expect(successNoAccount.deriveConclusion(false) == AnalysisConclusion::Indeterminate,
             L"F-05 success without any coverage account cannot claim no-difference");

    // F-06：范围口径 —— 请求 [0x1000,0x9000) 只处理到 0x2000。
    EvidenceEnvelope shortRange;
    shortRange.outcome = CollectionOutcome::success();
    shortRange.coverage.requestedBegin = OptionalU64::of(0x1000ULL);
    shortRange.coverage.requestedEnd = OptionalU64::of(0x9000ULL);
    shortRange.coverage.processedBegin = OptionalU64::of(0x1000ULL);
    shortRange.coverage.processedEnd = OptionalU64::of(0x2000ULL);
    s.expect(!shortRange.coverage.fullyCovered(),
             L"F-06 a request range wider than the processed range is not fully covered");
    s.expect(shortRange.deriveConclusion(false) == AnalysisConclusion::Indeterminate,
             L"F-05 a Success status with a short-processed range still cannot say no-difference");
    s.expect(shortRange.coverage.describeRemaining() == "remaining-range:28672",
             L"F-06 the unprocessed tail is reported as an exact remainder");

    // 端点残缺：只有 begin 而没有 end 时，末尾边界无从校验 -> 不完整。
    CoverageAccount halfEndpoints;
    halfEndpoints.requestedBegin = OptionalU64::of(0x1000ULL);
    halfEndpoints.processedBegin = OptionalU64::of(0x1000ULL);
    s.expect(!halfEndpoints.fullyCovered(),
             L"F-06 a range with only begin endpoints cannot claim full coverage");

    // 四个端点齐全且处理范围盖住请求范围：这才是范围口径下的完整覆盖。
    CoverageAccount wholeRange;
    wholeRange.requestedBegin = OptionalU64::of(0x1000ULL);
    wholeRange.requestedEnd = OptionalU64::of(0x2000ULL);
    wholeRange.processedBegin = OptionalU64::of(0x1000ULL);
    wholeRange.processedEnd = OptionalU64::of(0x2000ULL);
    s.expect(wholeRange.fullyCovered() && wholeRange.describeRemaining() == "remaining-range:0",
             L"F-06 a fully processed range is complete and reports a zero remainder");

    // F-06：truncated / skipped 单独就足以否定完整覆盖，且必须把结论压回 Indeterminate。
    EvidenceEnvelope truncatedRun;
    truncatedRun.outcome = CollectionOutcome::success();
    truncatedRun.coverage.totalKnown = OptionalU64::of(10U);
    truncatedRun.coverage.succeeded = 10U;
    truncatedRun.coverage.truncated = 3U;
    s.expect(!truncatedRun.coverage.fullyCovered(),
             L"F-06 truncated items block the fully-covered claim");
    s.expect(truncatedRun.deriveConclusion(false) == AnalysisConclusion::Indeterminate,
             L"F-05 a truncated success cannot be upgraded to no-difference");
    s.expect(truncatedRun.coverage.describeRemaining() == "truncated:3",
             L"F-06 truncation is named as the reason instead of reporting remaining:0");

    EvidenceEnvelope skippedRun;
    skippedRun.outcome = CollectionOutcome::success();
    skippedRun.coverage.totalKnown = OptionalU64::of(10U);
    skippedRun.coverage.succeeded = 9U;
    skippedRun.coverage.skipped = 1U;
    s.expect(!skippedRun.coverage.fullyCovered(),
             L"F-06 a skipped item blocks the fully-covered claim");
    s.expect(skippedRun.deriveConclusion(false) == AnalysisConclusion::Indeterminate,
             L"F-05 a success with a skipped item cannot be upgraded to no-difference");
    s.expect(skippedRun.coverage.describeRemaining() == "incomplete:failed=0,skipped=1",
             L"F-06 a count that adds up but hides a skip is reported as incomplete");

    EvidenceEnvelope interfaceFailure;
    interfaceFailure.outcome = CollectionOutcome::failure(CollectionStatus::Error, "NTSTATUS",
                                                          0xC0000001ULL, "STATUS_UNSUCCESSFUL");
    s.expect(interfaceFailure.deriveConclusion(false) == AnalysisConclusion::NoEvidence,
             L"F-05 a failed collector never yields a normal conclusion");
    s.expect(interfaceFailure.outcome.nativeCode.present &&
                 interfaceFailure.outcome.nativeCode.value == 0xC0000001ULL &&
                 interfaceFailure.outcome.nativeCodeDomain == "NTSTATUS" &&
                 !interfaceFailure.outcome.message.empty(),
             L"F-05 the raw error code and message are preserved");

    EvidenceEnvelope halfReturned;
    halfReturned.outcome.status = CollectionStatus::Partial;
    halfReturned.coverage.succeeded = 50U;
    halfReturned.coverage.totalKnown = OptionalU64::of(100U);
    s.expect(halfReturned.deriveConclusion(false) == AnalysisConclusion::Indeterminate,
             L"F-05 a half-covered scan cannot conclude no-difference");
    s.expect(halfReturned.deriveConclusion(true) == AnalysisConclusion::DifferenceObserved,
             L"F-05 a partial scan can still report a difference it did observe");
    s.expect(halfReturned.coverage.describeRemaining() == "remaining:50",
             L"F-06 remaining count is derived from the declared total");

    EvidenceEnvelope notStarted;
    s.expect(notStarted.outcome.status == CollectionStatus::NotCollected &&
                 notStarted.deriveConclusion(false) == AnalysisConclusion::NoEvidence,
             L"F-05 a collector that never ran is not a normal result");

    EvidenceEnvelope denied;
    denied.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5ULL,
                                                "ERROR_ACCESS_DENIED");
    s.expect(denied.deriveConclusion(false) == AnalysisConclusion::NoEvidence &&
                 !StatusCarriesObservation(denied.outcome.status),
             L"F-05 access denied is distinguishable from an empty success");

    EvidenceEnvelope unsupported;
    unsupported.outcome.status = CollectionStatus::Unsupported;
    s.expect(std::string(CollectionStatusName(unsupported.outcome.status)) == "Unsupported" &&
                 std::string(CollectionStatusName(denied.outcome.status)) == "AccessDenied" &&
                 std::string(CollectionStatusName(emptyButSuccessful.outcome.status)) == "Success" &&
                 std::string(CollectionStatusName(halfReturned.outcome.status)) == "Partial" &&
                 std::string(CollectionStatusName(notStarted.outcome.status)) == "NotCollected",
             L"F-05 all five availability states export as distinct names");

    // F-06：总数未知不得用已返回数量冒充
    CoverageAccount unknownTotal;
    unknownTotal.succeeded = 128U;
    s.expect(!unknownTotal.totalKnown.present &&
                 unknownTotal.describeRemaining() == "remaining:unknown",
             L"F-06 an unknown total is reported as unknown, not as the returned count");

    CoverageAccount limited;
    limited.limitHit = true;
    limited.limit = OptionalU64::of(4096U);
    limited.succeeded = 4096U;
    s.expect(!limited.fullyCovered() && limited.describeRemaining() == "limit-hit:4096",
             L"F-06 hitting the cap never reports a 100% complete scan");

    // F-06：某一项计数来源未知时，failed/skipped 里的 0 只是"没数到"而不是"没发生"。
    // 上一轮 T 模块的评审实测到：来源只报总计时，未知项被按 0 汇总，账目看着精确、
    // 实际是下界。countsIncomplete 把这件事变成一个显式状态。
    CoverageAccount unknownCounts;
    unknownCounts.totalKnown = OptionalU64::of(10U);
    unknownCounts.succeeded = 10U;
    s.expect(unknownCounts.fullyCovered(),
             L"F-06 a fully reconciled count basis is complete when every counter is known");
    unknownCounts.countsIncomplete = true;
    s.expect(!unknownCounts.fullyCovered(),
             L"F-06 an unknown counter source blocks the fully-covered claim even when the numbers add up");
    s.expect(unknownCounts.describeRemaining() == "counts-incomplete",
             L"F-06 an unknown counter source is reported as such, not as a precise remaining count");

    CoverageAccount withFailures;
    withFailures.succeeded = 10U;
    withFailures.failed = 1U;
    withFailures.totalKnown = OptionalU64::of(11U);
    s.expect(!withFailures.fullyCovered(),
             L"F-06 a single item failure blocks the fully-covered claim");
    s.expect(withFailures.describeRemaining() == "incomplete:failed=1,skipped=0",
             L"F-06 a failed item is named rather than folded into remaining:0");

    // F-06 一致性不变式：fullyCovered() 为真时，describeRemaining() 不得说"未知"。
    // 两个方法必须给出同一套说法 —— 早先"空账目 = 完整覆盖 + 剩余未知"就是同时
    // 说出了这两句互相矛盾的话。
    CoverageAccount countComplete;
    countComplete.totalKnown = OptionalU64::of(3U);
    countComplete.succeeded = 3U;
    const CoverageAccount samples[] = {blank,          halfEndpoints, wholeRange,
                                       countComplete,  withFailures,  limited,
                                       unknownTotal,   truncatedRun.coverage,
                                       skippedRun.coverage, shortRange.coverage,
                                       emptyButSuccessful.coverage};
    bool invariantHolds = true;
    for (const CoverageAccount& account : samples) {
        if (account.fullyCovered() && account.describeRemaining() == "remaining:unknown") {
            invariantHolds = false;
        }
    }
    s.expect(invariantHolds,
             L"F-06 fully-covered and remaining:unknown can never be reported together");
    s.expect(countComplete.fullyCovered() && countComplete.describeRemaining() == "remaining:0",
             L"F-06 a declared total that was fully processed is complete with a zero remainder");
}

// ---------------------------------------------------------------------------
// F-11：来源可信度边界
// ---------------------------------------------------------------------------
void TestTrustBoundary(KswordTests::Suite& s) {
    EvidenceEnvelope wrapperOne;
    wrapperOne.source.collectorId = "ui.processTable";
    wrapperOne.source.sourceGroup = "r0.process.enum";
    wrapperOne.source.origin = SourceOrigin::LiveKernel;
    wrapperOne.outcome.status = CollectionStatus::Partial;  // 同一份不完整数据

    EvidenceEnvelope wrapperTwo = wrapperOne;
    wrapperTwo.source.collectorId = "api.processList";  // 同一底层 collector 的第二层包装

    EvidenceEnvelope thirdWrapper = wrapperOne;
    thirdWrapper.source.collectorId = "cli.processDump";

    const TrustStatement statement = BuildTrustStatement({wrapperOne, wrapperTwo, thirdWrapper});
    s.expect(statement.viewCount == 3U && statement.independentSourceGroupCount == 1U,
             L"X-01 three wrappers over one collector count as one independent source group");
    s.expect(statement.allFromSameLiveKernel && statement.anyIncompleteCoverage,
             L"F-11 the trust statement records same-kernel origin and incomplete coverage");

    bool hasAbsenceLimit = false;
    bool hasSingleGroupLimit = false;
    for (const std::string& key : statement.limitationKeys) {
        if (key == "trust.limitation.noAbsenceProof") {
            hasAbsenceLimit = true;
        }
        if (key == "trust.limitation.singleSourceGroup") {
            hasSingleGroupLimit = true;
        }
    }
    s.expect(hasAbsenceLimit && hasSingleGroupLimit,
             L"F-11 agreement across same-source views is reported as a limitation, never as safety");

    EvidenceEnvelope independent = wrapperOne;
    independent.source.collectorId = "r3.toolhelp";
    independent.source.sourceGroup = "r3.toolhelp.snapshot";
    independent.source.origin = SourceOrigin::LiveUserMode;
    const TrustStatement mixed = BuildTrustStatement({wrapperOne, independent});
    s.expect(mixed.independentSourceGroupCount == 2U && !mixed.allFromSameLiveKernel,
             L"X-01 a genuinely different source raises the independent group count");

    // F-11：三类来源必须各自可见。allFromSameLiveKernel 为 false 时，剩下那一半
    // 到底是外部文件还是离线样本，不能在结构体里彻底消失。
    EvidenceEnvelope liveKernel;
    liveKernel.source.collectorId = "r0.module.enum";
    liveKernel.source.sourceGroup = "r0.module.enum";
    liveKernel.source.origin = SourceOrigin::LiveKernel;
    liveKernel.outcome = CollectionOutcome::success();
    liveKernel.coverage.totalKnown = OptionalU64::of(0U);

    EvidenceEnvelope offline = liveKernel;
    offline.source.collectorId = "session.replay";
    offline.source.sourceGroup = "session.replay";
    offline.source.origin = SourceOrigin::OfflineSample;

    EvidenceEnvelope external = liveKernel;
    external.source.collectorId = "disk.image";
    external.source.sourceGroup = "disk.image";
    external.source.origin = SourceOrigin::ExternalFile;

    const TrustStatement offlineMix = BuildTrustStatement({offline, liveKernel});
    s.expect(offlineMix.offlineSampleViewCount == 1U && offlineMix.liveKernelViewCount == 1U &&
                 offlineMix.distinctOriginCount == 2U && !offlineMix.allFromSameLiveKernel,
             L"F-11 a half-offline conclusion counts both origins instead of hiding one");
    s.expect(offlineMix.originViewCount(SourceOrigin::OfflineSample) == 1U &&
                 offlineMix.originViewCount(SourceOrigin::ExternalFile) == 0U,
             L"F-11 per-origin counts are readable by kind");

    bool hasOfflineLimit = false;
    for (const std::string& key : offlineMix.limitationKeys) {
        if (key == "trust.limitation.offlineSample") {
            hasOfflineLimit = true;
        }
    }
    s.expect(hasOfflineLimit,
             L"F-11 mixing an offline sample into a conclusion is stated as a limitation");

    const TrustStatement externalMix = BuildTrustStatement({external, liveKernel});
    bool hasExternalLimit = false;
    for (const std::string& key : externalMix.limitationKeys) {
        if (key == "trust.limitation.externalFile") {
            hasExternalLimit = true;
        }
    }
    s.expect(hasExternalLimit && externalMix.externalFileViewCount == 1U,
             L"F-11 an external file view is stated as a limitation of its own");

    const TrustStatement kernelOnly = BuildTrustStatement({liveKernel});
    bool kernelOnlyClaimsOffline = false;
    for (const std::string& key : kernelOnly.limitationKeys) {
        if (key == "trust.limitation.offlineSample" || key == "trust.limitation.externalFile") {
            kernelOnlyClaimsOffline = true;
        }
    }
    s.expect(!kernelOnlyClaimsOffline && kernelOnly.liveKernelViewCount == 1U &&
                 kernelOnly.distinctOriginCount == 1U,
             L"F-11 a purely live-kernel statement does not invent offline limitations");

    // F-04：来源类别与采集方式各自导出为独立名字。
    s.expect(std::string(SourceOriginName(SourceOrigin::ExternalFile)) == "ExternalFile" &&
                 std::string(SourceOriginName(SourceOrigin::OfflineSample)) == "OfflineSample" &&
                 std::string(SourceOriginName(SourceOrigin::LiveKernel)) == "LiveKernel" &&
                 std::string(SourceOriginName(SourceOrigin::LiveUserMode)) == "LiveUserMode" &&
                 std::string(SourceOriginName(SourceOrigin::Unknown)) == "Unknown",
             L"F-11 all five source origins export as distinct names");
    s.expect(std::string(CaptureModeName(CaptureMode::Unknown)) == "Unknown" &&
                 std::string(CaptureModeName(CaptureMode::Snapshot)) == "Snapshot" &&
                 std::string(CaptureModeName(CaptureMode::Streaming)) == "Streaming" &&
                 std::string(CaptureModeName(CaptureMode::Replay)) == "Replay",
             L"F-04 all four capture modes export as distinct names");
}

// ---------------------------------------------------------------------------
// F-10 / M-10：取消、并发与扫描预算
// ---------------------------------------------------------------------------
void TestTaskAndBudget(KswordTests::Suite& s) {
    LatestRequestGate gate;
    const std::uint64_t requestA = gate.begin();
    const std::uint64_t requestB = gate.begin();
    s.expect(!gate.accepts(requestA) && gate.accepts(requestB),
             L"F-10 a late result from request A cannot overwrite request B");
    gate.cancelCurrent();
    s.expect(!gate.accepts(requestB), L"F-10 cancelling invalidates the in-flight request immediately");

    s.expect(!TaskStateIsTerminal(TaskState::Cancelling) && TaskStateIsTerminal(TaskState::Cancelled),
             L"F-10 cancelling is distinct from cancelled so the UI cannot fake a finished cleanup");
    s.expect(!TaskStateIsTerminal(TaskState::Pending) && !TaskStateIsTerminal(TaskState::Running) &&
                 TaskStateIsTerminal(TaskState::Completed) && TaskStateIsTerminal(TaskState::Failed),
             L"F-10 only cancelled/completed/failed are terminal states");
    s.expect(std::string(TaskStateName(TaskState::Pending)) == "Pending" &&
                 std::string(TaskStateName(TaskState::Running)) == "Running" &&
                 std::string(TaskStateName(TaskState::Cancelling)) == "Cancelling" &&
                 std::string(TaskStateName(TaskState::Cancelled)) == "Cancelled" &&
                 std::string(TaskStateName(TaskState::Completed)) == "Completed" &&
                 std::string(TaskStateName(TaskState::Failed)) == "Failed",
             L"F-10 all six task states export as distinct names");

    const AddressRange approved{0x10000ULL, 0x10000ULL};
    s.expect(ValidateRange({0x10000ULL, 0x1000ULL}, approved) == RangeValidation::Ok,
             L"M-10 an in-range request is accepted");
    s.expect(ValidateRange({0x10000ULL, 0U}, approved) == RangeValidation::EmptyRange,
             L"M-10 an empty range is rejected");
    s.expect(ValidateRange({0xFFFFFFFFFFFFFFFFULL, 0x10ULL}, approved) == RangeValidation::Overflow,
             L"M-10 a wrapping range is rejected");
    s.expect(ValidateRange({0x8000ULL, 0x1000ULL}, approved) == RangeValidation::ExceedsApproved,
             L"M-10 a request below the approved window is rejected");
    s.expect(ValidateRange({0x1FFF0ULL, 0x1000ULL}, approved) == RangeValidation::ExceedsApproved,
             L"M-10 a request past the approved window is rejected");

    // M-10：逆序范围。(begin,length) 表达法下调用方自算长度会把逆序压成回绕，
    // 端点入口必须把"给反了"原样带过来。
    s.expect(ValidateRange(AddressRange::fromBeginEnd(0x20000ULL, 0x10000ULL), approved) ==
                 RangeValidation::Reversed,
             L"M-10 an end below begin is reported as reversed, not as an empty or wrapping range");
    s.expect(AddressRange::fromBeginEnd(0x10000ULL, 0x11000ULL).length == 0x1000ULL &&
                 ValidateRange(AddressRange::fromBeginEnd(0x10000ULL, 0x11000ULL), approved) ==
                     RangeValidation::Ok,
             L"M-10 a well-ordered endpoint pair becomes the matching length and validates");
    s.expect(ValidateRange(AddressRange::fromBeginEnd(0x10000ULL, 0x10000ULL), approved) ==
                 RangeValidation::EmptyRange,
             L"M-10 equal endpoints are an empty range, not a reversed one");
    s.expect(std::string(RangeValidationName(RangeValidation::Reversed)) == "Reversed",
             L"M-10 the reversed verdict has its own exported name");

    // M-10：未限定批准范围 != 允许扫全 64 位地址空间。
    const AddressRange unbounded{};
    s.expect(ValidateRange({0ULL, (std::numeric_limits<std::uint64_t>::max)()}, unbounded) ==
                 RangeValidation::ExceedsApproved,
             L"M-10 scanning the whole 64-bit space is refused even without an approved window");
    s.expect(ValidateRange({0x10000ULL, 0x1000ULL}, unbounded) == RangeValidation::Ok,
             L"M-10 an ordinary request without an approved window is still accepted");

    ScanBudget budget;
    budget.maxBytes = OptionalU64::of(4096U);
    budget.maxDurationNanos = OptionalU64::of(1000000ULL);
    s.expect(budget.bounded(), L"M-10 a production scan budget is bounded");

    ScanProgress progress;
    progress.bytesDone = 2048U;
    s.expect(EvaluateBudget(budget, progress) == BudgetStop::Continue,
             L"M-10 a scan under budget keeps going");
    progress.bytesDone = 4096U;
    const BudgetStop stop = EvaluateBudget(budget, progress);
    s.expect(stop == BudgetStop::BytesExhausted, L"M-10 the byte cap stops the scan");

    CoverageAccount coverage;
    coverage.succeeded = 4096U;
    ApplyStopToCoverage(stop, budget, coverage);
    const CollectionOutcome outcome = OutcomeForStop(stop);
    s.expect(outcome.status == CollectionStatus::Partial && coverage.limitHit && !coverage.fullyCovered(),
             L"M-10 a capped scan reports partial results and keeps what it finished");

    ScanProgress cancelled;
    cancelled.bytesDone = 1U;
    cancelled.cancelRequested = true;
    s.expect(EvaluateBudget(budget, cancelled) == BudgetStop::Cancelled,
             L"M-10 cancel takes priority over the remaining budget");

    // F-06：取消不是"命中上限"。把它记成 limitHit + limit=unset 会让账目输出
    // "limit-hit:unknown" —— 一次用户主动取消被说成命中了一个不知道多少的上限。
    CoverageAccount cancelCoverage;
    cancelCoverage.succeeded = 1U;
    ApplyStopToCoverage(BudgetStop::Cancelled, budget, cancelCoverage);
    s.expect(cancelCoverage.cancelled && !cancelCoverage.limitHit,
             L"F-06 a user cancellation is recorded as cancelled, not as a limit hit");
    s.expect(cancelCoverage.describeRemaining() == "cancelled",
             L"F-06 the account names cancellation as the stop reason");
    s.expect(cancelCoverage.describeRemaining().rfind("limit-hit:", 0U) != 0U,
             L"F-06 a cancellation never reports itself as limit-hit:unknown");
    s.expect(!cancelCoverage.fullyCovered(),
             L"F-06 a cancelled scan is never fully covered");
    s.expect(OutcomeForStop(BudgetStop::Cancelled).status == CollectionStatus::Partial &&
                 OutcomeForStop(BudgetStop::Cancelled).message == "cancelled",
             L"F-06 a cancelled scan keeps its partial results and says why");

    // M-10：页 / 条目 / 时间三条上限各自独立生效。
    ScanBudget pageBudget;
    pageBudget.maxPages = OptionalU64::of(2U);
    ScanProgress pagesDone;
    pagesDone.pagesDone = 2U;
    ScanBudget itemBudget;
    itemBudget.maxItems = OptionalU64::of(5U);
    ScanProgress itemsDone;
    itemsDone.itemsDone = 5U;
    ScanBudget timeBudget;
    timeBudget.maxDurationNanos = OptionalU64::of(1000U);
    ScanProgress timeDone;
    timeDone.elapsedNanos = 1000U;
    s.expect(EvaluateBudget(pageBudget, pagesDone) == BudgetStop::PagesExhausted &&
                 EvaluateBudget(itemBudget, itemsDone) == BudgetStop::ItemsExhausted &&
                 EvaluateBudget(timeBudget, timeDone) == BudgetStop::TimeExhausted,
             L"M-10 the page, item and time caps each stop the scan on their own");
    s.expect(OutcomeForStop(BudgetStop::PagesExhausted).message == "budget:pages" &&
                 OutcomeForStop(BudgetStop::ItemsExhausted).message == "budget:items" &&
                 OutcomeForStop(BudgetStop::TimeExhausted).message == "budget:time",
             L"M-10 each cap records which budget stopped the scan");
    s.expect(std::string(BudgetStopName(BudgetStop::PagesExhausted)) == "PagesExhausted" &&
                 std::string(BudgetStopName(BudgetStop::ItemsExhausted)) == "ItemsExhausted" &&
                 std::string(BudgetStopName(BudgetStop::TimeExhausted)) == "TimeExhausted" &&
                 std::string(BudgetStopName(BudgetStop::Continue)) == "Continue",
             L"M-10 every budget stop reason exports as a distinct name");

    CoverageAccount pageCoverage;
    ApplyStopToCoverage(BudgetStop::PagesExhausted, pageBudget, pageCoverage);
    s.expect(pageCoverage.limitHit && !pageCoverage.cancelled &&
                 pageCoverage.describeRemaining() == "limit-hit:2",
             L"M-10 a page-cap stop records the cap that fired");

    ScanBudget unbounded2;
    s.expect(!unbounded2.bounded(),
             L"M-10 a budget with no cap at all reports itself as unbounded");
}

// ---------------------------------------------------------------------------
// F-09 / F-12：会话与现场分开、页面联动
// ---------------------------------------------------------------------------
void TestSessionAndNavigation(KswordTests::Suite& s) {
    s.expect(DecideRefresh(DataOrigin::Session, 5U, 9U, true) ==
                 RefreshDecision::RejectSessionIsImmutable,
             L"F-09 a saved session is never overwritten by a background refresh");
    s.expect(DecideRefresh(DataOrigin::Live, 5U, 9U, true) == RefreshDecision::Apply,
             L"F-09 a live view accepts a newer snapshot");
    s.expect(DecideRefresh(DataOrigin::Live, 9U, 5U, true) == RefreshDecision::RejectStaleSnapshot,
             L"F-09 a stale snapshot cannot replace a newer one");
    s.expect(DecideRefresh(DataOrigin::Live, 5U, 9U, false) == RefreshDecision::RejectNotLatestRequest,
             L"F-10 a result from a superseded request is dropped");

    ProcessInstanceId saved;
    saved.bootId = "boot-A";
    saved.pid = OptionalU64::of(4321U);
    saved.createTime100ns = OptionalU64::of(133000000000000000ULL);
    saved.imageName = "target.exe";

    LiveResolution gone;
    gone.found = false;
    s.expect(ResolveProcessNavigation(saved, gone) == LiveNavigationDecision::RejectObjectExited,
             L"F-09 an exited object reports as exited");

    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = saved;
    reused.liveProcess.createTime100ns = OptionalU64::of(133000000999999999ULL);
    s.expect(ResolveProcessNavigation(saved, reused) == LiveNavigationDecision::RejectIdentityMismatch,
             L"F-09 a reused PID is refused instead of handing the action to a new process");

    LiveResolution unverifiable;
    unverifiable.found = true;
    unverifiable.liveProcess = saved;
    unverifiable.liveProcess.createTime100ns = OptionalU64::unset();
    s.expect(ResolveProcessNavigation(saved, unverifiable) ==
                 LiveNavigationDecision::RejectIdentityUnverifiable,
             L"F-09 an unverifiable identity is neither allowed nor called a mismatch");

    LiveResolution same;
    same.found = true;
    same.liveProcess = saved;
    s.expect(ResolveProcessNavigation(saved, same) == LiveNavigationDecision::Allow,
             L"F-09 a confirmed identity still navigates");

    NavigationRequest request;
    request.page = NavigationPage::Memory;
    request.object = MakeProcessRef(saved, "ev-001");
    request.evidenceId = "ev-001";
    request.anchor = "0x00007FFE12340000";
    s.expect(request.object.navigable() && !request.object.key.empty(),
             L"F-12 a strong identity produces a navigable reference");
    s.expect(DecideNavigation(request, true, true, true) == NavigationOutcome::Delivered,
             L"F-12 an available page with the object present receives the request");
    s.expect(DecideNavigation(request, false, true, true) == NavigationOutcome::TargetPageMissing,
             L"F-12 a closed target page is reported, not silently retargeted");
    s.expect(DecideNavigation(request, true, false, true) == NavigationOutcome::ObjectNotPresent,
             L"F-12 a missing object is explained instead of jumping to the first row");
    s.expect(DecideNavigation(request, true, true, false) == NavigationOutcome::EvidenceNotSaved,
             L"M-08 evidence absent from an offline session is reported as not saved");

    NavigationRequest weak = request;
    ProcessInstanceId weakIdentity = saved;
    weakIdentity.createTime100ns = OptionalU64::unset();
    weak.object = MakeProcessRef(weakIdentity, "ev-002");
    s.expect(DecideNavigation(weak, true, true, true) == NavigationOutcome::IdentityUnusable,
             L"F-12 an identity too weak to be sure refuses to navigate");

    // F-12：身份门槛与 requireExactMatch 无关。requireExactMatch 说的是锚点精度，
    // 不是"要不要校验身份" —— 把它当开关，弱身份就能凭 false 一路跳过去。
    NavigationRequest weakInexact = weak;
    weakInexact.requireExactMatch = false;
    s.expect(!weakInexact.object.navigable(),
             L"F-12 the weak reference really is non-navigable");
    s.expect(DecideNavigation(weakInexact, true, true, true) == NavigationOutcome::IdentityUnusable,
             L"F-12 relaxing the anchor requirement does not relax the identity gate");

    // F-12：没带证据 id 的导航跳过去也回不到原始证据，不得算送达。
    NavigationRequest noEvidenceId = request;
    noEvidenceId.evidenceId.clear();
    s.expect(DecideNavigation(noEvidenceId, true, true, true) == NavigationOutcome::EvidenceIdMissing,
             L"F-12 a navigation request without an evidence id is refused, not delivered");
    s.expect(DecideNavigation(noEvidenceId, true, true, false) == NavigationOutcome::EvidenceIdMissing,
             L"F-12 a missing evidence id is reported even when the session has nothing saved");
    s.expect(std::string(NavigationOutcomeName(NavigationOutcome::EvidenceIdMissing)) ==
                 "EvidenceIdMissing",
             L"F-12 the missing-evidence-id verdict has its own exported name");
}

// ---------------------------------------------------------------------------
// F-05：驱动调用结果 -> 采集状态的归一层（生产实现在 ArkDriverEvidence.h）
// ---------------------------------------------------------------------------
void TestDriverOutcomeNormalisation(KswordTests::Suite& s) {
    using ksword::ark::DriverCallShape;
    using ksword::ark::IoResult;
    using ksword::ark::toCollectionOutcome;

    IoResult ok;
    ok.ok = true;
    ok.bytesReturned = 0U;  // 成功但零字节：正确的空集合
    const CollectionOutcome emptySuccess = toCollectionOutcome(ok);
    s.expect(emptySuccess.status == CollectionStatus::Success,
             L"F-05 a successful call returning nothing is a correct empty set");

    DriverCallShape truncatedShape;
    truncatedShape.partial = true;
    s.expect(toCollectionOutcome(ok, truncatedShape).status == CollectionStatus::Partial,
             L"F-05 a protocol PARTIAL/TRUNCATED flag downgrades success to partial");

    IoResult denied;
    denied.ok = false;
    denied.win32Error = ERROR_ACCESS_DENIED;
    denied.message = "DeviceIoControl failed";
    const CollectionOutcome deniedOutcome = toCollectionOutcome(denied);
    s.expect(deniedOutcome.status == CollectionStatus::AccessDenied &&
                 deniedOutcome.nativeCodeDomain == "WIN32" &&
                 deniedOutcome.nativeCode.present &&
                 deniedOutcome.nativeCode.value == ERROR_ACCESS_DENIED &&
                 deniedOutcome.message == "DeviceIoControl failed",
             L"F-05 access denied keeps its raw Win32 code and message");

    IoResult timedOut;
    timedOut.ok = false;
    timedOut.win32Error = WAIT_TIMEOUT;
    s.expect(toCollectionOutcome(timedOut).status == CollectionStatus::Timeout,
             L"F-05 a timeout is its own state, not a generic error");

    // 旧驱动对未知 IOCTL 返回 ERROR_INVALID_FUNCTION：那是不支持，不是出错。
    IoResult unknownIoctl;
    unknownIoctl.ok = false;
    unknownIoctl.win32Error = ERROR_INVALID_FUNCTION;
    s.expect(toCollectionOutcome(unknownIoctl).status == CollectionStatus::Unsupported,
             L"Q-04 an old driver rejecting a new IOCTL degrades to unsupported, not error");

    DriverCallShape unsupportedShape;
    unsupportedShape.unsupported = true;
    IoResult okButUnsupported;
    okButUnsupported.ok = true;
    s.expect(toCollectionOutcome(okButUnsupported, unsupportedShape).status ==
                 CollectionStatus::Unsupported,
             L"F-05 a protocol UNSUPPORTED flag wins over a successful DeviceIoControl");

    IoResult ntFailure;
    ntFailure.ok = false;
    ntFailure.ntStatus = static_cast<long>(0xC0000022L);  // STATUS_ACCESS_DENIED
    ntFailure.win32Error = ERROR_ACCESS_DENIED;
    const CollectionOutcome ntOutcome = toCollectionOutcome(ntFailure);
    s.expect(ntOutcome.nativeCodeDomain == "NTSTATUS" &&
                 ntOutcome.nativeCode.present &&
                 ntOutcome.nativeCode.value == 0xC0000022ULL,
             L"F-05 an NTSTATUS from R0 is preserved without sign loss");

    // ------------------------------------------------------------------
    // F-05：IOCTL 往返成功而 R0 侧操作失败 —— 全仓最常见的一种失败形态。
    // ok=true 且 win32Error=ERROR_SUCCESS，失败只写在响应包的 NTSTATUS 里。
    // 早先只看 io.ok，这条路径一律被判成 Success，装进 envelope 后
    // deriveConclusion(false) 直接给出"未发现差异"。
    // ------------------------------------------------------------------
    IoResult r0Denied;
    r0Denied.ok = true;
    r0Denied.win32Error = ERROR_SUCCESS;
    r0Denied.ntStatus = AsNtStatus(0xC0000022U);  // STATUS_ACCESS_DENIED
    const CollectionOutcome r0DeniedOutcome = toCollectionOutcome(r0Denied);
    s.expect(r0DeniedOutcome.status == CollectionStatus::AccessDenied,
             L"F-05 a successful IOCTL carrying STATUS_ACCESS_DENIED is an R0 failure, not a success");
    s.expect(r0DeniedOutcome.nativeCodeDomain == "NTSTATUS" &&
                 r0DeniedOutcome.nativeCode.present &&
                 r0DeniedOutcome.nativeCode.value == 0xC0000022ULL,
             L"F-05 the R0 NTSTATUS stays the raw code of record");
    EvidenceEnvelope r0DeniedEnvelope;
    r0DeniedEnvelope.outcome = r0DeniedOutcome;
    s.expect(r0DeniedEnvelope.deriveConclusion(false) == AnalysisConclusion::NoEvidence,
             L"F-05 an R0 access denial yields no evidence, never no-difference-observed");

    IoResult r0Missing;
    r0Missing.ok = true;
    r0Missing.ntStatus = AsNtStatus(0xC0000034U);  // STATUS_OBJECT_NAME_NOT_FOUND
    s.expect(toCollectionOutcome(r0Missing).status == CollectionStatus::Unsupported,
             L"F-05 STATUS_OBJECT_NAME_NOT_FOUND from R0 degrades to unsupported, not success");

    IoResult r0NotSupported;
    r0NotSupported.ok = true;
    r0NotSupported.ntStatus = AsNtStatus(0xC00000BBU);  // STATUS_NOT_SUPPORTED
    s.expect(toCollectionOutcome(r0NotSupported).status == CollectionStatus::Unsupported,
             L"F-05 STATUS_NOT_SUPPORTED from R0 is unsupported, not a generic error");

    IoResult r0Timeout;
    r0Timeout.ok = true;
    r0Timeout.ntStatus = AsNtStatus(0x00000102U);  // STATUS_TIMEOUT
    s.expect(toCollectionOutcome(r0Timeout).status == CollectionStatus::Timeout,
             L"F-05 STATUS_TIMEOUT is a timeout even though its severity bits say success");

    IoResult r0Generic;
    r0Generic.ok = true;
    r0Generic.ntStatus = AsNtStatus(0xC0000001U);  // STATUS_UNSUCCESSFUL
    s.expect(toCollectionOutcome(r0Generic).status == CollectionStatus::Error,
             L"F-05 any other NT_ERROR from R0 lands in Error rather than Success");

    // NT_WARNING（0x8xxxxxxx）是"拿到了数据但没拿全"，不是失败。写成 ntStatus < 0
    // 会把它一并打成错误，已取回的部分观测就白丢了。
    IoResult r0Overflow;
    r0Overflow.ok = true;
    r0Overflow.ntStatus = AsNtStatus(0x80000005U);  // STATUS_BUFFER_OVERFLOW
    const CollectionOutcome overflowOutcome = toCollectionOutcome(r0Overflow);
    s.expect(overflowOutcome.status == CollectionStatus::Partial,
             L"F-05 STATUS_BUFFER_OVERFLOW is partial data, neither success nor error");
    s.expect(StatusCarriesObservation(overflowOutcome.status),
             L"F-05 the partial data from a warning status still counts as an observation");

    // NT_SUCCESS / NT_INFORMATION 不改变判定。
    IoResult r0Informational;
    r0Informational.ok = true;
    r0Informational.ntStatus = AsNtStatus(0x40000000U);  // NT_INFORMATION 段
    s.expect(toCollectionOutcome(r0Informational).status == CollectionStatus::Success,
             L"F-05 an informational NTSTATUS leaves a successful collection successful");

    IoResult r0Zero;
    r0Zero.ok = true;
    r0Zero.ntStatus = 0;
    s.expect(toCollectionOutcome(r0Zero).status == CollectionStatus::Success &&
                 !toCollectionOutcome(r0Zero).nativeCode.present,
             L"F-05 STATUS_SUCCESS stays a success and writes no native code");

    // 个别协议把 lastStatus 当纯信息位用：那种协议必须能显式退出该判定。
    DriverCallShape informationalStatus;
    informationalStatus.ntStatusIsAuthoritative = false;
    s.expect(toCollectionOutcome(r0Denied, informationalStatus).status == CollectionStatus::Success,
             L"F-05 a protocol may opt out of NTSTATUS triage explicitly, never by default");

    // unsupported 标志仍然优先于 NTSTATUS 分流。
    s.expect(toCollectionOutcome(r0Denied, unsupportedShape).status == CollectionStatus::Unsupported,
             L"F-05 a protocol UNSUPPORTED flag still wins over the NTSTATUS triage");

    const CollectionOutcome absent = ksword::ark::driverNotCollected("driver not loaded");
    s.expect(absent.status == CollectionStatus::NotCollected &&
                 absent.message == "driver not loaded",
             L"F-05 never-started collection is distinct from an empty success");

    EvidenceEnvelope envelope;
    envelope.outcome = absent;
    s.expect(envelope.deriveConclusion(false) == AnalysisConclusion::NoEvidence,
             L"F-05 an unloaded driver produces no evidence, never a normal verdict");

    // X-01：sourceGroup 必须按底层来源填，两层包装共用一个组。
    const auto wrapperSource = ksword::ark::makeDriverSource(
        "ui.driverTable", 1U, "r0.module.enum", "IOCTL_KSWORD_ARK_QUERY_MODULES");
    const auto coreSource = ksword::ark::makeDriverSource(
        "r0.module.enum", 1U, "r0.module.enum", "IOCTL_KSWORD_ARK_QUERY_MODULES");
    EvidenceEnvelope wrapper;
    wrapper.source = wrapperSource;
    wrapper.outcome = CollectionOutcome::success();
    EvidenceEnvelope core;
    core.source = coreSource;
    core.outcome = CollectionOutcome::success();
    s.expect(BuildTrustStatement({wrapper, core}).independentSourceGroupCount == 1U,
             L"X-01 the driver source helper keeps two wrappers in one source group");
}

} // namespace

int RunEvidenceContractTests() {
    KswordTests::Suite suite(L"F evidence contract");
    TestLosslessValues(suite);
    TestJsonRoundTrip(suite);
    TestObjectIdentity(suite);
    TestSourceAndTime(suite);
    TestStatusAndCoverage(suite);
    TestTrustBoundary(suite);
    TestTaskAndBudget(suite);
    TestSessionAndNavigation(suite);
    TestDriverOutcomeNormalisation(suite);
    suite.report();
    return suite.failures();
}
