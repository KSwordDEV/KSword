// 无窗口原生测试：仅消费 shared/evidence/ApiTransferCandidateWindow.h 与 ApiTransferChain.cpp。
// 构造显式 AAIP1 包，验证跨段真实原行、256 候选、1024 写淘汰、复制草稿与来源隔离。
#include "../../../shared/evidence/ApiTransferCandidateWindow.h"

#include <cstdio>
#include <string>
#include <vector>

namespace Monitor = ks::winapi_monitor;
using namespace Ksword::ActionAnalyze::Detection;
using Ksword::Evidence::ApiInjectionFieldsV1;
using Ksword::Evidence::ApiInjectionOperation;

namespace {

int assertions = 0; // 本轮实际执行的断言总数。
int failures = 0; // 未满足预期的断言数，决定进程退出码。
// 输入条件和断言名，累计并输出失败；无返回值，不修改产品状态。
void Check(bool ok, const char* label) {
    ++assertions;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", label);
    }
}

const char* kApiWrite = "WriteProcessMemory"; // Win32 写入行的保留标记。
const char* kApiNtWrite = "NtWriteVirtualMemory"; // NT 写入行的保留标记。
const char* kApiCreate = "CreateRemoteThread"; // Win32 创建行的保留标记。
const char* kApiNtCreate = "NtCreateThreadEx"; // NT 创建行的保留标记。

struct Row {
    std::uint64_t segment = 0; // 原包实际归档段。
    std::uint64_t sequence = 0; // 原包在 raw 流中的真实序号。
    std::string api; // 原行的详情标记，用于验证候选双方副本。
};

const SampleScope testScope{"project", "sample", "machine", "boot"}; // 本测试固定采样范围。

// 输入实际写入起点及完成长度，返回同一源端声明的显式写入字段。
ApiInjectionFieldsV1 WriteFields(std::uint64_t address, std::uint64_t bytes) {
    ApiInjectionFieldsV1 f; // 构造有效的写入返回字段，不从摘要推断。
    f.operation = ApiInjectionOperation::MemoryWrite;
    f.flags = Ksword::Evidence::ApiInjectionActorIdentity |
        Ksword::Evidence::ApiInjectionTargetIdentity |
        Ksword::Evidence::ApiInjectionTargetStable |
        Ksword::Evidence::ApiInjectionAddress |
        Ksword::Evidence::ApiInjectionCompletedLength;
    f.actorCreationFileTime = 1000;
    f.targetPid = 20;
    f.targetCreationFileTime = 2000;
    f.address = address;
    f.requestedBytes = bytes;
    f.completedBytes = bytes;
    f.enterQpc = 100;
    f.returnQpc = 110;
    return f;
}

// 输入请求入口，返回相同声明实例的线程创建返回字段，不证明实际执行。
ApiInjectionFieldsV1 CreateFields(std::uint64_t start) {
    ApiInjectionFieldsV1 f; // 与写入共享来源及目标实例的声明。
    f.operation = ApiInjectionOperation::ThreadCreate;
    f.flags = Ksword::Evidence::ApiInjectionActorIdentity |
        Ksword::Evidence::ApiInjectionTargetIdentity |
        Ksword::Evidence::ApiInjectionThreadIdentity |
        Ksword::Evidence::ApiInjectionTargetStable |
        Ksword::Evidence::ApiInjectionStartAddress;
    f.actorCreationFileTime = 1000;
    f.targetPid = 20;
    f.targetCreationFileTime = 2000;
    f.targetTid = 30;
    f.targetThreadCreationFileTime = 3000;
    f.startAddress = start;
    f.enterQpc = 200;
    f.returnQpc = 210;
    return f;
}

// 输入精确 API、类别、字段、会话与原始返回值，输出可由正式解析器消费的包。
Monitor::ApiMonitorEventPacket Packet(const wchar_t* api, Monitor::EventCategory category,
    const ApiInjectionFieldsV1& fields, std::uint64_t session, std::uint64_t returns) {
    Monitor::ApiMonitorEventPacket p; // 测试包保留协议默认大小、版本和零初始化。
    p.pid = 10;
    p.tid = 11;
    p.category = static_cast<std::uint32_t>(category);
    const std::wstring_view text{api}; // 原包中的精确导出名。
    std::copy(text.begin(), text.end(), p.apiName);
    const std::wstring_view module = category == Monitor::EventCategory::Memory // 本测试使用的声明模块。
        ? std::wstring_view{L"KernelBase"} : std::wstring_view{L"Kernel32"};
    std::copy(module.begin(), module.end(), p.moduleName);
    p.snapshotIndex = Monitor::kApiCallReturnValueMarker;
    p.hookAddress = returns;
    p.resultCode = 0;
    p.resultKind = static_cast<std::uint32_t>(Monitor::EventResultKind::StatusCode);
    p.sessionIdentity = session;
    Ksword::Evidence::StoreApiInjectionFields(p, fields);
    return p;
}

// 输入原包与来源序号，返回正式分类器解释的归档线索值。
Ksword::Evidence::ArchivedApiMonitorClue Clue(const Monitor::ApiMonitorEventPacket& p,
    std::uint64_t source) {
    Ksword::Evidence::ArchivedApiMonitorClue c; // 与桌面读取端同形的测试输入。
    c.packet = p;
    c.clue = Ksword::Evidence::ClassifyApiMonitorClue(p);
    c.sourceSequence = source;
    return c;
}

} // namespace

// 无参数入口；只在内存中验证候选窗口，失败返回 1，通过返回 0。
int main() {
    using Window = Ksword::Evidence::ApiTransferCandidateWindow<Row>;
    const auto write = Packet(L"WriteProcessMemory", Monitor::EventCategory::Memory,
        WriteFields(0x1000, 8), 1234, 8);
    const auto create = Packet(L"CreateRemoteThread", Monitor::EventCategory::Thread,
        CreateFields(0x1004), 1234, 99);
    Check(Ksword::Evidence::ClassifyApiMonitorClue(write) &&
        Ksword::Evidence::ClassifyApiMonitorClue(create), "explicit-packets-classified");

    // NT 写入与创建同样通过正式解析器，避免仅声明 API 名却没有消费该分支。
    {
        Window native(testScope); // NT 对应的独立候选窗口。
        const auto ntWrite = Packet(L"NtWriteVirtualMemory", Monitor::EventCategory::Memory,
            WriteFields(0x1000, 8), 1234, 0); // NTSTATUS 成功的写入返回包。
        const auto ntCreate = Packet(L"NtCreateThreadEx", Monitor::EventCategory::Thread,
            CreateFields(0x1004), 1234, 0); // NTSTATUS 成功的创建返回包。
        native.Accept(Clue(ntWrite, 2), Row{1, 2, kApiNtWrite}, 1, 2, "epoch");
        native.Accept(Clue(ntCreate, 3), Row{2, 3, kApiNtCreate}, 2, 3, "epoch");
        Check(native.Candidates().size() == 1, "nt-api-pair-candidate");
    }

    // 跨段一对真实原行：写入在 raw/1 #2，创建在 raw/2 #3。
    {
        Window w(testScope);
        w.Accept(Clue(write, 2), Row{1, 2, kApiWrite}, 1, 2, "epoch");
        w.Accept(Clue(create, 3), Row{2, 3, kApiCreate}, 2, 3, "epoch");
        Check(w.Candidates().size() == 1, "cross-segment-one-candidate");
        if (!w.Candidates().empty()) {
            const auto& c = w.Candidates().front();
            Check(c.link.write.raw && c.link.write.raw->segmentOrdinal == 1 &&
                c.link.write.raw->sequence == 2, "write-real-raw-coordinate");
            Check(c.link.threadCreate.raw && c.link.threadCreate.raw->segmentOrdinal == 2 &&
                c.link.threadCreate.raw->sequence == 3, "create-real-raw-coordinate");
            Check(c.write.segment == 1 && c.write.sequence == 2 &&
                c.threadCreate.segment == 2 && c.threadCreate.sequence == 3, "both-rows-retained");
        }
    }

    // 256 对有界窗口；总数包含被裁剪的候选而不回退。
    {
        Window w(testScope);
        for (std::uint64_t i = 0; i < 260; ++i) {
            auto wp = Packet(L"WriteProcessMemory", Monitor::EventCategory::Memory,
                WriteFields(0x2000 + i * 8, 8), 1234, 8);
            auto cp = Packet(L"CreateRemoteThread", Monitor::EventCategory::Thread,
                CreateFields(0x2000 + i * 8), 1234, 99);
            w.Accept(Clue(wp, i + 1), Row{1, i + 1, kApiWrite}, 1, i + 1, "epoch");
            w.Accept(Clue(cp, i + 1), Row{2, i + 1, kApiCreate}, 2, i + 1, "epoch");
        }
        Check(w.Candidates().size() == 256, "candidate-window-bounded-256");
        Check(w.CandidateCount() == 260, "candidate-total-not-regressed");
    }

    // 1024 写入状态淘汰随查询公开。
    {
        Window w(testScope);
        for (std::uint64_t i = 0; i < 1025; ++i) {
            auto wp = Packet(L"NtWriteVirtualMemory", Monitor::EventCategory::Memory,
                WriteFields(0x3000 + i * 8, 8), 1234, 0);
            w.Accept(Clue(wp, i + 1), Row{1, i + 1, kApiNtWrite}, 1, i + 1, "epoch");
        }
        Check(w.EvictedWrites() == 1, "write-window-evicted-1");
    }

    // 复制草稿只在副本提交；原状态不被污染。
    {
        Window committed(testScope);
        committed.Accept(Clue(write, 2), Row{1, 2, kApiWrite}, 1, 2, "epoch");
        Window staged = committed;
        staged.Accept(Clue(create, 3), Row{2, 3, kApiCreate}, 2, 3, "epoch");
        Check(staged.Candidates().size() == 1 && committed.Candidates().empty(),
            "staged-copy-not-contaminating-committed");
        Check(committed.CandidateCount() == 0, "committed-total-unchanged");
    }

    // 来源隔离：不同代次或会话不能跨链。
    {
        Window w(testScope);
        w.Accept(Clue(write, 2), Row{1, 2, kApiWrite}, 1, 2, "epoch");
        w.Accept(Clue(create, 3), Row{2, 3, kApiCreate}, 2, 3, "other-epoch");
        Check(w.Candidates().empty(), "foreign-epoch-isolated");
        auto foreign = Packet(L"CreateRemoteThread", Monitor::EventCategory::Thread,
            CreateFields(0x1004), 9999, 99);
        w.Accept(Clue(foreign, 4), Row{2, 4, kApiCreate}, 2, 4, "epoch");
        Check(w.Candidates().empty(), "foreign-session-isolated");
    }

    std::printf("assertions=%d failures=%d\n", assertions, failures);
    return failures ? 1 : 0;
}
