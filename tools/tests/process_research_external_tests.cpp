#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessResearchExternal.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../shared/usermode/backend/driver/DriverQueries.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QScopeGuard>
#include <QtEndian>
#include <iostream>
#include <stdexcept>

using namespace ksword::detection;
namespace
{
    int checks = 0, hvmCalls = 0, processCalls = 0;
    ksword::ark::SsdtEnumResult ssdtFixture;
    ksword::ark::KernelInlineHookScanResult inlineFixture;
    ksword::ark::DriverObjectModuleSnapshot moduleFixture;
    unsigned ssdtCalls = 0, inlineCalls = 0;
    void check(bool condition, const char* reason)
    {
        ++checks;
        if (!condition) throw std::runtime_error(reason);
    }
    MethodReport collect(int id, const ScanInputs& inputs, ScanResult& scan)
    {
        MethodReport r;
        check(CollectResearchExternal(id, inputs, scan, r, {}), "unhandled external method");
        return r;
    }
}
namespace ksword::ark
{
    SsdtEnumResult DriverClient::enumerateSsdt(unsigned long flags) const
    {
        check(flags == KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED, "unresolved SSDT entries omitted");
        ++ssdtCalls;
        return ssdtFixture;
    }
    KernelInlineHookScanResult DriverClient::scanInlineHooks(unsigned long flags, unsigned long maxEntries, const std::wstring& module) const
    {
        check(flags == 0 && maxEntries == KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES && module.empty(), "wrong inline observation scope");
        ++inlineCalls;
        return inlineFixture;
    }
    DriverObjectModuleSnapshot DriverClient::captureDriverObjectModules() const { return moduleFixture; }
    HvmEventResult DriverClient::queryHvmEvents(std::uint64_t, unsigned long, bool clear) const
    {
        check(!clear, "reader cleared event ring");
        ++hvmCalls;
        return {};
    }
    ProcessCrossViewResult DriverClient::queryProcessCrossView(unsigned long, std::uint32_t,
        std::uint32_t, unsigned long, DriverHandle*) const
    {
        ++processCalls;
        return {};
    }
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().size() == 3 && app.arguments()[1] == QStringLiteral("--vmrs"))
    {
        ScanInputs inputs;
        inputs.memoryImage = app.arguments()[2];
        ScanResult result;
        const auto receipt = collect(52, inputs, result);
        std::cout << "VMRS status=" << static_cast<int>(receipt.status) << " vcpu_records=" << receipt.count
            << " " << receipt.detail.toStdString() << '\n';
        return 0;
    }
    if (app.arguments().value(1) == QStringLiteral("--no-pad"))
    {
        if (app.arguments().size() != 5) return 4;
        if (!app.arguments().last().endsWith(QStringLiteral(".csv"))) {
            std::cout << "0000000000000000  psb\n0000000000000010  pip  fe000, nr    cr3 00000000000ff000\n";
            return 0;
        }
        std::cout << "0000000000000000  psb\n0000000000000010  pip             fffff000, nr\n";
        return 0;
    }
    try
    {
        if (app.arguments().size() == 3 && app.arguments()[1] == QStringLiteral("--ptdump"))
        {
            ScanInputs inputs;
            inputs.processorTraceTool = QFileInfo(app.arguments()[2]).absoluteFilePath();
            const QDir output(app.applicationDirPath() + QStringLiteral("/ProcessExternal/obj"));
            inputs.processorTraceFile = output.absoluteFilePath(QStringLiteral("libipt-psb-pip-psb.pt"));
            QFile sample(inputs.processorTraceFile);
            check(sample.open(QIODevice::WriteOnly | QIODevice::NewOnly), "cannot create test trace");
            const auto cleanup = qScopeGuard([&] { sample.close(); sample.remove(); });
            // Intel libipt v2.2.1, test/src/psb-pip-psb.ptt: PIP(0xa00) between two sync blocks.
            const auto psb = QByteArray::fromHex("0282").repeated(8);
            const auto psbend = QByteArray::fromHex("0223");
            const auto bytes = psb + psbend + QByteArray::fromHex("0243a00000000000") + psb + psbend;
            check(sample.write(bytes) == bytes.size() && sample.flush(), "cannot write PT vector");
            sample.close();
            ScanResult result;
            const auto receipt = collect(50, inputs, result);
            std::cout << receipt.detail.toStdString() << '\n';
            for (const auto& row : result.evidence) std::cout << row.detail.toStdString() << '\n';
            check(receipt.status == Status::Complete && receipt.count == 1 && result.evidence.size() == 1, "official ptdump scan failed");
            check(receipt.detail.contains(QStringLiteral("PSB=2, PIP=1, OVF=0")), "packet counters must reflect the upstream vector");
            const auto& hit = result.evidence.front();
            check(hit.objectAddress == 0 && hit.pid == 0 && hit.detail.endsWith(QStringLiteral("CR3=0xa00")),
                "PIP paging context must retain CR3 without implying a process identity");
            return 0;
        }
        const QDir fixtures(QDir::cleanPath(app.applicationDirPath() + QStringLiteral("/../../fixtures/process_external")));
        ScanInputs inputs;
        ScanResult empty;
        for (int id = 44; id <= 53; ++id)
            check(collect(id, inputs, empty).status == Status::Unavailable, "absent input should report unavailable");
        check(hvmCalls == 1 && !processCalls, "four HVM readers must share a single captured ring");
        MethodReport cancelled;
        check(CollectResearchExternal(52, inputs, empty, cancelled, [] {return true;}) &&
            cancelled.status == Status::Cancelled, "cancelled provider");
        check(!CollectResearchExternal(54, inputs, empty, cancelled, {}), "unrelated method intercepted");
        ScanResult ring;
        ring.researchHvmEvents = std::make_shared<ksword::ark::HvmEventResult>();
        ring.researchHvmEvents->io.ok = true;
        auto& events = ring.researchHvmEvents->response;
        events.returnedRows = events.availableRows = 5;
        events.rows[0].type = KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT;
        events.rows[0].exitReason = 28; events.rows[0].qualification = 3;
        events.rows[1] = events.rows[0]; events.rows[1].qualification = 0x13; // MOV from CR3
        auto& write = events.rows[2];
        write.type = KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION;
        write.eventFlags = KSWORD_ARK_HVM_EVENT_FLAG_WATCH_HIT | KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID |
            KSWORD_ARK_HVM_EVENT_FLAG_RANGE_MATCH;
        write.access = 2; write.guestCr3 = 0x13009; write.guestPhysicalAddress = 0x13080;
        write.guestLinearAddress = 0xffff8000123400a0;
        events.rows[3] = write; events.rows[3].access = 4;
        events.rows[4] = write; events.rows[4].guestPhysicalAddress = 0x95000; events.rows[4].eventFlags = 0;
        auto& processes = ring.processCrossView.emplace();
        processes.io.ok = true;
        auto& owner = processes.entries.emplace_back();
        owner.processId = 77; owner.objectAddress = 0xffff800012340000; owner.fieldOffsets.epActiveProcessLinks = 0xa0;
        for (int id = 45; id <= 48; ++id)
        {
            const auto r = collect(id, inputs, ring);
            check(r.count == 1 && r.status == Status::Partial, "EPT or CR3 evidence was overclassified");
        }
        check(ring.evidence[2].pid == 77 && ring.evidence[2].historical, "post-capture EPROCESS attribution");
        inputs.memProcFsRoot = fixtures.filePath(QStringLiteral("other-provider"));
        inputs.vmiMountRoot = fixtures.absolutePath(); inputs.guestProcessFile = fixtures.filePath(QStringLiteral("guest.csv"));
        ScanResult compared;
        auto comparison = collect(49, inputs, compared);
        check(comparison.status == Status::Partial && comparison.count == 1 && compared.evidence.front().pid == 110,
            "CIM comparison or non-atomic result misclassified");
        check(collect(44, inputs, compared).status == Status::Unavailable && collect(51, inputs, compared).status == Status::Unavailable,
            "copied fixture was treated as a live VMI or DMA backend");
        inputs.guestProcessFile = fixtures.filePath(QStringLiteral("other_guest.csv"));
        check(collect(49, inputs, compared).status == Status::Failed, "different guest computers must not be correlated");

        const QDir testDir(app.applicationDirPath() + QStringLiteral("/ProcessExternal"));
        inputs.xenTraceFile = testDir.filePath(QStringLiteral("process-context.xentrace"));
        QFile xen(inputs.xenTraceFile);
        check(xen.open(QIODevice::NewOnly | QIODevice::WriteOnly), "xentrace path occupied");
        const auto cleanXen = qScopeGuard([&] { xen.close(); xen.remove(); });
        const auto put = [&](quint32 value) {
            char word[4]; qToLittleEndian(value, word);
            if (xen.write(word, 4) != 4) throw std::runtime_error("xentrace fixture write");
        };
        put(0x2001f003); put(1); put(44); // CPU 1, window contains switch(20) + CR_WRITE64 with TSC(24).
        put(0x4002800a); put(0); put(0); put(17); put(3);
        put(0xb0082109); put(0x333); put(0x222); put(3); put(0x45678000); put(0x00000012);
        xen.close();
        ScanResult trace;
        const auto crWrite = collect(45, inputs, trace);
        check(crWrite.status == Status::Complete && crWrite.count == 1 &&
            trace.evidence.front().detail.contains(QStringLiteral("d17/v3 CR3=0x1245678000")), "decoded Xen CR_WRITE64 operand or vCPU");
        check(xen.open(QIODevice::WriteOnly | QIODevice::Append), "xentrace reopen");
        put(0x2001f003); xen.close();
        check(collect(45, inputs, trace).status == Status::Partial, "truncated CPU window after valid data");
        inputs.processorTraceTool = testDir.filePath(QStringLiteral("ptdump.exe"));
        const auto alias = QDir::toNativeSeparators(inputs.processorTraceTool).toStdWString();
        const auto self = QDir::toNativeSeparators(app.applicationFilePath()).toStdWString();
        check(CreateHardLinkW(alias.c_str(), self.c_str(), nullptr) != FALSE, "cannot create named fixture child");
        const auto cleanAlias = qScopeGuard([&] { DeleteFileW(alias.c_str()); });
        inputs.processorTraceFile = fixtures.filePath(QStringLiteral("guest.csv"));
        ScanResult pt;
        const auto packets = collect(50, inputs, pt);
        check(packets.status == Status::Complete && packets.count == 1 && pt.evidence.front().detail.contains(QStringLiteral("fffff000")),
            "libipt output fixture did not preserve the CR3 context");
        inputs.processorTraceFile = xen.fileName();
        ScanResult badPt;
        const auto mismatch = collect(50, inputs, badPt);
        check(mismatch.status == Status::Partial && !mismatch.count && badPt.evidence.isEmpty(), "mismatched PIP annotation");
        ScanResult system;
        MethodReport paths;
        paths.status = Status::Unavailable;
        ssdtFixture.io.deviceOpenFailed = inlineFixture.io.deviceOpenFailed = true;
        ReadResearchKernelPaths(system, paths, {});
        check(paths.status == Status::Unavailable && !paths.count, "absent R0 became a clean report");
        constexpr quint64 kernel = 0xffff000000100000, table = kernel + 0x800;
        using namespace ks::r3::driver;
        moduleFixture.systemInformation.resize(sizeof(KRTL_PROCESS_MODULES));
        auto* modules = reinterpret_cast<KRTL_PROCESS_MODULES*>(moduleFixture.systemInformation.data());
        modules->NumberOfModules = 1;
        modules->Modules[0].ImageBase = reinterpret_cast<void*>(kernel);
        modules->Modules[0].ImageSize = 0x10000;
        strcpy_s(reinterpret_cast<char*>(modules->Modules[0].FullPathName), sizeof(modules->Modules[0].FullPathName), "\\SystemRoot\\system32\\ntoskrnl.exe");
        ssdtFixture.io.ok = inlineFixture.io.ok = true;
        ssdtFixture.serviceTableBase = table;
        ssdtFixture.serviceCountFromTable = ssdtFixture.totalCount = ssdtFixture.returnedCount = 2;
        ksword::ark::SsdtEntry good;
        good.flags = KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED | KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID | KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_VALUE_CAPTURED;
        good.serviceRoutineAddress = kernel + 0x2000; good.zwRoutineAddress = kernel + 0x1900;
        good.tableEntrySize = 4; good.tableEntryAddress = table;
        auto unusual = good; unusual.serviceIndex = 1; unusual.tableEntryAddress += 4; unusual.serviceRoutineAddress += 0x100000;
        ssdtFixture.entries = {good, unusual};
        inlineFixture.status = KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN;
        inlineFixture.moduleCount = inlineFixture.returnedCount = inlineFixture.totalCount = 1;
        inlineFixture.entries.emplace_back().status = KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS;
        paths = {};
        ReadResearchKernelPaths(system, paths, {});
        check(paths.status == Status::Complete && paths.count == 2 && system.evidence.front().objectAddress == table + 4,
            "valid Zw stub difference counted or cross-module target ignored");
        ++ssdtFixture.totalCount;
        paths = {};
        ReadResearchKernelPaths(system, paths, {});
        check(paths.status == Status::Partial, "truncated SSDT response became complete");
        ++inlineFixture.totalCount;
        ssdtFixture.io.ok = false;
        paths = {};
        ReadResearchKernelPaths(system, paths, {});
        check(paths.status == Status::Partial, "unavailable SSDT/partial Inline became clean");
        const auto observations = ssdtCalls + inlineCalls;
        ReadResearchKernelPaths(system, paths, [] { return true; });
        check(paths.status == Status::Cancelled && observations == ssdtCalls + inlineCalls, "cancelled kernel path scan issued queries");
        std::cout << "PASS external checks=" << checks << " HVM_reads=" << hvmCalls << '\n';
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "FAIL check=" << checks << " " << e.what() << '\n';
        return 1;
    }
}
