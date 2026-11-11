#include <QCoreApplication>
#include <QFile>
#include <iostream>
#include "MonitorDock/WinAPISignatureCatalog.h"
using namespace ks::monitor;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QFile file(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("APIMonitor_x64/api_monitor_definitions.json"));
    CHECK(file.open(QIODevice::ReadOnly));
    WinAPISignatureCatalog catalog;
    CHECK(catalog.load(file.readAll()) && catalog.size() >= 641);
    const auto* reference = catalog.find(QStringLiteral("aclui.dll"), QStringLiteral("CreateSecurityPage"));
    if (argc == 1) CHECK(!reference && catalog.size() == 641);
    else {
    CHECK(reference && reference->referenceOnly && reference->referenceSource == QStringLiteral("Windows/Aclui.xml"));
    CHECK(reference->parameters.size() == 1 && reference->parameters[0].direction == QStringLiteral("unknown"));
    const auto* charsetA = catalog.find(QStringLiteral("dbghelp.dll"), QStringLiteral("EnumDirTree"));
    const auto* charsetW = catalog.find(QStringLiteral("dbghelp.dll"), QStringLiteral("EnumDirTreeW"));
    CHECK(charsetA && charsetW && charsetA->referenceOnly && charsetW->referenceOnly);
    CHECK(!charsetA->sdkAbiVerified && !charsetW->sdkAbiVerified);
    }
    const auto* signature = catalog.find(QStringLiteral("KERNELBASE.DLL"), QStringLiteral("CreateFileW"));
    CHECK(signature && signature->returnType == QStringLiteral("HANDLE") && signature->parameters.size() == 7);
    CHECK(catalog.find(QStringLiteral("KernelBase"), QStringLiteral("CreateFileW")) == signature);
    CHECK(!catalog.find(QStringLiteral("KernelBase.exe"), QStringLiteral("CreateFileW")));
    CHECK(!catalog.find(QStringLiteral("C:\\Windows\\KernelBase.dll"), QStringLiteral("CreateFileW")));
    CHECK(signature->parameters[0].name == QStringLiteral("fileNamePointer"));
    CHECK(signature->parameters[0].type == QStringLiteral("LPCWSTR"));
    CHECK(FormatWinAPISignature(*signature).contains(QStringLiteral("LPCWSTR fileNamePointer")));
    CHECK(!catalog.find(QStringLiteral("kernelbase.dll"), QStringLiteral("createfilew")));
    auto raw = ParseRawParameterData(QStringLiteral("params=raw abi=x64 RCX=0x40 RDX=0x41 R8=0x42 R9=0x43 stackSlots=[0x44,0x45]"));
    if (reference) {
    CHECK(!MapWinAPIRawArguments(*reference, raw)[0].available);
    CHECK(!MapWinAPIRawArguments(*reference, RawParameterData{4, {1}})[0].available);
    const auto* getMessage = catalog.find(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"));
    CHECK(getMessage && getMessage->referenceOnly && getMessage->sdkAbiVerified);
    CHECK(getMessage->returnType == QStringLiteral("BOOL") && getMessage->parameters.size() == 4);
    CHECK(getMessage->parameters[0].type == QStringLiteral("LPMSG") && getMessage->parameters[0].direction == QStringLiteral("unknown"));
    auto verified64 = MapWinAPIRawArguments(*getMessage, raw);
    auto verified32 = MapWinAPIRawArguments(*getMessage, RawParameterData{4, {1, 2, 3, 4}});
    CHECK(verified64[0].rawHex == QStringLiteral("0x0000000000000040") && verified64[3].rawHex == QStringLiteral("0x0000000000000043"));
    CHECK(verified32[0].rawHex == QStringLiteral("0x00000001") && verified32[3].rawHex == QStringLiteral("0x00000004"));
    }
    if (argc > 1) {
        const auto* show = catalog.find(QStringLiteral("user32.dll"), QStringLiteral("ShowWindow"));
        CHECK(show && show->sdkAbiVerified && show->parameters.size() == 2);
        CHECK(show->parameters[0].direction == QStringLiteral("unknown"));
        CHECK(MapWinAPIRawArguments(*show, raw)[1].rawHex == QStringLiteral("0x0000000000000041"));
        CHECK(MapWinAPIRawArguments(*show, RawParameterData{4, {1, 2}})[1].rawHex == QStringLiteral("0x00000002"));
        const auto* invalid = catalog.find(QStringLiteral("user32.dll"), QStringLiteral("InvalidateRect"));
        CHECK(invalid && invalid->sdkAbiVerified && invalid->parameters.size() == 3);
        CHECK(MapWinAPIRawArguments(*invalid, raw)[1].rawHex == QStringLiteral("0x0000000000000041"));
    }
    if (argc > 2 && QString::fromLocal8Bit(argv[2]) == QStringLiteral("--batch")) {
        const auto* added = catalog.find(QStringLiteral("user32.dll"), QStringLiteral("AddClipboardFormatListener"));
        CHECK(added && added->sdkAbiVerified && added->parameters.size() == 1);
        CHECK(added->parameters[0].direction == QStringLiteral("unknown"));
        CHECK(MapWinAPIRawArguments(*added, raw)[0].rawHex == QStringLiteral("0x0000000000000040"));
        CHECK(MapWinAPIRawArguments(*added, RawParameterData{4, {1}})[0].rawHex == QStringLiteral("0x00000001"));
        const auto* rejected = catalog.find(QStringLiteral("user32.dll"), QStringLiteral("OemToCharBuffW"));
        CHECK(rejected && !rejected->sdkAbiVerified);
        CHECK(!MapWinAPIRawArguments(*rejected, raw)[0].available);
    }
    const auto mapped = MapWinAPIRawArguments(*signature, raw);
    CHECK(mapped.size() == 7 && mapped[0].rawHex == QStringLiteral("0x0000000000000040"));
    CHECK(mapped[4].rawHex == QStringLiteral("0x0000000000000044"));
    CHECK(mapped[5].available && !mapped[6].available);
    CHECK(FormatWinAPIRawSummary(*signature, raw).contains(QStringLiteral("templateFile=?")));
    WinAPISignature synthetic;
    synthetic.function = QStringLiteral("F"); synthetic.returnType = QStringLiteral("BOOL"); synthetic.callingConvention = QStringLiteral("WINAPI");
    synthetic.architectures = {QStringLiteral("x86"), QStringLiteral("x64")};
    synthetic.parameters = {{QStringLiteral("a"), QStringLiteral("DWORD"), QStringLiteral("in")},
        {QStringLiteral("large"), QStringLiteral("ULONGLONG"), QStringLiteral("in")},
        {QStringLiteral("last"), QStringLiteral("DWORD"), QStringLiteral("in")}};
    RawParameterData x86{4, {1, 0x55667788, 0x11223344, 9}};
    auto x86Args = MapWinAPIRawArguments(synthetic, x86);
    CHECK(x86Args[1].rawHex == QStringLiteral("0x1122334455667788") && x86Args[2].rawHex == QStringLiteral("0x00000009"));
    synthetic.callingConvention = QStringLiteral("FASTCALL");
    CHECK(!MapWinAPIRawArguments(synthetic, x86)[0].available);
    synthetic.callingConvention = QStringLiteral("WINAPI");
    synthetic.parameters[1].type = QStringLiteral("UNKNOWN_BY_VALUE");
    x86Args = MapWinAPIRawArguments(synthetic, x86);
    CHECK(x86Args[0].available && !x86Args[1].available && !x86Args[2].available);
    synthetic.parameters[1].type = QStringLiteral("FLOAT");
    const auto x64Args = MapWinAPIRawArguments(synthetic, raw);
    CHECK(x64Args[0].available && !x64Args[1].available && x64Args[2].rawHex == QStringLiteral("0x0000000000000042"));
    synthetic.callingConvention = QStringLiteral("VECTORCALL");
    CHECK(!MapWinAPIRawArguments(synthetic, raw)[0].available);
    synthetic.callingConvention = QStringLiteral("WINAPI");
    synthetic.returnType = QStringLiteral("UNKNOWN_STRUCT");
    CHECK(!MapWinAPIRawArguments(synthetic, raw)[0].available);
    CHECK(!catalog.load("{") && catalog.find(QStringLiteral("kernelbase.dll"), QStringLiteral("CreateFileW")));
    CHECK(!catalog.load(R"({"schema_version":1,"apis":[{}]})"));
    CHECK(!catalog.load(R"({"schema_version":1,"apis":[],"reference_signatures":{"schema_version":1,"status":"unverified","entries":[["x.dll","F","STDCALL","BOOL",[["x"]],"x.xml"]]}})"));
    CHECK((catalog.find(QStringLiteral("aclui.dll"), QStringLiteral("CreateSecurityPage")) != nullptr) == (reference != nullptr));
    std::cout << "PASS: project declarations, identity, bounded Raw mapping, x86 widths and missing FP registers\n";
}
