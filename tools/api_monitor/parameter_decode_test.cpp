#include <QCoreApplication>
#include <QTemporaryDir>
#include <iostream>
#include "MonitorDock/WinAPIParameterDecode.h"
#include "MonitorDock/WinAPIParameterRules.h"
#include "MonitorDock/WinAPIFilterRules.h"
#include "MonitorDock/WinAPIFilterCatalog.h"
using namespace ks::monitor;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    auto raw = ParseRawParameterData(QStringLiteral("params=raw abi=x64 RCX=0x40 RDX=0x41 R8=0x1 R9=0x1122334455667788 stackSlots=[0x7FF600000007,0x8]"));
    CHECK(raw.slotBytes == 8 && raw.rawWords.size() == 6);
    QVector<RawParameterAllocation> types{{RawParameterType::Int}, {RawParameterType::Char},
        {RawParameterType::Bool}, {RawParameterType::LongLong}};
    auto value = DecodeRawParameters(raw, types, RawDecodeMode::Parameters);
    CHECK(value.valid && value.values.size() == 4);
    CHECK(value.values[0].value == QStringLiteral("64"));
    CHECK(value.values[1].value == QStringLiteral("65"));
    CHECK(value.values[2].value == QStringLiteral("true"));
    CHECK(value.values[3].value == QString::number(std::int64_t{0x1122334455667788LL}));
    CHECK(value.unallocated.size() == 16);
    auto shifted = types; shifted.removeAt(0);
    CHECK(DecodeRawParameters(raw, shifted, RawDecodeMode::Parameters).values[0].value == QStringLiteral("64"));
    shifted.move(0, 1);
    CHECK(DecodeRawParameters(raw, shifted, RawDecodeMode::Parameters).values[0].value == QStringLiteral("true"));
    auto bytes = DecodeRawParameters(raw, types, RawDecodeMode::Bytes);
    CHECK(bytes.valid && bytes.values[0].value == QStringLiteral("64"));
    CHECK(bytes.values[1].value == QStringLiteral("0"));
    CHECK(bytes.unallocated.size() == 34);
    auto x86 = ParseRawParameterData(QStringLiteral("params=raw abi=x86 ECX=0xA EDX=0xB stackSlots=[0xFFFFFFFE,0x41,0x1,0x2]"));
    CHECK(x86.slotBytes == 4 && x86.rawWords.size() == 4);
    CHECK(DecodeRawParameters(x86, types, RawDecodeMode::Parameters).values[0].value == QStringLiteral("-2"));
    auto extended = DecodeRawParameters(x86, {{RawParameterType::Pointer}, {RawParameterType::UShort}, {RawParameterType::WinBool}}, RawDecodeMode::Parameters);
    CHECK(extended.valid && extended.values[0].value == QStringLiteral("0xfffffffe"));
    CHECK(extended.values[1].value == QStringLiteral("65") && extended.values[2].value == QStringLiteral("true"));
    CHECK(RawParameterWidth({RawParameterType::Long}, 8) == 4 && RawParameterWidth({RawParameterType::WinDword}, 8) == 4);
    CHECK(RawParameterWidth({RawParameterType::Handle}, 4) == 4 && RawParameterWidth({RawParameterType::SizeT}, 8) == 8);
    RawParameterData floatData{4, {0x3f800000, 0x00000000, 0x40040000}};
    auto floats = DecodeRawParameters(floatData, {{RawParameterType::Float}, {RawParameterType::Double}}, RawDecodeMode::Parameters);
    CHECK(floats.values[0].value == QStringLiteral("1") && floats.values[1].value == QStringLiteral("2.5"));
    CHECK(DecodeRawParameters(raw, {{RawParameterType::Float}}, RawDecodeMode::Parameters).values[0].value == QStringLiteral("未采集浮点寄存器"));
    CHECK(DecodeRawParameters(RawParameterData{8, {0x3f800000}}, {{RawParameterType::Float}}, RawDecodeMode::Bytes).values[0].value == QStringLiteral("1"));
    auto incomplete = DecodeRawParameters(x86, {{RawParameterType::Bytes, 20}}, RawDecodeMode::Bytes);
    CHECK(incomplete.valid && !incomplete.values[0].available && incomplete.unallocated.size() == 16);
    CHECK(!DecodeRawParameters(x86, {{RawParameterType::Bytes, 0}}, RawDecodeMode::Bytes).valid);
    CHECK(ParseRawParameterData(QStringLiteral("params=unparsed")).slotBytes == 0);
    CHECK(ParseRawParameterData(QStringLiteral("params=raw abi=x86 stackSlots=[0x100000000]")).slotBytes == 0);
    CHECK(FormatRawHex(QByteArray::fromHex("414200ff")).contains(QStringLiteral("41 42 00 FF")));
    CHECK(FormatRawHex(QByteArray::fromHex("414200ff")).contains(QStringLiteral(" | AB..")));
    const auto layout = LayoutRawParameters(raw, {{RawParameterType::Int}, {RawParameterType::Char}}, RawDecodeMode::Bytes, 40);
    CHECK(layout.widths.size() == 2 && layout.widths[0] == 160 && layout.widths[1] == 40 && layout.remainderWidth == 43 * 40);
    const auto slotLayout = LayoutRawParameters(raw, {{RawParameterType::Int}, {RawParameterType::Char}}, RawDecodeMode::Parameters, 40);
    CHECK(slotLayout.widths[0] == 320 && slotLayout.widths[1] == 320 && slotLayout.remainderWidth == 32 * 40);
    const auto overflowLayout = LayoutRawParameters(x86, {{RawParameterType::Int}, {RawParameterType::Bytes, 48}}, RawDecodeMode::Bytes, 40);
    CHECK(overflowLayout.widths[0] == 160 && overflowLayout.widths[1] == 1 && overflowLayout.remainderWidth == 479);
    const RawParameterData arrayRaw{8, {0x0000000200000001ULL, 0x0000000400000003ULL}};
    auto arrayDecoded = DecodeRawParameters(arrayRaw, {{RawParameterType::Int, 3}, {RawParameterType::Int}}, RawDecodeMode::Bytes);
    CHECK(arrayDecoded.valid && arrayDecoded.values[0].value == QStringLiteral("[1, 2, 3]"));
    CHECK(arrayDecoded.values[1].value == QStringLiteral("4") && arrayDecoded.unallocated.isEmpty());
    auto slotArray = DecodeRawParameters(arrayRaw, {{RawParameterType::Int, 2}, {RawParameterType::Int}}, RawDecodeMode::Parameters);
    CHECK(slotArray.values[0].value == QStringLiteral("[1, 2]") && slotArray.values[1].value == QStringLiteral("3"));
    CHECK(!DecodeRawParameters(arrayRaw, {{RawParameterType::Int, 5}}, RawDecodeMode::Bytes).values[0].available);
    const auto fitted = FitRawAllocationWidths({1, 2, 1}, {20, 20, 20}, 400);
    CHECK(fitted.size() == 3 && fitted[0] == 100 && fitted[1] == 200 && fitted[2] == 100);
    const auto narrow = FitRawAllocationWidths({1, 2}, {50, 70}, 60);
    CHECK(narrow[0] >= 50 && narrow[1] >= 70);
    QTemporaryDir folder; CHECK(folder.isValid());
    const QString path = folder.filePath(QStringLiteral("config/winapi-param.cfg"));
    WinAPIParameterRules rules(path); CHECK(rules.load());
    const auto key = WinAPIParameterRules::key(QStringLiteral("USER32.DLL"), QStringLiteral("GetMessageW"));
    RawParameterRule rule; rule.mode = RawDecodeMode::Bytes; rule.allocations = types;
    CHECK(rules.saveRule(key, rule));
    WinAPIParameterRules loaded(path); CHECK(loaded.load());
    const auto restored = loaded.rule(WinAPIParameterRules::key(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW")));
    CHECK(restored.mode == RawDecodeMode::Bytes && restored.allocations.size() == 4);
    CHECK(loaded.rule(WinAPIParameterRules::key(QStringLiteral("user32.dll"), QStringLiteral("getmessagew"))).allocations.isEmpty());
    rule.allocations = {{RawParameterType::UChar}, {RawParameterType::Short}, {RawParameterType::UShort}, {RawParameterType::UInt},
        {RawParameterType::ULongLong}, {RawParameterType::Float}, {RawParameterType::Double}, {RawParameterType::Pointer},
        {RawParameterType::WChar}, {RawParameterType::WinBool}, {RawParameterType::Long}, {RawParameterType::ULong},
        {RawParameterType::WinByte}, {RawParameterType::WinWord}, {RawParameterType::WinDword}, {RawParameterType::Handle}, {RawParameterType::SizeT}};
    rule.allocations[0].length = 3;
    CHECK(rules.saveRule(key, rule)); WinAPIParameterRules extendedRules(path); CHECK(extendedRules.load());
    CHECK(extendedRules.rule(key).allocations.size() == rule.allocations.size());
    CHECK(extendedRules.rule(key).allocations[0].length == 3);
    for (qsizetype i = 0; i < rule.allocations.size(); ++i) CHECK(extendedRules.rule(key).allocations[i].type == rule.allocations[i].type);
    QFile corrupt(path); CHECK(corrupt.open(QIODevice::WriteOnly | QIODevice::Truncate)); corrupt.write("{"); corrupt.close();
    WinAPIParameterRules bad(path); CHECK(!bad.load());
    const QString filterPath = folder.filePath(QStringLiteral("config/winapi-filter.cfg"));
    WinAPIFilterRules filters(filterPath); CHECK(filters.load());
    WinAPIFilterSnapshot snapshot;
    snapshot.preModules.insert(WinAPIFilterSnapshot::moduleKey(QStringLiteral("NTDLL.DLL")));
    snapshot.postFunctions.insert(WinAPIFilterSnapshot::functionKey(QStringLiteral("USER32.DLL"), QStringLiteral("GetMessageW")));
    CHECK(filters.save(snapshot));
    CHECK(filters.snapshot()->rejects(QStringLiteral("ntdll.dll"), QStringLiteral("Foo"), true));
    CHECK(!filters.snapshot()->rejects(QStringLiteral("ntdll.dll"), QStringLiteral("Foo"), false));
    CHECK(filters.snapshot()->rejectsApi(QStringLiteral("user32.dll!GetMessageW"), false));
    CHECK(!filters.snapshot()->rejectsApi(QStringLiteral("user32.dll!getmessagew"), false));
    WinAPIFilterRules filtersLoaded(filterPath); CHECK(filtersLoaded.load());
    CHECK(filtersLoaded.snapshot()->rejectsApi(QStringLiteral("user32.dll!GetMessageW"), false));
    auto exceptions = *filtersLoaded.snapshot();
    const auto allowedKey = WinAPIFilterSnapshot::functionKey(QStringLiteral("ntdll.dll"), QStringLiteral("Allowed"));
    exceptions.preAllowed.insert(allowedKey); CHECK(filtersLoaded.save(exceptions));
    WinAPIFilterRules exceptionReload(filterPath); CHECK(exceptionReload.load());
    CHECK(!exceptionReload.snapshot()->rejects(QStringLiteral("ntdll.dll"), QStringLiteral("Allowed"), true));
    CHECK(exceptionReload.snapshot()->rejects(QStringLiteral("ntdll.dll"), QStringLiteral("Other"), true));
    const QString exportPath = folder.filePath(QStringLiteral("export.cfg"));
    CHECK(filtersLoaded.exportFile(exportPath)); WinAPIFilterRules imported(exportPath); CHECK(imported.load());
    CHECK(imported.snapshot()->rejects(QStringLiteral("ntdll.dll"), QStringLiteral("Bar"), true));
    QFile broken(filterPath); CHECK(broken.open(QIODevice::WriteOnly | QIODevice::Truncate)); broken.write("{"); broken.close();
    CHECK(!filtersLoaded.load()); CHECK(filtersLoaded.snapshot()->rejectsApi(QStringLiteral("user32.dll!GetMessageW"), false));
    QFile legacy(filterPath); CHECK(legacy.open(QIODevice::WriteOnly | QIODevice::Truncate));
    legacy.write(R"({"version":1,"rules":[{"module":"user32.dll","function":"GetMessageW","pre":false,"post":true}]})"); legacy.close();
    WinAPIFilterRules oldRules(filterPath); CHECK(oldRules.load());
    CHECK(oldRules.snapshot()->rejectsApi(QStringLiteral("USER32.DLL!GetMessageW"), false));
    CHECK(!oldRules.snapshot()->rejectsApi(QStringLiteral("USER32.DLL!GetMessageW"), true));
    WinAPIFilterCatalog catalog;
    CHECK(ParseWinAPIFilterCatalog(R"({"schema_version":1,"apis":[{"module":"User32.dll","export":"GetMessageW","category":"Process"},{"module":"USER32.dll","export":"GetMessageW","category":"Process"},{"module":"user32.dll","export":"getmessagew","category":"Other"}]})", &catalog));
    CHECK(catalog.size() == 2 && catalog[0].module == QStringLiteral("User32.dll"));
    CHECK(catalog[0].function == QStringLiteral("GetMessageW") && catalog[0].category == QStringLiteral("Process"));
    CHECK(!ParseWinAPIFilterCatalog("{", &catalog) && catalog.size() == 2);
    QFile definitions(QStringLiteral("APIMonitor_x64/api_monitor_definitions.json")); CHECK(definitions.open(QIODevice::ReadOnly));
    CHECK(ParseWinAPIFilterCatalog(definitions.readAll(), &catalog) && catalog.size() >= 600);
    std::cout << "PASS: x86/x64 slots, both allocation modes, unavailable data and hex/ASCII\n";
}
