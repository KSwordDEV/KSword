"""Exercise the production native property producers without opening KSword or querying a driver."""
from pathlib import Path
import argparse, json, os, re, shutil, subprocess


def balanced_end(source, start):
    depth = 0
    quote = None
    index = start
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            continue
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if not depth:
                return index + 1
        index += 1
    raise ValueError("Unclosed source function")


def function(source, name):
    start = source.index(name)
    return source[start:balanced_end(source, source.index("{", start))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qt-root", type=Path, default=Path(".codex-tmp/qt-fixture/ucrt64"))
    parser.add_argument("--compiler", default="g++")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    app = root / "Ksword5.1/Ksword5.1"
    qt = (root / args.qt_root).resolve() if not args.qt_root.is_absolute() else args.qt_root
    output = root / "work/report-property-model-tests"
    output.mkdir(parents=True, exist_ok=True)
    model = (app / "UI/StructuredFieldView.cpp").read_text(encoding="utf-8-sig")
    model = model[:model.index("    StructuredFieldView::StructuredFieldView(")] + "\n}\n"
    model = re.sub(r'#include "([^"\n]+)"', lambda m: '#include "' + (app / "UI" / m[1]).resolve().as_posix() + '"', model)
    (output / "production-model.cpp").write_text(model, encoding="utf-8")
    device_source = (app / "HardwareDock/HardwareDeviceManagerPage.cpp").read_text(encoding="utf-8-sig")
    device_header = (app / "HardwareDock/HardwareDeviceManagerPage.h").read_text(encoding="utf-8-sig")
    device_struct = function(device_header, "struct DeviceEntry") + ";"
    device_functions = "\n".join(function(device_source, name) for name in
        ("QString safeDisplayText(", "ks::ui::FieldDocument buildDevicePropertiesText(", "ks::ui::FieldDocument buildDriverDetailsText("))
    dump_source = (app / "MinidumpDock/MinidumpDock.Tables.cpp").read_text(encoding="utf-8-sig")
    dump_function = function(dump_source, "ks::ui::FieldDocument MinidumpDock::buildReportText(")
    dump_function = dump_function.replace("MinidumpDock::buildReportText", "buildDumpDocument").replace(") const\n{", ")\n{")
    dump_function = function(dump_source, "QString hexText(") + "\n" + dump_function
    dump_limit = re.search(r"constexpr std::size_t kReportMemoryRowLimit\s*=\s*([^;]+);", dump_source)[0]
    analyzer = (app / "MinidumpDock/DumpAnalyzer.cpp").read_text(encoding="utf-8-sig")
    confidence = function(analyzer, "QString AnalysisConfidenceText(")
    tests = r'''
#include "Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"
#include "Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccessBackend.h"
#include "Ksword5.1/Ksword5.1/MinidumpDock/MinidumpFormat.h"
#include "Ksword5.1/Ksword5.1/MinidumpDock/DumpAnalyzer.h"
#include <QCoreApplication>
#include <QStringList>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

namespace ks::i18n {
    // Identity translation isolates value/branch conservation from language-pack content.
    struct LanguageManager::State {};
    LanguageManager::LanguageManager() = default;
    LanguageManager::~LanguageManager() = default;
    LanguageManager& LanguageManager::instance() { static LanguageManager value; return value; }
    QString LanguageManager::sourceText(const QString& source) const { return source; }
    QString LanguageManager::contextText(const QString&, const QString& source) const { return source; }
    bool LanguageManager::eventFilter(QObject* object, QEvent* event) { return QObject::eventFilter(object, event); }
}
namespace device_fixture {
    struct HardwareDeviceManagerPage { DEVICE_STRUCT };
    DEVICE_FUNCTIONS
}
namespace ks::minidump { CONFIDENCE_FUNCTION }
namespace dump_fixture {
    DUMP_LIMIT
    DUMP_FUNCTION
}
int checks = 0;
void require(bool value, const char* description) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL %s\n", description); std::abort(); }
}
void values(const ks::ui::FieldNode& node, QStringList& result) {
    if (node.kind != ks::ui::FieldNode::Kind::Section) result.append(node.value);
    for (const auto& child : node.children) values(child, result);
}
QStringList values(const ks::ui::FieldDocument& document) {
    QStringList result;
    for (const auto& node : document.nodes) values(node, result);
    return result;
}
int main(int argc, char** argv) {
    QCoreApplication application(argc, argv);
    device_fixture::HardwareDeviceManagerPage::DeviceEntry device;
    QStringList raw;
    const auto assign = [&raw](QString& target, const char* name) {
        target = QString::fromLatin1(name) + QStringLiteral(" : %2 [section]\n<raw>&value");
        raw.append(target);
    };
    assign(device.nameText, "name"); assign(device.manufacturerText, "manufacturer");
    assign(device.serviceText, "service"); assign(device.classText, "class");
    assign(device.enumeratorText, "enumerator"); assign(device.installedText, "installed");
    assign(device.instanceIdText, "instance"); assign(device.parentInstanceIdText, "parent");
    assign(device.classGuidText, "guid"); assign(device.driverText, "driver");
    assign(device.driverInfPathText, "inf"); assign(device.driverProviderText, "provider");
    assign(device.driverVersionText, "version"); assign(device.driverDateText, "date");
    assign(device.driverRegistryPathText, "registry"); assign(device.serviceImagePathText, "image");
    assign(device.locationText, "location"); assign(device.hardwareIdsText, "hardware_ids");
    assign(device.compatibleIdsText, "compatible_ids"); assign(device.problemText, "problem");
    assign(device.statusText, "status");
    const auto general = device_fixture::buildDevicePropertiesText(device);
    const auto driver = device_fixture::buildDriverDetailsText(device);
    const auto general_values = values(general);
    for (const auto& value : raw) {
        require(general_values.contains(value), "all device fields survive as exact scalar values");
        require(general.toPlainText().contains(value), "device text export is derived from conserved model values");
    }
    require(general.nodes.size() == 3, "General retains General/Identity/Driver sections");
    require(driver.toPlainText().contains(device.instanceIdText), "driver view retains full instance identity");
    require(driver.toPlainText().contains(device.hardwareIdsText), "driver view retains multiline hardware IDs");
    require(driver.toPlainText().contains(device.compatibleIdsText), "driver view retains compatible IDs");

    using namespace ks::privilege::access::detail;
    for (unsigned combination = 0; combination < 64; ++combination) {
        Result result;
        result.request.pid = 123;
        result.request.desired = READ_CONTROL;
        result.request.path = QStringLiteral("C:/raw:%2\n[not a generated section]");
        result.canonicalPath = QStringLiteral("canonical_%3_<plain>");
        result.user = QStringLiteral("user_%2"); result.userSid = QStringLiteral("S-1-5-raw_%3");
        result.owner = QStringLiteral("owner_%7"); result.ownerSid = QStringLiteral("owner_sid_%8");
        result.groupSid = QStringLiteral("group_sid_%9");
        result.descriptorSddl = QStringLiteral("D:(A;;RC;;;WD) raw:%1\n[raw]");
        result.labelSddl = QStringLiteral("S:(ML;;NW;;;ME) raw:%2");
        result.tokenIntegrityKnown = (combination & 1) != 0;
        result.labelKnown = (combination & 2) != 0;
        result.nullDacl = (combination & 4) != 0;
        result.probe = (combination & 8) != 0;
        result.probeOpened = (combination & 16) != 0;
        if (combination & 32) {
            result.anchor = std::make_shared<Anchor>();
            result.anchor->creation = 123456789;
            result.anchor->statistics.TokenId.HighPart = 101;
            result.anchor->statistics.TokenId.LowPart = 202;
        }
        const auto document = buildAccessDocument(result);
        const auto text = document.toPlainText();
        for (const auto& value : { result.request.path, result.canonicalPath, result.user,
            result.userSid, result.owner, result.ownerSid, result.groupSid,
            result.descriptorSddl, result.labelSddl }) require(text.contains(value), "access model conserves unparsed evidence values in every branch");
        require(text.contains(QStringLiteral("进程创建时间")) == bool(result.anchor), "null anchor never leaks/dereferences anchor-only fields");
        require(text.contains(QStringLiteral("主体完整性 RID")) == result.tokenIntegrityKnown, "unknown integrity does not fabricate a known RID");
        require(text.contains(QStringLiteral("对象完整性 RID")) == result.labelKnown, "unknown object label does not fabricate a known RID");
    }
    Result failed;
    failed.stage = Stage::Token; failed.error = ERROR_ACCESS_DENIED;
    const auto failure = buildAccessDocument(failed);
    require(values(failure).size() == 2, "failed evaluation keeps stage/error and stops before absent evidence");

    ks::minidump::DumpParseResult dump;
    dump.filePath = QStringLiteral("C:/dump_%2_[raw].dmp");
    dump.overview.push_back({QStringLiteral("raw_%1"), QStringLiteral("value_%2\n[raw]")});
    dump.exceptionInfo.push_back({QStringLiteral("exception"), QStringLiteral("exception_%3")});
    dump.executionContext.push_back({QStringLiteral("context"), QStringLiteral("context_%4")});
    dump.analysis.headline = QStringLiteral("finding_%5");
    dump.analysis.findings.append(QStringLiteral("finding_detail_%6"));
    dump.analysis.suggestions.append(QStringLiteral("suggestion_%7"));
    dump.diagnostics.append(QStringLiteral("diagnostic_%8\n<raw>"));
    const auto dump_document = dump_fixture::buildDumpDocument(dump);
    const auto dump_text = dump_document.toPlainText();
    for (const auto& value : {dump.filePath, dump.overview.front().value,
        dump.exceptionInfo.front().value, dump.executionContext.front().value,
        dump.analysis.headline, dump.analysis.findings.front(), dump.analysis.suggestions.front(), dump.diagnostics.front()})
        require(dump_text.contains(value), "dump document conserves source facts and diagnostics");
    require(dump_document.title == QStringLiteral("KSword 转储解析报告"), "dump report model preserves its identity");
    std::printf("PASS native property producer conservation: %d checks\n", checks);
}
'''
    for key, value in {"DEVICE_STRUCT": device_struct, "DEVICE_FUNCTIONS": device_functions,
        "CONFIDENCE_FUNCTION": confidence, "DUMP_LIMIT": dump_limit, "DUMP_FUNCTION": dump_function}.items():
        tests = tests.replace(key, value)
    (output / "producer-conservation.cpp").write_text(tests, encoding="utf-8")
    compiler = shutil.which(args.compiler) or args.compiler
    flags = ["-std=c++20", "-O1", "-g0", "-ffunction-sections", "-fdata-sections", "-DNOMINMAX", "-DUNICODE", "-D_UNICODE", "-I" + str(root)]
    for module in ("", "QtCore", "QtGui", "QtWidgets"):
        flags += ["-isystem", str(qt / "include/qt6" / module)]
    sources = [output / "production-model.cpp", output / "producer-conservation.cpp", app / "PrivilegeDock/PrivilegeAccessReport.cpp"]
    objects = []
    for source in sources:
        obj = output / (source.stem + ".o")
        subprocess.run([compiler, *flags, "-c", str(source), "-o", str(obj)], cwd=root, check=True, timeout=180)
        objects.append(str(obj))
    binary = output / "producer-conservation.exe"
    subprocess.run([compiler, *objects, "-Wl,--gc-sections", "-L" + str(qt / "lib"), "-lQt6Widgets", "-lQt6Gui", "-lQt6Core", "-ladvapi32", "-o", str(binary)], cwd=root, check=True, timeout=120)
    environment = dict(os.environ)
    environment["PATH"] = str(qt / "bin") + os.pathsep + environment.get("PATH", "")
    run = subprocess.run([str(binary)], cwd=root, env=environment, capture_output=True, text=True, timeout=60)
    log = root / ".codex-build-logs/report-property-model-test.json"
    log.parent.mkdir(exist_ok=True)
    log.write_text(json.dumps({"exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr,
        "scope": "production pure producers, identity i18n stub, no QWidget/driver/account queries"}, indent=2), encoding="utf-8")
    print(run.stdout, end="")
    if run.returncode:
        print(run.stderr)
        raise SystemExit(run.returncode)


if __name__ == "__main__":
    main()
