"""Exercise the production PFN area projection without a scan or driver."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
from process_activity_tree_tests import declaration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qt', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    qt = (args.qt or root / '.deps/Qt/6.9.3/msvc2022_64').resolve()
    source = (root / 'Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageAttributionPage.cpp').read_text(encoding='utf-8-sig')
    arrays = []
    for marker in ('constexpr std::array<const char*, useCount> useNames', 'constexpr std::array<const char*, 8> stateNames'):
        start = source.index(marker)
        arrays.append(source[start:source.index('};', start) + 2])
    helper = declaration(source, 'std::vector<ks::ui::MetricAreaNode> pfnMetricAreaNodes(')
    fixture = '''#include "Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageScan.h"
#include "Ksword5.1/Ksword5.1/UI/MetricAreaCanvas.h"
#include <cassert>
#include <cmath>
#include <iostream>
#include <set>
using namespace ksword::pfn;
QString L(const char* source) { return QString::fromUtf8(source); }
'''
    fixture += '\n'.join(arrays) + '\n' + declaration(source, 'QString bytes(') + '\n' + declaration(source, 'QString hex(') + '\n' + helper
    for signature in ('std::vector<ks::ui::MetricAreaNode> pfnProcessMetricAreaNodes(',
                      'std::vector<ks::ui::MetricAreaNode> pfnBackingMetricAreaNodes(',
                      'std::vector<ks::ui::MetricAreaNode> pfnCoverageMetricAreaNodes('):
        fixture += '\n' + declaration(source, signature)
    fixture += r'''
int main() {
    Accounting counts;
    counts.expected = 12;
    for (unsigned i = 0; i < 3; ++i) counts.add({6U << 4, 0}, Use::Private);
    counts.add({3U << 4, 0}, Use::MappedFile);
    counts.add({0, 0}, Use::Unassigned);
    counts.add({2U << 4, 0}, Use::MappedFile);
    counts.add({5U << 4, 0}, Use::Unknown);
    counts.add({7U << 4, 0}, Use::Unknown);
    counts.failed(2);
    assert(counts.reconciles());
    for (int mode : {0, 1}) {
        const auto nodes = pfnMetricAreaNodes(counts, mode);
        double total = 0;
        std::set<QString> identities;
        for (const auto& node : nodes) {
            assert(node.known && node.parent == -1 && !node.group);
            assert(identities.insert(node.key).second);
            assert(std::isfinite(node.weight) && node.weight >= 0);
            total += node.weight;
        }
        assert(total == static_cast<double>(counts.expected * pageBytes));
        const auto find = [&](const QString& key) -> const ks::ui::MetricAreaNode& {
            for (const auto& node : nodes) if (node.key == key) return node;
            assert(false); return nodes.front();
        };
        assert(find(QStringLiteral("unreadable")).weight == 2 * pageBytes);
        assert(find(QStringLiteral("unscanned")).weight == 2 * pageBytes);
        if (mode == 0) {
            assert(find(QStringLiteral("use:0")).weight == 3 * pageBytes);
            assert(find(QStringLiteral("use:1")).weight == pageBytes);
            assert(find(QStringLiteral("use:15")).weight == pageBytes);
            assert(find(QStringLiteral("available")).weight == 2 * pageBytes);
            assert(find(QStringLiteral("bad")).weight == pageBytes);
        } else assert(find(QStringLiteral("state:6")).weight == 3 * pageBytes);
    }
    Accounting unvisited; unvisited.expected = 31;
    const auto empty = pfnMetricAreaNodes(unvisited, 0);
    double unvisitedTotal = 0;
    for (const auto& node : empty) {
        unvisitedTotal += node.weight;
        assert(node.key == QStringLiteral("unscanned") || node.weight == 0);
    }
    assert(unvisitedTotal == 31 * pageBytes);
    // Independent native state matrix: neither available nor bad pages may
    // appear again among the in-use classes in category mode.
    Accounting states; states.expected = useCount * 8;
    for (std::size_t use = 0; use < useCount; ++use)
        for (unsigned state = 0; state < 8; ++state) states.add({state << 4, 0}, static_cast<Use>(use));
    for (int mode : {0, 1}) {
        double total = 0;
        for (const auto& node : pfnMetricAreaNodes(states, mode)) total += node.weight;
        assert(total == states.expected * pageBytes);
    }
    Scan ledger; ledger.epoch = QStringLiteral("ledger-a"); ledger.accounting = counts; ledger.ownerCoverage.initialize(counts);
    Group first; first.use = Use::Private; first.pages = 1; first.activePages = 1; first.pagesByState[6] = 1;
    first.pid = 17; first.ownerCreateTime = 100; first.ownerLifetimeVerified = true; first.name = QStringLiteral("alpha.exe");
    Group reused = first; reused.ownerCreateTime = 200; reused.name = QStringLiteral("beta.exe");
    Group unresolved = first; unresolved.pid = 18; unresolved.ownerLifetimeVerified = false;
    Group oversized = first; oversized.pages = 100; oversized.pid = 999;
    Group file; file.use = Use::MappedFile; file.pages = 1; file.pagesByState[3] = 1;
    ledger.groups = {first, reused, unresolved, oversized, file};
    const auto leaves = [](const auto& nodes) { double total = 0; for (const auto& node : nodes) if (!node.group && node.known) total += node.weight; return total; };
    const auto tree = pfnProcessMetricAreaNodes(ledger);
    assert(leaves(tree) == 5 * pageBytes); // In-use denominator, not installed/free RAM.
    std::set<QString> keys;
    for (const auto& node : tree) {
        assert(keys.insert(node.key).second);
        assert(node.key != QStringLiteral("available") && node.key != QStringLiteral("unscanned"));
        assert(node.key != QStringLiteral("process:18:100") && node.key != QStringLiteral("process:999:100"));
        if (node.key == QStringLiteral("use:0")) assert(node.weight == pageBytes);
    }
    assert(keys.count(QStringLiteral("process:17:100")) && keys.count(QStringLiteral("process:17:200")));
    const auto backing = pfnBackingMetricAreaNodes(ledger);
    assert(leaves(backing) == 5 * pageBytes);
    assert(leaves(pfnBackingMetricAreaNodes(ledger, nullptr, true)) == 3 * pageBytes);
    Scan next = ledger; next.epoch = QStringLiteral("ledger-b");
    next.groups = {file, unresolved, reused, first, oversized};
    const auto positional = [](const QString& key) { return key.startsWith(QStringLiteral("group:"))
        || key.startsWith(QStringLiteral("group-state:")) || key.startsWith(QStringLiteral("group-other:")); };
    std::set<QString> oldDrilldownKeys;
    for (const auto& node : tree) if (positional(node.key)) oldDrilldownKeys.insert(node.key);
    for (const auto& node : backing) if (positional(node.key)) oldDrilldownKeys.insert(node.key);
    Scan fallback = ledger; fallback.groups[0].pagesByState = {};
    bool haveOther = false;
    for (const auto& node : pfnProcessMetricAreaNodes(fallback)) if (positional(node.key)) {
        oldDrilldownKeys.insert(node.key);
        if (node.key.startsWith(QStringLiteral("group-other:"))) haveOther = true;
    }
    assert(haveOther);
    const auto nextTree = pfnProcessMetricAreaNodes(next);
    const auto nextBacking = pfnBackingMetricAreaNodes(next);
    for (const auto& node : nextTree) if (positional(node.key)) assert(oldDrilldownKeys.count(node.key) == 0);
    for (const auto& node : nextBacking) if (positional(node.key)) assert(oldDrilldownKeys.count(node.key) == 0);
    next.groups[3].pagesByState = {};
    for (const auto& node : pfnProcessMetricAreaNodes(next)) if (positional(node.key)) assert(oldDrilldownKeys.count(node.key) == 0);
    std::set<QString> nextProcessKeys;
    for (const auto& node : nextTree) if (node.key.startsWith(QStringLiteral("process:"))) nextProcessKeys.insert(node.key);
    assert(nextProcessKeys.count(QStringLiteral("process:17:100")) && nextProcessKeys.count(QStringLiteral("process:17:200")));
    assert(leaves(nextTree) == leaves(tree) && leaves(nextBacking) == leaves(backing));
    assert(ledger.ownerCoverage.resolve(Use::Private, first.pagesByState));
    assert(ledger.ownerCoverage.resolve(Use::Private, reused.pagesByState));
    ledger.ownerCoverage.objectKeyKnown[static_cast<std::size_t>(Use::MappedFile)][3] = 1;
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 4)) == 2 * pageBytes);
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 5)) == 3 * pageBytes);
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 6)) == 3 * pageBytes);
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 7)) == pageBytes);
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 8)) == 8 * pageBytes);
    ledger.ownerCoverage.resolved[0][6] += 1;
    assert(leaves(pfnCoverageMetricAreaNodes(ledger, 4)) == 0);
    std::cout << "PFN_METRIC_AREA=PASS PHYSICAL_PARTITION=1 PROCESS_HIERARCHY=1 IN_USE_DENOMINATOR=1 COVERAGE_METRICS=1 DRIVER_IO=0\n";
}
'''
    developer = next((p for p in (
        Path('C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/VsDevCmd.bat'),
        Path('D:/Software/VS/Common7/Tools/VsDevCmd.bat')) if p.is_file()), None)
    if not developer:
        raise SystemExit('HostX64 MSVC developer environment is required')
    with tempfile.TemporaryDirectory(prefix='pfn-area-', dir=root / 'output') as folder:
        work = Path(folder)
        cpp = work / 'pfn-area.cpp'
        cpp.write_text(fixture, encoding='utf-8')
        binary = work / 'pfn-area.exe'
        command = ['cl', '/nologo', '/std:c++20', '/Zc:__cplusplus', '/utf-8', '/EHsc', '/MD', '/W4', '/WX', '/external:W0',
                   '/I' + str(root), '/external:I' + str(qt / 'include'),
                   '/external:I' + str(qt / 'include/QtCore'), '/external:I' + str(qt / 'include/QtGui'),
                   '/external:I' + str(qt / 'include/QtWidgets'), str(cpp), '/Fe:' + str(binary),
                   '/link', '/LIBPATH:' + str(qt / 'lib'), 'Qt6Core.lib', 'Qt6Gui.lib']
        script = work / 'build.cmd'
        script.write_text('@echo off\ncall "' + str(developer) + '" -arch=x64 -host_arch=x64 >nul\n'
                          + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding='utf-8')
        subprocess.run(['cmd', '/d', '/c', str(script)], cwd=work, check=True)
        env = dict(os.environ)
        env['PATH'] = str(qt / 'bin') + os.pathsep + env.get('PATH', '')
        subprocess.run([str(binary)], env=env, check=True)


if __name__ == '__main__':
    main()
