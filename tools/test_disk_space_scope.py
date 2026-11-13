"""Run exact production MFT folder scoping and projection with controlled values.

No disk enumeration, raw volume handle, widget or alternate scoping algorithm.
"""
from pathlib import Path
import os
import subprocess
from native_msvc_test_support import find_msvc_developer_environment, qt_root
from ntfs_index_projection_test import function

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "Ksword5.1/Ksword5.1"


def main():
    page = (APP / "FileDock/DiskSpacePage.cpp").read_text(encoding="utf-8-sig")
    backend = (APP / "FileDock/NtfsFastIndex.cpp").read_text(encoding="utf-8-sig")
    code = r'''
#include "FileDock/NtfsFastIndex.h"
#include <QDateTime>
#include <QDir>
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <limits>
#include <utility>
#include <cstdio>
using Index = ks::files::NtfsFastIndex;
using Entry = ks::files::NtfsIndexEntry;
'''
    code += "namespace ks::files {\n" + function(backend, "QString NtfsFastIndex::fullPath(") + "\n}\n"
    code += function(page, "quint64 addBytes(") + "\n"
    code += page[page.index("struct Totals "):page.index("ProjectionPtr project(")]
    for signature in ("ProjectionPtr project(", "QString normalizedFolder(", "Index::Snapshot scopeMftSnapshot("):
        code += function(page, signature) + "\n"
    code += r'''
int main() {
    int checks = 0, failures = 0;
    const auto check = [&](bool value) { ++checks; if (!value) { ++failures; std::printf("FAILED_CHECK=%d\n", checks); } };
    auto snapshot = std::make_shared<ks::files::NtfsIndexSnapshot>();
    snapshot->volumeRoot = QStringLiteral("T:\\"); snapshot->rootReference = 1; snapshot->complete = true;
    const auto add = [&](quint64 id, quint64 parent, const char* name, bool directory, quint64 size = 0) {
        Entry entry; entry.fileReference = id; entry.parentReference = parent; entry.name = QString::fromUtf8(name);
        entry.attributes = directory ? 0x10U : 0U; entry.sizeKnown = true; entry.logicalBytes = size; entry.allocatedBytes = size * 2;
        entry.names.append({parent, entry.name}); snapshot->entries.insert(id, entry);
    };
    add(1, 1, ".", true); add(2, 1, "chosen", true); add(3, 1, "chosen-other", true);
    add(4, 2, "nested", true); add(5, 4, "leaf.bin", false, 7); add(6, 3, "outside.bin", false, 99);
    add(7, 3, "outside-alias.bin", false, 13); snapshot->entries[7].names.append({4, QStringLiteral("inside-alias.bin")});
    add(8, 2, "two-links.bin", false, 17); snapshot->entries[8].names.append({4, QStringLiteral("second-link.bin")});
    add(9, 2, "unknown.bin", false, 55); snapshot->entries[9].sizeKnown = false;
    add(10, 2, "junction", true); snapshot->entries[10].attributes |= 0x400U;
    add(11, 10, "target-only.bin", false, 800);
    add(12, 3, "unmeasured-name.bin", false, 32); snapshot->entries[12].hasAttributeList = true; snapshot->entries[12].attributeListResident = false;
    snapshot->namesIncompleteCount = 1;
    const auto cancel = std::make_shared<std::atomic_bool>(false);
    const auto scoped = scopeMftSnapshot(snapshot, QStringLiteral("t:\\CHOSEN\\"), cancel);
    check(bool(scoped)); check(scoped->rootReference == 2); check(scoped->entries.size() == 7);
    check(!scoped->entries.contains(3)); check(!scoped->entries.contains(6)); check(!scoped->entries.contains(11));
    check(scoped->entries.contains(10)); check(scoped->entries[2].parentReference == 2);
    check(scoped->entries[7].parentReference == 4); check(scoped->entries[7].name == QStringLiteral("inside-alias.bin"));
    check(Index::fullPath(*scoped, 7).compare(QStringLiteral("t:\\CHOSEN\\nested\\inside-alias.bin"), Qt::CaseInsensitive) == 0);
    check(scoped->unknownSizeCount == 1); check(scoped->namesIncompleteCount == 0);
    const auto projection = project(scoped, cancel); check(bool(projection));
    check(projection->directories[2].totals.files == 4); check(projection->directories[2].totals.logical == 37);
    check(projection->directories[2].totals.allocated == 74); check(projection->directories[2].totals.unknown == 1);
    check(projection->directories[10].totals.files == 0); check(projection->children[4].count(7) == 1);
    check(projection->directories[4].totals.logical == 20); // 7+13; second name of #8 is not counted again.
    check(!scopeMftSnapshot(snapshot, QStringLiteral("T:\\missing"), cancel));
    check(!scopeMftSnapshot(snapshot, QStringLiteral("T:\\chosen\\nested\\leaf.bin"), cancel));
    const auto all = scopeMftSnapshot(snapshot, QStringLiteral("T:\\"), cancel); check(bool(all));
    check(all->entries.contains(6)); check(!all->entries.contains(11)); check(all->namesIncompleteCount == 1);
    cancel->store(true); check(!scopeMftSnapshot(snapshot, QStringLiteral("T:\\chosen"), cancel));
    std::printf("DISK_SPACE_SCOPE_CHECKS=%d FAILURES=%d NATIVE_IO=0 GUI=0\n", checks, failures);
    return failures ? 1 : 0;
}
'''
    work = ROOT / ".codex-build-logs/disk-space-scope"
    work.mkdir(parents=True, exist_ok=True)
    fixture = work / "fixture.cpp"
    fixture.write_text(code, encoding="utf-8")
    qt = qt_root()
    binary = work / "test.exe"
    command = ["cl", "/nologo", "/std:c++20", "/O2", "/EHsc", "/MD", "/W4", "/WX", "/utf-8", "/Zc:__cplusplus", "/DNOMINMAX", "/external:W0",
               "/external:I" + str(qt / "include"), "/external:I" + str(qt / "include/QtCore"), "/I" + str(APP), str(fixture), "/Fe:" + str(binary),
               "/Fo:" + str(work) + "\\", "/link", "/LIBPATH:" + str(qt / "lib"), "Qt6Core.lib"]
    script = work / "build.cmd"
    script.write_text('@echo off\ncall "' + str(find_msvc_developer_environment()) + '" -arch=x64 -host_arch=x64 >nul\n'
                      + subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding="utf-8")
    subprocess.run(["cmd", "/d", "/c", str(script)], cwd=work, check=True)
    env = dict(os.environ)
    env["PATH"] = str(qt / "bin") + os.pathsep + env.get("PATH", "")
    subprocess.run([str(binary)], cwd=work, env=env, check=True)


if __name__ == "__main__":
    main()
