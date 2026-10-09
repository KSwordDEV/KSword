"""Run production DDMA editor read/write methods against scripted backends.

The methods are extracted unchanged from DdmaPage.cpp. Small Qt/editor shims
exercise write consent, snapshot provenance and actual-byte readback without
loading a driver or performing DMA. Requires G++ or Clang++, not Qt/MSBuild.
"""

from pathlib import Path
import argparse
import os
import shutil
import subprocess

from test_memory_transfer import extract_function


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Ksword5.1/Ksword5.1/MemoryDock/DdmaPage.cpp"

QT = r'''
#pragma once
#include <cstdint>
#include <string>
#include <utility>
using qsizetype = std::int64_t;
class QString {
public:
    std::string value;
    QString() = default;
    QString(const char* text) : value(text) {}
    QString replaceArg(const std::string& text) const {
        QString result=*this;
        const auto position=result.value.find('%');
        if (position!=std::string::npos) {
            auto end=position+1;
            while (end<result.value.size() && result.value[end]>='0' && result.value[end]<='9') ++end;
            result.value.replace(position,end-position,text);
        }
        return result;
    }
    template<class T> QString arg(const T& value) const { return replaceArg(std::to_string(value)); }
    QString arg(const QString& text) const { return replaceArg(text.value); }
    bool isEmpty() const { return value.empty(); }
    QString& operator+=(const QString& text) { value += text.value; return *this; }
};
#define QStringLiteral(text) QString(text)
class QByteArray {
public:
    std::string value;
    QByteArray() = default;
    QByteArray(const char* bytes) : value(bytes) {}
    qsizetype size() const { return static_cast<qsizetype>(value.size()); }
    void clear() { value.clear(); }
    char& operator[](qsizetype index) { return value.at(index); }
    char operator[](qsizetype index) const { return value.at(index); }
    QByteArray mid(qsizetype offset, qsizetype length) const {
        QByteArray result; result.value = value.substr(offset, length); return result;
    }
    bool operator==(const QByteArray& other) const { return value == other.value; }
    bool operator!=(const QByteArray& other) const { return !(*this == other); }
};
'''

PRELUDE = r'''
#include "MemoryAccessBackend.h"
#include <deque>
#include <functional>
#include <iostream>
#include <stdexcept>
struct QLabel { QString value; void setText(const QString& text) { value = text; } };
struct QPushButton { bool enabled=false; void setEnabled(bool value) { enabled=value; } };
struct QLineEdit { QString text() const { return QString("1000"); } };
struct QSpinBox { int value() const { return 4; } };
namespace ks::ui {
enum class DisassemblyArchitecture { X86, X64 };
struct SnapshotWorkbenchWidget {
    QByteArray original, bytes;
    std::uint64_t base=0x1000, anchor=0x1000;
    bool editable=false;
    void setEditable(bool value) { editable=value; }
    QByteArray data() const { return bytes; }
    QByteArray originalBytes() const { return original; }
    std::uint64_t baseAddress() const { return base; }
    bool hasChanges() const { return original != bytes; }
    DisassemblyArchitecture currentArchitecture() const { return DisassemblyArchitecture::X64; }
    void setSnapshot(const QByteArray& value, std::uint64_t address, DisassemblyArchitecture,
                     std::uint64_t selected, const QString&) { original=value; bytes=value; base=address; anchor=selected; }
    void clear() { original.clear(); bytes.clear(); }
};
// 原生 HEX 视图读取同一个快照模型，长度/基址/插入点不会与快照缓存分叉。
struct HexView {
    const SnapshotWorkbenchWidget* snapshot;
    std::uint64_t bufferSize() const { return static_cast<std::uint64_t>(snapshot->data().size()); }
    std::uint64_t baseAddress() const { return snapshot->baseAddress(); }
    std::uint64_t caretAddress() const { return bufferSize() == 0 ? 0 : snapshot->anchor; }
};
}
struct QMessageBox {
    enum StandardButton { Yes=1, No=2 };
    static inline std::deque<StandardButton> answers;
    static inline std::function<void()> afterAnswer;
    static StandardButton warning(void*, const QString&, const QString&,
                                  int=No, StandardButton=No) {
        const auto answer=answers.empty() ? No : answers.front();
        if (!answers.empty()) answers.pop_front();
        if (afterAnswer) { auto callback=std::move(afterAnswer); afterAnswer={}; callback(); }
        return answer;
    }
    static StandardButton question(void* p, const QString& a, const QString& b,
                                   int options, StandardButton fallback) {
        return warning(p,a,b,options,fallback);
    }
};
namespace fake {
using namespace ksword::memory_backend;
QByteArray memory;
DdmaSession session;
std::uint64_t generation=1;
int reads=0, writes=0;
bool wrongWrite=false, failedWriteMutation=false;
std::deque<AccessOutcome> scriptedWrites;
std::function<AccessOutcome(int)> scriptedRead;
AccessOutcome successRead() { AccessOutcome result; result.ok=true; result.data=memory; result.bytesDone=memory.size(); return result; }
}
namespace ksword::memory_backend {
const DdmaSession& currentDdmaSession() { return fake::session; }
std::uint64_t ddmaSessionGeneration() { return fake::generation; }
bool isDdmaUsable(const DdmaSession& value, QString*) { return value.configured && value.scratchAcknowledged; }
AccessOutcome readPhysical(MemoryAccessBackend, const DdmaSession&, std::uint64_t, std::uint64_t, bool) {
    ++fake::reads;
    return fake::scriptedRead ? fake::scriptedRead(fake::reads) : fake::successRead();
}
AccessOutcome writePhysical(MemoryAccessBackend, const DdmaSession&, std::uint64_t address,
                            const QByteArray& bytes, bool) {
    ++fake::writes;
    AccessOutcome result;
    if (!fake::scriptedWrites.empty()) { result=fake::scriptedWrites.front(); fake::scriptedWrites.pop_front(); }
    else { result.ok=true; result.bytesDone=bytes.size(); }
    if (result.ok) {
        fake::memory.value.replace(static_cast<std::size_t>(address-0x1000),bytes.size(),bytes.value);
        if (fake::wrongWrite) fake::memory[1]='Z';
    } else if (fake::failedWriteMutation) fake::memory[1]='Y';
    return result;
}
}
class DdmaPage {
public:
    ksword::memory_backend::DdmaSession m_session, m_snapshotSession;
    std::uint64_t m_snapshotSessionGeneration=1, m_snapshotAddress=0x1000;
    QByteArray m_originalBytes, m_editedBytes;
    bool m_hasSnapshot=true;
    ks::ui::SnapshotWorkbenchWidget editor;
    ks::ui::SnapshotWorkbenchWidget* m_accessMemoryEditor=&editor;
    ks::ui::HexView hex{&editor};
    ks::ui::HexView* m_accessHexEditor=&hex;
    QLabel status;
    QLabel* m_accessStatusLabel=&status;
    QPushButton button;
    QPushButton* m_accessWriteButton=&button;
    QLineEdit address;
    QLineEdit* m_accessAddressEdit=&address;
    QSpinBox length;
    QSpinBox* m_accessLengthSpin=&length;
    void resetAccessSnapshot();
    void refreshAccessEditorState();
    void readPhysicalFromUi();
    void writePhysicalFromUi();
    static bool parseAddressText(const QString&, std::uint64_t& result) { result=0x1000; return true; }
    static QString formatAddress(std::uint64_t) { return QString("1000"); }
};
'''

TESTS = r'''
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
bool statusHas(const DdmaPage& page, const char* text) { return page.status.value.value.find(text)!=std::string::npos; }
void setup(DdmaPage& page) {
    fake::memory=QByteArray("ABCD"); fake::generation=1; fake::reads=0; fake::writes=0;
    fake::wrongWrite=false; fake::failedWriteMutation=false;
    fake::scriptedWrites.clear(); fake::scriptedRead={};
    fake::session={}; fake::session.configured=true; fake::session.scratchAcknowledged=true;
    QMessageBox::answers={QMessageBox::Yes}; QMessageBox::afterAnswer={};
    page.m_session=fake::session; page.m_snapshotSession=fake::session;
    page.m_originalBytes=fake::memory; page.m_editedBytes=QByteArray("AXCD");
    page.editor.original=page.m_originalBytes; page.editor.bytes=page.m_editedBytes;
}
int main() {
    try {
        { DdmaPage page; setup(page); page.writePhysicalFromUi();
          check(fake::writes==1 && fake::reads==2, "successful write must re-read baseline and final state");
          check(statusHas(page,"DDMA 写入成功") && page.m_originalBytes==QByteArray("AXCD"),"only verified write becomes success"); }
        { DdmaPage page; setup(page); fake::memory=QByteArray("AQCD"); page.writePhysicalFromUi();
          check(fake::writes==0 && page.editor.bytes==fake::memory, "stale baseline must never be overwritten");
          check(statusHas(page,"目标内存已变化"),"baseline conflict must be reported"); }
        { DdmaPage page; setup(page); fake::wrongWrite=true; page.writePhysicalFromUi();
          check(!statusHas(page,"DDMA 写入成功") && statusHas(page,"不一致"),"successful transport with wrong bytes must fail");
          check(page.editor.bytes==fake::memory,"mismatch must display actual bytes"); }
        { DdmaPage page; setup(page); ksword::memory_backend::AccessOutcome failed; failed.failureText=QString("original-write-failure");
          fake::scriptedWrites.push_back(failed); fake::failedWriteMutation=true; page.writePhysicalFromUi();
          check(fake::reads==2 && page.editor.bytes==fake::memory,"failed partial writer must refresh actual state");
          check(statusHas(page,"original-write-failure") && !statusHas(page,"写入成功"),"readback cannot erase write failure"); }
        { DdmaPage page; setup(page); fake::scriptedRead=[](int count) { auto result=fake::successRead();
              if (count==2) { result.partial=true; result.data=QByteArray("AX"); } return result; };
          page.writePhysicalFromUi(); check(!page.m_hasSnapshot && !page.editor.editable && page.editor.bytes.size()==0,"incomplete readback must clear and disable"); }
        { DdmaPage page; setup(page); QMessageBox::afterAnswer=[]() { ++fake::generation; }; page.writePhysicalFromUi();
          check(fake::writes==0 && fake::reads==0,"changed global session generation must reject modal continuation"); }
        { DdmaPage page; setup(page); ++fake::generation; page.refreshAccessEditorState();
          check(!page.editor.editable && !page.button.enabled,"reopened session must disable old snapshot"); }
        { DdmaPage page; setup(page); ksword::memory_backend::AccessOutcome force; force.forceRequired=true;
          fake::scriptedWrites.push_back(force); QMessageBox::answers={QMessageBox::Yes,QMessageBox::No};
          page.writePhysicalFromUi(); check(fake::writes==1 && fake::reads==2,"force cancellation must not retry");
          check(page.editor.bytes==QByteArray("AXCD") && page.editor.original==QByteArray("ABCD"),"force cancellation without writes must retain staging"); }
        { DdmaPage page; setup(page); fake::scriptedRead=[](int) { auto result=fake::successRead(); result.scratchDirty=true; return result; };
          page.writePhysicalFromUi(); check(statusHas(page,"严重告警"),"scratch damage must be reported even on successful readback"); }
        { DdmaPage page; setup(page); page.editor.bytes=page.editor.original; fake::scriptedRead=[](int) {
              auto result=fake::successRead(); result.partial=true; result.data=QByteArray("AB"); return result; };
          page.readPhysicalFromUi(); check(!page.m_hasSnapshot && page.editor.bytes.size()==0,"partial fresh read must clear stale editor"); }
        { DdmaPage page; setup(page); fake::scriptedRead=[](int count) { auto result=fake::successRead();
              if (count==2) { fake::memory[1]='Q'; result.data=fake::memory; } return result; };
          ksword::memory_backend::AccessOutcome force; force.forceRequired=true;
          fake::scriptedWrites.push_back(force); QMessageBox::answers={QMessageBox::Yes,QMessageBox::Yes};
          page.writePhysicalFromUi(); check(fake::writes==1 && fake::reads==3,"force retry must revalidate live original");
          check(page.editor.bytes==fake::memory && !statusHas(page,"写入成功"),"force conflict must refresh actual state"); }
        { DdmaPage page; setup(page); ksword::memory_backend::AccessOutcome failed;
          failed.failureText=QString("failed-even-with-matching-readback"); fake::scriptedWrites.push_back(failed);
          fake::scriptedRead=[](int count) { if (count==2) fake::memory=QByteArray("AXCD"); return fake::successRead(); };
          page.writePhysicalFromUi(); check(!statusHas(page,"写入成功") && statusHas(page,"failed-even-with-matching-readback"),
              "matching final readback cannot infer a failed writer succeeded"); }
        { DdmaPage page; setup(page); ksword::memory_backend::AccessOutcome force; force.forceRequired=true;
          fake::scriptedWrites.push_back(force); QMessageBox::answers={QMessageBox::Yes,QMessageBox::Yes};
          QMessageBox::afterAnswer=[]() { QMessageBox::afterAnswer=[]() { ++fake::generation; }; };
          page.writePhysicalFromUi(); check(fake::writes==1 && fake::reads==1,
              "global session change during force confirmation must never retry"); }
        { DdmaPage page; setup(page); page.editor.anchor=0x1002; page.writePhysicalFromUi();
          check(fake::writes==1 && page.editor.anchor==0x1002,
              "verified readback preserves the native HexView caret address"); }
        std::cout << "DDMA editor production workflow: 14 cases passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".out" / "ddma-editor-tests",
                        help="Existing output directory; no temporary build directories are created")
    args = parser.parse_args()
    compiler = os.environ.get("CXX") or shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        raise RuntimeError("G++ or Clang++ is required")
    source = SOURCE.read_text(encoding="utf-8-sig")
    names = ["sameDdmaSession", "ddmaSnapshotIdentity"]
    names += ["DdmaPage::" + name for name in (
        "resetAccessSnapshot", "refreshAccessEditorState", "readPhysicalFromUi", "writePhysicalFromUi")]
    production = "\n".join(extract_function(source, name) for name in names)
    path = args.output.resolve()
    if not path.is_dir():
        raise RuntimeError("--output must point to an existing directory")
    (path / "qt_shim.h").write_text(QT, encoding="utf-8")
    for name in ("QString", "QByteArray"):
        (path / name).write_text('#include "qt_shim.h"\n', encoding="utf-8")
    cpp = path / "workflow.cpp"
    exe = path / "workflow.exe"
    cpp.write_text(PRELUDE + production + TESTS, encoding="utf-8")
    include = ROOT / "Ksword5.1/Ksword5.1/MemoryDock"
    command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2",
               "-I", str(path), "-I", str(include), str(cpp), "-o", str(exe)]
    subprocess.run(command, check=True)
    environment = dict(os.environ)
    environment["PATH"] = str(Path(compiler).parent) + os.pathsep + environment.get("PATH", "")
    subprocess.run([str(exe)], check=True, env=environment)


if __name__ == "__main__":
    main()
