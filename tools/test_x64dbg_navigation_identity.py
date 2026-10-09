"""离线编译生产导航身份策略和工作台锚点身份见证；不访问真实进程或调试器。

QtGlobal 仅替换为标准整数 typedef；Win32 句柄查询仅用确定性 mocks。
支持 G++/Clang++ 或已载入 vcvars64 的 MSVC cl。--output 指向既有目录。
--negative-controls 在内存中撤回关键判断，要求同一套测试拒绝三个变异。
"""
from pathlib import Path
import argparse
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "Ksword5.1/Ksword5.1/UI"
MEMORY = ROOT / "Ksword5.1/Ksword5.1/MemoryDock"


def body(source, marker):
    """保留生产函数/类原文；花括号平衡只用于定位已知完整定义。"""
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start:index + 1]
    raise AssertionError(f"unclosed production definition: {marker}")


def verify_wiring():
    """检查纯策略确实接在 UI/插件/快照入口，防止 helper 测试成为未调用的死代码。"""
    navigation = (UI / "X64DbgNavigation.cpp").read_text(encoding="utf-8-sig")
    opened = body(navigation, "void Open(")
    action = body(navigation, "void AddAction(")
    assert "CheckCapturedIdentity(target, ProcessCreateTime100ns)" in opened
    assert opened.index("CheckCapturedIdentity") < opened.index("QFileInfo::exists(launcher())")
    assert "target.processCreateTime100ns =" not in opened + action
    assert "ProcessCreateTime100ns(" not in action
    assert "HasCapturedIdentity(target.pid, target.processCreateTime100ns)" in action

    host = (UI.parent / "PluginHost.cpp").read_text(encoding="utf-8-sig")
    menu = body(host, "void ks::plugin_host::populateTargetMenu(")
    assert "ProcessCreateTime100ns(" not in menu
    assert "const InvocationContext boundContext = context" in menu
    assert "action->setEnabled(ks::ui::x64dbg_navigation::HasCapturedIdentity(" in menu
    detail = (UI.parent / "ProcessDock/ProcessDetailWindow.BaseAndUi.cpp").read_text(encoding="utf-8-sig")
    assert "context.processCreateTime100ns = m_baseRecord.creationTime100ns;" in detail

    editor = (UI / "MemoryWorkbench/SnapshotWorkbenchWidget.Editing.cpp").read_text(encoding="utf-8-sig")
    context = body(editor, "void SnapshotWorkbenchWidget::setProcessContext(")
    assert "SnapshotAddressKind::FileOffset" in context
    assert "ProcessCreateTime100ns(" not in context
    assert "HasCapturedIdentity(pid, createTime100ns)" in context
    live = (UI / "MemoryWorkbench/MemoryWorkbenchView.RowCanvas.cpp").read_text(encoding="utf-8-sig")
    assert "const auto session = target_->session();" in live
    assert "!session.processCreateTime100ns" in live
    assert "{session.pid, session.processCreateTime100ns, address, view}" in live
    assert "ProcessCreateTime100ns(" not in live
    target = (UI / "MemoryWorkbench/WorkbenchTarget.cpp").read_text(encoding="utf-8-sig")
    attached = body(target, "void WorkbenchTarget::onDockAttached(")
    assert attached.index("AcquireAnchorFromDockHandle(attach.handle)") < attached.index("tracker_.FollowAttach(")
    assert "attach.pid, info.createTime100ns, attach.attachGeneration, info.addressBits" in attached
    detached = body(target, "void WorkbenchTarget::onDockDetached()")
    assert "ReleaseAnchorHandle(dockAnchorHandle_)" in detached
    assert "tracker_.FollowDetach()" in detached
    for retired in ("MemoryDock.DriverMemoryRw.cpp", "MemoryDock.DriverMemorySource.cpp", "MemoryDock.DriverMemoryView.cpp"):
        assert not (MEMORY / retired).exists(), "retired page implementation must not remain as a second identity path"


MOCKS = r'''
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
using quint32 = std::uint32_t;
using quint64 = std::uint64_t;
using DWORD = std::uint32_t;
using BOOL = int;
struct FILETIME { std::uint32_t dwLowDateTime = 0, dwHighDateTime = 0; };
struct FakeProcess {
    std::uint32_t pid;
    std::uint64_t created;
    bool alive = true;
    bool wow64 = false;
    DWORD exitCode = 259;
};
using HANDLE = FakeProcess*;
constexpr unsigned PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
constexpr int FALSE = 0;
constexpr DWORD STILL_ACTIVE = 259, ERROR_ACCESS_DENIED = 5, ERROR_INVALID_PARAMETER = 87;
FakeProcess* currentProcess = nullptr;
bool mayOpen = true, mayQuery = true, mayDuplicate = true, mayQueryExit = true;
unsigned opens = 0, closes = 0, duplicates = 0, checks = 0;
DWORD lastError = 0;
HANDLE GetCurrentProcess() { static FakeProcess self{1, 1}; return &self; }
HANDLE OpenProcess(unsigned access, int, std::uint32_t pid) {
    ++opens;
    if (access != PROCESS_QUERY_LIMITED_INFORMATION) std::abort();
    if (!mayOpen) { lastError=ERROR_ACCESS_DENIED; return nullptr; }
    if (!currentProcess || currentProcess->pid != pid) { lastError=ERROR_INVALID_PARAMETER; return nullptr; }
    return currentProcess;
}
BOOL DuplicateHandle(HANDLE, HANDLE source, HANDLE, HANDLE* output, DWORD access, BOOL, DWORD) {
    ++duplicates;
    if (access != PROCESS_QUERY_LIMITED_INFORMATION) std::abort();
    if (!mayDuplicate) { lastError=ERROR_ACCESS_DENIED; return FALSE; }
    *output=source;
    return source != nullptr;
}
DWORD GetLastError() { return lastError; }
void CloseHandle(HANDLE handle) { if (handle) ++closes; }
BOOL IsWow64Process(HANDLE handle, BOOL* wow64) {
    if (!handle) return FALSE;
    *wow64=handle->wow64;
    return 1;
}
BOOL GetExitCodeProcess(HANDLE handle, DWORD* code) {
    if (!handle || !mayQueryExit) return FALSE;
    *code=handle->alive ? STILL_ACTIVE : handle->exitCode;
    return 1;
}
BOOL GetProcessTimes(HANDLE handle, FILETIME* created, FILETIME* exited, FILETIME*, FILETIME*) {
    if (!handle || !mayQuery) return FALSE;
    created->dwLowDateTime=static_cast<std::uint32_t>(handle->created);
    created->dwHighDateTime=static_cast<std::uint32_t>(handle->created >> 32);
    exited->dwLowDateTime=handle->alive ? 0 : 1;
    exited->dwHighDateTime=0;
    return 1;
}
void require(bool passed, const char* why) {
    ++checks;
    if (!passed) { std::cerr << "FAIL: " << why << '\n'; std::exit(1); }
}
'''


TESTS = r'''
int main() {
    using namespace ks::ui::x64dbg_navigation;
    unsigned observations = 0;
    quint64 currentCreation = 200;
    const auto observe = [&](quint32 pid) noexcept {
        ++observations;
        require(pid == 42, "observer receives the captured PID");
        return currentCreation;
    };
    Target missing{42, 0, 0x1000, View::Dump};
    require(!HasCapturedIdentity(42, 0) && !HasCapturedIdentity(0, 100), "missing original identity is unauthorized");
    require(CheckCapturedIdentity(missing, observe) == IdentityStatus::Missing, "current process must not authorize old unknown snapshot");
    require(observations == 0 && missing.processCreateTime100ns == 0, "unknown snapshot never queries or receives replacement identity");
    require(CheckCapturedIdentity(Target{0, 100, 0, View::Disassembly}, observe) == IdentityStatus::Missing, "missing PID refuses navigation");
    require(observations == 0, "missing PID has no process query");
    const Target original{42, 100, 0x1000, View::Dump};
    require(CheckCapturedIdentity(original, observe) == IdentityStatus::Changed, "reused PID cannot inherit original snapshot");
    require(original.processCreateTime100ns == 100 && observations == 1, "changed observation does not replace original identity");
    currentCreation = 0;
    require(CheckCapturedIdentity(original, observe) == IdentityStatus::Unavailable, "exited or denied original is refused");
    currentCreation = 100;
    require(CheckCapturedIdentity(original, observe) == IdentityStatus::Matching, "same original identity remains navigable");
    require(CheckCapturedIdentity(Target{42, 100, 0, View::Disassembly}, observe) == IdentityStatus::Matching, "current instruction navigation still requires same original identity");
    require(HasCapturedIdentity(42, 100), "complete frozen identity enables the action");

    using namespace ks::ui;
    FakeProcess process{42, 0x123456789ULL}, reused{42, 0xABCDEF123ULL};
    currentProcess=&process;
    const auto dock = AcquireAnchorFromDockHandle(&process);
    require(dock.handle == &process && dock.createTime100ns == process.created && !dock.identityWeak,
        "Dock snapshot captures the exact held process creation time");
    require(dock.addressBits == 64 && duplicates == 1 && opens == 0,
        "Dock identity uses a limited duplicate without reopening the PID");
    ReleaseAnchorHandle(dock.handle);
    require(closes == 1, "copied Dock anchor is released");
    const auto pin = AcquireAnchorForPid(42);
    require(pin.handle == &process && pin.createTime100ns == process.created && !pin.identityWeak,
        "pinned target captures its own exact process identity");
    require(QueryAnchorAlive(pin.handle) == std::optional<bool>(true), "held target is alive");
    process.alive=false; currentProcess=&reused;
    require(pin.handle == &process && pin.createTime100ns != reused.created,
        "PID reuse cannot replace the original held target anchor");
    require(QueryAnchorAlive(pin.handle) == std::optional<bool>(false),
        "exit code 259 with nonzero exit time still means the original exited");
    ReleaseAnchorHandle(pin.handle);
    mayQuery=false;
    const auto weak=AcquireAnchorForPid(42);
    require(weak.identityWeak && weak.createTime100ns == 0 && weak.handle == &reused,
        "missing creation witness retains a releasable weak handle without navigation identity");
    mayQuery=true; ReleaseAnchorHandle(weak.handle);
    reused.wow64=true;
    const auto x86=AcquireAnchorForPid(42);
    require(x86.addressBits == 32 && x86.createTime100ns == reused.created, "WOW64 anchor keeps exact identity and 32-bit addressing");
    ReleaseAnchorHandle(x86.handle);
    mayOpen=false;
    const auto denied=AcquireAnchorForPid(42);
    require(denied.identityWeak && !denied.handle && !denied.targetGone && denied.lastError == ERROR_ACCESS_DENIED,
        "access denial does not invent target exit or identity");
    mayOpen=true; currentProcess=nullptr;
    const auto gone=AcquireAnchorForPid(42);
    require(gone.targetGone && gone.identityWeak && !gone.handle && gone.lastError == ERROR_INVALID_PARAMETER,
        "missing process is distinguished from denied process");
    const auto previousOpens=opens;
    require(AcquireAnchorForPid(0).handle == nullptr && opens == previousOpens, "nonprocess evidence does not open an anchor");
    require(QueryAnchorAlive(nullptr) == std::nullopt, "missing anchor has unknown liveness");
    mayQueryExit=false;
    require(QueryAnchorAlive(&reused) == std::nullopt, "failed liveness query remains unknown");
    require(closes == 4, "all acquired strong and weak anchors are released");
    std::cout << "PASS navigation identity checks=" << checks << '\n';
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "output/x64dbg_navigation_identity_tests.exe")
    parser.add_argument("--compiler", help="G++/Clang++/cl 命令或绝对路径；MSVC 需先载入 vcvars64")
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    compiler = (shutil.which(args.compiler) if args.compiler else
                shutil.which("g++") or shutil.which("clang++") or shutil.which("cl"))
    if not compiler:
        raise SystemExit("G++/Clang++ or a vcvars64-configured MSVC cl is required")
    if not args.output.parent.is_dir():
        raise SystemExit("--output must use an existing directory")
    verify_wiring()
    header = (UI / "X64DbgNavigation.h").read_text(encoding="utf-8-sig")
    header = header.replace("#pragma once", "").replace("#include <QtGlobal>", "")
    anchor_header = (UI / "MemoryWorkbench/WorkbenchTarget.h").read_text(encoding="utf-8-sig")
    anchor = (UI / "MemoryWorkbench/WorkbenchTarget.Anchor.cpp").read_text(encoding="utf-8-sig")
    declaration = body(anchor_header, "struct AnchorInfo") + ";\n"
    implementation = anchor[anchor.index("namespace ks::ui"):]
    original = MOCKS + header + "\nnamespace ks::ui {\n" + declaration + "}\n" + implementation + TESTS

    def run(source):
        output = args.output.resolve()
        msvc = Path(compiler).stem.casefold() == "cl"
        if msvc:
            # cl 不接受 stdin：源码/对象均放在调用方指定的既有输出目录，最后恢复原逻辑。
            source_file = output.with_suffix(".cpp")
            source_file.write_text(source, encoding="utf-8")
            command = [compiler, "/nologo", "/std:c++17", "/W4", "/WX", "/utf-8", "/EHsc",
                       f"/Fo{output.with_suffix('.obj')}", f"/Fd{output.with_suffix('.pdb')}", f"/Fe{output}", str(source_file)]
        else:
            command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-x", "c++", "-", "-o", str(output)]
        compiled = subprocess.run(command, input=None if msvc else source, text=True,
                                  encoding="utf-8", errors="replace", capture_output=True, timeout=60)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)
        return subprocess.run([str(args.output.resolve())], capture_output=True, text=True, timeout=15)

    control = run(original)
    assert control.returncode == 0, control.stderr
    print(control.stdout.strip())
    if args.negative_controls:
        changes = {
            "missing-original-identity": ("if (!HasCapturedIdentity(target.pid, target.processCreateTime100ns))", "if (false)"),
            "reused-pid-comparison": ("currentCreation == target.processCreateTime100ns", "currentCreation != target.processCreateTime100ns"),
            "exited-with-code-259": ("return FileTimeToUint64(exitTime) == 0;", "return true;"),
        }
        for name, (before, after) in changes.items():
            assert original.count(before) == 1, name
            rejected = run(original.replace(before, after, 1))
            assert rejected.returncode != 0 and "FAIL:" in rejected.stderr, name
            print(f"CAUGHT {name}: {rejected.stderr.strip()}")
        restored = run(original)
        assert restored.returncode == 0, restored.stderr
        print("PASS original production logic restored")


if __name__ == "__main__":
    main()
