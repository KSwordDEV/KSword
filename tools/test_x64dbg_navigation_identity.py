"""离线编译生产导航身份策略和 driver 读取身份见证；不访问真实进程或调试器。

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

    editor = (UI / "MemoryEditorWidget.InlineAssembly.cpp").read_text(encoding="utf-8-sig")
    context = body(editor, "void MemoryEditorWidget::setProcessContext(")
    assert "SnapshotAddressKind::FileOffset" in context
    assert "ProcessCreateTime100ns(" not in context
    assert "HasCapturedIdentity(pid, createTime100ns)" in context
    viewer = (MEMORY / "MemoryDock.ViewBreakpointUtil.cpp").read_text(encoding="utf-8-sig")
    reload_viewer = body(viewer, "void MemoryDock::reloadMemoryViewerPage()")
    assert reload_viewer.index("::GetProcessTimes(navigationHandle, &created") < reload_viewer.index("readOutcome =")
    assert "navigationGeneration == m_processAttachmentGeneration.load()" in reload_viewer
    loaded_viewer = body(viewer, "void MemoryDock::loadMemoryViewerSnapshot(")
    assert "GetProcessTimes(" not in loaded_viewer
    assert "processVirtual ? m_viewerSnapshotProcessCreateTime100ns : 0ULL" in loaded_viewer
    cleared_viewer = body(viewer, "void MemoryDock::clearMemoryViewerSnapshot()")
    assert "m_viewerSnapshotProcessCreateTime100ns = 0;" in cleared_viewer

    driver = (MEMORY / "MemoryDock.DriverMemoryRw.cpp").read_text(encoding="utf-8-sig")
    read = body(driver, "void MemoryDock::driverReadMemoryFromUi()")
    assert read.index("const DriverNavigationIdentityLease navigationIdentity(") < read.index("::readVirtual(")
    assert read.count("m_driverMemorySnapshotProcessCreateTime100ns = navigationIdentity.verifiedCreation();") == 2
    reset = body(driver, "void MemoryDock::resetDriverMemoryRwState()")
    assert "m_driverMemorySnapshotProcessCreateTime100ns = 0;" in reset
    views = (MEMORY / "MemoryDock.DriverMemoryView.cpp").read_text(encoding="utf-8-sig")
    assert "processVirtual ? m_driverMemorySnapshotProcessCreateTime100ns : 0ULL" in views
    assert "processVirtual ? toDwordPid(m_driverMemorySnapshotPid) : 0U,\n        m_driverMemorySnapshotProcessCreateTime100ns" in views


MOCKS = r'''
#include <cstdint>
#include <cstdlib>
#include <iostream>
using quint32 = std::uint32_t;
using quint64 = std::uint64_t;
struct FILETIME { std::uint32_t dwLowDateTime = 0, dwHighDateTime = 0; };
struct FakeProcess { std::uint32_t pid; std::uint64_t created; bool alive = true; };
using HANDLE = FakeProcess*;
constexpr unsigned PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, SYNCHRONIZE = 0x100000;
constexpr int FALSE = 0;
constexpr unsigned WAIT_TIMEOUT = 258, WAIT_OBJECT_0 = 0;
FakeProcess* currentProcess = nullptr;
bool mayOpen = true, mayQuery = true;
unsigned opens = 0, closes = 0, checks = 0;
HANDLE OpenProcess(unsigned access, int, std::uint32_t pid) {
    ++opens;
    if (access != (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)) std::abort();
    return mayOpen && currentProcess && currentProcess->pid == pid ? currentProcess : nullptr;
}
void CloseHandle(HANDLE handle) { if (handle) ++closes; }
std::uint32_t GetProcessId(HANDLE handle) { return handle ? handle->pid : 0; }
unsigned WaitForSingleObject(HANDLE handle, unsigned) { return handle && handle->alive ? WAIT_TIMEOUT : WAIT_OBJECT_0; }
int GetProcessTimes(HANDLE handle, FILETIME* created, FILETIME*, FILETIME*, FILETIME*) {
    if (!handle || !mayQuery) return 0;
    created->dwLowDateTime = static_cast<std::uint32_t>(handle->created);
    created->dwHighDateTime = static_cast<std::uint32_t>(handle->created >> 32);
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

    FakeProcess process{42, 0x123456789ULL}, reused{42, 0xABCDEF123ULL};
    currentProcess = &process;
    {
        const DriverNavigationIdentityLease lease(42);
        require(lease.verifiedCreation() == process.created, "same held process survives the read");
        require(opens == 1, "verification does not reopen process by PID");
    }
    require(closes == 1, "successful read releases identity handle");
    {
        const DriverNavigationIdentityLease lease(42);
        process.alive = false;
        currentProcess = &reused;
        require(lease.verifiedCreation() == 0, "exit and PID reuse during read do not authorize new process");
        require(opens == 2, "recheck uses original handle after reuse");
    }
    require(closes == 2, "exited original handle is released");
    {
        const DriverNavigationIdentityLease lease(42);
        ++reused.created;
        require(lease.verifiedCreation() == 0, "creation mismatch rejects the read identity witness");
    }
    mayOpen = false;
    {
        const DriverNavigationIdentityLease lease(42);
        require(lease.verifiedCreation() == 0, "R0-only read may retain evidence without navigation authorization");
    }
    mayOpen = true;
    mayQuery = false;
    {
        const DriverNavigationIdentityLease lease(42);
        mayQuery = true;
        require(lease.verifiedCreation() == 0, "late identity query cannot replace missing pre-read witness");
    }
    require(closes == 4, "all acquired handles are released after rejected witnesses");
    const auto previousOpens = opens;
    {
        const DriverNavigationIdentityLease lease(0);
        require(lease.verifiedCreation() == 0, "kernel physical and DDMA targets have no process navigation identity");
    }
    require(opens == previousOpens, "nonprocess bytes cause no process query");
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
    driver = (MEMORY / "MemoryDock.DriverMemoryRw.cpp").read_text(encoding="utf-8-sig")
    lease = body(driver, "class DriverNavigationIdentityLease final") + ";\n"
    original = MOCKS + header + lease + TESTS

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
            "pre-read-witness-required": ("m_created != 0 && current == m_created ? m_created : 0", "current"),
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
