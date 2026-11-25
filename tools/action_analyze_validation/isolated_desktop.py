"""在独立 Windows 桌面运行正式 GUI 回归，保留当前输入桌面。"""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import runpy
import subprocess
import sys
import uuid

import win32api
import win32con
import win32event
import win32process
import win32service


_TEST_DESKTOP = "KSWORD_ACTION_ANALYZE_TEST_DESKTOP"  # 供本轮脚本核对桌面归属。
_UOI_NAME = 2  # Win32 GetUserObjectInformation 的名称索引。
_UOI_IO = 6  # 直接查询测试桌面是否接收用户输入，不打开其它桌面。
_user32 = ctypes.WinDLL("user32", use_last_error=True)  # 桌面查询使用 Win32 的实际错误码。
_get_desktop_info = _user32.GetUserObjectInformationW
_get_desktop_info.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p)
_get_desktop_info.restype = wintypes.BOOL
_enum_callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_enum_desktop_windows = _user32.EnumDesktopWindows
_enum_desktop_windows.argtypes = (wintypes.HANDLE, _enum_callback, wintypes.LPARAM)
_enum_desktop_windows.restype = wintypes.BOOL


def require_isolated_desktop():
    """在创建产品进程或修改测试配置前，校验线程桌面和输入桌面。"""
    expected = os.environ.get(_TEST_DESKTOP)  # 由下方独立桌面启动器设置。
    current = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())  # 当前线程的实际桌面。
    if not expected or not expected.startswith("KSwordActionAnalyze-") or (
        win32service.GetUserObjectInformation(current, _UOI_NAME) != expected
    ):
        raise RuntimeError("Run GUI validation through tools/action_analyze_validation/isolated_desktop.py")
    receives_input = wintypes.BOOL()  # 由系统根据当前测试桌面句柄报告。
    if not _get_desktop_info(int(current), _UOI_IO, ctypes.byref(receives_input), ctypes.sizeof(receives_input), None):
        raise ctypes.WinError(ctypes.get_last_error())
    if receives_input.value:
        raise RuntimeError("The test desktop must remain separate from the input desktop")


class _GuiProcess:
    """提供现有回归所用的进程接口，所有退出和终止都使用原始句柄。"""

    def __init__(self, handle, pid, args):
        self._handle = handle  # 正式产品的进程句柄，退出后在 poll/wait 关闭。
        self.pid = pid  # 回归只向此 PID 的窗口发送消息。
        self._args = args  # 等待超时时用于回执。
        self.returncode = None  # 进程真实退出前保持空值。

    def wait(self, timeout):
        """等待本进程退出并保留退出码。"""
        if self.returncode is None:
            result = win32event.WaitForSingleObject(self._handle, int(timeout * 1000))
            if result == win32con.WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired(self._args, timeout)
            self.returncode = win32process.GetExitCodeProcess(self._handle)
            self._handle.Close()
        return self.returncode

    def poll(self):
        """读取现有退出状态，不额外等待。"""
        try:
            return self.wait(0)
        except subprocess.TimeoutExpired:
            return None

    def terminate(self):
        """请求终止本次测试创建的产品进程。"""
        if self.poll() is None:
            win32process.TerminateProcess(self._handle, 1)


def launch_gui(args, *, cwd, env=None):
    """显式设置 STARTUPINFO.lpDesktop，产品不会选取调用方的输入桌面。"""
    require_isolated_desktop()
    startup = win32process.STARTUPINFO()  # 此处需使用带 lpDesktop 的 Win32 启动参数。
    startup.lpDesktop = os.environ[_TEST_DESKTOP]
    command = subprocess.list2cmdline([os.fspath(arg) for arg in args])  # 用 Windows argv 规则转义参数。
    handle, thread, pid, _ = win32process.CreateProcess(
        os.fspath(args[0]), command, None, None, False, 0, env, os.fspath(cwd), startup
    )
    thread.Close()
    return _GuiProcess(handle, pid, args)


def test_windows():
    """返回测试桌面的顶层窗口，调用者仍按本次产品 PID 过滤。"""
    current = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())  # 用明确的桌面句柄定位窗口。
    handles = []  # 每轮返回当前桌面的独立快照。

    @_enum_callback
    def collect(window, _):
        handles.append(window)
        return True

    # 空桌面的首次枚举允许返回空结果。清零错误码以区分具体失败。
    ctypes.set_last_error(0)
    if not _enum_desktop_windows(int(current), collect, 0):
        error = ctypes.get_last_error()
        if error:
            raise ctypes.WinError(error)
    return handles


def main():
    """在本线程绑定测试桌面后运行指定回归，并在退出时释放桌面。"""
    if len(sys.argv) < 2:
        raise SystemExit("Usage: isolated_desktop.py SCRIPT [ARG ...]")
    script = Path(sys.argv[1]).resolve(strict=True)  # 待运行的现有回归入口。
    base = Path(__file__).resolve().parent  # 只接受本目录下的正式桌面回归脚本。
    if script.parent not in (base / "qt", base / "light") or script.suffix != ".py":
        raise SystemExit("Choose an ActionAnalyze GUI script under qt/ or light/")

    original = win32service.GetThreadDesktop(win32api.GetCurrentThreadId())  # 结束时恢复本线程桌面。
    name = f"KSwordActionAnalyze-{os.getpid()}-{uuid.uuid4().hex}"  # 每次运行独占桌面身份。
    access = (win32con.DESKTOP_CREATEWINDOW | win32con.DESKTOP_CREATEMENU | win32con.DESKTOP_ENUMERATE
              | win32con.DESKTOP_READOBJECTS | win32con.DESKTOP_WRITEOBJECTS)  # 测试窗口及其枚举所需权限。
    desktop = win32service.CreateDesktop(name, 0, access, None)  # 维持句柄直至正式窗口退出。
    try:
        desktop.SetThreadDesktop()
        os.environ[_TEST_DESKTOP] = name
        require_isolated_desktop()
        print(f"GUI_DESKTOP={name} INPUT_DESKTOP_SEPARATE=True", flush=True)
        sys.argv = [str(script), *sys.argv[2:]]
        sys.path.insert(0, str(script.parent))
        runpy.run_path(str(script), run_name="__main__")
    finally:
        os.environ.pop(_TEST_DESKTOP, None)
        # 进程退出时系统会清理从原应用取得的桌面引用。
        original.SetThreadDesktop()
        desktop.CloseDesktop()


if __name__ == "__main__":
    main()
