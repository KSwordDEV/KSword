#!/usr/bin/env python3
"""直接执行本脚本：非阻塞获取 CLI 验收互斥，再以低优先级构建并运行无窗口测试。"""
import ctypes
from ctypes import wintypes
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # 固定仓库根，不使用任意临时目录。
MSBUILD = Path(r'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe')  # 本机已核对的 x64 宿主。
PROJ = ROOT / 'tools/action_analyze_validation/api_transfer_tree/ApiTransferCandidateWindowValidation.vcxproj'
EXE = ROOT / 'Ksword5.1/x64/Release/ApiTransferCandidateWindowValidation.exe'  # 统一正式输出。
MUTEX = r'Local\KSword.ActionAnalyze.CliValidation'  # 与正式 CLI 验收共用的互斥身份。

# 显式声明 HANDLE 和指针宽度，防止 64 位 Python 默认 c_int 截断内核句柄。
k32 = ctypes.WinDLL('kernel32', use_last_error=True)  # 本进程的原生同步与优先级接口。
k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
k32.CreateMutexW.restype = wintypes.HANDLE
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.ReleaseMutex.argtypes = [wintypes.HANDLE]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]


def main():
    """无参数；持锁完成构建及运行，返回其退出码，忙时返回 2，原生错误抛出异常。"""
    handle = k32.CreateMutexW(None, False, MUTEX)  # 存在同名对象不等于它正被持有。
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    acquired = False  # 只在本线程确实取得所有权后释放互斥。
    try:
        state = k32.WaitForSingleObject(handle, 0)  # 零等待，绝不与其它 CLI 验收重叠。
        if state == 258:
            print('MUTEX_BUSY=1')
            return 2
        if state not in (0, 128):  # 正常取得及 abandoned 均授予本线程所有权。
            raise ctypes.WinError(ctypes.get_last_error())
        acquired = True
        if not k32.SetPriorityClass(k32.GetCurrentProcess(), 0x00004000):
            raise ctypes.WinError(ctypes.get_last_error())
        print('MUTEX_HELD=1 PRIORITY=BelowNormal HOST=HostX64', flush=True)
        if not MSBUILD.exists():
            print(f'NO_MSBUILD={MSBUILD}')
            return 3

        # 固定工程声明 IntDir/OutDir；所有编译子进程继承 BelowNormal 优先级。
        cmd = [str(MSBUILD), str(PROJ), '/t:Build', '/p:Configuration=Release', '/p:Platform=x64',
               '/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64',
               '/p:PROCESSOR_ARCHITEW6432=AMD64', '/m:1', '/v:minimal']  # 不使用 shell 拼接命令。
        build = subprocess.run(cmd, cwd=str(ROOT))  # 实际编译回执，失败时不运行旧产物。
        print(f'BUILD_EXIT={build.returncode}', flush=True)
        if build.returncode:
            return build.returncode
        if not EXE.exists():
            print(f'NO_EXE={EXE}')
            return 4
        run = subprocess.run([str(EXE)], cwd=str(ROOT))  # 仅运行专用无窗口候选窗口测试。
        print(f'TEST_EXIT={run.returncode}', flush=True)
        return run.returncode
    finally:
        if acquired:
            k32.ReleaseMutex(handle)
        k32.CloseHandle(handle)


if __name__ == '__main__':
    raise SystemExit(main())
