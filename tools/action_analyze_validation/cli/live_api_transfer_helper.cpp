// live_api_transfer_helper.cpp
// 活采候选链 CLI 夹具的自有导出线程入口。只导出一个可由父进程 CreateRemoteThread
// 调用的例程；父进程从本模块解析 RVA，再加子进程中该模块的真实基址。
// 不加载 Agent、不查询目标、不写文件；线程只在自有夹具子进程中执行。

#define _WIN32_WINNT 0x0A00
#include <windows.h>

extern "C" {

// 子进程映像内的自有导出线程例程；返回一个可核对的常量，不访问外部对象。
__declspec(dllexport) DWORD WINAPI LiveTransferThreadProc(LPVOID)
{
    return 0x4C545241u; // "LTRA"
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    return reason != DLL_PROCESS_DETACH;
}

} // extern "C"
