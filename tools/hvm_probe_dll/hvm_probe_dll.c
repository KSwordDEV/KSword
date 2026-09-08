/*
 * hvm_probe_dll.dll —— R-1 DLL 注入的证据。
 *
 * 它只做一件事：被加载时写一个文件，内容是加载它的那个进程的 PID。
 *
 * 为什么要落盘而不是弹窗或写共享内存：注入是在**另一台机器上**由 hypervisor 在
 * 一个被借用的线程上触发的，验证方拿不到那个进程的任何句柄。文件是唯一一种
 * "事后从外面就能核实、且能证明是谁写的"的证据——PID 对得上，就排除了"这个
 * 文件是别的什么东西留下的"。
 *
 * DllMain 里做文件 I/O 在生产代码里是要避免的（加载器锁）。这里可以接受：它是
 * 一次性的实验室探针，CreateFile/WriteFile 不会回到加载器里去，而换成"设个事件
 * 等外面来收"反而需要更多在锁下不该做的事。
 */

#include <windows.h>
#include <stdio.h>

static void WriteProof(void)
{
    char text[128];
    DWORD written = 0UL;
    HANDLE file = CreateFileA(
        "C:\\ksword\\dll-inject-proof.txt",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    /* PID 是"谁加载了我"的凭证，验证方拿它与靶子进程对账。 */
    (void)sprintf_s(
        text,
        sizeof(text),
        "loaded-by-pid %lu\r\n",
        GetCurrentProcessId());
    (void)WriteFile(
        file,
        text,
        (DWORD)strlen(text),
        &written,
        NULL);
    CloseHandle(file);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        /* 不需要线程附加通知，少一类在加载器锁下的回调。 */
        (void)DisableThreadLibraryCalls(module);
        WriteProof();
    }
    return TRUE;
}
