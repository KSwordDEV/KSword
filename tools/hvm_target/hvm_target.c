/*
 * hvm_target.exe —— R-1 进程处置的可观察靶子。
 *
 * 存在的理由是"从外面看，成功和什么都没发生长得一样"。冻结与结束都作用在一个
 * **客户物理页**上，而选错页——选到一页永远不会被执行的地址——的表现是驱动
 * 一切正常、表里有记录、拦截数恒为零。用记事本之类的现成进程做靶子时，"没死"
 * 到底是机制没生效还是页选错了，分不开。
 *
 * 所以这个程序自己把答案交出来：
 *   1. 打印自己主循环所在的**客户线性地址**，处置就钉在那一页上；
 *   2. 每 200 毫秒打一行带序号的心跳，并立刻刷盘。
 *
 * 于是三种结局在外面是可区分的：
 *   冻结 —— 心跳停在某个序号上，进程还在，拦截数持续增长；撤销后**从下一个
 *           序号继续**（不是重启），那就是"指令没退休、状态没变"的直接证据。
 *   结束 —— 进程消失。
 *   没生效 —— 心跳照常，拦截数为零。
 *
 * /MT 静态链接，与同目录其它工具一致：全新安装的 Windows 没有 VC++ 可再发行
 * 组件，动态链接的 exe 在 guest 里根本起不来，而症状是"没有输出"，看着像别的
 * 毛病。
 */

#include <windows.h>
#include <stdio.h>

/*
 * 心跳循环单独一个函数，且禁止内联。
 *
 * 取它的函数地址当作"要拒绝执行的那一页"。写在 main 里也能取地址，但优化器可以
 * 把循环搬到别处，于是打印出来的地址与真正在执行的页不是同一页——又是一次
 * 静默失效。
 */
#pragma optimize("", off)
static void __declspec(noinline) HeartbeatLoop(void)
{
    unsigned long long tick = 0ULL;

    for (;;) {
        printf("tick %llu\n", tick);
        fflush(stdout);
        tick += 1ULL;
        Sleep(200);
    }
}
#pragma optimize("", on)

int main(void)
{
    /* 让 guest 里的 PowerShell 一次就能抓到这两个数。 */
    printf("pid %lu\n", GetCurrentProcessId());
    printf("loop 0x%016llX\n", (unsigned long long)(ULONG_PTR)&HeartbeatLoop);
    fflush(stdout);
    HeartbeatLoop();
    /* 循环不返回；这一行只是让编译器看到一条完整的返回路径。 */
    return 0;
}
