/*
 * hvm_target.exe —— R-1 处置与注入的可观察靶子。
 *
 * 存在的理由是"从外面看，成功和什么都没发生长得一样"。处置与注入都作用在一个
 * **客户物理页**上，而选错页——选到一页永远不会被执行的地址——的表现是驱动
 * 一切正常、表里有记录、计数恒为零。用记事本之类的现成进程做靶子时，"没反应"
 * 到底是机制没生效还是页选错了，分不开。
 *
 * 所以这个程序自己把答案交出来：
 *   1. 打印自己主循环所在的**客户线性地址**，处置就钉在那一页上；
 *   2. 打印一页专门给注入用的靶页地址：它可执行、每次心跳都会被执行到、
 *      而且除了开头几个字节以外全是零——注入需要一段"空隙"来放外壳与载荷，
 *      而真实模块里那段空隙是节尾填充，位置与长度都不可控。拿一页确定的空白
 *      来做首次验证，是为了把"外壳编码对不对"和"这一页有没有空隙"这两件事
 *      分开；
 *   3. 打印一个标记变量的地址，并在每次心跳里回显它的值。载荷只要往这个地址
 *      写一个数，外面立刻就能看见——这是"载荷真的跑了"唯一可靠的证据，比
 *      "进程没崩"强得多；
 *   4. 每 200 毫秒打一行带序号的心跳，并立刻刷盘。
 *
 * 于是几种结局在外面是可区分的：
 *   冻结   心跳停在某个序号上，进程还在，拦截数持续增长；撤销后**从下一个
 *          序号继续**（不是重启），那就是"指令没退休、状态没变"的直接证据。
 *   结束   进程消失。
 *   注入   标记值从 0 变成载荷写进去的那个数，而心跳**继续正常推进**——
 *          后半句同样重要：它证明被借用的那个线程被完好地还了回来。
 *   没生效 心跳照常，标记仍是 0，计数为零。
 *
 * /MT 静态链接，与同目录其它工具一致：全新安装的 Windows 没有 VC++ 可再发行
 * 组件，动态链接的 exe 在 guest 里根本起不来，而症状是"没有输出"，看着像别的
 * 毛病。
 */

#include <windows.h>
#include <stdio.h>

/*
 * 注入的效果观测点。
 *
 * volatile：载荷是由 hypervisor 在另一条执行流上写进来的，编译器无从知道这件
 * 事，不加的话它完全有权把每次读都优化成同一个缓存值——那样即使载荷跑了，
 * 心跳里也永远显示 0，看起来和没生效一模一样。
 */
static volatile unsigned int g_injectionMarker = 0U;

/*
 * 心跳循环单独一个函数，且禁止内联。
 *
 * 取它的函数地址当作"要拒绝执行的那一页"。写在 main 里也能取地址，但优化器可以
 * 把循环搬到别处，于是打印出来的地址与真正在执行的页不是同一页——又是一次
 * 静默失效。
 */
#pragma optimize("", off)
static void __declspec(noinline) HeartbeatLoop(void (*probe)(void))
{
    unsigned long long tick = 0ULL;

    for (;;) {
        /* 每一拍都执行一次靶页，保证注入装上之后很快就会被触发到。 */
        probe();
        printf("tick %llu marker %08X\n", tick, g_injectionMarker);
        fflush(stdout);
        tick += 1ULL;
        Sleep(200);
    }
}
#pragma optimize("", on)

int main(void)
{
    /*
     * 靶页：一整页可执行内存，开头一条 ret，其余全零。
     *
     * 全零的部分就是注入要用的空隙。真实模块里也有这样的空隙（节尾填充），
     * 但位置和长度取决于链接结果，首次验证不该同时押上这一条。
     */
    unsigned char* probePage = (unsigned char*)VirtualAlloc(
        NULL,
        4096U,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (probePage == NULL) {
        printf("probe-page-alloc-failed %lu\n", GetLastError());
        fflush(stdout);
        return 1;
    }
    /* VirtualAlloc 保证清零，这里只写那条 ret。 */
    probePage[0] = 0xC3U;

    /* 让 guest 里的 PowerShell 一次就能抓到这四个数。 */
    printf("pid %lu\n", GetCurrentProcessId());
    printf("loop 0x%016llX\n", (unsigned long long)(ULONG_PTR)&HeartbeatLoop);
    printf("probe 0x%016llX\n", (unsigned long long)(ULONG_PTR)probePage);
    printf("marker 0x%016llX\n",
           (unsigned long long)(ULONG_PTR)&g_injectionMarker);
    fflush(stdout);
    HeartbeatLoop((void (*)(void))probePage);
    /* 循环不返回；这一行只是让编译器看到一条完整的返回路径。 */
    return 0;
}
