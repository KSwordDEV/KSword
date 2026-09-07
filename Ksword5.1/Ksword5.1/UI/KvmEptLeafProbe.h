#pragma once

// KvmEptLeafProbe：把一个客户机物理地址在 EPT 里的四级页表项**读回来**。
//
// 存在的理由：
// - 这条线上反复缺同一个读数 ——「视图/规则装上了」与「那张叶真的被限制了」
//   是两件事，而协议只回答前者。ADD 响应里的 deniedAccess 是**归一化后的请求**，
//   不是叶的现值；addView 返回成功也只证明驱动接受了请求；
// - 本项目出过的最坏一类故障正是「叶写对了却完全不生效，而所有自检全绿」。
//   任何间接判据在那种故障下都会说谎，只有把叶项本身读回来不会。
//
// 为什么用户态能读到：EPT 页表是驱动自己分配的普通客户机物理内存，并被恒等
// 映射成 RWX，所以走现成的 OP_READ_PHYSICAL 就能逐级读。不需要改驱动，也不
// 需要写权限门 —— 这一层是纯只读观测。
//
// ---------------------------------------------------------------------------
// 【已知盲区，必须随读数一起呈现】
//
// 它读的是**基座**层次（hvm_ctl.c 的 ept-leaf 命令在 2396 与 2517 两处都是这么
// 标注的）：根地址取自 QUERY_HVM 回报的 eptPointer，沿着那一棵树往下走。
//
// 因此**每处理器私有 EPT 与 EPTP 切换后端实际装载的次层次，它看不到**。
// 那些次层次是从基座分叉出去的另一棵树（那正是它们的设计），本探针一个字节
// 也读不到它们。所以在 localEptArmed 或 eptpSwitchArmed 为真时，这里读回的
// 「基座里这一页此刻允许什么」不等于「正在跑的那个处理器此刻看到什么」。
//
// 这是这条判据的已知盲区。结果结构体里的 localEptArmed / eptpSwitchArmed 就是
// 为了让调用方把这句话如实标出来 —— 不标出来，它就会变成又一条假判据。
// ---------------------------------------------------------------------------
//
// 全部调用都是阻塞 IOCTL（一次 QUERY_HVM + 最多四次 READ_PHYSICAL），
// 调用方必须放到后台线程。本层不碰任何控件。

#include <QString>

#include <array>

namespace ks::ui
{
    // EptLeafEntryRecord：EPT 走表途中某一级的读回结果。
    //
    // 四级都留一格，没走到的那几级 read 为假 —— 这样调用方能看出walk 停在哪，
    // 而不是只拿到一个"失败"。
    struct EptLeafEntryRecord
    {
        // read：这一级的 8 字节读回来了。为假时要么根本没走到（上一级已停），
        // 要么这一次 READ_PHYSICAL 失败，两种情形靠 failure 是否为空区分。
        bool read = false;
        // index：本级在表内的槽位下标（0..511）。
        quint32 index = 0;
        // tableBase：本级页表的物理基址（页对齐）。
        quint64 tableBase = 0;
        // entryAddress：本项自身所在的物理地址，= tableBase + index * 8。
        // 留着它是为了让人能拿这个地址去别处复核同一个字节。
        quint64 entryAddress = 0;
        // entry：项的 64 位原值。为 0 表示这一级没有映射。
        quint64 entry = 0;
        // 访问权限三位（bit0/1/2）。EPT 里它们就是全部的权限，没有 U/S 之分。
        bool readable = false;
        bool writable = false;
        bool executable = false;
        // largePage：bit7（PS）。只在 PDPT（1 GiB）与 PD（2 MiB）上有意义，
        // 置位表示这一级就是叶，不再往下走。
        bool largePage = false;
        // failure：这一级读失败时的原因，已本地化。成功时为空。
        QString failure;
    };

    // EptLeafProbeResult：一次基座 EPT 走表的完整结果。
    struct EptLeafProbeResult
    {
        // ok：走表过程中没有任何一次读失败，因而下面的结论可信。
        // 注意「未映射」不是失败：那本身就是一个确定的结论，ok 仍为真。
        bool ok = false;
        // targetGpa：调用方传入的原始地址（页内偏移原样保留，便于回显）。
        quint64 targetGpa = 0;
        // pageBaseGpa：targetGpa 所在的 4 KiB 页基址，走表实际用的就是它。
        quint64 pageBaseGpa = 0;
        // eptPointer：QUERY_HVM 回报的原值，低 12 位是内存类型/层数/AD 编码。
        quint64 eptPointer = 0;
        // eptRoot：从 eptPointer 里取出的 PML4 物理基址，走表的起点。
        quint64 eptRoot = 0;
        // 下面两位不参与走表，只用来标注盲区（见文件头）：任一为真时，本结果
        // 描述的是基座，而运行中的处理器可能挂在另一棵树上。
        bool localEptArmed = false;
        bool eptpSwitchArmed = false;
        // levels：PML4 / PDPT / PD / PT 四级，下标即级号。
        std::array<EptLeafEntryRecord, 4> levels{};
        // walkedLevels：实际发起过读的级数（1..4）。
        int walkedLevels = 0;
        // reachedLeaf：找到了描述这一页的叶项（PT 项非零，或 PDPT/PD 上的大页项）。
        bool reachedLeaf = false;
        // largePage：叶落在 PDPT（1 GiB）或 PD（2 MiB）上。
        // 这一位为真时，叶项管的不止目标这一页 —— 改它会影响整段范围。
        bool largePage = false;
        // unmapped：走表被一个全零项截断，这一页在基座里没有映射。
        bool unmapped = false;
        // leafLevel：叶所在的级号（0..3）；没走到叶时为 -1。
        int leafLevel = -1;
        // leafEntry：叶项的 64 位原值。
        quint64 leafEntry = 0;
        // leafFrameAddress：叶项指向的物理帧基址，按该级页大小对齐。
        quint64 leafFrameAddress = 0;
        // 叶项的访问权限三位 —— 这三个布尔就是本探针要拿的那个读数。
        // 没走到叶时三个都为假，所以判断"被限制了"之前必须先看 reachedLeaf。
        bool readable = false;
        bool writable = false;
        bool executable = false;
        // memoryType：叶项 bit5..3 的 EPT 内存类型（0=UC，6=WB）。
        // 只在 reachedLeaf 为真时有意义。
        quint32 memoryType = 0;
        // ignorePat：叶项 bit6。
        bool ignorePat = false;
        // suppressVe：叶项 bit63。驱动给每个叶项都带上这一位，两道 #VE 保险里
        // 的一道就是它；读回来发现它被清掉了，是一个要立刻停下来看的信号。
        bool suppressVe = false;
        // message：已本地化的一句结论或失败原因，可直接展示。
        QString message;
    };

    // eptLeafLevelName：级号到助记名（PML4 / PDPT / PD / PT）。
    // 这是体系结构助记符不是译文，所以不进词条。
    QString eptLeafLevelName(int level);

    // readBaseEptLeaf：走一遍**基座** EPT，把 targetGpa 那一页的四级项读回来。
    //
    // - 阻塞（一次 QUERY_HVM + 最多四次 READ_PHYSICAL），必须在后台线程调用；
    // - 只读，不需要写权限门，也不改变任何驱动侧状态；
    // - eptPointer 为 0（资源尚未准备或驱动未运行）时返回 ok=false 且 message
    //   说明差在哪，不会崩；
    // - 结果只描述基座层次，盲区见文件头。
    EptLeafProbeResult readBaseEptLeaf(quint64 targetGpa);
}
