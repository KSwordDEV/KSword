#pragma once

// KvmHookPlan：一条 HOOK 视图从「用户指了个目标」到「装上了」之间的全部值。
//
// 存在的理由：
// - 今天装一条 HOOK 视图要用户自己做三件事——把符号/偏移换成虚拟地址、把虚拟地址
//   翻译成物理地址、再把物理地址手算页对齐——其中任何一步算错，驱动都不会报错：
//   它只查「页对齐」和「小于 8 TiB」两条（hvm_ept_view.c:288-295），既不查目标页
//   是不是 RAM，也不查它归谁。算错的结果是给一页无关内存挂了 HOOK；
// - 所以这一层的职责就是把那三步固化成一条不可跳过的管线，并把每一步的中间值都
//   留在结构体里，让后面的预检、安装摘要、校验都引用同一份数字，而不是各算一遍。
//
// 这个头文件里没有任何 Qt 控件，也不发 IOCTL：它是一个可拷贝的值对象，可以整份
// 拷进后台线程再拷回来。向导跨步骤共享的就是它。
//
// 【HOOK 的影子页是被执行的那一份】
//   驱动侧稳态 primary 叶 = 真页 | READ | WRITE（不给 X），翻转态 secondary 叶 =
//   影子页 | EXECUTE（hvm_ept_view.c:180 与 :186-190）。所以影子页必须是
//   「原页 4096 字节 + 补丁」的完整一页，补丁区间以外每个字节都要与原页逐位相同，
//   否则处理器被重定向过去执行的是一页垃圾。构造由 shared/evidence 的算术层承担。
//
// 【CLOAK/HOOK 不是安全边界】
//   这一层只保证数字正确。任何引用它的文案都不得暗示 HOOK 能防住一个有权限的对手。

#include <QByteArray>
#include <QString>
#include <QVector>
#include <QtGlobal>

#include <cstdint>

#include "../../../shared/evidence/HookPatchCompose.h"
#include "ThemeStatusRole.h"

namespace ks::ui
{
    // ---------------------------------------------------------------------
    // 目标入口
    // ---------------------------------------------------------------------

    // KvmHookTargetSource：用户从哪个入口指定的目标。
    //
    // 四个入口最终都收敛到同一条归一化管线（见 KvmHookTargetResolution），
    // 差别只在「虚拟地址是怎么来的」这一步：
    // - ModuleOffset：模块基址 + 偏移。人最常用的一种，也是唯一能防住"地址抄错一位"
    //   的一种——因为偏移能被模块的 imageSize 夹住；
    // - KernelVa：用户直接给一个内核虚拟地址。不做归属校验，只做翻译；
    // - RawPa：用户直接给物理地址，跳过翻译这一步（virtualAddress 保持 0）。
    //   这是唯一一条拿不到虚拟地址的路径，所以补丁里的近跳/远跳编码在这条路上
    //   没有可信的源地址，上层必须据此把跳转模板停掉；
    // - Rehearsal：排练。目标是本进程自己分配的一页，装上去不会影响任何别人。
    //   它是这条流程里唯一一个可以在不冒险的前提下走完五步的入口，因此不是玩具：
    //   前置条件、TOCTOU 比对、校验判据在排练下与真实目标逐条一致。
    enum class KvmHookTargetSource : int
    {
        ModuleOffset = 0,
        KernelVa,
        RawPa,
        Rehearsal
    };

    // KvmHookModuleChoice：内核模块下拉里的一项。
    //
    // 它是 KernelThreadAuditTab::ModuleRecord 的一个轻量投影，刻意不直接复用那个
    // 结构：那个头文件带 Framework.h 和 Win32 依赖，而本头文件要能被纯值层引用。
    // 转换在 KvmHookWizard.cpp 里做。
    struct KvmHookModuleChoice
    {
        QString name;
        QString path;
        quint64 baseAddress = 0;
        // imageSize 升到 64 位保存：偏移上界要按 64 位比较，用 32 位去比会在
        // 「基址 + 偏移」这一步把一个越界的偏移算成一个看起来合法的地址。
        quint64 imageSize = 0;
        bool kernelImage = false;
    };

    // ---------------------------------------------------------------------
    // 归一化管线的产物
    // ---------------------------------------------------------------------

    // KvmHookTargetResolution：一次「虚拟地址 -> 物理地址 -> 页几何」的结果。
    //
    // 固定三步，顺序不可换：
    //   1) 按入口算出 virtualAddress；
    //   2) translate(0, virtualAddress) 拿到 fullPhysicalAddress（**含页内偏移**）；
    //   3) pageBasePhysical = fullPhysicalAddress & ~0xFFFULL，
    //      pageOffset       = fullPhysicalAddress &  0xFFFULL。
    // 第 3 步就是这条流程消灭掉的那一步人工计算——它以前在用户脑子里。
    //
    // directoryBase 恒传 0：驱动会用 __readcr3()，而内核地址在任何进程页表里都能解析。
    // 排练入口的目标在本进程用户空间里，调用线程正好就在这个进程，所以同样成立。
    struct KvmHookTargetResolution
    {
        bool ok = false;
        // resolvedVirtualAddress：RawPa 入口下恒为 0，那条路径没有虚拟地址。
        quint64 virtualAddress = 0;
        quint64 fullPhysicalAddress = 0;
        quint64 pageBasePhysical = 0;
        quint32 pageOffset = 0;
        // usedDirectWindow：翻译是否真的走了私有页表窗口。为假说明退化到了
        // MmCopyMemory 路径，仍然能翻译，但不再规避内核层 Hook——这是一个要如实
        // 展示的读数，不是失败。
        bool usedDirectWindow = false;
        // message：已本地化的一句结论或失败原因，可直接显示。
        QString message;
    };

    // ---------------------------------------------------------------------
    // 三态判定 —— 预检与校验共用同一套
    // ---------------------------------------------------------------------

    // KvmCheckVerdict：一条判据的结论。
    //
    // **NoReading 必须是独立的一态**，这是这套枚举存在的全部理由：
    // 「目标函数在观察窗口内没被执行过」既不是通过也不是失败；
    // 「EPTP 切换后端下 flipCount 恒为 0」也不是失败（唯一递增点在
    // hvm_ept_view.c:903，切换后端在 :821 就提前 return 了）。
    // 只有两态的话，这两条读数会被强行涂成绿或红，而两种涂法都是在说谎。
    enum class KvmCheckVerdict : int
    {
        Pass = 0,
        Fail,
        NoReading
    };

    // KvmCheckRemedy：一条判据配的「修复」动作。
    //
    // 注意 ExplainLocalEptUnreachable：它**不是一个出路**。多核机上安装视图需要
    // LocalEptArmed，而 ENABLE_LOCAL_EPT 虽然被 PREPARE 读取（hvm_runtime.c:1573-1582）
    // 却不在 PREPARE 的 allowedFlags 白名单里（:2682-2685），驱动注释自己称之为
    // standing defect（:2674-2681）。所以这条判据在多核机上通过协议不可达。
    // 这一项挂的按钮只能打开一段解释，绝不能假装能修好它——放一个点了没用的
    // 「启用私有 EPT」按钮，比不放按钮更坏。
    enum class KvmCheckRemedy : int
    {
        None = 0,
        // 开启 R-1 写权限门，走 ks::ui::requestKvmWriteAccess。
        EnableWriteAccess,
        // 执行 ensurePrepared()，让资源就绪。
        PrepareResources,
        // 执行 stopResident()，离开常驻——视图表在常驻期间不可改。
        StopResident,
        // 打开 EPTP 切换后端：它只随 PREPARE 发出，所以要
        // releaseResources() + ensurePrepared() 才生效。
        SwitchToEptpBackend,
        // 打开视图面板去腾位置（视图表已满，上限 KSWORD_ARK_HVM_MAX_VIEWS = 32）。
        OpenViewPanel,
        // 退回第 1 步重选目标。
        ReturnToTargetStep,
        // 退回第 2 步重编补丁。
        ReturnToPatchStep,
        // 重新抓一次基线页。
        RecaptureBaseline,
        // 只解释，不修复。见上面那段。
        ExplainLocalEptUnreachable,
        // 只解释，不修复：这条判据本身就是「本项目没有实测过」。
        ExplainNotMeasured
    };

    // KvmCheckRow：预检表 / 校验表的一行。四列 = 判据 / 当前读数 / 结论 / 修复按钮。
    struct KvmCheckRow
    {
        // criterionId：本行对应哪一条判据。预检表取 KvmHookPreflightCriterion，
        // 校验 A 段取 KvmHookVerifyCriterion，B 段取 KvmHookResidentCriterion。
        // 存成 int 是为了让三张表共用同一个行结构而不互相包含对方的枚举。
        int criterionId = 0;
        // criterion：判据本身，一句话（第 1 列）。
        QString criterion;
        // reading：**当前实测读数**，要带具体数字/状态位（第 2 列）。
        // 这一列不许写结论，只写读到了什么——结论在下一列。
        QString reading;
        // verdict：三态结论（第 3 列的语义来源）。
        KvmCheckVerdict verdict = KvmCheckVerdict::NoReading;
        // conclusion：结论的一句话说明（第 3 列的文字）。
        // NoReading 时必须说清「为什么没有读数」，否则它看起来就像失败。
        QString conclusion;
        // remedy / remedyLabel：第 4 列按钮。remedy 为 None 时不放按钮。
        KvmCheckRemedy remedy = KvmCheckRemedy::None;
        QString remedyLabel;
        // blocking：这一条不通过时能不能继续往下装。
        // 只有驱动侧真的会拒绝的那几条才是 blocking；观测性的读数（例如翻译是否
        // 走了私有窗口）不是。UI 不得放宽驱动侧的前置检查，但也不该自己发明新的。
        bool blocking = false;
    };

    // KvmHookPreflightCriterion：第 3 步预检的判据集合（顺序即行序，冻结）。
    //
    // 前七条逐条对应驱动安装视图的前置检查，出处见 KvmControl.h 里 KvmState 的
    // resourcesReady / eptReady / inveptSingleReady / monitorTrapFlagReady 四位
    // 与 hvm_ept_view.c。后四条是本层自己的几何与内容检查。
    enum class KvmHookPreflightCriterion : int
    {
        // R-1 写权限门已开（客户端侧的第二道门，驱动侧另外还要确认令牌）。
        WriteAccessGate = 0,
        // PREPARE 已执行且未 TEARDOWN（KvmState::resourcesReady）。
        ResourcesPrepared,
        // 未常驻：常驻期间驱动拒绝改动视图表（KvmState::residentActive 为假）。
        NotResident,
        // EPT 层次已建好（KvmState::eptReady）。
        EptReady,
        // 拓扑：processorCount == 1 || localEptArmed。
        // 不满足时 remedy = ExplainLocalEptUnreachable，见上文。
        Topology,
        // 单上下文 INVEPT 可用（KvmState::inveptSingleReady）。两套后端都要它。
        InveptSingle,
        // 后端能力：eptpSwitchArmed 为真时看 execute-only（由驱动侧判定，这里只
        // 转述状态位）；为假时看 monitorTrapFlagReady。**必须连着 eptpSwitchArmed
        // 一起看**——单看 MTF 会把嵌套 Hyper-V 客户机误判成无解。
        Backend,
        // 视图表还有位置：已安装条数 < KSWORD_ARK_HVM_MAX_VIEWS（32）。
        ViewTableCapacity,
        // 目标页几何：pageBasePhysical 页对齐且 < 8 TiB。驱动只查这两条。
        TargetPageGeometry,
        // 补丁几何：ClassifyCrossPage 判为 InPage，且补丁非空。
        // 跨页在两种后端下都 fail-closed，直接拒绝，**不拆成两条视图**。
        PatchGeometry,
        // 基线页完整：恰好 4096 字节且是从目标页读回来的那一份。
        BaselineComplete,
        Count
    };

    // KvmHookVerifyCriterion：第 5 步 A 段（未常驻可得的四条读数）。
    enum class KvmHookVerifyCriterion : int
    {
        // listViews() 里有这条 viewId，且 kind == HOOK。
        ViewPresent = 0,
        // shadowPhysicalAddress 非零且不等于 pageBasePhysical。
        ShadowDistinct,
        // 真页未被改动：重读 pageBasePhysical 一页应与 baselinePage 逐字节相同。
        // HOOK 不改真页——这一条要是失败了，说明有别的东西动过它。
        RealPageUnchanged,
        // 基座 EPT 叶读回：稳态 primary 叶 = 真页 | R | W，**不给 X**。
        // 所以判据是 reachedLeaf && !executable。
        // 【盲区】localEptArmed 或 eptpSwitchArmed 为真时，探针读的是基座，而运行
        // 中的处理器挂在另一棵树上——那时这一条只能是 NoReading，不能算通过也不
        // 能算失败。见 KvmEptLeafProbe.h 文件头。
        BaseEptLeafNotExecutable,
        Count
    };

    // KvmHookResidentCriterion：第 5 步 B 段（要起常驻才有的三条，默认折叠）。
    //
    // 默认折叠是因为这一段要求用户主动起一次常驻，而起常驻本身有代价；
    // 三条里有两条在常见配置下注定是 NoReading，把它们默认摊开只会制造焦虑。
    enum class KvmHookResidentCriterion : int
    {
        // flipCount > 0。**只在默认后端（写叶 + MTF）下递增**（唯一递增点
        // hvm_ept_view.c:903）；EPTP 切换后端在 :821 就提前 return，flipCount 恒为 0。
        // 所以读这一条之前必须先看 eptpSwitchArmed：切换后端下它是
        // 「本后端不产生此计数」= NoReading，不是失败。
        FlipCount = 0,
        // 事件环里出现过 ruleId == viewId 的翻转事件（readEvents；KvmEventEntry 的
        // ruleId 对视图翻转承载的就是 viewId）。没出现 = 目标页在观察窗口内没被
        // 碰过 = NoReading。
        FlipEventObserved,
        // HOOK 方向——执行是否真的被重定向到影子页——**本项目未实测**。
        // 这一条恒为 NoReading，文案照路线图原文写，不许改成"已验证"。
        ExecutionRedirected,
        Count
    };

    // ---------------------------------------------------------------------
    // 计划本体
    // ---------------------------------------------------------------------

    // KvmHookPlan：向导五步共享的唯一一份可变状态。
    //
    // 它是纯值：可以整份拷进后台线程算完再拷回来，不含指针、不含控件、不拥有任何
    // 系统资源（排练页的所有权在向导手里，这里只记它的虚拟地址）。
    struct KvmHookPlan
    {
        // ---- 第 1 步：目标 ----
        KvmHookTargetSource targetSource = KvmHookTargetSource::Rehearsal;
        // 模块入口用的三个值。其它入口下 moduleName 为空、moduleBase/imageSize 为 0。
        QString moduleName;
        quint64 moduleBase = 0;
        quint64 imageSize = 0;
        // offset：模块入口下的模块内偏移；其它入口下为 0。
        quint64 offset = 0;
        // virtualAddress：归一化管线第 1 步的产物。RawPa 入口下为 0。
        quint64 virtualAddress = 0;
        // fullPhysicalAddress：translate 的返回值，**含页内偏移**。
        quint64 fullPhysicalAddress = 0;
        // pageBasePhysical / pageOffset：第 3 步的产物，安装用的就是 pageBasePhysical。
        quint64 pageBasePhysical = 0;
        quint32 pageOffset = 0;
        // resolved：归一化管线跑完且成功。为假时 pageBasePhysical 不可信。
        bool resolved = false;

        // ---- 第 2 步：补丁 ----
        // baselinePage：目标页当前的 4096 字节，从 R-1 通道分片读回来的那一份。
        // 它同时是影子页的底稿和第 4 步 TOCTOU 比对的基准。
        QByteArray baselinePage;
        // patchBytes：用户实际改动的那一段，起点是 pageOffset。
        // 它是「成品影子页与基线页的差异」，不是整页——整页由 composedShadowPage() 现算。
        QByteArray patchBytes;

        // ---- 第 4 步：安装结果 ----
        // installedViewId：addView 成功后的 viewId。0 表示尚未安装。
        unsigned long installedViewId = 0;
        // shadowPhysicalAddress：驱动分配的影子页物理地址，从 listViews 读回。
        quint64 shadowPhysicalAddress = 0;
        // installed：addView 返回过成功。注意它只说明驱动接受了请求，
        // 不说明那张叶真的被改了——那要第 5 步的读数才知道。
        bool installed = false;

        // ---- 平凡内联求值 ----

        // baselineIsComplete：基线页恰好是一整页。分片读只要少一片就不成立，
        // 而少一片的基线拿去构造影子页，会让被执行的那一页里出现一段零字节。
        bool baselineIsComplete() const noexcept
        {
            return baselinePage.size()
                == static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes);
        }

        // patchIsEmpty：空补丁产出的影子页与原页逐位相同，那样一条 HOOK 视图什么
        // 都不改变却会让人以为补丁装上了。这是调用点的错误，不是合法的恒等补丁。
        bool patchIsEmpty() const noexcept { return patchBytes.isEmpty(); }

        // patchLength / patchEndOffset：几何判定用。两者都升到 64 位，
        // 32 位相加的回绕会把明显越界的请求算成一个页内的小和。
        quint64 patchLength() const noexcept
        {
            return static_cast<quint64>(patchBytes.size());
        }
        quint64 patchEndOffset() const noexcept
        {
            return static_cast<quint64>(pageOffset) + patchLength();
        }

        // pageIsAligned：驱动只查这一条和 8 TiB 上界，所以这一条要在客户端先看。
        bool pageIsAligned() const noexcept
        {
            return (pageBasePhysical & 0xFFFULL) == 0ULL;
        }

        // hasVirtualAddress：RawPa 入口拿不到虚拟地址，跳转编码在那条路上没有可信
        // 的源地址，跳转模板必须停掉。
        bool hasVirtualAddress() const noexcept
        {
            return targetSource != KvmHookTargetSource::RawPa
                && virtualAddress != 0ULL;
        }

        // ---- 非平凡求值：实现在 KvmHookWizard.Patch.cpp ----

        // composedShadowPage：现算一页成品影子页 = 基线页 + 补丁。
        //
        // 每次都现算而不缓存，是因为缓存的成品页与基线/补丁三者之间会出现不一致，
        // 而不一致的那一份正好就是被处理器执行的那一份。
        //
        // 内部走 Ksword::Evidence::ComposePage，检查顺序被那一层的单测钉死：
        // 原页指针 -> 补丁指针 -> 几何 -> 空补丁。
        // 失败时返回空 QByteArray（不返回"差不多能用"的半成品页），
        // failureReasonOut 非空时写入已本地化的一句拒绝理由。
        QByteArray composedShadowPage(QString* failureReasonOut = nullptr) const;

        // classifyPatchGeometry：补丁装不装得进这一页。
        // 实现在 KvmHookWizard.Patch.cpp，只是 ClassifyCrossPage 的一层转发，
        // 留在这里是为了让预检与第 2 步的即时提示引用同一个判定。
        Ksword::Evidence::CrossPageClassification classifyPatchGeometry() const;
    };

    // ---------------------------------------------------------------------
    // 自由函数（实现位置见各自注释）
    // ---------------------------------------------------------------------

    // describeHookTargetSource：入口名，已本地化。实现在 KvmHookWizard.cpp。
    QString describeHookTargetSource(KvmHookTargetSource source);

    // describeCheckVerdict：三态的一句话，已本地化。实现在 KvmHookWizard.Verify.cpp。
    QString describeCheckVerdict(KvmCheckVerdict verdict);

    // checkVerdictStatusRole：三态到语义状态色的映射，供表格与状态行上色。
    //
    // 约定死：Pass -> StatusRole::Success，Fail -> StatusRole::Error，
    // NoReading -> StatusRole::Idle。NoReading **必须取中性色**——涂红会让一条
    // 「没有读数」看起来像失败，涂绿会让它看起来像通过，而它两者都不是。
    // 实现在 KvmHookWizard.Verify.cpp。
    StatusRole checkVerdictStatusRole(KvmCheckVerdict verdict);
}
