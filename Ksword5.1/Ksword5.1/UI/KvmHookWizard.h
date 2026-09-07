#pragma once

// KvmHookWizard：装一条 HOOK 视图的五步向导。
//
// 为什么要有它：
// - 现有的 KvmViewDialog 是一张平铺的表单，它把「算地址、抓基线、判前置、拼整页
//   影子、装、再证明装上了」六件事全交给用户，而其中任何一件做错都不会报错——
//   驱动只查页对齐和 8 TiB 上界两条（hvm_ept_view.c:288-295）。装错的结果是给一页
//   无关内存挂了 HOOK，而且看起来一切正常；
// - 所以这里换成一条不可跳过的管线：每一步只问一件事，每一步的产物都进同一份
//   KvmHookPlan，下一步只读上一步的产物，不重算。
//
// 为什么是 QDialog + QStackedWidget 而不是 QWizard：
//   全仓零处使用 QWizard。引入它意味着这一个对话框的外观、主题染色、按钮布局都
//   走一套没人维护过的路径。形状照 KvmViewDialog 抄，是为了让它和旁边六个 KVM
//   面板长得一样。
//
// 【CLOAK/HOOK 不是安全边界】—— 已定案。
//   这个向导里任何一句面向用户的文案都不得暗示 HOOK 能防住一个有权限的对手。
//   失败即放行：InstructionLength = 0 时处理器会重执行并读到真页。
//
// 【HOOK 方向未实测】
//   「执行被重定向到影子页」这件事本项目**没有实测过**，这是路线图原文。
//   第 5 步 B 段的 ExecutionRedirected 一条因此恒为 NoReading，不许改成"已验证"。
//
// 【多核机上没有出路】
//   安装视图要求 ProcessorCount == 1 || LocalEptArmed，而 ENABLE_LOCAL_EPT 被
//   PREPARE 读取（hvm_runtime.c:1573-1582）却不在 PREPARE 的 allowedFlags 白名单里
//   （:2682-2685），驱动注释自己称之为 standing defect（:2674-2681）。
//   所以第 3 步的 Topology 一条在多核机上通过协议不可达。UI 的职责是把这三处事实
//   如实摆出来，**不得提供一个假装是出路的按钮**。
//
// ===========================================================================
// 【三个 .cpp 的分工 —— 这一段是契约，先看这里再写代码】
//
//   KvmHookWizard.cpp        骨架 + 第 1 步（选目标）+ 第 4 步（安装）
//   KvmHookWizard.Patch.cpp  第 2 步（编补丁）+ 一页字节的读与拼
//   KvmHookWizard.Verify.cpp 第 3 步（预检）+ 第 5 步（校验）
//
// 每个成员函数的归属都标在它自己的声明上，格式是行尾的 [W] / [P] / [V]：
//   [W] = KvmHookWizard.cpp
//   [P] = KvmHookWizard.Patch.cpp
//   [V] = KvmHookWizard.Verify.cpp
// 没有第四个位置。声明在这里而三处都不实现，链接期才会发现；两处都实现，
// 链接期报重复定义。所以动手前先按标记认领。
//
// 跨文件复用的两个点，不要各写一份：
//   - readTargetPage()（[P] 实现）：把一页 4096 字节从 R-1 通道分片读回来。
//     第 2 步抓基线用它，第 4 步 TOCTOU 重读用它，第 5 步真页比对也用它。
//   - KvmHookPlan::composedShadowPage()（[P] 实现，声明在 KvmHookPlan.h）：
//     现算成品影子页。第 2 步预览用它，第 4 步安装用它。
// ===========================================================================
//
// 【全部 ksword::kvm::* 调用都是阻塞 IOCTL，绝不能在 UI 线程直接调】
//   既有模式照抄 KvmViewDialog.cpp:221-272：QPointer + std::thread + detach +
//   QMetaObject::invokeMethod(Qt::QueuedConnection) 回到 UI 线程。
//   本类为此备好了三件东西，见下面「异步骨架」一段：防抖定时器、单飞标志、序号。
//   序号不是可选项——第 1 步的输入框每敲一个字符就可能发一次翻译，
//   回来的顺序不保证与发出的顺序一致，没有序号就会用一个旧地址覆盖新地址。

#include <QByteArray>
#include <QDialog>
#include <QString>
#include <QVector>

#include <cstdint>

#include "KvmControl.h"
#include "KvmEptLeafProbe.h"
#include "KvmHookPlan.h"

class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTableWidget;
class QTimer;
class QWidget;

// HexEditorWidget 在全局命名空间（见 UI/HexEditorWidget.h），不在 ks::ui 里。
class HexEditorWidget;

namespace ks::ui
{
    // readTargetPage：把 pageBasePhysical 那一页 4096 字节读回来。            [P]
    //
    // R-1 通道单次上限 1024 字节，所以固定切成 4 片顺序读。任何一片失败都返回空
    // QByteArray 并把原因写进 failureOut——不返回一页残缺的字节，因为残缺的基线
    // 拼出来的影子页会在被执行的那一页里留一段零。
    //
    // 阻塞（4 次 READ_PHYSICAL），**只能在后台线程调用**。不碰任何控件。
    QByteArray readTargetPage(quint64 pageBasePhysical, QString* failureOut);

    // KvmHookWizard：五步向导本体。
    class KvmHookWizard final : public QDialog
    {
        Q_OBJECT

    public:
        // Step：页序，与 m_pageStack 的下标一一对应。
        enum class Step : int
        {
            Target = 0,   // 选目标
            Patch = 1,    // 编补丁
            Preflight = 2,// 预检
            Install = 3,  // 安装
            Verify = 4,   // 校验
            Count = 5
        };

        // JumpTemplate：第 2 步提供的两种跳转模板。
        //
        // 两种都要，理由在 HookPatchCompose.h 里写过：内核模块之间的间距经常超过
        // ±2 GiB，只给近跳会让最常用的补丁形式频繁失败，而失败的形式会诱使人去改
        // 别的地方绕过去。
        enum class JumpTemplate : int
        {
            None = 0,
            Rel32Near,    // E9 + int32，5 字节；位移基准是**下一条指令**
            Absolute14    // FF 25 00000000 + 小端 8 字节绝对地址，14 字节
        };

        explicit KvmHookWizard(QWidget* parent = nullptr);                  // [W]
        ~KvmHookWizard() override;                                          // [W]

        // openWizard：从菜单/面板打开一次向导的唯一入口。                    [W]
        // 内部负责非模态生命周期与 WA_DeleteOnClose，调用点不要自己 new。
        static void openWizard(QWidget* parent);

        // plan：只读取当前计划，供外部（例如测试或调试面板）核对数字。
        const KvmHookPlan& plan() const noexcept { return m_plan; }
        // currentStep：当前停在哪一步。
        Step currentStep() const noexcept { return m_currentStep; }

    private:
        // -------------------------------------------------------------
        // 后台任务的快照结构。
        // 全部字段可拷贝：整份从后台线程拷回 UI 线程，UI 线程不重新发 IOCTL。
        // -------------------------------------------------------------

        // PreflightSnapshot：第 3 步一次性取齐的读数（一次 QUERY + 一次 LIST）。
        // 合成一个后台任务是因为两个读数必须来自同一时刻：分两次取会出现
        // 「状态说未常驻、视图表却是常驻期间的旧值」这种自相矛盾的一屏。
        struct PreflightSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            bool viewsOk = false;
            unsigned long viewCount = 0;
            QString viewsMessage;
        };

        // InstallOutcome：第 4 步一次安装的全过程结果。
        //
        // 顺序固定：重读目标页 -> 与 baselinePage 比对 -> 只有相同才发 addView。
        // TOCTOU 比对不是形式：从第 2 步抓基线到这里可能过了几分钟，目标页在这段
        // 时间里被改过的话，我们拼出来的影子页里含的是**过期的原字节**，而影子页
        // 正是被执行的那一份。比对不过就必须停下，不是提示一下继续装。
        struct InstallOutcome
        {
            bool rereadOk = false;
            QString rereadFailure;
            bool baselineMatches = false;
            // freshPage：重读回来的一页。比对失败时要拿它去做差异展示，
            // 也要拿它当「重新抓基线」的现成结果，避免再读一遍。
            QByteArray freshPage;
            // addAttempted：真的发出过 addView。为假说明卡在重读或比对，
            // 此时 addResult 的两个失败码保持零，而零恰好就是 VIEW_STATUS_OK，
            // 所以判断失败必须先看这一位再看 addResult.ok。
            bool addAttempted = false;
            ksword::kvm::KvmViewResult addResult;
            // listAfter：安装成功后立刻回读一次，为的是拿 shadowPhysicalAddress
            // ——ADD 的响应里没有它。
            ksword::kvm::KvmViewResult listAfter;
        };

        // VerifyStaticSnapshot：第 5 步 A 段（未常驻可得的四条读数）。
        struct VerifyStaticSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            ksword::kvm::KvmViewResult views;
            QByteArray rereadPage;
            QString rereadFailure;
            EptLeafProbeResult leaf;
        };

        // VerifyResidentSnapshot：第 5 步 B 段（起了常驻才有的三条）。
        struct VerifyResidentSnapshot
        {
            ksword::kvm::KvmState state;
            bool stateValid = false;
            ksword::kvm::KvmViewResult views;
            ksword::kvm::KvmEventResult events;
        };

        // =============================================================
        // 骨架与导航 —— 全部 [W]
        // =============================================================

        // buildUi：建页栈、导航条、状态行，并把五个 buildXxxPage() 的
        // 返回控件按 Step 顺序塞进 m_pageStack。                            [W]
        void buildUi();

        // goToStep：切页。只负责页栈下标、导航按钮状态与步骤标题；          [W]
        // 「进入这一步要做什么」由 enterStep() 分派，两件事不要混在一起。
        void goToStep(Step step);

        // enterStep：进入某一步时该触发的动作分派。                          [W]
        // - Target：如果模块列表还没取过，发一次模块枚举；
        // - Patch：如果基线还没抓过（或目标变了），发一次基线抓取；
        // - Preflight：发一次预检刷新；
        // - Install：重建摘要文本；
        // - Verify：发一次 A 段校验。
        // 分派本身在 [W]，被分派到的函数各自在自己的文件里。
        void enterStep(Step step);

        // canLeaveStep：当前步骤允许不允许往下走，不允许时 reasonOut 写原因。 [W]
        // 这里只拦「下一步一定会用到而当前还没有」的东西（例如目标未解析、
        // 基线不完整、预检有 blocking 未通过）。它不放宽任何驱动侧的检查，
        // 也不替驱动发明新的检查。
        bool canLeaveStep(Step step, QString* reasonOut) const;

        // updateNavigationState：按当前步骤与忙碌状态刷新上一步/下一步/关闭。  [W]
        void updateNavigationState();

        // setBusy：忙碌期间禁用导航与全部动作按钮。                          [W]
        void setBusy(bool busy);

        // setStatusText：写底部全局状态行，并按三态上色。                    [W]
        void setStatusText(const QString& text, KvmCheckVerdict verdict);

        // failBackTo：把一次失败退回到产生它的那一步。                       [W]
        //
        // 存在的理由：KvmViewResult 的 message 是给人读的一句话，翻译过之后就丢掉了
        // 「失败发生在哪一步」；而同一个 protocolStatus 会由多个分支产生
        // （MULTIPROCESSOR_UNSAFE 既可能是"正在常驻"也可能是"拓扑或能力不满足"），
        // 只有配上 lastStatus 才分得开。所以两级失败码原样带过去，由目标步骤自己
        // 决定怎么解释，而不是拿字符串去猜。
        void failBackTo(
            Step step,
            const QString& reason,
            unsigned long protocolStatus,
            long lastStatus);

        // stepForViewFailure：把一次 addView 失败归到该退回的那一步。         [W]
        // 只在 ok 为假时调用——两个失败码在客户端就被拒的路径上保持零，
        // 而零恰好是 VIEW_STATUS_OK。
        static Step stepForViewFailure(
            unsigned long protocolStatus,
            long lastStatus);

        // =============================================================
        // 第 1 步：选目标 —— 全部 [W]
        // =============================================================

        // buildTargetPage：建第 1 步的控件树，返回页容器。                    [W]
        QWidget* buildTargetPage();

        // onTargetSourceChanged：切换四个入口时换 m_sourceStack 的子页，       [W]
        // 并把 m_plan 里属于旧入口的字段清干净——留着旧值会让第 4 步的摘要
        // 显示一个用户已经不再选择的目标。
        void onTargetSourceChanged();

        // scheduleTargetResolve：输入变化后按 kInputDebounceMilliseconds 防抖，[W]
        // 到点才真发翻译。直接每敲一个字符发一次 IOCTL 会把 UI 拖垮。
        void scheduleTargetResolve();

        // startTargetResolve：发起一次后台归一化（VA -> translate -> 页几何）。[W]
        // 单飞：m_targetResolveInFlight 为真时不叠发，防抖定时器会再来一次。
        void startTargetResolve();

        // applyTargetResolve：回到 UI 线程后落地翻译结果。                    [W]
        // sequence 与 m_targetResolveSequence 不等时**直接丢弃**：那是一个已经
        // 被后续输入作废的旧地址，落地它会让页几何与输入框对不上。
        void applyTargetResolve(
            quint64 sequence,
            const KvmHookTargetResolution& resolution);

        // resolveTargetBlocking：归一化管线本体，阻塞，后台线程调用。         [W]
        // 静态且只吃值：它不碰控件，所以能被整份拷进 std::thread。
        static KvmHookTargetResolution resolveTargetBlocking(
            KvmHookTargetSource source,
            quint64 virtualAddress,
            quint64 rawPhysicalAddress);

        // refreshModuleList：后台枚举内核模块，填 m_moduleBox。               [W]
        // 走 KernelThreadAuditTab::queryKernelModules（R3 的
        // NtQuerySystemInformation，不依赖驱动），结果投影成 KvmHookModuleChoice。
        void refreshModuleList();

        // updateTargetReadout：把 m_plan 的四个几何值刷到四个只读标签上。      [W]
        // 这四个数就是这条流程消灭掉的那一步人工计算，必须一直摆在用户眼前。
        void updateTargetReadout();

        // allocateRehearsalPage / releaseRehearsalPage：排练页的分配与释放。   [W]
        //
        // 用 VirtualAlloc 拿一页（天然 4 KiB 对齐），分配后必须**先写一个字节再
        // VirtualLock**：没有驻留的页翻译出来的物理地址要么失败要么是一个随时会
        // 换人的帧，而我们接下来要往那个帧上挂 EPT 视图。
        // 释放在析构里做，且必须在移除视图之后。
        bool allocateRehearsalPage();
        void releaseRehearsalPage();

        // =============================================================
        // 第 2 步：编补丁 —— 全部 [P]
        // =============================================================

        // buildPatchPage：建第 2 步的控件树，返回页容器。                      [P]
        // 中间是 HexEditorWidget（setEditable(true)），基址传 pageBasePhysical，
        // 这样十六进制视图里的地址列直接就是物理地址，不用心算。
        QWidget* buildPatchPage();

        // startBaselineCapture：后台抓一次基线页（readTargetPage）。            [P]
        // 单飞 + 序号，规则与第 1 步相同。
        void startBaselineCapture();

        // applyBaselineCapture：落地基线页。                                    [P]
        // 成功后把整页装进 m_shadowEditor，并 jumpToAbsoluteAddress 到
        // pageBasePhysical + pageOffset —— 用户关心的是那几个字节，不是页首。
        void applyBaselineCapture(
            quint64 sequence,
            const QByteArray& page,
            const QString& failure);

        // onShadowByteEdited：用户改了一个字节之后重算补丁。                    [P]
        void onShadowByteEdited(
            std::uint64_t absoluteAddress,
            std::uint8_t oldValue,
            std::uint8_t newValue);

        // recomputePatchFromEditor：把编辑器现值与基线页逐字节比对，            [P]
        // 取出「第一个不同字节 .. 最后一个不同字节」这一段作为 patchBytes，
        // 并把 m_plan.pageOffset 更新成那一段的起点。
        //
        // 为什么补丁是差异区间而不是整页：一条视图恰好覆盖一页，成品影子页要整页
        // 没错，但**补丁**是要被几何判定（跨页 / 非空）和拒绝理由引用的那个东西，
        // 整页永远"刚好装得下"，那样几何判定就退化成永远通过。
        void recomputePatchFromEditor();

        // updatePatchSummary：刷新补丁摘要（起点、长度、跨页结论、非空结论）。  [P]
        void updatePatchSummary();

        // refreshPatchDisassembly：把补丁区间前后一段反汇编出来给人看。         [P]
        // 走 ks::ui::InstructionDecoder::decode(bytes, base, X64)。
        //
        // 【它不回答"补丁有没有切断一条指令"】x86 是变长指令，从一个任意偏移向前
        // 线性解码只能是启发式，仓库里的 InstructionDecoder 也只有正向能力。
        // 所以这一块的标题必须说清它是**参考**，不是判据，更不能挂一个绿勾。
        void refreshPatchDisassembly();

        // applyJumpTemplate：把一条跳转按模板写进编辑器的当前偏移。             [P]
        //
        // 近跳的位移基准是**下一条指令**（E9 自身 5 字节），源地址取
        // virtualAddress，所以 RawPa 入口下没有可信源地址，这两个模板必须停掉
        // （KvmHookPlan::hasVirtualAddress() 就是给这里用的）。
        // 位移装不进 int32 时如实拒绝并说明"请改用 14 字节的绝对跳"，
        // 不要偷偷替用户换成绝对跳。
        void applyJumpTemplate(JumpTemplate templateKind, quint64 targetVa);

        // revertPatch：把编辑器还原成基线页，patchBytes 清空。                  [P]
        void revertPatch();

        // updatePatchEnabledState：按基线是否就绪、入口是否有虚拟地址、          [P]
        // 是否忙碌，刷新第 2 步全部控件的可用性。
        void updatePatchEnabledState();

        // =============================================================
        // 第 3 步：预检 —— 全部 [V]
        // =============================================================

        // buildPreflightPage：建第 3 步的控件树，返回页容器。                   [V]
        // 表格四列固定：判据 / 当前读数 / 结论 / 修复。列数与列序都不要改，
        // 第 5 步两张表复用同一套列。
        QWidget* buildPreflightPage();

        // schedulePreflightRefresh / startPreflightRefresh：防抖 + 单飞 + 序号。 [V]
        void schedulePreflightRefresh();
        void startPreflightRefresh();

        // applyPreflightResult：落地预检读数。                                  [V]
        // sequence 与 m_preflightSequence 不等时丢弃。
        void applyPreflightResult(
            quint64 sequence,
            const PreflightSnapshot& snapshot);

        // collectPreflightSnapshot：一次取齐 QUERY + LIST，阻塞，后台线程。     [V]
        static PreflightSnapshot collectPreflightSnapshot();

        // buildPreflightRows：把读数 + 计划算成 KvmHookPreflightCriterion 那     [V]
        // 十一行。纯函数，不碰控件，因此可以被单测直接调。
        //
        // 三条不许写错的：
        // - Topology 不满足时 remedy 只能是 ExplainLocalEptUnreachable；
        // - Backend 必须先看 state.eptpSwitchArmed 再决定看哪一位能力，
        //   单看 monitorTrapFlagReady 会把嵌套 Hyper-V 客户机误判成无解；
        // - PatchGeometry 跨页时直接 Fail，不提供"拆成两条视图"的选项。
        static QVector<KvmCheckRow> buildPreflightRows(
            const PreflightSnapshot& snapshot,
            const KvmHookPlan& plan);

        // runPreflightRemedy：执行第 4 列按钮。                                 [V]
        // 会改状态的三个（写权限门、ensurePrepared、stopResident）各自走自己的
        // 后台任务，完成后自动重跑一次预检；两个 Explain* 只弹一段说明。
        void runPreflightRemedy(KvmCheckRemedy remedy);

        // hasBlockingPreflightFailure：还有没有 blocking 且未通过的判据。       [V]
        // canLeaveStep(Step::Preflight) 靠它。NoReading **不算通过**，
        // 但也不等同于 Fail：blocking 的 NoReading 同样挡住下一步，
        // 因为「不知道」不是「可以装」。
        bool hasBlockingPreflightFailure() const;

        // =============================================================
        // 第 4 步：安装 —— 全部 [W]
        // =============================================================

        // buildInstallPage：建第 4 步的控件树，返回页容器。                     [W]
        QWidget* buildInstallPage();

        // buildInstallSummaryText：安装前的摘要，要把这些原样摆出来：           [W]
        // 入口与目标（模块+偏移 / VA / PA / 排练）、virtualAddress、
        // fullPhysicalAddress、pageBasePhysical、pageOffset、补丁起止与长度、
        // 影子页种子（Explicit，整页 4096）、当前后端（默认 / EPTP 切换）、
        // 以及一句「HOOK 不是安全边界、失败即放行」。
        QString buildInstallSummaryText() const;

        // startInstall：走完确认 -> 重读 -> 比对 -> addView -> 回读。            [W]
        //
        // 顺序不可换。确认走
        // ks::ui::confirmDestructiveAction(this, key, actionTitle,
        //                                  targetDescription, riskDescription)
        // ——五个参数，带 ks::ui:: 限定。确认在 UI 线程弹，弹完才起后台线程。
        //
        // addView 的调用形状是固定的：
        //   addView(KSWORD_ARK_HVM_VIEW_KIND_HOOK,
        //           plan.pageBasePhysical,
        //           KvmViewShadowSeed::Explicit,
        //           plan.composedShadowPage())
        // seed 必须是 Explicit：HOOK 的影子页是被执行的那一份，Zero 会让处理器
        // 执行一页零字节，FromTarget 会让它执行一页没打补丁的原字节。
        // Explicit 下 shadow 必须**恰好 4096 字节**（KvmControl.cpp:1142-1150）。
        void startInstall();

        // applyInstallOutcome：落地安装结果。                                   [W]
        // - 重读失败或比对不过：failBackTo(Step::Patch, ...)，并把 freshPage
        //   当成新基线供用户重编，而不是让他从第 1 步重来；
        // - addView 失败：failBackTo(stepForViewFailure(...), ...)，两级失败码原样带；
        // - 成功：写 installedViewId / shadowPhysicalAddress / installed，
        //   然后 goToStep(Step::Verify)。
        void applyInstallOutcome(const InstallOutcome& outcome);

        // performInstallBlocking：重读 + 比对 + addView + 回读，阻塞，后台线程。 [W]
        // 静态且只吃值，不碰控件。
        static InstallOutcome performInstallBlocking(
            quint64 pageBasePhysical,
            const QByteArray& baselinePage,
            const QByteArray& shadowPage);

        // =============================================================
        // 第 5 步：校验 —— 全部 [V]
        // =============================================================

        // buildVerifyPage：建第 5 步的控件树，返回页容器。                      [V]
        // 上半是 A 段表（四行，未常驻即可得），下半是 B 段 QGroupBox
        // （三行，要起常驻，**默认折叠**）。
        QWidget* buildVerifyPage();

        // startVerifyStatic / applyVerifyStatic：A 段的取数与落地。             [V]
        void startVerifyStatic();
        void applyVerifyStatic(
            quint64 sequence,
            const VerifyStaticSnapshot& snapshot);

        // collectVerifyStaticSnapshot：一次取齐 QUERY + LIST + 重读一页 +       [V]
        // readBaseEptLeaf。阻塞，后台线程。
        static VerifyStaticSnapshot collectVerifyStaticSnapshot(
            quint64 pageBasePhysical);

        // buildVerifyStaticRows：算 A 段四行。纯函数。                          [V]
        //
        // BaseEptLeafNotExecutable 一条的盲区必须如实标出来：
        // snapshot.state.localEptArmed 或 eptpSwitchArmed 为真时，探针读的是
        // **基座**层次，而运行中的处理器挂在从基座分叉出去的另一棵树上，探针一个
        // 字节也读不到它。那时这一条只能是 NoReading，并在 reading 列里写明
        // 「本读数描述基座，不描述正在跑的那个处理器」。
        // 见 KvmEptLeafProbe.h 文件头那段「已知盲区」。
        static QVector<KvmCheckRow> buildVerifyStaticRows(
            const VerifyStaticSnapshot& snapshot,
            const KvmHookPlan& plan);

        // startVerifyResident / applyVerifyResident：B 段的取数与落地。         [V]
        // B 段只在用户主动展开并点按钮时才发起——它读的是常驻期间的计数与事件，
        // 自动发起会让一个折叠着的分组在背后打 IOCTL。
        void startVerifyResident();
        void applyVerifyResident(
            quint64 sequence,
            const VerifyResidentSnapshot& snapshot);

        // collectVerifyResidentSnapshot：QUERY + LIST + readEvents。阻塞。      [V]
        // afterSequence 传 m_eventCursor，clear 传 false：清环会把别的面板正在
        // 消费的事件一起抹掉。
        static VerifyResidentSnapshot collectVerifyResidentSnapshot(
            unsigned long long afterSequence);

        // buildVerifyResidentRows：算 B 段三行。纯函数。                        [V]
        //
        // 三条各自的三态规则，写错了整个 B 段就是假判据：
        // - FlipCount：state.eptpSwitchArmed 为真 -> **NoReading**，
        //   reading 列写「本后端不产生此计数」（唯一递增点 hvm_ept_view.c:903，
        //   切换后端在 :821 提前 return）。默认后端下 > 0 才 Pass，
        //   == 0 是 NoReading（页没被碰过），不是 Fail；
        // - FlipEventObserved：事件环里没有 ruleId == viewId 的行 -> NoReading，
        //   不是 Fail。目标函数在观察窗口内没被执行过，既不是成功也不是失败；
        // - ExecutionRedirected：**恒 NoReading**，remedy = ExplainNotMeasured。
        //   「HOOK 方向未实测」是路线图原文，UI 如实标注，不许改。
        static QVector<KvmCheckRow> buildVerifyResidentRows(
            const VerifyResidentSnapshot& snapshot,
            const KvmHookPlan& plan);

        // fillCheckTable：把一组行刷进一张四列表，并按三态给结论列上色。        [V]
        // 预检表与校验两张表共用它，三处的列语义因此不会走散。
        static void fillCheckTable(
            QTableWidget* table,
            const QVector<KvmCheckRow>& rows);

        // =============================================================
        // 异步骨架
        // =============================================================
        //
        // 三件套，每个异步入口都要齐：
        //   1) 防抖定时器：输入类的触发才需要（第 1 步、第 3 步）；
        //   2) 单飞标志：在飞就不叠发，避免同一时刻两条线程抢同一份状态锁；
        //   3) 序号：**必需**。回来的顺序不保证与发出的顺序一致，序号不等就丢弃。
        //      只靠单飞标志不够——单飞只保证同时最多一条在飞，不保证那条飞回来时
        //      它算的还是用户现在想要的那个地址。

        static constexpr int kInputDebounceMilliseconds = 250;

        QTimer* m_targetDebounce = nullptr;
        bool m_targetResolveInFlight = false;
        quint64 m_targetResolveSequence = 0;

        bool m_moduleQueryInFlight = false;
        quint64 m_moduleQuerySequence = 0;

        bool m_baselineInFlight = false;
        quint64 m_baselineSequence = 0;

        QTimer* m_preflightDebounce = nullptr;
        bool m_preflightInFlight = false;
        quint64 m_preflightSequence = 0;

        bool m_installInFlight = false;

        bool m_verifyStaticInFlight = false;
        quint64 m_verifyStaticSequence = 0;
        bool m_verifyResidentInFlight = false;
        quint64 m_verifyResidentSequence = 0;

        // =============================================================
        // 跨步骤共享状态
        // =============================================================

        // m_plan：五步共享的唯一一份可变状态。谁写哪一段见 KvmHookPlan.h 的分节。
        KvmHookPlan m_plan;

        // m_modules：第 1 步模块下拉的数据源，与 m_moduleBox 的行序一一对应。
        QVector<KvmHookModuleChoice> m_modules;

        // m_preflightRows / m_verifyStaticRows / m_verifyResidentRows：
        // 三张表的当前内容。留着是为了让「还有没有 blocking 未通过」和第 4 列按钮
        // 的回调都从同一份数据里取，而不是回头去读表格控件里的字符串。
        QVector<KvmCheckRow> m_preflightRows;
        QVector<KvmCheckRow> m_verifyStaticRows;
        QVector<KvmCheckRow> m_verifyResidentRows;

        // m_eventCursor：B 段读事件用的消费游标（KvmEventEntry::sequence 单调递增）。
        unsigned long long m_eventCursor = 0;

        // m_rehearsalPage：排练入口自己分配的一页。
        // VirtualAlloc 出来的，天然 4 KiB 对齐；分配后要写一字节并 VirtualLock，
        // 否则翻译到的帧随时会换人。所有权在本对话框，析构时释放（且必须在移除
        // 视图之后）。
        void* m_rehearsalPage = nullptr;

        Step m_currentStep = Step::Target;
        bool m_busy = false;

        // =============================================================
        // 控件
        // =============================================================

        // ---- 骨架（[W] 创建）----
        QStackedWidget* m_pageStack = nullptr;
        QLabel* m_stepTitleLabel = nullptr;
        QLabel* m_stepHintLabel = nullptr;
        QPushButton* m_backButton = nullptr;
        QPushButton* m_nextButton = nullptr;
        QPushButton* m_closeButton = nullptr;
        QLabel* m_statusLabel = nullptr;

        // ---- 第 1 步（[W] 创建）----
        QComboBox* m_sourceBox = nullptr;
        QStackedWidget* m_sourceStack = nullptr;
        QComboBox* m_moduleBox = nullptr;
        QPushButton* m_moduleReloadButton = nullptr;
        QLineEdit* m_moduleOffsetEdit = nullptr;
        QLabel* m_moduleRangeLabel = nullptr;
        QLineEdit* m_kernelVaEdit = nullptr;
        QLineEdit* m_rawPaEdit = nullptr;
        QPushButton* m_rehearsalAllocButton = nullptr;
        QLabel* m_rehearsalLabel = nullptr;
        // 归一化管线四个产物的只读回显 —— 这四个数就是被这条流程消灭掉的那一步
        // 人工计算，必须一直可见。
        QLabel* m_readoutVaLabel = nullptr;
        QLabel* m_readoutFullPaLabel = nullptr;
        QLabel* m_readoutPageBaseLabel = nullptr;
        QLabel* m_readoutPageOffsetLabel = nullptr;
        QLabel* m_targetStatusLabel = nullptr;

        // ---- 第 2 步（[P] 创建）----
        HexEditorWidget* m_shadowEditor = nullptr;
        QPushButton* m_recaptureBaselineButton = nullptr;
        QPushButton* m_revertPatchButton = nullptr;
        QComboBox* m_jumpTemplateBox = nullptr;
        QLineEdit* m_jumpTargetEdit = nullptr;
        QPushButton* m_applyJumpButton = nullptr;
        QLabel* m_patchSummaryLabel = nullptr;
        QPlainTextEdit* m_patchDisassemblyView = nullptr;
        QLabel* m_patchStatusLabel = nullptr;

        // ---- 第 3 步（[V] 创建）----
        QTableWidget* m_preflightTable = nullptr;
        QPushButton* m_preflightRefreshButton = nullptr;
        QLabel* m_preflightStatusLabel = nullptr;

        // ---- 第 4 步（[W] 创建）----
        QPlainTextEdit* m_installSummaryView = nullptr;
        QPushButton* m_installButton = nullptr;
        QLabel* m_installStatusLabel = nullptr;

        // ---- 第 5 步（[V] 创建）----
        QTableWidget* m_verifyStaticTable = nullptr;
        QPushButton* m_verifyRefreshButton = nullptr;
        QGroupBox* m_verifyResidentGroup = nullptr; // 可勾选、默认折叠
        QTableWidget* m_verifyResidentTable = nullptr;
        QPushButton* m_verifyResidentButton = nullptr;
        QLabel* m_verifyStatusLabel = nullptr;
    };
}
