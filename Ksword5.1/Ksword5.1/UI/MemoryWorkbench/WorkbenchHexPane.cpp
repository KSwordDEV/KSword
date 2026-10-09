// ============================================================
// WorkbenchHexPane.cpp
// 作用：
// - 实现 WorkbenchHexPane.h 里"数据与管线接线"这一半：构造/析构、overlay 与三个
//   内部控件的访问器、三条管线（PageProvider/BaselineFeeder/WriteController）的
//   注入与它们到 canvas_/overlay_ 的反向接线、setAddressSpace/clearAddressSpace
//   的换目标流程、setEditable/insertionAddress/jumpTo 这几个薄转发、以及 Wave 3
//   新增的两个增量方法 setSourceRevisionProvider/rereadWindow。
// - 画布信号驱动基线喂入器、把基线喂入器的结果转发回画布这两件"跟随"相关的事也
//   在本文件（四个私有槛）；查找条的构造、Esc/F3 规则、右键菜单与编辑拒绝的转发
//   放在 WorkbenchHexPane.Panels.cpp（见该文件头的分工说明）。
// - 本文件只在 UI 线程被调用（头文件已经逐条声明），因此可以直接触碰 canvas_/
//   overlay_/三个 QPointer 成员，不需要加锁。
// ============================================================

#include "WorkbenchHexPane.h"

#include "WorkbenchBaselineFeeder.h"
#include "WorkbenchPageProvider.h"
#include "WorkbenchWriteController.h"

#include <QSplitter>
#include <QVBoxLayout>

#include <limits>

namespace ks::ui
{
    // 构造：只做一件事——搭界面（buildUi 在 WorkbenchHexPane.Panels.cpp 里定义，
    // 包含子控件创建、画布信号接线、查找条接线与 Esc/F3 快捷键）。overlay_ 由
    // 成员默认构造（空叠加层，HasBaseline()==false），三条管线指针默认空
    // （QPointer 默认构造即为空），hasAddressSpace_ 默认 false——这正是头文件
    // 承诺的"任一管线缺失仍能构造并显示'无数据'初态，不崩溃"的起点：在
    // setAddressSpace 被调用之前，本类的任何公开方法都只会看到"没有地址空间"
    // 这一种状态，不会访问任何未初始化的东西。
    WorkbenchHexPane::WorkbenchHexPane(QWidget* parent)
        : QWidget(parent)
    {
        buildUi();
    }

    // 析构：三个管线指针是 QPointer<非拥有>，管线对象先于本类销毁时会自动变空，
    // 之后不会再被本类（已经在析构中）访问；管线对象后于本类销毁时，它们内部
    // 持有的 canvas_/overlay_ 指针也是非拥有的 QPointer/裸指针，画布随本类的
    // QWidget 基类析构一起被 Qt 的父子关系释放后，QPointer<HexCanvas> 会自动变
    // 空（overlay_ 是值成员，随本类一起被销毁，是裸指针持有方——装配接口文档
    // §1 已经论证过这条生命周期关系：三条管线对象析构时，它们持有的
    // WorkbenchHexPane::overlay() 指针是否仍然有效，与它们相对本类的声明顺序
    // 无关，取决于调用方自己的销毁顺序约定，不是本类需要在这里主动做什么的事）。
    // 因此这里不需要写任何函数体，交给成员的默认析构顺序（声明的逆序）即可。
    WorkbenchHexPane::~WorkbenchHexPane() = default;

    // overlay：返回唯一一份暂存叠加层的引用，供三条管线与三个只读子页经非拥有
    // 指针/引用使用。本类自己不对外转移这份对象的所有权。
    ksword::memwb::MemoryDiffOverlay& WorkbenchHexPane::overlay() noexcept
    {
        return overlay_;
    }

    // canvas / inspector / findBar：内部控件访问器，直接返回已经在 buildUi 里
    // 建好的子控件指针，不转移所有权。三者在构造函数体内（buildUi）就已经建好，
    // 因此这里不需要像 HexView::ensureInspector 那样做"懒创建"。
    HexCanvas* WorkbenchHexPane::canvas() const noexcept
    {
        return canvas_;
    }

    HexInspectorPanel* WorkbenchHexPane::inspector() const noexcept
    {
        return inspector_;
    }

    HexFindBar* WorkbenchHexPane::findBar() const noexcept
    {
        return findBar_;
    }

    // setPageProvider：接住装配层注入的页提供者（非拥有），并把它接到画布——
    // 画布持有 IHexPageProvider* 基类指针，provider 持有 HexCanvas* 回填目标，
    // 两者互相指向对方，一次性接好（见头文件"窗口跟随"一节）。传空表示解除
    // 接线：画布请求页会落到"没有提供者"的状态（静默不回填，HexCanvas 自身的
    // 契约），provider 侧也不会再被本类调用。
    void WorkbenchHexPane::setPageProvider(WorkbenchPageProvider* provider)
    {
        // 换一个新 provider 前，先断开旧 provider 的 jobLanded 连接——旧 provider
        // 若仍存活（只是被换掉，不是被销毁），残留的连接会在它身上每次落地都触发
        // 一次本类的 noteDirty 转发，参数却是"现在"的 pageProvider_/baselineFeeder_
        // 状态，意义已经不对。QPointer 为空（旧 provider 已销毁）时 disconnect 是
        // 安全的空操作。
        if (pageProvider_)
        {
            disconnect(pageProvider_, &WorkbenchPageProvider::jobLanded, this, nullptr);
        }

        pageProvider_ = provider;
        if (provider != nullptr)
        {
            // provider 需要知道往哪个画布回填；canvas_ 在 buildUi 里已经建好，
            // 这里传的恒是同一个非空画布。
            provider->setCanvas(canvas_);

            // jobLanded（增量①）→ 再驱动一次 baselineFeeder_->noteDirty：页请求
            // 刚提交时 hasInFlightRequests()==true，喂入器不会重算；必须等这个
            // 页真正落地（不管成功/失败/取消）之后再補一次 noteDirty，否则"滚动到
            // 一段从未读过的新区域"这种场景里，喂入器会永远停在"脏但以为还在等"
            // 的状态，没有任何后续事件会再把它唤醒。
            //
            // 锚点必须复用 lastAnchor_（上一次真正调用过 noteDirty 时用的那个
            // 锚点），**不能**改用 insertionAddress()：纯滚动（插入点没动，只是
            // 视口中心变了）场景下，caretMoved 根本不会发生，insertionAddress()
            // 仍是滚动之前的旧值；如果这里重新取 insertionAddress()，会在页
            // 落地的这一刻把 onCanvasVisibleRangeChanged 当时记下的"新视口中心"
            // 锚点覆盖回旧插入点，基线窗口因此跟不上纯滚动——已用
            // wpJ5_tests.Baseline.cpp 的 TestScrollOnlyFollowsViaVisibleRangeAnchor
            // 实测抓到（修复前该测试失败：滚动到新区域后窗口 base 纹丝不动）。
            connect(provider, &WorkbenchPageProvider::jobLanded, this, [this]() {
                if (!baselineFeeder_ || !pageProvider_)
                {
                    return;
                }
                const std::uint64_t sourceRevision = sourceRevisionProvider_ ? sourceRevisionProvider_() : 0ULL;
                baselineFeeder_->noteDirty(lastAnchor_, sourceRevision, pageProvider_->hasInFlightRequests());
            });
        }
        // 画布持有的是 IHexPageProvider* 基类指针；WorkbenchPageProvider 公开
        // 继承该接口，传 nullptr 时画布回到"无提供者"状态。
        if (canvas_ != nullptr)
        {
            canvas_->setPageProvider(provider);
        }
    }

    // setBaselineFeeder：接住装配层注入的基线喂入器（非拥有），并把它接到
    // canvas_/overlay_——喂入器需要从画布的页缓存里原样拷字节（copyCachedRange
    // 系列）、往 overlay_ 喂基线，两者都是非拥有指针，由本类（唯一知道 canvas_
    // 与 overlay_ 真实身份的一方）负责接线。传空表示解除接线。
    //
    // **本函数还负责把 feeder->baselineRefreshed 接到本类的 onBaselineRefreshed
    // 槛**（头文件私有槛列表里原本就声明了这个槛，但最初实现遗漏了连接它的这
    // 一行——槛函数本身写对了、也编译通过，却从来不会被调用，canvas_ 因此永远
    // 收不到"叠加层被绕过改了基线"的通知。用 wpJ5_tests.Baseline.cpp 的
    // TestBaselineWindowContainsInsertionPoint 新增的 QSignalSpy 断言实测抓到：
    // flushNow() 之后 lastWindow() 已经正确更新，但 canvas_ 的 contentChanged
    // 一次都没有发出）。
    void WorkbenchHexPane::setBaselineFeeder(WorkbenchBaselineFeeder* feeder)
    {
        if (baselineFeeder_)
        {
            disconnect(baselineFeeder_, &WorkbenchBaselineFeeder::baselineRefreshed, this, nullptr);
        }

        baselineFeeder_ = feeder;
        if (feeder != nullptr)
        {
            feeder->setCanvas(canvas_);
            feeder->setOverlay(&overlay_);
            connect(feeder, &WorkbenchBaselineFeeder::baselineRefreshed, this, &WorkbenchHexPane::onBaselineRefreshed);
        }
    }

    // setWriteController：接住装配层注入的写事务控制器（非拥有），并把 overlay_
    // 的非拥有指针交给它——控制器需要读写叠加层的暂存补丁（DiffBlocks/
    // AcceptWrite 等）。注意：控制器的 target_/confirmation_/audit_ 等依赖不经
    // 由本类注入（本类根本不持有 WorkbenchTarget，见头文件文件头"三者的接线
    // 点"一节只提到 canvas/overlay 这两样是本类独有的），那些由装配层直接调用
    // 控制器自己的 setTarget/setConfirmationSink/setAuditSink 完成；
    // canvasReadOnlyHook/commitSuspendHook 也由装配层直接接到本类的 setEditable
    // 与喂入器的 setSuspended（见头文件"窗口跟随"一节与装配接口文档 §3），本类
    // 不在这里反向注册这两个钩子——那要求本类持有对 baselineFeeder_ 的
    // setSuspended 调用权与对自身 setEditable 的绑定，职责会和装配层重叠，
    // 装配接口文档已经明确把这一步划给了装配层。
    void WorkbenchHexPane::setWriteController(WorkbenchWriteController* controller)
    {
        writeController_ = controller;
        if (controller != nullptr)
        {
            controller->setOverlay(&overlay_);
        }
    }

    // setSourceRevisionProvider：见头文件增量②的声明处注释，只是存一份回调。
    void WorkbenchHexPane::setSourceRevisionProvider(std::function<std::uint64_t()> provider)
    {
        sourceRevisionProvider_ = std::move(provider);
    }

    // setAddressSpace：换目标/换范围的统一入口。
    //
    // **顺序与任务书字面列出的顺序不同，这是本实现对着真实读数修正过的一处
    // 偏离，记录原因**：任务书把 provider.resetScratchLatch/cancelAllInFlight
    // 列在 canvas_->setAddressSpace 之后；但 WorkbenchPageProvider::
    // cancelAllInFlight() 的真实实现（见 WorkbenchPageProvider.cpp）会
    // **无条件** `pendingJobs_.clear()` 并递增 generation_——如果先调用
    // canvas_->setAddressSpace()（它内部的 installSpace 会同步调用
    // requestVisiblePages() 并立刻提交一个新的页请求），再调用
    // cancelAllInFlight()，等于把刚刚替新地址空间提交的请求连同旧请求一起
    // 作废：这个新请求落地时会因为 generation 不符被 D4 判定为"已作废"而
    // 直接丢弃，画布因此永远读不到任何字节——本包夹具
    // wpJ5_tests.Wiring.cpp 的 TestPageProviderWiringEndToEnd 用真实
    // hasInFlightRequests()/读计数逐步打点复现过这个现象（pendingJobs_ 在
    // onJobFinishedOnUiThread 真正落地之前就已经被清空），不是推测。
    // 现在改成先作废旧请求、再换地址空间触发新请求，新请求提交时
    // generation_ 已经是新值，不会被自己刚刚的调用连带作废：
    //   1) pageProvider_->resetScratchLatch / cancelAllInFlight —— 先作废
    //      旧目标仍在途的页读取任务（含已经排队但还没跑的）、清 DDMA 脏扇区
    //      闩锁，此时画布仍是旧地址空间，cancelPages 的画布代次守卫仍然
    //      命中旧请求；
    //   2) canvas_->setAddressSpace —— 清缓存、换新的"画布轴"来源代次，
    //      内部同步提交新地址空间的页请求（此刻 generation_ 已经是第 1 步
    //      之后的新值，不会被追溯作废）；
    //   3) overlay_.LoadBaseline(新 identityKey, firstAddress, {}, {}) ——
    //      用一个"空窗口占位"立即清空旧目标的暂存补丁（LoadBaseline 的语义：
    //      换身份串恒清补丁），真正的基线内容由随后页回填驱动的
    //      BaselineFeeder 喂入，本类不在这里代为读一次目标字节；
    //   4) baselineFeeder_->setIdentityKey / setAddressSpaceBounds —— 让
    //      喂入器知道新身份串与新地址空间边界，并按它们自己的契约清掉旧目标
    //      遗留的待处理锚点/代次、取消已起算的防抖定时器。
    // 三条管线任一为空都只是跳过对应那一步，不影响其余步骤正常进行（支撑"任一
    // 管线缺失不崩溃"的头文件承诺）。
    //
    // canvas_->setAddressSpace 本身会在"首行开始 > 末行"时返回 false 并保持
    // canvas_ 原状（HexCanvas.h 的契约）；此时本函数整体提前返回，不再触碰
    // overlay_/baselineFeeder_——但第 1 步的 cancelAllInFlight 已经执行过
    // （作废旧请求本身不依赖新区间是否合法，是安全的提前动作，不回滚）。
    void WorkbenchHexPane::setAddressSpace(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress,
        const std::string& identityKey)
    {
        if (canvas_ == nullptr)
        {
            // 防御：canvas_ 在 buildUi 里恒会建好，正常运行不会走到这里；
            // 保留判空只是不让本函数假设一个绝对不出错的前提。
            return;
        }

        const QPointer<WorkbenchHexPane> alive(this);
        const std::uint64_t spaceTicket = ++spaceRevision_;
        ++navigationRevision_;
        const auto current = [this, alive, spaceTicket]() {
            return alive && spaceRevision_ == spaceTicket;
        };

        if (pageProvider_)
        {
            pageProvider_->resetScratchLatch();
            if (!current()) return;
            pageProvider_->cancelAllInFlight();
            if (!current()) return;
        }

        const bool installed = canvas_->setAddressSpace(firstAddress, lastAddress);
        if (!current()) return;
        if (!installed)
        {
            // 非法区间（first > last）：画布保持原状，本函数不再继续——
            // overlay_/baselineFeeder_ 都还没被这次调用改动过。
            return;
        }

        // 换新身份串、清空旧补丁、以"空窗口"占位——真正的基线内容等页回填
        // 驱动 BaselineFeeder 喂入。bytes/validMask 都传空向量，长度为 0 的
        // 窗口是 MemoryDiffOverlay::LoadBaseline 的合法输入（校验只检查两者
        // 等长且 baseAddress+长度不溢出，0 长度恒满足）。
        overlay_.LoadBaseline(identityKey, firstAddress, {}, {});

        if (baselineFeeder_)
        {
            baselineFeeder_->setIdentityKey(identityKey);
            baselineFeeder_->setAddressSpaceBounds(
                ksword::memwb::AddressSpaceBounds{firstAddress, lastAddress});
        }

        hasAddressSpace_ = true;

        // 旧目标的可见范围缓存对新目标没有意义；canvas_->setAddressSpace 内部
        // 会同步重新发一次 visibleRangeChanged（新地址空间非空时），
        // onCanvasVisibleRangeChanged 会在那一刻把这两个成员重新填入新值。
        hasVisibleRange_ = false;
        lastVisibleFirst_ = 0;
        lastVisibleLast_ = 0;

        // ---- 独立审核 wave3 review-wpJ5.md §1.1 修复：不依赖画布是否重发信号 ----
        // 换目标但地址空间边界恰好与旧目标相同、且插入点从未被用户移动过时
        // （典型：Process 范围内切换到位数相同的另一个进程，用户还没碰过画布），
        // HexCanvas 的两处去重逻辑可能一个信号都不发：
        //   ①notifyVisibleRange()（HexCanvas.Scroll.cpp）只在"本次可见范围与
        //     上次通知的 [first,last] 不同"时才 emit——同一地址空间边界算出的
        //     可见范围完全一样，不会重发；
        //   ②applySelectionChange()（InstallSpace 内部）只在插入点真的变化时
        //     才 emit caretMoved——新视图的插入点恒落在 firstAddress（见
        //     HexViewport 构造），如果旧插入点正好也停在旧目标的 firstAddress
        //     （同样的边界值），两者相等，同样不会重发。
        // 两条路径都哑火时，onCanvasVisibleRangeChanged/onCanvasCaretMoved 都
        // 不会被调用，lastAnchor_ 停留在旧目标身上，基线窗口因此可能永远围绕
        // 一个已经不存在的旧目标锚点选取，直到用户下一次手动滚动/移动插入点
        // 才会被唤醒——这段时间内 F5/实时刷新/写后重读这些依赖"基线窗口"的
        // 功能工作在一段与屏幕脱节的地址范围上。
        // 本函数不等待画布的信号，自己在这里无条件更新锚点并喂一次
        // noteDirty：
        // - 锚点取 canvas_->caretAddress()——HexViewport 的构造函数把初始插入点
        //   钉死在 firstAddress（shared/evidence/memory_workbench/HexViewport.cpp），
        //   所以这里读到的恒是"新地址空间的起点"，同时也完全符合"锚点＝插入点"
        //   这条文档字面约定（不是另造一种"起点兜底"的第三种锚点语义）。
        // - 在途位取 pageProvider_->hasInFlightRequests()——canvas_->setAddressSpace
        //   内部的 requestVisiblePages() 可能已经同步提交了新请求（Gate 可用时，
        //   WorkbenchPageProvider::submitJob 会在返回前就把 pendingJobs_ 填好），
        //   这里读到的是此刻真实的在途状态，不是凭空传 false；若确实在途，
        //   noteDirty 只记录待处理请求，真正的重算留给 jobLanded 落地时按
        //   lastAnchor_（这里已经更新为新锚点）再驱动一次。
        if (canvas_ != nullptr)
        {
            lastAnchor_ = canvas_->caretAddress();
            if (baselineFeeder_)
            {
                const std::uint64_t sourceRevision = sourceRevisionProvider_ ? sourceRevisionProvider_() : 0ULL;
                if (!current()) return;
                const bool inFlight = pageProvider_ ? pageProvider_->hasInFlightRequests() : false;
                baselineFeeder_->noteDirty(lastAnchor_, sourceRevision, inFlight);
            }
        }
    }

    // clearAddressSpace：回到"无目标"状态，与 setAddressSpace 对称地清空
    // canvas_/overlay_/三条管线的相关状态，但不要求地址空间参数（没有新目标）。
    void WorkbenchHexPane::clearAddressSpace()
    {
        const QPointer<WorkbenchHexPane> alive(this);
        const std::uint64_t spaceTicket = ++spaceRevision_;
        ++navigationRevision_;
        const auto current = [this, alive, spaceTicket]() {
            return alive && spaceRevision_ == spaceTicket;
        };
        // 与 setAddressSpace 同一个顺序理由（见该函数的注释）：先作废旧的
        // 在途页请求，再改画布状态——clearAddressSpace 本身不会让画布提交
        // 新请求，这里不是同一个 bug 会实际触发的场景，但保持同一顺序避免
        // 以后两个函数的写法不一致、留下误导。
        if (pageProvider_)
        {
            pageProvider_->resetScratchLatch();
            if (!current()) return;
            pageProvider_->cancelAllInFlight();
            if (!current()) return;
        }

        if (canvas_ != nullptr)
        {
            canvas_->clearAddressSpace();
            if (!current() || canvas_->addressSpaceRange().has_value()) return;
        }

        // 身份串清空、窗口清空：与 setAddressSpace 同一个 LoadBaseline 调用，
        // 只是新身份串是空串——"无目标"本身就是一种身份，旧补丁同样被清空。
        overlay_.LoadBaseline(std::string(), 0, {}, {});

        if (baselineFeeder_)
        {
            baselineFeeder_->setIdentityKey(std::string());
            baselineFeeder_->setAddressSpaceBounds(ksword::memwb::AddressSpaceBounds{});
        }

        hasAddressSpace_ = false;
        hasVisibleRange_ = false;
        lastVisibleFirst_ = 0;
        lastVisibleLast_ = 0;
    }

    // setEditable：薄转发；WriteController 的 CanvasReadOnlyHook 正是接到本方法
    // （由装配层连接，见头文件注释），本类自己不判断"写入忙/只读通道"这些业务
    // 规则，只负责把结果转给画布。
    void WorkbenchHexPane::setEditable(bool editable)
    {
        if (canvas_ != nullptr)
        {
            canvas_->setEditable(editable);
        }
    }

    // insertionAddress：薄转发 canvas_->caretAddress()；canvas_ 恒非空（buildUi
    // 保证），没有地址空间时 HexCanvas 自己的契约是返回 0。
    std::uint64_t WorkbenchHexPane::insertionAddress() const
    {
        return (canvas_ != nullptr) ? canvas_->caretAddress() : 0;
    }

    void WorkbenchHexPane::requestBrowseWindow(std::uint64_t address, std::uint64_t length)
    {
        if (!canvas_ || !length) return;
        const auto bounds = canvas_->addressSpaceRange();
        if (!bounds || address < bounds->first || address > bounds->last) return;
        const auto last = address + std::min<std::uint64_t>(length - 1, bounds->last - address);
        canvas_->requestAddressRange(address, last);
        lastVisibleFirst_ = address;
        lastVisibleLast_ = last;
        hasVisibleRange_ = true;
        lastAnchor_ = address + (last - address) / 2;
        if (baselineFeeder_)
            baselineFeeder_->noteDirty(lastAnchor_, sourceRevisionProvider_ ? sourceRevisionProvider_() : 0ULL,
                pageProvider_ ? pageProvider_->hasInFlightRequests() : false);
    }

    void WorkbenchHexPane::setExternalBrowseMode(bool enabled)
    {
        if (externalBrowseMode_ == enabled) return;
        externalBrowseMode_ = enabled;
        if (!canvas_) return;
        // 重新启用视口读取和滚动都可能同步通知宿主，宿主可以销毁本页。
        const QPointer<WorkbenchHexPane> alive(this);
        canvas_->setViewportReadEnabled(!enabled);
        if (!alive) return;
        if (!enabled)
        {
            // 用户纯滚动不会移动 caret；切页返回只恢复当前真实视口及其基线，
            // 不能为了揭示旧 caret 把浏览位置拉回。显式跨页定位已由 jumpTo 处理。
            const auto visible = canvas_->visibleAddressRange();
            if (visible) onCanvasVisibleRangeChanged(visible->first, visible->last);
        }
    }

    // selectionStart：选区闭区间的起点；无选区（无地址空间）时退回插入点（此时恒为 0）。
    std::uint64_t WorkbenchHexPane::selectionStart() const
    {
        if (canvas_ == nullptr)
        {
            return 0;
        }
        const std::optional<HexCanvas::AddressRange> range = canvas_->selectedRange();
        return range.has_value() ? range->first : canvas_->caretAddress();
    }

    // jumpTo：跳转入口。先用 cellStateAt(address).inSpace 核实目标地址本身是否
    // 落在当前地址空间内——这是"返回 false"的唯一判据，不借助 setCaretAddress
    // 的返回值做这件事（那个返回值还会被"选区末端是否越界"干扰，见下）。
    // 地址本身合法之后，用与 HexFindBar::onFindMatch 相同的两段式手法选中
    // [address, endAddress]：先把锚点移到选区末端（extend=false），再把插入点
    // 移回起点（extend=true，锚点不动），结果是"选区覆盖整段、插入点停在起点"。
    // 如果选区末端越过地址空间尾部，在发通知前退为起点单字节；有效地址的
    // setCaretAddress 若返回 false，表示同步换源/重入，不能再恢复旧请求。
    bool WorkbenchHexPane::jumpTo(std::uint64_t address, std::uint64_t selectLength,
        HexCanvas::ScrollAlign align)
    {
        if (!hasAddressSpace_ || canvas_ == nullptr)
        {
            return false;
        }
        if (!canvas_->cellStateAt(address).inSpace)
        {
            return false;
        }

        const std::uint64_t length = (selectLength == 0) ? 1ULL : selectLength;
        std::uint64_t endAddress = address;
        if (length > 1ULL)
        {
            const std::uint64_t span = length - 1ULL;
            constexpr std::uint64_t kMaxAddress = (std::numeric_limits<std::uint64_t>::max)();
            endAddress = (span > kMaxAddress - address) ? kMaxAddress : (address + span);
        }
        if (!canvas_->cellStateAt(endAddress).inSpace) endAddress = address;

        // 选区通知允许同步销毁页面；冻结对齐参数后，在下一次触碰画布前探活。
        const QPointer<WorkbenchHexPane> alive(this);
        const std::uint64_t navigationTicket = ++navigationRevision_;
        const std::uint64_t sourceTicket = canvas_->sourceRevision();
        const auto current = [this, alive, navigationTicket, sourceTicket]() {
            return alive && navigationRevision_ == navigationTicket && canvas_->sourceRevision() == sourceTicket;
        };
        const bool endAccepted = canvas_->setCaretAddress(endAddress, false, false);
        if (!current() || !endAccepted)
        {
            return false;
        }
        // extend=true 保留上一步设下的锚点（在 endAddress），把插入点移回起点，
        // 先完成选区，再按调用方的明确政策滚动；避免 setCaretAddress 自带的
        // Nearest 把远处地址压到末行，造成模块/区域起点之前全是未知字节。
        const bool startAccepted = canvas_->setCaretAddress(address, true, false);
        if (!current() || !startAccepted)
        {
            return false;
        }
        const bool revealed = canvas_->revealCaret(align);
        return current() && revealed;
    }

    // rereadWindow：见头文件增量③的声明处注释。计算"基线窗口"（overlay_ 当前
    // 已载入的那一段）与"可见页"（onCanvasVisibleRangeChanged 缓存的最近一次
    // 可见范围）两个闭区间的并集，交给 pageProvider_->rereadByteRange 原位
    // 重读。两者都缺失（从未 setAddressSpace，或刚 clearAddressSpace）时什么
    // 都不做；pageProvider_ 为空同样什么都不做（没有管线可以执行重读）。
    void WorkbenchHexPane::rereadWindow()
    {
        if (!pageProvider_)
        {
            return;
        }

        bool haveRange = false;
        std::uint64_t unionFirst = 0;
        std::uint64_t unionLast = 0;

        if (overlay_.HasBaseline() && overlay_.BaselineSize() > 0)
        {
            unionFirst = overlay_.BaseAddress();
            unionLast = overlay_.BaseAddress() + overlay_.BaselineSize() - 1ULL;
            haveRange = true;
        }

        if (hasVisibleRange_)
        {
            if (!haveRange)
            {
                unionFirst = lastVisibleFirst_;
                unionLast = lastVisibleLast_;
                haveRange = true;
            }
            else
            {
                unionFirst = (lastVisibleFirst_ < unionFirst) ? lastVisibleFirst_ : unionFirst;
                unionLast = (lastVisibleLast_ > unionLast) ? lastVisibleLast_ : unionLast;
            }
        }

        if (!haveRange)
        {
            return;
        }

        // 长度 = unionLast - unionFirst + 1；唯一的回绕风险是 unionFirst==0 且
        // unionLast==UINT64_MAX（整个 64 位地址空间都在并集内），此时按最大可
        // 表示长度处理，不让加 1 绕回 0。
        constexpr std::uint64_t kMaxAddress = (std::numeric_limits<std::uint64_t>::max)();
        const std::uint64_t length =
            (unionFirst == 0 && unionLast == kMaxAddress) ? kMaxAddress : (unionLast - unionFirst + 1ULL);

        pageProvider_->rereadByteRange(unionFirst, length);
    }

    // setRowWidthPreference：应用一份行宽偏好（见头文件）。
    // 自适应：只记下手选值、把画布切到自适应（画布立即按当前视口宽度重选一档）；
    // 手动：把画布固定为手选值（HexCanvas::setBytesPerRow 会同时关闭自适应）。
    void WorkbenchHexPane::setRowWidthPreference(bool automatic, int manualBytes)
    {
        if (canvas_ == nullptr)
        {
            return;
        }

        // 手选值只接受画布支持的几档；非法值忽略，沿用已记下的值，不让坏数据污染"上次手选值"。
        if (manualBytes > 0
            && ksword::memwb::HexViewport::IsSupportedBytesPerRow(static_cast<std::uint32_t>(manualBytes)))
        {
            manualBytesPerRow_ = manualBytes;
        }

        if (automatic)
        {
            canvas_->setAutoBytesPerRow(true);
        }
        else
        {
            canvas_->setBytesPerRow(manualBytesPerRow_);
        }
    }

    // rowWidthAutomatic：画布当前是否自适应行宽。
    bool WorkbenchHexPane::rowWidthAutomatic() const
    {
        return canvas_ != nullptr && canvas_->isAutoBytesPerRow();
    }

    // manualBytesPerRow：用户上次手选的行宽。
    int WorkbenchHexPane::manualBytesPerRow() const
    {
        return manualBytesPerRow_;
    }

    // onCanvasVisibleRangeChanged：画布可见范围变化——缓存下来供 rereadWindow()
    // 使用，并用视口中心作为锚点驱动 baselineFeeder_->noteDirty（docs 原文：
    // "anchorAddress 当前锚点（插入点或视口中心）"，滚动场景用视口中心更贴近
    // "这段窗口现在该围绕哪里选取"的直觉）。
    void WorkbenchHexPane::onCanvasVisibleRangeChanged(quint64 first, quint64 last)
    {
        if (externalBrowseMode_) return;
        const QPointer<WorkbenchHexPane> alive(this);
        const std::uint64_t navigationTicket = navigationRevision_;
        const std::uint64_t sourceTicket = canvas_->sourceRevision();
        const auto current = [this, alive, navigationTicket, sourceTicket, first, last]() {
            if (!alive || navigationRevision_ != navigationTicket || canvas_->sourceRevision() != sourceTicket) return false;
            const auto actual = canvas_->visibleAddressRange();
            return actual && actual->first == first && actual->last == last;
        };
        lastVisibleFirst_ = first;
        lastVisibleLast_ = last;
        hasVisibleRange_ = true;

        if (findBar_ != nullptr)
        {
            // 查找条的可见高亮按当前可见范围重算，见 HexFindBar::setVisibleRange。
            findBar_->setVisibleRange(first, last);
            if (!current()) return;
        }

        // 视口中心：first + (last-first)/2，二者都是无符号数，first<=last 由
        // 画布保证，减法不会回绕。无论 baselineFeeder_ 是否注入都先记下来——
        // lastAnchor_ 是 jobLanded 落地时唯一可信的锚点来源（见该连接处的
        // 注释），不能因为这一刻 feeder 恰好是空指针就不更新。
        const std::uint64_t anchor = first + (last - first) / 2ULL;
        lastAnchor_ = anchor;

        if (baselineFeeder_)
        {
            const std::uint64_t sourceRevision = sourceRevisionProvider_ ? sourceRevisionProvider_() : 0ULL;
            if (!current()) return;
            const bool inFlight = pageProvider_ ? pageProvider_->hasInFlightRequests() : false;
            baselineFeeder_->noteDirty(anchor, sourceRevision, inFlight);
        }
    }

    // onCanvasCaretMoved：插入点变化——转发为本类自己的 insertionPointChanged
    // 信号（供装配层刷新侧栏/状态条等），并用插入点本身作锚点驱动
    // baselineFeeder_->noteDirty（"锚点"的另一种取值：插入点）。
    void WorkbenchHexPane::onCanvasCaretMoved(quint64 address)
    {
        const QPointer<WorkbenchHexPane> alive(this);
        const std::uint64_t navigationTicket = navigationRevision_;
        const std::uint64_t sourceTicket = canvas_->sourceRevision();
        const auto current = [this, alive, navigationTicket, sourceTicket, address]() {
            return alive && navigationRevision_ == navigationTicket && canvas_->sourceRevision() == sourceTicket
                && canvas_->caretAddress() == address;
        };
        emit insertionPointChanged(address);
        if (!current()) return;
        if (externalBrowseMode_) return;

        // 同上：lastAnchor_ 无条件更新，不依赖 baselineFeeder_ 是否已注入。
        lastAnchor_ = address;

        if (baselineFeeder_)
        {
            const std::uint64_t sourceRevision = sourceRevisionProvider_ ? sourceRevisionProvider_() : 0ULL;
            if (!current()) return;
            const bool inFlight = pageProvider_ ? pageProvider_->hasInFlightRequests() : false;
            baselineFeeder_->noteDirty(address, sourceRevision, inFlight);
        }
    }

    // onCanvasContentChanged：画布上某些地址显示的值可能变了（页回填、换代次、
    // 暂存、丢弃……，详见 HexCanvas.h"四之二"）。HexInspectorPanel 自己订阅了
    // 画布的这个信号（setCanvas 内部接好），本类不需要代为转发；本类真正要做
    // 的是驱动 WorkbenchWriteController::notifyWindowMayCover（地址簿异步暂存
    // 票据据此重新尝试），以及让查找条知道数据可能已经变化（HexFindBar::
    // dataChanged 会取消在途搜索、丢弃陈旧结果与高亮——宁可偶尔多invalidate
    // 一次正在进行的搜索，也不让搜索结果残留在已经变化的数据上）。
    void WorkbenchHexPane::onCanvasContentChanged()
    {
        if (writeController_)
        {
            writeController_->notifyWindowMayCover();
        }
        if (findBar_ != nullptr)
        {
            findBar_->dataChanged();
        }
    }

    // onBaselineRefreshed：WorkbenchBaselineFeeder 成功喂入（或原位重喂）一次
    // 基线之后发出，本类据此调用 canvas_->notifyOverlayChanged()——画布自己的
    // stageBytes/丢弃会自动发信号，但"宿主绕过画布直接改了叠加层"这一类变化
    // （RefreshBaseline 正是其中一种）画布无从知道，必须显式通知（见 HexCanvas.h
    // "四之二"）。
    void WorkbenchHexPane::onBaselineRefreshed(quint64 baseAddress, quint64 length)
    {
        Q_UNUSED(baseAddress);
        Q_UNUSED(length);
        if (canvas_ != nullptr)
        {
            canvas_->notifyOverlayChanged();
        }
    }
}
