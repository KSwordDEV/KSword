#pragma once

// ============================================================
// HexFindBar.h
// 作用：
// - HexView 的查找条：模式（十六进制 / UTF-8 / UTF-16LE / 系统 ANSI 四段按钮）、输入框、区分大小写开关、
//   上一个 / 下一个、结果文字、关闭。取代旧 HexEditorWidget 的查找面板。
// - 搜索引擎复用 shared/evidence/memory_workbench/MemoryByteSearch（经 HexFindSearch.h 适配）：
//   半字节通配、空格逗号分隔或连写、UTF-16LE、可取消的分块扫描、重叠命中。
//
// ------------------------------------------------------------
// 一、取代旧控件的缺陷
// ------------------------------------------------------------
// - 旧控件"十六进制必须空格分隔"：现在 4D5A9000、0x4D 0x5A、4D,5A 都合法，?? / A? / ?A 通配。
// - 旧控件 Next 到尾静默回绕：现在回绕时结果文字写明"已从头继续"（向前找）或"已从末尾继续"（向后找），
//   一整圈都没有命中则写"未找到"。回绕由本条显式请求（wrap=true），引擎如实置位 wrapped。
// - 旧控件编辑缓冲后命中高亮残留、重读后旧结果套到新数据：现在宿主在缓冲变化时调用 dataChanged()，
//   本条取消在途搜索、丢弃陈旧结果（票据）、清掉高亮与"上一个命中"，并提示"数据已变化，请重新查找"。
//
// ------------------------------------------------------------
// 二、后台搜索与线程安全
// ------------------------------------------------------------
// - 搜索在本条自有的单线程 QThreadPool 里运行，UI 线程不阻塞。数据取查找开始那一刻缓冲的隐式共享拷贝
//   （QByteArray 引用计数，不复制数据）；搜索期间宿主改缓冲只会让宿主那一侧写时分离，不影响正在扫描的快照。
// - 每次搜索领一张票据（递增整数）并带一个取消标志；新搜索、dataChanged()、deactivate()、析构都会置位旧标志并
//   让票据前进。结果经队列回到 UI 线程，票据对不上就丢弃——陈旧结果绝不会选中、高亮或改文字。
// - 引擎在每个 256 KiB 分块读取之前检查取消标志，所以取消在一个分块的扫描时间内生效。
// - 析构：置位取消、让票据前进、waitForDone()，之后才销毁控件；工作线程的回调以本对象为上下文入队，
//   对象销毁后队列里的回调被 Qt 丢弃，窗口关闭时不会触及悬空对象。
//
// ------------------------------------------------------------
// 三、命中呈现
// ------------------------------------------------------------
// - 命中后发 matchFound(起点, 长度, 是否回绕)，宿主据此选中命中范围并滚动到可见（HexView 已接好）。
// - 当前可见范围内的全部命中用 highlightsChanged 交给宿主画（宿主用画布高亮层）。只扫描可见范围
//   （HitsInRange），耗时与缓冲大小无关；宿主在滚动/换行宽时调用 setVisibleRange 让高亮跟随视口。
// - "起点"规则：下一个 = 上次命中起点 + 1（允许重叠命中）；选区不是上次命中时从选区起点（含）开始；
//   上一个对称。到尽头一律回绕并明示。
//
// ------------------------------------------------------------
// 四、接口约定（宿主需要提供两个回调，且只在 UI 线程调用）
// ------------------------------------------------------------
// - setSourceGetter：返回当前缓冲与基址。每次搜索开始、每次刷新高亮时调用，返回值只被当次使用。
// - setSelectionGetter：返回当前选区闭区间；返回 false 表示没有选区。用来决定搜索起点。
// - 所有公开函数只允许在 UI 线程调用。
//
// 文件分工：HexFindBar.h（Q_OBJECT，需 moc）/ HexFindBar.cpp（界面与状态）/ HexFindSearch.h/.cpp（纯逻辑）。
// ============================================================

#include "HexFindSearch.h"
#include "HexViewWidgets.h"

#include <QByteArray>
#include <QString>
#include <QThreadPool>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

class QLineEdit;

namespace ks::ui
{
    // HexFindBar：查找条，详见文件头。
    class HexFindBar : public HexViewBarFrame
    {
        Q_OBJECT

    public:
        // 下面几个别名只是让调用方少写命名空间。
        using Mode = hexfind::Mode;
        using AddressRange = hexfind::AddressRange;

        // SourceView：一次搜索使用的数据快照。
        struct SourceView
        {
            QByteArray data;            // 缓冲（隐式共享）
            std::uint64_t base = 0;     // 缓冲对应的起始地址
            QByteArray validMask;       // 非空时逐字节标明可读性；普通完整文件缓冲留空表示全部有效
        };

        // SourceGetter：宿主提供的数据读取回调。
        using SourceGetter = std::function<SourceView()>;
        // Optional highlighter-only range snapshot; full navigation search stays unchanged.
        using RangeSourceGetter = std::function<SourceView(std::uint64_t first, std::uint64_t last)>;

        // SelectionGetter：宿主提供的选区读取回调；返回 false 表示没有选区，两个出参指向选区闭区间两端。
        using SelectionGetter = std::function<bool(std::uint64_t* firstOut, std::uint64_t* lastOut)>;

        // 构造：parent 为父控件。创建界面与单线程池，初始隐藏由宿主决定。
        explicit HexFindBar(QWidget* parent = nullptr);

        // 析构：取消在途搜索并等待工作线程结束（见文件头第二节）。
        ~HexFindBar() override;

        // ---------------- 宿主接口 ----------------

        // setSourceGetter / setSelectionGetter：设置两个回调（见文件头第四节）。
        void setSourceGetter(SourceGetter getter);
        void setRangeSourceGetter(RangeSourceGetter getter);
        void setSelectionGetter(SelectionGetter getter);

        // dataChanged：缓冲内容变了（换数据、编辑、静默改字节）。
        // 作用：取消在途搜索、让票据前进（陈旧结果被丢弃）、清除高亮与上次命中。
        void dataChanged();

        // setVisibleRange：宿主告知当前可见地址范围（闭区间）；已有命中时据此重算可见高亮。
        void setVisibleRange(std::uint64_t first, std::uint64_t last);

        // open：显示本条并聚焦输入框、全选已有文字。
        void open();

        // deactivate：取消搜索、清除高亮与结果文字、让票据前进（不隐藏本条，隐藏由宿主负责）。
        void deactivate();

        // ---------------- 状态与输入 ----------------

        // mode / setMode：当前查找模式；切换会更新占位提示与大小写开关的可用性，不清输入。
        Mode mode() const;
        void setMode(Mode mode);

        // patternText / setPatternText：输入框文字。
        QString patternText() const;
        void setPatternText(const QString& text);

        // caseSensitive / setCaseSensitive：区分大小写开关（只对文本模式有意义）。
        bool caseSensitive() const;
        void setCaseSensitive(bool enabled);

        // findNext / findPrevious：开始一次向后 / 向前的查找（异步）。
        // 传出：true 表示搜索已启动；false 表示没有启动（模式无效或没有数据，原因已显示在结果文字里）。
        bool findNext();
        bool findPrevious();

        // isSearching：是否有搜索在途。
        bool isSearching() const;

        // waitForIdle：等待工作线程池空闲，最多 timeoutMs 毫秒；传出：是否在时限内空闲。
        // 注意：它只等线程结束，结果回调仍在事件循环里排队，调用方需要再处理一轮事件。
        bool waitForIdle(int timeoutMs);

        // resultText / resultKind：结果文字与种类（"已找到 …" / "未找到" / "无效模式：…" 等）。
        QString resultText() const;
        HexViewMessageLabel::Kind resultKind() const;

        // highlightRanges / highlightActive：当前交给宿主的可见高亮区间与是否处于"有命中"状态。
        const std::vector<AddressRange>& highlightRanges() const;
        bool highlightActive() const;

        // 内部控件访问器：供宿主微调与离屏测试读取，不改变行为。
        QLineEdit* lineEdit() const;
        HexViewSegmented* modeSegment() const;
        HexViewGlyphButton* caseButton() const;
        HexViewGlyphButton* previousButton() const;
        HexViewGlyphButton* nextButton() const;
        HexViewGlyphButton* closeButton() const;

    signals:
        // matchFound：搜索命中。first 起点，length 命中长度，wrapped 是否经过了回绕。
        void matchFound(quint64 first, quint64 length, bool wrapped);

        // searchCompleted：一次（未被丢弃的）搜索结束，found 表示是否命中。被取消/陈旧的搜索不发。
        void searchCompleted(bool found);

        // highlightsChanged：可见高亮区间变化（含清空）。
        void highlightsChanged(const std::vector<hexfind::AddressRange>& ranges);

        // closeRequested：用户点了关闭按钮。
        void closeRequested();

    private:
        // Direction：查找方向（引擎类型的别名，缩短书写）。
        using Direction = ksword::memwb::SearchDirection;

        // LastMatch：上一次命中，用来决定"下一个"从哪里开始。
        struct LastMatch
        {
            bool valid = false;             // 是否有效
            std::uint64_t address = 0;      // 命中起点
            std::uint64_t length = 0;       // 命中长度
            ksword::memwb::SearchPattern pattern;   // 产生这次命中的模式（换了模式后选区即使仍是旧命中，也要从选区起点（含）重新找）
        };

        // ---------- HexFindBar.cpp ----------
        void buildUi();
        bool startSearch(Direction direction);
        void onSearchFinished(
            std::uint64_t ticket,
            const hexfind::Outcome& outcome,
            bool forcedWrap,
            Direction direction);
        void showResult(HexViewMessageLabel::Kind kind, const QString& text);
        void refreshHighlights();
        void clearHighlights();
        void cancelRunning();
        void onModeChanged();

        // ---- 子控件 ----
        HexViewSegmented* m_modeSegment = nullptr;      // 模式三段按钮
        QLineEdit* m_edit = nullptr;                    // 输入框
        HexViewGlyphButton* m_caseButton = nullptr;     // 区分大小写开关
        HexViewGlyphButton* m_prevButton = nullptr;     // 上一个
        HexViewGlyphButton* m_nextButton = nullptr;     // 下一个
        HexViewGlyphButton* m_closeButton = nullptr;    // 关闭
        HexViewMessageLabel* m_result = nullptr;        // 结果文字

        // ---- 宿主回调 ----
        SourceGetter m_sourceGetter;
        RangeSourceGetter m_rangeSourceGetter;                    // 数据读取回调
        SelectionGetter m_selectionGetter;              // 选区读取回调

        // ---- 搜索状态 ----
        QThreadPool m_pool;                             // 单线程池：后台搜索
        std::uint64_t m_ticket = 0;                     // 当前票据；结果票据对不上即丢弃
        std::shared_ptr<std::atomic<bool>> m_cancel;    // 当前搜索的取消标志（与工作线程共享）
        bool m_searching = false;                       // 是否有搜索在途
        ksword::memwb::SearchPattern m_pendingPattern;  // 在途搜索使用的模式（结果被接受时转为 m_activePattern）
        LastMatch m_last;                               // 上一次命中

        // ---- 高亮状态 ----
        bool m_active = false;                          // 是否有成功的搜索（可见高亮据此计算）
        ksword::memwb::SearchPattern m_activePattern;   // 高亮使用的模式
        bool m_visibleValid = false;                    // 宿主是否告知过可见范围
        std::uint64_t m_visibleFirst = 0;               // 可见范围起点
        std::uint64_t m_visibleLast = 0;                // 可见范围终点
        std::vector<AddressRange> m_highlights;         // 当前交给宿主的可见高亮
    };
}
