#pragma once

// ============================================================
// WorkbenchCompareView.h
// 作用：
// - 内存工作台 Phase 3 的"对比"子页（WP-H）。分两段："待写入修改"（橙）与"两次读取之间"
//   （青），数据同样只经 IWorkbenchBytesProvider 读取（见 WorkbenchDisasmView.h），本文件不做
//   任何 I/O、不持有目标，颜色规则与 HexCanvas.Paint.cpp 的 PaintPalette 完全一致。
// - 两段数据直接对应 ksword::memwb::ByteChangeKind：
//     Pending         → "待写入修改"：旧值取 BaselineByte（未叠加补丁），新值取 Materialize
//                        （叠加补丁后的现值，即将要写入目标的值）；
//     ExternalChange  → "两次读取之间"：旧值取 PreviousByte（上一次读取），新值取当前
//                        BaselineByte（这一次读取）。D8 修复后不再直接用 ChangeKind()==
//                        ExternalChange 判定命中：该函数按 Pending > SelfWritten >
//                        ExternalChange 的优先级，一个字节如果同时有暂存补丁又发生了外部
//                        变化只会报 Pending，把"目标自己也变了"这件事藏起来——这正是本页
//                        最该提示的情形。现改为自己重新比较 previous/baseline，只排除真正
//                        的 SelfWritten（可疑点 7）。
// - 分组按"绝对地址 16 字节对齐"（与 HexViewport 的行网格一致，不是按窗口起点从 0 开始数），
//   窗口起点本身非 16 的倍数时第一组仍然只覆盖窗口实际有的那一段（可疑点 6）；一行只要
//   落在该分组里的任一字节命中当前分段就显示；真虚拟列表（见 CompareGroupSummary），不再
//   有旧版的"上一页/下一页"分页钮，也不会为未命中的分组分配任何字符串。
// - "两次读取之间"在 HasPreviousRead() 为假时整段隐藏表格，显示旧文案（沿用旧文案，一字不改：
//   "没有上次相同目标和范围的读取可供对比。"）。
// - N5（第二轮审核）：按绝对地址分组的循环贴着地址空间顶端（窗口终点为 2^64-1）时，组地址
//   自增会整数回绕成死循环；rebuildRows() 的循环体末尾在自增前判断一次是否快要回绕，提前
//   结束。N6：悬停明细里"（另有待写入）"这段标注经 ks::i18n::displayText 翻译（模型
//   ToolTipRole 不会被通用小部件扫描自动翻译到）。
// ============================================================

#include "WorkbenchDisasmView.h"

#include <QAbstractTableModel>
#include <QColor>
#include <QString>
#include <QVector>
#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QTableView;

namespace ks::ui
{
    class HexViewSegmented;

    // CompareGroupSummary：D8——一个命中分组的摘要，只含整数/地址，不含任何格式化好的文本。
    // 真虚拟列表的关键就在这里：rebuildRows 扫描整窗口时只做这种便宜的整数比较来决定
    // "这一组要不要显示"，真正的十六进制/ASCII/悬停明细文本留给 data() 按需现算，
    // 代价是同一单元格被多次请求会重复格式化一次，换来的是"扫一遍不显示的窗口"不再
    // 分配任何字符串、"显示很多命中行"也不会在 rebuildRows 这一刻就把所有文本都建好。
    struct CompareGroupSummary
    {
        // groupAddress：该分组的绝对起始地址，永远是 16 的倍数（可疑点 6：按绝对地址对齐，
        // 不是按窗口起点从 0 开始数）；窗口起点非 16 倍数时，分组覆盖的字节里会有一部分
        // 落在窗口之外，data() 现算时按"不可用"（×/??）处理，不是真的去读那些地址。
        std::uint64_t groupAddress = 0;
        int changedCount = 0;        // 命中当前分段变化种类的字节数（> 0，否则不会进入分组列表）
    };

    // WorkbenchCompareModel：对比表格的模型，六列：地址/旧十六进制/新十六进制/旧ASCII/新ASCII/变化数。
    // D8：本模型不持有"已经格式化好的字符串行"，只持有一次窗口快照 + 命中分组摘要；
    // data() 被调用时才按列现算，彻底避免整窗口字节一次性字符串化。
    class WorkbenchCompareModel final : public QAbstractTableModel
    {
        Q_OBJECT

    public:
        explicit WorkbenchCompareModel(QObject* parent = nullptr);

        // setWindow：整体替换窗口快照、命中分组列表与当前分段；isPendingMode 为 true 表示
        // "待写入修改"分段（旧值取基线/新值取现值），为 false 表示"两次读取之间"分段
        // （旧值取上次读取/新值取基线）。颜色不在这里缓存——data() 的 BackgroundRole 现取
        // KswordTheme 的配方，主题切换后下一次重绘就是新颜色，不必等到下一次数据刷新
        // （D12：旧代码把颜色算好存进模型，主题切换到下一次刷新之间会显示旧颜色）。
        void setWindow(
            const WorkbenchByteWindow& window,
            bool isPendingMode,
            const QVector<CompareGroupSummary>& groups);

        // setRange：大捕获范围只保留整数摘要，单元格显示时从仍存活的提供者取最多 16 字节。
        // 调用方更换/销毁提供者前必须清空模型；不复制整份多 MiB 的七组数组。
        void setRange(IWorkbenchBytesProvider* provider, std::uint64_t address, std::uint64_t length,
            bool isPendingMode, const QVector<CompareGroupSummary>& groups);

        // firstRowAtOrAfter：第一个分组地址 >= address 的行号（分组按地址升序）；
        // 所有分组都在 address 之前时返回最后一行；没有任何分组返回 -1。
        int firstRowAtOrAfter(std::uint64_t address) const;

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        int columnCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role) const override;
        void setFileOffsetCoordinates(bool fileOffsets);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    private:
        // kGroupBytes：与 WorkbenchCompareView 的分组宽度保持一致（声明顺序原因这里重复
        // 一份常量，两边都是私有实现细节，没有共享头文件可放）。
        static constexpr std::uint64_t kGroupBytes = 16;

        WorkbenchByteWindow m_window;              // 窗口快照（现值/基线/上次读取/变化种类）
        IWorkbenchBytesProvider* m_provider = nullptr; // 虚拟范围的缓存来源，生命周期由视图负责。
        std::uint64_t m_address = 0;               // 虚拟范围首地址，首行导航不越界。
        std::uint64_t m_length = 0;                // 虚拟范围字节数，末行只读取实际捕获尾部。
        bool m_fileOffsets = false;                // 文件宿主显式使用偏移坐标列名。
        bool m_isPendingMode = true;                 // 当前分段：true=待写入修改，false=两次读取之间
        QVector<CompareGroupSummary> m_groups;      // 只含命中分组，真正的行数来源
    };

    // WorkbenchCompareView：对比子页，顶部分段按钮 + 表格/提示文案。
    class WorkbenchCompareView final : public QWidget
    {
        Q_OBJECT

    public:
        // Mode：两段，下标与 HexViewSegmented 的段下标一致。
        enum class Mode : int
        {
            Pending = 0,
            ExternalChange = 1
        };

        explicit WorkbenchCompareView(QWidget* parent = nullptr);

        // setBytesProvider：设置数据源（非拥有）；传空等价于清空视图。
        void setBytesProvider(IWorkbenchBytesProvider* provider);

        // setWindow：设置要对比的字节区间（通常跟随十六进制页当前可见范围）。
        void setWindow(std::uint64_t address, std::uint64_t length);

        // reset：回到"尚未定位"的初始状态（清窗口，状态行回到占位文案）。换目标时由宿主调用。
        void reset();

        // scrollToAddress：把表格滚到并选中"第一个分组地址 >= address 对齐到 16 字节"的行——
        // 对比页只列出有变化的分组，"跳到某地址"就是跳到它之后（含它所在分组）的第一处变化；
        // 没有任何分组时什么都不做。
        void scrollToAddress(std::uint64_t address);

        // setMode：切换分段；真的变了才重新渲染。
        void setMode(Mode mode);

        // mode：当前分段。
        Mode mode() const;

        // refreshView：数据源内容变化后由宿主调用，重新拉取并渲染。
        void refreshView();
        // 文件偏移列名和真实内存地址分开，指令位数不改变坐标域。
        void setFileOffsetCoordinates(bool fileOffsets);

        // table / model：供夹具与宿主做诊断查询。
        QTableView* table() const;
        WorkbenchCompareModel* model() const;
        // 总计来自完整范围分块扫描；有效比较字节少于范围时界面明确报告不完整。
        std::uint64_t totalChangedBytes() const { return m_totalChanged; }
        std::uint64_t comparedBytes() const { return m_compared; }
        std::uint64_t rangeLength() const { return m_length; }

        // minimumSizeHint（Wave 3 修复缺陷 1 增量，任务书明确允许的最小修改：
        // 只改这一个覆盖，不动其它任何行为）：m_table（六列对比表）默认的
        // minimumSizeHint 会按六列各自的最小列宽求和，一路向上传播会让装配
        // 本页的 QStackedWidget（进而宿主顶层窗口）被钉在一个拖不动的下限上
        // ——与 WorkbenchHexPane::minimumSizeHint 同一处理方式（见该函数注释）。
        QSize minimumSizeHint() const override;

    signals:
        // 正式比较页与快照宿主共用定位动作，数据源仍只由宿主读取。
        void requestHexLocate(quint64 address);

    private:
        // kMaxWindowBytes：整范围预算；超限明确拒绝，绝不默默截掉尾部冒充完整比较。
        static constexpr std::uint64_t kMaxWindowBytes = 64ULL * 1024ULL * 1024ULL;
        // kGroupBytes：分组对齐宽度，与旧代码的 16 字节分行惯例一致。
        static constexpr std::uint64_t kGroupBytes = 16;

        // rebuildRows：按当前窗口与分段重新计算行并刷新模型/状态文案。
        void rebuildRows();

        IWorkbenchBytesProvider* m_provider = nullptr;   // 数据源（非拥有）
        HexViewSegmented* m_modeSegmented = nullptr;      // 分段按钮
        QTableView* m_table = nullptr;                    // 对比表格
        WorkbenchCompareModel* m_model = nullptr;          // 表格模型
        QLabel* m_status = nullptr;                        // 状态行 / "没有上次读取"文案
        std::uint64_t m_address = 0;                       // 当前窗口起始地址
        std::uint64_t m_length = 0;                        // 当前窗口长度
        std::uint64_t m_totalChanged = 0;                   // 整范围已确认变化字节数。
        std::uint64_t m_compared = 0;                       // 两侧有效、实际已比较的字节数。
        bool m_hasWindow = false;                          // 是否已经设置过窗口
    };
}
