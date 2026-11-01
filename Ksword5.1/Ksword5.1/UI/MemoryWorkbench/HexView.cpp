// HexView.cpp
// 作用：HexView 的构造与析构、界面搭建、画布信号接线、状态条刷新、选区/外观访问器。
// 其余职责按文件拆分：
//   HexView.Toolbar.cpp  工具栏与下拉菜单
//   HexView.Compat.cpp   缓冲模型（页提供者、setBuffer / setReference / setByteQuiet、编辑同步）
//   HexView.Panels.cpp   查找 / 跳转 / 解释器 / 快捷键 / 导出 / 主题刷新

#include "HexView.h"

#include "HexCanvasFormat.h"
#include "HexInspectorPanel.h"
#include "HexViewFormat.h"

#include <QSplitter>
#include <QVBoxLayout>

#include <algorithm>

namespace ks::ui
{
    // 构造：搭界面 -> 接线 -> 安装页提供者与叠加层 -> 面板与快捷键 -> 恢复解释器偏好。
    HexView::HexView(QWidget* parent)
        : QWidget(parent)
    {
        buildUi();
        connectCanvas();
        buildPanels();

        // 焦点代理：宿主对本控件 setFocus 时，焦点交给画布。
        setFocusProxy(m_canvas);
    }

    // 搭建界面：根布局 + 工具栏 + 两个条 + 分割器（画布）+ 状态条。
    void HexView::buildUi()
    {
        m_root = new QVBoxLayout(this);
        m_root->setContentsMargins(0, 0, 0, 0);
        m_root->setSpacing(0);

        // 工具栏（HexView.Toolbar.cpp）：先于画布创建，按钮点击时才访问其余控件，所以顺序无碍。
        buildToolbar();

        // 查找条与跳转条：默认隐藏。
        m_findBar = new HexFindBar(this);
        m_findBar->hide();
        m_root->addWidget(m_findBar);
        m_gotoBar = new HexGotoBar(this);
        m_gotoBar->hide();
        m_root->addWidget(m_gotoBar);

        // 分割器：画布在左，解释器面板（按需创建）在右。
        m_splitter = new QSplitter(Qt::Horizontal, this);
        m_splitter->setChildrenCollapsible(false);
        m_canvas = new HexCanvas(m_splitter);
        // All buffer/snapshot hosts share the workbench's cache-only overview
        // and address header controls. Keep file/sector offsets on a fixed axis;
        // data loading, edit permissions and the host's window range stay owned
        // by the existing buffer provider.
        m_canvas->setFixedAddressScale(true);
        m_canvas->setOverviewEnabled(true);
        m_canvas->setAddressColumnCollapseEnabled(true);
        m_splitter->addWidget(m_canvas);
        m_splitter->setStretchFactor(0, 1);
        m_root->addWidget(m_splitter, 1);

        // 状态条。
        m_status = new HexViewStatusBar(this);
        m_root->addWidget(m_status);

        // 画布的数据源与叠加层：页提供者从基线切页回填，叠加层承载编辑暂存（见头文件第四节）。
        attachBufferModel();

        updateToolbarBadges();
        refreshStatus();
    }

    // 接线：把画布的信号转成本控件的兼容信号，并驱动状态条与查找高亮。
    void HexView::connectCanvas()
    {
        connect(m_canvas, &HexCanvas::selectionChanged, this, &HexView::onCanvasSelectionChanged);
        connect(m_canvas, &HexCanvas::caretMoved, this, [this](quint64 address) {
            emit caretMoved(address);
        });
        connect(m_canvas, &HexCanvas::contextMenuAboutToShow, this, [this](QMenu* menu, quint64 address, bool hasByte) {
            emit aboutToShowContextMenu(menu, address, hasByte);
        });

        // 编辑：暂存成功与丢弃都要把结果同步进缓冲（HexView.Compat.cpp）。
        connect(m_canvas, &HexCanvas::editStaged, this, &HexView::onEditStaged);
        connect(m_canvas, &HexCanvas::editDiscarded, this, &HexView::onEditDiscarded);

        // 编辑被拒绝：状态条显示原因并转发给宿主。
        connect(m_canvas, &HexCanvas::editRejected, this, [this](const QString& reason) {
            showStatusMessage(HexViewStatusBar::Kind::Warning, reason);
            emit editRejected(reason);
        });

        // 复制被拒绝：同样显示在状态条。
        connect(m_canvas, &HexCanvas::copyRejected, this, [this](const QString& reason) {
            showStatusMessage(HexViewStatusBar::Kind::Warning, reason);
        });

        // 可见范围：记下来供查找定位用，并交给查找条重算可见高亮。
        connect(m_canvas, &HexCanvas::visibleRangeChanged, this, [this](quint64 first, quint64 last) {
            m_visibleValid = true;
            m_visibleFirst = first;
            m_visibleLast = last;
            m_findBar->setVisibleRange(first, last);
        });
    }

    // 选区变化：转成旧控件语义的 selectionChanged（相对基址、止偏移不含），恢复状态条三段显示。
    void HexView::onCanvasSelectionChanged(bool valid, quint64 first, quint64 last)
    {
        if (!valid)
        {
            emit selectionChanged(0, 0, false);
        }
        else
        {
            emit selectionChanged(first - m_baseAddress, last - m_baseAddress + 1ULL, true);
        }
        m_status->clearMessage();
        refreshStatus();
    }

    // 刷新状态条三段：插入点 | 选区长度 | 数据范围与总字节数。
    void HexView::refreshStatus()
    {
        if (m_buffer.isEmpty())
        {
            m_status->setCaretText(QStringLiteral("无数据"));
            m_status->setSelectionText(QString());
            m_status->setRangeText(QString());
            return;
        }

        // digits：地址显示位数，与画布地址列、各提示里的地址一致。
        const std::uint64_t last = lastAddress();
        const int digits = hexview_format::AddressDigitsFor(m_baseAddress, last);
        m_status->setCaretText(QStringLiteral("插入点 %1").arg(
            hexcanvas_format::FormatAddress(m_canvas->caretAddress(), digits)));

        // 选区长度：画布恒有选区（至少插入点那一个字节）。
        const std::optional<HexCanvas::AddressRange> range = m_canvas->selectedRange();
        const qulonglong selected = range.has_value() ? (range->last - range->first + 1ULL) : 0ULL;
        m_status->setSelectionText(QStringLiteral("选区 %1 字节").arg(selected));
        m_status->setRangeText(QStringLiteral("范围 %1 - %2，共 %3 字节")
            .arg(hexcanvas_format::FormatAddress(m_baseAddress, digits))
            .arg(hexcanvas_format::FormatAddress(last, digits))
            .arg(static_cast<qulonglong>(m_buffer.size())));
    }

    // ======================== 选区与访问器 ========================

    // 插入点绝对地址。
    std::uint64_t HexView::caretAddress() const
    {
        return m_buffer.isEmpty() ? 0ULL : m_canvas->caretAddress();
    }

    // 选区的半开偏移区间。
    bool HexView::selectionRange(std::uint64_t& startOffsetOut, std::uint64_t& endOffsetOut) const
    {
        if (m_buffer.isEmpty())
        {
            return false;
        }
        const std::optional<HexCanvas::AddressRange> range = m_canvas->selectedRange();
        if (!range.has_value())
        {
            return false;
        }
        startOffsetOut = range->first - m_baseAddress;
        endOffsetOut = range->last - m_baseAddress + 1ULL;
        return true;
    }

    // 选区字节：直接从缓冲切，不依赖画布页缓存。
    QByteArray HexView::selectedBytes() const
    {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
        if (!selectionRange(start, end))
        {
            return QByteArray();
        }
        return m_buffer.mid(static_cast<qsizetype>(start), static_cast<qsizetype>(end - start));
    }

    // 是否可编辑。
    void HexView::setEditable(bool editable)
    {
        m_canvas->setEditable(editable);
    }

    bool HexView::isEditable() const
    {
        return m_canvas->isEditable();
    }

    // 每行字节数：成功后更新徽标与跳转条的行宽。
    bool HexView::setBytesPerRow(int bytesPerRow)
    {
        if (!m_canvas->setBytesPerRow(bytesPerRow))
        {
            return false;
        }
        updateToolbarBadges();
        if (!m_buffer.isEmpty())
        {
            m_gotoBar->setSpace(m_baseAddress, lastAddress(), m_canvas->bytesPerRow());
        }
        return true;
    }

    int HexView::bytesPerRow() const
    {
        return m_canvas->bytesPerRow();
    }

    // 分组字节数。
    bool HexView::setGroupSize(int groupSize)
    {
        if (!m_canvas->setGroupSize(groupSize))
        {
            return false;
        }
        updateToolbarBadges();
        return true;
    }

    int HexView::groupSize() const
    {
        return m_canvas->groupSize();
    }

    // 基址与字节数。
    std::uint64_t HexView::baseAddress() const
    {
        return m_baseAddress;
    }

    std::uint64_t HexView::bufferSize() const
    {
        return static_cast<std::uint64_t>(m_buffer.size());
    }

    // 当前缓冲。
    QByteArray HexView::buffer() const
    {
        return m_buffer;
    }

    // 工具栏与状态条显隐。
    void HexView::setToolbarVisible(bool visible)
    {
        m_toolbar->setVisible(visible);
    }

    bool HexView::toolbarVisible() const
    {
        return !m_toolbar->isHidden();
    }

    void HexView::setStatusBarVisible(bool visible)
    {
        m_status->setVisible(visible);
    }

    bool HexView::statusBarVisible() const
    {
        return !m_status->isHidden();
    }

    // 内部控件访问器。
    HexCanvas* HexView::canvas() const
    {
        return m_canvas;
    }

    HexFindBar* HexView::findBar() const
    {
        return m_findBar;
    }

    HexGotoBar* HexView::gotoBar() const
    {
        return m_gotoBar;
    }

    HexViewStatusBar* HexView::statusBar() const
    {
        return m_status;
    }

    QWidget* HexView::toolbar() const
    {
        return m_toolbar;
    }

    HexViewGlyphButton* HexView::rowWidthButton() const
    {
        return m_rowWidthButton;
    }

    HexViewGlyphButton* HexView::groupButton() const
    {
        return m_groupButton;
    }

    HexViewGlyphButton* HexView::findButton() const
    {
        return m_findButton;
    }

    HexViewGlyphButton* HexView::gotoButton() const
    {
        return m_gotoButton;
    }

    HexViewGlyphButton* HexView::exportButton() const
    {
        return m_exportButton;
    }

    HexViewGlyphButton* HexView::inspectorButton() const
    {
        return m_inspectorButton;
    }

    QSplitter* HexView::splitter() const
    {
        return m_splitter;
    }

    QMenu* HexView::rowWidthMenu() const
    {
        return m_rowWidthMenu;
    }

    QMenu* HexView::groupMenu() const
    {
        return m_groupMenu;
    }

    QMenu* HexView::exportMenu() const
    {
        return m_exportMenu;
    }
}
