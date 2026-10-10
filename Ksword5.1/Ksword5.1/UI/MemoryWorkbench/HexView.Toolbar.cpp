// HexView.Toolbar.cpp
// 作用：HexView 的工具栏（行宽、分组、查找、跳转、导出、解释器开关）与三个下拉菜单。
//
// 约定：
// - 所有按钮都是自绘图标（HexViewGlyphButton），每个都有悬停提示；行宽与分组按钮带当前值徽标，
//   悬停提示随当前值更新。
// - 三个下拉菜单每次弹出前（aboutToShow）按当前状态重建，并显式设置不透明背景、文字、选中态、禁用态样式
//   （静态主题色，每次重新取，主题切换后下一次弹出即是新主题）；菜单项都有悬停提示。

#include "HexView.h"
#include "../ToolbarMetrics.h"

#include "../../theme.h"

#include <QAction>
#include <QActionGroup>
#include <QHBoxLayout>
#include <QMenu>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        // kRowWidthChoices：行宽菜单的可选值，与画布支持的集合一致。
        constexpr int kRowWidthChoices[] = { 8, 16, 32, 48, 64 };

        // kGroupChoices：分组菜单的可选值，与画布支持的集合一致。
        constexpr int kGroupChoices[] = { 1, 2, 4, 8 };
    }

    // 搭建工具栏：左侧 行宽、分组 | 查找、跳转、导出，右侧 解释器开关。
    void HexView::buildToolbar()
    {
        m_toolbar = new HexViewBarFrame(HexViewBarFrame::Edge::Bottom, this);
        auto* layout = new QHBoxLayout(m_toolbar);
        layout->setContentsMargins(6, 3, 6, 3);
        layout->setSpacing(4);

        // 行宽：下拉菜单，徽标显示当前值。
        m_rowWidthButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::RowWidth, m_toolbar);
        m_rowWidthMenu = new QMenu(m_toolbar);
        m_rowWidthButton->setMenu(m_rowWidthMenu);
        m_rowWidthButton->setPopupMode(QToolButton::InstantPopup);
        layout->addWidget(m_rowWidthButton);

        // 分组：下拉菜单，徽标显示当前值。
        m_groupButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::GroupSize, m_toolbar);
        m_groupMenu = new QMenu(m_toolbar);
        m_groupButton->setMenu(m_groupMenu);
        m_groupButton->setPopupMode(QToolButton::InstantPopup);
        layout->addWidget(m_groupButton);

        // 查找与跳转：点击打开对应的条。
        m_findButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Find, m_toolbar);
        m_findButton->setToolTip(QStringLiteral("查找（Ctrl+F）：十六进制字节、UTF-8 / UTF-16 文本，支持通配"));
        layout->addWidget(m_findButton);
        m_gotoButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Goto, m_toolbar);
        m_gotoButton->setToolTip(QStringLiteral("跳转（Ctrl+G）：按地址、偏移或行号定位"));
        layout->addWidget(m_gotoButton);

        // 导出：下拉菜单。
        m_exportButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Export, m_toolbar);
        m_exportButton->setToolTip(QStringLiteral("导出：二进制、十六进制文本、选中字节的十六进制文本"));
        m_exportMenu = new QMenu(m_toolbar);
        m_exportButton->setMenu(m_exportMenu);
        m_exportButton->setPopupMode(QToolButton::InstantPopup);
        layout->addWidget(m_exportButton);

        layout->addStretch(1);

        // 解释器面板开关：可勾选，放在最右。
        m_inspectorButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Inspector, m_toolbar);
        m_inspectorButton->setCheckable(true);
        m_inspectorButton->setToolTip(
            QStringLiteral("数据解释器面板：把插入点处的字节解释成整数、浮点、指针、时间等，并可直接改值"));
        layout->addWidget(m_inspectorButton);
        // 自绘图标保留徽标所需宽度，统一整行高度和动作间距。
        NormalizeToolbarRow(layout);

        m_root->addWidget(m_toolbar);

        // 连接：按钮点击打开条；菜单弹出前重建；解释器开关由 Panels 文件里的槽处理。
        connect(m_findButton, &QToolButton::clicked, this, [this]() { openFind(); });
        connect(m_gotoButton, &QToolButton::clicked, this, [this]() { openGoto(); });
        connect(m_rowWidthMenu, &QMenu::aboutToShow, this, [this]() { rebuildRowWidthMenu(); });
        connect(m_groupMenu, &QMenu::aboutToShow, this, [this]() { rebuildGroupMenu(); });
        connect(m_exportMenu, &QMenu::aboutToShow, this, [this]() { rebuildExportMenu(); });
        connect(m_inspectorButton, &QToolButton::toggled, this, [this](bool checked) { onInspectorToggled(checked); });
    }

    // 刷新行宽与分组的徽标与悬停提示。
    void HexView::updateToolbarBadges()
    {
        const int rowWidth = m_canvas->bytesPerRow();
        const int group = m_canvas->groupSize();
        m_rowWidthButton->setBadgeText(QString::number(rowWidth));
        m_rowWidthButton->setToolTip(QStringLiteral("每行字节数：%1（点击选择 8 / 16 / 32 / 48 / 64）").arg(rowWidth));
        m_groupButton->setBadgeText(QString::number(group));
        m_groupButton->setToolTip(QStringLiteral("十六进制列分组：每 %1 个字节一组（点击选择 1 / 2 / 4 / 8）").arg(group));
    }

    // 菜单样式：背景、文字、选中态、禁用态、分隔线全部用主题静态色；菜单每次弹出前重建，此刻取到的就是当前主题。
    QString HexView::menuStyleSheet() const
    {
        return QStringLiteral(
            "QMenu{background-color:%1;color:%2;border:1px solid %3;padding:3px;}"
            "QMenu::item{color:%2;background-color:transparent;padding:5px 20px 5px 24px;}"
            "QMenu::item:selected{background-color:%4;color:%5;}"
            "QMenu::item:disabled{color:%6;background-color:transparent;}"
            "QMenu::separator{height:1px;background-color:%3;margin:3px 6px;}")
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::ThemeColorName(KswordTheme::PrimaryAccentColor()))
            .arg(KswordTheme::OnAccentHex())
            .arg(KswordTheme::TextDisabledColorHex());
    }

    // 重建行宽菜单：互斥的可勾选项，当前值打勾。
    void HexView::rebuildRowWidthMenu()
    {
        m_rowWidthMenu->clear();
        m_rowWidthMenu->setAttribute(Qt::WA_TranslucentBackground, false);
        m_rowWidthMenu->setAutoFillBackground(true);
        m_rowWidthMenu->setStyleSheet(menuStyleSheet());
        m_rowWidthMenu->setToolTipsVisible(true);

        // 上一次弹出时建的互斥组随菜单项一起作废，先删掉，避免每次弹出都多留一个孤儿对象。
        qDeleteAll(m_rowWidthMenu->findChildren<QActionGroup*>(Qt::FindDirectChildrenOnly));
        auto* group = new QActionGroup(m_rowWidthMenu);
        group->setExclusive(true);
        for (const int choice : kRowWidthChoices)
        {
            QAction* action = m_rowWidthMenu->addAction(QStringLiteral("%1 字节 / 行").arg(choice));
            action->setCheckable(true);
            action->setChecked(choice == m_canvas->bytesPerRow());
            action->setToolTip(QStringLiteral("每行显示 %1 个字节").arg(choice));
            group->addAction(action);
            connect(action, &QAction::triggered, this, [this, choice]() { setBytesPerRow(choice); });
        }
    }

    // 重建分组菜单：互斥的可勾选项，当前值打勾。
    void HexView::rebuildGroupMenu()
    {
        m_groupMenu->clear();
        m_groupMenu->setAttribute(Qt::WA_TranslucentBackground, false);
        m_groupMenu->setAutoFillBackground(true);
        m_groupMenu->setStyleSheet(menuStyleSheet());
        m_groupMenu->setToolTipsVisible(true);

        // 同上：先删掉上一次弹出建的互斥组。
        qDeleteAll(m_groupMenu->findChildren<QActionGroup*>(Qt::FindDirectChildrenOnly));
        auto* group = new QActionGroup(m_groupMenu);
        group->setExclusive(true);
        for (const int choice : kGroupChoices)
        {
            QAction* action = m_groupMenu->addAction(QStringLiteral("%1 字节一组").arg(choice));
            action->setCheckable(true);
            action->setChecked(choice == m_canvas->groupSize());
            action->setToolTip(QStringLiteral("十六进制列每 %1 个字节为一组，组间留出间隙").arg(choice));
            group->addAction(action);
            connect(action, &QAction::triggered, this, [this, choice]() { setGroupSize(choice); });
        }
    }

    // 重建导出菜单：三项，没有数据时全部置灰，选区为空时"导出选中字节"置灰。
    void HexView::rebuildExportMenu()
    {
        m_exportMenu->clear();
        m_exportMenu->setAttribute(Qt::WA_TranslucentBackground, false);
        m_exportMenu->setAutoFillBackground(true);
        m_exportMenu->setStyleSheet(menuStyleSheet());
        m_exportMenu->setToolTipsVisible(true);

        const bool hasData = !m_buffer.isEmpty();
        QAction* binary = m_exportMenu->addAction(QStringLiteral("导出二进制…"));
        binary->setToolTip(QStringLiteral("把整个缓冲按原样写成二进制文件"));
        binary->setEnabled(hasData);
        connect(binary, &QAction::triggered, this, [this]() { exportBinary(); });

        QAction* dump = m_exportMenu->addAction(QStringLiteral("导出十六进制文本…"));
        dump->setToolTip(QStringLiteral("导出带地址与 ASCII 的转储文本，每行 16 字节"));
        dump->setEnabled(hasData);
        connect(dump, &QAction::triggered, this, [this]() { exportHexText(); });

        QAction* selected = m_exportMenu->addAction(QStringLiteral("导出选中字节为十六进制文本…"));
        selected->setToolTip(QStringLiteral("把选区字节写成大写、空格分隔的十六进制文本"));
        selected->setEnabled(hasData);
        connect(selected, &QAction::triggered, this, [this]() { exportSelectedHex(); });
    }
}
