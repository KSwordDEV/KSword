#include "../UI/StructuredFieldView.h"
#include "../UI/FlatButtonTheme.h"
// ============================================================
// MinidumpDock.Tables.cpp
// 作用：
// - 实现转储解析结果的全部渲染逻辑：
//   诊断结论/肇事模块/概览/异常/调用栈/寄存器/流目录/模块/线程/内存/
//   句柄/已卸载模块共十二张表 + 全文报告；
// - 表格控件在 MinidumpDock.cpp 预创建，这里只负责清空重填与挂载页签，
//   语言切换时重进本文件即可完成重译；
// - 宽表通过 createStructuredTablePage 提供互补 A/B/C 列组预设与
//   表头右键逐列显隐（遵循项目 A/B 列组规范）。
// ============================================================

#include "MinidumpDock.h"

#include "DumpAnalyzer.h"
#include "DumpByteView.h"
#include "DumpMemoryView.h"
#include "DumpSymbolResolver.h"
#include "Internationalization/LanguageManager.h"
#include "MinidumpFormat.h"
#include "UI/CodeEditorWidget.h"
#include "UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "UI/TableHeaderSortingSupport.h"
#include "theme.h"

#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
    // kReportMemoryRowLimit：全文报告里内存区域最多列出的行数。
    constexpr std::size_t kReportMemoryRowLimit = 2000;

    // hexText 作用：把数值格式化成 0x 大写十六进制（渲染层通用）。
    QString hexText(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
    }

    // makeItem 作用：创建一个只读表格单元格。
    // 传入 text 单元格文本；返回新建的 QTableWidgetItem。
    QTableWidgetItem* makeItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // beginFill 作用：批量填充前关闭刷新与排序并清空内容。
    // 注意 endFill 只恢复刷新，不重新打开排序——本页所有表都以解析产出的
    // 原始顺序呈现（调用栈的帧序、模块的加载顺序本身就是信息），
    // 让用户点表头打乱它没有意义。
    void beginFill(QTableWidget* const table)
    {
        table->setUpdatesEnabled(false);
        table->setSortingEnabled(false);
        table->clearContents();
        table->setRowCount(0);
    }

    // endFill 作用：批量填充完毕后恢复刷新并自适应列宽（限制最大宽度）。
    void endFill(QTableWidget* const table)
    {
        table->resizeColumnsToContents();
        // 列宽上限：超长路径列不允许把其它列挤出视口。
        for (int column = 0; column < table->columnCount(); ++column)
        {
            // 隐藏列的 columnWidth() 返回 0，跟着钳制会把它的宽度真的写成 0，
            // 等用户通过 A/B/C 或表头菜单把它显示出来时就成了零宽列。
            if (table->isColumnHidden(column))
            {
                continue;
            }
            table->setColumnWidth(
                column,
                std::min(table->columnWidth(column), 420));
        }
        table->setUpdatesEnabled(true);
    }
}

QTableWidget* MinidumpDock::createReadOnlyTable(QWidget* parent) const
{
    // table：统一风格的只读表格；与 ScannerDock 保持一致的交互配置。
    auto* table = new QTableWidget(parent);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setAlternatingRowColors(true);
    table->setWordWrap(false);
    table->setTextElideMode(Qt::ElideMiddle);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionsMovable(true);
    table->horizontalHeader()->setStretchLastSection(true);
    // 表头左对齐：末列被拉伸后会很宽，居中的表头文字会飘到列中央，
    // 和左对齐的数据完全对不上。数据表的惯例本来也是左对齐。
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    // 转储解析表的帧序、加载序和采集序本身属于证据，禁用通用表头排序。
    ks::ui::SetTableHeaderClickSortingEnabled(table, false);
    return table;
}

void MinidumpDock::clearResultTabs()
{
    // 只摘下页签不销毁控件：全部表格/编辑器都是预创建的复用成员。
    // removeTab 不会改变父子关系，被摘下的控件仍是 m_resultTabs 的子控件；
    // 若不显式隐藏，它会作为普通子控件浮在当前页之上，看起来就是"表格重叠"。
    while (m_resultTabs->count() > 0)
    {
        QWidget* const detachedPage = m_resultTabs->widget(0);
        m_resultTabs->removeTab(0);
        if (detachedPage != nullptr)
        {
            detachedPage->hide();
        }
    }
    // 原始字节块页持有前一次转储的复制数据，换结果时销毁这些子页。
    while (m_rawMemoryTabs->count() > 0)
    {
        QWidget* const blockPage = m_rawMemoryTabs->widget(0);
        m_rawMemoryTabs->removeTab(0);
        delete blockPage;
    }
}

QWidget* MinidumpDock::createStructuredTablePage(
    QTableWidget* table,
    const int columnCount) const
{
    // 五列以内无需拆组；返回原表可避免增加无意义的控制条。
    if (table == nullptr || columnCount <= 5)
    {
        return table;
    }

    // page/pageLayout：宽表页由紧贴的 A/B/C 控件和原只读表组成。
    auto* page = new QWidget(m_resultTabs); // page：本结构表的外层页面。
    auto* pageLayout = new QVBoxLayout(page); // pageLayout：纵向排列列组按钮与数据表。
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(4);
    auto* buttonLayout = new QHBoxLayout(); // buttonLayout：无间距排列 A/B/C 按钮。
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(0);

    // groupCount：最多三组；第一列作为识别键在各组保留，其余列平均分配。
    const int remainingColumns = columnCount - 1; // remainingColumns：除识别列外的字段数。
    const int groupCount = std::clamp((remainingColumns + 3) / 4, 2, 3); // groupCount：实际列组数。
    const int columnsPerGroup = (remainingColumns + groupCount - 1) / groupCount; // columnsPerGroup：每组字段上限。
    auto groups = std::make_shared<std::vector<std::vector<int>>>(); // groups：每个预设显示的列索引。
    auto buttons = std::make_shared<std::vector<QPointer<QPushButton>>>(); // buttons：可安全失效的列组按钮。

    // activeStyle/inactiveStyle：当前预设使用主题强调色；自定义显隐时全部取消着色。
    // 两个字符串都被 applyGroup 与表头右键菜单按值捕获，之后每次重下发用的都是同一份
    // 文本——所以颜色必须全部取 palette 动态 token；一旦烘成静态色值，主题切换后
    // 从外部再也够不着它们。激活态文字用 highlighted-text，正好配 palette(highlight) 底。
    // A/B/C 的强调状态仍由列预设决定；自定义布局保持中性实心底色。
    const QString activeStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent)
        + QStringLiteral("QPushButton{padding:3px 10px;}");
    const QString inactiveStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
        + QStringLiteral("QPushButton{padding:3px 10px;}");

    for (int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
    {
        // columns：每组保留第 0 列，并加入属于本组的互补字段。
        std::vector<int> columns{ 0 }; // columns：当前 A/B/C 预设的可见列。
        const int firstColumn = 1 + groupIndex * columnsPerGroup; // firstColumn：当前分组首列。
        const int endColumn = std::min(columnCount, firstColumn + columnsPerGroup); // endColumn：当前分组尾后列。
        for (int column = firstColumn; column < endColumn; ++column)
        {
            columns.push_back(column);
        }
        groups->push_back(std::move(columns));

        // groupButton：A/B/C 采用紧贴布局，并通过悬停说明当前行为。
        const char16_t groupLetter = static_cast<char16_t>(u'A' + groupIndex); // groupLetter：当前组的字母标识。
        auto* groupButton = new QPushButton(
            QString(QChar(groupLetter)),
            page); // groupButton：切换到当前互补字段组。
        groupButton->setMinimumWidth(36);
        groupButton->setToolTip(
            translated(
                "minidump.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。")
                .arg(groupButton->text()));
        groupButton->setStyleSheet(groupIndex == 0 ? activeStyle : inactiveStyle);
        buttons->push_back(groupButton);
        buttonLayout->addWidget(groupButton);
    }
    buttonLayout->addStretch(1);
    pageLayout->addLayout(buttonLayout);
    pageLayout->addWidget(table, 1);

    // currentGroup：当前生效的预设下标。本函数在 buildUi 阶段被调用，
    // 那时表格还没有任何列，applyGroup 里的 setColumnHidden 全是空操作
    //（Qt 对越界的 section 直接忽略）。于是 A 按钮被高亮成“当前视图”，
    // 表格却在渲染后显示了全部列——高亮状态与实际不符。
    // 记下当前下标，等列数真正就位时再重放一次。
    auto currentGroup = std::make_shared<int>(0);

    // applyGroup：切换预设时先隐藏所有列，再仅显示目标组并更新按钮主题。
    const auto applyGroup =
        [table, groups, buttons, activeStyle, inactiveStyle, currentGroup](const int groupIndex)
        {
            *currentGroup = groupIndex;
            for (int column = 0; column < table->columnCount(); ++column)
            {
                table->setColumnHidden(column, true);
            }
            for (const int column : groups->at(static_cast<std::size_t>(groupIndex)))
            {
                table->setColumnHidden(column, false);
            }
            for (int buttonIndex = 0; buttonIndex < static_cast<int>(buttons->size()); ++buttonIndex)
            {
                if (buttons->at(static_cast<std::size_t>(buttonIndex)))
                {
                    buttons->at(static_cast<std::size_t>(buttonIndex))->setStyleSheet(
                        buttonIndex == groupIndex ? activeStyle : inactiveStyle);
                }
            }
        };

    for (int groupIndex = 0; groupIndex < static_cast<int>(buttons->size()); ++groupIndex)
    {
        // groupButton：当前按钮连接到自己的预设索引，点击不会改变表内数据。
        QPushButton* groupButton = buttons->at(static_cast<std::size_t>(groupIndex)); // groupButton：待连接按钮。
        connect(
            groupButton,
            &QPushButton::clicked,
            page,
            [applyGroup, groupIndex]() { applyGroup(groupIndex); });
    }
    applyGroup(0);

    // 列数从 0 变成实际值时（renderResult 里的 setColumnCount）重放当前预设。
    // 只有这时候 setColumnHidden 才真正生效，否则按钮高亮与表格内容会长期不一致。
    // 后续重复解析时列数不变、信号不发，用户手动选择的列组因此得以保留。
    connect(
        table->horizontalHeader(),
        &QHeaderView::sectionCountChanged,
        page,
        [applyGroup, currentGroup](const int oldCount, const int newCount)
        {
            if (oldCount == 0 && newCount > 0)
            {
                applyGroup(*currentGroup);
            }
        });

    // 表头右键菜单允许逐列显隐；每次手动调整后取消 A/B/C 激活色，表示自定义布局。
    // QMenu 按项目规范显式设置背景/文字/选中态/禁用态，避免透明继承导致黑底黑字。
    QHeaderView* tableHeader = table->horizontalHeader(); // tableHeader：承载列菜单的表头。
    tableHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        tableHeader,
        &QHeaderView::customContextMenuRequested,
        page,
        [this, table, tableHeader, buttons, inactiveStyle](const QPoint& position)
        {
            QMenu menu(tableHeader); // menu：仅在当前右键操作期间存在的列显隐菜单。
            menu.setStyleSheet(QStringLiteral(
                "QMenu { background:%1; color:%2; border:1px solid %3; }"
                "QMenu::item { padding:5px 22px; }"
                "QMenu::item:selected { background:%4; color:%5; }"
                "QMenu::item:disabled { color:%6; }")
                .arg(
                    KswordTheme::SurfaceHex(),
                    KswordTheme::TextPrimaryHex(),
                    KswordTheme::BorderHex(),
                    KswordTheme::AccentHex(KswordTheme::AccentRole::Blue),
                    KswordTheme::OnAccentDynamicHex(),
                    KswordTheme::TextDisabledColorHex()));

            // columnAction：勾选状态直接反映当前列可见性。
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QAction* columnAction = menu.addAction( // columnAction：控制单列显隐的菜单项。
                    table->horizontalHeaderItem(column) != nullptr
                        ? table->horizontalHeaderItem(column)->text()
                        : translated("minidump.column.unnamed", "未命名列"));
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(column));
                connect(
                    columnAction,
                    &QAction::toggled,
                    &menu,
                    [table, column, buttons, inactiveStyle](const bool visible)
                    {
                        table->setColumnHidden(column, !visible);
                        for (const QPointer<QPushButton>& button : *buttons)
                        {
                            if (button)
                            {
                                button->setStyleSheet(inactiveStyle);
                            }
                        }
                    });
            }
            menu.exec(tableHeader->mapToGlobal(position));
        });
    return page;
}

void MinidumpDock::renderResult(const ks::minidump::DumpParseResult& result)
{
    clearResultTabs();

    // ===================== 诊断结论页（放在最前，是本页的主产出） =====================
    const ks::minidump::DumpAnalysis& analysis = result.analysis;
    // 只要有结论文本就展示本页。可信度为 None 的情形（例如不含异常记录的快照转储）
    // 恰恰最需要把「这不是崩溃现场」讲清楚，藏起来只会让人白找崩溃点。
    if (result.success && !analysis.headline.isEmpty())
    {
        // 结论页按"先说结论，再给证据，最后给动作"的顺序排版。
        // 可信度用带底色的徽章而不是一行文字：它决定了这份结论该被多认真地对待，
        // 必须一眼看到，不能和其它属性混在一起。
        const QString accentHex = KswordTheme::AccentHex(KswordTheme::AccentRole::Blue);
        const QString textHex = KswordTheme::TextPrimaryHex();
        const QString mutedHex = KswordTheme::TextDisabledColorHex();
        const QString borderHex = KswordTheme::BorderHex();
        const QString surfaceAltHex = KswordTheme::SurfaceAltHex();

        // confidenceColor：可信度越低越要显眼地降调，避免低可信结论被当成定论。
        QColor confidenceColor = KswordTheme::TextDisabledColor();
        switch (analysis.confidence)
        {
        case ks::minidump::AnalysisConfidence::High:
            confidenceColor = KswordTheme::AccentColor(KswordTheme::AccentRole::Red);
            break;
        case ks::minidump::AnalysisConfidence::Medium:
            confidenceColor = KswordTheme::AccentColor(KswordTheme::AccentRole::Orange);
            break;
        case ks::minidump::AnalysisConfidence::Low:
            confidenceColor = KswordTheme::AccentColor(KswordTheme::AccentRole::Yellow);
            break;
        case ks::minidump::AnalysisConfidence::None:
        default:
            break;
        }
        const QString confidenceHex = KswordTheme::ThemeColorName(confidenceColor);
        // confidenceTextHex：徽章前景按徽章自己的底色反算，不能套 OnAccentHex()——
        // 后者只对蓝色主强调色做过对比度校正，压在 Yellow（琥珀）和 None 的灰蓝上
        // 白字只有 2:1，而这两档恰恰最需要用户看清"别把这个结论当定论"。
        const QString confidenceTextHex = KswordTheme::ThemeColorName(
            KswordTheme::EnsureTextContrast(
                KswordTheme::TextPrimaryColor(),
                confidenceColor));

        // escape：结论文本里可能出现 <> &，必须转义后再拼进 HTML。
        const auto escape = [](const QString& text) { return text.toHtmlEscaped(); };

        QString html;
        html.reserve(2048);
        html += QStringLiteral("<div style='color:%1;'>").arg(textHex);

        // 一句话结论：整页最大的字号，单独成块。
        html += QStringLiteral(
            "<div style='font-size:15pt; font-weight:600; line-height:150%%; margin:2px 0 10px 0;'>%1</div>")
            .arg(escape(ks::i18n::sourceText(analysis.headline)));

        // 徽章行：可信度 + 故障归类。
        html += QStringLiteral("<div style='margin-bottom:14px;'>");
        html += QStringLiteral(
            "<span style='background:%1; color:%2; padding:3px 10px; "
            "border-radius:4px; font-weight:600;'>%3 %4</span>")
            .arg(confidenceHex)
            .arg(confidenceTextHex)
            .arg(translated("minidump.analysis.confidence", "可信度"))
            .arg(escape(ks::i18n::sourceText(
                ks::minidump::AnalysisConfidenceText(analysis.confidence))));
        if (!analysis.category.isEmpty())
        {
            html += QStringLiteral(
                "&nbsp;&nbsp;<span style='background:%1; color:%2; padding:3px 10px; "
                "border-radius:4px; border:1px solid %3;'>%4</span>")
                .arg(surfaceAltHex)
                .arg(textHex)
                .arg(borderHex)
                .arg(escape(ks::i18n::sourceText(analysis.category)));
        }
        html += QStringLiteral("</div>");

        // sectionHtml：统一渲染"小标题 + 条目列表"。
        const auto sectionHtml =
            [&escape, &accentHex, &textHex](const QString& title, const QStringList& items)
            {
                if (items.isEmpty())
                {
                    return QString();
                }
                QString block = QStringLiteral(
                    "<div style='color:%1; font-weight:600; font-size:11pt; "
                    "margin:0 0 6px 0;'>%2</div>")
                    .arg(accentHex)
                    .arg(escape(title));
                block += QStringLiteral("<div style='margin:0 0 16px 0;'>");
                for (const QString& item : items)
                {
                    // 用悬挂缩进的行而不是 <ul>：Qt 富文本对列表的边距控制很有限，
                    // 长条目换行后会顶到项目符号下面，读起来更乱。
                    block += QStringLiteral(
                        "<div style='color:%1; line-height:160%%; margin-bottom:5px;'>"
                        "<span style='color:%2;'>▸</span>&nbsp;%3</div>")
                        .arg(textHex)
                        .arg(accentHex)
                        .arg(escape(item));
                }
                block += QStringLiteral("</div>");
                return block;
            };

        QStringList localizedFindings;
        for (const QString& finding : analysis.findings)
        {
            localizedFindings.append(ks::i18n::sourceText(finding));
        }
        QStringList localizedSuggestions;
        for (const QString& suggestion : analysis.suggestions)
        {
            localizedSuggestions.append(ks::i18n::sourceText(suggestion));
        }

        // 崩溃点：整份报告里最该被记住的一个地址，单独成块并用等宽字体，
        // 免得在证据条目里跟其它文字混成一片。
        if (result.faultingAddress != 0)
        {
            // faultSymbol：优先用肇事候选里与崩溃地址同模块的那条，给出"模块+偏移"。
            QString faultSymbol;
            for (const ks::minidump::BlameEntry& blame : analysis.blame)
            {
                if (blame.address == result.faultingAddress && !blame.moduleName.isEmpty())
                {
                    faultSymbol = QStringLiteral("%1+0x%2")
                        .arg(blame.moduleName)
                        .arg(QString::number(blame.offset, 16).toUpper());
                    break;
                }
            }
            html += QStringLiteral(
                "<div style='background:%1; border:1px solid %2; border-radius:6px; "
                "padding:8px 12px; margin-bottom:16px;'>"
                "<span style='color:%3;'>%4</span>&nbsp;&nbsp;"
                "<span style='font-family:Consolas,monospace; font-size:11pt; color:%5;'>%6</span>")
                .arg(surfaceAltHex)
                .arg(borderHex)
                .arg(mutedHex)
                .arg(translated("minidump.analysis.fault_address", "崩溃点"))
                .arg(textHex)
                .arg(hexText(result.faultingAddress));
            if (!faultSymbol.isEmpty())
            {
                html += QStringLiteral(
                    "&nbsp;&nbsp;<span style='color:%1; font-weight:600;'>%2</span>")
                    .arg(accentHex)
                    .arg(escape(faultSymbol));
            }
            html += QStringLiteral("</div>");
        }

        // 肇事模块候选直接嵌进本页：它是结论的直接依据，让用户为了看第一嫌疑
        // 再跳一个页签没有道理。权重画成条形，相对高低一眼可见。
        if (!analysis.blame.empty())
        {
            html += QStringLiteral(
                "<div style='color:%1; font-weight:600; font-size:11pt; margin:0 0 8px 0;'>%2</div>")
                .arg(accentHex)
                .arg(escape(translated("minidump.analysis.blame_title", "肇事模块候选")));

            // maxWeight：条形长度的基准。权重全为 0 时退化为等长，避免除零。
            int maxWeight = 1;
            for (const ks::minidump::BlameEntry& blame : analysis.blame)
            {
                maxWeight = std::max(maxWeight, blame.weight);
            }

            // 只列前若干条：候选表尾部通常是权重极低的噪音，完整列表在专页里。
            constexpr std::size_t kInlineBlameLimit = 5;
            const std::size_t shownCount =
                std::min(kInlineBlameLimit, analysis.blame.size());
            html += QStringLiteral("<table cellspacing='0' cellpadding='0' width='100%'>");
            for (std::size_t blameIndex = 0; blameIndex < shownCount; ++blameIndex)
            {
                const ks::minidump::BlameEntry& blame = analysis.blame[blameIndex];
                const int barPercent =
                    std::clamp(blame.weight * 100 / maxWeight, 3, 100);
                // 第一名用强调色，其余用中性色：排序本身已经表达了先后，
                // 全部上色反而让"第一名"失去意义。
                const QString barColor = (blameIndex == 0) ? confidenceHex : borderHex;
                const QString nameText = blame.unloadedModule
                    ? QStringLiteral("%1 [%2]")
                        .arg(blame.moduleName, translated("minidump.blame.unloaded", "已卸载"))
                    : blame.moduleName;
                html += QStringLiteral(
                    "<tr>"
                    "<td width='34%%' style='padding:3px 8px 3px 0; color:%1;'>%2</td>"
                    "<td width='50%%' style='padding:3px 0;'>"
                    "<table cellspacing='0' cellpadding='0' width='100%%'><tr>"
                    "<td width='%3%%' style='background:%4;'>&nbsp;</td>"
                    "<td>&nbsp;</td></tr></table></td>"
                    "<td width='16%%' style='padding:3px 0 3px 8px; color:%5;'>%6 %7</td>"
                    "</tr>")
                    .arg(textHex)
                    .arg(escape(nameText))
                    .arg(barPercent)
                    .arg(barColor)
                    .arg(mutedHex)
                    .arg(translated("minidump.column.weight", "证据权重"))
                    .arg(blame.weight);
            }
            html += QStringLiteral("</table>");
            if (analysis.blame.size() > shownCount)
            {
                html += QStringLiteral(
                    "<div style='color:%1; margin:4px 0 0 0;'>%2</div>")
                    .arg(mutedHex)
                    .arg(escape(translated(
                        "minidump.analysis.blame_more",
                        "更多候选与逐条证据见“肇事模块”页。")));
            }
            html += QStringLiteral("<div style='margin-bottom:16px;'></div>");
        }

        html += sectionHtml(
            translated("minidump.analysis.findings_title", "证据"),
            localizedFindings);
        html += sectionHtml(
            translated("minidump.analysis.suggestions_title", "接下来怎么做"),
            localizedSuggestions);

        html += QStringLiteral("</div>");
        m_analysisView->setHtml(html);
        m_resultTabs->addTab(m_analysisView,
            translated("minidump.tab.analysis", "诊断结论"));
    }

    // ===================== 肇事模块候选页 =====================
    if (!analysis.blame.empty())
    {
        beginFill(m_blameTable);
        m_blameTable->setColumnCount(6);
        m_blameTable->setHorizontalHeaderLabels({
            translated("minidump.column.suspect_module", "模块"),
            translated("minidump.column.suspect_function", "函数"),
            translated("minidump.column.hit_address", "命中地址"),
            translated("minidump.column.module_offset", "模块内偏移"),
            translated("minidump.column.weight", "证据权重"),
            translated("minidump.column.evidence", "证据") });
        m_blameTable->setRowCount(static_cast<int>(analysis.blame.size()));
        int blameRow = 0;
        for (const ks::minidump::BlameEntry& blame : analysis.blame)
        {
            // moduleText：已卸载模块单独标注，它是最强的单条证据。
            const QString moduleText = blame.unloadedModule
                ? QStringLiteral("%1 [%2]")
                    .arg(blame.moduleName,
                         translated("minidump.blame.unloaded", "已卸载"))
                : blame.moduleName;
            m_blameTable->setItem(blameRow, 0, makeItem(moduleText));
            // 有符号时把函数名单列出来：归因到模块只能说明"哪个驱动"，
            // 归因到函数才能直接落到代码上，这是本页最有价值的一列。
            m_blameTable->setItem(blameRow, 1, makeItem(blame.functionText));
            m_blameTable->setItem(blameRow, 2, makeItem(hexText(blame.address)));
            m_blameTable->setItem(blameRow, 3, makeItem(hexText(blame.offset)));
            m_blameTable->setItem(blameRow, 4, makeItem(QString::number(blame.weight)));
            // evidence：多条证据合成一行，用分号分隔，避免行数爆炸。
            QStringList localizedEvidence;
            for (const QString& evidence : blame.evidence)
            {
                localizedEvidence.append(ks::i18n::sourceText(evidence));
            }
            m_blameTable->setItem(blameRow, 5,
                makeItem(localizedEvidence.join(QStringLiteral("；"))));
            ++blameRow;
        }
        endFill(m_blameTable);
        m_resultTabs->addTab(m_blameTable,
            translated("minidump.tab.blame", "肇事模块"));
    }

    // ===================== 概览页（恒存在） =====================
    beginFill(m_overviewTable);
    m_overviewTable->setColumnCount(2);
    m_overviewTable->setHorizontalHeaderLabels({
        translated("minidump.column.property", "属性"),
        translated("minidump.column.value", "值") });
    // overviewRows：概览属性 + 解析告警合并展示，一次性设定行数。
    const int overviewRowCount =
        static_cast<int>(result.overview.size()) +
        static_cast<int>(result.diagnostics.size()) +
        (result.memoryRegionShown < result.memoryRegionTotal ? 1 : 0);
    m_overviewTable->setRowCount(overviewRowCount);
    int overviewRow = 0;
    for (const ks::minidump::DumpProperty& property : result.overview)
    {
        m_overviewTable->setItem(overviewRow, 0,
            makeItem(ks::i18n::sourceText(property.name)));
        m_overviewTable->setItem(overviewRow, 1,
            makeItem(ks::i18n::sourceText(property.value)));
        ++overviewRow;
    }
    // 内存截断说明与解析告警都作为“解析告警”属性行列出。
    if (result.memoryRegionShown < result.memoryRegionTotal)
    {
        m_overviewTable->setItem(overviewRow, 0,
            makeItem(translated("minidump.overview.warning", "解析告警")));
        m_overviewTable->setItem(overviewRow, 1,
            makeItem(translated(
                "minidump.overview.memory_truncated",
                "内存区域过多，仅展示前 %1 / %2 条。")
                .arg(result.memoryRegionShown)
                .arg(result.memoryRegionTotal)));
        ++overviewRow;
    }
    for (const QString& diagnostic : result.diagnostics)
    {
        m_overviewTable->setItem(overviewRow, 0,
            makeItem(translated("minidump.overview.warning", "解析告警")));
        m_overviewTable->setItem(overviewRow, 1,
            makeItem(ks::i18n::sourceText(diagnostic)));
        ++overviewRow;
    }
    endFill(m_overviewTable);
    m_resultTabs->addTab(m_overviewTable, translated("minidump.tab.overview", "概览"));

    // ===================== 异常/停止码页 =====================
    if (!result.exceptionInfo.empty())
    {
        beginFill(m_exceptionTable);
        m_exceptionTable->setColumnCount(2);
        m_exceptionTable->setHorizontalHeaderLabels({
            translated("minidump.column.property", "属性"),
            translated("minidump.column.value", "值") });
        m_exceptionTable->setRowCount(static_cast<int>(result.exceptionInfo.size()));
        int exceptionRow = 0;
        for (const ks::minidump::DumpProperty& property : result.exceptionInfo)
        {
            m_exceptionTable->setItem(exceptionRow, 0,
                makeItem(ks::i18n::sourceText(property.name)));
            m_exceptionTable->setItem(exceptionRow, 1,
                makeItem(ks::i18n::sourceText(property.value)));
            ++exceptionRow;
        }
        endFill(m_exceptionTable);
        // 多行“参数含义”允许换行展示。
        m_exceptionTable->setWordWrap(true);
        m_exceptionTable->resizeRowsToContents();
        m_resultTabs->addTab(m_exceptionTable,
            translated("minidump.tab.exception", "异常信息"));
    }

    // ===================== 崩溃现场页 =====================
    // TRIAGE 小型内核转储会保存当前 CPU、KTHREAD 与 EPROCESS 的局部快照。
    // 它们与“线程”页的用户态 MINIDUMP_THREAD 不同，不能混在一起展示。
    if (!result.executionContext.empty())
    {
        beginFill(m_executionContextTable);
        m_executionContextTable->setColumnCount(2);
        m_executionContextTable->setHorizontalHeaderLabels({
            translated("minidump.column.property", "属性"),
            translated("minidump.column.value", "值") });
        m_executionContextTable->setRowCount(
            static_cast<int>(result.executionContext.size()));
        int contextRow = 0;
        for (const ks::minidump::DumpProperty& property : result.executionContext)
        {
            m_executionContextTable->setItem(contextRow, 0,
                makeItem(ks::i18n::sourceText(property.name)));
            m_executionContextTable->setItem(contextRow, 1,
                makeItem(ks::i18n::sourceText(property.value)));
            ++contextRow;
        }
        endFill(m_executionContextTable);
        m_resultTabs->addTab(m_executionContextTable,
            translated("minidump.tab.execution_context", "崩溃现场"));
    }

    // ===================== 调用栈页 =====================
    if (!result.stackFrames.empty())
    {
        beginFill(m_stackTable);
        m_stackTable->setColumnCount(7);
        m_stackTable->setHorizontalHeaderLabels({
            translated("minidump.column.thread_id", "线程 ID"),
            translated("minidump.column.frame_index", "帧"),
            translated("minidump.column.symbol", "符号"),
            translated("minidump.column.source_location", "源码位置"),
            translated("minidump.column.frame_address", "返回地址"),
            translated("minidump.column.stack_address", "栈地址"),
            translated("minidump.column.frame_source", "来源") });
        m_stackTable->setRowCount(static_cast<int>(result.stackFrames.size()));
        int stackRow = 0;
        for (const ks::minidump::StackFrameEntry& frame : result.stackFrames)
        {
            m_stackTable->setItem(stackRow, 0,
                makeItem(frame.threadId != 0
                    ? QString::number(frame.threadId)
                    : translated("minidump.stack.crash_thread", "崩溃线程")));
            m_stackTable->setItem(stackRow, 1, makeItem(QString::number(frame.index)));
            // 符号列优先给"模块!函数+偏移"，没有符号才退回"模块+偏移"。
            // 合成一列而不是新开一列，是为了不把这张表撑到需要列组预设——
            // 一旦分组，"来源"列可能被隐藏，那条误报提示就没地方说了。
            const QString baseSymbol = frame.functionText.isEmpty()
                ? frame.symbolText
                : frame.functionText;
            const QString symbolText = frame.unloadedModule
                ? QStringLiteral("%1 [%2]")
                    .arg(baseSymbol,
                         translated("minidump.blame.unloaded", "已卸载"))
                : baseSymbol;
            m_stackTable->setItem(stackRow, 2, makeItem(symbolText));
            // 源码位置只在映像与 PDB 都匹配时才有值，解析器已经把不可信的滤掉了。
            m_stackTable->setItem(stackRow, 3, makeItem(frame.sourceText));
            m_stackTable->setItem(stackRow, 4, makeItem(hexText(frame.address)));
            m_stackTable->setItem(stackRow, 5,
                makeItem(frame.stackAddress != 0 ? hexText(frame.stackAddress) : QString()));
            // 来源必须如实标注：只有第 0 帧取自 CONTEXT，其余都是扫描猜测。
            m_stackTable->setItem(stackRow, 6,
                makeItem(frame.fromContext
                    ? translated("minidump.stack.from_context", "上下文（可信）")
                    : translated("minidump.stack.from_scan", "栈扫描（可能误报）")));
            ++stackRow;
        }
        endFill(m_stackTable);
        m_resultTabs->addTab(m_stackPage,
            translated("minidump.tab.stack", "调用栈"));
    }

    // ===================== 崩溃历史页 =====================
    // 单看一个转储答不出两件事：这次到底是蓝屏还是"没有转储的硬挂死"，
    // 以及崩溃当时跑的是哪一次构建的驱动。前者决定了还要不要去找转储文件，
    // 后者决定了"修复到底生效没有"——两个判断都只能靠系统事件日志给答案。
    if (!result.crashHistory.empty())
    {
        beginFill(m_crashHistoryTable);
        m_crashHistoryTable->setColumnCount(4);
        m_crashHistoryTable->setHorizontalHeaderLabels({
            translated("minidump.column.event_time", "时间"),
            translated("minidump.column.event_kind", "性质"),
            translated("minidump.column.event_summary", "摘要"),
            translated("minidump.column.detail", "说明") });
        m_crashHistoryTable->setRowCount(
            static_cast<int>(result.crashHistory.size()));
        int historyRow = 0;
        for (const ks::minidump::CrashHistoryEntry& entry : result.crashHistory)
        {
            m_crashHistoryTable->setItem(historyRow, 0,
                makeItem(entry.time.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
            m_crashHistoryTable->setItem(historyRow, 1,
                makeItem(ks::i18n::sourceText(entry.kindText)));
            m_crashHistoryTable->setItem(historyRow, 2,
                makeItem(ks::i18n::sourceText(entry.summary)));
            m_crashHistoryTable->setItem(historyRow, 3,
                makeItem(ks::i18n::sourceText(entry.detail)));
            ++historyRow;
        }
        endFill(m_crashHistoryTable);
        m_resultTabs->addTab(m_crashHistoryTable,
            translated("minidump.tab.crash_history", "崩溃历史"));
    }

    // ===================== 池标记页 =====================
    // 池损坏类停止码（0x13A / 0xC2 / 0x19…）里，"被损坏的那块内存归谁"
    // 比调用栈更能指向肇事者：栈上出现的往往只是下一个来分配内存、
    // 因而撞上坏链表的发现者，两次崩溃可以是两个毫不相干的模块。
    if (!result.poolTags.empty())
    {
        beginFill(m_poolTagTable);
        m_poolTagTable->setColumnCount(4);
        m_poolTagTable->setHorizontalHeaderLabels({
            translated("minidump.column.pool_tag", "池标记"),
            translated("minidump.column.pool_tag_source", "来源"),
            translated("minidump.column.pool_tag_owner", "映像中出现该标记的模块"),
            translated("minidump.column.pool_tag_purpose", "已知用途") });
        m_poolTagTable->setRowCount(static_cast<int>(result.poolTags.size()));
        int poolRow = 0;
        for (const ks::minidump::PoolTagCandidate& candidate : result.poolTags)
        {
            m_poolTagTable->setItem(poolRow, 0, makeItem(candidate.tagText));
            m_poolTagTable->setItem(poolRow, 1,
                makeItem(ks::i18n::sourceText(candidate.source)));
            m_poolTagTable->setItem(poolRow, 2,
                makeItem(candidate.ownerModules.join(QStringLiteral("、"))));
            m_poolTagTable->setItem(poolRow, 3, makeItem(candidate.knownPurpose));
            ++poolRow;
        }
        endFill(m_poolTagTable);
        m_resultTabs->addTab(m_poolTagTable,
            translated("minidump.tab.pool_tags", "池标记"));
    }

    // ===================== 符号状态页 =====================
    // 这一页的存在理由只有一条：让"函数名和行号到底可不可信"变成一个
    // 用户看得见的结论。符号化最危险的失败方式不是报错，而是在映像已经
    // 被重新编译过之后，安静地给出整体错位的行号。
    if (!result.symbolStatus.empty())
    {
        beginFill(m_symbolTable);
        m_symbolTable->setColumnCount(5);
        m_symbolTable->setHorizontalHeaderLabels({
            translated("minidump.column.module", "模块"),
            translated("minidump.column.symbol_state", "符号状态"),
            translated("minidump.column.image_path", "映像路径"),
            translated("minidump.column.pdb_path", "PDB 路径"),
            translated("minidump.column.detail", "说明") });
        m_symbolTable->setRowCount(static_cast<int>(result.symbolStatus.size()));
        int symbolRow = 0;
        for (const ks::minidump::ModuleSymbolStatus& status : result.symbolStatus)
        {
            m_symbolTable->setItem(symbolRow, 0, makeItem(status.moduleName));
            m_symbolTable->setItem(symbolRow, 1,
                makeItem(ks::i18n::sourceText(
                    ks::minidump::SymbolMatchStateText(status.state))));
            m_symbolTable->setItem(symbolRow, 2, makeItem(status.imagePath));
            m_symbolTable->setItem(symbolRow, 3, makeItem(status.pdbPath));
            m_symbolTable->setItem(symbolRow, 4,
                makeItem(ks::i18n::sourceText(status.detail)));
            ++symbolRow;
        }
        endFill(m_symbolTable);
        m_resultTabs->addTab(m_symbolTable,
            translated("minidump.tab.symbols", "符号"));
    }

    // ===================== 寄存器页 =====================
    if (!result.registers.empty())
    {
        beginFill(m_registerTable);
        m_registerTable->setColumnCount(3);
        m_registerTable->setHorizontalHeaderLabels({
            translated("minidump.column.register", "寄存器"),
            translated("minidump.column.value", "值"),
            translated("minidump.column.interpretation", "解读") });
        m_registerTable->setRowCount(static_cast<int>(result.registers.size()));
        int registerRow = 0;
        for (const ks::minidump::RegisterEntry& registerEntry : result.registers)
        {
            m_registerTable->setItem(registerRow, 0, makeItem(registerEntry.name));
            m_registerTable->setItem(registerRow, 1, makeItem(hexText(registerEntry.value)));
            m_registerTable->setItem(registerRow, 2,
                makeItem(ks::i18n::sourceText(registerEntry.note)));
            ++registerRow;
        }
        endFill(m_registerTable);
        m_resultTabs->addTab(m_registerTable,
            translated("minidump.tab.registers", "寄存器"));
    }

    // ===================== 流目录/数据布局页 =====================
    if (!result.streams.empty())
    {
        beginFill(m_streamTable);
        m_streamTable->setColumnCount(5);
        m_streamTable->setHorizontalHeaderLabels({
            translated("minidump.column.stream_type", "类型编号"),
            translated("minidump.column.stream_name", "类型名"),
            translated("minidump.column.offset", "文件偏移"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.note", "说明") });
        m_streamTable->setRowCount(static_cast<int>(result.streams.size()));
        int streamRow = 0;
        for (const ks::minidump::StreamEntry& stream : result.streams)
        {
            m_streamTable->setItem(streamRow, 0, makeItem(QString::number(stream.type)));
            m_streamTable->setItem(streamRow, 1, makeItem(stream.typeName));
            m_streamTable->setItem(streamRow, 2, makeItem(hexText(stream.rva)));
            m_streamTable->setItem(streamRow, 3, makeItem(QString::number(stream.size)));
            m_streamTable->setItem(streamRow, 4,
                makeItem(ks::i18n::sourceText(stream.note)));
            ++streamRow;
        }
        endFill(m_streamTable);
        m_resultTabs->addTab(m_streamTable,
            result.kind == ks::minidump::DumpKind::UserMinidump
                ? translated("minidump.tab.streams", "流目录")
                : translated("minidump.tab.layout", "数据布局"));
    }

    // ===================== 模块/驱动页 =====================
    if (!result.modules.empty())
    {
        beginFill(m_moduleTable);
        m_moduleTable->setColumnCount(8);
        m_moduleTable->setHorizontalHeaderLabels({
            translated("minidump.column.module_name", "名称"),
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.timestamp", "时间戳"),
            translated("minidump.column.version", "版本"),
            translated("minidump.column.pdb_file", "PDB 文件"),
            translated("minidump.column.pdb_guid", "PDB GUID/Age"),
            translated("minidump.column.checksum", "校验和") });
        m_moduleTable->setRowCount(static_cast<int>(result.modules.size()));
        int moduleRow = 0;
        for (const ks::minidump::ModuleEntry& module : result.modules)
        {
            m_moduleTable->setItem(moduleRow, 0, makeItem(module.name));
            m_moduleTable->setItem(moduleRow, 1, makeItem(hexText(module.base)));
            m_moduleTable->setItem(moduleRow, 2, makeItem(hexText(module.size)));
            m_moduleTable->setItem(moduleRow, 3, makeItem(module.timestampText));
            m_moduleTable->setItem(moduleRow, 4, makeItem(module.version));
            m_moduleTable->setItem(moduleRow, 5, makeItem(module.pdbName));
            m_moduleTable->setItem(moduleRow, 6, makeItem(module.pdbGuidAge));
            m_moduleTable->setItem(moduleRow, 7,
                makeItem(module.checksum != 0 ? hexText(module.checksum) : QString()));
            ++moduleRow;
        }
        endFill(m_moduleTable);
        m_resultTabs->addTab(m_modulePage,
            result.kind == ks::minidump::DumpKind::UserMinidump
                ? translated("minidump.tab.modules", "模块")
                : translated("minidump.tab.drivers", "驱动"));
    }

    // ===================== 线程页 =====================
    if (!result.threads.empty())
    {
        beginFill(m_threadTable);
        m_threadTable->setColumnCount(13);
        m_threadTable->setHorizontalHeaderLabels({
            translated("minidump.column.thread_id", "线程 ID"),
            translated("minidump.column.thread_state", "状态"),
            translated("minidump.column.thread_name", "名称"),
            translated("minidump.column.instruction_pointer", "指令指针"),
            translated("minidump.column.ip_module", "指令指针所属模块"),
            translated("minidump.column.start_address", "起始地址"),
            translated("minidump.column.start_module", "起始地址所属模块"),
            translated("minidump.column.cpu_time", "CPU 时间(用户/内核)"),
            translated("minidump.column.teb", "TEB"),
            translated("minidump.column.stack_base", "栈基址"),
            translated("minidump.column.stack_size", "栈大小"),
            translated("minidump.column.suspend_count", "挂起计数"),
            translated("minidump.column.priority", "优先级") });
        m_threadTable->setRowCount(static_cast<int>(result.threads.size()));
        int threadRow = 0;
        for (const ks::minidump::ThreadEntry& thread : result.threads)
        {
            m_threadTable->setItem(threadRow, 0, makeItem(QString::number(thread.threadId)));
            m_threadTable->setItem(threadRow, 1,
                makeItem(thread.faulting
                    ? translated("minidump.thread.faulting", "崩溃线程")
                    : QString()));
            m_threadTable->setItem(threadRow, 2, makeItem(thread.name));
            m_threadTable->setItem(threadRow, 3,
                makeItem(thread.instructionPointer != 0
                    ? hexText(thread.instructionPointer)
                    : QString()));
            m_threadTable->setItem(threadRow, 4, makeItem(thread.ipSymbolText));
            m_threadTable->setItem(threadRow, 5,
                makeItem(thread.startAddress != 0 ? hexText(thread.startAddress) : QString()));
            m_threadTable->setItem(threadRow, 6, makeItem(thread.startSymbolText));
            m_threadTable->setItem(threadRow, 7, makeItem(thread.cpuTimeText));
            m_threadTable->setItem(threadRow, 8, makeItem(hexText(thread.teb)));
            m_threadTable->setItem(threadRow, 9, makeItem(hexText(thread.stackBase)));
            m_threadTable->setItem(threadRow, 10, makeItem(QString::number(thread.stackSize)));
            m_threadTable->setItem(threadRow, 11, makeItem(QString::number(thread.suspendCount)));
            m_threadTable->setItem(threadRow, 12,
                makeItem(QStringLiteral("%1 / %2")
                    .arg(thread.priorityClass)
                    .arg(thread.priority)));
            ++threadRow;
        }
        endFill(m_threadTable);
        m_resultTabs->addTab(m_threadPage, translated("minidump.tab.threads", "线程"));
    }

    // ===================== 内存区域页 =====================
    if (!result.memoryRegions.empty())
    {
        beginFill(m_memoryTable);
        m_memoryTable->setColumnCount(6);
        m_memoryTable->setHorizontalHeaderLabels({
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.mem_state", "状态"),
            translated("minidump.column.mem_protect", "保护"),
            translated("minidump.column.mem_type", "类型"),
            translated("minidump.column.mem_source", "来源") });
        m_memoryTable->setRowCount(static_cast<int>(result.memoryRegions.size()));
        int memoryRow = 0;
        for (const ks::minidump::MemoryRegionEntry& region : result.memoryRegions)
        {
            m_memoryTable->setItem(memoryRow, 0, makeItem(hexText(region.base)));
            m_memoryTable->setItem(memoryRow, 1, makeItem(hexText(region.size)));
            m_memoryTable->setItem(memoryRow, 2, makeItem(region.state));
            m_memoryTable->setItem(memoryRow, 3, makeItem(region.protect));
            m_memoryTable->setItem(memoryRow, 4, makeItem(region.type));
            m_memoryTable->setItem(memoryRow, 5,
                makeItem(ks::i18n::sourceText(region.source)));
            ++memoryRow;
        }
        endFill(m_memoryTable);
        m_resultTabs->addTab(m_memoryPage,
            translated("minidump.tab.memory", "内存区域"));
    }

    // ===================== 原始内存预览页 =====================
    // 带虚拟地址的 TRIAGE 块复用只读内存多视图。辅助文件数据仍是文本预览，
    // 不把文件偏移解释成虚拟地址，也不为未捕获字节提供读取或写回入口。
    if (!result.byteBlocks.empty())
    {
        for (std::size_t index = 0; index < result.byteBlocks.size(); ++index)
        {
            const ks::minidump::DumpByteBlock& block = result.byteBlocks[index];
            const std::uint64_t previewBytes = block.previewBytes.size();
            const std::uint64_t omittedBytes = block.capturedBytes > previewBytes
                ? block.capturedBytes - previewBytes : 0;
            const QString blockTitle = QStringLiteral("%1 %2")
                .arg(translated("minidump.raw.block", "数据块")).arg(index + 1);
            ks::ui::FieldDocument metadataDocument;
            metadataDocument.title = blockTitle;
            metadataDocument.field(QStringLiteral("来源"), block.source, true);
            metadataDocument.field(QStringLiteral("虚拟地址"), block.hasVirtualAddress ? hexText(block.address) : QStringLiteral("不适用"));
            metadataDocument.field(QStringLiteral("文件偏移"), hexText(block.fileOffset));
            metadataDocument.field(QStringLiteral("完整捕获大小（字节）"), QString::number(block.capturedBytes));
            metadataDocument.field(QStringLiteral("预览大小（字节）"), QString::number(previewBytes));
            auto* page = new QWidget(m_rawMemoryTabs);
            auto* layout = new QVBoxLayout(page);
            layout->setContentsMargins(0, 0, 0, 0);
            auto* metadata = new ks::ui::StructuredFieldView(page);
            metadata->setMaximumHeight(145);
            metadata->setDocument(metadataDocument);
            layout->addWidget(metadata);
            if (block.hasVirtualAddress)
            {
                auto* editor = new ks::ui::SnapshotWorkbenchWidget(page);
                editor->setEditable(false);
                const QByteArray bytes(block.previewBytes.empty() ? nullptr
                    : reinterpret_cast<const char*>(block.previewBytes.data()),
                    static_cast<qsizetype>(previewBytes));
                const auto architecture = result.pointerSize == 4
                    ? ks::ui::DisassemblyArchitecture::X86 : ks::ui::DisassemblyArchitecture::X64;
                const auto anchor = result.faultingAddress >= block.address
                    && result.faultingAddress - block.address < previewBytes
                    ? result.faultingAddress : block.address;
                editor->setSnapshot(bytes, block.address, architecture, anchor,
                    QStringLiteral("dump-block:%1:%2:%3:%4")
                        .arg(result.filePath).arg(result.fileSize)
                        .arg(result.fileLastModifiedUtcMs).arg(block.fileOffset));
                layout->addWidget(editor, 1);
            }
            else
            {
                const QString rawText = ks::minidump::FormatDumpBytes(block.fileOffset,
                    block.previewBytes.empty() ? nullptr : block.previewBytes.data(),
                    previewBytes, omittedBytes);
                auto* report = new CodeEditorWidget(page);
                report->setReadOnly(true);
                report->setRawText(rawText);
                layout->addWidget(report, 1);
            }
            m_rawMemoryTabs->addTab(page, blockTitle);
        }
        m_resultTabs->addTab(m_rawMemoryTabs,
            translated("minidump.tab.raw_memory", "原始内存"));
    }

    // ===================== 内存查看器页 =====================
    // 预览页只保留少量 TRIAGE 块的前部字节；查看器则按解析期验证过的
    // 地址映射重开 DMP，能翻页读取完整块，也同时覆盖 MDMP 内存流和线程栈。
    if (!result.capturedMemoryRanges.empty())
    {
        m_memoryView->setDumpData(result);
        m_resultTabs->addTab(m_memoryView,
            translated("minidump.tab.memory_view", "内存查看器"));
    }
    else
    {
        m_memoryView->clearData();
    }

    // ===================== 句柄页 =====================
    if (!result.handles.empty())
    {
        beginFill(m_handleTable);
        m_handleTable->setColumnCount(7);
        m_handleTable->setHorizontalHeaderLabels({
            translated("minidump.column.handle_value", "句柄值"),
            translated("minidump.column.handle_type", "类型"),
            translated("minidump.column.object_name", "对象名"),
            translated("minidump.column.attributes", "属性"),
            translated("minidump.column.granted_access", "访问掩码"),
            translated("minidump.column.handle_count", "句柄计数"),
            translated("minidump.column.pointer_count", "指针计数") });
        m_handleTable->setRowCount(static_cast<int>(result.handles.size()));
        int handleRow = 0;
        for (const ks::minidump::HandleEntry& handle : result.handles)
        {
            m_handleTable->setItem(handleRow, 0, makeItem(hexText(handle.handleValue)));
            m_handleTable->setItem(handleRow, 1, makeItem(handle.typeName));
            m_handleTable->setItem(handleRow, 2, makeItem(handle.objectName));
            m_handleTable->setItem(handleRow, 3, makeItem(hexText(handle.attributes)));
            m_handleTable->setItem(handleRow, 4, makeItem(hexText(handle.grantedAccess)));
            m_handleTable->setItem(handleRow, 5, makeItem(QString::number(handle.handleCount)));
            m_handleTable->setItem(handleRow, 6, makeItem(QString::number(handle.pointerCount)));
            ++handleRow;
        }
        endFill(m_handleTable);
        m_resultTabs->addTab(m_handlePage, translated("minidump.tab.handles", "句柄"));
    }

    // ===================== 已卸载模块页 =====================
    if (!result.unloadedModules.empty())
    {
        beginFill(m_unloadedTable);
        m_unloadedTable->setColumnCount(5);
        m_unloadedTable->setHorizontalHeaderLabels({
            translated("minidump.column.module_name", "名称"),
            translated("minidump.column.base", "基址"),
            translated("minidump.column.size", "大小"),
            translated("minidump.column.timestamp", "时间戳"),
            translated("minidump.column.checksum", "校验和") });
        m_unloadedTable->setRowCount(static_cast<int>(result.unloadedModules.size()));
        int unloadedRow = 0;
        for (const ks::minidump::UnloadedModuleEntry& module : result.unloadedModules)
        {
            m_unloadedTable->setItem(unloadedRow, 0, makeItem(module.name));
            m_unloadedTable->setItem(unloadedRow, 1, makeItem(hexText(module.base)));
            m_unloadedTable->setItem(unloadedRow, 2, makeItem(hexText(module.size)));
            m_unloadedTable->setItem(unloadedRow, 3, makeItem(module.timestampText));
            m_unloadedTable->setItem(unloadedRow, 4,
                makeItem(module.checksum != 0 ? hexText(module.checksum) : QString()));
            ++unloadedRow;
        }
        endFill(m_unloadedTable);
        m_resultTabs->addTab(m_unloadedTable,
            translated("minidump.tab.unloaded", "已卸载模块"));
    }

    // ===================== 全文报告页 =====================
    if (result.success)
    {
        // 报告用中文规范文本生成，只读编辑器按当前语言即时渲染。
        m_reportEditor->setDocument(buildReportText(result));
        m_resultTabs->addTab(m_reportEditor, translated("minidump.tab.report", "报告"));
    }
}

ks::ui::FieldDocument MinidumpDock::buildReportText(const ks::minidump::DumpParseResult& result) const
{
    ks::ui::FieldDocument document;
    document.title = QStringLiteral("KSword 转储解析报告");
    document.field(QStringLiteral("文件"), result.filePath);
    const auto appendProperties = [&document](const QString& title, const auto& properties) {
        document.section(title);
        for (const auto& property : properties) document.field(property.name, property.value);
    };
    const auto& analysis = result.analysis;
    if (!analysis.headline.isEmpty()) {
        document.section(QStringLiteral("诊断结论"));
        document.field(QStringLiteral("结论"), analysis.headline, true);
        document.field(QStringLiteral("可信度"), ks::minidump::AnalysisConfidenceText(analysis.confidence), true);
        if (!analysis.category.isEmpty()) document.field(QStringLiteral("故障归类"), analysis.category, true);
        for (const auto& finding : analysis.findings) document.field(QStringLiteral("发现"), finding, true);
        for (const auto& suggestion : analysis.suggestions) document.field(QStringLiteral("建议"), suggestion, true);
    }
    if (!analysis.blame.empty()) {
        document.section(QStringLiteral("肇事模块候选"));
        document.note(QStringLiteral("按证据权重降序"));
        for (const auto& blame : analysis.blame) {
            document.section(blame.moduleName);
            document.field(QStringLiteral("权重"), QString::number(blame.weight));
            document.field(QStringLiteral("命中"), hexText(blame.address));
            document.field(QStringLiteral("偏移"), hexText(blame.offset));
            document.field(QStringLiteral("已卸载模块"), blame.unloadedModule ? QStringLiteral("是") : QStringLiteral("否"), true);
            for (const auto& evidence : blame.evidence) document.field(QStringLiteral("证据"), evidence, true);
        }
    }
    appendProperties(QStringLiteral("概览"), result.overview);
    if (!result.exceptionInfo.empty()) appendProperties(QStringLiteral("异常信息"), result.exceptionInfo);
    if (!result.executionContext.empty()) appendProperties(QStringLiteral("崩溃现场"), result.executionContext);
    if (!result.registers.empty()) {
        document.section(QStringLiteral("崩溃点寄存器"));
        for (const auto& entry : result.registers) {
            document.field(entry.name, hexText(entry.value));
            if (!entry.note.isEmpty()) document.note(entry.note);
        }
    }
    if (!result.stackFrames.empty()) {
        document.section(QStringLiteral("疑似调用栈"));
        document.note(QStringLiteral("由栈内存扫描重建，无符号；顺序为近似值，可能含残留帧"));
        for (const auto& frame : result.stackFrames) {
            document.section(QStringLiteral("TID %1 / #%2").arg(frame.threadId).arg(frame.index));
            document.field(QStringLiteral("地址"), hexText(frame.address));
            document.field(QStringLiteral("符号"), frame.symbolText);
            document.field(QStringLiteral("来源"), frame.fromContext ? QStringLiteral("上下文") : QStringLiteral("栈扫描"), true);
        }
    }
    if (!result.streams.empty()) {
        document.section(QStringLiteral("数据流"));
        for (const auto& stream : result.streams) {
            document.section(stream.typeName);
            document.field(QStringLiteral("类型"), QString::number(stream.type));
            document.field(QStringLiteral("偏移"), hexText(stream.rva));
            document.field(QStringLiteral("大小"), QString::number(stream.size));
        }
    }
    if (!result.modules.empty()) {
        document.section(QStringLiteral("模块"));
        document.field(QStringLiteral("数量"), QString::number(result.modules.size()));
        for (const auto& module : result.modules) {
            document.section(module.name);
            document.field(QStringLiteral("基址"), hexText(module.base));
            document.field(QStringLiteral("大小"), hexText(module.size));
            if (!module.version.isEmpty()) document.field(QStringLiteral("版本"), module.version);
            if (!module.timestampText.isEmpty()) document.field(QStringLiteral("时间戳"), module.timestampText);
            if (!module.pdbName.isEmpty()) document.field(QStringLiteral("PDB"), module.pdbName);
        }
    }
    if (!result.threads.empty()) {
        document.section(QStringLiteral("线程"));
        document.field(QStringLiteral("数量"), QString::number(result.threads.size()));
        for (const auto& thread : result.threads) {
            document.section(QStringLiteral("TID %1").arg(thread.threadId));
            document.field(QStringLiteral("崩溃线程"), thread.faulting ? QStringLiteral("是") : QStringLiteral("否"), true);
            if (!thread.name.isEmpty()) document.field(QStringLiteral("名称"), thread.name);
            if (thread.instructionPointer != 0) document.field(QStringLiteral("IP"), hexText(thread.instructionPointer));
            document.field(QStringLiteral("TEB"), hexText(thread.teb));
            document.field(QStringLiteral("栈"), hexText(thread.stackBase));
            document.field(QStringLiteral("栈大小"), QString::number(thread.stackSize));
        }
    }
    if (!result.memoryRegions.empty()) {
        document.section(QStringLiteral("内存区域"));
        document.field(QStringLiteral("总数"), QString::number(result.memoryRegionTotal));
        const std::size_t reportRows = std::min(result.memoryRegions.size(), kReportMemoryRowLimit);
        for (std::size_t index = 0; index < reportRows; ++index) {
            const auto& region = result.memoryRegions[index];
            document.section(hexText(region.base));
            document.field(QStringLiteral("大小"), hexText(region.size));
            if (!region.state.isEmpty()) document.field(QStringLiteral("状态"), region.state, true);
            if (!region.protect.isEmpty()) document.field(QStringLiteral("保护"), region.protect, true);
            if (!region.type.isEmpty()) document.field(QStringLiteral("类型"), region.type, true);
        }
        if (result.memoryRegions.size() > reportRows) document.note(QStringLiteral("(其余 %1 条内存区域未列入报告)").arg(result.memoryRegions.size() - reportRows));
    }
    if (!result.handles.empty()) {
        document.section(QStringLiteral("句柄"));
        for (const auto& handle : result.handles) {
            document.section(hexText(handle.handleValue));
            document.field(QStringLiteral("类型"), handle.typeName);
            if (!handle.objectName.isEmpty()) document.field(QStringLiteral("对象名称"), handle.objectName);
        }
    }
    if (!result.unloadedModules.empty()) {
        document.section(QStringLiteral("已卸载模块"));
        for (const auto& module : result.unloadedModules) {
            document.section(module.name);
            document.field(QStringLiteral("基址"), hexText(module.base));
            document.field(QStringLiteral("大小"), hexText(module.size));
        }
    }
    if (!result.diagnostics.isEmpty()) {
        document.section(QStringLiteral("解析告警"));
        for (const auto& diagnostic : result.diagnostics) document.note(diagnostic);
    }
    return document;
}
