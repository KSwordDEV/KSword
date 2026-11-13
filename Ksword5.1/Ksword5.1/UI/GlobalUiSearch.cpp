#include "./NavigationHighlight.h"
#include "GlobalUiSearch.h"
#include "./ScopedObjectDiscoveryCursor.h"

#include "TableSearchSupport.h"
#include "TableRowFilterSupport.h"

#include "../include/ads/DockWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractButton>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QElapsedTimer>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QStyleOption>
#include <QStyledItemDelegate>
#include <QTabBar>
#include "./SegmentedControl.h"
#include <QTabWidget>
#include <QTableView>
#include <QTextDocument>
#include <QTextDocumentFragment>
#include <QTextOption>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>

namespace
{
    using ks::ui::StripUiSearchMnemonicMarkers;

    // g_activeSearchController：主窗口当前活动的标题栏搜索控制器。
    QPointer<ks::ui::GlobalUiSearchController> g_activeSearchController;

    // 搜索与展示参数：
    // - kSearchDebounceIntervalMs：输入防抖间隔；
    // - kMaxHitsPerDock：单个 Dock 允许贡献的命中上限，避免单页刷屏；
    // - kMaxTotalHits：结果总量上限；
    // - kMaxVisibleResultRows：弹层一次最多完整展示的行数（超出滚动）；
    // - kResultItemHeight：结果行固定高度（两行：匹配文本 + 页面路径）；
    // - kSnippetMaxLength：匹配文本展示片段的最大字符数；
    // - kSnippetMatchLeadin：片段截取时命中位置前保留的字符数；
    // - kComboBoxItemScanLimit：下拉框条目参与索引的数量上限；
    // - kHeaderColumnScanLimit：表头列参与索引的数量上限；
    // - kFlashDelayMs：Dock 置前后到点亮高亮之间的布局稳定等待；
    // - kProgressContentHeight：扫描进行中弹层进度行的内容高度；
    // - kResultHtmlRole：列表项富文本内容的自定义数据角色。
    constexpr int kSearchDebounceIntervalMs = 220;
    constexpr int kMaxHitsPerDock = 24;
    constexpr int kMaxTotalHits = 96;
    constexpr int kMaxVisibleResultRows = 8;
    constexpr int kResultItemHeight = 46;
    constexpr int kSnippetMaxLength = 60;
    constexpr int kSnippetMatchLeadin = 18;
    constexpr int kComboBoxItemScanLimit = 60;
    constexpr int kHeaderColumnScanLimit = 80;
    constexpr int kFlashDelayMs = 140;
    constexpr int kProgressContentHeight = 44;
    constexpr int kResultHtmlRole = Qt::UserRole + 41;
    // HTML 只缓存文本与语义占位，实际绘制时按该行真实底色求色，避免跨主题保存 RGB。
    constexpr auto kResultPrimaryColorToken = "__KS_SEARCH_PRIMARY_COLOR__";
    constexpr auto kResultSecondaryColorToken = "__KS_SEARCH_SECONDARY_COLOR__";
    constexpr auto kResultAccentColorToken = "__KS_SEARCH_ACCENT_COLOR__";

    // normalizeUiText：
    // - 作用：把控件原始文本压成适合匹配与单行展示的纯文本；
    // - 处理：富文本转纯文本、换行/制表符归并为空格、去首尾空白；
    // - 传入 rawText：控件读取到的原始文本；
    // - 传出：规范化后的单行文本。
    QString normalizeUiText(QString rawText)
    {
        if (rawText.contains(QLatin1Char('<')) && Qt::mightBeRichText(rawText))
        {
            rawText = QTextDocumentFragment::fromHtml(rawText).toPlainText();
        }
        rawText.replace(QLatin1Char('\n'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\r'), QLatin1Char(' '));
        rawText.replace(QLatin1Char('\t'), QLatin1Char(' '));
        return rawText.simplified();
    }

    // isWidgetChainRevealable：
    // - 作用：判断目标控件是否能通过“切换页签”被真实展示出来；
    // - 规则：向上遍历到所属 Dock 为止，任何被显式隐藏、且其父不是
    //   QStackedWidget（页签导航性质隐藏）的祖先都视为不可揭示；
    // - 传入 targetWidget：候选命中控件；
    // - 传出：true=激活结果后可见，false=永远展示不出来（不收录）。
    bool isWidgetChainRevealable(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                return true;
            }
            if (cursorWidget->isHidden()
                && qobject_cast<QStackedWidget*>(cursorWidget->parentWidget()) == nullptr)
            {
                return false;
            }
        }
        return true;
    }

    // resolveMatchRank：
    // - 作用：计算命中排序权重；
    // - 规则：0=整串相等（忽略大小写），1=前缀命中，2=普通包含；
    // - 传入 normalizedText：命中文本；queryText：查询；matchIndex：首个命中位置。
    int resolveMatchRank(const QString& normalizedText, const QString& queryText, const int matchIndex)
    {
        if (normalizedText.compare(queryText, Qt::CaseInsensitive) == 0)
        {
            return 0;
        }
        return matchIndex == 0 ? 1 : 2;
    }

    // tableViewForWidget：从事件目标沿父链解析所属表格。
    QTableView* tableViewForWidget(QWidget* sourceWidget)
    {
        for (QWidget* cursorWidget = sourceWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (QTableView* tableView = qobject_cast<QTableView*>(cursorWidget))
            {
                return tableView;
            }
        }
        return nullptr;
    }

    // dockWidgetForWidget：从控件父链解析所属 ADS Dock。
    ads::CDockWidget* dockWidgetForWidget(QWidget* sourceWidget)
    {
        for (QWidget* cursorWidget = sourceWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (ads::CDockWidget* dockWidget = qobject_cast<ads::CDockWidget*>(cursorWidget))
            {
                return dockWidget;
            }
        }
        return nullptr;
    }

    // buildPagePathText：
    // - 作用：生成“Dock 标题 › 内部页签 › 分组框”形式的页面路径；
    // - 处理：从目标控件向上收集 QTabWidget/QStackedWidget 页名与
    //   QGroupBox 标题（目标自身标题不重复计入），由外到内拼接；
    // - 传入 dockWidget：所属 Dock；dockTitleText：Dock 标题；targetWidget：命中控件；
    // - 传出：页面路径文本。
    QString buildPagePathText(
        const ads::CDockWidget* dockWidget,
        const QString& dockTitleText,
        QWidget* targetWidget)
    {
        QStringList innerPathParts;
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == dockWidget)
            {
                break;
            }

            QWidget* parentWidget = cursorWidget->parentWidget();
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int tabIndex = tabWidget->indexOf(cursorWidget);
                    if (tabIndex >= 0)
                    {
                        const QString tabText =
                            normalizeUiText(StripUiSearchMnemonicMarkers(tabWidget->tabText(tabIndex)));
                        if (!tabText.isEmpty())
                        {
                            innerPathParts.prepend(tabText);
                        }
                    }
                }
            }

            if (cursorWidget != targetWidget)
            {
                if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(cursorWidget))
                {
                    const QString groupTitleText = normalizeUiText(groupBox->title());
                    if (!groupTitleText.isEmpty())
                    {
                        innerPathParts.prepend(groupTitleText);
                    }
                }
            }
        }

        QStringList fullPathParts;
        fullPathParts << dockTitleText;
        fullPathParts << innerPathParts;
        fullPathParts.removeAll(QString());
        return fullPathParts.join(QStringLiteral(" › "));
    }

    // 静态标题/检索描述来自同源工厂；每条命中保留局部ID，只有用户激活才解析widget。
    void collectCatalogSearchHits(ads::CDockWidget* dock, const QString& query,
        const QVector<ks::ui::ResolvedPageNavigationDescriptor>& pages,
        QVector<ks::ui::UiSearchHit>& hits, bool currentPageOnly)
    {
        int appended = 0;
        for (const auto& descriptor : pages)
        {
            if (!descriptor.page.visible || (currentPageOnly && !descriptor.page.current)) continue;
            QStringList candidates = descriptor.page.searchTexts;
            candidates.prepend(descriptor.page.title);
            QString best;
            int bestRank = 3;
            for (const QString& text : candidates)
            {
                const QString normalized = normalizeUiText(StripUiSearchMnemonicMarkers(text));
                const int position = normalized.indexOf(query, 0, Qt::CaseInsensitive);
                if (position < 0) continue;
                const int rank = resolveMatchRank(normalized, query, position);
                if (rank < bestRank) { best = normalized; bestRank = rank; }
            }
            if (best.isEmpty()) continue;
            ks::ui::UiSearchHit hit;
            hit.pageDockWidget = dock;
            hit.navigationDescriptorId = descriptor.page.id;
            hit.navigationEnabled = descriptor.page.enabled;
            hit.matchedText = best;
            hit.pagePathText = descriptor.path.join(QStringLiteral(" › "));
            hit.matchRank = bestRank;
            hits.append(std::move(hit));
            if (++appended >= kMaxHitsPerDock) break;
        }
    }

    // 主Dock身份与标题在惰性壳创建时已经存在，是独立于业务widget的冷导航源。
    void collectDockTitleSearchHit(ads::CDockWidget* dock, const QString& query,
        QVector<ks::ui::UiSearchHit>& hits)
    {
        if (dock == nullptr) return;
        const QString title = normalizeUiText(StripUiSearchMnemonicMarkers(dock->windowTitle()));
        const int position = title.indexOf(query, 0, Qt::CaseInsensitive);
        if (position < 0) return;
        ks::ui::UiSearchHit hit;
        hit.pageDockWidget = dock;
        hit.navigationRoot = true;
        hit.matchedText = title;
        hit.pagePathText = title;
        hit.matchRank = resolveMatchRank(title, query, position);
        hits.append(std::move(hit));
    }

    // collectDockSearchHits：
    // - 作用：在单个 Dock 的控件树内做关键词匹配并追加命中；
    // - 索引来源：QLabel 文本、按钮文本、分组框标题、QTabWidget 页签、
    //   下拉框条目、输入框占位符、表格/树视图水平表头；
    // - 传入 dockWidget：目标 Dock；queryText：查询；outHitList：命中输出；
    // - 传出：无返回值，命中追加到 outHitList（受单页上限约束）。
    // collectDirectTableSearchHits：只扫描显式目标表格，供“当前表格”范围使用。
    void collectDirectTableSearchHits(
        QTableView* tableView,
        const QVector<ks::ui::TableCellSearchMatch>& tableMatchList,
        QVector<ks::ui::UiSearchHit>& outHitList)
    {
        if (tableView == nullptr)
        {
            return;
        }

        ads::CDockWidget* dockWidget = dockWidgetForWidget(tableView);
        const QString dockTitleText = dockWidget != nullptr
            ? normalizeUiText(dockWidget->windowTitle())
            : normalizeUiText(tableView->window()->windowTitle());
        for (const ks::ui::TableCellSearchMatch& tableMatch : tableMatchList)
        {
            ks::ui::UiSearchHit hitEntry;
            hitEntry.pageDockWidget = dockWidget;
            hitEntry.targetWidget = tableView;
            hitEntry.targetTableView = tableView;
            hitEntry.targetModelIndex = tableMatch.modelIndex;
            hitEntry.matchedText = tableMatch.matchedText;
            hitEntry.pagePathText = dockWidget != nullptr
                ? buildPagePathText(dockWidget, dockTitleText, tableView)
                    + QStringLiteral(" › ")
                    + tableMatch.locationText
                : dockTitleText
                    + QStringLiteral(" › ")
                    + tableMatch.locationText;
            hitEntry.matchRank = tableMatch.matchRank;
            outHitList.push_back(hitEntry);
        }
    }

    // scrollAncestorsToWidget：
    // - 作用：让目标控件所有 QScrollArea 祖先滚动到目标可见位置；
    // - 传入 targetWidget：要露出的控件。
    void scrollAncestorsToWidget(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            if (cursorWidget == targetWidget)
            {
                continue;
            }
            if (QScrollArea* scrollAreaWidget = qobject_cast<QScrollArea*>(cursorWidget))
            {
                scrollAreaWidget->ensureWidgetVisible(targetWidget, 48, 48);
            }
        }
    }

    // revealHitTargetWithinPage：
    // - 作用：在目标 Dock 内部逐层把目标控件揭示出来；
    // - 处理：向上遍历，命中 QTabWidget/QStackedWidget 页时切换到
    //   目标所在页，最后让滚动区域滚动到目标；
    // - 传入 targetWidget：命中控件。
    void revealHitTargetWithinPage(QWidget* targetWidget)
    {
        for (QWidget* cursorWidget = targetWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (qobject_cast<ads::CDockWidget*>(cursorWidget) != nullptr)
            {
                break;
            }
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (parentWidget == nullptr)
            {
                break;
            }
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int tabIndex = tabWidget->indexOf(cursorWidget);
                    if (tabIndex >= 0 && tabWidget->currentIndex() != tabIndex)
                    {
                        tabWidget->setCurrentIndex(tabIndex);
                    }
                }
                else
                {
                    const int stackIndex = stackedWidget->indexOf(cursorWidget);
                    if (stackIndex >= 0 && stackedWidget->currentIndex() != stackIndex)
                    {
                        stackedWidget->setCurrentIndex(stackIndex);
                    }
                }
            }
        }

        scrollAncestorsToWidget(targetWidget);
    }

    // buildSnippetHtml：
    // - 作用：把命中文本裁剪成展示片段并给命中的查询子串上强调色；
    // - 传入 matchedText：完整命中文本；queryText：查询；accentColorHex：强调色；
    // - 传出：转义后的 HTML 片段（含省略号标记）。
    QString buildSnippetHtml(
        const QString& matchedText,
        const QString& queryText,
        const QString& accentColorHex)
    {
        const int matchedLength = static_cast<int>(matchedText.size());
        const int firstMatchIndex = static_cast<int>(
            matchedText.indexOf(queryText, 0, Qt::CaseInsensitive));
        QString snippetText = matchedText;
        bool clippedHead = false;
        bool clippedTail = false;
        if (matchedLength > kSnippetMaxLength)
        {
            int snippetStart = 0;
            if (firstMatchIndex > kSnippetMatchLeadin)
            {
                snippetStart = std::min(
                    firstMatchIndex - kSnippetMatchLeadin,
                    matchedLength - kSnippetMaxLength);
            }
            snippetText = matchedText.mid(snippetStart, kSnippetMaxLength);
            clippedHead = snippetStart > 0;
            clippedTail = (snippetStart + kSnippetMaxLength) < matchedLength;
        }

        QString htmlText;
        int cursorIndex = 0;
        while (cursorIndex <= snippetText.size())
        {
            const int matchIndex = queryText.isEmpty()
                ? -1
                : snippetText.indexOf(queryText, cursorIndex, Qt::CaseInsensitive);
            if (matchIndex < 0)
            {
                htmlText += snippetText.mid(cursorIndex).toHtmlEscaped();
                break;
            }
            htmlText += snippetText.mid(cursorIndex, matchIndex - cursorIndex).toHtmlEscaped();
            htmlText += QStringLiteral("<span style=\"color:%1;font-weight:600;\">").arg(accentColorHex);
            htmlText += snippetText.mid(matchIndex, queryText.size()).toHtmlEscaped();
            htmlText += QStringLiteral("</span>");
            cursorIndex = matchIndex + queryText.size();
        }

        if (clippedHead)
        {
            htmlText.prepend(QStringLiteral("…"));
        }
        if (clippedTail)
        {
            htmlText.append(QStringLiteral("…"));
        }
        return htmlText;
    }

    // ============================================================
    // SearchResultItemDelegate
    // 说明：
    // - 结果行绘制委托：第一行匹配文本（命中子串强调色加粗），
    //   第二行页面路径（次级色小字号）；
    // - 选中/悬停行画主题强调色半透明圆角底。
    // ============================================================
    class SearchResultItemDelegate final : public QStyledItemDelegate
    {
    public:
        using QStyledItemDelegate::QStyledItemDelegate;

        void paint(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);

            const QRect itemRect = option.rect.adjusted(4, 2, -4, -2);
            const bool selectedState = option.state.testFlag(QStyle::State_Selected);
            const bool hoveredState = option.state.testFlag(QStyle::State_MouseOver);
            QColor actualBackground = option.palette.color(QPalette::Base); // 当前 viewport 的真实基底。
            if (selectedState || hoveredState)
            {
                QColor rowBackgroundColor = KswordTheme::PrimaryAccentColor();
                rowBackgroundColor.setAlpha(selectedState ? 52 : 26);
                actualBackground = KswordTheme::BlendColors(
                    actualBackground, rowBackgroundColor, rowBackgroundColor.alpha());
                painter->setPen(Qt::NoPen);
                painter->setBrush(rowBackgroundColor);
                painter->drawRoundedRect(itemRect, 4, 4);
            }

            QTextDocument contentDocument;
            contentDocument.setDefaultFont(option.font);
            QTextOption noWrapOption = contentDocument.defaultTextOption();
            noWrapOption.setWrapMode(QTextOption::NoWrap);
            contentDocument.setDefaultTextOption(noWrapOption);
            contentDocument.setDocumentMargin(0.0);
            // 每个选态单独求 4.5:1；中灰自定义底可能不存在跨三态都可读的单一前景。
            QString itemHtml = index.data(kResultHtmlRole).toString();
            const auto actualTextColor = [&actualBackground](const QColor& preferredColor) {
                return KswordTheme::ThemeColorName(
                    KswordTheme::EnsureTextContrast(preferredColor, actualBackground, 4.5));
            };
            // 只替换完整样式属性前缀；正文/path 已 HTML 转义，字面量占位名称仍原样显示。
            const auto resolveColorAttribute = [&itemHtml, &actualTextColor](
                const char* token, const QColor& preferredColor) {
                itemHtml.replace(QStringLiteral("style=\"color:%1;").arg(QString::fromLatin1(token)),
                    QStringLiteral("style=\"color:%1;").arg(actualTextColor(preferredColor)));
            };
            resolveColorAttribute(kResultPrimaryColorToken, KswordTheme::TextPrimaryColor());
            resolveColorAttribute(kResultSecondaryColorToken, KswordTheme::TextSecondaryColor());
            resolveColorAttribute(kResultAccentColorToken, KswordTheme::PrimaryAccentColor());
            contentDocument.setHtml(itemHtml);

            painter->translate(itemRect.left() + 8, itemRect.top() + 4);
            contentDocument.drawContents(
                painter,
                QRectF(0, 0, itemRect.width() - 16, itemRect.height() - 8));
            painter->restore();
        }

        QSize sizeHint(
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            Q_UNUSED(option);
            Q_UNUSED(index);
            return QSize(200, kResultItemHeight);
        }
    };

    // widgetBelongsToBranch：
    // - 作用：判断控件是否位于指定祖先分支内（含祖先本身）；
    // - 传入 widgetObject：命中控件；expectedAncestor：期望祖先；
    // - 传出：true=属于该分支。
    bool widgetBelongsToBranch(const QWidget* widgetObject, const QWidget* expectedAncestor)
    {
        if (widgetObject == nullptr || expectedAncestor == nullptr)
        {
            return false;
        }
        for (const QWidget* cursorWidget = widgetObject;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (cursorWidget == expectedAncestor)
            {
                return true;
            }
        }
        return false;
    }
}

namespace ks::ui
{
    // Preserve widget/table discovery order and the existing per-dock hit cap.
    // Each active table uses the same bounded model cursor as CurrentTable scope;
    // one no-hit table can no longer block the complete dock callback.
    struct GlobalUiSearchController::DockSearchCursor final : QObject
    {
        DockSearchCursor(ads::CDockWidget* dock, QString query, bool visibleOnly,
            const QVector<ResolvedPageNavigationDescriptor>& bodyCatalog = {})
            : m_dock(dock), m_content(dock ? dock->widget() : nullptr),
              m_query(std::move(query)), m_visibleOnly(visibleOnly)
        {
            for (const auto& page : bodyCatalog)
                if (page.page.coldBodyComplete && !page.page.coldBodyTexts.isEmpty())
                    m_coldBodies.insert(page.page.id, page);
            rebuild();
        }
        ads::CDockWidget* dock() const { return m_dock.data(); }
        const QVector<UiSearchHit>& matches() const { return m_hits; }
        bool waitingForFullTable() const { return IsTableCellSearchPreparing(m_tableScan); }
        bool advance()
        {
            if (!m_dock) { m_hits.clear(); return true; }
            if (m_dock->widget() != m_content)
            {
                m_content = m_dock->widget();
                m_restart = true;
            }
            if (!m_content) { m_hits.clear(); return true; }
            for (const auto& scan : m_finishedScans)
                if (!IsTableCellSearchCurrent(scan)) { m_restart = true; break; }
            if (m_restart) rebuild();
            QElapsedTimer budget;
            budget.start();
            int widgets = 0;
            int discoveryOperations = 64;
            while (m_hits.size() < kMaxHitsPerDock)
            {
                if (m_tableScan)
                {
                    if (!ContinueTableCellSearch(m_tableScan)) return false;
                    const bool current = IsTableCellSearchCurrent(m_tableScan);
                    if (!current && m_activeTable && m_activeTable->model())
                    {
                        // A live table changed model while its cursor was in
                        // flight. Rescan the dock rather than publish old cells.
                        m_restart = true;
                        return false;
                    }
                    appendTableMatches(CompletedTableCellSearchMatches(m_tableScan));
                    // A table without a model is an empty candidate, not an
                    // invalidation source that should restart the dock forever.
                    if (current) m_finishedScans.push_back(m_tableScan);
                    m_tableScan.reset(); m_activeTable.clear();
                    if (budget.elapsed() >= 4) return false;
                }
                if (m_restart) return false;
                if (++widgets > 64 || budget.elapsed() >= 4) return false;
                QPointer<QObject> discovered;
                const auto result = m_discovery.next(discovered, discoveryOperations);
                if (result == ScopedObjectDiscoveryResult::Yield) return false;
                if (result == ScopedObjectDiscoveryResult::Complete) return true;
                QWidget* candidate = qobject_cast<QWidget*>(discovered.data());
                if (!candidate || candidate->isWindow()) continue;
                if (m_visibleOnly && !candidate->isVisibleTo(m_content.data())) continue;

                if (!m_coldBodies.isEmpty())
                {
                    const auto body = m_coldBodies.constFind(candidate->property("ksword_search_body_page_id").toString());
                    if (body != m_coldBodies.cend() && body->page.visible && isWidgetChainRevealable(candidate))
                        appendColdBody(*body);
                }

                if (auto* label = qobject_cast<QLabel*>(candidate)) appendHit(label, label->text());
                else if (auto* button = qobject_cast<QAbstractButton*>(candidate))
                    appendHit(button, StripUiSearchMnemonicMarkers(button->text()));
                else if (auto* group = qobject_cast<QGroupBox*>(candidate)) appendHit(group, group->title());
                else if (auto* tabs = qobject_cast<QTabWidget*>(candidate))
                {
                    const int first = m_visibleOnly ? tabs->currentIndex() : 0;
                    const int end = m_visibleOnly ? std::min(tabs->count(), first + 1) : tabs->count();
                    for (int index = std::max(0, first); index < end; ++index)
                        appendHit(tabs->widget(index), StripUiSearchMnemonicMarkers(tabs->tabText(index)));
                }
                else if (auto* combo = qobject_cast<QComboBox*>(candidate))
                {
                    if (combo->count() <= kComboBoxItemScanLimit)
                        for (int index = 0; index < combo->count(); ++index) appendHit(combo, combo->itemText(index));
                }
                else if (auto* edit = qobject_cast<QLineEdit*>(candidate)) appendHit(edit, edit->placeholderText());
                else if (auto* view = qobject_cast<QAbstractItemView*>(candidate))
                {
                    QAbstractItemModel* model = view->model();
                    if (model && (qobject_cast<QTableView*>(view) || qobject_cast<QTreeView*>(view)))
                    {
                        const int columns = std::min(model->columnCount(), kHeaderColumnScanLimit);
                        for (int column = 0; column < columns; ++column)
                            appendHit(view, model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString());
                    }
                    if (auto* table = qobject_cast<QTableView*>(view))
                    {
                        m_activeTable = table;
                        m_tableScan = BeginTableCellSearch(table, m_query, kMaxHitsPerDock - m_hits.size());
                        // Return before entering model data; each table gets its
                        // own next event-loop slice even after widget discovery.
                        return false;
                    }
                }
            }
            return !m_restart;
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event && (event->type() == QEvent::ChildAdded || event->type() == QEvent::ChildRemoved))
            {
                // 被替换/移走的旧子树不再使当前内容失效，仅沿此次事件的父链确认归属。
                for (QObject* ancestor = watched; ancestor != nullptr; ancestor = ancestor->parent())
                    if (ancestor == m_content) { m_restart = true; break; }
            }
            return false;
        }
    private:
        void appendColdBody(const ResolvedPageNavigationDescriptor& page)
        {
            for (const auto& entry : page.page.coldBodyTexts)
            {
                if (m_hits.size() >= kMaxHitsPerDock) return;
                if (entry.targetObjectName.isEmpty()) continue;
                const QString text = normalizeUiText(entry.mnemonic ? StripUiSearchMnemonicMarkers(entry.text) : entry.text);
                const int matchIndex = text.indexOf(m_query, 0, Qt::CaseInsensitive);
                if (text.isEmpty() || matchIndex < 0) continue;
                const QString key = page.page.id + QLatin1Char('\x1f')
                    + entry.targetObjectName + QLatin1Char('\x1f') + text;
                if (m_dedup.contains(key)) continue;
                m_dedup.insert(key);
                UiSearchHit hit;
                hit.pageDockWidget = m_dock;
                hit.navigationDescriptorId = page.page.id;
                hit.navigationBodyTargetName = entry.targetObjectName;
                hit.navigationEnabled = page.page.enabled;
                hit.matchedText = text;
                QStringList path;
                for (qsizetype index = 0; index < page.path.size(); ++index)
                {
                    const QString title = normalizeUiText(index == 0 ? page.path[index]
                        : StripUiSearchMnemonicMarkers(page.path[index]));
                    if (!title.isEmpty()) path.append(title);
                }
                for (const auto& group : entry.groupTitles)
                    if (const QString title = normalizeUiText(group); !title.isEmpty()) path.append(title);
                hit.pagePathText = path.join(QStringLiteral(" › "));
                hit.matchRank = resolveMatchRank(text, m_query, matchIndex);
                m_hits.append(std::move(hit));
            }
        }
        void rebuild()
        {
            m_restart = false;
            m_hits.clear(); m_dedup.clear(); m_discovery.reset();
            m_tableScan.reset(); m_activeTable.clear(); m_finishedScans.clear();
            for (const auto& connection : m_navigationConnections) QObject::disconnect(connection);
            m_navigationConnections.clear();
            if (!m_dock || !m_content) return;
            m_title = normalizeUiText(m_dock->windowTitle());
            m_discovery.reset(m_content.data(), [this](QObject* object) {
                auto* candidate = qobject_cast<QWidget*>(object);
                // 保留旧findChildren范围：只在advance跳过独立window本节点，
                // 同一明确contentroot归属树内的后代仍按旧可见/可揭示条件匹配。
                // 只在当前搜索游标的明确内容root内短暂监听结构变更；销毁游标自动解除。
                object->installEventFilter(this);
                if (m_visibleOnly)
                {
                    if (auto* tabs = qobject_cast<QTabWidget*>(candidate))
                        m_navigationConnections.push_back(connect(tabs, &QTabWidget::currentChanged, this,
                            [this]() { m_restart = true; }));
                    else if (auto* stack = qobject_cast<QStackedWidget*>(candidate))
                        m_navigationConnections.push_back(connect(stack, &QStackedWidget::currentChanged, this,
                            [this]() { m_restart = true; }));
                }
                return true;
            });
        }
        void appendHit(QWidget* target, const QString& raw)
        {
            if (m_hits.size() >= kMaxHitsPerDock || !target) return;
            const QString text = normalizeUiText(raw);
            if (text.isEmpty()) return;
            const int matchIndex = text.indexOf(m_query, 0, Qt::CaseInsensitive);
            if (matchIndex < 0 || !isWidgetChainRevealable(target)) return;
            const QString key = QString::number(reinterpret_cast<quintptr>(target),16)
                + QLatin1Char('\x1f') + text;
            if (m_dedup.contains(key)) return;
            m_dedup.insert(key);
            UiSearchHit hit;
            hit.pageDockWidget = m_dock; hit.targetWidget = target;
            hit.matchedText = text;
            hit.pagePathText = buildPagePathText(m_dock.data(), m_title, target);
            hit.matchRank = resolveMatchRank(text, m_query, matchIndex);
            m_hits.push_back(std::move(hit));
        }
        void appendTableMatches(const QVector<TableCellSearchMatch>& matches)
        {
            for (const auto& match : matches)
            {
                if (!m_activeTable || m_hits.size() >= kMaxHitsPerDock) return;
                UiSearchHit hit;
                hit.pageDockWidget = m_dock; hit.targetWidget = m_activeTable.data();
                hit.targetTableView = m_activeTable;
                hit.targetModelIndex = match.modelIndex;
                hit.matchedText = match.matchedText;
                hit.pagePathText = buildPagePathText(m_dock.data(), m_title, m_activeTable.data())
                    + QStringLiteral(" › ") + match.locationText;
                hit.matchRank = match.matchRank;
                m_hits.push_back(std::move(hit));
            }
        }
        QPointer<ads::CDockWidget> m_dock;
        QPointer<QWidget> m_content;
        QString m_query, m_title;
        QHash<QString, ResolvedPageNavigationDescriptor> m_coldBodies;
        bool m_visibleOnly = false, m_restart = false;
        ScopedObjectDiscoveryCursor m_discovery;
        QSet<QString> m_dedup;
        QVector<UiSearchHit> m_hits;
        QVector<QMetaObject::Connection> m_navigationConnections;
        QPointer<QTableView> m_activeTable;
        std::shared_ptr<TableCellSearchCursor> m_tableScan;
        QVector<std::shared_ptr<TableCellSearchCursor>> m_finishedScans;
    };


    GlobalUiSearchController::GlobalUiSearchController(
        QWidget* popupHostWindow,
        QLineEdit* searchInputEdit,
        QWidget* popupAnchorWidget,
        QObject* parentObject)
        : QObject(parentObject)
        , m_popupHostWindow(popupHostWindow)
        , m_searchInputEdit(searchInputEdit)
        , m_popupAnchorWidget(popupAnchorWidget)
    {
        g_activeSearchController = this;
        m_searchDebounceTimer = new QTimer(this);
        m_searchDebounceTimer->setSingleShot(true);
        m_searchDebounceTimer->setInterval(kSearchDebounceIntervalMs);
        connect(m_searchDebounceTimer, &QTimer::timeout, this, [this]() {
            runSearchNow();
        });

        if (m_searchInputEdit != nullptr)
        {
            m_searchInputEdit->installEventFilter(this);
        }
        if (m_popupHostWindow != nullptr)
        {
            m_popupHostWindow->installEventFilter(this);
        }
        if (qApp != nullptr)
        {
            // 应用级过滤监听弹层外点击和主题变化；切色只重着色既有结果，不触发搜索。
            qApp->installEventFilter(this);
        }
        QTimer::singleShot(0, this, [this]() {
            refreshSearchScopeDisplayText();
        });
    }

    GlobalUiSearchController::~GlobalUiSearchController()
    {
        clearSearchResultFilters();
        if (g_activeSearchController == this)
        {
            g_activeSearchController.clear();
        }
    }

    void GlobalUiSearchController::setDockListProvider(DockListProvider dockListProvider)
    {
        m_dockListProvider = std::move(dockListProvider);
    }

    void GlobalUiSearchController::setPageCatalog(
        PageNavigationCatalogProvider provider, PageNavigationCatalogNavigator navigator,
        PageNavigationCatalogSearchCompleteness searchCompleteness)
    {
        m_pageCatalogProvider = std::move(provider);
        m_pageCatalogNavigator = std::move(navigator);
        m_pageCatalogSearchCompleteness = std::move(searchCompleteness);
    }

    void GlobalUiSearchController::setDockPreparer(DockPreparer dockPreparer)
    {
        m_dockPreparer = std::move(dockPreparer);
    }

    void GlobalUiSearchController::setNestedDockPreparer(NestedDockPreparer nestedDockPreparer)
    {
        m_nestedDockPreparer = std::move(nestedDockPreparer);
    }

    void GlobalUiSearchController::setDockActivator(DockActivator dockActivator)
    {
        m_dockActivator = std::move(dockActivator);
    }

    void GlobalUiSearchController::activateForTable(
        QTableView* tableView,
        const QString& queryText,
        const bool focusTopInput)
    {
        if (tableView == nullptr)
        {
            return;
        }

        m_targetTableView = tableView;
        m_recentTableView = tableView;
        m_recentPageDockWidget = dockWidgetForWidget(tableView);
        setSearchScope(UiSearchScope::CurrentTable);

        // 页面切换或 Dock 恢复也可能让标题栏输入框重新获焦，不能把这些焦点变化
        // 当作用户请求并自动展开结果弹层。只有表格搜索入口明确请求焦点、且输入框
        // 当前尚未获焦时，才允许下一次 FocusIn 展开弹层。
        m_showPopupOnNextSearchInputFocus = focusTopInput
            && m_searchInputEdit != nullptr
            && !m_searchInputEdit->hasFocus();
        emit requestSearchInputActivation(focusTopInput);

        if (m_searchInputEdit != nullptr && !queryText.isNull())
        {
            if (m_searchInputEdit->text() != queryText)
            {
                m_searchInputEdit->setText(queryText);
            }
            else
            {
                handleQueryEdited(queryText);
            }
        }
    }

    QString GlobalUiSearchController::searchScopeDisplayText() const
    {
        switch (m_searchScope)
        {
        case UiSearchScope::CurrentPage:
            return ks::i18n::sourceText(QStringLiteral("当前页面"));
        case UiSearchScope::CurrentTable:
        {
            QTableView* tableView = resolveCurrentTable();
            const QString tableName = ks::ui::ResolveTableSearchDisplayName(tableView);
            return ks::i18n::sourceText(QStringLiteral("当前表格（%1）")).arg(tableName);
        }
        case UiSearchScope::Global:
        default:
            return ks::i18n::sourceText(QStringLiteral("全局"));
        }
    }

    void GlobalUiSearchController::handleQueryEdited(const QString& queryText)
    {
        m_pendingQueryText = queryText;
        if (m_searchInProgress && queryText.trimmed() != m_activeQueryText)
        {
            ++m_searchGeneration;
            m_tableSearchCursor.reset();
            m_dockSearchCursor.reset();
            m_preparingSearchDock.clear();
            m_preparingSearchContent.clear();
            m_preparingHasBodyCatalog = false;
            m_searchInProgress = false;
        }
        if (!m_searchModeActive)
        {
            return;
        }
        if (!isCurrentQueryLongEnough(queryText.trimmed()))
        {
            dismissPopup();
            clearSearchResultFilters();
            m_currentHitList.clear();
            if (m_searchInputEdit != nullptr && m_searchInputEdit->hasFocus())
            {
                showOptionsOnlyPopup();
            }
            return;
        }
        m_searchDebounceTimer->start();
    }

    void GlobalUiSearchController::setSearchInputActive(const bool searchModeActive)
    {
        m_searchModeActive = searchModeActive;
        if (!searchModeActive)
        {
            dismissPopup();
            clearSearchResultFilters();
        }
        else if (isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
        {
            m_searchDebounceTimer->start();
        }
        else if (m_searchInputEdit != nullptr && m_searchInputEdit->hasFocus())
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::setSearchResultsOnly(const bool checked)
    {
        if (m_searchResultsOnly == checked)
        {
            refreshSearchOptionControls();
            if (m_searchScope == UiSearchScope::CurrentTable)
            {
            }
            return;
        }

        const bool popupWasVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
        dismissPopup();
        clearSearchResultFilters();
        m_searchResultsOnly = checked;
        refreshSearchOptionControls();
        if (m_searchScope == UiSearchScope::CurrentTable)
        {
        }
        if (m_searchModeActive && isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
        {
            if (popupWasVisible)
            {
                runSearchNow();
            }
            else
            {
                m_searchDebounceTimer->start();
            }
        }
        else if (popupWasVisible)
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::dismissPopup()
    {
        // 代数自增让仍在事件队列里的异步分片全部作废。
        ++m_searchGeneration;
        m_tableSearchCursor.reset();
        m_dockSearchCursor.reset();
        m_preparingSearchDock.clear();
        m_preparingSearchContent.clear();
        m_preparingHasBodyCatalog = false;
        m_searchInProgress = false;
        if (m_searchDebounceTimer != nullptr)
        {
            m_searchDebounceTimer->stop();
        }
        if (m_popupPanel != nullptr && m_popupPanel->isVisible())
        {
            m_popupPanel->hide();
        }
    }

    bool GlobalUiSearchController::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        const QEvent::Type eventType = eventObject->type();

        if (eventType == QEvent::ApplicationPaletteChange
            || (eventType == QEvent::PaletteChange
                && (watchedObject == m_popupHostWindow || watchedObject == m_popupPanel
                    || watchedObject == m_resultListWidget)))
        {
            scheduleResultThemeRefresh();
        }

        if (watchedObject == m_searchInputEdit)
        {
            if (eventType == QEvent::KeyPress)
            {
                // keyEvent 用途：仅在标题输入框截获四节点循环，弹层内字段保留正常焦点导航。
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                // isScopeCycleKey 用途：普通 Tab/Shift+Tab；不拦截 Ctrl/Alt/Meta 组合快捷键。
                const bool mouseless = qApp->property("ksword_mouseless_mode").toBool();
                const bool isScopeCycleKey = (!mouseless && (keyEvent->key() == Qt::Key_Tab
                    || keyEvent->key() == Qt::Key_Backtab)
                    && !keyEvent->modifiers().testFlag(Qt::ControlModifier)
                    && !keyEvent->modifiers().testFlag(Qt::AltModifier)
                    && !keyEvent->modifiers().testFlag(Qt::MetaModifier))
                    || (mouseless && keyEvent->key() == Qt::Key_S
                        && keyEvent->modifiers().testFlag(Qt::ControlModifier)
                        && keyEvent->modifiers().testFlag(Qt::AltModifier)
                        && !keyEvent->modifiers().testFlag(Qt::GroupSwitchModifier)
                        && !keyEvent->modifiers().testFlag(Qt::MetaModifier));
                if (isScopeCycleKey)
                {
                    // direction 用途：兼容 Key_Backtab 和带 Shift 的 Key_Tab 两种反向事件。
                    const int direction = keyEvent->key() == Qt::Key_Backtab
                        || keyEvent->modifiers().testFlag(Qt::ShiftModifier)
                        ? -1
                        : 1;
                    if (m_searchModeActive)
                    {
                        cycleSearchScope(direction);
                    }
                    else
                    {
                        // 从 CMD 进入当前表格时重新采用最近交互上下文，不复用旧显式目标。
                        if (direction < 0)
                        {
                            m_targetTableView.clear();
                        }
                        setSearchScope(direction < 0
                            ? UiSearchScope::CurrentTable
                            : UiSearchScope::Global);
                        emit requestSearchInputActivation(true);
                    }
                    keyEvent->accept();
                    return true;
                }

                // CMD 回车/Esc 继续由 CommandExecutionPopup 处理校验和关闭，不在搜索层消费。
                if (!m_searchModeActive)
                {
                    return false;
                }

                const bool popupVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
                switch (keyEvent->key())
                {
                case Qt::Key_Down:
                    if (popupVisible)
                    {
                        moveSelection(1);
                    }
                    else if (isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Up:
                    if (popupVisible)
                    {
                        moveSelection(-1);
                        return true;
                    }
                    break;
                case Qt::Key_Return:
                case Qt::Key_Enter:
                    if (popupVisible)
                    {
                        const int currentRow = m_resultListWidget != nullptr
                            ? std::max(0, m_resultListWidget->currentRow())
                            : 0;
                        activateHitAtRow(currentRow);
                    }
                    else if (isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
                    {
                        runSearchNow();
                    }
                    return true;
                case Qt::Key_Escape:
                    if (popupVisible)
                    {
                        dismissPopup();
                        return true;
                    }
                    break;
                default:
                    break;
                }
            }
            else if (m_searchModeActive)
            {
                const bool openedByMouse = eventType == QEvent::MouseButtonPress;
                const bool openedByExplicitTableSearch = eventType == QEvent::FocusIn
                    && m_showPopupOnNextSearchInputFocus;
                if (eventType == QEvent::FocusIn)
                {
                    m_showPopupOnNextSearchInputFocus = false;
                }
                if (!openedByMouse && !openedByExplicitTableSearch)
                {
                    return false;
                }
                if (isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
                {
                    m_searchDebounceTimer->start();
                }
                else
                {
                    QTimer::singleShot(0, this, [this]() {
                        if (m_searchModeActive)
                        {
                            showOptionsOnlyPopup();
                        }
                        });
                }
            }
            return false;
        }

        if (eventType == QEvent::LanguageChange)
        {
            refreshSearchScopeDisplayText();
        }

        if (eventType == QEvent::FocusIn || eventType == QEvent::MouseButtonPress)
        {
            QWidget* contextWidget = qobject_cast<QWidget*>(watchedObject);
            if (contextWidget != nullptr)
            {
                if (QTableView* tableView = tableViewForWidget(contextWidget))
                {
                    m_recentTableView = tableView;
                    m_recentPageDockWidget = dockWidgetForWidget(tableView);
                    if (m_searchScope == UiSearchScope::CurrentTable
                        && m_targetTableView != tableView)
                    {
                        dismissPopup();
                        clearSearchResultFilters();
                        m_targetTableView = tableView;
                        refreshSearchScopeDisplayText();
                        if (m_searchModeActive
                            && isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
                        {
                            m_searchDebounceTimer->start();
                        }
                    }
                }
                else if (ads::CDockWidget* dockWidget = dockWidgetForWidget(contextWidget))
                {
                    const bool currentPageChanged = m_searchScope == UiSearchScope::CurrentPage
                        && m_recentPageDockWidget != dockWidget;
                    if (currentPageChanged)
                    {
                        dismissPopup();
                        clearSearchResultFilters();
                    }
                    m_recentPageDockWidget = dockWidget;
                    if (currentPageChanged
                        && m_searchModeActive
                        && isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
                    {
                        m_searchDebounceTimer->start();
                    }
                }
            }
        }

        if (watchedObject == m_popupHostWindow)
        {
            const bool popupVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
            if (popupVisible && (eventType == QEvent::Resize || eventType == QEvent::Move))
            {
                if (eventType == QEvent::Resize) updatePopupSize();
                repositionPopupPanel();
            }
            else if (popupVisible && eventType == QEvent::WindowDeactivate)
            {
                dismissPopup();
            }
            return false;
        }

        if (eventType == QEvent::MouseButtonPress
            && m_popupPanel != nullptr
            && m_popupPanel->isVisible())
        {
            QWidget* clickedWidget = qobject_cast<QWidget*>(watchedObject);
            if (clickedWidget != nullptr
                && !widgetBelongsToBranch(clickedWidget, m_popupPanel)
                && !widgetBelongsToBranch(clickedWidget, m_popupAnchorWidget))
            {
                dismissPopup();
            }
        }

        return false;
    }

    void GlobalUiSearchController::ensurePopupCreated()
    {
        if (m_popupPanel != nullptr || m_popupHostWindow == nullptr)
        {
            return;
        }

        m_popupPanel = new QFrame(m_popupHostWindow);
        m_popupPanel->setObjectName(QStringLiteral("ksGlobalUiSearchPopup"));
        m_popupPanel->setAttribute(Qt::WA_StyledBackground, true);
        m_popupPanel->hide();

        auto* panelLayout = new QVBoxLayout(m_popupPanel);
        panelLayout->setContentsMargins(4, 4, 4, 4);
        panelLayout->setSpacing(0);

        m_searchOptionsRow = new QWidget(m_popupPanel);
        auto* optionsLayout = new QVBoxLayout(m_searchOptionsRow);
        optionsLayout->setContentsMargins(8, 4, 8, 4);
        optionsLayout->setSpacing(8);
        auto* scopeLayout = new QHBoxLayout;
        scopeLayout->setSpacing(8);
        optionsLayout->addLayout(scopeLayout);

        m_searchScopeLabel = new QLabel(m_searchOptionsRow);
        m_searchScopeTabs = new QTabBar(m_searchOptionsRow);
        m_searchScopeTabs->setMinimumWidth(0);
        m_searchScopeTabs->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        m_searchScopeTabs->setDrawBase(false);
        m_searchScopeTabs->setExpanding(true);
        m_searchScopeTabs->setUsesScrollButtons(false);
        m_searchScopeTabs->setElideMode(Qt::ElideRight);
        m_searchScopeTabs->addTab(QString());
        m_searchScopeTabs->addTab(QString());
        m_searchScopeTabs->addTab(QString());
        InstallSegmentedTabBar(m_searchScopeTabs);
        m_searchResultsOnlyCheck = new QCheckBox(m_searchOptionsRow);

        scopeLayout->addWidget(m_searchScopeLabel, 0);
        scopeLayout->addWidget(m_searchScopeTabs, 1);
        optionsLayout->addWidget(m_searchResultsOnlyCheck, 0, Qt::AlignLeft);

        connect(
            m_searchScopeTabs,
            &QTabBar::currentChanged,
            this,
            [this](const int tabIndex) {
                if (tabIndex < static_cast<int>(UiSearchScope::Global)
                    || tabIndex > static_cast<int>(UiSearchScope::CurrentTable))
                {
                    return;
                }
                setSearchScope(static_cast<UiSearchScope>(tabIndex));
            });
        connect(
            m_searchResultsOnlyCheck,
            &QCheckBox::toggled,
            this,
            &GlobalUiSearchController::setSearchResultsOnly);

        m_resultListWidget = new QListWidget(m_popupPanel);
        m_resultListWidget->setObjectName(QStringLiteral("ksGlobalUiSearchResultList"));
        m_resultListWidget->setFrameShape(QFrame::NoFrame);
        m_resultListWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        m_resultListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        m_resultListWidget->setUniformItemSizes(true);
        m_resultListWidget->setMouseTracking(true);
        m_resultListWidget->viewport()->setAttribute(Qt::WA_Hover, true);
        m_resultListWidget->setItemDelegate(new SearchResultItemDelegate(m_resultListWidget));
        connect(m_resultListWidget, &QListWidget::itemClicked, this, [this](QListWidgetItem* listItem) {
            if (m_resultListWidget != nullptr && listItem != nullptr)
            {
                activateHitAtRow(m_resultListWidget->row(listItem));
            }
        });
        connect(m_resultListWidget, &QListWidget::itemActivated, this, [this](QListWidgetItem* listItem) {
            if (m_resultListWidget != nullptr && listItem != nullptr)
            {
                activateHitAtRow(m_resultListWidget->row(listItem));
            }
        });

        m_emptyHintLabel = new QLabel(QStringLiteral("未找到匹配内容"), m_popupPanel);
        m_emptyHintLabel->setObjectName(QStringLiteral("ksGlobalUiSearchEmptyHint"));
        m_emptyHintLabel->setAlignment(Qt::AlignCenter);
        m_emptyHintLabel->setTextFormat(Qt::PlainText);
        m_emptyHintLabel->setWordWrap(true);
        m_retrySearchButton = new QPushButton(m_popupPanel);
        m_retrySearchButton->hide();
        connect(m_retrySearchButton, &QPushButton::clicked, this, &GlobalUiSearchController::runSearchNow);

        // 进度行：异步扫描进行中显示“正在搜索：Dock 名（n/N）”+ 进度条。
        m_searchProgressRow = new QWidget(m_popupPanel);
        m_searchProgressRow->setObjectName(QStringLiteral("ksGlobalUiSearchProgressRow"));
        auto* progressLayout = new QVBoxLayout(m_searchProgressRow);
        progressLayout->setContentsMargins(10, 6, 10, 8);
        progressLayout->setSpacing(5);

        m_searchProgressLabel = new QLabel(m_searchProgressRow);
        m_searchProgressLabel->setObjectName(QStringLiteral("ksGlobalUiSearchProgressLabel"));

        m_searchProgressBar = new QProgressBar(m_searchProgressRow);
        m_searchProgressBar->setObjectName(QStringLiteral("ksGlobalUiSearchProgressBar"));
        m_searchProgressBar->setTextVisible(false);
        m_searchProgressBar->setFixedHeight(6);

        progressLayout->addWidget(m_searchProgressLabel, 0);
        progressLayout->addWidget(m_searchProgressBar, 0);
        m_searchProgressRow->hide();

        panelLayout->addWidget(m_searchOptionsRow, 0);
        panelLayout->addWidget(m_searchProgressRow, 0);
        panelLayout->addWidget(m_resultListWidget, 1);
        panelLayout->addWidget(m_emptyHintLabel, 0);
        panelLayout->addWidget(m_retrySearchButton, 0);
        refreshSearchOptionControls();
    }

    void GlobalUiSearchController::refreshSearchOptionControls()
    {
        if (m_retrySearchButton) m_retrySearchButton->setText(ks::i18n::sourceText(QStringLiteral("重新搜索")));
        if (m_searchScopeLabel != nullptr)
        {
            m_searchScopeLabel->setText(ks::i18n::sourceText(QStringLiteral("范围")));
        }
        if (m_searchScopeTabs != nullptr)
        {
            const QSignalBlocker scopeSignalBlocker(m_searchScopeTabs);
            m_searchScopeTabs->setTabText(
                static_cast<int>(UiSearchScope::Global),
                ks::i18n::sourceText(QStringLiteral("全局")));
            m_searchScopeTabs->setTabText(
                static_cast<int>(UiSearchScope::CurrentPage),
                ks::i18n::sourceText(QStringLiteral("当前页面")));
            m_searchScopeTabs->setTabText(
                static_cast<int>(UiSearchScope::CurrentTable),
                ks::i18n::sourceText(QStringLiteral("当前表格（%1）")).arg(
                    ks::ui::ResolveTableSearchDisplayName(resolveCurrentTable())));
            for (int index = 0; index < m_searchScopeTabs->count(); ++index)
                m_searchScopeTabs->setTabToolTip(index, m_searchScopeTabs->tabText(index));
            m_searchScopeTabs->setCurrentIndex(static_cast<int>(m_searchScope));
        }
        if (m_searchResultsOnlyCheck != nullptr)
        {
            const QSignalBlocker resultsOnlySignalBlocker(m_searchResultsOnlyCheck);
            m_searchResultsOnlyCheck->setText(
                ks::i18n::sourceText(QStringLiteral("仅显示搜索结果")));
            m_searchResultsOnlyCheck->setChecked(m_searchResultsOnly);
        }
    }

    void GlobalUiSearchController::showOptionsOnlyPopup()
    {
        ensurePopupCreated();
        if (m_retrySearchButton) m_retrySearchButton->hide();
        m_currentHitList.clear();
        if (m_searchProgressRow != nullptr)
        {
            m_searchProgressRow->hide();
        }
        if (m_resultListWidget != nullptr)
        {
            m_resultListWidget->clear();
            m_resultListWidget->hide();
        }
        if (m_emptyHintLabel != nullptr)
        {
            m_emptyHintLabel->setText(
                ks::i18n::sourceText(QStringLiteral("输入关键词查找页面、功能或内容；选择结果后跳转到对应位置。")));
            m_emptyHintLabel->show();
        }
        refreshSearchOptionControls();
        showPopupPanel();
    }

    void GlobalUiSearchController::runSearchNow()
    {
        const QString queryText = m_pendingQueryText.trimmed();
        if (!m_searchModeActive || !isCurrentQueryLongEnough(queryText))
        {
            dismissPopup();
            clearSearchResultFilters();
            return;
        }
        if (m_searchScope != UiSearchScope::CurrentTable && !m_dockListProvider)
        {
            return;
        }
        if (m_searchInProgress
            && queryText == m_activeQueryText
            && m_searchScope == m_activeSearchScope)
        {
            // 相同查询的扫描已在途（例如聚焦触发的重复启动），继续用它。
            return;
        }

        // 新代数使仍在事件队列中的旧扫描分片全部作废；先撤销上一轮附加行过滤。
        clearSearchResultFilters();
        ++m_searchGeneration;
        m_activeQueryText = queryText;
        m_activeSearchScope = m_searchScope;
        m_currentHitList.clear();
        m_pendingSearchDockList.clear();
        m_pendingDirectTableView.clear();
        m_tableSearchCursor.reset();
        m_dockSearchCursor.reset();
        m_preparingSearchDock.clear();
        m_preparingSearchContent.clear();
        m_preparingHasBodyCatalog = false;
        if (m_activeSearchScope == UiSearchScope::CurrentTable)
        {
            m_pendingDirectTableView = resolveCurrentTable();
        }
        else if (m_activeSearchScope == UiSearchScope::CurrentPage)
        {
            if (ads::CDockWidget* currentDockWidget = resolveCurrentPageDock())
            {
                m_pendingSearchDockList.append(currentDockWidget);
            }
        }
        else
        {
            const QList<ads::CDockWidget*> dockList = m_dockListProvider();
            for (ads::CDockWidget* dockWidget : dockList)
            {
                if (dockWidget != nullptr)
                {
                    m_pendingSearchDockList.append(QPointer<ads::CDockWidget>(dockWidget));
                }
            }
        }
        m_nextSearchDockIndex = 0;
        m_searchInProgress = true;

        // 进度态弹层：隐藏结果列表与空态，只显示进度行。
        ensurePopupCreated();
        if (m_retrySearchButton) m_retrySearchButton->hide();
        if (m_resultListWidget != nullptr)
        {
            m_resultListWidget->clear();
            m_resultListWidget->setVisible(false);
        }
        if (m_emptyHintLabel != nullptr)
        {
            m_emptyHintLabel->setVisible(false);
        }
        if (m_searchProgressBar != nullptr)
        {
            const int workItemCount = m_activeSearchScope == UiSearchScope::CurrentTable
                ? 1
                : static_cast<int>(m_pendingSearchDockList.size());
            m_searchProgressBar->setRange(
                0,
                std::max(1, workItemCount));
            m_searchProgressBar->setValue(0);
        }
        if (m_searchProgressRow != nullptr)
        {
            m_searchProgressRow->setVisible(true);
        }
        if (!m_pendingSearchDockList.isEmpty()
            && m_pendingSearchDockList.first() != nullptr)
        {
            updateSearchProgressUi(m_pendingSearchDockList.first()->windowTitle());
        }
        else if (!m_pendingDirectTableView.isNull())
        {
            updateSearchProgressUi(
                ks::ui::ResolveTableSearchDisplayName(m_pendingDirectTableView.data()));
        }
        showPopupPanel();

        const quint64 searchGeneration = m_searchGeneration;
        QTimer::singleShot(0, this, [this, searchGeneration]() {
            processNextSearchChunk(searchGeneration);
        });
    }

    void GlobalUiSearchController::processNextSearchChunk(const quint64 searchGeneration)
    {
        if (searchGeneration != m_searchGeneration || !m_searchInProgress)
        {
            return;
        }

        const int workItemCount = m_activeSearchScope == UiSearchScope::CurrentTable
            ? 1
            : static_cast<int>(m_pendingSearchDockList.size());
        if (m_nextSearchDockIndex >= workItemCount
            || (!m_searchResultsOnly
                && m_currentHitList.size() >= kMaxTotalHits))
        {
            finishAsyncSearch();
            return;
        }

        if (m_activeSearchScope == UiSearchScope::CurrentTable)
        {
            if (!m_tableSearchCursor)
                m_tableSearchCursor = BeginTableCellSearch(m_pendingDirectTableView.data(), m_activeQueryText, kMaxTotalHits);
            if (!ContinueTableCellSearch(m_tableSearchCursor))
            {
                QTimer::singleShot(IsTableCellSearchPreparing(m_tableSearchCursor) ? 50 : 0, this, [this, searchGeneration]() { processNextSearchChunk(searchGeneration); });
                return;
            }
            collectDirectTableSearchHits(
                m_pendingDirectTableView.data(),
                CompletedTableCellSearchMatches(m_tableSearchCursor),
                m_currentHitList);
            m_tableSearchCursor.reset();
        m_dockSearchCursor.reset();
            applySearchResultFilterToTable(
                m_pendingDirectTableView.data());
        }
        else
        {
            QPointer<ads::CDockWidget> dock = m_pendingSearchDockList.at(m_nextSearchDockIndex);
            if (!dock) m_dockSearchCursor.reset();
            else
            {
                if (!m_dockSearchCursor || m_dockSearchCursor->dock() != dock.data())
                {
                    updateSearchProgressUi(dock->windowTitle());
                    const QPointer<GlobalUiSearchController> alive(this);
                    // Nested factories can yield many times. Their incomplete body
                    // coverage does not change per slice; do not rediscover the
                    // growing navigation tree or re-run root preparation each time.
                    const bool continuingPreparation = m_preparingSearchDock == dock
                        && m_preparingSearchContent == dock->widget();
                    bool searchComplete = false;
                    if (!continuingPreparation)
                    {
                        std::optional<QVector<ResolvedPageNavigationDescriptor>> descriptors;
                        if (m_pageCatalogProvider)
                        {
                            const auto provider = m_pageCatalogProvider;
                            const auto catalog = provider(dock);
                            if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                            if (dock && catalog) descriptors = ResolvePageNavigationCatalog(*catalog, dock->windowTitle());
                        }
                        if (descriptors && m_pageCatalogSearchCompleteness)
                        {
                            const auto completeness = m_pageCatalogSearchCompleteness;
                            searchComplete = completeness(dock);
                            if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                        }
                        m_preparingHasBodyCatalog = descriptors.has_value() && m_pageCatalogNavigator
                            && m_activeSearchScope == UiSearchScope::Global;
                        if (!searchComplete)
                        {
                            if (dock && m_dockPreparer) m_dockPreparer(dock.data(), m_preparingHasBodyCatalog);
                            if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                            m_preparingSearchDock = dock;
                            m_preparingSearchContent = dock ? dock->widget() : nullptr;
                        }
                    }
                    if (!searchComplete)
                    {
                        // 纯导航目录不代表冷页正文完整；未证明全文覆盖时保留原factory正文搜索。
                        const auto resume = [alive, searchGeneration]() {
                            if (alive) QTimer::singleShot(0, alive.data(), [alive, searchGeneration]() {
                                if (alive) alive->processNextSearchChunk(searchGeneration);
                            });
                        };
                        const auto prepared = !dock || !m_nestedDockPreparer ? PageSearchPreparation::Complete
                            : m_nestedDockPreparer(dock.data(), m_activeSearchScope, true,
                                m_preparingHasBodyCatalog, resume);
                        if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                        if (prepared != PageSearchPreparation::Complete)
                        {
                            if (prepared == PageSearchPreparation::MorePages) resume();
                            return;
                        }
                    }
                    std::optional<QVector<ResolvedPageNavigationDescriptor>> bodyCatalog;
                    if (dock && m_pageCatalogProvider)
                    {
                        const auto provider = m_pageCatalogProvider;
                        const auto catalog = provider(dock);
                        if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                        if (dock && catalog) bodyCatalog = ResolvePageNavigationCatalog(*catalog, dock->windowTitle());
                    }
                    if (!bodyCatalog && m_preparingHasBodyCatalog)
                    {
                        // A provider lost its schema while factories yielded.
                        // Retry original preparation without skipping any cold UI.
                        m_preparingHasBodyCatalog = false;
                        QTimer::singleShot(0, this, [this, searchGeneration]() { processNextSearchChunk(searchGeneration); });
                        return;
                    }
                    m_preparingSearchDock.clear();
                    m_preparingSearchContent.clear();
                    m_preparingHasBodyCatalog = false;
                    const QVector<ResolvedPageNavigationDescriptor> emptyCatalog;
                    if (dock) m_dockSearchCursor = std::make_shared<DockSearchCursor>(dock.data(),
                        m_activeQueryText, m_activeSearchScope == UiSearchScope::CurrentPage,
                        bodyCatalog ? *bodyCatalog : emptyCatalog);
                }
                if (m_dockSearchCursor && !m_dockSearchCursor->advance())
                {
                    QTimer::singleShot(m_dockSearchCursor->waitingForFullTable() ? 50 : 0, this, [this, searchGeneration]() { processNextSearchChunk(searchGeneration); });
                    return;
                }
                if (m_dockSearchCursor)
                {
                    // 保留TS07每个widget/model分片与epoch；只在该Dock完成后追加最新目录投影。
                    m_currentHitList += m_dockSearchCursor->matches();
                    const QPointer<GlobalUiSearchController> alive(this);
                    if (dock && m_pageCatalogProvider)
                    {
                        const auto provider = m_pageCatalogProvider;
                        const auto catalog = provider(dock);
                        if (!alive || searchGeneration != m_searchGeneration || !m_searchInProgress) return;
                        if (dock && catalog)
                            if (const auto descriptors = ResolvePageNavigationCatalog(*catalog, dock->windowTitle()))
                                collectCatalogSearchHits(dock, m_activeQueryText, *descriptors, m_currentHitList,
                                    m_activeSearchScope == UiSearchScope::CurrentPage);
                    }
                    if (dock) collectDockTitleSearchHit(dock, m_activeQueryText, m_currentHitList);
                    const auto hitKey = [](const UiSearchHit& hit) {
                        return QString::number(reinterpret_cast<quintptr>(hit.pageDockWidget.data()), 16)
                            + QLatin1Char('\x1f') + hit.pagePathText + QLatin1Char('\x1f') + hit.matchedText;
                    };
                    QSet<QString> liveKeys;
                    for (const auto& hit : m_currentHitList)
                        if ((hit.navigationDescriptorId.isEmpty() && !hit.navigationRoot)
                            || !hit.navigationBodyTargetName.isEmpty()) liveKeys.insert(hitKey(hit));
                    for (qsizetype index = 0; index < m_currentHitList.size();)
                    {
                        const auto& hit = m_currentHitList[index];
                        if (hit.navigationBodyTargetName.isEmpty()
                            && (!hit.navigationDescriptorId.isEmpty() || hit.navigationRoot) && liveKeys.contains(hitKey(hit)))
                            m_currentHitList.removeAt(index);
                        else ++index;
                    }
                }
                m_dockSearchCursor.reset();
                if (dock) applySearchResultFiltersToDock(dock.data(),
                    m_activeSearchScope == UiSearchScope::CurrentPage);
            }
        }
        ++m_nextSearchDockIndex;
        if (m_searchProgressBar != nullptr)
        {
            m_searchProgressBar->setValue(m_nextSearchDockIndex);
        }

        QTimer::singleShot(0, this, [this, searchGeneration]() {
            processNextSearchChunk(searchGeneration);
        });
    }

    void GlobalUiSearchController::finishAsyncSearch()
    {
        m_currentHitList.erase(std::remove_if(m_currentHitList.begin(), m_currentHitList.end(),
            [](const UiSearchHit& hit) {
                if (hit.navigationRoot || !hit.navigationDescriptorId.isEmpty()) return hit.pageDockWidget.isNull();
                if (hit.targetWidget.isNull()) return true;
                if (!hit.targetTableView) return false;
                return !hit.targetModelIndex.isValid()
                    || hit.targetModelIndex.model() != hit.targetTableView->model()
                    || IsTableCellExcludedByBusinessFilter(hit.targetTableView.data(), hit.targetModelIndex);
            }), m_currentHitList.end());
        m_searchInProgress = false;
        if (m_currentHitList.size() > kMaxTotalHits)
        {
            m_currentHitList.resize(kMaxTotalHits);
        }

        std::stable_sort(
            m_currentHitList.begin(),
            m_currentHitList.end(),
            [](const UiSearchHit& leftHit, const UiSearchHit& rightHit) {
                return leftHit.matchRank < rightHit.matchRank;
            });

        if (m_searchProgressRow != nullptr)
        {
            m_searchProgressRow->setVisible(false);
        }
        rebuildResultList();
        showPopupPanel();
    }

    void GlobalUiSearchController::updateSearchProgressUi(const QString& dockTitleText)
    {
        if (m_searchProgressLabel == nullptr)
        {
            return;
        }

        const int dockCount = m_activeSearchScope == UiSearchScope::CurrentTable
            ? 1
            : static_cast<int>(m_pendingSearchDockList.size());
        const int displayIndex = std::min(m_nextSearchDockIndex + 1, std::max(1, dockCount));
        m_searchProgressLabel->setText(
            ks::i18n::sourceText(QStringLiteral("正在搜索：%1（%2/%3）"))
                .arg(normalizeUiText(dockTitleText))
                .arg(displayIndex)
                .arg(dockCount));
    }

    void GlobalUiSearchController::rebuildResultList()
    {
        ensurePopupCreated();
        if (m_resultListWidget == nullptr)
        {
            return;
        }

        m_resultListWidget->clear();
        for (const UiSearchHit& hitEntry : m_currentHitList)
        {
            auto* listItem = new QListWidgetItem(m_resultListWidget);
            if (!hitEntry.navigationEnabled) listItem->setFlags(listItem->flags() & ~Qt::ItemIsEnabled);
            listItem->setToolTip(
                hitEntry.matchedText
                + QStringLiteral("\n")
                + hitEntry.pagePathText);
        }
        refreshResultHtmlColors();

        const bool hasResults = !m_currentHitList.isEmpty();
        m_resultListWidget->setVisible(hasResults);
        if (m_emptyHintLabel != nullptr)
        {
            m_emptyHintLabel->setText(m_searchScope == UiSearchScope::CurrentTable && !resolveCurrentTable()
                ? ks::i18n::sourceText(QStringLiteral("尚未选择可搜索的表格。请在目标表格的操作条点击搜索。"))
                : ks::i18n::sourceText(QStringLiteral("在%1中未找到匹配内容。可修改关键词或切换搜索范围。"))
                    .arg(searchScopeDisplayText()));
            m_emptyHintLabel->setVisible(!hasResults);
        }
        if (hasResults)
        {
            m_resultListWidget->setCurrentRow(0);
        }
    }

    void GlobalUiSearchController::refreshResultHtmlColors()
    {
        if (m_resultListWidget == nullptr)
        {
            return;
        }
        // 对原列表项保存文本 markup 和颜色语义；RGB 只在 delegate 按实际绘制选态解析。
        // 不 clear/插入，不改变当前行、滚动位置和表格隐藏快照。
        const int itemCount = std::min(m_resultListWidget->count(),
            static_cast<int>(m_currentHitList.size()));
        for (int row = 0; row < itemCount; ++row)
        {
            QListWidgetItem* const listItem = m_resultListWidget->item(row);
            const UiSearchHit& hitEntry = m_currentHitList.at(row);
            const QString itemHtml = QStringLiteral(
                "<div style=\"color:%1;\">%2</div>"
                "<div style=\"color:%3;margin-top:3px;\">%4</div>")
                .arg(QString::fromLatin1(kResultPrimaryColorToken),
                    buildSnippetHtml(hitEntry.matchedText, m_activeQueryText,
                        QString::fromLatin1(kResultAccentColorToken)),
                    QString::fromLatin1(kResultSecondaryColorToken), hitEntry.pagePathText.toHtmlEscaped());
            listItem->setData(kResultHtmlRole, itemHtml);
        }
        m_resultListWidget->viewport()->update();
    }

    void GlobalUiSearchController::scheduleResultThemeRefresh()
    {
        if (m_resultThemeRefreshScheduled)
        {
            return;
        }
        m_resultThemeRefreshScheduled = true;
        QTimer::singleShot(0, this, [this]() {
            refreshResultHtmlColors();
            m_resultThemeRefreshScheduled = false;
        });
    }

    void GlobalUiSearchController::showPopupPanel()
    {
        ensurePopupCreated();
        if (m_popupPanel == nullptr || m_popupHostWindow == nullptr)
        {
            return;
        }

        // 每次展示都重取主题 token，保证深浅色切换后样式即时正确。
        m_popupPanel->setStyleSheet(QStringLiteral(
            "#ksGlobalUiSearchPopup{"
            "  background:%1;"
            "  border:1px solid %2;"
            "  border-radius:6px;"
            "}"
            "#ksGlobalUiSearchPopup QListWidget{"
            "  background:transparent;"
            "  border:none;"
            "}"
            "#ksGlobalUiSearchPopup QLabel#ksGlobalUiSearchEmptyHint{"
            "  color:%3;"

            "  padding:14px 0;"
            "}"
            "#ksGlobalUiSearchPopup QLabel#ksGlobalUiSearchProgressLabel{"
            "  color:%3;"

            "}"
            "#ksGlobalUiSearchPopup QProgressBar#ksGlobalUiSearchProgressBar{"
            "  background:%4;"
            "  border:none;"
            "  border-radius:3px;"
            "}"
            "#ksGlobalUiSearchPopup QProgressBar#ksGlobalUiSearchProgressBar::chunk{"
            "  background:%5;"
            "  border-radius:3px;"
            "}")
            .arg(
                KswordTheme::SurfaceHex(),
                KswordTheme::BorderStrongHex(),
                KswordTheme::TextSecondaryHex(),
                KswordTheme::SurfaceAltHex(),
                KswordTheme::ThemeColorName(KswordTheme::PrimaryAccentColor())));
        if (m_searchOptionsRow != nullptr)
        {
            m_searchOptionsRow->setStyleSheet(QStringLiteral(
                "background:%1;border-bottom:1px solid %2;")
                .arg(KswordTheme::SurfaceAltHex(), KswordTheme::BorderStrongHex()));
        }
        if (m_searchScopeLabel != nullptr)
        {
            m_searchScopeLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        }
        if (m_searchResultsOnlyCheck != nullptr)
        {
            m_searchResultsOnlyCheck->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        }
        // 范围栏颜色由共享分段组件在绘制时求值，显示弹层不再覆写它的选中样式。

        updatePopupSize();
        repositionPopupPanel();
        m_popupPanel->raise();
        m_popupPanel->show();
    }

    void GlobalUiSearchController::updatePopupSize()
    {
        if (!m_popupPanel || !m_popupHostWindow) return;
        const int anchorWidth = m_popupAnchorWidget != nullptr ? m_popupAnchorWidget->width() : 460;
        const int availableWidth = std::max(1, m_popupHostWindow->width() - 24);
        const int panelWidth = std::clamp(
            anchorWidth + 220,
            std::min(460, availableWidth),
            availableWidth);
        const int visibleRowCount = std::min(
            static_cast<int>(m_currentHitList.size()),
            kMaxVisibleResultRows);
        int contentHeight = 48;
        if (m_searchInProgress)
        {
            contentHeight = kProgressContentHeight;
        }
        else if (!m_currentHitList.isEmpty())
        {
            contentHeight = visibleRowCount * kResultItemHeight + 2;
        }
        else if (m_emptyHintLabel)
        {
            const int hintWidth = std::max(1, panelWidth - 20);
            contentHeight = std::max(contentHeight, m_emptyHintLabel->heightForWidth(hintWidth) + 12);
            if (m_retrySearchButton && !m_retrySearchButton->isHidden())
                contentHeight += m_retrySearchButton->sizeHint().height() + 8;
        }
        const int optionsHeight = m_searchOptionsRow ? m_searchOptionsRow->sizeHint().height() : 0;
        m_popupPanel->setFixedSize(panelWidth, contentHeight + optionsHeight + 8);
    }

    void GlobalUiSearchController::repositionPopupPanel()
    {
        if (m_popupPanel == nullptr
            || m_popupHostWindow == nullptr
            || m_popupAnchorWidget == nullptr)
        {
            return;
        }

        const QPoint anchorBottomLeftGlobal =
            m_popupAnchorWidget->mapToGlobal(QPoint(0, m_popupAnchorWidget->height()));
        const QPoint anchorBottomLeftInHost =
            m_popupHostWindow->mapFromGlobal(anchorBottomLeftGlobal);

        int panelLeft = anchorBottomLeftInHost.x()
            + (m_popupAnchorWidget->width() - m_popupPanel->width()) / 2;
        const int maxPanelLeft = std::max(8, m_popupHostWindow->width() - m_popupPanel->width() - 8);
        panelLeft = std::clamp(panelLeft, 8, maxPanelLeft);

        const int panelTop = anchorBottomLeftInHost.y() + 6;
        m_popupPanel->move(panelLeft, panelTop);
    }

    void GlobalUiSearchController::showNavigationUnavailable()
    {
        dismissPopup();
        clearSearchResultFilters();
        ensurePopupCreated();
        if (!m_popupHostWindow || !m_popupPanel || !m_resultListWidget
            || !m_searchProgressRow || !m_emptyHintLabel || !m_retrySearchButton) return;
        m_currentHitList.clear();
        m_resultListWidget->clear();
        m_resultListWidget->hide();
        m_searchProgressRow->hide();
        m_emptyHintLabel->setText(ks::i18n::sourceText(QStringLiteral("目标页面或结果已变化，无法跳转。请重新搜索后选择。")));
        m_emptyHintLabel->show();
        m_retrySearchButton->show();
        showPopupPanel();
    }

    void GlobalUiSearchController::activateHitAtRow(const int rowIndex)
    {
        if (m_searchInProgress)
        {
            // 扫描期间列表尚未填充，行号与命中不对应，忽略激活请求。
            return;
        }
        if (rowIndex < 0 || rowIndex >= m_currentHitList.size())
        {
            return;
        }

        const UiSearchHit hitEntry = m_currentHitList.at(rowIndex);
        if (!hitEntry.navigationEnabled) return;
        const QPointer<GlobalUiSearchController> lifetime(this);
        if (hitEntry.targetTableView) {
            const QPointer<QTableView> table(hitEntry.targetTableView);
            const bool unavailable = !hitEntry.targetModelIndex.isValid()
                || hitEntry.targetModelIndex.model() != table->model()
                || IsTableCellExcludedByBusinessFilter(table.data(), hitEntry.targetModelIndex);
            if (!lifetime) return;
            if (!table || unavailable) { showNavigationUnavailable(); return; }
        }
        const auto permittedDescriptor = [this, &hitEntry, lifetime]()
        {
            if (!hitEntry.pageDockWidget || !m_pageCatalogProvider || !m_pageCatalogNavigator) return false;
            const auto provider = m_pageCatalogProvider;
            const auto catalog = provider(hitEntry.pageDockWidget);
            if (!lifetime || !hitEntry.pageDockWidget || !catalog) return false;
            const auto pages = ResolvePageNavigationCatalog(*catalog, hitEntry.pageDockWidget->windowTitle());
            if (!pages) return false;
            for (const auto& page : *pages)
            {
                if (page.page.id == hitEntry.navigationDescriptorId)
                    return page.page.visible && page.page.enabled;
            }
            return false;
        };
        if (!hitEntry.navigationDescriptorId.isEmpty() && !permittedDescriptor())
        {
            if (!lifetime) return;
            showNavigationUnavailable();
            return;
        }
        QPointer<ads::CDockWidget> dockWidget = hitEntry.pageDockWidget;
        QPointer<QTableView> targetTableView = hitEntry.targetTableView;
        if (dockWidget == nullptr && targetTableView == nullptr)
        {
            showNavigationUnavailable();
            return;
        }

        if (dockWidget != nullptr && m_dockPreparer)
        {
            m_dockPreparer(dockWidget, false);
        }
        if (!lifetime) return;
        const bool descriptorHit = !hitEntry.navigationDescriptorId.isEmpty();
        if (dockWidget != nullptr && m_nestedDockPreparer && !descriptorHit && !hitEntry.navigationRoot)
        {
            // 真实widget命中保留兼容路径；静态ID和根入口只创建用户接受的目标分支。
            bool catalogAvailable = false;
            if (m_pageCatalogProvider)
            {
                const auto provider = m_pageCatalogProvider;
                const auto catalog = provider(dockWidget);
                if (!lifetime) return;
                catalogAvailable = dockWidget && catalog && ResolvePageNavigationCatalog(*catalog, dockWidget->windowTitle()).has_value();
            }
            if (!catalogAvailable && dockWidget) m_nestedDockPreparer(dockWidget, UiSearchScope::Global, false, false, {});
        }
        if (!lifetime) return;
        if (dockWidget != nullptr && m_dockActivator)
        {
            m_dockActivator(dockWidget);
        }
        else if (dockWidget != nullptr)
        {
            dockWidget->toggleView(true);
            if (!lifetime || !dockWidget) return;
            dockWidget->raise();
        }
        else if (targetTableView != nullptr && targetTableView->window() != nullptr)
        {
            targetTableView->window()->show();
            targetTableView->window()->raise();
            targetTableView->window()->activateWindow();
        }

        if (!lifetime) return;
        QPointer<QWidget> targetWidget = hitEntry.targetWidget;
        if (descriptorHit)
        {
            if (!permittedDescriptor()) { if (lifetime) showNavigationUnavailable(); return; }
            const auto navigator = m_pageCatalogNavigator;
            targetWidget = navigator(hitEntry.pageDockWidget, hitEntry.navigationDescriptorId);
            if (!lifetime) return;
            if (targetWidget && !hitEntry.navigationBodyTargetName.isEmpty()
                && targetWidget->objectName() != hitEntry.navigationBodyTargetName)
                targetWidget = targetWidget->findChild<QWidget*>(hitEntry.navigationBodyTargetName);
        }
        dismissPopup();
        if (targetWidget == nullptr)
        {
            showNavigationUnavailable();
            return;
        }

        revealHitTargetWithinPage(targetWidget);
        if (!lifetime || !targetWidget) return;

        // 页签切换与 Dock 置前后等一拍布局，再滚动一次并点亮高亮。
        QPointer<QWidget> guardedTarget(targetWidget);
        const QPersistentModelIndex guardedModelIndex = hitEntry.targetModelIndex;
        QPointer<QTableView> guardedTableView(targetTableView);
        QTimer::singleShot(kFlashDelayMs, this, [guardedTarget, guardedTableView, guardedModelIndex]() {
            if (guardedTarget == nullptr)
            {
                return;
            }
            scrollAncestorsToWidget(guardedTarget);
            if (guardedTableView != nullptr && guardedModelIndex.isValid())
            {
                ks::ui::TableCellSearchMatch tableMatch;
                tableMatch.tableView = guardedTableView;
                tableMatch.modelIndex = guardedModelIndex;
                ks::ui::RevealTableCellSearchMatch(tableMatch);
            }
            ks::ui::FlashNavigationTarget(guardedTarget, ks::ui::NavigationHighlightKind::SearchResult);
        });
    }

    void GlobalUiSearchController::moveSelection(const int rowDelta)
    {
        if (m_resultListWidget == nullptr || m_resultListWidget->count() <= 0)
        {
            return;
        }
        const int targetRow = std::clamp(
            m_resultListWidget->currentRow() + rowDelta,
            0,
            m_resultListWidget->count() - 1);
        m_resultListWidget->setCurrentRow(targetRow);
    }

    void GlobalUiSearchController::setSearchScope(const UiSearchScope searchScope)
    {
        if (m_searchScope == searchScope)
        {
            refreshSearchScopeDisplayText();
            return;
        }

        const bool popupWasVisible = m_popupPanel != nullptr && m_popupPanel->isVisible();
        dismissPopup();
        clearSearchResultFilters();
        m_searchScope = searchScope;
        if (m_searchScope == UiSearchScope::CurrentTable)
        {
            m_targetTableView = resolveCurrentTable();
        }
        refreshSearchScopeDisplayText();
        if (m_searchModeActive && isCurrentQueryLongEnough(m_pendingQueryText.trimmed()))
        {
            if (popupWasVisible)
            {
                runSearchNow();
            }
            else
            {
                m_searchDebounceTimer->start();
            }
        }
        else if (popupWasVisible)
        {
            showOptionsOnlyPopup();
        }
    }

    void GlobalUiSearchController::cycleSearchScope(const int direction)
    {
        constexpr int kScopeCount = 3;
        const int currentScopeIndex = static_cast<int>(m_searchScope);
        const int normalizedDirection = direction < 0 ? -1 : 1;
        // 第四节点是独立 CMD 模式：搜索边界不再三取模回到另一端，先收起在途搜索。
        if ((normalizedDirection > 0 && m_searchScope == UiSearchScope::CurrentTable)
            || (normalizedDirection < 0 && m_searchScope == UiSearchScope::Global))
        {
            dismissPopup();
            emit requestCommandInputActivation(true);
            return;
        }
        const int nextScopeIndex =
            (currentScopeIndex + normalizedDirection + kScopeCount) % kScopeCount;
        if (static_cast<UiSearchScope>(nextScopeIndex) == UiSearchScope::CurrentTable)
        {
            // 从其他范围切回“当前表格”时，重新采用最近交互的表格。
            m_targetTableView.clear();
            m_targetTableView = resolveCurrentTable();
        }
        setSearchScope(static_cast<UiSearchScope>(nextScopeIndex));
    }

    void GlobalUiSearchController::clearSearchResultFilters()
    {
        for (const QPointer<QTableView>& tableView : m_filteredTableViewList)
        {
            if (!tableView.isNull())
            {
                ks::ui::ClearTableSearchResultFilter(tableView.data());
            }
        }
        m_filteredTableViewList.clear();
    }

    void GlobalUiSearchController::applySearchResultFilterToTable(
        QTableView* tableView)
    {
        if (!m_searchResultsOnly
            || tableView == nullptr
            || m_activeQueryText.trimmed().isEmpty()
            || !ks::ui::IsGenericTableSearchEligible(tableView))
        {
            return;
        }

        if (!ks::ui::ApplyTableSearchResultFilter(
                tableView,
                m_activeQueryText))
        {
            return;
        }

        const QPointer<QTableView> guardedTable(tableView);
        if (!m_filteredTableViewList.contains(guardedTable))
        {
            m_filteredTableViewList.push_back(guardedTable);
        }
    }

    void GlobalUiSearchController::applySearchResultFiltersToDock(
        ads::CDockWidget* dockWidget,
        const bool visiblePageOnly)
    {
        if (!m_searchResultsOnly
            || dockWidget == nullptr
            || dockWidget->widget() == nullptr)
        {
            return;
        }

        QWidget* contentWidget = dockWidget->widget();
        QList<QTableView*> tableViewList = contentWidget->findChildren<QTableView*>();
        if (QTableView* rootTableView = qobject_cast<QTableView*>(contentWidget))
        {
            tableViewList.prepend(rootTableView);
        }
        for (QTableView* tableView : tableViewList)
        {
            if (tableView == nullptr
                || (visiblePageOnly && !tableView->isVisibleTo(contentWidget)))
            {
                continue;
            }
            applySearchResultFilterToTable(tableView);
        }
    }

    ads::CDockWidget* GlobalUiSearchController::resolveCurrentPageDock() const
    {
        if (!m_recentPageDockWidget.isNull()
            && m_recentPageDockWidget->isVisible()
            && m_recentPageDockWidget->isCurrentTab())
        {
            return m_recentPageDockWidget.data();
        }
        if (!m_targetTableView.isNull())
        {
            if (ads::CDockWidget* dockWidget = dockWidgetForWidget(m_targetTableView.data()))
            {
                return dockWidget;
            }
        }
        if (QApplication::focusWidget() != nullptr)
        {
            if (ads::CDockWidget* dockWidget = dockWidgetForWidget(QApplication::focusWidget()))
            {
                return dockWidget;
            }
        }
        if (m_dockListProvider)
        {
            const QList<ads::CDockWidget*> dockList = m_dockListProvider();
            for (ads::CDockWidget* dockWidget : dockList)
            {
                if (dockWidget != nullptr && dockWidget->isVisible() && dockWidget->isCurrentTab())
                {
                    return dockWidget;
                }
            }
        }
        return nullptr;
    }

    QTableView* GlobalUiSearchController::resolveCurrentTable() const
    {
        if (!m_targetTableView.isNull())
        {
            return m_targetTableView.data();
        }
        if (!m_recentTableView.isNull())
        {
            return m_recentTableView.data();
        }
        if (QApplication::focusWidget() != nullptr)
        {
            if (QTableView* tableView = tableViewForWidget(QApplication::focusWidget()))
            {
                return tableView;
            }
        }

        ads::CDockWidget* dockWidget = resolveCurrentPageDock();
        if (dockWidget != nullptr && dockWidget->widget() != nullptr)
        {
            const QList<QTableView*> tableViewList = dockWidget->widget()->findChildren<QTableView*>();
            for (QTableView* tableView : tableViewList)
            {
                if (tableView != nullptr && tableView->isVisibleTo(dockWidget->widget()))
                {
                    return tableView;
                }
            }
        }
        return nullptr;
    }

    void GlobalUiSearchController::refreshSearchScopeDisplayText()
    {
        refreshSearchOptionControls();
        emit searchScopeDisplayTextChanged(searchScopeDisplayText());
    }

    bool GlobalUiSearchController::isQueryLongEnough(const QString& queryText)
    {
        if (queryText.isEmpty())
        {
            return false;
        }
        if (queryText.size() >= 2)
        {
            return true;
        }
        // 单字符查询只放行 CJK 等宽字符（U+2E80 起），单个 ASCII 字符噪声过大。
        return queryText.at(0).unicode() >= 0x2E80;
    }

    bool GlobalUiSearchController::isCurrentQueryLongEnough(const QString& queryText) const
    {
        if (m_searchScope == UiSearchScope::CurrentTable)
        {
            return !queryText.trimmed().isEmpty();
        }
        return isQueryLongEnough(queryText);
    }

    void ActivateGlobalUiSearchForTable(
        QTableView* tableView,
        const QString& queryText,
        const bool focusTopInput)
    {
        if (!g_activeSearchController.isNull())
        {
            g_activeSearchController->activateForTable(
                tableView,
                queryText,
                focusTopInput);
        }
    }
}
