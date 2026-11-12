#include "./DetailPresentation.h"
#include "./StructuredFieldView.h"
#include "./PrimaryPageStyle.h"
#include "./ThemeBinding.h"
#include "./ToolbarMetrics.h"
#include "./MainSurfaceStyle.h"
#include "./ComplexReportView.h"
#include "./DetailCardProjectionValues.h"
#include "./DetailFieldProjectionWidgets.h"
#include "./AsyncUiDispatcher.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QApplication>
#include <QClipboard>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPointer>
#include <QScrollArea>
#include <QScrollBar>
#include <QShowEvent>
#include <QStyle>
#include <QToolButton>
#include <QVBoxLayout>
#include <QTimer>
#include <algorithm>
#include <QFontMetrics>
#include <QThreadPool>
#include <QMap>
#include <QSet>
#include <QKeyEvent>
#include <QPainter>
#include <deque>
#include <climits>

namespace
{
    class DetailFieldProjection final : public QWidget
    {
    public:
        DetailFieldProjection(ks::ui::StructuredFieldView* source, QWidget* parent, bool scrollBody, QWidget* toolbarPrefix)
            : QWidget(parent), m_source(source), m_dispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this))
        {
            const bool embeddedSource = parent == source; // 原source本身是Tab/Stack页时保留其业务身份。
            // 唯一详情视图是分组卡片；先销毁旧格式控件与树，停止隐藏树的构建和列测量。
            source->setDocumentOnly();
            setProperty("ksword_detail_projection", true);
            setProperty("ksword_detail_projection_embedded_source", embeddedSource);
            setProperty("ksword_detail_projection_scroll", scrollBody);
            setMinimumSize(0, 0);
            setSizePolicy(QSizePolicy::Ignored, scrollBody ? QSizePolicy::Ignored : QSizePolicy::Preferred);
            auto* root = new QVBoxLayout(this);
            root->setContentsMargins(0, 0, 0, 0);
            root->setSpacing(12);
            auto* tools = new QHBoxLayout();
            root->addLayout(tools);
            if (toolbarPrefix) tools->addWidget(toolbarPrefix); // 业务刷新与文档操作共用一行，避免重复页头占正文高度。
            // 原搜索、复制和导出控件直接复用，所有既有信号和文档导出语义保留。
            m_search = source->findChild<QLineEdit*>();
            if (m_search)
            {
                tools->addWidget(m_search, 1);
                ks::ui::StyleStandaloneInput(m_search);
                connect(m_search, &QLineEdit::textChanged, this, [this]() { scheduleRefresh(); });
            }
            for (auto* button : source->findChildren<QToolButton*>(QString(), Qt::FindDirectChildrenOnly))
            {
                tools->addWidget(button);
                button->show();
            }
            ks::ui::NormalizeToolbarRow(tools);
            if (m_search)
            {
                m_search->show();
            }
            if (source->property("ksword_complex_report_source").toBool())
            {
                // 复杂报告保留原规范源和工具动作，仅正文改为模型视口，不进入展平卡片路径。
                m_complexReport = new ks::ui::ComplexReportView(this);
                tools->addWidget(m_complexReport->actionsButton());
                m_complexReport->bindSearchField(m_search);
                root->setSpacing(6);
                if (m_search) m_search->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
                ks::ui::NormalizeToolbarRow(tools);
                root->addWidget(m_complexReport, 1);
            }
            else
            {
                m_body = new ks::ui::detail_cards::Canvas(this);
                m_body->setProperty("ksword_detail_document_body", true);
                m_body->setMinimumWidth(0);
                m_body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                m_body->installEventFilter(this);
                m_loading = new QLabel(m_body);
                m_loading->setProperty("ksword_detail_loading", true);
                m_loading->setWordWrap(true);
                m_loading->setAlignment(Qt::AlignTop | Qt::AlignLeft);
                m_loading->setMargin(16);
                m_loading->hide();
                if (scrollBody)
                {
                    m_scroll = new QScrollArea(this);
                    m_scroll->setFrameShape(QFrame::NoFrame);
                    m_scroll->setWidgetResizable(true);
                    m_scroll->setMinimumSize(0, 0);
                    m_scroll->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                    m_scroll->setWidget(m_body);
                    root->addWidget(m_scroll, 1);
                }
                else
                {
                    root->addWidget(m_body);
                }
            }
            source->setProperty("ksword_detail_projection_source", true);
            if (!embeddedSource)
            {
                source->setParent(this);
                source->hide();
            }
            connect(source, &ks::ui::StructuredFieldView::documentChanged, this, [this]() { scheduleRefresh(); });
            const QPointer<DetailFieldProjection> safe(this);
            ks::ui::BindWidgetTheme(this, [safe]()
            {
                if (safe)
                {
                    safe->applyProjectionStyle();
                    safe->scheduleRefresh();
                }
            });
            scheduleRefresh();
        }
        ~DetailFieldProjection() override
        {
            m_dispatcher->close();
            if (m_cancel) m_cancel->store(true, std::memory_order_relaxed);
            discardCards();
            if (m_retirement) m_retirement->finish();
            m_snapshot.reset();
        }
    protected:
        void changeEvent(QEvent* event) override
        {
            QWidget::changeEvent(event);
            if (event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange)
                scheduleRefresh();
            if (event->type() == QEvent::LanguageChange)
            {
                // 等语言广播结束再更新卡片，避免广播遍历中同步销毁旧标题/字段控件。
                ++m_translationRevision;
                scheduleRefresh();
            }
        }
        // 首次显示和切回隐藏页时，首帧直接使用最新文档，不先画旧内容再排队重建。
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            m_dirty = true;
            refresh();
            if (m_body) materialize();
        }
    private:
        using Row = ks::ui::detail_cards::MaterializedRow; // 保留原字段控件、选区和高度缓存。
        using Card = ks::ui::detail_cards::MaterializedCard; // 外框稳定，物化范围有界。
        using Values = ks::ui::detail_cards::Projection;

        // Old cards can include many intentionally pinned selections. Detach
        // once, then destroy individual labels in fixed event-turn budgets.
        class Retirement final : public QObject
        {
        public:
            explicit Retirement(QObject* parent) : QObject(parent) {}
            void add(Card card)
            {
                if (!card.widget) return;
                card.widget->hide();
                card.widget->setParent(nullptr);
                m_cards.push_back(std::move(card));
                schedule();
            }
            void finish()
            {
                m_finished = true;
                if (m_cards.empty()) deleteLater();
            }
        private:
            void schedule()
            {
                if (m_pending) return;
                m_pending = true;
                QTimer::singleShot(0, this, [this]
                {
                    m_pending = false;
                    ks::ui::detail_cards::drainBudget(m_cards, 32,
                        [](Card& card)
                        {
                            if (card.rows.isEmpty()) return false;
                            auto row = card.rows.begin();
                            delete row->label.data();
                            delete row->value.data();
                            card.rows.erase(row);
                            return true;
                        }, [](Card& card) { delete card.widget.data(); });
                    if (!m_cards.empty()) schedule();
                    else if (m_finished) deleteLater();
                });
            }
            std::deque<Card> m_cards;
            bool m_pending = false;
            bool m_finished = false;
        };

        void retire(Card card)
        {
            if (!m_retirement) m_retirement = new Retirement(QCoreApplication::instance());
            m_retirement->add(std::move(card));
        }
        void discardCards()
        {
            m_focusSection = m_focusField = -1;
            while (!m_bindings.isEmpty())
            {
                auto it = m_bindings.begin();
                retire(std::move(it.value()));
                m_bindings.erase(it);
            }
        }
        void scheduleRefresh()
        {
            m_dirty = true;
            if (m_cancel) m_cancel->store(true, std::memory_order_relaxed);
            if (m_refreshPending || m_refreshing || !isVisible()) return;
            m_refreshPending = true;
            QTimer::singleShot(0, this, [this]
            {
                m_refreshPending = false;
                refresh();
            });
        }
        void bindViewport()
        {
            QScrollArea* scroll = m_scroll;
            if (!scroll)
                for (auto* ancestor = parentWidget(); ancestor && ancestor->window() == window(); ancestor = ancestor->parentWidget())
                    if ((scroll = qobject_cast<QScrollArea*>(ancestor))) break;
            QWidget* viewport = scroll ? scroll->viewport() : this;
            if (viewport == m_viewport) return;
            if (m_viewport) m_viewport->removeEventFilter(this);
            QObject::disconnect(m_scrollConnection);
            m_viewport = viewport;
            m_outerScroll = scroll;
            viewport->installEventFilter(this);
            if (scroll) m_scrollConnection = connect(scroll->verticalScrollBar(), &QScrollBar::valueChanged, this,
                [this] { scheduleViewport(); });
        }
        void scheduleViewport()
        {
            if (m_viewportPending || !isVisible()) return;
            m_viewportPending = true;
            QTimer::singleShot(0, this, [this]
            {
                m_viewportPending = false;
                materialize();
            });
        }
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (auto* value = qobject_cast<QLabel*>(watched); value && event->type() == QEvent::KeyPress)
            {
                auto* key = static_cast<QKeyEvent*>(event);
                if (m_refreshing) return true;
                if (key->key() == Qt::Key_Tab || key->key() == Qt::Key_Backtab)
                {
                    const bool backwards = key->key() == Qt::Key_Backtab || key->modifiers().testFlag(Qt::ShiftModifier);
                    if (focusRelative(value->property("ksword_card_section").toInt(), value->property("ksword_card_field").toInt(), backwards))
                        return true;
                }
            }
            if (watched == m_body || watched == m_viewport)
            {
                if (event->type() == QEvent::Resize)
                {
                    if (m_body && m_body->width() != m_renderWidth) scheduleRefresh();
                    scheduleViewport();
                }
                // 物化时重建表单本身就会发出LayoutRequest；不能把它作为下一次物化的输入。
                // 真正的视口变化由Resize/Move/滚动通知驱动，行高校正则显式安排补轮。
                else if (event->type() == QEvent::Show || event->type() == QEvent::Move)
                    scheduleViewport();
            }
            return QWidget::eventFilter(watched, event);
        }
        bool focusRelative(int section, int field, bool backwards)
        {
            if (!m_snapshot || section < 0 || section >= m_snapshot->sections.size()) return false;
            const auto& order = m_snapshot->sections.at(section).acceptedOrder;
            const auto found = std::lower_bound(order.cbegin(), order.cend(), field);
            if (found == order.cend() || *found != field) return false;
            int position = static_cast<int>(found - order.cbegin()) + (backwards ? -1 : 1);
            if (position < 0)
            {
                const qint64 previous = m_snapshot->sectionsHeight.prefix(section) - 1;
                if (previous < 0) return focusOutside(backwards);
                section = static_cast<int>(m_snapshot->sectionsHeight.containing(previous));
                position = static_cast<int>(m_snapshot->sections.at(section).acceptedOrder.size()) - 1;
            }
            else if (position >= order.size())
            {
                section = static_cast<int>(m_snapshot->sectionsHeight.containing(m_snapshot->sectionsHeight.prefix(section + 1)));
                if (section >= m_snapshot->sections.size()) return focusOutside(backwards);
                position = 0;
            }
            const auto& data = m_snapshot->sections.at(section);
            if (position < 0 || position >= data.acceptedOrder.size()) return false;
            field = data.acceptedOrder.at(position);
            const int column = data.fields.at(field).column;
            const auto columnRow = std::lower_bound(data.accepted[column].cbegin(), data.accepted[column].cend(), field) - data.accepted[column].cbegin();
            const auto& geometry = m_snapshot->geometry.at(section);
            const qint64 y = m_snapshot->sectionsHeight.prefix(section) + geometry.columnStart(column) + geometry.columns[column].prefix(columnRow);
            m_focusSection = section; m_focusField = field;
            if (m_outerScroll && m_viewport)
            {
                const int height = m_body->minimumHeight(), viewport = m_viewport->height();
                const int current = -m_body->mapTo(m_viewport, QPoint()).y();
                const qint64 total = qMax<qint64>(0, m_snapshot->sectionsHeight.total() - 14); // 间隔只在两卡之间。
                const qint64 currentTop = ks::ui::detail_cards::logicalTop(current, height, viewport, total);
                const qint64 extent = qMin<qint64>(geometry.columns[column].at(columnRow) - 6, qMax(1, viewport - 100));
                qint64 wantedTop = currentTop;
                if (y < currentTop) wantedTop = y - 50;
                else if (y + extent > currentTop + viewport) wantedTop = y + extent - viewport + 50;
                if (wantedTop != currentTop)
                {
                    wantedTop = qBound<qint64>(0, wantedTop, qMax<qint64>(0, total - viewport));
                    const int wanted = ks::ui::detail_cards::physicalTop(wantedTop, height, viewport, total);
                    auto* bar = m_outerScroll->verticalScrollBar();
                    bar->setValue(bar->value() + wanted - current);
                }
            }
            scheduleViewport();
            return true;
        }
        bool focusOutside(bool backwards)
        {
            QWidget* current = QApplication::focusWidget();
            if (!current) return false;
            for (QWidget* candidate = backwards ? current->previousInFocusChain() : current->nextInFocusChain();
                candidate && candidate != current; candidate = backwards ? candidate->previousInFocusChain() : candidate->nextInFocusChain())
            {
                if (candidate == m_body || (m_body && m_body->isAncestorOf(candidate))) continue;
                if (candidate->window() != window() || !candidate->isVisible() || !candidate->isEnabled()
                    || !(candidate->focusPolicy() & Qt::TabFocus)) continue;
                candidate->setFocus(backwards ? Qt::BacktabFocusReason : Qt::TabFocusReason);
                return true;
            }
            return false;
        }
        void refresh()
        {
            if (!m_source || !m_dirty || !isVisible() || m_refreshing) return;
            bindViewport();
            const quint64 revision = m_source->documentRevision();
            const auto translator = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
            const QString language = translator.languageId();
            const QString theme = projectionCanvasColor().name() + KswordTheme::SurfaceColorHex()
                + KswordTheme::TextPrimaryColorHex() + KswordTheme::TextSecondaryColorHex()
                + KswordTheme::SuccessColor().name(QColor::HexArgb) + KswordTheme::ErrorColor().name(QColor::HexArgb);
            const QString query = m_search ? m_search->text().trimmed() : QString();
            const int width = m_body ? m_body->width() : 0;
            const bool canonicalChanged = !m_snapshotReady || revision != m_documentRevision || language != m_language
                || m_translationRevision != m_renderedTranslationRevision;
            const bool dataChanged = canonicalChanged || query != m_query || width != m_renderWidth || font() != m_renderFont;
            const bool themeChanged = theme != m_theme;
            m_dirty = false;
            if (themeChanged) { applyProjectionStyle(); m_theme = theme; }
            if (m_complexReport)
            {
                if (canonicalChanged) m_complexReport->setDocument(m_source->document());
                if (themeChanged) m_complexReport->refreshTheme();
                if (query != m_query) m_complexReport->setSearchText(query);
                m_documentRevision = revision; m_language = language; m_query = query;
                m_renderedTranslationRevision = m_translationRevision; m_snapshotReady = true;
                return;
            }
            if (!dataChanged) { scheduleViewport(); return; }
            if (m_refreshing) { m_dirty = true; return; }
            m_refreshing = true;
            m_loading->setText(ks::i18n::text(QStringLiteral("shared.fields.loading"), QStringLiteral("正在准备字段...")));
            if (!m_snapshotReady)
            {
                m_loading->show();
                positionLoading();
            }
            const auto document = m_source->document();
            const QFont renderFont = font();
            const quint64 translationRevision = m_translationRevision;
            const auto previous = std::shared_ptr<const Values>(m_snapshot);
            const auto canceled = std::make_shared<std::atomic_bool>(false);
            m_cancel = canceled;
            const auto gate = m_dispatcher;
            QThreadPool::globalInstance()->start([this, gate, document, translator, previous, canceled, revision,
                translationRevision, language, query, width, renderFont]
            {
                // QFontMetrics is a value; all full-document traversal and
                // translation uses captured values, never a widget or singleton.
                const QFontMetrics metrics(renderFont);
                QFont headingFont = renderFont; // 标题与生产卡片相同的半粗字体，预先计算跨行标题。
                headingFont.setWeight(QFont::DemiBold);
                const QFontMetrics headingMetrics(headingFont); // 标题测量不复用正文常规字重。
                const int lineHeight = metrics.height();
                auto values = ks::ui::detail_cards::prepare(document,
                    [translator](const QString& text) { return translator.sourceText(text); }, query,
                    width - 32 >= 616, lineHeight,
                    [headingMetrics, width, lineHeight](const ks::ui::detail_cards::Field& field, bool)
                    {
                        // 此轮先建立规范字段树；正文在名称列宽确定后统一测量，标题使用全宽。
                        return field.note ? headingMetrics.boundingRect(QRect(0, 0, qMax(1, width - 32),
                            INT_MAX / 8), Qt::TextWordWrap, field.value).height() + 1 : lineHeight;
                     }, previous, canceled);
                // 名称列宽按整段字段一次确定，不让当前可见的短/长名称改变其它行宽度。
                // 仍使用原生表单和响应式分栏；只给名称列保留稳定的自然宽度上限。
                if (values)
                {
                    for (int section = 0; section < values->sections.size() && !canceled->load(std::memory_order_relaxed); ++section)
                    {
                        auto& geometry = values->geometry[section]; // 本轮宽度对应的纯值几何。
                        const auto& data = values->sections.at(section); // 当前过滤后的规范字段集合。
                        const int contentWidth = qMax(1, width - 32); // 卡片扣除左右16px后的整段宽度。
                        const auto columnWidth = [&](int column) // 原生等分列把奇数余量分给第一列，附注始终全宽。
                        {
                            return !geometry.twoColumns || column == 2 ? contentWidth
                                : qMax(1, (contentWidth - 16 + (column == 0 ? 1 : 0)) / 2);
                        };
                        for (int column = 0; column < 2; ++column)
                        {
                            int naturalWidth = 0; // 当前完整字段列的名称自然宽度。
                            for (const int index : data.accepted[column])
                            {
                                if (canceled->load(std::memory_order_relaxed)) break;
                                naturalWidth = qMax(naturalWidth, metrics.horizontalAdvance(data.fields.at(index).name));
                            }
                            geometry.labelWidths[column] = qMin(naturalWidth, qMax(20, (columnWidth(column) - 16) / 2));
                        }
                        // 同一宽度下整段行高一次算准，滚动只裁出窗口，不再校正未见行导致总高漂移。
                        for (int column = 0; column < 3; ++column)
                        {
                            const int nameWidth = geometry.labelWidths[column]; // 此列稳定名称宽度，附注列为零。
                            const int valueWidth = column == 2 ? contentWidth : qMax(1, columnWidth(column) - nameWidth - 16);
                            for (int position = 0; position < data.accepted[column].size(); ++position)
                            {
                                if (canceled->load(std::memory_order_relaxed)) break;
                                const auto& field = data.fields.at(data.accepted[column].at(position)); // 当前规范行。
                                const int nameHeight = field.note ? 0 : qMax(lineHeight, metrics.boundingRect(
                                    QRect(0, 0, qMax(1, nameWidth), INT_MAX / 8),
                                    Qt::TextWordWrap | Qt::TextWrapAnywhere, field.name).height());
                                const int valueHeight = qMax(lineHeight, metrics.boundingRect(
                                    QRect(0, 0, valueWidth, INT_MAX / 8), Qt::TextWordWrap, field.value).height() + 1);
                                geometry.columns[column].set(position, qMax(nameHeight, valueHeight) + 6);
                            }
                        }
                        const bool visible = !data.acceptedOrder.isEmpty(); // 搜索空结果仍不占用虚拟正文高度。
                        values->sectionsHeight.set(section, visible ? geometry.height() + 14 : 0);
                    }
                }
                // Every final release, including a dropped queued callback, is
                // dispatched to a worker. The GUI never frees a large value tree.
                auto published = ks::ui::detail_cards::workerOwned(std::move(values), [](std::function<void()> action)
                    { QThreadPool::globalInstance()->start(std::move(action)); });
                gate->post([this, published = std::move(published), canceled, revision, translationRevision,
                    language, query, width, renderFont]() mutable
                {
                    m_refreshing = false;
                    if (!published || canceled->load(std::memory_order_relaxed) || !m_source
                        || revision != m_source->documentRevision() || translationRevision != m_translationRevision
                        || language != ks::i18n::LanguageManager::instance().currentLanguageId()
                        || query != (m_search ? m_search->text().trimmed() : QString()) || width != m_body->width() || renderFont != font())
                    { m_dirty = true; scheduleRefresh(); return; }
                    if (!published->sameStructure) discardCards();
                    m_snapshot = std::move(published);
                    ++m_snapshotRevision;
                    m_documentRevision = revision; m_language = language; m_query = query;
                    m_renderWidth = width; m_renderFont = renderFont;
                    m_renderedTranslationRevision = translationRevision; m_snapshotReady = true;
                    m_body->show();
                    materialize();
                    if (m_dirty) scheduleRefresh();
                });
            });
        }
        Card createCard(int section)
        {
            Card card;
            const auto& value = m_snapshot->sections.at(section);
            card.widget = ks::ui::CreateDetailCard(value.title, m_body);
            // 虚拟卡片只承载当前窗口的自然行高，余量留在底部，避免每次裁窗均分到顶部。
            card.widget->layout()->setAlignment(Qt::AlignTop);
            card.heading = card.widget->findChild<QLabel*>(QString(), Qt::FindDirectChildrenOnly);
            if (value.fieldCount >= 8)
                ks::ui::AddDetailFieldColumns(card.widget, card.forms[0], card.forms[1]);
            else if (value.fieldCount > 0)
            {
                card.firstPane = new QWidget(card.widget);
                card.forms[0] = new QFormLayout(card.firstPane);
                ks::ui::ConfigureDetailForm(card.forms[0]);
                static_cast<QVBoxLayout*>(card.widget->layout())->addWidget(card.firstPane);
            }
            if (!card.firstPane && card.forms[0]) card.firstPane = card.forms[0]->parentWidget();
            if (card.forms[1]) card.secondPane = card.forms[1]->parentWidget();
            if (value.fieldCount > 0)
            {
                card.columnsHost = card.widget->layout()->itemAt(1)->widget();
                card.columnsInLayout = true;
            }
            card.notesPane = new QWidget(card.widget);
            card.forms[2] = new QFormLayout(card.notesPane);
            ks::ui::ConfigureDetailForm(card.forms[2]);
            static_cast<QVBoxLayout*>(card.widget->layout())->addWidget(card.notesPane);
            card.widget->show();
            return card;
        }
        Row createRow(Card& card, int index)
        {
            const auto& field = m_snapshot->sections.at(m_buildSection).fields.at(index);
            Row row;
            // 标签直接归最终表单面板；addRow不再把新标签从卡片重挂而触发整支样式失效。
            QWidget* pane = field.column == 0 ? card.firstPane.data()
                : field.column == 1 ? card.secondPane.data() : card.notesPane.data(); // 此字段的最终父控件。
            auto* value = new QLabel(pane ? pane : card.widget.data());
            row.value = value;
            value->setTextFormat(Qt::PlainText); value->setWordWrap(true); value->setMinimumWidth(0);
            value->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            value->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
            value->setProperty("ksword_card_focus_policy", static_cast<int>(value->focusPolicy()));
            value->setProperty("ks_i18n_preserve_data_text", true);
            value->setProperty("ksword_detail_field_value", true);
            value->setContextMenuPolicy(Qt::CustomContextMenu);
            value->setProperty("ksword_card_section", m_buildSection);
            value->setProperty("ksword_card_field", index);
            value->installEventFilter(this);
            connect(value, &QWidget::customContextMenuRequested, value, [value](const QPoint& point)
            {
                const QString snapshot = value->text();
                QMenu menu; menu.setStyleSheet(KswordTheme::ContextMenuStyle());
                auto* copy = menu.addAction(ks::i18n::sourceText(QStringLiteral("复制")));
                if (menu.exec(value->mapToGlobal(point)) == copy && QApplication::clipboard()) QApplication::clipboard()->setText(snapshot);
            });
            if (!field.note)
            {
                row.label = new ks::ui::detail_cards::NameLabel(field.name, pane ? pane : card.widget.data());
                row.label->setProperty("ksword_detail_field_label", true);
                row.label->setWordWrap(true); row.label->setMinimumWidth(0);
            }
            return row;
        }
        void positionLoading()
        {
            if (!m_viewport || !m_body || !m_loading->isVisible()) return;
            const int y = qMax(0, -m_body->mapTo(m_viewport, QPoint()).y());
            m_loading->setGeometry(0, y, m_body->width(), qMax(m_viewport->height(), fontMetrics().height() * 3));
            m_loading->raise();
        }
        void materialize()
        {
            if (isVisible() && m_body) bindViewport();
            positionLoading();
            if (!isVisible() || !m_snapshot || m_refreshing || m_materializing || !m_viewport || !m_body) return;
            m_materializing = true;
            const int viewportHeight = qMax(1, m_viewport->height());
            const qint64 total = qMax<qint64>(0, m_snapshot->sectionsHeight.total() - 14); // 不在末卡外再加一行留白。
            const int physicalHeight = static_cast<int>(qMin<qint64>(QWIDGETSIZE_MAX - 1024, qMax<qint64>(1, total)));
            if (m_body->minimumHeight() != physicalHeight) m_body->setMinimumHeight(physicalHeight);
            const int physical = -m_body->mapTo(m_viewport, QPoint()).y();
            const qint64 top = ks::ui::detail_cards::logicalTop(physical, physicalHeight, viewportHeight, total);
            const qint64 firstPixel = qMax<qint64>(0, top - 160), lastPixel = top + viewportHeight + 160;
            const qsizetype first = m_snapshot->sectionsHeight.containing(firstPixel);
            const qsizetype last = m_snapshot->sectionsHeight.containing(lastPixel);
            int budget = 32;
            bool unfinished = false;
            for (auto it = m_bindings.begin(); it != m_bindings.end();)
            {
                if (it.key() < first || it.key() > last || !m_snapshot->sectionsHeight.at(it.key()))
                {
                    bool pinned = false;
                    for (const auto& row : it->rows) pinned |= row.pinned();
                    if (!pinned) { retire(std::move(it.value())); it = m_bindings.erase(it); continue; }
                    it->widget->setGeometry(-QWIDGETSIZE_MAX / 2, 0, 1, 1);
                }
                ++it;
            }
            for (int section = static_cast<int>(first); section <= last && section < m_snapshot->sections.size();
                section = static_cast<int>(m_snapshot->sectionsHeight.containing(m_snapshot->sectionsHeight.prefix(section + 1))))
            {
                if (!m_snapshot->sectionsHeight.at(section)) continue;
                if (!m_bindings.contains(section))
                {
                    if (budget <= 0) { unfinished = true; break; }
                    --budget; m_bindings.insert(section, createCard(section));
                }
                auto& card = m_bindings[section];
                const auto& data = m_snapshot->sections.at(section);
                auto& geometry = m_snapshot->geometry[section];
                const qint64 sectionTop = m_snapshot->sectionsHeight.prefix(section);
                // 在已有窗口的安全余量内滚动只搬移像素；越过边缘后才补充有界字段集合。
                const qint64 visibleFirst = qMax<qint64>(0, top - sectionTop - 80); // 视口上方必须保留的文字范围。
                const qint64 visibleLast = qMin(geometry.height(), top + viewportHeight - sectionTop + 80); // 视口下方安全范围。
                const bool reuseWindow = card.layoutRevision == m_snapshotRevision
                    && card.windowFirst <= visibleFirst && card.windowLast >= visibleLast;
                const qint64 requestedFirst = reuseWindow ? card.windowFirst : qMax<qint64>(0, top - sectionTop - 320);
                qint64 clipFirst = requestedFirst;
                const qint64 requestedLast = reuseWindow ? card.windowLast
                    : qMin(geometry.height(), top + viewportHeight - sectionTop + 320);
                card.windowFirst = requestedFirst;
                card.windowLast = requestedLast;
                qint64 clipLast = requestedLast;
                if (clipFirst < geometry.header) clipFirst = 0;
                for (int column = 0; column < 3; ++column)
                {
                    const auto& heights = geometry.columns[column];
                    const qint64 start = geometry.columnStart(column);
                    const auto window = ks::ui::detail_cards::rowWindow(heights, start, requestedFirst, requestedLast);
                    if (window.begin < window.end)
                    {
                        clipFirst = qMin(clipFirst, start + heights.prefix(window.begin));
                        // QFormLayout must receive the whole last realized row;
                        // clipping its host inside a long field compresses the text.
                        clipLast = qMax(clipLast, start + heights.prefix(window.end) - 6);
                    }
                }
                // 普通卡片保持完整外框，滚动不再缩放/移动实底；仅字段继续按可见范围物化。
                // 超出Qt控件尺寸上限的逻辑卡片保留裁窗回退，避免破坏超大文档坐标映射。
                const bool stableFrame = geometry.height() < QWIDGETSIZE_MAX - 1024;
                if (stableFrame)
                {
                    clipFirst = 0;
                    clipLast = geometry.height();
                }
                const qint64 contentTop = qMax(geometry.header, clipFirst);
                QSet<int> wanted;
                std::array<QVector<int>, 3> selected;
                for (int column = 0; column < 3; ++column)
                {
                    const auto& heights = geometry.columns[column];
                    const qint64 start = geometry.columnStart(column);
                    const auto window = ks::ui::detail_cards::rowWindow(heights, start, requestedFirst, requestedLast);
                    for (qsizetype row = window.begin; row < window.end; ++row)
                    {
                        const int index = data.accepted[column].at(row);
                        wanted.insert(index); selected[column].append(static_cast<int>(row));
                        if (!card.rows.contains(index))
                        {
                            if (budget <= 0) { unfinished = true; continue; }
                            --budget; m_buildSection = section; card.rows.insert(index, createRow(card, index));
                        }
                    }
                }
                for (auto it = card.rows.begin(); it != card.rows.end();)
                {
                    const bool accepted = std::binary_search(data.acceptedOrder.cbegin(), data.acceptedOrder.cend(), it.key());
                    if (it->value)
                    {
                        const Qt::FocusPolicy policy = accepted ? static_cast<Qt::FocusPolicy>(it->value->property("ksword_card_focus_policy").toInt()) : Qt::NoFocus;
                        if (it->value->focusPolicy() != policy) it->value->setFocusPolicy(policy);
                    }
                    if (!wanted.contains(it.key()))
                    {
                        if (it->label) it->label->setGeometry(-10000, 0, 1, 1);
                        if (it->value) it->value->setGeometry(-10000, 0, 1, 1);
                    }
                    if (!wanted.contains(it.key()) && !it->pinned())
                    {
                        if (budget <= 0) { unfinished = true; ++it; continue; }
                        --budget;
                        auto* form = card.forms[data.fields.at(it.key()).column]; // 删除控件前移除整行，避免留下空布局项。
                        if (form && form->indexOf(it->value) >= 0)
                        {
                            const auto removed = form->takeRow(it->value);
                            delete removed.labelItem;
                            delete removed.fieldItem;
                        }
                        delete it->label.data();
                        delete it->value.data();
                        it = card.rows.erase(it);
                        continue;
                    }
                    ++it;
                }
                // Rebuild only a bounded visible form, keeping the QLabel
                // objects (and unchanged text selection/focus) in place.
                for (int column = 0; column < 3; ++column)
                {
                    auto* form = card.forms[column];
                    if (!form) continue;
                    QWidget* pane = column == 0 ? card.firstPane.data() : column == 1 ? card.secondPane.data() : card.notesPane.data();
                    const auto& heights = geometry.columns[column];
                    const qint64 start = geometry.columnStart(column);
                    const qint64 regionFirst = qMax(contentTop, start);
                    const qint64 regionLast = qMin(clipLast, start + geometry.columnHeight(column));
                    QVector<int> formRows; // 仅比较有界可见集合，未完成的占位转为控件时也必须补建。
                    for (const int position : selected[column])
                    {
                        const int index = data.accepted[column].at(position);
                        formRows.append(card.rows.contains(index) ? index : -index - 1);
                    }
                    if (card.layoutRevision == m_snapshotRevision && card.formRows[column] == formRows
                        && card.formFirst[column] == regionFirst && card.formLast[column] == regionLast)
                    {
                        continue; // 单纯滚动保留现有表单，不再先取空布局项再重新挂入同一批标签。
                    }
                    const bool complete = std::all_of(formRows.cbegin(), formRows.cend(),
                        [](int index) { return index >= 0; }); // 存在预算占位时仍按原顺序完整构造该有界表单。
                    card.formRows[column] = std::move(formRows);
                    card.formFirst[column] = regionFirst;
                    card.formLast[column] = regionLast;
                    // 无预算占位时只增删窗口边缘，已有可见行不经过“整列拆空”路径。
                    const bool retained = complete && ks::ui::detail_cards::retainFormRows(form, wanted);
                    while (!retained && form->rowCount())
                    {
                        const auto row = form->takeRow(0); // 仅真实窗口集合变化时替换布局项，标签身份仍保留。
                        delete row.labelItem;
                        delete row.fieldItem;
                    }
                    bool pinned = false;
                    for (auto row = card.rows.cbegin(); row != card.rows.cend(); ++row)
                        pinned |= data.fields.at(row.key()).column == column && row->pinned();
                    const bool show = (regionLast > regionFirst && !data.accepted[column].isEmpty()) || pinned;
                    if (pane) pane->setVisible(show);
                    if (!show) continue;
                    // 首尾虚拟空白用表单边距表达；零高占位行仍会触发6px原生行距，
                    // 将1–5px空白放大，造成滚动中整列反复偏移。
                    const qint64 firstRow = selected[column].isEmpty() ? regionLast
                        : start + heights.prefix(selected[column].first()); // 此窗口首行的规范正文坐标。
                    const int topMargin = static_cast<int>(qMax<qint64>(0, firstRow - regionFirst)); // 精确前缀空白。
                    form->setContentsMargins(0, topMargin, 0, 0);
                    qint64 cursor = regionFirst + topMargin; // 已由边距消费前缀，不额外插入空行。
                    int formPosition = 0; // 本轮规范行在有界表单中的目标顺序。
                    for (const int position : selected[column])
                    {
                        const int index = data.accepted[column].at(position);
                        const qint64 rowY = start + heights.prefix(position);
                        if (rowY > cursor) form->setItem(form->rowCount(), QFormLayout::SpanningRole,
                            new QSpacerItem(0, static_cast<int>(qMax<qint64>(0, rowY - cursor - 6)), QSizePolicy::Minimum, QSizePolicy::Fixed));
                        const auto row = card.rows.find(index);
                        if (row != card.rows.end())
                        {
                            const auto& field = data.fields.at(index);
                            if (row->value->text() != field.value)
                            {
                                row->value->setText(field.value);
                                row->value->setToolTip(field.value);
                                row->measuredWidth = -1;
                            }
                            if (row->value->property("ksword_detail_field_semantic").toString() != field.semantic)
                            {
                                row->value->setProperty("ksword_detail_field_semantic", field.semantic);
                                row->value->style()->unpolish(row->value); row->value->style()->polish(row->value);
                            }
                            if (row->label)
                            {
                                const int labelWidth = geometry.labelWidths[column]; // 整段共享名称列宽，滚动窗口变化不改列宽。
                                if (row->label->minimumWidth() != labelWidth || row->label->maximumWidth() != labelWidth)
                                {
                                    row->label->setFixedWidth(labelWidth);
                                }
                                if (!retained || form->indexOf(row->value) < 0)
                                {
                                    form->insertRow(formPosition, row->label, row->value);
                                }
                                row->label->show();
                            }
                            else if (!retained || form->indexOf(row->value) < 0)
                            {
                                form->insertRow(formPosition, row->value);
                            }
                            row->value->show();
                        }
                        else form->setItem(form->rowCount(), QFormLayout::SpanningRole,
                            new QSpacerItem(0, static_cast<int>(heights.at(position) - 6), QSizePolicy::Minimum, QSizePolicy::Fixed));
                        cursor = qMax(cursor, rowY + heights.at(position));
                        ++formPosition;
                    }
                    const int bottomMargin = selected[column].isEmpty() ? 0
                        : static_cast<int>(qMax<qint64>(0, regionLast - cursor + 6)); // 空列只用顶部边距占位，不增加虚构行距。
                    form->setContentsMargins(0, topMargin, 0, bottomMargin);
                }
                auto* layout = static_cast<QVBoxLayout*>(card.widget->layout());
                const auto placePane = [&](QWidget* pane, bool present, bool pinned, bool& inLayout, int position)
                {
                    if (!pane) return;
                    if (present)
                    {
                        if (!inLayout) { layout->insertWidget(position, pane); inLayout = true; }
                        pane->show();
                    }
                    else if (pinned)
                    {
                        if (inLayout) { layout->removeWidget(pane); inLayout = false; }
                        pane->setGeometry(-10000, 0, qMax(1, pane->width()), qMax(1, pane->height()));
                        pane->show();
                    }
                    else pane->hide();
                };
                bool pinnedColumns = false, pinnedNotes = false;
                for (auto row = card.rows.cbegin(); row != card.rows.cend(); ++row)
                    if (row->pinned())
                    {
                        if (data.fields.at(row.key()).column == 2) pinnedNotes = true;
                        else pinnedColumns = true;
                    }
                placePane(card.columnsHost, stableFrame ? !data.accepted[0].isEmpty() || !data.accepted[1].isEmpty()
                    : !selected[0].isEmpty() || !selected[1].isEmpty(), pinnedColumns, card.columnsInLayout, 1);
                placePane(card.notesPane, stableFrame ? !data.accepted[2].isEmpty()
                    : !selected[2].isEmpty(), pinnedNotes, card.notesInLayout, layout->count());
                const bool headingVisible = clipFirst < geometry.header && !data.title.isEmpty();
                if (card.heading) card.heading->setVisible(headingVisible);
                layout->setContentsMargins(16, clipFirst == 0 ? 14 : 0, 16, clipLast == geometry.height() ? 14 : 0);
                card.widget->setGeometry(0, physical + static_cast<int>(sectionTop + clipFirst - top),
                    m_body->width(), static_cast<int>(qMax<qint64>(1, clipLast - clipFirst)));
                layout->activate();
                // 外卡片激活不保证嵌套表单已消费本轮宽度；先逐层完成列布局再读取字段矩形。
                // 否则旧列宽参与高度回写，在临界宽度处会不断放大/缩小虚拟卡片。
                if (card.columnsHost && card.columnsHost->layout())
                {
                    card.columnsHost->layout()->activate();
                }
                for (int column = 0; column < 3; ++column)
                {
                    auto* form = card.forms[column]; // 当前物化列的原生表单。
                    if (!form || !form->parentWidget()->isVisible())
                    {
                        continue;
                    }
                    if (auto* parentLayout = form->parentWidget()->parentWidget()->layout()) // 表单上层列宿主先分配本轮宽度。
                    {
                        parentLayout->activate();
                    }
                    form->activate();
                }
                // Native WrapLongRows decides whether label and value share a
                // row. Correct only realized row heights, in O(log N), so a
                // conservative estimate cannot hide the tail of a long field.
                bool corrected = false;
                if (headingVisible && card.heading)
                {
                    const int headingHeight = qMax(card.heading->fontMetrics().height(), card.heading->heightForWidth(qMax(1, card.heading->width())));
                    const qint64 header = 14 + headingHeight + 10;
                    if (header != geometry.header) { geometry.header = header; corrected = true; }
                }
                for (int column = 0; column < 3; ++column)
                    for (const int position : selected[column])
                    {
                        const auto row = card.rows.find(data.accepted[column].at(position)); // 此行文字自然高度缓存。
                        if (row == card.rows.end() || !row->value) continue;
                        const int valueWidth = qMax(1, row->value->width()); // 已激活原生列布局的当前宽度。
                        if (row->measuredWidth != valueWidth || row->measuredFont != row->value->font())
                        {
                            // QLabel::heightForWidth会钳制到现有固定高度；仅缓存失效时解除旧约束，
                            // 测出自然高度后立即重新固定，不让旧窄窗的高度污染新宽度及行高前缀树。
                            row->value->setMinimumHeight(0);
                            row->value->setMaximumHeight(QWIDGETSIZE_MAX);
                            row->naturalHeight = qMax(row->value->fontMetrics().height(), row->value->heightForWidth(valueWidth));
                            row->measuredWidth = valueWidth;
                            row->measuredFont = row->value->font();
                        }
                        const int valueHeight = row->naturalHeight; // 同一文字/字体/宽度在滚动中保持不变。
                        // QFormLayout可能压缩字段，且名称标签不保证按heightForWidth分配高度。
                        // 用本轮真实宽度提供最小文字高度，让原生布局保留完整名称和raw预览。
                        if (row->value->minimumHeight() != valueHeight || row->value->maximumHeight() != valueHeight)
                        {
                            row->value->setFixedHeight(valueHeight);
                            // 即使前缀树高度已正确，最小高度变化仍需补轮让表单消费新约束。
                            corrected = true;
                        }
                        int height = valueHeight;
                        if (row->label)
                        {
                            const int labelHeight = qMax(row->label->fontMetrics().height(), row->label->heightForWidth(qMax(1, row->label->width())));
                            if (row->label->minimumHeight() != labelHeight || row->label->maximumHeight() != labelHeight)
                            {
                                row->label->setFixedHeight(labelHeight);
                                corrected = true;
                            }
                            height = row->label->y() + row->label->height() <= row->value->y()
                                ? labelHeight + valueHeight + 6 : qMax(labelHeight, valueHeight);
                        }
                        corrected |= geometry.columns[column].set(position, height + 6);
                    }
                if (corrected)
                {
                    m_snapshot->sectionsHeight.set(section, geometry.height() + 14);
                    unfinished = true;
                }
                card.layoutRevision = corrected ? 0 : m_snapshotRevision;
                ks::ui::PrepareWidgetThemeBindingsForShow(card.widget);
                if (section == m_focusSection && card.rows.contains(m_focusField))
                {
                    card.rows[m_focusField].value->setFocus(Qt::TabFocusReason);
                    m_focusSection = m_focusField = -1;
                }
            }
            m_materializing = false;
            if (unfinished)
            {
                scheduleViewport();
            }
            else m_loading->hide();
        }

        // 输入是当前宿主链，返回实际画布颜色；独立详情不能穿过顶层窗口继承 owner 的参数表面。
        QColor projectionCanvasColor() const
        {
            QWidget* topLevel = window(); // Qt 的窗口父对象仍可指向另一窗口中的业务控件。
            for (QWidget* ancestor = parentWidget(); ancestor; ancestor = ancestor->parentWidget())
            {
                if (ancestor->property("ksword_parameter_surface").toBool())
                {
                    return ks::ui::MainWindowSurfaceColors().content;
                }
                if (ancestor == topLevel)
                {
                    break;
                }
            }
            return KswordTheme::WindowColor();
        }

        // 集中生成投影自己的精确主题块；状态色仍按卡片实底校准，不覆盖外部额外业务规则。
        void applyProjectionStyle()
        {
            const auto readableColor = [](const QColor& color)
            {
                return KswordTheme::EnsureTextContrast(color, KswordTheme::SurfaceColor(), 4.5).name();
            };
            const QString begin = QStringLiteral("/* KSWORD_DETAIL_PROJECTION_BEGIN */");
            const QString end = QStringLiteral("/* KSWORD_DETAIL_PROJECTION_END */");
            const QString block = begin + QStringLiteral(
                "QWidget[ksword_detail_projection=\"true\"]{background:%1;border:0;}"
                "QScrollArea,QScrollArea > QWidget{background:%1;border:0;}"
                "QLabel[ksword_detail_loading=\"true\"]{background:%1;color:%2;border:0;}"
                "QLabel[ksword_detail_field_label=\"true\"]{background:transparent;color:%2;}"
                "QLabel[ksword_detail_field_value=\"true\"]{background:transparent;color:%3;}"
                "QLabel[ksword_detail_field_value=\"true\"][ksword_detail_field_semantic=\"success\"]{color:%4;}"
                "QLabel[ksword_detail_field_value=\"true\"][ksword_detail_field_semantic=\"error\"]{color:%5;}")
                .arg(projectionCanvasColor().name(), KswordTheme::TextSecondaryHex(),
                    readableColor(KswordTheme::TextPrimaryColor()), readableColor(KswordTheme::SuccessColor()),
                    readableColor(KswordTheme::ErrorColor())) + end;
            QString style = styleSheet(); // 保留其它拥有者定点添加的样式，只替换框架拥有的块。
            const qsizetype first = style.indexOf(begin);
            const qsizetype last = first < 0 ? -1 : style.indexOf(end, first);
            if (first >= 0 && last >= first)
            {
                style.remove(first, last + end.size() - first);
            }
            style = style.trimmed();
            if (!style.isEmpty())
            {
                style += QLatin1Char('\n');
            }
            style += block;
            if (styleSheet() != style)
            {
                setStyleSheet(style);
            }
            if (m_body)
            {
                // QSS不再接管正文填底；opaque标记与自身paint实际使用的颜色同步。
                static_cast<ks::ui::detail_cards::Canvas*>(m_body)->setCanvasColor(projectionCanvasColor());
            }
        }
        QPointer<ks::ui::StructuredFieldView> m_source; // 保留规范数据源及原导出入口。
        ks::ui::ComplexReportView* m_complexReport = nullptr; // 显式复杂报告正文，普通详情保持原卡片。
        QPointer<QLineEdit> m_search; // 原搜索控件，不维护平行查询字符串。
        QWidget* m_body = nullptr;
        QLabel* m_loading = nullptr;
        QScrollArea* m_scroll = nullptr; // 嵌入已有正文滚动时为空。
        QMap<int, Card> m_bindings;
        QPointer<Retirement> m_retirement;
        QPointer<QWidget> m_viewport;
        QPointer<QScrollArea> m_outerScroll;
        QMetaObject::Connection m_scrollConnection;
        std::shared_ptr<Values> m_snapshot;
        std::shared_ptr<std::atomic_bool> m_cancel;
        std::shared_ptr<ks::ui::AsyncUiDispatcher> m_dispatcher;
        QFont m_renderFont;
        int m_renderWidth = -1;
        int m_buildSection = 0;
        int m_focusSection = -1, m_focusField = -1;
        bool m_viewportPending = false;
        bool m_materializing = false;
        quint64 m_documentRevision = 0; // 最后一帧使用的规范文档代次。
        quint64 m_snapshotRevision = 0; // 每次接纳新投影使现有表单消费新文字、字体和几何。
        quint64 m_translationRevision = 0; // LanguageChange只在统一调度器中递增。
        quint64 m_renderedTranslationRevision = 0; // 已展示的翻译代次，兜底主题回调不重复翻译。
        QString m_language; // 相同语言的重复广播不重建字段文本。
        QString m_theme; // 精确记录卡片使用的主题颜色，纯主题更新不展开文档。
        QString m_query; // 相同搜索和数据无需再次遍历可见性。
        bool m_snapshotReady = false; // 初次空文档也需要建立画布与过滤状态。
        bool m_dirty = true; // 隐藏页面保留待更新状态，Show首帧同步处理。
        bool m_refreshPending = false; // 合并同一事件轮内的文档/语言/主题通知。
        bool m_refreshing = false; // 创建字段与套样式期间禁止重入。
    };
}

QWidget* ks::ui::CreateDetailFieldProjection(StructuredFieldView* source, QWidget* parent, bool scrollBody, QWidget* toolbarPrefix)
{
    if (!source)
    {
        return nullptr;
    }
    if (source->property("ksword_detail_projection_source").toBool() && source->parentWidget()
        && source->parentWidget()->property("ksword_detail_projection").toBool())
    {
        return source->parentWidget(); // 重复接入复用同一宿主，保留原搜索和完整文档导出控件。
    }
    // canonical source仍作为业务Tab页时，投影是其直接子项，不通过换父对象查找宿主。
    for (QWidget* child : source->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly))
    {
        if (child->property("ksword_detail_projection").toBool()
            && child->property("ksword_detail_projection_embedded_source").toBool())
        {
            return child;
        }
    }
    return new DetailFieldProjection(source, parent ? parent : source->parentWidget(), scrollBody, toolbarPrefix);
}
