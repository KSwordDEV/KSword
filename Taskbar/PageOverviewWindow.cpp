#include "PageOverviewWindow.h"
#include "PageOverviewBackdrop.h"
#include "../shared/usermode/KswordPageNavigation.h"
#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QFrame>
#include <QFocusEvent>
#include <QHBoxLayout>
#include <QHideEvent>
#include <QHash>
#include <QSet>
#include <QScrollBar>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QScreen>
#include <QSettings>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizeGrip>
#include <QStyleOption>
#include <QSlider>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QWindow>
#include <shellapi.h>
#include <algorithm>
#include <cmath>
#include <deque>
#include <functional>

namespace
{
    // RGB 只作用于列顶部、当前项和悬停面，正文保持稳定高对比白色。
    QColor rainbow(qreal hue, int alpha = 255)
    {
        QColor color = QColor::fromHsvF(static_cast<float>(std::fmod(hue + 1.0, 1.0)), 0.62f, 1.0f);
        color.setAlpha(alpha);
        return color;
    }

    class PageEntryInputTracker final : public QObject
    {
    public:
        enum class InputSource { Unknown, Pointer, Keyboard };
        explicit PageEntryInputTracker(QApplication* app) : QObject(app)
        {
            app->installEventFilter(this);
        }
        InputSource source() const { return m_source; }
        void noteKeyboardIntent() { m_source = InputSource::Keyboard; }
    protected:
        bool eventFilter(QObject* watched, QEvent* event) override;
    private:
        InputSource m_source = InputSource::Unknown;
    };

    PageEntryInputTracker* pageEntryInputTracker()
    {
        if (!qApp || QCoreApplication::closingDown()) return nullptr;
        static QPointer<PageEntryInputTracker> tracker;
        if (!tracker) tracker = new PageEntryInputTracker(qApp);
        return tracker.data();
    }

    class PageEntry final : public QPushButton
    {
    public:
        PageEntry(const QString& text, const QString& path, int depth, QWidget* parent)
            : QPushButton(text, parent), searchPath(path), m_depth(depth)
        {
            pageEntryInputTracker(); // One application-owned source tracker for all entries.
            setProperty("ksword_taskbar_page_entry", true);
            setToolTip(path);
            setCursor(Qt::PointingHandCursor);
            setFixedHeight(depth < 0 ? 34 : 25);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        }
        bool updateContent(const QString& title, const QString& path, const int depth)
        {
            const bool searchChanged = searchPath != path;
            if (text() != title) setText(title);
            if (searchPath != path) { searchPath = path; setToolTip(path); }
            if (m_depth != depth) { m_depth = depth; update(); }
            return searchChanged;
        }
        bool isHighlightActive() const
        {
            return isEnabled() && (underMouse() || isDown() || (hasFocus() && m_keyboardFocus));
        }
        bool searchMatch = false;
        QString route;      // 服务端对象生命周期身份，不能解释为地址或命令。
        QString searchPath; // 包含父级标题的完整检索路径。
        qreal hue = 0.0;
        bool current = false;
    protected:
        bool event(QEvent* event) override
        {
            bool keyboardFocus = m_keyboardFocus;
            if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseButtonDblClick)
                keyboardFocus = false;
            else if (event->type() == QEvent::KeyPress && hasFocus())
            {
                const int key = static_cast<QKeyEvent*>(event)->key();
                if (key != Qt::Key_Shift && key != Qt::Key_Control && key != Qt::Key_Alt
                    && key != Qt::Key_Meta && key != Qt::Key_AltGr)
                    keyboardFocus = true;
            }
            else if (event->type() == QEvent::FocusIn)
            {
                auto* input = pageEntryInputTracker();
                const auto reason = static_cast<QFocusEvent*>(event)->reason();
                using InputSource = PageEntryInputTracker::InputSource;
                const InputSource source = input ? input->source() : InputSource::Unknown;
                if (reason == Qt::ShortcutFocusReason || reason == Qt::MenuBarFocusReason)
                {
                    if (input) input->noteKeyboardIntent();
                    keyboardFocus = true;
                }
                else if (reason == Qt::TabFocusReason || reason == Qt::BacktabFocusReason)
                {
                    // Qt also emits TabFocusReason when disabling/hiding the old
                    // focus widget. Only actual input establishes keyboard origin.
                    if (source != InputSource::Unknown)
                        keyboardFocus = source == InputSource::Keyboard;
                    else
                    {
                        QStyleOption option;
                        option.initFrom(this);
                        keyboardFocus = option.state.testFlag(QStyle::State_KeyboardFocusChange);
                    }
                }
                else if (reason == Qt::PopupFocusReason || reason == Qt::ActiveWindowFocusReason)
                {
                    if (source != InputSource::Unknown)
                        keyboardFocus = source == InputSource::Keyboard;
                }
                else
                    keyboardFocus = false;
            }
            setKeyboardFocus(keyboardFocus);
            return QPushButton::event(event);
        }
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            const bool active = isHighlightActive();
            if (current || active)
            {
                painter.setPen(Qt::NoPen);
                painter.setBrush(rainbow(hue, isDown() ? 145 : current ? 95 : 55));
                painter.drawRoundedRect(rect().adjusted(3, 1, -3, -1), 3, 3);
                painter.fillRect(QRect(3, 4, 2, height() - 8), rainbow(hue));
            }
            QFont textFont = font(); // 只有一级列标题和二级分组加重，三级项保持紧凑。
            textFont.setPointSizeF(m_depth < 0 ? 12.0 : 11.0);
            textFont.setWeight(m_depth <= 1 ? QFont::DemiBold : QFont::Normal);
            painter.setFont(textFont);
            painter.setPen(!isEnabled() ? QColor(137, 149, 168) : m_depth < 0 ? rainbow(hue) : QColor(235, 241, 250));
            const int indent = 12 + std::min(3, std::max(0, m_depth - 1)) * 12;
            const QRect textRect = rect().adjusted(indent, 0, -9, 0);
            painter.drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft,
                QFontMetrics(textFont).elidedText(text(), Qt::ElideRight, textRect.width()));
        }
    private:
        friend class PageEntryInputTracker;
        void setKeyboardFocus(bool keyboardFocus)
        {
            if (m_keyboardFocus != keyboardFocus)
            {
                m_keyboardFocus = keyboardFocus;
                update();
            }
        }
        bool m_keyboardFocus = false;
        int m_depth; // 一级列标题为 -1，二级页为 1，后续每层缩进。
    };

    bool PageEntryInputTracker::eventFilter(QObject* watched, QEvent* event)
    {
        if (event->type() == QEvent::MouseButtonPress || event->type() == QEvent::MouseButtonDblClick)
        {
            m_source = InputSource::Pointer;
            // Same-focus clicks do not send FocusIn. Clear only the previously
            // focused entry, including a click on another non-focusable control.
            QWidget* focused = QApplication::focusWidget();
            if (focused && focused->property("ksword_taskbar_page_entry").toBool())
            {
                const QPointer<QObject> target(watched);
                static_cast<PageEntry*>(focused)->setKeyboardFocus(false);
                return target.isNull();
            }
        }
        else if (event->type() == QEvent::KeyPress)
        {
            const int key = static_cast<QKeyEvent*>(event)->key();
            if (key != Qt::Key_Shift && key != Qt::Key_Control && key != Qt::Key_Alt
                && key != Qt::Key_Meta && key != Qt::Key_AltGr)
                m_source = InputSource::Keyboard;
        }
        else if (event->type() == QEvent::Shortcut)
            m_source = InputSource::Keyboard;
        return false;
    }

    class PageColumn final : public QWidget
    {
    public:
        PageColumn(const QString& title, QWidget* parent) : QWidget(parent), title(title)
        {
            setFixedWidth(184);
            setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Maximum);
            layout = new QVBoxLayout(this);
            layout->setContentsMargins(3, 4, 3, 7);
            layout->setSpacing(1);
            header = new PageEntry(title, title, -1, this);
            layout->addWidget(header);
        }
        QString title;
        QVBoxLayout* layout;
        PageEntry* header;
        QList<PageEntry*> entries;
        QHash<QString, PageEntry*> entriesByRoute;
        int matches = 0;
        qreal hue = 0.0;
    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setPen(QPen(rainbow(hue, 85), 1));
            painter.setBrush(QColor(13, 18, 28, 215));
            painter.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 6, 6);
            QLinearGradient line(0, 0, width(), 0);
            line.setColorAt(0, rainbow(hue));
            line.setColorAt(1, rainbow(hue + 0.13));
            painter.fillRect(QRect(6, 0, width() - 12, 2), line);
            painter.setPen(QColor(110, 127, 150, 65));
            painter.drawLine(8, 38, width() - 8, 38);
        }
    };

    HWND findServer()
    {
        HWND found = nullptr; // 只发现本发行目录的 KSword 页面服务窗口。
        ::EnumWindows([](HWND window, LPARAM context) -> BOOL
        {
            if (::GetPropW(window, ks::page_navigation::ServerProperty)
                && ks::page_navigation::IsCompanionWindow(window, L"Ksword5.1.exe"))
            {
                *reinterpret_cast<HWND*>(context) = window;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&found));
        return found;
    }
}

struct PageOverviewWindow::State
{
    PageOverviewWindow* owner;
    QLineEdit* search = nullptr;
    QLabel* status = nullptr;
    QPushButton* launch = nullptr;
    QScrollArea* scroll = nullptr;
    QWidget* board = nullptr;
    QHBoxLayout* columnsLayout = nullptr;
    QList<PageColumn*> columns;
    QHash<QString, PageColumn*> columnsByRoute;
    QStringList incomingColumns;
    QHash<QString, QString> incomingTitles;
    QSet<QString> seenColumns;
    QHash<QString, QSet<QString>> seenEntries;
    QHash<QString, int> incomingPositions;
    QString catalogInstance;
    QString catalogRevision;
    QString appliedQuery;
    int totalMatches = 0;
    std::deque<std::function<void()>> pending;
    bool pumpScheduled = false;
    quint64 pumpGeneration = 0;
    QTimer* filterDelay = nullptr;
    QTimer* animation = nullptr;
    QTimer* timeout = nullptr;
    QTimer* startup = nullptr;
    QElapsedTimer clock;
    HWND server = nullptr;
    QString request;
    bool loading = false;
    int startupTicks = 0;
    QString summary; // 搜索清空后恢复目录概况，不丢掉加载状态。
    std::unique_ptr<PageOverviewBackdrop> backdrop; // 独立原生合成层，不模糊前景控件。
    QSlider* blurAmount = nullptr; // 0 关闭，1–40 实时改变高斯效果强度。
    QLabel* blurValue = nullptr; // 定宽数值不会在拖动过程中挤动搜索与页面列。

    // 设置单独保存在 Taskbar 目录，避免修改主程序主题或通知设置。
    void saveAppearance() const
    {
        QSettings settings(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarPageOverview.ini"),
            QSettings::IniFormat);
        settings.setValue(QStringLiteral("Appearance/BlurAmount"), blurAmount->value());
    }

    void applyBlur()
    {
        blurValue->setText(QString::number(blurAmount->value()));
        if (!backdrop->setAmount(blurAmount->value()))
        {
            blurAmount->setEnabled(false);
            blurValue->setText(QStringLiteral("—"));
            blurAmount->setToolTip(QStringLiteral("当前系统无法提供桌面背景模糊，已保留透明背景。"));
        }
    }

    // WM_COPYDATA 只提交短请求，主程序在事件循环里分片生成目录，避免互相阻塞。
    bool send(const QString& operation, const QString& id = QString())
    {
        if (!server || !ks::page_navigation::IsCompanionWindow(server, L"Ksword5.1.exe"))
        {
            return false;
        }
        const QByteArray bytes = QJsonDocument(QJsonObject{
            {QStringLiteral("version"), 1}, {QStringLiteral("op"), operation},
            {QStringLiteral("request"), request}, {QStringLiteral("id"), id}}).toJson(QJsonDocument::Compact);
        COPYDATASTRUCT packet{ks::page_navigation::RequestTag, static_cast<DWORD>(bytes.size()),
            const_cast<char*>(bytes.constData())};
        DWORD_PTR accepted = 0;
        return ::SendMessageTimeoutW(server, WM_COPYDATA, static_cast<WPARAM>(owner->winId()),
            reinterpret_cast<LPARAM>(&packet), SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, &accepted) && accepted;
    }

    void navigate(PageEntry* entry)
    {
        DWORD processId = 0; // 把前台激活权限交给已核验的 KSword 实例。
        ::GetWindowThreadProcessId(server, &processId);
        if (processId) ::AllowSetForegroundWindow(processId);
        if (!send(QStringLiteral("navigate"), entry->route))
        {
            status->setText(QStringLiteral("KSword 未响应，请刷新页面目录。"));
            return;
        }
        status->setText(QStringLiteral("正在打开：%1").arg(entry->searchPath));
        timeout->start(15000);
    }

    void updateFilterStatus()
    {
        if (!appliedQuery.isEmpty())
        {
            status->setText(totalMatches == 0 ? QStringLiteral("没有匹配页面，可尝试一级分类或页面名称。")
                : QStringLiteral("找到 %1 个页面 · Enter 打开首项，Esc 收起").arg(totalMatches));
        }
        else if (!loading && !summary.isEmpty()) status->setText(summary);
    }

    void filterColumn(PageColumn* column)
    {
        const bool visible = appliedQuery.isEmpty() || column->matches != 0
            || column->title.contains(appliedQuery, Qt::CaseInsensitive);
        if (column->isHidden() == visible) column->setVisible(visible);
    }

    void filterEntry(PageColumn* column, PageEntry* entry)
    {
        const bool match = appliedQuery.isEmpty() || entry->searchPath.contains(appliedQuery, Qt::CaseInsensitive);
        if (entry->searchMatch != match)
        {
            column->matches += match ? 1 : -1;
            totalMatches += match ? 1 : -1;
            entry->searchMatch = match;
        }
        if (entry->isHidden() == match) entry->setVisible(match);
        filterColumn(column);
    }

    void filter()
    {
        appliedQuery = search->text().trimmed();
        totalMatches = 0;
        for (PageColumn* column : columns)
        {
            column->matches = 0;
            for (PageEntry* entry : column->entries)
            {
                entry->searchMatch = false;
                filterEntry(column, entry);
            }
            filterColumn(column);
        }
        updateFilterStatus();
    }

    void schedulePump()
    {
        if (pumpScheduled || pending.empty()) return;
        pumpScheduled = true;
        const auto generation = pumpGeneration;
        QTimer::singleShot(0, owner, [this, generation]()
        {
            if (generation != pumpGeneration) return;
            pumpScheduled = false;
            if (!owner->isVisible()) return;
            QElapsedTimer budget; budget.start();
            int count = 0;
            while (!pending.empty() && count < 24 && (count == 0 || budget.elapsed() < 4))
            {
                auto next = std::move(pending.front()); pending.pop_front();
                next(); ++count;
            }
            updateFilterStatus();
            schedulePump();
        });
    }

    void cancelProjection()
    {
        ++pumpGeneration;
        pumpScheduled = false;
        pending.clear();
    }

    void refresh()
    {
        if (loading) send(QStringLiteral("cancel"));
        cancelProjection();
        board->setEnabled(false);
        timeout->stop();
        server = findServer();
        request = QUuid::createUuid().toString(QUuid::WithoutBraces);
        summary.clear();
        launch->setVisible(!server);
        if (!server)
        {
            status->setText(QStringLiteral("请启动同目录的新版 KSword，然后刷新页面目录。"));
            loading = false;
            return;
        }
        loading = true;
        status->setText(QStringLiteral("正在读取 KSword 页面目录…"));
        if (!send(QStringLiteral("catalog")))
        {
            loading = false;
            status->setText(QStringLiteral("KSword 未响应，请稍后刷新。"));
            return;
        }
        timeout->start(60000);
    }

    // 每列独立追加，搜索在加载过程中也能使用；标题和路径均来自当前实例实际页面。
    void receive(const QJsonObject& message)
    {
        if (message.value(QStringLiteral("request")).toString() != request
            || message.value(QStringLiteral("version")).toInt() != 1)
        {
            return;
        }
        const QString type = message.value(QStringLiteral("type")).toString();
        if (type == QStringLiteral("begin"))
        {
            board->setEnabled(true);
            seenColumns.clear(); seenEntries.clear(); incomingColumns.clear(); incomingTitles.clear(); incomingPositions.clear();
            const QString instance = message.value(QStringLiteral("catalog_instance")).toString();
            const QJsonArray groups = message.value(QStringLiteral("columns")).toArray();
            if (groups.size() > 64) return;
            catalogInstance = instance;
            for (int index = 0; index < groups.size(); ++index)
            {
                const QJsonObject group = groups.at(index).toObject();
                const QString id = group.value(QStringLiteral("id")).toString();
                incomingColumns.append(id); seenColumns.insert(id);
                incomingTitles.insert(id, group.value(QStringLiteral("title")).toString());
                pending.push_back([this, group, id, index]()
                {
                    auto* column = columnsByRoute.value(id, nullptr);
                    if (column == nullptr)
                    {
                        column = new PageColumn(group.value(QStringLiteral("title")).toString(), board);
                        column->header->route = id;
                        QObject::connect(column->header, &QPushButton::clicked, owner,
                            [this, column]() { navigate(column->header); });
                        columns.append(column); columnsByRoute.insert(id, column);
                    }
                    column->title = group.value(QStringLiteral("title")).toString();
                    column->header->updateContent(column->title, column->title, -1);
                    column->hue = std::fmod(index * 0.067, 1.0); column->header->hue = column->hue;
                    if (columnsLayout->indexOf(column) != index)
                    { columnsLayout->removeWidget(column); columnsLayout->insertWidget(index, column, 0, Qt::AlignTop); }
                    filterColumn(column);
                });
            }
        }
        else if (type == QStringLiteral("column"))
        {
            const int index = message.value(QStringLiteral("column")).toInt(-1);
            if (index < 0 || index >= incomingColumns.size()) return;
            const QString columnId = incomingColumns.at(index);
            const QJsonArray entries = message.value(QStringLiteral("entries")).toArray();
            if (entries.size() > 2048) return;
            for (const QJsonValue& value : entries)
            {
                const QJsonObject row = value.toObject();
                const QString id = row.value(QStringLiteral("id")).toString();
                if (seenEntries[columnId].contains(id)) continue;
                seenEntries[columnId].insert(id);
                const int position = incomingPositions[columnId]++;
                pending.push_back([this, row, columnId, id, position]()
                {
                    auto* column = columnsByRoute.value(columnId, nullptr);
                    if (column == nullptr) return;
                    auto* entry = column->entriesByRoute.value(id, nullptr);
                    bool changed = false;
                    const bool created = entry == nullptr;
                    if (entry == nullptr)
                    {
                        entry = new PageEntry(row.value(QStringLiteral("title")).toString(),
                            row.value(QStringLiteral("path")).toString(), row.value(QStringLiteral("depth")).toInt(), column);
                        entry->route = id;
                        column->entries.append(entry); column->entriesByRoute.insert(id, entry);
                        QObject::connect(entry, &QPushButton::clicked, owner, [this, entry]() { navigate(entry); });
                        changed = true;
                    }
                    changed = entry->updateContent(row.value(QStringLiteral("title")).toString(),
                        row.value(QStringLiteral("path")).toString(), row.value(QStringLiteral("depth")).toInt()) || changed;
                    const bool current = row.value(QStringLiteral("current")).toBool();
                    if (entry->current != current) { entry->current = current; entry->update(); }
                    entry->hue = column->hue;
                    const bool enabled = row.value(QStringLiteral("enabled")).toBool();
                    if (entry->isEnabled() != enabled) entry->setEnabled(enabled);
                    if (column->entries.value(position, nullptr) != entry)
                    { column->entries.removeOne(entry); column->entries.insert(position, entry); }
                    auto* item = column->layout->itemAt(position + 1);
                    if (created || item == nullptr || item->widget() != entry)
                    {
                        if (!created) column->layout->removeWidget(entry);
                        column->layout->insertWidget(position + 1, entry);
                    }
                    if (changed) filterEntry(column, entry);
                });
            }
            status->setText(QStringLiteral("正在整理页面：%1（%2/%3）")
                .arg(incomingTitles.value(columnId)).arg(index + 1).arg(incomingColumns.size()));
            timeout->start(60000);
        }
        else if (type == QStringLiteral("complete"))
        {
            const QString revision = message.value(QStringLiteral("revision")).toString();
            const QString instance = message.value(QStringLiteral("catalog_instance")).toString();
            pending.push_back([this, revision, instance]()
            {
                // 只在完整目录到齐后修剪旧身份；每个旧按钮也进入同一有预算队列。
                for (PageColumn* column : columns)
                {
                    const QString id = column->header->route;
                    for (PageEntry* entry : column->entries)
                    {
                        if (seenColumns.contains(id) && seenEntries.value(id).contains(entry->route)) continue;
                        pending.push_back([this, column, entry]()
                        {
                            if (entry->searchMatch) { --column->matches; --totalMatches; }
                            column->entries.removeOne(entry); column->entriesByRoute.remove(entry->route);
                            column->layout->removeWidget(entry); delete entry;
                        });
                    }
                    if (!seenColumns.contains(id))
                    {
                        pending.push_back([this, column, id]()
                        {
                            columns.removeOne(column); columnsByRoute.remove(id);
                            columnsLayout->removeWidget(column); delete column;
                        });
                    }
                }
                pending.push_back([this, revision, instance]()
                {
                    QList<PageColumn*> ordered;
                    for (const QString& id : incomingColumns)
                        if (auto* column = columnsByRoute.value(id, nullptr)) { ordered.append(column); filterColumn(column); }
                    columns = ordered;
                    catalogRevision = revision; catalogInstance = instance;
                    loading = false; timeout->stop();
                    int pages = columns.size();
                    for (PageColumn* column : columns) pages += column->entries.size();
                    summary = QStringLiteral("%1 个分类 · %2 个页面 · 点击进入，Esc 收起").arg(columns.size()).arg(pages);
                    status->setText(summary);
                });
            });
        }
        else if (type == QStringLiteral("activated"))
        {
            timeout->stop();
            owner->hide();
            return;
        }
        else if (type == QStringLiteral("stale"))
        {
            timeout->stop();
            status->setText(QStringLiteral("页面已变化，请刷新目录后重新选择。"));
            return;
        }
        schedulePump();
    }
};

PageOverviewWindow::PageOverviewWindow(QWidget* owner)
    : QWidget(owner, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint), m_state(std::make_unique<State>())
{
    // Observe search/header input before the asynchronous catalog creates entries.
    pageEntryInputTracker();
    m_state->owner = this;
    m_state->backdrop = std::make_unique<PageOverviewBackdrop>(this);
    setWindowTitle(QStringLiteral("KSword 页面平铺"));
    setObjectName(QStringLiteral("ks_taskbar_page_overview"));
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_DeleteOnClose, false);
    setMinimumSize(480, 280);
    QFont body = QApplication::font();
    body.setPointSizeF(9.0);
    setFont(body);
    // 不对整个窗口设置 opacity：只让底板透明，文本和输入控件保持完整不透明度。
    setStyleSheet(QStringLiteral(
        "QWidget#ks_taskbar_page_overview,QScrollArea,QScrollArea > QWidget > QWidget{background:transparent;}"
        "QFrame#overview_header{background:rgba(13,18,28,235);border:1px solid #435168;border-radius:6px;}"
        "QLabel{color:#d6e2f4;background:transparent;border:0;}"
        "QLineEdit{background:rgba(31,41,58,245);color:#edf3ff;border:1px solid #536582;border-radius:4px;padding:5px 9px;}"
        "QLineEdit:focus{border-color:#9e9bff;}"
        "QPushButton{background:rgba(35,46,65,235);color:#e3ecfa;border:0;border-radius:4px;padding:4px 9px;}"
        "QPushButton:hover{background:#40516d;}"
        "QScrollBar:vertical{background:transparent;width:7px;}"
        "QScrollBar:horizontal{background:transparent;height:7px;}"
        "QScrollBar::handle{background:#667b9a;border-radius:3px;min-width:24px;min-height:24px;}"
        "QScrollBar::add-line,QScrollBar::sub-line{width:0;height:0;}"
        "QScrollBar::add-page,QScrollBar::sub-page{background:transparent;}"));
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(7, 7, 7, 7);
    root->setSpacing(10);
    auto* header = new QFrame(this);
    header->setObjectName(QStringLiteral("overview_header"));
    auto* top = new QHBoxLayout(header);
    top->setContentsMargins(12, 8, 9, 8);
    auto* title = new QLabel(QStringLiteral("KSword  /  页面平铺"), header);
    title->setAttribute(Qt::WA_TransparentForMouseEvents);
    top->addWidget(title);
    m_state->search = new QLineEdit(header);
    m_state->search->setPlaceholderText(QStringLiteral("搜索页面或路径…"));
    m_state->search->setClearButtonEnabled(true);
    top->addWidget(m_state->search, 1);
    m_state->launch = new QPushButton(QStringLiteral("启动 KSword"), header);
    m_state->launch->setToolTip(QStringLiteral("启动同目录的 KSword 主程序"));
    auto* refresh = new QPushButton(QStringLiteral("刷新"), header);
    refresh->setToolTip(QStringLiteral("重新读取所有一级、二级与三级页面"));
    auto* close = new QPushButton(QStringLiteral("×"), header);
    close->setToolTip(QStringLiteral("收起页面平铺（Esc）"));
    close->setFixedWidth(28);
    top->addWidget(m_state->launch);
    top->addWidget(refresh);
    top->addWidget(close);
    // 记录原 9pt 工具行的高度，再放大字；文字变大不会把整个框架撑高。
    header->ensurePolished();
    m_state->search->ensurePolished();
    const int controlHeight = m_state->search->sizeHint().height();
    header->setFixedHeight(header->sizeHint().height());
    m_state->search->setFixedHeight(controlHeight);
    for (QPushButton* button : {m_state->launch, refresh, close})
        button->setFixedHeight(controlHeight);
    QFont headerFont = font();
    headerFont.setPointSizeF(10.5);
    header->setFont(headerFont);
    header->setStyleSheet(QStringLiteral("QLineEdit{padding:2px 9px;}QPushButton{padding:2px 9px;}"));
    root->addWidget(header);
    m_state->scroll = new QScrollArea(this);
    m_state->scroll->setFrameShape(QFrame::NoFrame);
    m_state->scroll->setWidgetResizable(true);
    m_state->scroll->viewport()->setAutoFillBackground(false);
    m_state->board = new QWidget(m_state->scroll);
    m_state->columnsLayout = new QHBoxLayout(m_state->board);
    m_state->columnsLayout->setContentsMargins(0, 0, 0, 0);
    m_state->columnsLayout->setSpacing(10);
    m_state->columnsLayout->addStretch();
    m_state->scroll->setWidget(m_state->board);
    root->addWidget(m_state->scroll, 1);
    auto* footer = new QHBoxLayout();
    m_state->status = new QLabel(this);
    m_state->status->setStyleSheet(QStringLiteral(
        "QLabel{background:rgba(13,18,28,225);color:#d6e2f4;padding:3px 8px;border-radius:4px;}"));
    QFont footerFont = font();
    footerFont.setPointSizeF(10.0);
    m_state->status->setFont(footerFont);
    m_state->status->setWordWrap(true);
    footer->addWidget(m_state->status, 1);
    // 调节器占用现有底栏，不增加工具行、不改变列宽与页面行高。
    auto* blurControls = new QFrame(this);
    blurControls->setFixedHeight(26);
    blurControls->setStyleSheet(QStringLiteral(
        "QFrame{background:rgba(13,18,28,225);border-radius:4px;}"
        "QLabel{background:transparent;color:#d6e2f4;}"
        "QSlider::groove:horizontal{height:4px;background:#4b596d;border-radius:2px;}"
        "QSlider::sub-page:horizontal{background:#8d9cff;border-radius:2px;}"
        "QSlider::handle:horizontal{width:12px;margin:-4px 0;background:#edf3ff;border-radius:6px;}"));
    blurControls->setFont(footerFont);
    auto* blurLayout = new QHBoxLayout(blurControls);
    blurLayout->setContentsMargins(8, 0, 8, 0);
    blurLayout->setSpacing(7);
    blurLayout->addWidget(new QLabel(QStringLiteral("模糊"), blurControls));
    m_state->blurAmount = new QSlider(Qt::Horizontal, blurControls);
    m_state->blurAmount->setRange(0, 40);
    m_state->blurAmount->setFixedWidth(84);
    m_state->blurAmount->setPageStep(5);
    m_state->blurAmount->setAccessibleName(QStringLiteral("背景高斯模糊强度"));
    m_state->blurAmount->setToolTip(QStringLiteral("实时调节背景高斯模糊强度，0 关闭；不改变面板透明度。"));
    QSettings appearance(QCoreApplication::applicationDirPath() + QStringLiteral("/TaskbarPageOverview.ini"),
        QSettings::IniFormat);
    m_state->blurAmount->setValue(std::clamp(appearance.value(QStringLiteral("Appearance/BlurAmount"), 20).toInt(), 0, 40));
    blurLayout->addWidget(m_state->blurAmount);
    m_state->blurValue = new QLabel(QString::number(m_state->blurAmount->value()), blurControls);
    m_state->blurValue->setFixedWidth(23);
    m_state->blurValue->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    blurLayout->addWidget(m_state->blurValue);
    footer->addWidget(blurControls);
    footer->addWidget(new QSizeGrip(this), 0, Qt::AlignRight);
    root->addLayout(footer);
    connect(m_state->blurAmount, &QSlider::valueChanged, this, [this]() { m_state->applyBlur(); });

    m_state->timeout = new QTimer(this);
    m_state->timeout->setSingleShot(true);
    connect(m_state->timeout, &QTimer::timeout, this, [this]()
    {
        if (m_state->loading) m_state->send(QStringLiteral("cancel"));
        m_state->loading = false;
        m_state->cancelProjection();
        m_state->status->setText(QStringLiteral("目录加载或页面跳转超时，请稍后刷新。"));
    });
    m_state->filterDelay = new QTimer(this);
    m_state->filterDelay->setSingleShot(true); m_state->filterDelay->setInterval(120);
    connect(m_state->filterDelay, &QTimer::timeout, this, [this]() { m_state->filter(); });
    connect(m_state->search, &QLineEdit::textChanged, this, [this]() { m_state->filterDelay->start(); });
    connect(m_state->search, &QLineEdit::returnPressed, this, [this]()
    {
        m_state->filterDelay->stop(); m_state->filter();
        for (PageColumn* column : m_state->columns)
        {
            if (column->isHidden()) continue;
            for (PageEntry* entry : column->entries)
            {
                if (!entry->isHidden() && entry->isEnabled())
                {
                    m_state->navigate(entry);
                    return;
                }
            }
        }
    });
    connect(refresh, &QPushButton::clicked, this, [this]() { m_state->refresh(); });
    connect(close, &QPushButton::clicked, this, &QWidget::hide);
    m_state->startup = new QTimer(this);
    m_state->startup->setInterval(500);
    connect(m_state->launch, &QPushButton::clicked, this, [this]()
    {
        const QString path = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Ksword5.1.exe"));
        if (!QFileInfo::exists(path))
        {
            m_state->status->setText(QStringLiteral("同目录未找到 Ksword5.1.exe。"));
            return;
        }
        const auto result = reinterpret_cast<INT_PTR>(::ShellExecuteW(nullptr, L"open",
            reinterpret_cast<LPCWSTR>(path.utf16()), nullptr,
            reinterpret_cast<LPCWSTR>(QCoreApplication::applicationDirPath().utf16()), SW_SHOWNORMAL));
        if (result <= 32)
        {
            m_state->status->setText(QStringLiteral("KSword 未启动，可能已取消授权。"));
            return;
        }
        m_state->status->setText(QStringLiteral("正在等待 KSword 启动…"));
        m_state->launch->setEnabled(false);
        m_state->startupTicks = 0;
        m_state->startup->start();
    });
    connect(m_state->startup, &QTimer::timeout, this, [this]()
    {
        if (findServer() || ++m_state->startupTicks >= 120)
        {
            m_state->startup->stop();
            m_state->launch->setEnabled(true);
            m_state->refresh();
        }
    });
    // RGB 缓慢循环，只在窗口可见时更新；遵循系统关闭界面动画的偏好。
    m_state->clock.start();
    m_state->animation = new QTimer(this);
    m_state->animation->setInterval(33);
    connect(m_state->animation, &QTimer::timeout, this, [this]()
    {
        const qreal phase = (m_state->clock.elapsed() % 14000) / 14000.0;
        for (int index = 0; index < m_state->columns.size(); ++index)
        {
            PageColumn* column = m_state->columns[index];
            if (column->isHidden() || column->visibleRegion().isEmpty()) continue;
            column->hue = std::fmod(phase + index * 0.067, 1.0);
            column->header->hue = column->hue;
            column->header->update();
            for (PageEntry* entry : column->entries)
            {
                entry->hue = column->hue;
                if (entry->current || entry->isHighlightActive()) entry->update();
            }
            if (!column->isHidden()) column->update();
        }
    });
    ::SetPropW(reinterpret_cast<HWND>(winId()), ks::page_navigation::ClientProperty, reinterpret_cast<HANDLE>(1));
    CHANGEFILTERSTRUCT filter{sizeof(CHANGEFILTERSTRUCT), 0};
    ::ChangeWindowMessageFilterEx(reinterpret_cast<HWND>(winId()), WM_COPYDATA, MSGFLT_ALLOW, &filter);
}

PageOverviewWindow::~PageOverviewWindow()
{
    m_state->saveAppearance();
    m_state->backdrop->hide();
    ::RemovePropW(reinterpret_cast<HWND>(winId()), ks::page_navigation::ClientProperty);
}

void PageOverviewWindow::openOnScreen(QScreen* screen)
{
    if (!screen) screen = QApplication::primaryScreen();
    const QRect available = screen->availableGeometry();
    setMinimumSize(std::min(480, available.width()), std::min(280, available.height()));
    resize(std::min(available.width(), std::max(480, available.width() * 92 / 100)),
        std::min(available.height(), std::max(280, available.height() * 84 / 100)));
    move(available.center() - rect().center());
    show();
    raise();
    activateWindow();
    m_state->search->setFocus();
}

bool PageOverviewWindow::nativeEvent(const QByteArray& type, void* message, qintptr* result)
{
    const MSG* native = static_cast<const MSG*>(message);
    if (native && native->message == WM_WINDOWPOSCHANGED)
    {
        // 原生移动/缩放/置顶变化时立即同步背景，避免拖动中留下一块旧底板。
        m_state->backdrop->synchronize();
    }
    if (native && native->message == WM_COPYDATA)
    {
        const auto* data = reinterpret_cast<const COPYDATASTRUCT*>(native->lParam);
        const HWND sender = reinterpret_cast<HWND>(native->wParam);
        if (data && data->dwData == ks::page_navigation::ReplyTag && data->lpData
            && data->cbData <= ks::page_navigation::MaxMessageBytes && sender == m_state->server
            && ks::page_navigation::IsCompanionWindow(sender, L"Ksword5.1.exe"))
        {
            const QJsonObject reply = QJsonDocument::fromJson(
                QByteArray(static_cast<const char*>(data->lpData), data->cbData)).object();
            QTimer::singleShot(0, this, [this, reply]() { if (isVisible()) m_state->receive(reply); });
            *result = TRUE;
            return true;
        }
    }
    return QWidget::nativeEvent(type, message, result);
}

void PageOverviewWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    QTimer::singleShot(0, this, [this]()
    {
        if (isVisible()) m_state->applyBlur();
    });
    BOOL animations = TRUE;
    ::SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animations, 0);
    if (animations) m_state->animation->start();
    if (m_state->appliedQuery != m_state->search->text().trimmed()) m_state->filter();
    m_state->refresh();
}

void PageOverviewWindow::hideEvent(QHideEvent* event)
{
    m_state->backdrop->hide();
    m_state->saveAppearance();
    if (m_state->loading) m_state->send(QStringLiteral("cancel"));
    m_state->loading = false;
    m_state->cancelProjection();
    m_state->filterDelay->stop();
    m_state->animation->stop();
    m_state->timeout->stop();
    m_state->startup->stop();
    m_state->launch->setEnabled(true);
    QWidget::hideEvent(event);
}

void PageOverviewWindow::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && event->position().y() < 56 && windowHandle())
    {
        windowHandle()->startSystemMove();
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void PageOverviewWindow::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Escape)
    {
        hide();
        return;
    }
    if (event->matches(QKeySequence::Find))
    {
        m_state->search->setFocus();
        m_state->search->selectAll();
        return;
    }
    QWidget::keyPressEvent(event);
}
