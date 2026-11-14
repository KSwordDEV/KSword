#include "RuntimeControlPages.h"
#include "ShortcutRegistry.h"
#include "SecondaryPageLayout.h"
#include "TablePresentation.h"
#include "PageControlStyle.h"
#include "ToolbarMetrics.h"
#include "FlatButtonTheme.h"
#include "FlowLayout.h"
#include "VisibleTableWidget.h"
#include "UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include <QComboBox>
#include <QHeaderView>
#include <QHideEvent>
#include <QKeySequenceEdit>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        QString contextText(const QString& context)
        {
            if (context == QStringLiteral("application")) return i18n::sourceText(QStringLiteral("应用内"));
            if (context == QStringLiteral("system")) return i18n::sourceText(QStringLiteral("系统全局"));
            if (context == QStringLiteral("navigation")) return i18n::sourceText(QStringLiteral("无鼠标模式"));
            if (context == QStringLiteral("editor")) return i18n::sourceText(QStringLiteral("文本编辑器"));
            if (context == QStringLiteral("file")) return i18n::sourceText(QStringLiteral("文件浏览器"));
            if (context == QStringLiteral("registry")) return i18n::sourceText(QStringLiteral("注册表编辑器"));
            if (context == QStringLiteral("memory")) return i18n::sourceText(QStringLiteral("内存工作台"));
            if (context == QStringLiteral("process")) return i18n::sourceText(QStringLiteral("进程列表"));
            if (context == QStringLiteral("debug")) return i18n::sourceText(QStringLiteral("内存调试"));
            return context;
        }
        QString commandTitle(const ShortcutRegistry::Command& command)
        {
            const QString title = i18n::displayText(command.title);
            return command.context == QStringLiteral("memory")
                ? title.section(QChar(0xFF08), 0, 0).section(QLatin1Char('('), 0, 0) : title;
        }
    }
    struct ShortcutManagerDialog::State
    {
        SystemFactory factory;
        SystemSearch search;
        QTabWidget* tabs = nullptr;
        QWidget* systemShell = nullptr;
        VisibleTableWidget* table = nullptr;
        QLineEdit* filter = nullptr;
        QComboBox* scope = nullptr;
        QKeySequenceEdit* keys = nullptr;
        QLabel *selected = nullptr, *status = nullptr;
        QPushButton *save = nullptr, *clear = nullptr, *defaults = nullptr, *occupancy = nullptr;
        QTimer* timer = nullptr;
        QString id;
        QHash<QString, QKeySequence> drafts;
        bool loading = false;
        quint64 revision = ~quint64(0);
    };

    ShortcutManagerDialog::ShortcutManagerDialog(QWidget* parent, SystemFactory factory, SystemSearch search)
        : QDialog(parent), m(std::make_unique<State>())
    {
        StyleSecondaryManagerWindow(this);
        m->factory = std::move(factory); m->search = std::move(search);
        setObjectName(QStringLiteral("ks_shortcut_manager"));
        setWindowTitle(i18n::sourceText(QStringLiteral("快捷键管理")));
        setModal(false);
        applyResponsiveWindowGeometry(this, parent, QSize(1040, 720), QSize(700, 500));
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(6, 6, 6, 6);
        m->tabs = new QTabWidget(this);
        StyleSecondaryTabs(m->tabs);
        root->addWidget(m->tabs, 1);
        auto* appPage = new QWidget(m->tabs);
        auto* layout = new QVBoxLayout(appPage);
        layout->setContentsMargins(0, 6, 0, 0);
        layout->setSpacing(8);
        auto* toolbar = new QHBoxLayout();
        m->filter = new QLineEdit(appPage);
        m->filter->setPlaceholderText(i18n::sourceText(QStringLiteral("搜索动作或快捷键")));
        m->filter->setClearButtonEnabled(true);
        StyleSearchField(m->filter);
        m->scope = new QComboBox(appPage);
        m->scope->addItem(i18n::sourceText(QStringLiteral("全部范围")), QString{});
        for (const char* scope : {"application", "editor", "file", "registry", "memory", "process", "debug", "navigation", "system"})
        {
            const QString value = QString::fromLatin1(scope);
            m->scope->addItem(contextText(value), value);
        }
        toolbar->addWidget(m->filter, 1); toolbar->addWidget(m->scope);
        NormalizeToolbarRow(toolbar);
        layout->addLayout(toolbar);
        m->table = new VisibleTableWidget(appPage);
        m->table->setObjectName(QStringLiteral("ks_shortcut_binding_list"));
        m->table->setColumnCount(3);
        m->table->setHorizontalHeaderLabels({i18n::sourceText(QStringLiteral("动作")), i18n::sourceText(QStringLiteral("快捷键")),
            i18n::sourceText(QStringLiteral("范围"))});
        m->table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m->table->setSelectionMode(QAbstractItemView::SingleSelection);
        m->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m->table->verticalHeader()->hide();
        m->table->verticalHeader()->setDefaultSectionSize(30);
        m->table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        m->table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        m->table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        SetTableActionBarMode(m->table, TableActionBarMode::None);
        ApplyTablePresentation(m->table);
        layout->addWidget(m->table, 1);
        auto* footer = new QWidget(appPage);
        auto* footerLayout = new QVBoxLayout(footer);
        footerLayout->setContentsMargins(0, 8, 0, 0);
        footerLayout->setSpacing(6);
        m->selected = new QLabel(footer);
        m->selected->setWordWrap(true);
        footerLayout->addWidget(m->selected);
        auto* controls = new QWidget(footer);
        auto* controlRow = new FlowLayout(controls, 0, 8, 6);
        m->keys = new QKeySequenceEdit(controls);
        m->keys->setObjectName(QStringLiteral("ks_shortcut_binding_editor"));
        m->keys->setMinimumWidth(180); m->keys->setMaximumWidth(260);
        m->save = new QPushButton(i18n::sourceText(QStringLiteral("应用")), controls);
        m->clear = new QPushButton(i18n::sourceText(QStringLiteral("清除绑定")), controls);
        m->defaults = new QPushButton(i18n::sourceText(QStringLiteral("恢复默认")), controls);
        m->occupancy = new QPushButton(i18n::sourceText(QStringLiteral("查找占用")), controls);
        controlRow->addWidget(m->keys);
        for (auto* button : {m->save, m->clear, m->defaults, m->occupancy}) controlRow->addWidget(button);
        NormalizeToolbarLayout(controlRow);
        ApplyFlatButtonTheme(m->save, FlatButtonTone::Accent, FlatButtonAppearance::Solid);
        footerLayout->addWidget(controls);
        m->status = new QLabel(footer);
        m->status->setWordWrap(true);
        footerLayout->addWidget(m->status);
        StyleSecondaryFooter(footer);
        layout->addWidget(footer);
        m->tabs->addTab(appPage, i18n::sourceText(QStringLiteral("KSword 快捷键")));
        m->systemShell = new QWidget(m->tabs);
        auto* systemLayout = new QVBoxLayout(m->systemShell);
        systemLayout->setContentsMargins(0, 6, 0, 0);
        m->tabs->addTab(m->systemShell, i18n::sourceText(QStringLiteral("系统快捷键")));
        connect(m->tabs, &QTabWidget::currentChanged, this, [this](int index) {
            if (index == 1 && m->factory)
            {
                if (QWidget* page = m->factory(m->systemShell)) { m->systemShell->layout()->addWidget(page); m->factory = {}; }
            }
            if (m->timer) { if (index == 0 && isVisible()) { refresh(); m->timer->start(); } else m->timer->stop(); }
        });
        connect(m->table, &QTableWidget::itemSelectionChanged, this, [this]() { selectCommand(); });
        connect(m->table, &QTableWidget::cellDoubleClicked, this, [this]() { if (m->keys->isEnabled()) m->keys->setFocus(); });
        connect(m->filter, &QLineEdit::textChanged, this, [this]() { refresh(); });
        connect(m->scope, &QComboBox::currentIndexChanged, this, [this]() { refresh(); });
        connect(m->keys, &QKeySequenceEdit::keySequenceChanged, this, [this](const QKeySequence& keys) {
            if (m->loading || m->id.isEmpty()) return;
            if (keys == ShortcutRegistry::instance().binding(m->id)) m->drafts.remove(m->id); else m->drafts[m->id] = keys;
            m->save->setEnabled(m->drafts.contains(m->id));
            m->status->setText(m->drafts.contains(m->id) ? i18n::sourceText(QStringLiteral("快捷键尚未应用。")) : QString{});
            m->revision = ~quint64(0); refresh();
        });
        connect(m->save, &QPushButton::clicked, this, [this]() { apply(0); });
        connect(m->clear, &QPushButton::clicked, this, [this]() { apply(1); });
        connect(m->defaults, &QPushButton::clicked, this, [this]() { apply(2); });
        connect(m->occupancy, &QPushButton::clicked, this, [this]() {
            const auto keys = m->keys->keySequence();
            if (keys.isEmpty() || keys.count() != 1) { m->status->setText(i18n::sourceText(QStringLiteral("请选择一个组合键，再查找系统占用。"))); return; }
            showSystemPage();
            if (m->search) m->search(keys.toString(QKeySequence::NativeText));
        });
        m->timer = new QTimer(this);
        m->timer->setInterval(750);
        connect(m->timer, &QTimer::timeout, this, [this]() { refresh(); });
        refresh(); selectCommand();
    }
    ShortcutManagerDialog::~ShortcutManagerDialog() = default;
    void ShortcutManagerDialog::showSystemPage() { m->tabs->setCurrentIndex(1); }
    void ShortcutManagerDialog::showEvent(QShowEvent* event)
    {
        QDialog::showEvent(event);
        refresh();
        if (m->tabs->currentIndex() == 0) m->timer->start();
    }
    void ShortcutManagerDialog::hideEvent(QHideEvent* event) { m->timer->stop(); QDialog::hideEvent(event); }

    void ShortcutManagerDialog::refresh()
    {
        auto& registry = ShortcutRegistry::instance();
        const QSignalBlocker block(m->table);
        if (m->revision != registry.revision())
        {
            m->revision = registry.revision();
            const auto commands = registry.snapshot();
            m->table->setRowCount(commands.size());
            for (int row = 0; row < commands.size(); ++row)
            {
                const auto& command = commands[row];
                QStringList bindings{command.binding.toString(QKeySequence::NativeText)};
                bindings.append(command.alternateBindings);
                QString displayed = bindings.join(QStringLiteral(" / "));
                if (m->drafts.contains(command.id)) displayed = m->drafts[command.id].toString(QKeySequence::NativeText) + QStringLiteral(" *");
                else if (displayed.isEmpty()) displayed = i18n::sourceText(command.editable ? QStringLiteral("未绑定") : QStringLiteral("固定手势"));
                if (!command.editable && !command.binding.isEmpty()) displayed += QStringLiteral(" · ") + i18n::sourceText(QStringLiteral("固定"));
                const QStringList cells{commandTitle(command), displayed, contextText(command.context)};
                for (int col = 0; col < cells.size(); ++col)
                {
                    auto* item = m->table->item(row, col);
                    if (!item) { item = new QTableWidgetItem(); m->table->setItem(row, col, item); }
                    if (item->text() != cells[col]) item->setText(cells[col]);
                    item->setToolTip(col == 0 ? cells[0] : i18n::displayText(command.restriction));
                }
                m->table->item(row, 0)->setData(Qt::UserRole, command.id);
                m->table->item(row, 0)->setData(Qt::UserRole + 1, command.context);
                m->table->item(row, 1)->setData(Qt::UserRole, bindings.join(QLatin1Char(' ')));
                if (command.id == m->id) m->table->selectRow(row);
            }
        }
        for (int row = 0; row < m->table->rowCount(); ++row)
        {
            QString text = m->table->item(row, 1)->data(Qt::UserRole).toString();
            for (int col = 0; col < 3; ++col) text += QLatin1Char(' ') + m->table->item(row, col)->text();
            const bool shown = text.contains(m->filter->text().trimmed(), Qt::CaseInsensitive)
                && (m->scope->currentData().toString().isEmpty() || m->scope->currentData() == m->table->item(row, 0)->data(Qt::UserRole + 1));
            m->table->setRowHidden(row, !shown);
        }
    }
    void ShortcutManagerDialog::selectCommand()
    {
        const auto selected = m->table->selectionModel()->selectedRows();
        m->id = selected.isEmpty() ? QString{} : m->table->item(selected.front().row(), 0)->data(Qt::UserRole).toString();
        m->loading = true;
        bool found = false;
        for (const auto& command : ShortcutRegistry::instance().snapshot())
        {
            if (command.id != m->id) continue;
            found = true;
            m->selected->setText(commandTitle(command));
            m->keys->setMaximumSequenceLength(command.sequence ? 4 : 1);
            m->keys->setKeySequence(m->drafts.value(command.id, command.binding));
            m->keys->setEnabled(command.editable);
            m->save->setEnabled(command.editable && m->drafts.contains(command.id));
            m->clear->setEnabled(command.editable);
            m->defaults->setEnabled(command.editable);
            m->occupancy->setEnabled(command.binding.count() <= 1);
            m->status->setText(m->drafts.contains(command.id) ? i18n::sourceText(QStringLiteral("快捷键尚未应用。"))
                : i18n::displayText(command.restriction));
            break;
        }
        if (!found)
        {
            m->selected->setText(i18n::sourceText(QStringLiteral("选择动作后修改快捷键；双击列表可直接开始录入。")));
            m->keys->setEnabled(false);
            for (auto* button : {m->save, m->clear, m->defaults, m->occupancy}) button->setEnabled(false);
            m->status->clear();
        }
        m->loading = false;
    }
    void ShortcutManagerDialog::apply(int operation)
    {
        const QString id = m->id;
        QString error;
        auto& registry = ShortcutRegistry::instance();
        const bool ok = operation == 2 ? registry.restoreDefault(id, &error)
            : registry.rebind(id, operation == 1 ? QKeySequence{} : m->keys->keySequence(), &error);
        if (ok) m->drafts.remove(id);
        m->revision = ~quint64(0); refresh();
        if (ok) selectCommand();
        m->status->setText(ok ? i18n::sourceText(QStringLiteral("绑定已保存并应用。")) : error);
    }
}
