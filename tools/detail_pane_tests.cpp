// 离屏夹具编译实际详情宿主和 CodeEditor，禁止访问真实驱动/进程/剪贴板。
#include "../Ksword5.1/Ksword5.1/UI/DetailLayoutHost.h"
#include "../Ksword5.1/Ksword5.1/UI/DetailLayoutRegistry.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"

#include <QApplication>
#include <QDialog>
#include <QHeaderView>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTableWidget>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeView>
#include <QVBoxLayout>

#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

namespace
{
    using ks::settings::DetailDisplayScheme;
    int checks = 0;   // 累计生产行为断言。
    int failures = 0; // 回归失败数。

    void expect(const bool condition, const char* label)
    {
        ++checks;
        if (!condition)
        {
            ++failures;
            std::printf("DETAIL_PANE_FAILURE=%s\n", label);
        }
    }

    void drain()
    {
        for (int iteration = 0; iteration < 12; ++iteration)
        {
            QCoreApplication::sendPostedEvents();
            QCoreApplication::processEvents();
            QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        }
    }

    // 业务选择槽先准备文本，再通过实际 clicked signal 测试 queued 布局行为。
    void clickRow(QTableWidget* table, const int row)
    {
        table->setCurrentCell(row, 0);
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, table->model()->index(row, 0)));
        drain();
    }

    QToolButton* toggleButton(QWidget* parent)
    {
        for (QToolButton* const button : parent->findChildren<QToolButton*>())
        {
            if (button->size() == QSize(44, 18))
            {
                return button;
            }
        }
        return nullptr;
    }

    ks::ui::FieldDocument nativeDocument(const QString& value)
    {
        ks::ui::FieldDocument document;
        document.title = QStringLiteral("Native fixture");
        document.section(QStringLiteral("Identity"));
        document.field(QStringLiteral("Name"), value);
        document.field(QStringLiteral("Pid"), QStringLiteral("42"));
        ks::ui::FieldNode nested;
        nested.kind = ks::ui::FieldNode::Kind::Section;
        nested.name = QStringLiteral("Nested source fields");
        nested.children.push_back({ks::ui::FieldNode::Kind::Field, QStringLiteral("Address"), QStringLiteral("0x1234"), false, {}});
        document.nodes.last().children.push_back(nested);
        return document;
    }

    void explicitStrategies()
    {
        QWidget page;
        page.resize(850, 620);
        QVBoxLayout root(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        root.addWidget(splitter);
        auto* table = new QTableWidget(2, 1, splitter);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("z")));
        table->setItem(1, 0, new QTableWidgetItem(QStringLiteral("a")));
        auto* editor = new CodeEditorWidget(splitter);
        editor->setReadOnly(true);
        editor->setRawText(QStringLiteral("source bytes\r\n0x1234"));
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(table, editor, &page, splitter, table, editor);
        page.show();
        drain();
        expect(host != nullptr && host->hasExplicitBinding() && host->isBound(), "explicit two panel contract bound");
        expect(splitter->count() == 3 && splitter->widget(0) == table && splitter->widget(2) == editor,
            "host only inserts toggle between declared panels");
        expect(ks::ui::DetailLayoutRegistry::registerHost(table, editor, &page, splitter, table, editor) == host,
            "explicit registry reuses same host");
        expect(splitter->count() == 3, "repeat registration does not duplicate layout controls");
        expect(!host->bindPanels({splitter, table, table}), "same main and detail panel rejected");
        expect(host->isBound(), "invalid rebinding preserves existing layout");
        expect(editor->isHidden(), "bottom starts collapsed");
        QToolButton* const toggle = toggleButton(&page);
        expect(toggle != nullptr, "production bottom toggle exists");
        if (toggle != nullptr)
        {
            toggle->click();
            drain();
            expect(!editor->isHidden(), "actual bottom toggle expands detail");
            host->applyScheme(DetailDisplayScheme::BottomCollapsed);
            expect(!editor->isHidden(), "same scheme preserves user expansion");
            toggle->click();
            drain();
            expect(editor->isHidden(), "actual bottom toggle collapses detail");
        }

        host->applyScheme(DetailDisplayScheme::Right);
        drain();
        expect(splitter->orientation() == Qt::Horizontal && !editor->isHidden(), "right strategy uses declared panels");
        QAbstractItemDelegate* const sourceDelegate = table->itemDelegate();
        const int originalHeight = table->rowHeight(0);
        host->applyScheme(DetailDisplayScheme::Embedded);
        clickRow(table, 0);
        expect(table->rowCount() == 2 && table->rowHeight(0) > originalHeight,
            "inline expands source geometry without inserting business row");
        expect(table->itemDelegate() != sourceDelegate, "inline installs production delegate wrapper");
        auto mirrors = table->viewport()->findChildren<CodeEditorWidget*>();
        expect(mirrors.size() == 1 && mirrors.front()->text() == editor->text(),
            "inline raw mirror retains source bytes and mode");
        table->sortItems(0, Qt::AscendingOrder);
        drain();
        if (table->rowHeight(0) != originalHeight || table->rowHeight(1) != originalHeight)
        {
            std::printf("DETAIL_PANE_HEIGHTS=original:%d first:%d second:%d\n",
                originalHeight, table->rowHeight(0), table->rowHeight(1));
        }
        expect(table->rowHeight(0) == originalHeight && table->rowHeight(1) == originalHeight,
            "sorting restores geometry before persistent indices move");
        expect(table->itemDelegate() == sourceDelegate, "sorting restores existing source delegate");

        clickRow(table, 0);
        auto* replacementDelegate = new QStyledItemDelegate(table);
        table->setItemDelegate(replacementDelegate);
        host->prepareDataRebuild();
        drain();
        expect(table->itemDelegate() == replacementDelegate, "cleanup preserves delegate replaced by business page");
        expect(table->rowHeight(0) == originalHeight, "explicit rebuild restores row height");

        // 同模型同维度的原地重建也必须取消已经排队的点击，不能重新展开旧详情。
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, table->model()->index(0, 0)));
        host->prepareDataRebuild();
        table->item(0, 0)->setText(QStringLiteral("same model refreshed"));
        drain();
        expect(table->viewport()->findChildren<CodeEditorWidget*>().isEmpty()
            && table->rowHeight(0) == originalHeight, "in place rebuild cancels queued old inline click");
        host->prepareDataRebuild();

        // 在 queued 点击到达前切模式，旧任务不得再插入行内编辑器或打开窗口。
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, table->model()->index(0, 0)));
        host->applyScheme(DetailDisplayScheme::BottomCollapsed);
        drain();
        expect(table->viewport()->findChildren<CodeEditorWidget*>().isEmpty(), "stale queued inline click canceled on scheme change");
        editor->setRawText(QStringLiteral("untranslated user code\r\nPid: 42"));
        host->applyScheme(DetailDisplayScheme::Floating);
        clickRow(table, 0);
        const auto floating = page.findChildren<QDialog*>();
        expect(floating.size() == 1 && floating.front()->isVisible(), "floating strategy opens one production dialog");
        if (!floating.isEmpty())
        {
            auto* mirror = floating.front()->findChild<CodeEditorWidget*>();
            expect(mirror != nullptr && mirror->text() == editor->text(),
                "floating raw mirror preserves original CRLF bytes");
        }
        for (int iteration = 0; iteration < 8; ++iteration)
        {
            host->applyScheme(DetailDisplayScheme::Right);
            host->applyScheme(DetailDisplayScheme::Embedded);
            host->applyScheme(DetailDisplayScheme::BottomCollapsed);
            host->applyScheme(DetailDisplayScheme::Floating);
        }
        drain();
        expect(splitter->count() == 3 && table->rowHeight(0) == originalHeight && table->rowCount() == 2,
            "repeated mode switches do not accumulate geometry or rows");
        expect(page.findChildren<QDialog*>().isEmpty(), "leaving floating strategy destroys old detail dialog");
    }

    void lateConstructionAndCompatibility()
    {
        QWidget page;
        QVBoxLayout layout(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        layout.addWidget(splitter);
        auto* table = new QTableWidget(1, 1, &page);
        auto* editor = new CodeEditorWidget(&page);
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(table, editor, &page, splitter, table, editor);
        expect(host != nullptr && !host->isBound() && host->hasExplicitBinding(),
            "unfinished explicit construction does not infer another ancestor");
        splitter->addWidget(table);
        splitter->addWidget(editor);
        page.show();
        drain();
        expect(host->isBound() && splitter->count() == 3, "late panel mount completes queued binding");
        auto* toggle = toggleButton(&page);
        if (toggle != nullptr)
        {
            toggle->click();
        }
        drain();
        expect(toggle != nullptr && !editor->isHidden(), "late-created toggle is actually connected");

        QWidget hiddenPage;
        QVBoxLayout hiddenLayout(&hiddenPage);
        auto* hiddenSplitter = new QSplitter(Qt::Vertical, &hiddenPage);
        hiddenLayout.addWidget(hiddenSplitter);
        auto* hiddenTable = new QTableWidget(1, 1, hiddenSplitter);
        auto* hiddenEditor = new CodeEditorWidget(hiddenSplitter);
        hiddenSplitter->addWidget(hiddenTable);
        hiddenSplitter->addWidget(hiddenEditor);
        ks::ui::DetailLayoutRegistry::registerHost(
            hiddenTable, hiddenEditor, &hiddenPage, hiddenSplitter, hiddenTable, hiddenEditor);
        drain();
        hiddenPage.show();
        drain();
        expect(hiddenEditor->isHidden(), "hidden lazy page retains collapsed mode when first shown later");

        QWidget legacyPage;
        QVBoxLayout legacyLayout(&legacyPage);
        auto* legacyTable = new QTableWidget(1, 1, &legacyPage);
        auto* legacyEditor = new CodeEditorWidget(&legacyPage);
        legacyLayout.addWidget(legacyTable);
        legacyLayout.addWidget(legacyEditor);
        auto* legacyHost = ks::ui::DetailLayoutRegistry::registerHost(legacyTable, legacyEditor, &legacyPage);
        legacyPage.show();
        drain();
        expect(legacyHost != nullptr && !legacyHost->hasExplicitBinding() && legacyHost->isBound(),
            "old registration remains isolated compatible adapter");
    }

    void modelAndObjectLifetime()
    {
        QWidget page;
        QVBoxLayout layout(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        layout.addWidget(splitter);
        auto* table = new QTableView(splitter);
        auto* editor = new CodeEditorWidget(splitter);
        splitter->addWidget(table);
        splitter->addWidget(editor);
        QStandardItemModel first(2, 1);
        QStandardItemModel second(2, 1);
        table->setModel(&first);
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(table, editor, &page, splitter, table, editor);
        expect(host->bindModel(&second) && table->model() == &second, "generic view explicitly binds replacement model");
        page.resize(700, 500);
        page.show();
        editor->setReadOnly(true);
        editor->setRawText(QStringLiteral("generic view detail"));
        host->applyScheme(DetailDisplayScheme::Embedded);
        table->setCurrentIndex(second.index(0, 0));
        const int genericHeight = table->rowHeight(0);
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, second.index(0, 0)));
        drain();
        expect(table->rowHeight(0) > genericHeight && table->viewport()->findChildren<CodeEditorWidget*>().size() == 1,
            "generic QTableView has visible inline details");
        expect(host->supportsInlineDetails() && host->requestedScheme() == DetailDisplayScheme::Embedded
            && host->effectiveScheme() == DetailDisplayScheme::Embedded, "generic table effective inline contract is explicit");
        host->prepareDataRebuild();
        auto* guardDelegate = new QStyledItemDelegate(table);
        table->setItemDelegate(guardDelegate);
        first.clear();
        drain();
        expect(table->model() == &second && table->itemDelegate() == guardDelegate,
            "old model signals no longer mutate current view");
        second.setData(second.index(0, 0), QStringLiteral("fresh"));
        host->applyScheme(DetailDisplayScheme::Right);
        drain();
        expect(table->model()->data(table->model()->index(0, 0)).toString() == QStringLiteral("fresh")
            && !editor->isHidden(), "new model updates and layout remain live");

        QWidget plainTreePage;
        QVBoxLayout plainTreeLayout(&plainTreePage);
        auto* plainTreeSplitter = new QSplitter(Qt::Vertical, &plainTreePage);
        plainTreeLayout.addWidget(plainTreeSplitter);
        auto* plainTree = new QTreeView(plainTreeSplitter);
        auto* plainTreeEditor = new CodeEditorWidget(plainTreeSplitter);
        plainTreeSplitter->addWidget(plainTree);
        plainTreeSplitter->addWidget(plainTreeEditor);
        plainTree->setModel(&second);
        auto* plainTreeHost = ks::ui::DetailLayoutRegistry::registerHost(plainTree, plainTreeEditor,
            &plainTreePage, plainTreeSplitter, plainTree, plainTreeEditor);
        plainTreePage.show();
        plainTreeHost->applyScheme(DetailDisplayScheme::Embedded);
        drain();
        expect(!plainTreeHost->supportsInlineDetails() && plainTreeHost->requestedScheme() == DetailDisplayScheme::Embedded
            && plainTreeHost->effectiveScheme() == DetailDisplayScheme::Right && !plainTreeEditor->isHidden(),
            "generic tree explicit fallback keeps right detail pane visible");

        // 树明细被删除时先清理行内状态，后续不解引用原 QTreeWidgetItem 裸指针。
        auto* treePage = new QWidget;
        auto* treeLayout = new QVBoxLayout(treePage);
        auto* treeSplitter = new QSplitter(Qt::Vertical, treePage);
        treeLayout->addWidget(treeSplitter);
        auto* tree = new QTreeWidget(treeSplitter);
        tree->setColumnCount(1);
        auto* item = new QTreeWidgetItem(tree, {QStringLiteral("node")});
        auto* treeEditor = new CodeEditorWidget(treeSplitter);
        treeEditor->setReadOnly(true);
        treeEditor->setRawText(QStringLiteral("tree detail"));
        treeSplitter->addWidget(tree);
        treeSplitter->addWidget(treeEditor);
        auto* treeHost = ks::ui::DetailLayoutRegistry::registerHost(tree, treeEditor, treePage, treeSplitter, tree, treeEditor);
        treePage->show();
        treeHost->applyScheme(DetailDisplayScheme::Embedded);
        tree->setCurrentItem(item);
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        drain();
        expect(tree->viewport()->findChildren<CodeEditorWidget*>().size() == 1, "production tree inline detail opens");
        delete tree->takeTopLevelItem(0);
        drain();
        treeHost->prepareDataRebuild();
        expect(tree->viewport()->findChildren<CodeEditorWidget*>().isEmpty(), "tree row deletion safely clears raw node state");
        treeHost->applyScheme(DetailDisplayScheme::Floating);
        new QTreeWidgetItem(tree, {QStringLiteral("second")});
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        drain();
        const QPointer<QDialog> floating = treePage->findChild<QDialog*>();
        expect(!floating.isNull(), "owner lifetime fixture opens actual floating window");
        QPointer<ks::ui::DetailLayoutHost> lifetime(treeHost);
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        delete treePage;
        drain();
        expect(lifetime.isNull() && floating.isNull(), "owner destruction removes window, host and queued callbacks");
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::BottomCollapsed);
        expect(true, "global registry safely prunes destroyed page");
    }

    void replaceViewBindings()
    {
        QWidget page;
        QVBoxLayout root(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        root.addWidget(splitter);
        auto* mainPane = new QWidget(splitter);
        auto* mainLayout = new QVBoxLayout(mainPane);
        auto* oldTable = new QTableWidget(2, 1, mainPane);
        auto* newTable = new QTableWidget(2, 1, mainPane);
        mainLayout->addWidget(oldTable);
        mainLayout->addWidget(newTable);
        newTable->hide();
        auto* editor = new CodeEditorWidget(splitter);
        editor->setReadOnly(true);
        editor->setRawText(QStringLiteral("view detail"));
        splitter->addWidget(mainPane);
        splitter->addWidget(editor);
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(oldTable, editor, &page, splitter, mainPane, editor);
        page.resize(700, 500);
        page.show();
        host->applyScheme(DetailDisplayScheme::Embedded);
        drain();
        const int oldHeight = oldTable->rowHeight(0);
        clickRow(oldTable, 0);
        host->setTableView(newTable);
        oldTable->hide();
        newTable->show();
        drain();
        expect(oldTable->rowHeight(0) == oldHeight, "view replacement restores old table geometry");
        const int newHeight = newTable->rowHeight(0);
        clickRow(newTable, 0);
        expect(newTable->rowHeight(0) > newHeight, "replacement view receives inline interaction");
        oldTable->setRowCount(0);
        drain();
        expect(newTable->rowHeight(0) > newHeight && newTable->viewport()->findChildren<CodeEditorWidget*>().size() == 1,
            "old view model reset cannot clear new view inline details");
        host->prepareDataRebuild();
        expect(newTable->rowHeight(0) == newHeight, "replacement view cleanup restores its own geometry");
    }

    // 生命周期 owner 与视觉根可分别持有；删除 owner 不在 Qt 正在 Show 的控件内删除它自身。
    class RegisterOnShow final : public QObject
    {
    public:
        std::function<void()> callback;
        bool fired = false;

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event->type() == QEvent::Show && !fired)
            {
                fired = true;
                callback();
            }
            return QObject::eventFilter(watched, event);
        }
    };

    // 模拟页面在 Qt 同步通知中切布局；若通知对象也被清理，吞掉该次事件。
    class ReenterOnEvent final : public QObject
    {
    public:
        std::function<bool(QObject*, QEvent*)> matches;
        std::function<void()> callback;
        bool fired = false;

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            const QPointer<QObject> watchedGuard(watched);
            if (!fired && matches(watched, event))
            {
                fired = true;
                callback();
            }
            return watchedGuard.isNull() || QObject::eventFilter(watched, event);
        }
    };

    void synchronousLayoutReentry(const bool floating, const bool closeOwner = false)
    {
        QWidget page;
        page.resize(800, 600);
        QVBoxLayout layout(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        layout.addWidget(splitter);
        auto* table = new QTableWidget(2, 1, splitter);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("one")));
        auto* editor = new CodeEditorWidget(splitter);
        editor->setReadOnly(true);
        editor->setRawText(QStringLiteral("synchronous detail"));
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto lifetimeOwner = std::make_unique<QWidget>();
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(table, editor, lifetimeOwner.get(), splitter, table, editor);
        const QPointer<ks::ui::DetailLayoutHost> hostGuard(host);
        page.show();
        drain();
        host->applyScheme(floating ? DetailDisplayScheme::Floating : DetailDisplayScheme::Embedded);
        drain();
        const int originalHeight = table->rowHeight(0);
        QPointer<CodeEditorWidget> inlineEditor;
        if (!floating)
        {
            clickRow(table, 0);
            inlineEditor = table->viewport()->findChild<CodeEditorWidget*>();
        }
        ReenterOnEvent probe;
        probe.matches = [&](QObject* watched, QEvent* event)
        {
            return floating
                ? event->type() == QEvent::Show && qobject_cast<QDialog*>(watched) != nullptr
                : watched == inlineEditor && event->type() == QEvent::Resize;
        };
        probe.callback = [&]()
        {
            if (closeOwner)
            {
                lifetimeOwner.reset();
            }
            else
            {
                host->applyScheme(DetailDisplayScheme::Right);
            }
        };
        qApp->installEventFilter(&probe);
        if (floating)
        {
            clickRow(table, 0);
        }
        else
        {
            // viewport Resize 会让宿主重排 mirror，mirror Resize 内同步清理其所属布局。
            page.resize(940, 640);
            drain();
        }
        qApp->removeEventFilter(&probe);
        drain();
        expect(probe.fired && (closeOwner ? hostGuard.isNull()
            : hostGuard->effectiveScheme() == DetailDisplayScheme::Right && !editor->isHidden()),
            floating ? "floating Show callback may synchronously switch layout" : "inline geometry callback may synchronously switch layout");
        expect(page.findChildren<QDialog*>().isEmpty() && table->viewport()->findChildren<CodeEditorWidget*>().isEmpty()
            && table->rowHeight(0) == originalHeight,
            floating ? "floating reentry leaves no stale window operations" : "geometry reentry leaves no stale inline operations");
    }

    void registryReentry()
    {
        QWidget visualPage;
        visualPage.resize(700, 500);
        QVBoxLayout layout(&visualPage);
        auto* splitter = new QSplitter(Qt::Vertical, &visualPage);
        layout.addWidget(splitter);
        auto* table = new QTableWidget(1, 1, splitter);
        auto* editor = new CodeEditorWidget(splitter);
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto* lifetimeOwner = new QWidget;
        const QPointer<QWidget> ownerGuard(lifetimeOwner);
        auto* host = ks::ui::DetailLayoutRegistry::registerHost(table, editor, lifetimeOwner, splitter, table, editor);
        const QPointer<ks::ui::DetailLayoutHost> hostGuard(host);
        QWidget secondPage;
        auto* secondLayout = new QVBoxLayout(&secondPage);
        auto* secondSplitter = new QSplitter(Qt::Vertical, &secondPage);
        secondLayout->addWidget(secondSplitter);
        auto* secondTable = new QTableWidget(1, 1, secondSplitter);
        auto* secondEditor = new CodeEditorWidget(secondSplitter);
        secondSplitter->addWidget(secondTable);
        secondSplitter->addWidget(secondEditor);
        ks::ui::DetailLayoutRegistry::registerHost(secondTable, secondEditor, &secondPage,
            secondSplitter, secondTable, secondEditor);
        visualPage.show();
        secondPage.show();
        drain();
        RegisterOnShow probe;
        std::vector<std::unique_ptr<QWidget>> registeredPages;
        QPointer<ks::ui::DetailLayoutHost> registeredHost;
        probe.callback = [&]()
        {
            // 保留多个新页面，强制 live QList 扩容，让旧迭代器问题成为可见结果。
            for (int index = 0; index < 12; ++index)
            {
                auto registeredPage = std::make_unique<QWidget>();
                auto* registeredLayout = new QVBoxLayout(registeredPage.get());
                auto* registeredSplitter = new QSplitter(Qt::Vertical, registeredPage.get());
                registeredLayout->addWidget(registeredSplitter);
                auto* registeredTable = new QTableWidget(1, 1, registeredSplitter);
                auto* registeredEditor = new CodeEditorWidget(registeredSplitter);
                registeredSplitter->addWidget(registeredTable);
                registeredSplitter->addWidget(registeredEditor);
                registeredHost = ks::ui::DetailLayoutRegistry::registerHost(registeredTable, registeredEditor,
                    registeredPage.get(), registeredSplitter, registeredTable, registeredEditor);
                registeredPages.push_back(std::move(registeredPage));
            }
            delete lifetimeOwner;
        };
        editor->installEventFilter(&probe);
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::Right);
        drain();
        expect(probe.fired && ownerGuard.isNull() && hostGuard.isNull(),
            "Show callback may register a page and destroy current lifecycle owner");
        expect(!registeredHost.isNull() && registeredHost->isBound(),
            "reentrant registration remains valid after global layout transaction");
        expect(!secondEditor->isHidden(), "global snapshot still applies the original second page after QList growth");
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::BottomCollapsed);
    }

    void nativeStrategies()
    {
        QWidget page;
        page.resize(850, 620);
        QVBoxLayout root(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        root.addWidget(splitter);
        auto* table = new QTableWidget(2, 1, splitter);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("z")));
        table->setItem(1, 0, new QTableWidgetItem(QStringLiteral("a")));
        auto* editor = new ks::ui::StructuredFieldView(splitter);

        editor->setDocument(nativeDocument(QStringLiteral("source bytes\r\n0x1234")));
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto* host = ks::ui::DetailLayoutRegistry::registerStructuredHost(table, editor, &page, splitter, table, editor);
        page.show();
        drain();
        expect(host != nullptr && host->hasExplicitBinding() && host->isBound(), "native explicit two panel contract bound");
        expect(splitter->count() == 3 && splitter->widget(0) == table && splitter->widget(2) == editor,
            "host only inserts toggle between declared panels");
        expect(ks::ui::DetailLayoutRegistry::registerStructuredHost(table, editor, &page, splitter, table, editor) == host,
            "native explicit registry reuses same host");
        expect(splitter->count() == 3, "repeat registration does not duplicate layout controls");
        expect(!host->bindPanels({splitter, table, table}), "same main and detail panel rejected");
        expect(host->isBound(), "invalid rebinding preserves existing layout");
        expect(editor->isHidden(), "bottom starts collapsed");
        QToolButton* const toggle = toggleButton(&page);
        expect(toggle != nullptr, "production bottom toggle exists");
        if (toggle != nullptr)
        {
            toggle->click();
            drain();
            expect(!editor->isHidden(), "actual bottom toggle expands detail");
            host->applyScheme(DetailDisplayScheme::BottomCollapsed);
            expect(!editor->isHidden(), "same scheme preserves user expansion");
            toggle->click();
            drain();
            expect(editor->isHidden(), "actual bottom toggle collapses detail");
        }

        host->applyScheme(DetailDisplayScheme::Right);
        drain();
        expect(splitter->orientation() == Qt::Horizontal && !editor->isHidden(), "right strategy uses declared panels");
        QAbstractItemDelegate* const sourceDelegate = table->itemDelegate();
        const int originalHeight = table->rowHeight(0);
        host->applyScheme(DetailDisplayScheme::Embedded);
        clickRow(table, 0);
        expect(table->rowCount() == 2 && table->rowHeight(0) > originalHeight,
            "native inline expands source geometry without inserting business row");
        expect(table->itemDelegate() != sourceDelegate, "native inline installs production delegate wrapper");
        auto mirrors = table->viewport()->findChildren<ks::ui::StructuredFieldView*>();
        expect(mirrors.size() == 1 && mirrors.front()->document().toPlainText() == editor->document().toPlainText(),
            "native inline raw mirror retains source bytes and mode");
        editor->setDocument(nativeDocument(QStringLiteral("updated native value")));
        drain();
        mirrors = table->viewport()->findChildren<ks::ui::StructuredFieldView*>();
        expect(mirrors.size() == 1 && mirrors.front()->document().toPlainText() == editor->document().toPlainText(),
            "native inline clone updates from canonical document signal");
        expect(table->rowCount() == 2, "native document update leaves source row count unchanged");
        table->sortItems(0, Qt::AscendingOrder);
        drain();
        if (table->rowHeight(0) != originalHeight || table->rowHeight(1) != originalHeight)
        {
            std::printf("DETAIL_PANE_HEIGHTS=original:%d first:%d second:%d\n",
                originalHeight, table->rowHeight(0), table->rowHeight(1));
        }
        expect(table->rowHeight(0) == originalHeight && table->rowHeight(1) == originalHeight,
            "sorting restores geometry before persistent indices move");
        expect(table->itemDelegate() == sourceDelegate, "sorting restores existing source delegate");

        clickRow(table, 0);
        auto* replacementDelegate = new QStyledItemDelegate(table);
        table->setItemDelegate(replacementDelegate);
        host->prepareDataRebuild();
        drain();
        expect(table->itemDelegate() == replacementDelegate, "cleanup preserves delegate replaced by business page");
        expect(table->rowHeight(0) == originalHeight, "native explicit rebuild restores row height");

        // 同模型同维度的原地重建也必须取消已经排队的点击，不能重新展开旧详情。
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, table->model()->index(0, 0)));
        host->prepareDataRebuild();
        table->item(0, 0)->setText(QStringLiteral("same model refreshed"));
        drain();
        expect(table->viewport()->findChildren<ks::ui::StructuredFieldView*>().isEmpty()
            && table->rowHeight(0) == originalHeight, "in place rebuild cancels queued old inline click");
        host->prepareDataRebuild();

        // 在 queued 点击到达前切模式，旧任务不得再插入行内编辑器或打开窗口。
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, table->model()->index(0, 0)));
        host->applyScheme(DetailDisplayScheme::BottomCollapsed);
        drain();
        expect(table->viewport()->findChildren<ks::ui::StructuredFieldView*>().isEmpty(), "stale queued inline click canceled on scheme change");
        editor->setDocument(nativeDocument(QStringLiteral("untranslated user code\r\nPid: 42")));
        editor->setSearchText(QStringLiteral("Name"));
        editor->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
        const QString canonical = editor->document().toPlainText();
        host->applyScheme(DetailDisplayScheme::Floating);
        clickRow(table, 0);
        expect(editor->document().toPlainText() == canonical, "native view presentation cannot change field data");
        const auto floating = page.findChildren<QDialog*>();
        expect(floating.size() == 1 && floating.front()->isVisible(), "native floating strategy opens one production dialog");
        if (!floating.isEmpty())
        {
            auto* mirror = floating.front()->findChild<ks::ui::StructuredFieldView*>();
            expect(mirror != nullptr && mirror->document().toPlainText() == editor->document().toPlainText(),
                "native floating clone retains canonical nested fields");
            editor->setDocument(nativeDocument(QStringLiteral("floating updated value")));
            drain();
            expect(mirror != nullptr && mirror->document().toPlainText() == editor->document().toPlainText(),
                "native floating clone updates from canonical document signal");
        }
        for (int iteration = 0; iteration < 8; ++iteration)
        {
            host->applyScheme(DetailDisplayScheme::Right);
            host->applyScheme(DetailDisplayScheme::Embedded);
            host->applyScheme(DetailDisplayScheme::BottomCollapsed);
            host->applyScheme(DetailDisplayScheme::Floating);
        }
        drain();
        expect(splitter->count() == 3 && table->rowHeight(0) == originalHeight && table->rowCount() == 2,
            "repeated mode switches do not accumulate geometry or rows");
        expect(page.findChildren<QDialog*>().isEmpty(), "leaving floating strategy destroys old detail dialog");
    }

    void nativeModelAndObjectLifetime()
    {
        QWidget page;
        QVBoxLayout layout(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        layout.addWidget(splitter);
        auto* table = new QTableView(splitter);
        auto* editor = new ks::ui::StructuredFieldView(splitter);
        splitter->addWidget(table);
        splitter->addWidget(editor);
        QStandardItemModel first(2, 1);
        QStandardItemModel second(2, 1);
        table->setModel(&first);
        auto* host = ks::ui::DetailLayoutRegistry::registerStructuredHost(table, editor, &page, splitter, table, editor);
        expect(host->bindModel(&second) && table->model() == &second, "generic view explicitly binds replacement model");
        page.resize(700, 500);
        page.show();

        editor->setDocument(nativeDocument(QStringLiteral("generic view detail")));
        host->applyScheme(DetailDisplayScheme::Embedded);
        table->setCurrentIndex(second.index(0, 0));
        const int genericHeight = table->rowHeight(0);
        QMetaObject::invokeMethod(table, "clicked", Q_ARG(QModelIndex, second.index(0, 0)));
        drain();
        expect(table->rowHeight(0) > genericHeight && table->viewport()->findChildren<ks::ui::StructuredFieldView*>().size() == 1,
            "generic QTableView has visible inline details");
        expect(host->supportsInlineDetails() && host->requestedScheme() == DetailDisplayScheme::Embedded
            && host->effectiveScheme() == DetailDisplayScheme::Embedded, "generic table effective inline contract is explicit");
        host->prepareDataRebuild();
        auto* guardDelegate = new QStyledItemDelegate(table);
        table->setItemDelegate(guardDelegate);
        first.clear();
        drain();
        expect(table->model() == &second && table->itemDelegate() == guardDelegate,
            "old model signals no longer mutate current view");
        second.setData(second.index(0, 0), QStringLiteral("fresh"));
        host->applyScheme(DetailDisplayScheme::Right);
        drain();
        expect(table->model()->data(table->model()->index(0, 0)).toString() == QStringLiteral("fresh")
            && !editor->isHidden(), "new model updates and layout remain live");

        QWidget plainTreePage;
        QVBoxLayout plainTreeLayout(&plainTreePage);
        auto* plainTreeSplitter = new QSplitter(Qt::Vertical, &plainTreePage);
        plainTreeLayout.addWidget(plainTreeSplitter);
        auto* plainTree = new QTreeView(plainTreeSplitter);
        auto* plainTreeEditor = new ks::ui::StructuredFieldView(plainTreeSplitter);
        plainTreeSplitter->addWidget(plainTree);
        plainTreeSplitter->addWidget(plainTreeEditor);
        plainTree->setModel(&second);
        auto* plainTreeHost = ks::ui::DetailLayoutRegistry::registerStructuredHost(plainTree, plainTreeEditor,
            &plainTreePage, plainTreeSplitter, plainTree, plainTreeEditor);
        plainTreePage.show();
        plainTreeHost->applyScheme(DetailDisplayScheme::Embedded);
        drain();
        expect(!plainTreeHost->supportsInlineDetails() && plainTreeHost->requestedScheme() == DetailDisplayScheme::Embedded
            && plainTreeHost->effectiveScheme() == DetailDisplayScheme::Right && !plainTreeEditor->isHidden(),
            "generic tree explicit fallback keeps right detail pane visible");

        // 树明细被删除时先清理行内状态，后续不解引用原 QTreeWidgetItem 裸指针。
        auto* treePage = new QWidget;
        auto* treeLayout = new QVBoxLayout(treePage);
        auto* treeSplitter = new QSplitter(Qt::Vertical, treePage);
        treeLayout->addWidget(treeSplitter);
        auto* tree = new QTreeWidget(treeSplitter);
        tree->setColumnCount(1);
        auto* item = new QTreeWidgetItem(tree, {QStringLiteral("node")});
        auto* treeEditor = new ks::ui::StructuredFieldView(treeSplitter);

        treeEditor->setDocument(nativeDocument(QStringLiteral("tree detail")));
        treeSplitter->addWidget(tree);
        treeSplitter->addWidget(treeEditor);
        auto* treeHost = ks::ui::DetailLayoutRegistry::registerStructuredHost(tree, treeEditor, treePage, treeSplitter, tree, treeEditor);
        treePage->show();
        treeHost->applyScheme(DetailDisplayScheme::Embedded);
        tree->setCurrentItem(item);
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        drain();
        expect(tree->viewport()->findChildren<ks::ui::StructuredFieldView*>().size() == 1, "production tree inline detail opens");
        delete tree->takeTopLevelItem(0);
        drain();
        treeHost->prepareDataRebuild();
        expect(tree->viewport()->findChildren<ks::ui::StructuredFieldView*>().isEmpty(), "tree row deletion safely clears raw node state");
        treeHost->applyScheme(DetailDisplayScheme::Floating);
        new QTreeWidgetItem(tree, {QStringLiteral("second")});
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        drain();
        const QPointer<QDialog> floating = treePage->findChild<QDialog*>();
        expect(!floating.isNull(), "owner lifetime fixture opens actual floating window");
        QPointer<ks::ui::DetailLayoutHost> lifetime(treeHost);
        QMetaObject::invokeMethod(tree, "clicked", Q_ARG(QModelIndex, tree->model()->index(0, 0)));
        delete treePage;
        drain();
        expect(lifetime.isNull() && floating.isNull(), "owner destruction removes window, host and queued callbacks");
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::BottomCollapsed);
        expect(true, "global registry safely prunes destroyed page");
    }

    void nativeSynchronousLayoutReentry(const bool floating, const bool closeOwner = false)
    {
        QWidget page;
        page.resize(800, 600);
        QVBoxLayout layout(&page);
        auto* splitter = new QSplitter(Qt::Vertical, &page);
        layout.addWidget(splitter);
        auto* table = new QTableWidget(2, 1, splitter);
        table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("one")));
        auto* editor = new ks::ui::StructuredFieldView(splitter);

        editor->setDocument(nativeDocument(QStringLiteral("synchronous detail")));
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto lifetimeOwner = std::make_unique<QWidget>();
        auto* host = ks::ui::DetailLayoutRegistry::registerStructuredHost(table, editor, lifetimeOwner.get(), splitter, table, editor);
        const QPointer<ks::ui::DetailLayoutHost> hostGuard(host);
        page.show();
        drain();
        host->applyScheme(floating ? DetailDisplayScheme::Floating : DetailDisplayScheme::Embedded);
        drain();
        const int originalHeight = table->rowHeight(0);
        QPointer<ks::ui::StructuredFieldView> inlineEditor;
        if (!floating)
        {
            clickRow(table, 0);
            inlineEditor = table->viewport()->findChild<ks::ui::StructuredFieldView*>();
        }
        ReenterOnEvent probe;
        probe.matches = [&](QObject* watched, QEvent* event)
        {
            return floating
                ? event->type() == QEvent::Show && qobject_cast<QDialog*>(watched) != nullptr
                : watched == inlineEditor && event->type() == QEvent::Resize;
        };
        probe.callback = [&]()
        {
            if (closeOwner)
            {
                lifetimeOwner.reset();
            }
            else
            {
                host->applyScheme(DetailDisplayScheme::Right);
            }
        };
        qApp->installEventFilter(&probe);
        if (floating)
        {
            clickRow(table, 0);
        }
        else
        {
            // viewport Resize 会让宿主重排 mirror，mirror Resize 内同步清理其所属布局。
            page.resize(940, 640);
            drain();
        }
        qApp->removeEventFilter(&probe);
        drain();
        expect(probe.fired && (closeOwner ? hostGuard.isNull()
            : hostGuard->effectiveScheme() == DetailDisplayScheme::Right && !editor->isHidden()),
            floating ? "native floating Show callback may synchronously switch layout" : "native inline geometry callback may synchronously switch layout");
        expect(page.findChildren<QDialog*>().isEmpty() && table->viewport()->findChildren<ks::ui::StructuredFieldView*>().isEmpty()
            && table->rowHeight(0) == originalHeight,
            floating ? "native floating reentry leaves no stale window operations" : "geometry reentry leaves no stale inline operations");
    }

    void nativeRegistryReentry()
    {
        QWidget visualPage;
        visualPage.resize(700, 500);
        QVBoxLayout layout(&visualPage);
        auto* splitter = new QSplitter(Qt::Vertical, &visualPage);
        layout.addWidget(splitter);
        auto* table = new QTableWidget(1, 1, splitter);
        auto* editor = new ks::ui::StructuredFieldView(splitter);
        splitter->addWidget(table);
        splitter->addWidget(editor);
        auto* lifetimeOwner = new QWidget;
        const QPointer<QWidget> ownerGuard(lifetimeOwner);
        auto* host = ks::ui::DetailLayoutRegistry::registerStructuredHost(table, editor, lifetimeOwner, splitter, table, editor);
        const QPointer<ks::ui::DetailLayoutHost> hostGuard(host);
        QWidget secondPage;
        auto* secondLayout = new QVBoxLayout(&secondPage);
        auto* secondSplitter = new QSplitter(Qt::Vertical, &secondPage);
        secondLayout->addWidget(secondSplitter);
        auto* secondTable = new QTableWidget(1, 1, secondSplitter);
        auto* secondEditor = new ks::ui::StructuredFieldView(secondSplitter);
        secondSplitter->addWidget(secondTable);
        secondSplitter->addWidget(secondEditor);
        ks::ui::DetailLayoutRegistry::registerStructuredHost(secondTable, secondEditor, &secondPage,
            secondSplitter, secondTable, secondEditor);
        visualPage.show();
        secondPage.show();
        drain();
        RegisterOnShow probe;
        std::vector<std::unique_ptr<QWidget>> registeredPages;
        QPointer<ks::ui::DetailLayoutHost> registeredHost;
        probe.callback = [&]()
        {
            // 保留多个新页面，强制 live QList 扩容，让旧迭代器问题成为可见结果。
            for (int index = 0; index < 12; ++index)
            {
                auto registeredPage = std::make_unique<QWidget>();
                auto* registeredLayout = new QVBoxLayout(registeredPage.get());
                auto* registeredSplitter = new QSplitter(Qt::Vertical, registeredPage.get());
                registeredLayout->addWidget(registeredSplitter);
                auto* registeredTable = new QTableWidget(1, 1, registeredSplitter);
                auto* registeredEditor = new ks::ui::StructuredFieldView(registeredSplitter);
                registeredSplitter->addWidget(registeredTable);
                registeredSplitter->addWidget(registeredEditor);
                registeredHost = ks::ui::DetailLayoutRegistry::registerStructuredHost(registeredTable, registeredEditor,
                    registeredPage.get(), registeredSplitter, registeredTable, registeredEditor);
                registeredPages.push_back(std::move(registeredPage));
            }
            delete lifetimeOwner;
        };
        editor->installEventFilter(&probe);
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::Right);
        drain();
        expect(probe.fired && ownerGuard.isNull() && hostGuard.isNull(),
            "Show callback may register a page and destroy current lifecycle owner");
        expect(!registeredHost.isNull() && registeredHost->isBound(),
            "reentrant registration remains valid after global layout transaction");
        expect(!secondEditor->isHidden(), "global snapshot still applies the original second page after QList growth");
        ks::ui::DetailLayoutRegistry::applyGlobalScheme(DetailDisplayScheme::BottomCollapsed);
    }
}

int main(int argc, char* argv[])
{
    // 崩溃探针也保留已经完成的断言，不能因 stdout 缓冲丢掉失败前证据。
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    QApplication application(argc, argv);
    application.setQuitOnLastWindowClosed(false);
    if (argc > 1 && QString::fromUtf8(argv[1]) == QStringLiteral("--registry-reentry-only"))
    {
        registryReentry();
        std::printf("DETAIL_PANE_REENTRY_CHECKS=%d\nDETAIL_PANE_FAILURES=%d\n", checks, failures);
        return failures == 0 ? 0 : 1;
    }
    if (argc > 1 && (QString::fromUtf8(argv[1]) == QStringLiteral("--floating-reentry-only")
        || QString::fromUtf8(argv[1]) == QStringLiteral("--geometry-reentry-only")
        || QString::fromUtf8(argv[1]) == QStringLiteral("--ownerclose-reentry-only")))
    {
        synchronousLayoutReentry(QString::fromUtf8(argv[1]) == QStringLiteral("--floating-reentry-only"),
            QString::fromUtf8(argv[1]) == QStringLiteral("--ownerclose-reentry-only"));
        std::printf("DETAIL_PANE_TRANSACTION_CHECKS=%d\nDETAIL_PANE_FAILURES=%d\n", checks, failures);
        return failures == 0 ? 0 : 1;
    }
    nativeStrategies();
    nativeModelAndObjectLifetime();
    nativeRegistryReentry();
    nativeSynchronousLayoutReentry(true);
    nativeSynchronousLayoutReentry(false);
    nativeSynchronousLayoutReentry(false, true);
    explicitStrategies();
    lateConstructionAndCompatibility();
    modelAndObjectLifetime();
    replaceViewBindings();
    registryReentry();
    synchronousLayoutReentry(true);
    synchronousLayoutReentry(false);
    synchronousLayoutReentry(false, true);
    drain();
    std::printf("DETAIL_PANE_CHECKS=%d\nDETAIL_PANE_FAILURES=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
