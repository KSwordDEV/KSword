#include "MemoryDock.Internal.h"
#include "../UI/TableContextMenu.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/X64DbgNavigation.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h" // AcquireAnchorForPid：与工作台锚点同一取法读进程创建时间。

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QPersistentModelIndex>
#include <QTableView>
#include <QTreeView>
#include <QImage>
#include <QPixmap>
#include <QRunnable>
#include <QSaveFile>
#include <QSet>
#include <QTimer>
#include <QThread> // QThread::idealThreadCount：CPU 占用率的分母要按逻辑核数归一化。
#include <QVector>

#include <algorithm> // std::clamp / std::max：占用率夹取与核数下界。
#include <functional>
#include <memory>
#include <utility>

#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.ProcessRegion.cpp
// 作用：
// - 负责进程列表、模块列表、内存区域枚举与过滤展示。
// - 聚焦“附加目标与地址空间概览”能力。
// ============================================================

namespace
{
    // processRegionTableRowText 作用：
    // - 输入：MemoryDock 进程/区域等普通表格和行号；
    // - 处理：按列顺序读取整行文本，隐藏列也保留，方便复制 PID/Session 上下文；
    // - 返回：TSV 文本，行无效时返回空字符串。
    QString processRegionTableRowText(QTableView* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || (!table->model() || rowIndex >= table->model()->rowCount()))
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->model()->columnCount());
        for (int columnIndex = 0; columnIndex < table->model()->columnCount(); ++columnIndex)
        {
            fields.push_back(table->model()->index(rowIndex, columnIndex).data(Qt::DisplayRole).toString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // copyProcessRegionTableRow 作用：
    // - 输入：目标表格和行号；
    // - 处理：把整行 TSV 写入系统剪贴板；
    // - 返回：无，剪贴板不可用或行无效时直接返回。
    void copyProcessRegionTableRow(QTableView* table, const int rowIndex)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const QString rowText = processRegionTableRowText(table, rowIndex);
        if (!rowText.isEmpty())
        {
            QApplication::clipboard()->setText(rowText);
        }
    }

    // ============================================================
    // 异步刷新状态寄存
    // 说明：本轮改造不扩充 MemoryDock.h 的成员，刷新代次/在途标记全部寄存在
    // MemoryDock 对象自身的动态属性上。动态属性只在 UI 线程读写，且随控件析构
    // 一起释放，不会像“按实例地址索引的文件级静态表”那样泄漏或串号。
    // ============================================================

    // 进程列表刷新代次：每提交一次后台枚举自增一次，回投结果按它淘汰过期快照。
    constexpr const char* kProcessRefreshGenerationProperty = "kswordMemoryProcessRefreshGeneration";
    // 进程列表刷新是否在途：在途期间新请求只合并成待办，不叠加第二次 Toolhelp 快照。
    constexpr const char* kProcessRefreshInFlightProperty = "kswordMemoryProcessRefreshInFlight";
    // 进程列表是否存在待补刷新，以及该待补请求是否要求保留当前选择。
    constexpr const char* kProcessRefreshPendingProperty = "kswordMemoryProcessRefreshPending";
    constexpr const char* kProcessRefreshPendingKeepSelectionProperty =
        "kswordMemoryProcessRefreshPendingKeepSelection";
    // 跨页跳转登记的待定位 PID：进程表由异步结果重建，定位只能等回填后再做。
    constexpr const char* kProcessFocusPendingPidProperty = "kswordMemoryProcessFocusPendingPid";
    // 区域枚举是否在途，以及是否存在待补的区域刷新请求。
    constexpr const char* kRegionRefreshInFlightProperty = "kswordMemoryRegionRefreshInFlight";
    constexpr const char* kRegionRefreshPendingProperty = "kswordMemoryRegionRefreshPending";
    // 本次区域刷新是否由附加流程发起：附加按钮必须立即还控制权，禁止同步遍历地址空间。
    constexpr const char* kRegionRefreshFromAttachProperty = "kswordMemoryRegionRefreshFromAttach";
    constexpr const char* kProcessDumpInFlightProperty = "ksword_memory_process_dump_in_flight";

    // 图标路径角色：进程表第 0 列与模块树路径列都用它记录图标来源路径，
    // 后台提取完成后按路径反查需要刷新的行。UserRole/UserRole+1 已被其它数据占用。
    constexpr int kIconPathItemRole = Qt::UserRole + 2;

    // readBoolProperty 作用：
    // - 输入：属性宿主对象与属性名；
    // - 处理：读取布尔动态属性，属性未设置时按 false 处理；
    // - 返回：属性当前布尔值。
    bool readBoolProperty(const QObject* const propertyOwner, const char* const propertyName)
    {
        return propertyOwner != nullptr && propertyOwner->property(propertyName).toBool();
    }

    // bumpGenerationProperty 作用：
    // - 输入：属性宿主对象与代次属性名；
    // - 处理：把代次自增一次并写回，只允许 UI 线程调用；
    // - 返回：本次请求应携带的新代次。
    quint64 bumpGenerationProperty(QObject* const propertyOwner, const char* const propertyName)
    {
        const quint64 nextGeneration = propertyOwner->property(propertyName).toULongLong() + 1ULL;
        propertyOwner->setProperty(propertyName, QVariant::fromValue(nextGeneration));
        return nextGeneration;
    }

    // ============================================================
    // 图标异步解析
    // 说明：QIcon/QPixmap/QFileIconProvider 只能在 UI 线程使用，工作线程一律
    // 只产出可跨线程搬运的 QImage，落地成 QIcon 与写回表格都回到 UI 线程执行。
    // ============================================================

    // pathIconCache 作用：
    // - 输入：无；
    // - 处理：提供按绝对路径索引的图标缓存，只允许 UI 线程访问；
    // - 返回：进程与模块共用的缓存引用。
    QHash<QString, QIcon>& pathIconCache()
    {
        static QHash<QString, QIcon> iconCacheByPath;
        return iconCacheByPath;
    }

    // IconApplyCallback：图标落地后在 UI 线程执行的回写动作（入参为路径与已构造图标）。
    using IconApplyCallback = std::function<void(const QString&, const QIcon&)>;

    // pathIconWaiterTable 作用：
    // - 输入：无；
    // - 处理：记录每个在途路径的回写等待者，同路径按所属视图覆盖旧回写订阅，
    //   不重复向 Shell 发起查询（多个 MemoryDock 实例共存时同样成立）；
    // - 返回：等待表引用，只允许 UI 线程访问。
    QHash<QString, QHash<QObject*, IconApplyCallback>>& pathIconWaiterTable()
    {
        static QHash<QString, QHash<QObject*, IconApplyCallback>> waiterTableByPath;
        return waiterTableByPath;
    }

    // fallbackPathIcon 作用：
    // - 输入：无；
    // - 处理：提供图标尚未解析或解析失败时使用的占位图标；
    // - 返回：共享占位图标引用。
    const QIcon& fallbackPathIcon()
    {
        static const QIcon placeholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return placeholderIcon;
    }

    // extractShellIconImageFromPath 作用：
    // - 输入：可执行文件或模块的绝对路径；
    // - 处理：在工作线程向 Windows Shell 查询小图标并复制成独立位图；
    // - 返回：解析成功返回 QImage，失败返回空 QImage。
    QImage extractShellIconImageFromPath(const QString& absolutePath)
    {
        // shellFileInfo 持有 Shell 分配的 HICON，转换成 QImage 后必须显式销毁。
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(absolutePath.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (shellQueryResult == 0 || shellFileInfo.hIcon == nullptr)
        {
            return QImage();
        }

        QImage iconImage = QImage::fromHICON(shellFileInfo.hIcon);
        ::DestroyIcon(shellFileInfo.hIcon);
        return iconImage;
    }

    // lookupCachedPathIcon 作用：
    // - 输入：绝对路径；
    // - 处理：只查缓存，绝不触发任何磁盘或 Shell 查询，保证建表阶段零阻塞；
    // - 返回：命中返回缓存图标，未命中返回占位图标。
    QIcon lookupCachedPathIcon(const QString& absolutePath)
    {
        const QString normalizedPath = absolutePath.trimmed();
        if (normalizedPath.isEmpty())
        {
            return fallbackPathIcon();
        }

        const auto cachedIt = pathIconCache().constFind(normalizedPath);
        if (cachedIt != pathIconCache().constEnd())
        {
            return cachedIt.value();
        }
        return fallbackPathIcon();
    }

    // queuePathIconExtraction 作用：
    // - 输入：绝对路径与图标落地后的 UI 线程回写动作；
    // - 处理：缓存未命中时提交线程池任务做 Shell 查询，同路径并发请求合并成一个任务；
    // - 返回：无，回写动作只会在 UI 线程被调用一次。
    void queuePathIconExtraction(const QString& absolutePath, QObject* owner, IconApplyCallback applyIconOnUiThread)
    {
        const QString normalizedPath = absolutePath.trimmed();
        if (normalizedPath.isEmpty() || pathIconCache().contains(normalizedPath))
        {
            return;
        }

        auto waiterIt = pathIconWaiterTable().find(normalizedPath);
        if (waiterIt != pathIconWaiterTable().end())
        {
            waiterIt.value().insert(owner, std::move(applyIconOnUiThread));
            return;
        }
        pathIconWaiterTable().insert(
            normalizedPath,
            QHash<QObject*, IconApplyCallback>{{owner, std::move(applyIconOnUiThread)}});

        QRunnable* const extractionTask = QRunnable::create([normalizedPath]() {
            QImage iconImage = extractShellIconImageFromPath(normalizedPath);
            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                appInstance,
                [normalizedPath, iconImage = std::move(iconImage)]() mutable {
                    // QPixmap/QIcon 构造推迟到这里，确保只发生在 UI 线程。
                    QIcon resolvedIcon = fallbackPathIcon();
                    if (!iconImage.isNull())
                    {
                        const QPixmap iconPixmap = QPixmap::fromImage(iconImage);
                        if (!iconPixmap.isNull())
                        {
                            resolvedIcon = QIcon(iconPixmap);
                        }
                    }
                    pathIconCache().insert(normalizedPath, resolvedIcon);

                    const QHash<QObject*, IconApplyCallback> waiterList =
                        pathIconWaiterTable().take(normalizedPath);
                    for (const IconApplyCallback& waiterCallback : waiterList)
                    {
                        waiterCallback(normalizedPath, resolvedIcon);
                    }
                },
                Qt::QueuedConnection);
            });
        extractionTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(extractionTask);
    }

    // Stable persistent indexes avoid a full view scan for every cold icon.
    // One controller/subscription per view+path, regardless of filter rebuilds.
    class PathIconProjection final : public QObject {
    public:
        explicit PathIconProjection(QAbstractItemView* view) : QObject(view), view(view) {
            timer = new QTimer(this); timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this] { flush(); });
            view->installEventFilter(this);
        }
        ~PathIconProjection() override { unsubscribe(); }
        void reset(int column) {
            unsubscribe(); ++generation; timer->stop(); this->column = column;
            rows.clear(); requests.clear(); pending.clear(); deliveredIcons.clear();
        }
        void add(const QModelIndex& index, const QString& path) {
            if (!path.isEmpty() && index.isValid()) { const QPersistentModelIndex identity(index); auto& matches = rows[path]; if (!matches.contains(identity)) { matches.push_back(identity); } }
        }
        void watch(const QString& path) {
            if (path.isEmpty() || !rows.contains(path)) { return; }
            requests.insert(path); schedule();
        }
    protected:
        bool eventFilter(QObject*, QEvent* event) override {
            if (event->type() == QEvent::Show) { schedule(); }
            else if (event->type() == QEvent::Hide) { timer->stop(); }
            return false;
        }
    private:
        void unsubscribe() {
            for (const auto& path : subscriptions) {
                auto found = pathIconWaiterTable().find(path);
                if (found != pathIconWaiterTable().end()) { found.value().remove(this); }
            }
            subscriptions.clear();
        }
        void schedule() {
            if (view && view->isVisible() && (!requests.isEmpty() || !pending.isEmpty()) && !timer->isActive()) { timer->start(0); }
        }
        void flush() {
            if (!view || !view->isVisible()) { return; }
            const QPointer<PathIconProjection> self(this);
            const auto revision = generation;
            int cells = 0;
            QElapsedTimer budget; budget.start();
            for (int count = 0; !requests.isEmpty() && count < 16 && budget.elapsed() < 5; ++count) {
                const auto path = *requests.constBegin(); requests.remove(path);
                if (pathIconCache().contains(path)) { pending.insert(path, 0); continue; }
                subscriptions.insert(path);
                queuePathIconExtraction(path, this, [guard = QPointer<PathIconProjection>(this), revision](const QString& path, const QIcon&) {
                    if (!guard || guard->generation != revision) { return; }
                    guard->subscriptions.remove(path); guard->pending.insert(path, 0); guard->schedule();
                });
            }
            const auto apply = [this, self, revision, &cells](const QModelIndex& index) {
                if (!index.isValid()) { return true; }
                const auto path = index.data(kIconPathItemRole).toString();
                if (!pending.contains(path)) { return true; }
                const auto cached = pathIconCache().constFind(path);
                if (cached == pathIconCache().constEnd()) { return true; }
                if (dynamic_cast<ks::memory_detail::CoreReadOnlyModel*>(view->model())
                    ? deliveredIcons.value(QPersistentModelIndex(index), 0) != cached.value().cacheKey()
                    : index.data(Qt::DecorationRole).value<QIcon>().cacheKey() != cached.value().cacheKey()) {
                    if (dynamic_cast<ks::memory_detail::CoreReadOnlyModel*>(view->model())) { deliveredIcons.insert(QPersistentModelIndex(index), cached.value().cacheKey()); }
                    ++cells;
                    view->model()->setData(index, cached.value(), Qt::DecorationRole);
                }
                return self && self->generation == revision;
            };
            // Visible rows get their icons first; remaining exact path matches
            // drain below under the same time/cell budget.
            if (auto* table = qobject_cast<QTableView*>(view.data())) {
                const int first = qMax(0, table->rowAt(0));
                int last = table->rowAt(table->viewport()->height() - 1);
                if (last < 0) { last = qMin(table->model()->rowCount() - 1, first + 128); }
                for (int row = first; row <= last && cells < 256 && budget.elapsed() < 5; ++row) {
                    if (!apply(table->model()->index(row, column))) { return; }
                }
            } else if (auto* tree = qobject_cast<QTreeView*>(view.data())) {
                auto index = tree->indexAt(QPoint(1, 1));
                if (!index.isValid()) { index = tree->model()->index(0, 0); }
                for (int count = 0; index.isValid() && count < 128 && cells < 256 && budget.elapsed() < 5; ++count) {
                    if (tree->visualRect(index).top() >= tree->viewport()->height()) { break; }
                    if (!apply(index.siblingAtColumn(column))) { return; }
                    index = tree->indexBelow(index);
                }
            }
            for (int count = 0; !pending.isEmpty() && count < 256 && cells < 256 && budget.elapsed() < 5; ++count) {
                auto current = pending.begin();
                const auto found = rows.constFind(current.key());
                if (found == rows.constEnd() || current.value() >= found.value().size()) { pending.erase(current); continue; }
                const QPersistentModelIndex index = found.value()[current.value()++];
                if (!apply(index)) { return; }
            }
            schedule();
        }
        QPointer<QAbstractItemView> view;
        QTimer* timer = nullptr;
        QHash<QString, QVector<QPersistentModelIndex>> rows;
        QSet<QString> requests, subscriptions;
        QHash<QString, qsizetype> pending;
        QHash<QPersistentModelIndex, quint64> deliveredIcons;
        quint64 generation = 0;
        int column = 0;
    };

    PathIconProjection* pathIconProjection(QAbstractItemView* view)
    {
        constexpr const char* property = "ksword_path_icon_projection";
        if (auto* current = static_cast<PathIconProjection*>(view->property(property).value<void*>())) { return current; }
        auto* current = new PathIconProjection(view);
        view->setProperty(property, QVariant::fromValue(static_cast<void*>(current)));
        return current;
    }

    class CoreProjectionObserver final : public QObject {
    public:
        CoreProjectionObserver(QAbstractItemView* view, std::function<void(bool)> request, bool icons)
            : QObject(view), view(view), request(std::move(request)), icons(icons) {
            timer = new QTimer(this); timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this] { demandVisibleIcons(); });
            view->installEventFilter(this); view->viewport()->installEventFilter(this);
            connect(view->verticalScrollBar(), &QScrollBar::valueChanged, this, [this] { schedule(); });
        }
    protected:
        bool eventFilter(QObject* watched, QEvent* event) override {
            const QPointer<CoreProjectionObserver> alive(this);
            if (watched == view && event->type() == QEvent::Show) { request(false); }
            if (!alive || !view) { return false; }
            if (watched == view && event->type() == QEvent::LanguageChange) {
                if (auto* model = dynamic_cast<ks::memory_detail::CoreReadOnlyModel*>(view->model())) { model->refreshHeaders(); }
                if (!alive || !view) { return false; }
                request(true);
            }
            if (!alive || !view) { return false; }
            if (watched == view && (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange)) {
                if (auto* model = dynamic_cast<ks::memory_detail::CoreReadOnlyModel*>(view->model())) {
                    const auto top = view->indexAt(QPoint(0, 0));
                    if (top.isValid()) { model->refreshColors(top.row(), qMin(model->rowCount() - 1, top.row() + 255)); }
                }
            }
            if (!alive || !view) { return false; }
            if (event->type() == QEvent::Paint || event->type() == QEvent::Show || event->type() == QEvent::Resize) { schedule(); }
            return false;
        }
    private:
        void schedule() { if (icons && view && view->isVisible() && !timer->isActive()) { timer->start(0); } }
        void demandVisibleIcons() {
            if (!icons || !view || !view->isVisible()) { return; }
            const QPointer<CoreProjectionObserver> alive(this);
            auto* model = dynamic_cast<ks::memory_detail::CoreReadOnlyModel*>(view->model());
            auto* projection = pathIconProjection(view);
            if (!model) { if (lastModel) { projection->reset(0); lastModel = nullptr; } return; }
            auto top = view->indexAt(QPoint(0, 0));
            const int first = top.isValid() ? top.row() : 0;
            auto bottom = view->indexAt(QPoint(0, view->viewport()->height() - 1));
            const int last = qMin(model->rowCount() - 1, bottom.isValid() ? bottom.row() : first + 255);
            if (lastModel != model || revision != model->revision || first != previousFirst || last != previousLast) {
                projection->reset(0); lastModel = model; revision = model->revision; previousFirst = first; previousLast = last;
            }
            for (int row = first; row <= last && row < first + 256; ++row) {
                if (!alive || !view) { return; }
                const auto index = model->index(row, 0);
                const auto path = index.data(kIconPathItemRole).toString();
                if (path.isEmpty() || pathIconCache().contains(path)) { continue; }
                projection->add(index, path); projection->watch(path);
            }
        }
        QPointer<QAbstractItemView> view;
        std::function<void(bool)> request;
        bool icons;
        QTimer* timer;
        QPointer<QAbstractItemModel> lastModel;
        std::uint64_t revision = 0;
        int previousFirst = -1, previousLast = -1;
    };

    // selectProcessRowByPid 作用：
    // - 输入：进程表、进程下拉框与目标 PID；
    // - 处理：定位目标行并滚动到可视区域，同时把下拉框切到同一目标（值未变化时不重设，
    //   避免多触发一次 currentIndexChanged 引起的模块重复枚举）；
    // - 返回：进程表命中并选中时返回 true。
    bool selectProcessRowByPid(
        QTableView* const processTable,
        QComboBox* const processCombo,
        const std::uint32_t pid)
    {
        const QPointer<QTableView> guardedTable(processTable);
        const QPointer<QComboBox> guardedCombo(processCombo);
        bool rowSelected = false;
        if (processTable != nullptr)
        {
            for (int rowIndex = 0; rowIndex < processTable->model()->rowCount(); ++rowIndex)
            {
                const QPersistentModelIndex pidItem(processTable->model()->index(rowIndex, 1));
                if (!pidItem.isValid() || pidItem.data(Qt::DisplayRole).toString().toUInt() != pid)
                {
                    continue;
                }
                processTable->selectRow(rowIndex);
                if (!guardedTable || !pidItem.isValid()) { return false; }
                processTable->scrollTo(pidItem, QAbstractItemView::PositionAtCenter);
                if (!guardedTable || !pidItem.isValid()) { return false; }
                rowSelected = true;
                break;
            }
        }

        if (guardedCombo)
        {
            const int comboIndex =
                processCombo->findData(QVariant::fromValue(static_cast<uint>(pid)), Qt::UserRole);
            if (comboIndex >= 0 && comboIndex != processCombo->currentIndex())
            {
                processCombo->setCurrentIndex(comboIndex);
            }
        }
        return rowSelected;
    }

    // ============================================================
    // 后台采集数据结构
    // 说明：MemoryDock::ProcessEntry / RegionEntry 都是私有嵌套类型，无法出现在
    // 文件级函数签名里，这里用等价的纯值类型承载采集结果，回到 UI 线程后再转换。
    // ============================================================

    // ProcessSnapshotRow 作用：
    // - 保存后台线程采集到的单个进程信息，字段全部是值类型，可安全跨线程搬运。
    struct ProcessSnapshotRow
    {
        std::uint32_t pid = 0;          // 进程 PID。
        std::uint32_t sessionId = 0;    // 会话 ID。
        QString processName;            // 进程名（Toolhelp 快照给出的映像文件名）。
        QString imagePath;              // 映像完整路径，供图标解析使用（可能为空）。
        double workingSetMB = 0.0;      // 工作集大小（MB），查询失败时保持 0。
        // CPU 占用没法一次采样得出，只能靠两次采样之间的增量。这里只带回本次的
        // 累计 CPU 时间与它是否取到，占用率由 UI 线程与上一轮相减算出。
        std::uint64_t cpuTime100ns = 0; // 内核态 + 用户态累计时间，单位 100ns。
        std::uint64_t creationTime100ns = 0; // Bind address navigation to this snapshot's process object.
        bool cpuTimeValid = false;      // 取不到时间的进程（权限不足、已退出）保持 false。
    };

    // kProcessNumericSortRole：数值排序键。
    constexpr int kProcessNumericSortRole = Qt::UserRole + 50;
    constexpr int kProcessCreationTimeRole = Qt::UserRole + 51;

    // NumericSortTableItem 作用：
    // - 显示带单位的文本，排序按藏在角色里的裸数值。
    //
    // 为什么必须自定义：QTableWidgetItem 的默认 operator< 比的是 **DisplayRole**，
    // 也就是带单位的那串文本，按字典序排。于是 "10.00%" 会排在 "9.00%" 前面、
    // "100.0 MB" 排在 "9.0 MB" 前面。工作集正是用来从一堆同名进程里挑出主进程的
    // 那一列，排错了这一列就完全失去意义，而且排错了不会报任何错。
    class NumericSortTableItem final : public QTableWidgetItem
    {
    public:
        NumericSortTableItem(const QString& displayText, const double sortValue)
        {
            setData(Qt::DisplayRole, displayText);
            setData(kProcessNumericSortRole, sortValue);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            const QVariant leftValue = data(kProcessNumericSortRole);
            const QVariant rightValue = other.data(kProcessNumericSortRole);
            if (leftValue.isValid() && rightValue.isValid())
            {
                return leftValue.toDouble() < rightValue.toDouble();
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    // ProcessSnapshotResult 作用：
    // - 保存一次进程枚举的完整结果与失败原因，由 UI 线程决定是否弹出提示。
    struct ProcessSnapshotResult
    {
        bool snapshotCreated = false;       // CreateToolhelp32Snapshot 是否成功。
        bool enumerationStarted = false;    // Process32FirstW 是否成功。
        std::uint32_t lastErrorCode = 0;    // 失败时的 Win32 错误码。
        std::vector<ProcessSnapshotRow> rows; // 按 PID 升序排列的进程快照。
        // 采样时刻，单位 100ns，与 cpuTime100ns 同一量纲。CPU 占用率 =
        // CPU 时间增量 / (墙上时间增量 × 逻辑核数)，分母必须用这个时刻算，
        // 不能用"刷新间隔"这种名义值——刷新被推迟或提前时名义值就不成立了。
        std::uint64_t sampleTime100ns = 0;
    };

    // collectProcessSnapshotRows 作用：
    // - 输入：无；
    // - 处理：在工作线程完成 Toolhelp 快照、会话查询、工作集查询与映像路径解析，
    //   全程不触碰任何 Qt 控件；
    // - 返回：按 PID 升序排序的采集结果（含失败原因）。
    ProcessSnapshotResult collectProcessSnapshotRows()
    {
        ProcessSnapshotResult snapshotResult;

        // 进程枚举按需求使用 Toolhelp 快照接口。
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            return snapshotResult;
        }
        snapshotResult.snapshotCreated = true;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            ::CloseHandle(snapshotHandle);
            return snapshotResult;
        }
        snapshotResult.enumerationStarted = true;

        do
        {
            ProcessSnapshotRow snapshotRow;
            snapshotRow.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
            snapshotRow.processName = QString::fromWCharArray(processEntry.szExeFile);

            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(toDwordPid(snapshotRow.pid), &sessionId) != FALSE)
            {
                snapshotRow.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            // 尝试读取工作集大小：失败则保持 0，不影响主流程。
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                toDwordPid(snapshotRow.pid));
            if (processHandle != nullptr)
            {
                PROCESS_MEMORY_COUNTERS_EX memoryCounter{};
                if (::GetProcessMemoryInfo(
                    processHandle,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounter),
                    sizeof(memoryCounter)) != FALSE)
                {
                    snapshotRow.workingSetMB =
                        static_cast<double>(memoryCounter.WorkingSetSize) / (1024.0 * 1024.0);
                }

                // 顺便在同一个句柄上取 CPU 累计时间：这里已经有
                // PROCESS_QUERY_LIMITED_INFORMATION，不必为它再开一次进程。
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (::GetProcessTimes(
                    processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
                {
                    const auto toU64 = [](const FILETIME& fileTime) {
                        return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32)
                            | static_cast<std::uint64_t>(fileTime.dwLowDateTime);
                    };
                    snapshotRow.creationTime100ns = toU64(creationTime);
                    snapshotRow.cpuTime100ns = toU64(kernelTime) + toU64(userTime);
                    snapshotRow.cpuTimeValid = true;
                }
                ::CloseHandle(processHandle);
            }

            // 映像路径解析内部还会再打开一次进程句柄，因此同样留在后台线程完成。
            snapshotRow.imagePath =
                QString::fromStdString(ks::process::QueryProcessPathByPid(snapshotRow.pid));

            snapshotResult.rows.push_back(std::move(snapshotRow));
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);
        ::CloseHandle(snapshotHandle);

        // 采样时刻取在遍历**之后**：整轮遍历本身要花时间，取在前面会让分母比
        // 实际观察窗口短，算出来的占用率偏高。取在后面则偏低一点点，宁可偏低。
        FILETIME sampleFileTime{};
        ::GetSystemTimeAsFileTime(&sampleFileTime);
        snapshotResult.sampleTime100ns =
            (static_cast<std::uint64_t>(sampleFileTime.dwHighDateTime) << 32)
            | static_cast<std::uint64_t>(sampleFileTime.dwLowDateTime);

        // 为了稳定展示顺序，这里按 PID 升序排序。
        std::sort(
            snapshotResult.rows.begin(),
            snapshotResult.rows.end(),
            [](const ProcessSnapshotRow& left, const ProcessSnapshotRow& right) {
                return left.pid < right.pid;
            });
        return snapshotResult;
    }

    // RegionSnapshotRow 作用：
    // - 保存后台线程采集到的单个虚拟内存区域，字段全部是值类型，可安全跨线程搬运。
    struct RegionSnapshotRow
    {
        std::uint64_t baseAddress = 0;  // 区域起始地址。
        std::uint64_t regionSize = 0;   // 区域大小（字节）。
        std::uint32_t protect = 0;      // 保护属性位（PAGE_*）。
        std::uint32_t state = 0;        // 状态（MEM_COMMIT / MEM_RESERVE / MEM_FREE）。
        std::uint32_t type = 0;         // 类型（MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE）。
        QString mappedFilePath;         // 映射文件路径（如果可获取）。
    };

    // collectVirtualMemoryRegionRows 作用：
    // - 输入：目标进程句柄（调用方保证遍历期间句柄一直有效）；
    // - 处理：从用户地址空间下限遍历到上限，IMAGE/MAPPED 区域附带解析映射文件路径，
    //   全程无 Qt 控件访问，可直接在线程池任务里执行；
    // - 返回：区域快照数组，地址空间不可读时返回空数组。
    std::vector<RegionSnapshotRow> collectVirtualMemoryRegionRows(const HANDLE processHandle, const std::function<bool()>& cancelled = {}, std::uint32_t* error = nullptr)
    {
        std::vector<RegionSnapshotRow> regionRows;
        if (error) { *error = ERROR_SUCCESS; }
        if (processHandle == nullptr)
        {
            return regionRows;
        }

        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t minAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uint64_t maxAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        std::uint64_t currentAddress = minAddress;
        while (currentAddress < maxAddress)
        {
            if (cancelled && cancelled()) { break; }
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T querySize = ::VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
                &mbi,
                sizeof(mbi));
            if (querySize != sizeof(mbi))
            {
                if (error) { *error = ::GetLastError(); if (*error == ERROR_SUCCESS) { *error = ERROR_INVALID_DATA; } }
                break;
            }

            RegionSnapshotRow regionRow{};
            regionRow.baseAddress = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            regionRow.regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            regionRow.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionRow.state = static_cast<std::uint32_t>(mbi.State);
            regionRow.type = static_cast<std::uint32_t>(mbi.Type);

            // IMAGE/MAPPED 区域尽量解析映射文件路径，便于用户定位模块。
            if (regionRow.state == MEM_COMMIT &&
                (regionRow.type == MEM_IMAGE || regionRow.type == MEM_MAPPED))
            {
                if (cancelled && cancelled()) { break; }
                wchar_t mappedPath[MAX_PATH] = {};
                const DWORD length = ::GetMappedFileNameW(
                    processHandle,
                    mbi.BaseAddress,
                    mappedPath,
                    static_cast<DWORD>(std::size(mappedPath)));
                if (length > 0)
                {
                    regionRow.mappedFilePath =
                        QString::fromWCharArray(mappedPath, static_cast<int>(length));
                }
            }

            regionRows.push_back(std::move(regionRow));
            if (mbi.RegionSize == 0)
            {
                if (error) { *error = ERROR_INVALID_DATA; }
                break;
            }

            const std::uint64_t nextAddress =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                static_cast<std::uint64_t>(mbi.RegionSize);
            if (nextAddress <= currentAddress)
            {
                if (error) { *error = ERROR_INVALID_DATA; }
                break;
            }
            currentAddress = nextAddress;
        }
        return regionRows;
    }

    // reportRegionEnumerateFailure 作用：
    // - 输入：承载对话框的父窗口与枚举失败文本；
    // - 处理：输出失败日志，优先走权限恢复提示，未被处理时退回普通告警框；
    // - 返回：无。同步兜底路径与异步回投路径共用同一套提示，避免行为分叉。
    void reportRegionEnumerateFailure(QWidget* const parentWidget, const QString& errorText)
    {
        kLogEvent regionEnumerateFailEvent;
        err << regionEnumerateFailEvent
            << "[MemoryDock] refreshMemoryRegionList: 枚举区域失败, error="
            << errorText.toStdString()
            << eol;

        // privilegePromptHandled：记录区域枚举失败是否已由权限恢复提示处理。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            parentWidget,
            QStringLiteral("枚举进程内存区域"),
            errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(parentWidget, "区域刷新", errorText);
        }
    }
}

bool MemoryDock::isComboPopupVisible(QComboBox* const comboBox) const
{
    if (comboBox == nullptr)
    {
        return false;
    }
    // 进程组合框从 showPopup() 进入前置位，
    // 所以 qScrollEffect 暂时隐藏 QComboBoxPrivateContainer 时也不会误放行。
    if (comboBox == m_processCombo)
    {
        return m_processComboPopupLifecycleActive;
    }

    // 为非受保护子类保留无副作用兜底；不要调用 view()，它会惰性创建私有弹层。
    QWidget* const activePopupWidget = QApplication::activePopupWidget();
    return activePopupWidget != nullptr &&
        (activePopupWidget == comboBox || comboBox->isAncestorOf(activePopupWidget));
}

bool MemoryDock::isProcessComboPopupOpen()
{
    // 进程缓存回填不能在进程选择器弹层仍展开时提交。
    return isComboPopupVisible(m_processCombo);
}

bool MemoryDock::deferCommitWhileProcessComboPopupOpen(std::function<void()> commitAction)
{
    if (!commitAction)
    {
        return false;
    }
    if (!isProcessComboPopupOpen())
    {
        return false;
    }

    // 弹层展开时清空并重填下拉框会让弹层保持鼠标抓取而内容失效，
    // 表现就是“点了下拉框之后整个界面点不动”。这里只保留最新一次提交。
    kLogEvent deferCommitEvent;
    info << deferCommitEvent
        << "[MemoryDock] 进程下拉框展开中，推迟本轮进程列表提交。"
        << eol;
    m_processComboDeferredCommit = std::move(commitAction);
    return true;
}

void MemoryDock::flushProcessComboDeferredCommit()
{
    if (isProcessComboPopupOpen())
    {
        // 弹层又被打开，继续等待下一次收起。
        return;
    }

    if (!m_processComboDeferredCommit)
    {
        return;
    }

    std::function<void()> commitAction;
    commitAction.swap(m_processComboDeferredCommit);

    kLogEvent flushCommitEvent;
    info << flushCommitEvent
        << "[MemoryDock] 进程下拉框已收起，回投被推迟的进程列表提交。"
        << eol;
    // 完整进程快照提交一次完成列表与当前选择的回填。
    commitAction();
}

struct MemoryDock::PreparedProcessSnapshot {
    ProcessSnapshotResult snapshot;
    std::shared_ptr<std::vector<ProcessEntry>> entries = ks::memory_detail::ValueStorage<std::vector<ProcessEntry>>();
    std::shared_ptr<QHash<std::uint32_t, ProcessCpuSample>> samples = ks::memory_detail::ValueStorage<QHash<std::uint32_t, ProcessCpuSample>>();
    std::shared_ptr<QHash<std::uint32_t, int>> rowsByPid = ks::memory_detail::ValueStorage<QHash<std::uint32_t, int>>();
    std::shared_ptr<const QHash<std::uint32_t, ProcessCpuSample>> previous;
    int logicalCoreCount = 1;
    std::uint64_t selectedCreation = 0;
    bool failed = false;
};

void MemoryDock::prepareProcessSnapshot(const std::shared_ptr<PreparedProcessSnapshot>& prepared)
{
    try {
        const auto& snapshot = prepared->snapshot;
        if (!snapshot.snapshotCreated || !snapshot.enumerationStarted) { return; }
        QHash<QString, int> exactNames, foldedNames;
        for (const auto& row : snapshot.rows) { ++exactNames[row.processName]; ++foldedNames[row.processName.toCaseFolded()]; }
        prepared->entries->reserve(snapshot.rows.size()); prepared->samples->reserve(static_cast<int>(snapshot.rows.size())); prepared->rowsByPid->reserve(static_cast<int>(snapshot.rows.size()));
        for (const auto& row : snapshot.rows) {
            ProcessEntry entry;
            entry.pid = row.pid; entry.creationTime100ns = row.creationTime100ns; entry.sessionId = row.sessionId;
            entry.processName = row.processName; entry.imagePath = row.imagePath.trimmed(); entry.workingSetMB = row.workingSetMB;
            entry.exactNameCount = exactNames.value(row.processName); entry.foldedNameCount = foldedNames.value(row.processName.toCaseFolded());
            if (row.cpuTimeValid) {
                prepared->samples->insert(row.pid, ProcessCpuSample{row.cpuTime100ns, snapshot.sampleTime100ns, row.creationTime100ns});
                const auto previous = prepared->previous->constFind(row.pid);
                if (previous != prepared->previous->constEnd() && row.creationTime100ns != 0 && previous->creationTime100ns == row.creationTime100ns
                    && snapshot.sampleTime100ns > previous->sampleTime100ns && row.cpuTime100ns >= previous->cpuTime100ns) {
                    const auto cpu = static_cast<double>(row.cpuTime100ns - previous->cpuTime100ns);
                    const auto wall = static_cast<double>(snapshot.sampleTime100ns - previous->sampleTime100ns);
                    entry.cpuPercent = std::clamp(cpu / (wall * (std::max)(1, prepared->logicalCoreCount)) * 100.0, 0.0, 100.0);
                    entry.cpuPercentValid = true;
                }
            }
            prepared->rowsByPid->insert(entry.pid, static_cast<int>(prepared->entries->size()));
            prepared->entries->push_back(std::move(entry));
        }
    } catch (...) { prepared->failed = true; }
}

void MemoryDock::refreshProcessList(const bool keepSelection)
{
    const QPointer<MemoryDock> owner(this);
    flushProcessComboDeferredCommit();
    if (!owner) { return; }
    if (readBoolProperty(this, kProcessRefreshInFlightProperty)) {
        setProperty(kProcessRefreshPendingProperty, true);
        setProperty(kProcessRefreshPendingKeepSelectionProperty, keepSelection); return;
    }
    const auto previousPid = keepSelection ? m_processCombo->currentData(Qt::UserRole).toUInt() : 0U;
    const auto generation = bumpGenerationProperty(this, kProcessRefreshGenerationProperty);
    setProperty(kProcessRefreshInFlightProperty, true);
    auto prepared = ks::memory_detail::ValueStorage<PreparedProcessSnapshot>();
    prepared->selectedCreation = keepSelection ? m_processCombo->currentData(kProcessCreationTimeRole).toULongLong() : 0ULL;
    prepared->previous = m_previousCpuSamples;
    prepared->logicalCoreCount = (std::max)(1, QThread::idealThreadCount());
    try { QThreadPool::globalInstance()->start([owner, prepared, generation, previousPid] {
        try { prepared->snapshot = collectProcessSnapshotRows(); prepareProcessSnapshot(prepared); }
        catch (...) { prepared->failed = true; }
        if (auto* app = QCoreApplication::instance()) {
            QMetaObject::invokeMethod(app, [owner, prepared, generation, previousPid] {
                if (!owner || owner->property(kProcessRefreshGenerationProperty).toULongLong() != generation) { return; }
                if (prepared->failed || !prepared->snapshot.snapshotCreated || !prepared->snapshot.enumerationStarted) {
                    owner->setProperty(kProcessRefreshInFlightProperty, false); owner->setProperty(kProcessRefreshPendingProperty, false);
                    if (!prepared->snapshot.snapshotCreated) { QMessageBox::warning(owner, "进程刷新", "CreateToolhelp32Snapshot 失败。"); }
                    else if (owner->m_processCountLabel) { owner->m_processCountLabel->setText(ks::i18n::packedSourceText(QStringLiteral("Memory table projection failed"))); }
                    return;
                }
                const auto commit = [owner, prepared, generation, previousPid] { if (owner) { owner->commitProcessSnapshot(prepared, generation, previousPid); } };
                if (owner->deferCommitWhileProcessComboPopupOpen(commit)) { return; }
                if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(owner, QStringLiteral("memory-process-list-snapshot-apply"), {owner->m_processTable}, commit)) { return; }
                commit();
            }, Qt::QueuedConnection);
        }
    }); } catch (...) {
        setProperty(kProcessRefreshInFlightProperty, false); setProperty(kProcessRefreshPendingProperty, false);
        if (m_processCountLabel) { m_processCountLabel->setText(ks::i18n::packedSourceText(QStringLiteral("Memory table projection failed"))); }
    }
}

void MemoryDock::commitProcessSnapshot(const std::shared_ptr<PreparedProcessSnapshot>& prepared, const std::uint64_t generation, const std::uint32_t previousPid)
{
    if (property(kProcessRefreshGenerationProperty).toULongLong() != generation) { return; }
    const QPointer<MemoryDock> owner(this);
    m_processCache = prepared->entries; m_previousCpuSamples = prepared->samples; m_processRowsByPid = prepared->rowsByPid;
    updateProcessComboFromCache();
    if (!owner) { return; }
    if (previousPid != 0 && m_processRowsByPid->contains(previousPid)) {
        const auto row = m_processRowsByPid->value(previousPid);
        if (prepared->selectedCreation == 0 || (*m_processCache)[static_cast<std::size_t>(row)].creationTime100ns == prepared->selectedCreation) { m_processCombo->setCurrentIndex(row); }
    }
    if (!owner) { return; }
    requestCoreProjection(CoreKind::Processes, false);
    if (!owner) { return; }
    setProperty(kProcessRefreshInFlightProperty, false);
    if (property(kProcessRefreshPendingProperty).toBool()) {
        const auto keep = property(kProcessRefreshPendingKeepSelectionProperty).toBool();
        setProperty(kProcessRefreshPendingProperty, false); refreshProcessList(keep);
    }
}

std::shared_ptr<const ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot> MemoryDock::prepareTamperModuleCandidates(const std::vector<ModuleEntry>& modules)
{
    using Page = ksword::memory_dock::TamperDetectionPage;
    auto snapshot = ks::memory_detail::ValueStorage<Page::ModuleCandidateSnapshot>();
    snapshot->entries.reserve(modules.size()); snapshot->rowsByKey.reserve(static_cast<int>(modules.size()));
    for (const auto& module : modules) {
        Page::ModuleCandidate candidate;
        candidate.displayText = QString("%1  (%2 KB)").arg(module.moduleName).arg(module.sizeBytes / 1024ULL);
        candidate.filePath = module.fullPath; candidate.baseAddress = module.baseAddress; candidate.sizeBytes = module.sizeBytes;
        const auto key = Page::ModuleCandidateSnapshot::identity(candidate);
        if (!snapshot->rowsByKey.contains(key)) { snapshot->rowsByKey.insert(key, static_cast<int>(snapshot->entries.size())); }
        snapshot->entries.push_back(std::move(candidate));
    }
    return snapshot;
}

void MemoryDock::syncTamperDetectionTargets()
{
    if (!m_tamperDetectionPage) { return; }
    const QPointer<MemoryDock> owner(this);
    const QPointer<ksword::memory_dock::TamperDetectionPage> page(m_tamperDetectionPage);
    page->setAttachedProcess(m_attachedPid, m_attachedProcessName);
    if (!owner || !page) { return; }
    page->setModuleCandidates(m_moduleCachePid == m_attachedPid ? m_tamperCandidateSnapshot : ks::memory_detail::ValueStorage<ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot>());
}

void MemoryDock::applyProcessTableFilter()
{
    requestCoreProjection(CoreKind::Processes, true);
}

void MemoryDock::updateProcessComboFromCache()
{
    if (!m_processComboModel || !m_processCombo) { return; }
    const QPointer<MemoryDock> owner(this);
    QSignalBlocker blocker(m_processCombo);
    const auto source = m_processCache;
    m_processComboModel->publish(static_cast<int>(source->size()), [source](const int row, const int role) -> QVariant {
        const auto& entry = (*source)[static_cast<std::size_t>(row)];
        if (role == Qt::UserRole) { return QVariant::fromValue(entry.pid); }
        if (role == Qt::UserRole + 1) { return entry.processName; }
        if (role == Qt::UserRole + 2) { return entry.foldedNameCount; }
        if (role == kProcessCreationTimeRole) { return QVariant::fromValue<qulonglong>(entry.creationTime100ns); }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole) { return {}; }
        QString text = QString("%1 [PID:%2]").arg(entry.processName).arg(entry.pid);
        if (entry.exactNameCount > 1) { text += ks::i18n::sourceText(QStringLiteral(" · %1 MB · 同名 %2 个")).arg(entry.workingSetMB, 0, 'f', 0).arg(entry.exactNameCount); }
        return text;
    });
    if (!owner) { blocker.dismiss(); return; }
    m_processCombo->setCurrentIndex(m_processRowsByPid->contains(m_attachedPid) ? m_processRowsByPid->value(m_attachedPid) : source->empty() ? -1 : 0);
}

void MemoryDock::rebuildModuleTableFromCache() { requestCoreProjection(CoreKind::Modules, false); }

struct MemoryDock::ModuleRefreshJob {
    ModuleRefreshRequest request;
    std::uint64_t ticket = 0, creation = 0, elapsedMs = 0;
    std::size_t moduleCount = 0, threadCount = 0;
    std::atomic_bool cancel{false}, done{false};
    std::shared_ptr<std::atomic_bool> lifetime;
    bool cancelled() const { return cancel.load() || (lifetime && lifetime->load()); }
    QString diagnostic;
    std::vector<ModuleEntry> modules;
    std::shared_ptr<const ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot> candidates;
};

bool MemoryDock::refreshModuleListForPid(const std::uint32_t pid)
{
    // Explicit refresh/attach consumes any still-pending combo selection timer.
    if (m_processComboChangeTimer && m_processComboChangeTimer->isActive()) { m_processComboChangeTimer->stop(); }
    const bool includeSignatureCheck = m_moduleSignatureCheck && m_moduleSignatureCheck->isChecked();
    std::uint64_t creation = 0;
    for (const auto& entry : *m_processCache) { if (entry.pid == pid) { creation = entry.creationTime100ns; break; } }
    const ModuleRefreshRequest request{pid, creation, includeSignatureCheck};
    const auto sameRequest = [&request](const ModuleRefreshRequest& other) {
        return request.pid == other.pid && request.creation == other.creation && request.signatures == other.signatures;
    };
    if (pid && m_moduleRefreshJob && !m_moduleRefreshJob->cancel.load()
        && sameRequest(m_moduleRefreshJob->request) && !m_moduleRefreshPending) { return true; }
    if (pid && m_moduleRefreshPending && sameRequest(*m_moduleRefreshPending)) { return true; }
    m_moduleRefreshTicket.fetch_add(1);
    if (m_moduleRefreshJob) { m_moduleRefreshJob->cancel.store(true); }
    if (!pid) {
        m_moduleRefreshPending.reset(); m_moduleRefreshInProgress.store(false);
        m_moduleCache = ks::memory_detail::ValueStorage<std::vector<ModuleEntry>>(); m_moduleCacheStatusTemplate.clear(); m_tamperCandidateSnapshot = ks::memory_detail::ValueStorage<ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot>(); m_moduleCachePid = 0; m_moduleCacheCreateTime = 0;
        rebuildModuleTableFromCache();
        if (m_moduleRefreshButton) { m_moduleRefreshButton->setEnabled(true); }
        if (m_moduleStatusLabel) {
            m_moduleStatusLabel->setText("● 未选择有效进程");
            m_moduleStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return false;
    }
    m_moduleRefreshPending = request;
    m_moduleRefreshInProgress.store(true);
    // 刷新期间更新状态栏并临时禁用按钮，避免用户误以为点击无效而反复触发。
    if (m_moduleRefreshButton != nullptr)
    {
        m_moduleRefreshButton->setEnabled(false);
    }
    if (m_moduleStatusLabel != nullptr)
    {
        m_moduleStatusLabel->setText(
            QString("● 正在刷新模块(PID=%1, 签名校验=%2)...")
            .arg(pid)
            .arg(includeSignatureCheck ? "开启" : "关闭"));
        m_moduleStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    }


    if (!m_moduleRefreshPoll) {
        m_moduleRefreshPoll = new QTimer(this); m_moduleRefreshPoll->setInterval(25);
        connect(m_moduleRefreshPoll, &QTimer::timeout, this, [this] { pollModuleRefresh(); });
        connect(this, &QObject::destroyed, [lifetime = m_moduleRefreshLifetime] { lifetime->store(true); });
    }
    startPendingModuleRefresh();
    m_moduleRefreshPoll->start();
    return true;
}

void MemoryDock::startPendingModuleRefresh()
{
    if (m_moduleRefreshJob || !m_moduleRefreshPending) { return; }
    auto job = std::make_shared<ModuleRefreshJob>();
    job->request = *m_moduleRefreshPending; m_moduleRefreshPending.reset();
    job->ticket = m_moduleRefreshTicket.load(); m_moduleRefreshJob = job;
    job->lifetime = m_moduleRefreshLifetime;
    // Worker and teardown share only task state, with one lifecycle subscription per Dock.
    try { QThreadPool::globalInstance()->start([job] {
        try {
            if (!job->cancelled()) {
                const auto start = std::chrono::steady_clock::now();
                const auto anchor = ks::ui::AcquireAnchorForPid(job->request.pid);
                job->creation = anchor.createTime100ns;
                ks::ui::ReleaseAnchorHandle(anchor.handle);
                if (!job->cancelled() && (!job->request.creation || job->request.creation == job->creation)) {
                    const auto cancelled = [job] { return job->cancelled(); };
                    const auto snapshot = job->creation
                        ? ks::process::EnumerateProcessModulesAndThreadsIfIdentityMatches(job->request.pid, job->creation, job->request.signatures, cancelled)
                        : ks::process::EnumerateProcessModulesAndThreads(job->request.pid, job->request.signatures, cancelled);
                    job->moduleCount = snapshot.modules.size(); job->threadCount = snapshot.threads.size();
                    job->diagnostic = QString::fromStdString(snapshot.diagnosticText).trimmed();
                    job->modules.reserve(snapshot.modules.size());
                    for (const auto& record : snapshot.modules) {
                        if (job->cancelled()) { break; }
                        ModuleEntry entry{};
                        entry.fullPath = QString::fromStdString(record.modulePath); entry.moduleName = QFileInfo(entry.fullPath).fileName();
                        entry.baseAddress = record.moduleBaseAddress; entry.sizeBytes = record.moduleSizeBytes;
                        entry.signatureState = QString::fromStdString(record.signatureState); entry.signatureTrusted = record.signatureTrusted;
                        entry.entryPointOffset = record.entryPointRva; entry.runningState = QString::fromStdString(record.runningState);
                        entry.threadIdText = QString::fromStdString(record.threadIdText); entry.representativeThreadId = record.representativeThreadId;
                        job->modules.push_back(std::move(entry));
                    }
                    if (!job->cancelled()) { std::sort(job->modules.begin(), job->modules.end(), [](const auto& a, const auto& b) { return a.baseAddress < b.baseAddress; }); job->candidates = prepareTamperModuleCandidates(job->modules); }
                } else if (!job->cancelled()) {
                    job->creation = job->request.creation;
                    job->diagnostic = QString::number(ERROR_INVALID_PARAMETER);
                }
                job->elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
            }
        } catch (...) { job->diagnostic = QString::number(ERROR_GEN_FAILURE); }
        job->done.store(true);
    }); } catch (...) { job->diagnostic = QString::number(ERROR_GEN_FAILURE); job->done.store(true); }
}

void MemoryDock::pollModuleRefresh()
{
    if (!m_moduleRefreshJob || !m_moduleRefreshJob->done.load()) { return; }
    auto job = std::move(m_moduleRefreshJob);
    if (job->cancel.load() || job->ticket != m_moduleRefreshTicket.load()) {
        startPendingModuleRefresh();
        if (!m_moduleRefreshJob) { m_moduleRefreshPoll->stop(); }
        return;
    }
    const QPointer<MemoryDock> selfGuard(this);
    const auto refreshTicket = job->ticket;
    const auto pid = job->request.pid;
    const auto moduleCreateTime = job->creation;
    const auto includeSignatureCheck = job->request.signatures;
    const auto elapsedMs = job->elapsedMs;
    const auto moduleCount = job->moduleCount, threadCount = job->threadCount;
    const auto diagnosticText = job->diagnostic;
    const auto candidates = job->candidates ? job->candidates : ks::memory_detail::ValueStorage<ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot>();
    const auto moduleCacheSnapshot = ks::memory_detail::ValueStorage<std::vector<ModuleEntry>>(std::move(job->modules));
    const auto commitModuleSnapshot = [selfGuard, refreshTicket, pid, moduleCreateTime, includeSignatureCheck,
        elapsedMs, moduleCount, threadCount, diagnosticText, moduleCacheSnapshot, candidates] {
        if (!selfGuard || refreshTicket != selfGuard->m_moduleRefreshTicket.load()) { return; }
                    // 缓存和树必须原子落地；菜单打开时不能先换缓存再保留旧节点。
                    selfGuard->m_moduleCache = moduleCacheSnapshot;
                    selfGuard->m_tamperCandidateSnapshot = candidates;
                    selfGuard->m_moduleCachePid = pid;
                    selfGuard->m_moduleCacheCreateTime = moduleCreateTime;
                    selfGuard->rebuildModuleTableFromCache();
                    selfGuard->syncTamperDetectionTargets();

                    selfGuard->m_moduleRefreshInProgress.store(false);
                    if (selfGuard->m_moduleRefreshButton != nullptr)
                    {
                        selfGuard->m_moduleRefreshButton->setEnabled(true);
                    }

                    if (selfGuard->m_moduleStatusLabel != nullptr)
                    {
                        QString statusText = QString("● %1 ms | 模块:%2 线程:%3 显示:%4")
                            .arg(elapsedMs)
                            .arg(moduleCount)
                            .arg(threadCount)
                            .arg(QStringLiteral("%4"));
                        if (!diagnosticText.isEmpty())
                        {
                            statusText += QStringLiteral(
                                " | 存在诊断；详情已写入日志。");
                        }
                        selfGuard->m_moduleCacheStatusTemplate = statusText;
                        statusText = statusText.arg(selfGuard->m_moduleTable->topLevelItemCount());
                        selfGuard->m_moduleStatusLabel->setText(statusText);
                        selfGuard->m_moduleStatusLabel->setStyleSheet(
                            QStringLiteral("color:%1; font-weight:%2;")
                                .arg(moduleCount == 0
                                    ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                    : KswordTheme::SuccessColor().name(QColor::HexRgb))
                                .arg(moduleCount == 0 ? 700 : 600));
                    }

                    kLogEvent refreshModuleFinishEvent;
                    info << refreshModuleFinishEvent
                        << "[MemoryDock] refreshModuleListForPid: 刷新完成, pid="
                        << pid
                        << ", elapsedMs="
                        << elapsedMs
                        << ", moduleCount="
                        << moduleCount
                        << ", threadCount="
                        << threadCount
                        << ", visibleCount="
                        << selfGuard->m_moduleTable->topLevelItemCount()
                        << ", includeSignatureCheck="
                        << (includeSignatureCheck ? "true" : "false")
                        << ", diagnostic="
                        << diagnosticText.toStdString()
                        << eol;
    };
    m_moduleRefreshPoll->stop();
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this, QStringLiteral("memory-process-modules-snapshot-apply"),
        {m_moduleTable}, commitModuleSnapshot)) { return; }
    commitModuleSnapshot();
}

ks::ui::LeaveEntryStatus MemoryDock::attachToProcess(
    const std::uint32_t pid,
    const QString& processName,
    const bool showMessage,
    ks::ui::LeaveCompletion completion, ProcessOpenFailure openFailure)
{
    // 附加入口日志：记录目标 PID 与是否弹窗反馈。
    kLogEvent attachStartEvent;
    info << attachStartEvent
        << "[MemoryDock] attachToProcess: 开始附加, pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << ", showMessage="
        << (showMessage ? "true" : "false")
        << eol;

    if (m_workbenchProcessChangePending) return ks::ui::LeaveEntryStatus::Busy;
    const QPointer<MemoryDock> self(this);
    const auto attachment = m_processAttachmentGeneration.load();
    const auto anchor = std::shared_ptr<ks::ui::AnchorInfo>(new ks::ui::AnchorInfo(ks::ui::AcquireAnchorForPid(pid)),
        [](ks::ui::AnchorInfo* value) { ks::ui::ReleaseAnchorHandle(value->handle); delete value; });
    if (anchor->targetGone) return ks::ui::LeaveEntryStatus::Rejected;
    const auto expectedCreateTime = anchor->identityWeak ? 0 : anchor->createTime100ns;
    const auto leave = workbenchAllowsProcessChange(
        [self, attachment, anchor, expectedCreateTime, pid, processName, showMessage, completion, openFailure](bool allowed) mutable {
            if (!self) return;
            self->m_workbenchProcessChangePending = false;
            const bool current = self->m_processAttachmentGeneration.load() == attachment;
            const bool alive = !anchor->handle || ks::ui::QueryAnchorAlive(anchor->handle) != std::optional<bool>(false);
            const bool attached = allowed && current && alive
                && self->attachToProcessAfterLeave(pid, processName, showMessage, expectedCreateTime, openFailure);
            if (self && completion) completion(attached);
        });
    if (!self) return ks::ui::LeaveEntryStatus::Rejected;
    if (leave == ks::ui::LeaveEntryStatus::Pending)
    {
        m_workbenchProcessChangePending = true;
        return leave;
    }
    if (leave != ks::ui::LeaveEntryStatus::Completed) return leave;
    if (m_processAttachmentGeneration.load() != attachment) return ks::ui::LeaveEntryStatus::Rejected;
    return attachToProcessAfterLeave(pid, processName, showMessage, expectedCreateTime, std::move(openFailure))
        ? ks::ui::LeaveEntryStatus::Completed : ks::ui::LeaveEntryStatus::Rejected;
}

bool MemoryDock::attachToProcessAfterLeave(const std::uint32_t pid, const QString& processName,
    const bool showMessage, const std::uint64_t expectedCreateTime, ProcessOpenFailure openFailure)
{
    // 附加前先清理旧进程上下文，避免残留句柄。
    detachProcess();

    // 首选读写权限，满足写内存/断点能力。
    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr)
    {
        // 失败时回退只读权限，至少保证浏览能力。
        processHandle = ::OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (processHandle == nullptr)
        {
            const DWORD openError = ::GetLastError();
            kLogEvent attachOpenFailEvent;
            err << attachOpenFailEvent
                << "[MemoryDock] attachToProcess: 读写+只读权限均失败, pid="
                << pid
                << ", error="
                << openError
                << eol;
            if (showMessage)
            {
                if (openError == ERROR_ACCESS_DENIED)
                {
                    (void)ks::ui::requestAdministratorRestartForFeature(
                        this,
                        QStringLiteral("附加进程内存"));
                }
                else
                {
                    QMessageBox::warning(
                        this,
                        "附加失败",
                        "OpenProcess 失败，目标进程可能已退出或不可访问。");
                }
            }
            updateStatusBarText();
            if (openFailure)
            {
                openFailure(openError);
            }
            return false;
        }
        m_canReadWriteMemory = false;
        kLogEvent attachReadonlyEvent;
        warn << attachReadonlyEvent
            << "[MemoryDock] attachToProcess: 退化为只读句柄, pid="
            << pid
            << eol;
    }
    else
    {
        m_canReadWriteMemory = true;
        kLogEvent attachReadWriteEvent;
        info << attachReadWriteEvent
            << "[MemoryDock] attachToProcess: 获取到可读写句柄, pid="
            << pid
            << eol;
    }

    if (expectedCreateTime != 0)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool queried = ::GetProcessTimes(processHandle, &created, &exited, &kernel, &user) != FALSE;
        const std::uint64_t actual = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32U) | created.dwLowDateTime;
        if (!queried || actual != expectedCreateTime)
        {
            ::CloseHandle(processHandle);
            m_canReadWriteMemory = false;
            updateStatusBarText();
            return false;
        }
    }
    m_attachedProcessHandle = processHandle;
    m_attachedPid = pid;
    m_attachedProcessName = processName;
    updateStatusBarText();
    syncTamperDetectionTargets();

    // 句柄、PID、名称与读写标志都已就位：通知内存工作台目标已附加（视图未创建时是空操作）。
    workbenchOnAttached();

    // 附加后立即刷新模块与区域，减少下一步等待。两者都在后台执行，
    // 附加按钮点下去之后界面立刻可用，不会因为目标进程地址空间庞大而白屏。
    refreshModuleListForPid(pid);

    // 附加路径显式要求区域枚举走异步分支：此刻区域缓存必然为空（detachProcess 已清空），
    // 若不打这个标记就会落到“缓存为空时同步遍历”的兜底分支上，重新把 UI 卡住。
    setProperty(kRegionRefreshFromAttachProperty, true);
    refreshMemoryRegionList(true);

    if (showMessage)
    {
        QMessageBox::information(
            this,
            "附加成功",
            QString("已附加到 %1 (PID=%2)\n读写状态: %3")
            .arg(processName)
            .arg(pid)
            .arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    }

    // 附加结束日志：记录最终状态。
    kLogEvent attachFinishEvent;
    info << attachFinishEvent
        << "[MemoryDock] attachToProcess: 附加完成, pid="
        << pid
        << ", canReadWrite="
        << (m_canReadWriteMemory ? "true" : "false")
        << eol;
    return true;
}

void MemoryDock::focusProcessForOperations(const std::uint32_t pid, const bool showMessage, ks::ui::LeaveCompletion completion)
{
    // 从进程 Dock 跳转：刷新进程列表，定位目标行并切换到“进程与模块/内存区域”操作上下文。
    if (pid == 0)
    {
        return;
    }

    // 进程列表刷新已改为异步，附加不能再等表格重建完成。进程名优先取现有缓存，
    // 缓存未命中时只做一次映像路径查询（单个进程句柄，代价可忽略）。
    QString processName;
    for (const ProcessEntry& entry : *m_processCache)
    {
        if (entry.pid == pid)
        {
            processName = entry.processName.trimmed();
            break;
        }
    }
    if (processName.isEmpty())
    {
        const QString imagePath = QString::fromStdString(ks::process::QueryProcessPathByPid(pid));
        processName = QFileInfo(imagePath).fileName().trimmed();
    }
    if (processName.isEmpty())
    {
        processName = QStringLiteral("PID_%1").arg(pid);
    }

    // 目标行定位登记成待办：本轮异步刷新回填进程表后由提交阶段完成选中与滚动。
    setProperty(kProcessFocusPendingPidProperty, static_cast<uint>(pid));
    refreshProcessList(true);

    // 当前表里已经存在该进程时立即定位，不必等异步结果回来。
    (void)selectProcessRowByPid(m_processTable, m_processCombo, pid);

    const QPointer<MemoryDock> self(this);
    const auto status = attachToProcess(pid, processName, showMessage, [self, completion](bool allowed) mutable {
        if (!self) return;
        if (allowed && self->m_tabWidget && self->m_tabRegions) self->m_tabWidget->setCurrentWidget(self->m_tabRegions);
        if (self && completion) completion(allowed);
    });
    if (self && status == ks::ui::LeaveEntryStatus::Completed && m_tabWidget && m_tabRegions)
        m_tabWidget->setCurrentWidget(m_tabRegions);
}

void MemoryDock::focusProcessForSearch(const std::uint32_t pid, const bool showMessage)
{
    // 搜索页需要有效进程句柄和最新区域缓存，先复用标准附加流程，再切到搜索页。
    const QPointer<MemoryDock> self(this);
    focusProcessForOperations(pid, showMessage, [self, pid](bool allowed) {
        if (self && allowed && self->m_attachedPid == pid && self->m_tabWidget && self->m_tabSearch)
            self->m_tabWidget->setCurrentWidget(self->m_tabSearch);
    });
    if (self && m_attachedPid == pid && m_tabWidget != nullptr && m_tabSearch != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabSearch);
    }
}

void MemoryDock::setProcessDetailMemoryScope()
{
    // 进程详情只需要针对当前 PID 的基础内存分析入口。
    // 其余断点、R0 读写、内核扫描和证据页保留在独立内存 Dock，避免内嵌窗口成为完整副本。
    if (m_tabWidget == nullptr)
    {
        return;
    }

    // 内嵌实例：内存工作台视图以内嵌模式创建（恒跟随本 Dock、禁内核/物理、不落盘设置）。
    m_workbenchEmbedded = true;

    applyProcessDetailTabVisibility();

    if (m_tabRegions != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabRegions);
    }
}

void MemoryDock::applyProcessDetailTabVisibility()
{
    // 内嵌实例固定提供进程与模块、内存区域、内存搜索和统一工作台。
    if (m_tabWidget == nullptr)
    {
        return;
    }
    for (int tabIndex = 0; tabIndex < m_tabWidget->count(); ++tabIndex)
    {
        QWidget* const tabPage = m_tabWidget->widget(tabIndex);
        const bool visibleInProcessDetail =
            tabPage == m_tabProcessModule ||
            tabPage == m_tabRegions ||
            tabPage == m_tabSearch ||
            tabPage == m_tabWorkbench;
        m_tabWidget->setTabVisible(tabIndex, visibleInProcessDetail);
    }
}

void MemoryDock::detachProcess()
{
    cancelCoreProjection(false);
    // 分离入口日志：记录旧 PID 便于追踪。
    kLogEvent detachStartEvent;
    info << detachStartEvent
        << "[MemoryDock] detachProcess: 开始分离, oldPid="
        << m_attachedPid
        << eol;

    // 句柄仍然有效的最后时点：先让内存工作台处理"目标即将分离"（int3 补丁的未经提示安全网
    // 需要在句柄关闭之前还原；视图未创建时是空操作）。
    workbenchOnAboutToDetach();

    // 先取消扫描并解绑 UI；后台任务保留各自复制的进程句柄，
    // 直到物理任务结束再释放，不在界面线程等待。
    cancelMemoryScanTasks();

    // 先使所有基于旧附加上下文的异步快照失效。PTE/证据任务持有的是复制句柄，
    // 可以安全完成系统调用，但其结果不得再写回新的附加进程。
    m_processAttachmentGeneration.fetch_add(1U);

    // 区域枚举的在途/待补标记与附加上下文绑定：不在这里复位，重新附加时会被上一轮
    // 任务遗留的在途标记挡住，新目标永远等不到区域列表。旧任务回投时会先比对代次，
    // 发现上下文已变就整段放弃，不会再回来碰这组标记。
    setProperty(kRegionRefreshInFlightProperty, false);
    setProperty(kRegionRefreshPendingProperty, false);
    setProperty(kRegionRefreshFromAttachProperty, false);

    m_processPteTranslateRefreshTicket.fetch_add(1U);
    m_processMemoryEvidenceRefreshTicket.fetch_add(1U);
    m_processPteTranslateRefreshInProgress.store(false);
    m_processMemoryEvidenceRefreshInProgress.store(false);
    if (m_processPteTranslateRefreshButton != nullptr)
    {
        m_processPteTranslateRefreshButton->setEnabled(true);
    }
    if (m_processMemoryEvidenceRefreshButton != nullptr)
    {
        m_processMemoryEvidenceRefreshButton->setEnabled(true);
    }

    // 同步抬高模块刷新 ticket，确保旧的异步模块回调不会覆盖“已分离”状态。
    m_moduleRefreshTicket.fetch_add(1);
    m_moduleRefreshPending.reset();
    if (m_moduleRefreshJob) { m_moduleRefreshJob->cancel.store(true); }
    m_moduleRefreshInProgress.store(false);
    if (m_moduleRefreshButton != nullptr)
    {
        m_moduleRefreshButton->setEnabled(true);
    }

    if (m_attachedProcessHandle != nullptr)
    {
        ::CloseHandle(m_attachedProcessHandle);
        m_attachedProcessHandle = nullptr;
    }

    m_attachedPid = 0;
    m_attachedProcessName.clear();
    m_canReadWriteMemory = false;

    // 分离时清理依赖上下文的数据缓存。
    m_moduleCache = ks::memory_detail::ValueStorage<std::vector<ModuleEntry>>(); m_moduleCacheStatusTemplate.clear(); m_tamperCandidateSnapshot = ks::memory_detail::ValueStorage<ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot>();
    m_moduleCachePid = 0U;
    m_moduleCacheCreateTime = 0U;
    m_regionCache = ks::memory_detail::ValueStorage<std::vector<RegionEntry>>(); m_regionCachePartial = false; m_regionCacheError = 0;
    m_searchResultCache = ks::memory_detail::ValueStorage<std::vector<SearchResultEntry>>();
    m_searchResultVisibleCount = 0;
    m_processPteTranslateCache = ks::memory_detail::ValueStorage<std::vector<ProcessMemoryEvidenceEntry>>();
    m_processPteTranslateVisibleCount = 0;
    m_processMemoryEvidenceCache = ks::memory_detail::ValueStorage<std::vector<ProcessMemoryEvidenceEntry>>();
    m_processMemoryEvidenceVisibleCount = 0;

    // 清理表格展示，避免用户误操作旧数据。
    m_moduleTable->clear();
    if (m_moduleStatusLabel != nullptr)
    {
        m_moduleStatusLabel->setText("● 未附加进程");
        m_moduleStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;")
                .arg(KswordTheme::TextSecondaryColor().name(QColor::HexRgb)));
    }
    if (m_regionTable) { m_regionTable->clearEntries(); }
    if (m_searchResultTable) { m_searchResultTable->clearEntries(); }
    if (m_processPteTranslateTable != nullptr)
    {
        m_processPteTranslateTable->clearEntries();
    }
    if (m_processMemoryEvidenceTable != nullptr)
    {
        m_processMemoryEvidenceTable->clearEntries();
    }
    if (m_processPteTranslateStatusLabel != nullptr)
    {
        m_processPteTranslateStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
    }
    if (m_processMemoryEvidenceStatusLabel != nullptr)
    {
        m_processMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
    }

    updateStatusBarText();

    // 旧上下文已全部清零：通知内存工作台分离完成（视图未创建时是空操作）。
    workbenchOnDetached();

    // 分离结束日志：确认缓存已清空。
    kLogEvent detachFinishEvent;
    info << detachFinishEvent
        << "[MemoryDock] detachProcess: 分离完成，缓存与表格已重置。"
        << eol;
}

std::shared_ptr<void> MemoryDock::duplicateAttachedProcessHandleForWorker(
    std::uint32_t* const errorCodeOut) const
{
    // 后台任务不得借用 m_attachedProcessHandle：分离/重新附加会关闭它，且 Windows
    // 可能立即把相同数值分配给别的内核对象。独立复制句柄把系统调用生命周期与 UI 解耦。
    if (errorCodeOut != nullptr)
    {
        *errorCodeOut = ERROR_SUCCESS;
    }

    if (m_attachedProcessHandle == nullptr)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_INVALID_HANDLE;
        }
        return {};
    }

    HANDLE duplicatedHandle = nullptr;
    if (::DuplicateHandle(
            ::GetCurrentProcess(),
            m_attachedProcessHandle,
            ::GetCurrentProcess(),
            &duplicatedHandle,
            0U,
            FALSE,
            DUPLICATE_SAME_ACCESS) == FALSE)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = static_cast<std::uint32_t>(::GetLastError());
        }
        return {};
    }

    return std::shared_ptr<void>(duplicatedHandle, [](void* const rawHandle) {
        if (rawHandle != nullptr)
        {
            ::CloseHandle(static_cast<HANDLE>(rawHandle));
        }
    });
}

HANDLE MemoryDock::openProcessHandleForRead(const std::uint32_t pid, QString* const errorTextOut) const
{
    // 读取句柄日志：用于诊断权限不足问题。
    kLogEvent openReadHandleEvent;
    dbg << openReadHandleEvent
        << "[MemoryDock] openProcessHandleForRead: pid="
        << pid
        << eol;

    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr && errorTextOut != nullptr)
    {
        *errorTextOut = QString("OpenProcess 失败，错误码=%1").arg(::GetLastError());
        kLogEvent openReadHandleFailEvent;
        warn << openReadHandleFailEvent
            << "[MemoryDock] openProcessHandleForRead: 打开失败, pid="
            << pid
            << ", error="
            << ::GetLastError()
            << eol;
    }
    return processHandle;
}

void MemoryDock::showProcessTableContextMenu(const QPoint& localPosition)
{
    // 右键入口日志：记录触发位置，便于诊断菜单行为。
    kLogEvent contextMenuEvent;
    dbg << contextMenuEvent
        << "[MemoryDock] showProcessTableContextMenu: x="
        << localPosition.x()
        << ", y="
        << localPosition.y()
        << eol;

    if (m_processTable == nullptr)
    {
        return;
    }

    const QModelIndex index = m_processTable->indexAt(localPosition);
    if (!index.isValid() || !coreProjectionIsCurrent(CoreKind::Processes)) { return; }
    const QPointer<MemoryDock> menuOwner(this);
    const auto menuSource = m_corePublished[2];
    const int row = index.row();
    const QModelIndex pidItem = index.siblingAtColumn(1), nameItem = index.siblingAtColumn(0);
    if (!pidItem.isValid() || !nameItem.isValid())
    {
        return;
    }

    bool pidOk = false;
    const std::uint32_t pid = pidItem.data(Qt::DisplayRole).toString().toUInt(&pidOk);
    if (!pidOk || pid == 0)
    {
        return;
    }
    const QString processName = nameItem.data(Qt::DisplayRole).toString().trimmed();
    m_processTable->setCurrentIndex(index);
    if (!menuOwner || !coreProjectionIsCurrent(CoreKind::Processes)) { return; }
    const QString copiedRow = processRegionTableRowText(m_processTable, row);

    QMenu contextMenu;
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* attachAction = contextMenu.addAction(
        QIcon(":/Icon/process_start.svg"),
        QStringLiteral("附加进程"));
    QAction* dumpAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        QStringLiteral("Dump内存到文件"));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);

    const auto creationTime100ns = nameItem.data(kProcessCreationTimeRole).toULongLong();
    if (creationTime100ns != 0)
        ks::ui::x64dbg_navigation::AddAction(&contextMenu, this,
            {pid, creationTime100ns, 0, ks::ui::x64dbg_navigation::View::Disassembly});

    QAction* selectedAction = contextMenu.exec(m_processTable->viewport()->mapToGlobal(localPosition));
    if (!menuOwner || selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == attachAction && coreProjectionIsCurrent(CoreKind::Processes) && m_corePublished[2] == menuSource)
    {
        attachToProcess(pid, processName, true);
        return;
    }

    if (selectedAction == dumpAction && coreProjectionIsCurrent(CoreKind::Processes) && m_corePublished[2] == menuSource)
    {
        requestDumpProcessMemoryByPid(pid, processName);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QApplication::clipboard()->setText(copiedRow);
        kLogEvent copyProcessRowEvent;
        dbg << copyProcessRowEvent
            << "[MemoryDock] 进程表右键复制当前行, row="
            << row
            << ", pid="
            << pid
            << eol;
    }
}

void MemoryDock::requestDumpProcessMemoryByPid(const std::uint32_t pid, const QString& processName)
{
    if (readBoolProperty(this, kProcessDumpInFlightProperty))
    {
        QMessageBox::information(this, QStringLiteral("导出进程内存"),
            QStringLiteral("已有进程内存导出正在进行，请等待完成。"));
        return;
    }

    // Dump 请求日志：记录 PID 与进程名，便于后续审计。
    kLogEvent dumpRequestEvent;
    info << dumpRequestEvent
        << "[MemoryDock] requestDumpProcessMemoryByPid: pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << eol;

    // 保留选中 PID 对应的进程对象，模态选择期间退出也不会串到复用后的 PID。
    const HANDLE targetHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
        FALSE, toDwordPid(pid));
    if (targetHandle == nullptr)
    {
        const QString errorText = QStringLiteral("OpenProcess 失败, error=%1").arg(::GetLastError());
        if (!ks::ui::promptForPrivilegeFailure(this, QStringLiteral("导出进程内存"), errorText))
        {
            QMessageBox::warning(this, QStringLiteral("Dump失败"), errorText);
        }
        return;
    }
    const std::shared_ptr<void> targetProcess(targetHandle, [](void* handle) { ::CloseHandle(handle); });
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (::GetProcessTimes(targetHandle, &creation, &exit, &kernel, &user) == FALSE)
    {
        QMessageBox::warning(this, QStringLiteral("Dump失败"),
            QStringLiteral("无法读取目标进程创建时间，error=%1。").arg(::GetLastError()));
        return;
    }
    const std::uint64_t creationTime =
        (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) | creation.dwLowDateTime;

    using ksword::memory_backend::MemoryAccessBackend;
    const QStringList backendNames{
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::UserMode)),
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::StandardDriver)),
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::Hvm))
    };
    bool backendAccepted = false;
    const QString backendName = QInputDialog::getItem(this,
        QStringLiteral("导出进程内存"),
        QStringLiteral("选择本次导出的读取后端（区域由 Windows 查询；HVM 必须使用私有页表窗口）："),
        backendNames, 0, false, &backendAccepted);
    if (!backendAccepted)
    {
        return;
    }
    const int backendIndex = backendNames.indexOf(backendName);
    if (backendIndex < 0 || backendIndex > 2)
    {
        return;
    }
    const auto backend = static_cast<MemoryAccessBackend>(backendIndex);
    if (backend == MemoryAccessBackend::Hvm)
    {
        QString reason;
        if (!ksword::memory_backend::isHvmMemoryUsable(&reason))
        {
            QMessageBox::warning(this, QStringLiteral("Dump失败"), reason);
            return;
        }
    }

    const QString defaultFileName = QStringLiteral("%1_pid%2_%3.kmdump")
        .arg(processName.isEmpty() ? QStringLiteral("process") : processName)
        .arg(pid)
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("保存进程内存Dump"),
        defaultFileName,
        QStringLiteral("Ksword Memory Dump (*.kmdump);;All Files (*.*)"));
    if (outputPath.trimmed().isEmpty())
    {
        return;
    }
    // 模态对话框可触发重入；此处再查一次，避免两个导出共享同一进度任务。
    if (readBoolProperty(this, kProcessDumpInFlightProperty))
    {
        return;
    }
    setProperty(kProcessDumpInFlightProperty, true);

    if (m_dumpMemoryProgressPid == 0)
    {
        m_dumpMemoryProgressPid = kPro.addReusable(this, "内存", "Dump进程内存");
    }
    kPro.set(m_dumpMemoryProgressPid, "准备读取内存区域", 0, 5.0f);
    const int progressPid = m_dumpMemoryProgressPid;

    QPointer<MemoryDock> guardThis(this);
    std::thread([guardThis, pid, processName, outputPath, targetProcess, creationTime,
        backend, backendName, progressPid]() {
        if (guardThis == nullptr)
        {
            return;
        }

        QString errorText;
        // 工作函数是 static：不会借用 Dock 控件或可被分离操作关闭的进程句柄。
        const bool dumpOk = MemoryDock::dumpProcessMemoryToFile(pid, targetProcess,
            creationTime, backend, outputPath, progressPid, errorText);
        QMetaObject::invokeMethod(qApp, [guardThis, dumpOk, pid, processName, outputPath,
            backendName, progressPid, errorText]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->setProperty(kProcessDumpInFlightProperty, false);

            if (dumpOk)
            {
                kPro.set(progressPid, "Dump完成", 0, 100.0f);

                kLogEvent dumpFinishEvent;
                info << dumpFinishEvent
                    << "[MemoryDock] Dump完成, pid="
                    << pid
                    << ", path="
                    << outputPath.toStdString()
                    << eol;

                QMessageBox::information(
                    guardThis,
                    QStringLiteral("Dump完成"),
                    QStringLiteral("进程 %1 (PID=%2) 内存已通过 %3 保存到：\n%4")
                    .arg(processName)
                    .arg(pid)
                    .arg(backendName)
                    .arg(outputPath));
            }
            else
            {
                kPro.set(progressPid, "Dump失败", 0, 100.0f);

                kLogEvent dumpFailEvent;
                err << dumpFailEvent
                    << "[MemoryDock] Dump失败, pid="
                    << pid
                    << ", error="
                    << errorText.toStdString()
                    << eol;

                // privilegePromptHandled：记录 Dump 失败是否已由权限恢复提示处理。
                const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    guardThis,
                    QStringLiteral("导出进程内存"),
                    errorText);
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("Dump失败"),
                        QStringLiteral("进程 %1 (PID=%2) Dump失败：\n%3")
                        .arg(processName)
                        .arg(pid)
                        .arg(errorText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}

bool MemoryDock::dumpProcessMemoryToFile(
    const std::uint32_t pid,
    const std::shared_ptr<void>& targetProcess,
    const std::uint64_t creationTime,
    const ksword::memory_backend::MemoryAccessBackend backend,
    const QString& dumpFilePath,
    const int progressPid,
    QString& errorTextOut)
{
    errorTextOut.clear();

    using namespace ksword::memory_backend;
    if (backend != MemoryAccessBackend::UserMode
        && backend != MemoryAccessBackend::StandardDriver
        && backend != MemoryAccessBackend::Hvm)
    {
        errorTextOut = QStringLiteral("进程内存导出仅支持 R3、R0 或 HVM 后端。");
        return false;
    }
    const HANDLE processHandle = targetProcess.get();
    const auto identityCurrent = [processHandle, pid, creationTime]() {
        if (processHandle == nullptr || ::GetProcessId(processHandle) != toDwordPid(pid)
            || ::WaitForSingleObject(processHandle, 0) != WAIT_TIMEOUT)
        {
            return false;
        }
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (::GetProcessTimes(processHandle, &creation, &exit, &kernel, &user) == FALSE)
        {
            return false;
        }
        return ((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U)
            | creation.dwLowDateTime) == creationTime;
    };
    if (!identityCurrent())
    {
        errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
        return false;
    }

    // WOW64 目标的可查询上限可能低于宿主；非 LAA 目标的 2 GiB 上限还保留最后 64 KiB。
    // 不预截断范围，仍保留 VirtualQueryEx 可见的高位原生映射。
    BOOL targetIsWow64 = FALSE;
    const bool targetIsKnownWow64 =
        ::IsWow64Process(processHandle, &targetIsWow64) != FALSE && targetIsWow64 != FALSE;

    QSaveFile outputFile(dumpFilePath);
    outputFile.setDirectWriteFallback(false);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        errorTextOut = QStringLiteral("无法写入文件: %1").arg(dumpFilePath);
        return false;
    }
    const auto writeExact = [&outputFile, &errorTextOut](const char* bytes, const qint64 count) {
        if (outputFile.write(bytes, count) == count)
        {
            return true;
        }
        errorTextOut = QStringLiteral("转储文件写入失败：%1").arg(outputFile.errorString());
        return false;
    };

    // Dump 文件头结构：
    // - magic：文件签名；
    // - version：版本号（方便后续升级格式）；
    // - pid：目标进程 PID；
    // - timestamp100ns：创建时间戳；
    // - regionCount：成功写入的区域数量。
    struct DumpFileHeader final
    {
        char magic[8];
        std::uint32_t version = 1;
        std::uint32_t pid = 0;
        std::uint64_t timestamp100ns = 0;
        std::uint32_t regionCount = 0;
        std::uint32_t reserved = 0;
    };

    struct DumpRegionHeader final
    {
        std::uint64_t baseAddress = 0;
        std::uint64_t declaredRegionSize = 0;
        std::uint64_t dumpedBytes = 0;
        std::uint32_t protect = 0;
        std::uint32_t state = 0;
        std::uint32_t type = 0;
        std::uint32_t reserved = 0;
    };

    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER fileTimeValue{};
    fileTimeValue.LowPart = fileTime.dwLowDateTime;
    fileTimeValue.HighPart = fileTime.dwHighDateTime;

    DumpFileHeader fileHeader{};
    std::memcpy(fileHeader.magic, "KMDUMP1", 7);
    fileHeader.magic[7] = '\0';
    fileHeader.pid = pid;
    fileHeader.timestamp100ns = fileTimeValue.QuadPart;

    if (!writeExact(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader))))
    {
        return false;
    }

    SYSTEM_INFO systemInfo{};
    ::GetSystemInfo(&systemInfo);
    const std::uint64_t minAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const std::uint64_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    constexpr SIZE_T kChunkSize = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
    const DdmaSession unusedDdmaSession{};

    std::uint64_t currentAddress = minAddress;
    std::uint32_t dumpedRegionCount = 0;
    while (currentAddress < maxAddress)
    {
        if (!identityCurrent())
        {
            errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
            return false;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T querySize = ::VirtualQueryEx(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
            &mbi,
            sizeof(mbi));
        if (querySize != sizeof(mbi))
        {
            const DWORD queryError = ::GetLastError();
            if (querySize == 0U && queryError == ERROR_INVALID_PARAMETER
                && targetIsKnownWow64 && currentAddress >= 0x7FFF0000ULL)
            {
                // 已连续到达至少非 LAA 的 32 位上限，INVALID_PARAMETER 表示超出目标最高地址。
                // 仍在提交前复核句柄身份；更低地址、短响应及其他查询错误继续取消导出。
                break;
            }
            errorTextOut = QStringLiteral("内存区域查询失败，地址=0x%1，error=%2。")
                .arg(currentAddress, 0, 16).arg(queryError);
            return false;
        }

        const std::uint64_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uint64_t regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
        if (regionSize == 0ULL || regionBase > currentAddress
            || regionSize > (std::numeric_limits<std::uint64_t>::max)() - regionBase
            || regionBase + regionSize <= currentAddress)
        {
            errorTextOut = QStringLiteral("内存区域范围无效，导出已取消。");
            return false;
        }

        if (mbi.State == MEM_COMMIT && isReadableProtect(static_cast<std::uint32_t>(mbi.Protect)))
        {
            DumpRegionHeader regionHeader{};
            regionHeader.baseAddress = regionBase;
            regionHeader.declaredRegionSize = regionSize;
            regionHeader.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionHeader.state = static_cast<std::uint32_t>(mbi.State);
            regionHeader.type = static_cast<std::uint32_t>(mbi.Type);

            const qint64 headerPosition = outputFile.pos();
            if (!writeExact(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader))))
            {
                return false;
            }

            std::uint64_t offsetInRegion = 0;
            std::uint64_t dumpedBytes = 0;
            while (offsetInRegion < regionSize)
            {
                const SIZE_T remainSize = static_cast<SIZE_T>(std::min<std::uint64_t>(regionSize - offsetInRegion, kChunkSize));
                if (!identityCurrent())
                {
                    errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
                    return false;
                }
                const AccessOutcome outcome = readVirtual(backend, unusedDdmaSession,
                    pid, regionBase + offsetInRegion, static_cast<std::uint64_t>(remainSize),
                    /*requireHvmDirectWindow*/ true);
                if (!identityCurrent())
                {
                    errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
                    return false;
                }
                if (!outcome.ok || outcome.partial || outcome.bytesDone != remainSize
                    || static_cast<std::uint64_t>(outcome.data.size()) != remainSize)
                {
                    errorTextOut = QStringLiteral("内存读取未完成，地址=0x%1，实际=%2/%3 字节。%4")
                        .arg(regionBase + offsetInRegion, 0, 16).arg(outcome.bytesDone)
                        .arg(static_cast<std::uint64_t>(remainSize)).arg(outcome.failureText);
                    return false;
                }
                if (!writeExact(outcome.data.constData(), outcome.data.size()))
                {
                    return false;
                }
                dumpedBytes += static_cast<std::uint64_t>(remainSize);
                offsetInRegion += static_cast<std::uint64_t>(remainSize);
            }

            regionHeader.dumpedBytes = dumpedBytes;
            const qint64 endPosition = outputFile.pos();
            if (!outputFile.seek(headerPosition)
                || !writeExact(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader)))
                || !outputFile.seek(endPosition))
            {
                if (errorTextOut.isEmpty())
                {
                    errorTextOut = QStringLiteral("转储文件定位失败：%1").arg(outputFile.errorString());
                }
                return false;
            }

            if (dumpedBytes > 0)
            {
                ++dumpedRegionCount;
            }
        }

        const std::uint64_t totalRange = maxAddress - minAddress;
        if (totalRange > 0)
        {
            const float progressValue = static_cast<float>(
                std::min<std::uint64_t>(
                    95,
                    ((regionBase - minAddress) * 95ULL) / totalRange));
            kPro.set(progressPid, "读取并写入内存区域中", 0, progressValue);
        }

        const std::uint64_t nextAddress = regionBase + regionSize;
        currentAddress = nextAddress;
    }

    if (dumpedRegionCount == 0)
    {
        errorTextOut = QStringLiteral("未读取到可导出的有效区域。");
        return false;
    }
    if (!identityCurrent())
    {
        errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
        return false;
    }
    // 保留 KMDUMP1 布局；只有完整读取、所有文件写入成功才原子提交到目标路径。
    fileHeader.regionCount = dumpedRegionCount;
    if (!outputFile.seek(0)
        || !writeExact(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader))))
    {
        if (errorTextOut.isEmpty())
        {
            errorTextOut = QStringLiteral("转储文件定位失败：%1").arg(outputFile.errorString());
        }
        return false;
    }
    if (!outputFile.commit())
    {
        errorTextOut = QStringLiteral("转储文件提交失败：%1").arg(outputFile.errorString());
        return false;
    }
    return true;
}

bool MemoryDock::enumerateMemoryRegionsByVirtualQuery(
    HANDLE processHandle,
    std::vector<RegionEntry>& regionsOut,
    QString* const errorTextOut) const
{
    // VirtualQueryEx 枚举入口日志：输出句柄有效性说明。
    kLogEvent enumerateRegionStartEvent;
    dbg << enumerateRegionStartEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 开始遍历虚拟内存区域。"
        << eol;

    regionsOut.clear();

    // 实际遍历下沉到无 Qt 依赖的采集函数：同一段逻辑同时服务这里的同步兜底
    // 与 refreshMemoryRegionList 提交的线程池任务，避免两份实现慢慢走样。
    const std::vector<RegionSnapshotRow> regionRows = collectVirtualMemoryRegionRows(processHandle);
    regionsOut.reserve(regionRows.size());
    for (const RegionSnapshotRow& regionRow : regionRows)
    {
        RegionEntry entry{};
        entry.baseAddress = regionRow.baseAddress;
        entry.regionSize = regionRow.regionSize;
        entry.protect = regionRow.protect;
        entry.state = regionRow.state;
        entry.type = regionRow.type;
        entry.mappedFilePath = regionRow.mappedFilePath;
        regionsOut.push_back(std::move(entry));
    }

    if (regionsOut.empty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "VirtualQueryEx 未返回有效区域。";
        }
        kLogEvent enumerateRegionEmptyEvent;
        warn << enumerateRegionEmptyEvent
            << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 枚举结果为空。"
            << eol;
        return false;
    }

    // 枚举结束日志：用于衡量目标进程地址空间复杂度。
    kLogEvent enumerateRegionFinishEvent;
    dbg << enumerateRegionFinishEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 完成, count="
        << regionsOut.size()
        << eol;
    return true;
}

void MemoryDock::applyRegionFilterAndRebuildTable() { if (m_regionTable) { requestCoreProjection(CoreKind::Regions, false); } }


struct MemoryDock::CoreProjectionJob {
    std::atomic_bool done{false}, cancel{false};
    std::shared_ptr<std::atomic_bool> lifetime;
    std::shared_ptr<CoreProjectionData> data;
    bool failed = false;
    bool cancelled() const { return cancel.load() || (lifetime && lifetime->load()); }
};

QString MemoryDock::coreRowKey(const CoreProjectionData& data, const std::size_t row)
{
    if (data.kind == CoreKind::Processes) { const auto& entry = (*data.processes)[row]; return QString::number(entry.pid) + QLatin1Char(':') + QString::number(entry.creationTime100ns); }
    if (row == SIZE_MAX) { return {}; }
    const auto target = QString::number(data.pid) + QLatin1Char(':') + QString::number(data.target) + QLatin1Char(':');
    if (data.extraSource) { return target + data.extraKey(row); }
    if (data.kind == CoreKind::Modules) {
        const auto& entry = (*data.modules)[row];
        return target + QString::number(entry.baseAddress) + QLatin1Char(':') + QString::number(entry.fullPath.size()) + QLatin1Char(':') + entry.fullPath;
    }
    const auto& entry = (*data.regions)[row];
    return target + QString::number(entry.baseAddress) + QLatin1Char(':') + QString::number(entry.regionSize);
}

QVariant MemoryDock::coreCell(const CoreProjectionData& data, const std::size_t row, const int column, const int role)
{
    if (role == ks::memory_detail::CoreSourceIndexRole) { return QVariant::fromValue<qulonglong>(row); }
    if (role == ks::memory_detail::CoreIdentityRole) { return coreRowKey(data, row); }
    if (data.extraSource) { return data.extraCell(row, column, role); }
    const bool numeric = role == ks::ui::NumericSortRole;
    if (data.kind == CoreKind::Processes) {
        const auto& entry = (*data.processes)[row];
        if (column == 0) {
            if (role == kIconPathItemRole) { return entry.imagePath; }
            if (role == Qt::DecorationRole) { return lookupCachedPathIcon(entry.imagePath); }
            if (role == kProcessCreationTimeRole) { return QVariant::fromValue<qulonglong>(entry.creationTime100ns); }
        }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole && !numeric) { return {}; }
        switch (column) {
        case 0: return entry.processName;
        case 1: return numeric ? QVariant::fromValue(entry.pid) : QVariant(QString::number(entry.pid));
        case 2: return numeric ? QVariant::fromValue(entry.sessionId) : QVariant(QString::number(entry.sessionId));
        case 3: return numeric ? QVariant(entry.cpuPercentValid ? entry.cpuPercent : -1.0) : QVariant(entry.cpuPercentValid ? QString::number(entry.cpuPercent, 'f', 2) + QLatin1Char('%') : QStringLiteral("-"));
        case 4: return numeric ? QVariant(entry.workingSetMB) : QVariant(QStringLiteral("%1 MB").arg(entry.workingSetMB, 0, 'f', 1));
        default: return {};
        }
    }
    if (data.kind == CoreKind::Modules) {
        const auto& entry = (*data.modules)[row];
        if (column == 0) {
            if (role == kIconPathItemRole) { return entry.fullPath.trimmed(); }
            if (role == Qt::DecorationRole) { return lookupCachedPathIcon(entry.fullPath); }
            if (role == Qt::UserRole) { return QVariant::fromValue<qulonglong>(entry.baseAddress); }
            if (role == Qt::UserRole + 1) { return QVariant::fromValue(entry.representativeThreadId); }
        }
        if (column == 2 && role == Qt::ForegroundRole) {
            return QBrush(entry.signatureTrusted ? KswordTheme::SuccessColor()
                : entry.signatureState.compare(QStringLiteral("Pending"), Qt::CaseInsensitive) == 0 || entry.signatureState.compare(QStringLiteral("Unknown"), Qt::CaseInsensitive) == 0
                    ? KswordTheme::TextSecondaryColor() : KswordTheme::ErrorColor());
        }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole && !numeric) { return {}; }
        switch (column) {
        case 0: return entry.fullPath;
        case 1: return numeric ? QVariant::fromValue<qulonglong>(entry.sizeBytes) : QVariant(formatSize(entry.sizeBytes));
        case 2: return data.language.sourceText(entry.signatureState);
        case 3: return numeric ? QVariant::fromValue<qulonglong>(entry.entryPointOffset) : QVariant(QStringLiteral("0x%1").arg(entry.entryPointOffset, 0, 16).toUpper());
        case 4: return data.language.sourceText(entry.runningState);
        case 5: return role == Qt::ToolTipRole
            ? QVariant(data.language.sourceText(QStringLiteral("%1\n仅列出启动地址位于该模块内的线程，不代表当前执行位置。? 表示部分线程的启动地址无法查询。"))
                .arg(entry.threadIdText)) : QVariant(entry.threadIdText);
        default: return {};
        }
    }
    const auto& entry = (*data.regions)[row];
    if (role == Qt::UserRole) {
        if (column == 0) { return QVariant::fromValue<qulonglong>(entry.baseAddress); }
        if (column == 1) { return QVariant::fromValue<qulonglong>(entry.regionSize); }
    }
    if (role != Qt::DisplayRole && role != Qt::ToolTipRole && !numeric) { return {}; }
    switch (column) {
    case 0: return numeric ? QVariant::fromValue<qulonglong>(entry.baseAddress) : QVariant(formatAddress(entry.baseAddress));
    case 1: return numeric ? QVariant::fromValue<qulonglong>(entry.regionSize) : QVariant(formatSize(entry.regionSize));
    case 2: return protectToText(entry.protect);
    case 3: return stateToText(entry.state);
    case 4: return typeToText(entry.type);
    case 5: return entry.mappedFilePath;
    default: return {};
    }
}

bool MemoryDock::sameCoreRequest(const CoreProjectionData& left, const CoreProjectionData& right)
{
    return left.kind == right.kind && left.extraSource == right.extraSource && left.extraRisk == right.extraRisk && left.processes == right.processes && left.modules == right.modules && left.regions == right.regions
        && left.filter == right.filter && left.pid == right.pid && left.target == right.target
        && left.localeGeneration == right.localeGeneration && left.languageId == right.languageId
        && left.committed == right.committed && left.image == right.image && left.readable == right.readable
        && left.sortColumn == right.sortColumn && left.sortOrder == right.sortOrder;
}

std::shared_ptr<MemoryDock::CoreProjectionData> MemoryDock::captureCoreRequest(const CoreKind kind) const
{
    auto data = std::make_shared<CoreProjectionData>();
    data->kind = kind; data->localeGeneration = m_coreLocaleGeneration;
    data->language = ks::i18n::LanguageManager::instance().sourceTextSnapshot(); data->languageId = data->language.languageId();
    const auto index = static_cast<std::size_t>(kind);
    data->sortColumn = m_coreSortColumns[index]; data->sortOrder = m_coreSortOrders[index];
    if (kind == CoreKind::Processes) {
        data->processes = m_processCache; data->filter = m_processFilterEdit ? m_processFilterEdit->text().trimmed() : QString();
        if (m_processTable) { data->selectedKey = m_processTable->currentIndex().data(ks::memory_detail::CoreIdentityRole).toString(); data->selectedColumn = m_processTable->currentIndex().column(); }
    } else if (kind == CoreKind::Modules) {
        data->modules = m_moduleCache; data->filter = m_moduleFilterEdit ? m_moduleFilterEdit->text().trimmed() : QString();
        data->pid = m_moduleCachePid; data->target = m_moduleCacheCreateTime; data->statusTemplate = m_moduleCacheStatusTemplate;
        if (m_moduleTable) {
            data->selectedKey = m_moduleTable->currentIndex().data(ks::memory_detail::CoreIdentityRole).toString();
            data->selectedColumn = m_moduleTable->currentIndex().column();
        }
    } else if (kind == CoreKind::Regions) {
        data->regions = m_regionCache; data->filter = m_regionFilterEdit ? m_regionFilterEdit->text().trimmed() : QString();
        data->pid = m_attachedPid; data->target = m_processAttachmentGeneration.load();
        data->committed = m_regionCommittedOnlyCheck && m_regionCommittedOnlyCheck->isChecked();
        data->image = m_regionImageOnlyCheck && m_regionImageOnlyCheck->isChecked();
        data->readable = m_regionReadableOnlyCheck && m_regionReadableOnlyCheck->isChecked();
        if (m_regionTable) {
            data->selectedKey = m_regionTable->currentIndex().data(ks::memory_detail::CoreIdentityRole).toString();
            data->selectedColumn = m_regionTable->currentIndex().column();
        }
    }
    if (static_cast<int>(kind) >= 3) {
        data->pid = kind == CoreKind::PteEvidence || kind == CoreKind::ProcessEvidence || kind == CoreKind::SearchResults ? m_attachedPid : 0;
        data->target = kind == CoreKind::PteEvidence || kind == CoreKind::ProcessEvidence || kind == CoreKind::SearchResults ? m_processAttachmentGeneration.load() : 0;
        switch (kind) {
        case CoreKind::KernelExecutable: captureKernelExecutableProjection(*data); break;
        case CoreKind::KernelEvidence: captureKernelMemoryProjection(*data); break;
        case CoreKind::PteEvidence: capturePteProjection(*data); break;
        case CoreKind::ProcessEvidence: captureProcessEvidenceProjection(*data); break;
        case CoreKind::SearchResults: captureSearchResultProjection(*data); break;
        default: break;
        }
        if (auto* table = extraCoreTable(kind)) { data->selectedKey = table->currentIndex().data(ks::memory_detail::CoreIdentityRole).toString(); data->selectedColumn = table->currentIndex().column(); }
    }
    return data;
}

void MemoryDock::buildCoreProjection(const std::shared_ptr<CoreProjectionJob>& job)
{
    try {
        auto& data = *job->data;
        data.rows = ks::memory_detail::ValueStorage<std::vector<std::size_t>>();
        const std::size_t count = data.extraSource ? data.extraCount : data.kind == CoreKind::Processes ? data.processes->size() : data.kind == CoreKind::Modules ? data.modules->size() : data.regions->size();
        struct SortRow { std::size_t source; QVariant key; };
        std::vector<SortRow> rows; rows.reserve(count);
        auto selected = std::numeric_limits<std::size_t>::max();
        for (std::size_t row = 0; row < count; ++row) {
            if ((row & 63U) == 0 && job->cancelled()) { job->done.store(true); return; }
            if (data.extraSource) { if (!data.extraMatches(row)) { continue; } }
            else if (data.kind == CoreKind::Processes) {
                const auto& entry = (*data.processes)[row];
                if (!data.filter.isEmpty() && !entry.processName.contains(data.filter, Qt::CaseInsensitive) && !QString::number(entry.pid).contains(data.filter, Qt::CaseInsensitive)) { continue; }
            } else if (data.kind == CoreKind::Modules) {
                const auto& entry = (*data.modules)[row];
                if (!data.filter.isEmpty() && !entry.moduleName.contains(data.filter, Qt::CaseInsensitive) && !entry.fullPath.contains(data.filter, Qt::CaseInsensitive)) { continue; }
            } else {
                const auto& entry = (*data.regions)[row];
                if ((data.committed && entry.state != MEM_COMMIT) || (data.image && entry.type != MEM_IMAGE) || (data.readable && !isReadableProtect(entry.protect))) { continue; }
                if (!data.filter.isEmpty() && !formatAddress(entry.baseAddress).contains(data.filter, Qt::CaseInsensitive)
                    && !protectToText(entry.protect).contains(data.filter, Qt::CaseInsensitive) && !entry.mappedFilePath.contains(data.filter, Qt::CaseInsensitive)) { continue; }
            }
            if (!data.selectedKey.isEmpty() && coreRowKey(data, row) == data.selectedKey) { selected = row; }
            rows.push_back({row, coreCell(data, row, data.sortColumn, ks::ui::NumericSortRole)});
        }
        std::stable_sort(rows.begin(), rows.end(), [&](const auto& left, const auto& right) {
            int comparison = 0;
            if (left.key.metaType().id() == QMetaType::QString) { comparison = QString::compare(left.key.toString(), right.key.toString(), Qt::CaseInsensitive); }
            else if (left.key.metaType().id() == QMetaType::Double) { const auto a = left.key.toDouble(), b = right.key.toDouble(); comparison = a < b ? -1 : a > b ? 1 : 0; }
            else { const auto a = left.key.toULongLong(), b = right.key.toULongLong(); comparison = a < b ? -1 : a > b ? 1 : 0; }
            return comparison == 0 ? left.source < right.source : data.sortOrder == Qt::AscendingOrder ? comparison < 0 : comparison > 0;
        });
        if (!job->cancelled()) {
            data.rows->reserve(rows.size());
            for (const auto& row : rows) {
                if (row.source == selected) { data.selectedRow = static_cast<int>(data.rows->size()); }
                data.rows->push_back(row.source);
            }
            if (data.extraSource && data.extraDiagnosticRow && data.rows->empty()) { data.rows->push_back(SIZE_MAX); }
        }
    } catch (...) { job->failed = true; }
    job->done.store(true);
}

void MemoryDock::initializeCoreProjection(const CoreKind kind)
{
    const auto index = static_cast<std::size_t>(kind);
    if (m_coreInitialized[index]) { return; }
    m_coreInitialized[index] = true;
    if (!m_coreProjectionPoll) {
        m_coreProjectionPoll = new QTimer(this); m_coreProjectionPoll->setInterval(25);
        connect(m_coreProjectionPoll, &QTimer::timeout, this, [this] { pollCoreProjection(); });
        m_coreProjectionDebounce = new QTimer(this); m_coreProjectionDebounce->setSingleShot(true); m_coreProjectionDebounce->setInterval(120);
        connect(m_coreProjectionDebounce, &QTimer::timeout, this, [this] { pollCoreProjection(); });
        connect(this, &QObject::destroyed, [lifetime = m_coreProjectionLifetime] { lifetime->store(true); });
    }
    QAbstractItemView* view = kind == CoreKind::Processes ? static_cast<QAbstractItemView*>(m_processTable) : kind == CoreKind::Modules ? static_cast<QAbstractItemView*>(m_moduleTable) : kind == CoreKind::Regions ? m_regionTable : extraCoreTable(kind);
    auto* model = kind == CoreKind::Processes ? m_processTable->readOnlyModel : kind == CoreKind::Modules ? m_moduleTable->readOnlyModel : kind == CoreKind::Regions ? m_regionTable->readOnlyModel : extraCoreTable(kind)->readOnlyModel;
    model->requestSort = [guard = QPointer<MemoryDock>(this), kind, index](int column, Qt::SortOrder order) {
        if (!guard || (guard->m_coreSortColumns[index] == column && guard->m_coreSortOrders[index] == order)) { return; }
        guard->m_coreSortColumns[index] = column; guard->m_coreSortOrders[index] = order;
        guard->requestCoreProjection(kind, true);
    };
    new CoreProjectionObserver(view, [guard = QPointer<MemoryDock>(this), kind](bool language) {
        if (!guard) { return; }
        if (language) { ++guard->m_coreLocaleGeneration; }
        guard->requestCoreProjection(kind, false);
    }, kind == CoreKind::Modules || kind == CoreKind::Processes);
}

void MemoryDock::requestCoreProjection(const CoreKind kind, const bool debounce)
{
    const auto index = static_cast<std::size_t>(kind);
    QAbstractItemView* view = kind == CoreKind::Processes ? static_cast<QAbstractItemView*>(m_processTable) : kind == CoreKind::Modules ? static_cast<QAbstractItemView*>(m_moduleTable) : kind == CoreKind::Regions ? m_regionTable : extraCoreTable(kind);
    if (!view) { return; }
    auto request = captureCoreRequest(kind);
    if (m_corePublished[index] && sameCoreRequest(*request, *m_corePublished[index])) {
        if (m_coreProjectionJob && m_coreProjectionJob->data->kind == kind && !sameCoreRequest(*request, *m_coreProjectionJob->data)) { m_coreProjectionJob->cancel.store(true); }
        view->setEnabled(true); return;
    }
    if (m_coreFailed[index]) { if (sameCoreRequest(*request, *m_coreFailed[index])) { return; } m_coreFailed[index].reset(); }
    if (m_coreReady[index] && !sameCoreRequest(*request, *m_coreReady[index])) { m_coreReady[index].reset(); }
    const QPointer<MemoryDock> owner(this);
    const QPointer<QAbstractItemView> guardedView(view);
    view->setEnabled(false);
    if (!owner || !guardedView) { return; }
    if (m_coreProjectionJob && m_coreProjectionJob->data->kind == kind && !sameCoreRequest(*request, *m_coreProjectionJob->data)) { m_coreProjectionJob->cancel.store(true); }
    if (debounce) { m_coreProjectionDebounce->start(); return; }
    if (!view->isVisible() || m_coreProjectionDebounce->isActive()) { return; }
    if (m_coreReady[index]) {
        if (sameCoreRequest(*request, *m_coreReady[index])) {
            const auto ready = std::move(m_coreReady[index]); publishCoreProjection(ready); return;
        }
        m_coreReady[index].reset();
    }
    if (m_coreProjectionJob) { return; }
    const auto job = std::make_shared<CoreProjectionJob>(); job->data = std::move(request); job->lifetime = m_coreProjectionLifetime;
    m_coreProjectionJob = job; m_coreProjectionPoll->start();
    try { QThreadPool::globalInstance()->start([job] { buildCoreProjection(job); }); }
    catch (...) { job->failed = true; job->done.store(true); }
}

void MemoryDock::publishCoreProjection(const std::shared_ptr<CoreProjectionData>& data)
{
    const auto current = captureCoreRequest(data->kind);
    if (!sameCoreRequest(*current, *data)) { return; }
    const auto kind = static_cast<std::size_t>(data->kind);
    const QPointer<MemoryDock> owner(this);
    const QPointer<QAbstractItemView> view(data->kind == CoreKind::Processes ? static_cast<QAbstractItemView*>(m_processTable) : data->kind == CoreKind::Modules ? static_cast<QAbstractItemView*>(m_moduleTable) : data->kind == CoreKind::Regions ? m_regionTable : extraCoreTable(data->kind));
    if (!view || !view->isVisible()) { m_coreReady[kind] = data; return; }
    const QPointer<ks::memory_detail::CoreReadOnlyModel> model(data->kind == CoreKind::Processes ? m_processTable->readOnlyModel : data->kind == CoreKind::Modules ? m_moduleTable->readOnlyModel : data->kind == CoreKind::Regions ? m_regionTable->readOnlyModel : extraCoreTable(data->kind)->readOnlyModel);
    const int scroll = view->verticalScrollBar()->value();
    model->publish(data->rows, [data](std::size_t row, int column, int role) { return coreCell(*data, row, column, role); });
    if (!owner || !view || !sameCoreRequest(*captureCoreRequest(data->kind), *data)) { return; }
    m_corePublished[kind] = data;
    view->setEnabled(true);
    if (!owner || !view || !model || view->model() != model || !sameCoreRequest(*captureCoreRequest(data->kind), *data)) { return; }
    if (data->selectedRow >= 0 || (data->extraSource && model->rowCount() > 0)) { view->setCurrentIndex(model->index(data->selectedRow >= 0 ? data->selectedRow : 0, qMax(0, data->selectedColumn))); }
    if (!owner || !view || !model || view->model() != model || !sameCoreRequest(*captureCoreRequest(data->kind), *data)) { return; }
    view->verticalScrollBar()->setValue(scroll);
    if (!owner) { return; }
    if (data->extraSource) {
        const auto count = data->rows->size() == 1 && data->rows->front() == SIZE_MAX ? 0U : data->rows->size();
        switch (data->kind) {
        case CoreKind::KernelExecutable: m_kernelExecutableVisibleCount = count; if (!data->statusTemplate.isEmpty() && m_kernelExecutableStatusLabel) { m_kernelExecutableStatusLabel->setText(data->statusTemplate.arg(count)); } break;
        case CoreKind::KernelEvidence: m_kernelMemoryEvidenceVisibleCount = count; if (!data->statusTemplate.isEmpty() && m_kernelMemoryEvidenceStatusLabel) { m_kernelMemoryEvidenceStatusLabel->setText(data->statusTemplate.arg(count)); } break;
        case CoreKind::PteEvidence: m_processPteTranslateVisibleCount = count; break;
        case CoreKind::ProcessEvidence: m_processMemoryEvidenceVisibleCount = count; break;
        default: break;
        }
        if (!owner) { return; }
    }
    if (data->kind == CoreKind::Processes) {
        const auto pending = static_cast<std::uint32_t>(property(kProcessFocusPendingPidProperty).toUInt());
        if (pending != 0) { if (selectProcessRowByPid(m_processTable, m_processCombo, pending)) { setProperty(kProcessFocusPendingPidProperty, 0U); } }
        if (!owner) { return; }
        if (m_processCountLabel) { m_processCountLabel->setText(data->filter.isEmpty() ? QString("共 %1 个进程").arg(data->processes->size()) : QString("显示 %1 / 共 %2").arg(data->rows->size()).arg(data->processes->size())); }
    } else if (data->kind == CoreKind::Modules && m_moduleStatusLabel) {
        if (!data->statusTemplate.isEmpty()) { m_moduleStatusLabel->setText(data->statusTemplate.arg(data->rows->size())); }
    } else if (data->kind == CoreKind::Regions && m_regionStatusLabel) {
        QString status = m_attachedPid ? QStringLiteral("显示 %1 / 共 %2 个区域").arg(data->rows->size()).arg(data->regions->size()) : QStringLiteral("未附加进程。");
        if (m_regionCachePartial) { status += QStringLiteral(" | ") + ks::i18n::packedSourceText(QStringLiteral("Region enumeration is partial (Win32: %1)")).arg(m_regionCacheError); }
        m_regionStatusLabel->setText(status);
        // 模块跨页请求必须等真实区域投影发布后，再按地址选中排序后的显示行。
        applyPendingModuleRegionFocus();
    }
}

void MemoryDock::pollCoreProjection()
{
    const QPointer<MemoryDock> owner(this);
    pollMemoryScanTask();
    if (!owner) { return; }
    pollFirstScanPreparation();
    if (!owner) { return; }
    pollRegionRefresh();
    if (!owner) { return; }
    if (m_coreProjectionJob && m_coreProjectionJob->done.load()) {
        const auto job = std::move(m_coreProjectionJob);
        const auto kind = static_cast<std::size_t>(job->data->kind);
        if (!job->cancelled() && sameCoreRequest(*captureCoreRequest(job->data->kind), *job->data)) {
            if (job->failed) {
                m_coreFailed[kind] = job->data;
                QAbstractItemView* view = job->data->kind == CoreKind::Processes ? static_cast<QAbstractItemView*>(m_processTable) : job->data->kind == CoreKind::Modules ? static_cast<QAbstractItemView*>(m_moduleTable) : job->data->kind == CoreKind::Regions ? m_regionTable : extraCoreTable(job->data->kind);
                if (view) { view->setEnabled(true); }
                if (!owner) { return; }
                QLabel* label = job->data->kind == CoreKind::Processes ? m_processCountLabel : job->data->kind == CoreKind::Modules ? m_moduleStatusLabel : job->data->kind == CoreKind::Regions ? m_regionStatusLabel : job->data->kind == CoreKind::KernelExecutable ? m_kernelExecutableStatusLabel : job->data->kind == CoreKind::KernelEvidence ? m_kernelMemoryEvidenceStatusLabel : job->data->kind == CoreKind::PteEvidence ? m_processPteTranslateStatusLabel : job->data->kind == CoreKind::ProcessEvidence ? m_processMemoryEvidenceStatusLabel : job->data->kind == CoreKind::SearchResults ? m_scanStatusLabel : nullptr;
                if (label) { label->setText(ks::i18n::packedSourceText(QStringLiteral("Memory table projection failed"))); }
            } else { m_coreReady[kind] = job->data; }
        }
    }
    if (m_processTable && m_processTable->isVisible()) { requestCoreProjection(CoreKind::Processes, false); }
    if (!owner) { return; }
    if (m_moduleTable && m_moduleTable->isVisible()) { requestCoreProjection(CoreKind::Modules, false); }
    if (!owner) { return; }
    if (m_regionTable && m_regionTable->isVisible()) { requestCoreProjection(CoreKind::Regions, false); }
    if (auto* table = extraCoreTable(CoreKind::KernelExecutable); table && table->isVisible()) { requestCoreProjection(CoreKind::KernelExecutable, false); }
    if (!owner) { return; }
    if (auto* table = extraCoreTable(CoreKind::KernelEvidence); table && table->isVisible()) { requestCoreProjection(CoreKind::KernelEvidence, false); }
    if (!owner) { return; }
    if (auto* table = extraCoreTable(CoreKind::PteEvidence); table && table->isVisible()) { requestCoreProjection(CoreKind::PteEvidence, false); }
    if (!owner) { return; }
    if (auto* table = extraCoreTable(CoreKind::ProcessEvidence); table && table->isVisible()) { requestCoreProjection(CoreKind::ProcessEvidence, false); }
    if (!owner) { return; }
    if (m_searchResultTable && m_searchResultTable->isVisible()) { requestCoreProjection(CoreKind::SearchResults, false); }
    if (!owner) { return; }
    if (owner && !m_coreProjectionJob && !m_regionRefreshJob && !m_regionRefreshPendingJob && !m_firstScanPreparation && !m_scanInProgress.load() && !m_scanCompletion) { m_coreProjectionPoll->stop(); }
}

bool MemoryDock::coreProjectionIsCurrent(const CoreKind kind) const
{
    const auto index = static_cast<std::size_t>(kind);
    return m_corePublished[index] && sameCoreRequest(*captureCoreRequest(kind), *m_corePublished[index]);
}

struct MemoryDock::RegionRefreshJob {
    std::atomic_bool done{false}, cancel{false};
    std::shared_ptr<std::atomic_bool> lifetime;
    std::shared_ptr<void> handle;
    std::shared_ptr<const std::vector<RegionEntry>> rows;
    std::uint64_t generation = 0;
    std::uint32_t error = ERROR_SUCCESS;
    bool partial = false;
    bool cancelled() const { return cancel.load() || (lifetime && lifetime->load()); }
};

void MemoryDock::startPendingRegionRefresh()
{
    if (m_regionRefreshJob || !m_regionRefreshPendingJob) { return; }
    const auto job = std::move(m_regionRefreshPendingJob); m_regionRefreshJob = job;
    try { QThreadPool::globalInstance()->start([job] {
        try {
            const auto cancelled = [job] { return job->cancelled(); };
            auto collected = collectVirtualMemoryRegionRows(static_cast<HANDLE>(job->handle.get()), cancelled, &job->error);
            auto rows = ks::memory_detail::ValueStorage<std::vector<RegionEntry>>(); rows->reserve(collected.size());
            for (auto& row : collected) {
                if (job->cancelled()) { break; }
                RegionEntry entry; entry.baseAddress = row.baseAddress; entry.regionSize = row.regionSize;
                entry.protect = row.protect; entry.state = row.state; entry.type = row.type; entry.mappedFilePath = std::move(row.mappedFilePath);
                rows->push_back(std::move(entry));
            }
            job->partial = job->error != ERROR_SUCCESS; job->rows = std::move(rows);
        } catch (...) { job->error = ERROR_NOT_ENOUGH_MEMORY; }
        job->handle.reset(); job->done.store(true);
    }); } catch (...) { job->error = ERROR_NOT_ENOUGH_MEMORY; job->handle.reset(); job->done.store(true); }
}

void MemoryDock::pollRegionRefresh()
{
    if (!m_regionRefreshJob || !m_regionRefreshJob->done.load()) { return; }
    const auto job = std::move(m_regionRefreshJob);
    if (!job->cancelled() && job->generation == m_processAttachmentGeneration.load()) {
        const QPointer<MemoryDock> owner(this);
        m_regionSearchSnapshot = job->rows; m_regionSearchGeneration = job->generation;
        m_regionSearchError = job->error != ERROR_SUCCESS ? job->error : !job->rows || job->rows->empty() ? ERROR_INVALID_DATA : ERROR_SUCCESS;
        const bool hadSearch = bool(m_firstScanPreparation);
        if (hadSearch) { acceptFirstScanRegionSnapshot(m_regionSearchSnapshot, m_regionSearchError); }
        if (!owner) { return; }
        const auto commit = [owner, job, hadSearch] {
            if (!owner || job->generation != owner->m_processAttachmentGeneration.load() || job->cancelled()) { return; }
            if (!job->rows || job->rows->empty()) {
                owner->setProperty(kRegionRefreshInFlightProperty, false);
                const bool pending = owner->property(kRegionRefreshPendingProperty).toBool();
                owner->setProperty(kRegionRefreshPendingProperty, false);
                // 最终枚举失败时没有新投影可发布，显式结束模块定位，避免以后刷新抢回选区。
                if (!pending) { owner->m_pendingModuleRegionFocus.reset(); }
                if (!hadSearch) { reportRegionEnumerateFailure(owner, QStringLiteral("VirtualQueryEx 未返回有效区域。")); }
                if (owner && pending && job->generation == owner->m_processAttachmentGeneration.load()) { owner->refreshMemoryRegionList(true); }
                return;
            }
            owner->m_regionCache = job->rows; owner->m_regionCachePartial = job->partial; owner->m_regionCacheError = job->error;
            owner->applyRegionFilterAndRebuildTable();
            if (!owner) { return; }
            owner->setProperty(kRegionRefreshInFlightProperty, false);
            if (owner->property(kRegionRefreshPendingProperty).toBool()) {
                owner->setProperty(kRegionRefreshPendingProperty, false); owner->refreshMemoryRegionList(true);
            }
        };
        if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this, QStringLiteral("memory-region-list-snapshot-apply"), {m_regionTable}, commit)) { commit(); }
        if (!owner) { return; }
    }
    startPendingRegionRefresh();
}

void MemoryDock::requestFirstScanRegions()
{
    if (!m_regionCache->empty() && !m_regionCachePartial) { acceptFirstScanRegionSnapshot(m_regionCache, ERROR_SUCCESS); return; }
    if (readBoolProperty(this, kRegionRefreshInFlightProperty) && m_regionSearchGeneration == m_processAttachmentGeneration.load()) { acceptFirstScanRegionSnapshot(m_regionSearchSnapshot, m_regionSearchError); return; }
    if (readBoolProperty(this, kRegionRefreshInFlightProperty)) { return; }
    refreshMemoryRegionList(true);
}

void MemoryDock::refreshMemoryRegionList(const bool forceRequery)
{
    if (m_attachedProcessHandle == nullptr) {
        m_regionCache = ks::memory_detail::ValueStorage<std::vector<RegionEntry>>(); m_regionCachePartial = false; m_regionCacheError = 0;
        applyRegionFilterAndRebuildTable(); return;
    }
    if (!forceRequery && !m_regionCache->empty()) { applyRegionFilterAndRebuildTable(); return; }
    if (readBoolProperty(this, kRegionRefreshInFlightProperty)) { setProperty(kRegionRefreshPendingProperty, true); return; }
    setProperty(kRegionRefreshFromAttachProperty, false);
    std::uint32_t error = ERROR_SUCCESS;
    const auto handle = duplicateAttachedProcessHandleForWorker(&error);
    if (!handle) {
        if (m_firstScanPreparation) { acceptFirstScanRegionSnapshot({}, error != ERROR_SUCCESS ? error : ERROR_INVALID_HANDLE); }
        else { reportRegionEnumerateFailure(this, QStringLiteral("VirtualQueryEx 未返回有效区域。")); }
        return;
    }
    m_regionSearchSnapshot.reset(); m_regionSearchGeneration = UINT64_MAX; m_regionSearchError = ERROR_SUCCESS;
    auto job = std::make_shared<RegionRefreshJob>(); job->handle = handle; job->generation = m_processAttachmentGeneration.load(); job->lifetime = m_coreProjectionLifetime;
    m_regionRefreshPendingJob = job;
    if (m_regionRefreshJob) { m_regionRefreshJob->cancel.store(true); }
    setProperty(kRegionRefreshInFlightProperty, true);
    startPendingRegionRefresh(); m_coreProjectionPoll->start();
}

void MemoryDock::cancelCoreProjection(const bool closing)
{
    cancelFirstScanPreparation();
    m_regionSearchSnapshot.reset(); m_regionSearchGeneration = UINT64_MAX;
    if (closing) { m_coreProjectionLifetime->store(true); m_moduleRefreshLifetime->store(true); }
    if (m_coreProjectionJob) { m_coreProjectionJob->cancel.store(true); }
    if (m_regionRefreshJob) { m_regionRefreshJob->cancel.store(true); }
    if (m_moduleRefreshJob) { m_moduleRefreshJob->cancel.store(true); }
    m_regionRefreshPendingJob.reset();
    for (auto& data : m_coreReady) { data.reset(); }
    for (auto& data : m_corePublished) { data.reset(); }
    for (auto& data : m_coreFailed) { data.reset(); }
}

MemoryTableView* MemoryDock::extraCoreTable(const CoreKind kind) const
{
    switch (kind) {
    case CoreKind::KernelExecutable: return m_kernelExecutableTable;
    case CoreKind::KernelEvidence: return m_kernelMemoryEvidenceTable;
    case CoreKind::PteEvidence: return m_processPteTranslateTable;
    case CoreKind::ProcessEvidence: return m_processMemoryEvidenceTable;
    case CoreKind::SearchResults: return m_searchResultTable;
    default: return nullptr;
    }
}
