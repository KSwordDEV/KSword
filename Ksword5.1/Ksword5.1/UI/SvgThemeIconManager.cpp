#include "SvgThemeIconManager.h"
#include "ThemeAccentIcon.h"
#include "./FlatButtonTheme.h"

// ============================================================
// SvgThemeIconManager.cpp
// 实现说明：
// - 不修改 qrc 中的 SVG 源码，也不要求各个按钮改用新 API；
// - 只在主题加载/切换时遍历一次现有控件；
// - 遍历按时间预算切片，片间用 QTimer::singleShot(0) 让出事件循环，
//   不在调用栈上调用 processEvents，避免主题刷新中途被重入；
// - 后续懒加载控件通过同一事件过滤器进入共享缓存。
// ============================================================

#include <QAbstractButton>
#include <QAction>
#include <QActionEvent>
#include <QApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QEvent>
#include <QHash>
#include <QImage>
#include <QList>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QSet>
#include <QSize>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    constexpr auto OriginalButtonIconProperty =
        "ksword_svg_theme_original_button_icon"; // 按钮原始图标属性名。
    constexpr auto LastButtonIconKeyProperty =
        "ksword_svg_theme_last_button_icon_key"; // 管理器最近写入按钮的 QIcon cacheKey。
    constexpr auto OriginalActionIconProperty =
        "ksword_svg_theme_original_action_icon"; // QAction 原始图标属性名。
    constexpr auto LastActionIconKeyProperty =
        "ksword_svg_theme_last_action_icon_key"; // 管理器最近写入 QAction 的 cacheKey。
    constexpr auto OriginalWindowIconProperty =
        "ksword_svg_theme_original_window_icon"; // 普通控件 windowIcon 原始值。
    constexpr auto LastWindowIconKeyProperty =
        "ksword_svg_theme_last_window_icon_key"; // 管理器最近写入 windowIcon 的 cacheKey。
    constexpr auto OriginalTabIconProperty =
        "ksword_svg_theme_original_tab_icon"; // Tab 页面保存所属标签原始图标。
    constexpr auto LastTabIconKeyProperty =
        "ksword_svg_theme_last_tab_icon_key"; // 管理器最近写入 Tab 图标的 cacheKey。
    constexpr auto PendingIconRefreshProperty =
        "ksword_svg_theme_refresh_pending"; // 控件是否已有排队的增量补色。

    // hasSharedFlatButtonTheme：只询问共享按钮组件当前是否拥有真实颜色规则。
    // 不凭 managed 历史属性判断，未审核本地样式及 checkbox 等类型均返回 false。
    bool hasSharedFlatButtonTheme(const QAbstractButton* button)
    {
        QColor background; // 只用于确认真实底色可取得，状态颜色由引擎在绘制时重新读取。
        return ks::ui::TryGetFlatButtonBackground(
            button, QIcon::Normal, QIcon::Off, &background);
    }

    // cachedTintedIcons：
    // - key 是原图像素签名 + 目标颜色；
    // - value 是已构造多尺寸 pixmap 的 QIcon，所有窗口共享。
    QHash<QByteArray, QIcon>& cachedTintedIcons()
    {
        static QHash<QByteArray, QIcon> iconCache;
        return iconCache;
    }

    // cachedIconsBySourceKey：
    // - key 是源图 QIcon::cacheKey()，Qt 为每份图标数据分配单调递增序号，销毁后也不复用；
    // - value 是该源图在当前强调色下的着色结果，空 QIcon 表示“已判定为非候选、不着色”；
    // - 命中后可整段跳过 24x24 重渲染、逐像素候选判定和 SHA-256 像素签名。
    QHash<qint64, QIcon>& cachedIconsBySourceKey()
    {
        static QHash<qint64, QIcon> sourceKeyedIconCache;
        return sourceKeyedIconCache;
    }

    // MaximumSourceIconCacheEntries：
    // - 源图身份缓存只是加速表，条目超限时整体丢弃重建；
    // - 防止长时间运行中不断新建的 QIcon 让缓存无界增长。
    constexpr int MaximumSourceIconCacheEntries = 4096;

    // clearThemedIconCaches：
    // - 强调色变化时必须同时清空像素签名缓存与源图身份缓存；
    // - 只清其中一个会让旧强调色的结果被新一轮复用。
    void clearThemedIconCaches()
    {
        cachedTintedIcons().clear();
        cachedIconsBySourceKey().clear();
    }

    // IconApplySliceBudgetMilliseconds：
    // - 单个切片允许占用 UI 线程的毫秒上限；
    // - 超出预算立即让出事件循环，剩余控件下一片继续。
    constexpr qint64 IconApplySliceBudgetMilliseconds = 8;

    // IconApplyBudgetCheckStride：
    // - 每处理这么多控件才读一次时钟；
    // - 无图标控件的单次开销只有几微秒，逐个取时反而成为主要成本；
    // - 取值偏小，保证少量“每个都要重新栅格化 SVG”的控件不会撑爆单片预算。
    constexpr int IconApplyBudgetCheckStride = 8;

    // IconApplySliceState：
    // - SvgThemeIconManager 是进程内单例，分片状态随之只需一份，放在实现文件里即可；
    // - generation 用于淘汰被新一轮主题切换取代的旧切片。
    struct IconApplySliceState
    {
        QList<QPointer<QWidget>> pendingWidgets; // pendingWidgets：本轮待处理控件快照。
        int nextWidgetIndex = 0;                 // nextWidgetIndex：下一个待处理控件下标。
        QSet<QAction*> processedActions;         // processedActions：只做身份去重，从不解引用。
        std::function<void(int, int)> progressCallback; // progressCallback：进度回传，可为空。
        quint64 generation = 0;                  // generation：本轮批处理的代次。
        bool nextSliceScheduled = false;         // nextSliceScheduled：下一片是否已排队。
    };

    // iconApplySliceState：
    // - 返回进程内唯一的分片状态；
    // - 只在 UI 线程访问，无需额外加锁。
    IconApplySliceState& iconApplySliceState()
    {
        static IconApplySliceState sliceState;
        return sliceState;
    }

    // iconApplyGenerationCounter：
    // - 每次 applyToApplication 自增一次，作为本轮分片的身份；
    // - 已排队的旧切片发现代次不符就整体放弃，不会把旧强调色写回控件。
    quint64& iconApplyGenerationCounter()
    {
        static quint64 generationCounter = 0;
        return generationCounter;
    }

    // resetIconApplySliceState：
    // - 释放控件快照、动作去重集合与进度回调；
    // - 避免管理器长期持有已关闭窗口的 QPointer 和调用点的闭包。
    void resetIconApplySliceState(IconApplySliceState& sliceState)
    {
        sliceState.pendingWidgets.clear();
        sliceState.nextWidgetIndex = 0;
        sliceState.processedActions.clear();
        sliceState.progressCallback = {};
        sliceState.nextSliceScheduled = false;
    }

    // normalizedIconImage：
    // - 把任意 QIcon 统一渲染为 24x24 ARGB 图像；
    // - 同时用于候选识别和稳定缓存签名。
    QImage normalizedIconImage(const QIcon& sourceIcon)
    {
        QPixmap sourcePixmap =
            sourceIcon.pixmap(QSize(24, 24), QIcon::Normal, QIcon::Off);
        if (sourcePixmap.isNull())
        {
            return QImage();
        }
        return sourcePixmap.toImage().convertToFormat(QImage::Format_ARGB32);
    }

    // isThemeTintCandidate：
    // - SVG 图标通常可缩放且 availableSizes 为空；
    // - 旧 createBlueIcon 已转为位图，因此再用“低颜色数量”识别扁平图标；
    // - 多色进程/文件图标会超过阈值，不会被主题色覆盖。
    bool isThemeTintCandidate(const QIcon& sourceIcon, const QImage& normalizedImage)
    {
        if (sourceIcon.isNull() || normalizedImage.isNull())
        {
            return false;
        }
        if (sourceIcon.availableSizes(QIcon::Normal, QIcon::Off).isEmpty())
        {
            return true;
        }

        QSet<QRgb> opaqueColors; // opaqueColors：忽略透明度后见到的 RGB 集合。
        int visiblePixelCount = 0; // visiblePixelCount：用于排除全透明占位图标。
        constexpr int MaximumFlatColorCount = 48; // 扁平图标允许的最大颜色数量。
        for (int y = 0; y < normalizedImage.height(); ++y)
        {
            const QRgb* scanLine =
                reinterpret_cast<const QRgb*>(normalizedImage.constScanLine(y));
            for (int x = 0; x < normalizedImage.width(); ++x)
            {
                const QRgb pixelValue = scanLine[x];
                if (qAlpha(pixelValue) == 0)
                {
                    continue;
                }
                ++visiblePixelCount;
                opaqueColors.insert(qRgb(
                    qRed(pixelValue),
                    qGreen(pixelValue),
                    qBlue(pixelValue)));
                if (opaqueColors.size() > MaximumFlatColorCount)
                {
                    return false;
                }
            }
        }
        return visiblePixelCount > 0;
    }

    // iconCacheKey：
    // - 使用规范图像完整字节和目标 QColor 生成 SHA-256；
    // - 即使多个 QIcon 对象由同一 SVG 分别构造，也能命中同一缓存。
    QByteArray iconCacheKey(
        const QImage& normalizedImage,
        const QColor& themeColor)
    {
        QByteArray signatureBytes;
        signatureBytes.reserve(
            static_cast<int>(normalizedImage.sizeInBytes()) + 16);
        signatureBytes.append(
            reinterpret_cast<const char*>(normalizedImage.constBits()),
            static_cast<qsizetype>(normalizedImage.sizeInBytes()));
        signatureBytes.append(themeColor.name(QColor::HexArgb).toUtf8());
        return QCryptographicHash::hash(
            signatureBytes,
            QCryptographicHash::Sha256);
    }

    // originalIconFromProperty：
    // - 首次处理时把当前图标保存到 QObject 动态属性；
    // - 后续改色始终从原始图标生成，避免重复着色和清晰度损失。
    QIcon originalIconFromProperty(
        QObject* ownerObject,
        const char* propertyName,
        const char* lastAppliedKeyPropertyName,
        const QIcon& currentIcon)
    {
        if (ownerObject == nullptr)
        {
            return currentIcon;
        }
        const QVariant lastAppliedKeyValue =
            ownerObject->property(lastAppliedKeyPropertyName);
        bool lastAppliedKeyValid = false;
        const qulonglong lastAppliedKey =
            lastAppliedKeyValue.toULongLong(&lastAppliedKeyValid);
        // 外部主题刷新若在两轮集中处理之间替换了图标，当前值就是新的正确基线。
        // 只有当前图标仍是管理器上轮写入值时，才继续复用原始属性。
        if (lastAppliedKeyValid &&
            static_cast<qulonglong>(currentIcon.cacheKey()) != lastAppliedKey)
        {
            ownerObject->setProperty(
                propertyName,
                QVariant::fromValue(currentIcon));
            return currentIcon;
        }
        const QVariant storedValue = ownerObject->property(propertyName);
        if (storedValue.isValid() && storedValue.canConvert<QIcon>())
        {
            return storedValue.value<QIcon>();
        }
        ownerObject->setProperty(propertyName, QVariant::fromValue(currentIcon));
        return currentIcon;
    }

    // rememberAppliedIconKey：
    // - 记录管理器最后一次写入的图标身份；
    // - 下一轮可据此区分“仍是管理器着色结果”和“控件自行刷新了新图标”。
    void rememberAppliedIconKey(
        QObject* ownerObject,
        const char* propertyName,
        const QIcon& appliedIcon)
    {
        if (ownerObject == nullptr)
        {
            return;
        }
        ownerObject->setProperty(
            propertyName,
            QVariant::fromValue<qulonglong>(appliedIcon.cacheKey()));
    }

    // directWidgetActions：
    // - 合并控件关联的 actions() 与其直接拥有的 QAction；
    // - 禁止对每个控件递归 findChildren，避免启动期遍历退化为 O(N²)。
    QList<QAction*> directWidgetActions(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return {};
        }
        QList<QAction*> actionList = widgetPointer->actions();
        const QList<QAction*> ownedActionList =
            widgetPointer->findChildren<QAction*>(
                QString(),
                Qt::FindDirectChildrenOnly);
        for (QAction* actionPointer : ownedActionList)
        {
            if (actionPointer != nullptr &&
                !actionList.contains(actionPointer))
            {
                actionList.push_back(actionPointer);
            }
        }
        return actionList;
    }
}

ks::ui::SvgThemeIconManager& ks::ui::SvgThemeIconManager::instance()
{
    static SvgThemeIconManager manager;
    return manager;
}

ks::ui::SvgThemeIconApplyResult
ks::ui::SvgThemeIconManager::applyToApplication(
    QApplication* application,
    const QColor& themeColor,
    const bool isDefaultThemeColor,
    const std::function<void(int, int)>& progressCallback)
{
    SvgThemeIconApplyResult result;
    QElapsedTimer elapsedTimer;
    elapsedTimer.start();

    // 新一轮请求先丢弃上一轮残留状态并自增代次：已排队但尚未执行的旧切片
    // 会在下次执行时发现代次不符而整体放弃，不会把旧强调色写回控件。
    IconApplySliceState& sliceState = iconApplySliceState();
    resetIconApplySliceState(sliceState);
    ++iconApplyGenerationCounter();
    const quint64 currentGeneration = iconApplyGenerationCounter();
    sliceState.generation = currentGeneration;

    if (application == nullptr || !themeColor.isValid())
    {
        result.elapsedMilliseconds = elapsedTimer.elapsed();
        return result;
    }

    if (!m_filterInstalled)
    {
        application->installEventFilter(this);
        m_filterInstalled = true;
    }

    // 默认色也扫描已审核的共享实心按钮：Accent/checked 底需要独立前景对比度。
    // 其它槽位只在已有管理器记录时还原原图，新菜单/Tab/窗口图标保持首次跳过契约。

    // 缓存只服务当前强调色；切换颜色时释放旧色的多尺寸 pixmap，
    // 避免用户反复试色让进程生命周期内的图标缓存无界增长。
    if (m_themeColor.isValid() && m_themeColor != themeColor)
    {
        clearThemedIconCaches();
    }
    m_themeColor = themeColor;
    m_customTintActive = !isDefaultThemeColor;
    // allWidgets() 返回裸指针快照，而分片处理会在片间让出事件循环；先全部包进
    // QPointer，防止让出期间的延迟销毁让后续切片解引用悬空 QWidget。
    const QWidgetList currentWidgetList = application->allWidgets();
    sliceState.pendingWidgets.reserve(currentWidgetList.size());
    for (QWidget* widgetPointer : currentWidgetList)
    {
        sliceState.pendingWidgets.push_back(QPointer<QWidget>(widgetPointer));
    }
    sliceState.progressCallback = progressCallback;
    result.visitedWidgetCount = static_cast<int>(sliceState.pendingWidgets.size());

    // 首片同步执行，调用点返回前当前活动窗口的图标基本已换色；剩余控件交给
    // 事件循环逐片补齐。相比原先“每 64 个控件调一次 processEvents”，这里不再
    // 在 applyAppearanceSettings 的函数栈上派发事件，因此不会把排队的延迟初始化
    // 或另一次外观刷新重入到主题刷新中途。
    // 分片期间新建的控件由 Polish 事件过滤器兜底，不会漏掉着色。
    result.recoloredIconCount =
        runIconApplySlice(currentGeneration, &result.cacheHitCount);
    result.elapsedMilliseconds = elapsedTimer.elapsed();
    return result;
}

int ks::ui::SvgThemeIconManager::runIconApplySlice(
    const quint64 runGeneration,
    int* cacheHitCount)
{
    IconApplySliceState& sliceState = iconApplySliceState();
    if (sliceState.generation != runGeneration)
    {
        return 0;
    }
    sliceState.nextSliceScheduled = false;

    QElapsedTimer sliceTimer;
    sliceTimer.start();
    int recoloredCount = 0; // recoloredCount：本片替换或还原的图标槽位数量。
    const int totalWidgetCount =
        static_cast<int>(sliceState.pendingWidgets.size());
    while (sliceState.nextWidgetIndex < totalWidgetCount)
    {
        QWidget* const widgetPointer =
            sliceState.pendingWidgets.at(sliceState.nextWidgetIndex).data();
        ++sliceState.nextWidgetIndex;
        if (widgetPointer != nullptr)
        {
            recoloredCount += applyToWidget(widgetPointer, cacheHitCount);

            const QList<QAction*> actionList =
                directWidgetActions(widgetPointer);
            for (QAction* actionPointer : actionList)
            {
                if (actionPointer == nullptr ||
                    sliceState.processedActions.contains(actionPointer))
                {
                    continue;
                }
                sliceState.processedActions.insert(actionPointer);
                if (applyToAction(actionPointer, cacheHitCount))
                {
                    ++recoloredCount;
                }
            }
        }

        if ((sliceState.nextWidgetIndex % IconApplyBudgetCheckStride) == 0 &&
            sliceTimer.elapsed() >= IconApplySliceBudgetMilliseconds)
        {
            break;
        }
    }

    const int processedWidgetCount = sliceState.nextWidgetIndex;
    const bool sliceRunFinished = processedWidgetCount >= totalWidgetCount;
    // 先排下一片再回调进度：即使回调内部又触发了一次主题应用，旧代次的切片
    // 也会在执行时自行退出，不会和新一轮互相覆盖。
    if (!sliceRunFinished && !sliceState.nextSliceScheduled)
    {
        sliceState.nextSliceScheduled = true;
        QTimer::singleShot(
            0,
            this,
            [this, runGeneration]()
            {
                int ignoredCacheHitCount = 0; // ignoredCacheHitCount：续跑分片不再回传统计。
                (void)runIconApplySlice(runGeneration, &ignoredCacheHitCount);
            });
    }

    // 回调可能自带事件泵，先复制出来再调用，随后不再触碰分片状态。
    const std::function<void(int, int)> progressCallbackCopy =
        sliceState.progressCallback;
    if (sliceRunFinished)
    {
        resetIconApplySliceState(sliceState);
    }
    if (progressCallbackCopy && totalWidgetCount > 0)
    {
        progressCallbackCopy(processedWidgetCount, totalWidgetCount);
    }
    return recoloredCount;
}

bool ks::ui::SvgThemeIconManager::eventFilter(
    QObject* watchedObject,
    QEvent* eventObject)
{
    if (!m_themeColor.isValid() ||
        watchedObject == nullptr ||
        eventObject == nullptr)
    {
        return QObject::eventFilter(watchedObject, eventObject);
    }

    // Polish 之后页面仍可能设置图标；Show 与动作变更补上这些晚到的资源。
    // 排队执行避免在构造、菜单派发或绘制栈中重入控件自身的更新流程。
    const QEvent::Type eventType = eventObject->type(); // 本次事件的类别。
    QWidget* widgetPointer = qobject_cast<QWidget*>(watchedObject); // 事件所属控件。
    if (widgetPointer != nullptr &&
        (eventType == QEvent::Polish || eventType == QEvent::Show ||
         eventType == QEvent::ActionAdded || eventType == QEvent::ActionChanged ||
         eventType == QEvent::WindowIconChange ||
         (eventType == QEvent::StyleChange && qobject_cast<QAbstractButton*>(widgetPointer))))
    {
        scheduleWidgetRefresh(widgetPointer);
    }
    else if (eventType == QEvent::Paint)
    {
        // QAbstractButton::setIcon 没有 IconChanged 事件，以绘制前的身份变化兜底。
        // 已染色的图标不排队，因此常驻刷新不会重复栅格化或形成重绘循环。
        if (auto* buttonPointer = qobject_cast<QAbstractButton*>(watchedObject))
        {
            const QIcon currentIcon = buttonPointer->icon(); // 按钮当前图标。
            if (!buttonPointer->property("ksword_theme_icon_managed").toBool() &&
                !currentIcon.isNull() &&
                buttonPointer->property(LastButtonIconKeyProperty).toULongLong() !=
                    static_cast<qulonglong>(currentIcon.cacheKey()) &&
                (m_customTintActive || hasSharedFlatButtonTheme(buttonPointer)))
            {
                scheduleWidgetRefresh(buttonPointer);
            }
        }
        else if (m_customTintActive)
        {
            // 标签图标由 QTabBar 绘制，真正保存原图的对象仍是 QTabWidget 页面。
            auto* tabBarPointer = qobject_cast<QTabBar*>(watchedObject);
            auto* tabWidgetPointer = tabBarPointer != nullptr
                ? qobject_cast<QTabWidget*>(tabBarPointer->parentWidget()) : nullptr;
            if (tabWidgetPointer != nullptr)
            {
                for (int tabIndex = 0; tabIndex < tabWidgetPointer->count(); ++tabIndex)
                {
                    QWidget* pagePointer = tabWidgetPointer->widget(tabIndex); // 标签所属页面。
                    const QIcon currentIcon = tabWidgetPointer->tabIcon(tabIndex); // 当前标签图标。
                    if (pagePointer != nullptr && !currentIcon.isNull() &&
                        pagePointer->property(LastTabIconKeyProperty).toULongLong() !=
                            static_cast<qulonglong>(currentIcon.cacheKey()))
                    {
                        scheduleWidgetRefresh(tabWidgetPointer);
                        break;
                    }
                }
            }
        }
    }
    return QObject::eventFilter(watchedObject, eventObject);
}

void ks::ui::SvgThemeIconManager::scheduleWidgetRefresh(QWidget* widgetPointer)
{
    if (widgetPointer == nullptr || widgetPointer->property(PendingIconRefreshProperty).toBool())
    {
        return;
    }
    widgetPointer->setProperty(PendingIconRefreshProperty, true);
    const QPointer<QWidget> safeWidget(widgetPointer); // 防止排队期间控件销毁。
    QTimer::singleShot(0, this, [this, safeWidget]()
    {
        if (safeWidget == nullptr)
        {
            return;
        }
        safeWidget->setProperty(PendingIconRefreshProperty, false);
        if (!m_themeColor.isValid())
        {
            return;
        }
        int ignoredCacheHits = 0; // 增量补色不计入启动批处理统计。
        (void)applyToWidget(safeWidget, &ignoredCacheHits);
        const QList<QAction*> actionList = directWidgetActions(safeWidget); // 当前直接关联的动作。
        for (QAction* actionPointer : actionList)
        {
            (void)applyToAction(actionPointer, &ignoredCacheHits);
        }
    });
}

int ks::ui::SvgThemeIconManager::applyToWidget(
    QWidget* widgetPointer,
    int* cacheHitCount)
{
    if (widgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount：当前控件替换或还原的图标槽位数量。

    if (auto* buttonPointer = qobject_cast<QAbstractButton*>(widgetPointer))
    {
        const QIcon currentIcon = buttonPointer->icon();
        const bool sharedButtonTheme = hasSharedFlatButtonTheme(buttonPointer); // 当前实际共享样式所有权。
        const bool previouslyManaged = buttonPointer->property(LastButtonIconKeyProperty).isValid();
        // ADS 提供器已生成各状态/DPI 的主题图标，不再把它压成单一 Normal 颜色。
        if (!buttonPointer->property("ksword_theme_icon_managed").toBool() && !currentIcon.isNull()
            && (m_customTintActive || sharedButtonTheme || previouslyManaged))
        {
            const QIcon originalIcon = originalIconFromProperty(
                buttonPointer,
                OriginalButtonIconProperty,
                LastButtonIconKeyProperty,
                currentIcon);
            if (!m_customTintActive && !sharedButtonTheme)
            {
                // 默认主题的未知样式按钮只还原历史记录，不给未管理槽位建立包装。
                if (originalIcon.cacheKey() != currentIcon.cacheKey())
                {
                    buttonPointer->setIcon(originalIcon);
                    ++changedCount;
                }
                rememberAppliedIconKey(
                    buttonPointer,
                    LastButtonIconKeyProperty,
                    originalIcon);
            }
            else
            {
                bool cacheHit = false;
                QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
                // 共享缓存只负责候选判定与通用图标；实心按钮必须保留自己的绘制上下文。
                // 两个按钮即使源图相同，tone/父 palette/checked 都可能不同，不能共用此引擎。
                if (!replacementIcon.isNull() && sharedButtonTheme)
                {
                    replacementIcon = MakeThemeButtonAccentIcon(
                        originalIcon, m_themeColor, buttonPointer);
                }
                if (!replacementIcon.isNull() && replacementIcon.cacheKey() != currentIcon.cacheKey())
                {
                    buttonPointer->setIcon(replacementIcon);
                    rememberAppliedIconKey(
                        buttonPointer,
                        LastButtonIconKeyProperty,
                        replacementIcon);
                    ++changedCount;
                    if (cacheHit && cacheHitCount != nullptr)
                    {
                        ++(*cacheHitCount);
                    }
                }
                else if (replacementIcon.isNull())
                {
                    // 非候选多色图标也登记身份，避免每次绘制重复排队扫描。
                    rememberAppliedIconKey(buttonPointer, LastButtonIconKeyProperty, currentIcon);
                }
            }
        }
    }

    if (auto* tabWidgetPointer = qobject_cast<QTabWidget*>(widgetPointer))
    {
        changedCount += applyToTabWidget(tabWidgetPointer, cacheHitCount);
    }

    // Dock/面板图标也可能来自 SVG；顶层主窗口图标通常为多色资源，会被候选检测排除。
    const QIcon currentWindowIcon = widgetPointer->windowIcon();
    if (widgetPointer->isWindow() && !currentWindowIcon.isNull()
        && (m_customTintActive || widgetPointer->property(LastWindowIconKeyProperty).isValid()))
    {
        const QIcon originalWindowIcon = originalIconFromProperty(
            widgetPointer,
            OriginalWindowIconProperty,
            LastWindowIconKeyProperty,
            currentWindowIcon);
        if (!m_customTintActive)
        {
            if (originalWindowIcon.cacheKey() != currentWindowIcon.cacheKey())
            {
                widgetPointer->setWindowIcon(originalWindowIcon);
                ++changedCount;
            }
            rememberAppliedIconKey(
                widgetPointer,
                LastWindowIconKeyProperty,
                originalWindowIcon);
        }
        else
        {
            bool cacheHit = false;
            const QIcon replacementIcon =
                themedIcon(originalWindowIcon, &cacheHit);
            if (!replacementIcon.isNull() && replacementIcon.cacheKey() != currentWindowIcon.cacheKey())
            {
                widgetPointer->setWindowIcon(replacementIcon);
                rememberAppliedIconKey(
                    widgetPointer,
                    LastWindowIconKeyProperty,
                    replacementIcon);
                ++changedCount;
                if (cacheHit && cacheHitCount != nullptr)
                {
                    ++(*cacheHitCount);
                }
            }
        }
    }
    return changedCount;
}

bool ks::ui::SvgThemeIconManager::applyToAction(
    QAction* actionPointer,
    int* cacheHitCount)
{
    if (actionPointer == nullptr || actionPointer->icon().isNull())
    {
        return false;
    }
    // 默认主题只还原此前被本管理器处理的动作，不扫描新菜单的候选色或建立图标引擎。
    if (!m_customTintActive && !actionPointer->property(LastActionIconKeyProperty).isValid())
    {
        return false;
    }
    const QIcon originalIcon = originalIconFromProperty(
        actionPointer,
        OriginalActionIconProperty,
        LastActionIconKeyProperty,
        actionPointer->icon());
    if (!m_customTintActive)
    {
        const bool changed = originalIcon.cacheKey() != actionPointer->icon().cacheKey(); // 仅真实还原发出更新。
        if (changed)
        {
            actionPointer->setIcon(originalIcon);
        }
        rememberAppliedIconKey(
            actionPointer,
            LastActionIconKeyProperty,
            originalIcon);
        return changed;
    }

    bool cacheHit = false;
    const QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
    if (replacementIcon.isNull() || replacementIcon.cacheKey() == actionPointer->icon().cacheKey())
    {
        return false;
    }
    actionPointer->setIcon(replacementIcon);
    rememberAppliedIconKey(
        actionPointer,
        LastActionIconKeyProperty,
        replacementIcon);
    if (cacheHit && cacheHitCount != nullptr)
    {
        ++(*cacheHitCount);
    }
    return true;
}

int ks::ui::SvgThemeIconManager::applyToTabWidget(
    QTabWidget* tabWidgetPointer,
    int* cacheHitCount)
{
    if (tabWidgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount：当前 QTabWidget 实际处理的标签数量。
    for (int tabIndex = 0; tabIndex < tabWidgetPointer->count(); ++tabIndex)
    {
        QWidget* pagePointer = tabWidgetPointer->widget(tabIndex);
        const QIcon currentIcon = tabWidgetPointer->tabIcon(tabIndex);
        if (pagePointer == nullptr || currentIcon.isNull())
        {
            continue;
        }
        // 默认首次处理不保存或改写普通 Tab；仅恢复已有原图记录。
        if (!m_customTintActive && !pagePointer->property(LastTabIconKeyProperty).isValid())
        {
            continue;
        }
        const QIcon originalIcon = originalIconFromProperty(
            pagePointer,
            OriginalTabIconProperty,
            LastTabIconKeyProperty,
            currentIcon);
        if (!m_customTintActive)
        {
            if (originalIcon.cacheKey() != currentIcon.cacheKey())
            {
                tabWidgetPointer->setTabIcon(tabIndex, originalIcon);
                ++changedCount;
            }
            rememberAppliedIconKey(
                pagePointer,
                LastTabIconKeyProperty,
                originalIcon);
            continue;
        }

        bool cacheHit = false;
        const QIcon replacementIcon = themedIcon(originalIcon, &cacheHit);
        if (replacementIcon.isNull() || replacementIcon.cacheKey() == currentIcon.cacheKey())
        {
            // 非候选标签同样标记已检查，避免每次 QTabBar 绘制重新排队。
            rememberAppliedIconKey(pagePointer, LastTabIconKeyProperty, currentIcon);
            continue;
        }
        tabWidgetPointer->setTabIcon(tabIndex, replacementIcon);
        rememberAppliedIconKey(
            pagePointer,
            LastTabIconKeyProperty,
            replacementIcon);
        ++changedCount;
        if (cacheHit && cacheHitCount != nullptr)
        {
            ++(*cacheHitCount);
        }
    }
    return changedCount;
}

QIcon ks::ui::SvgThemeIconManager::themedIcon(
    const QIcon& sourceIcon,
    bool* cacheHitOut)
{
    if (cacheHitOut != nullptr)
    {
        *cacheHitOut = false;
    }
    if (sourceIcon.isNull())
    {
        return QIcon();
    }

    // 先按源图身份查一次廉价缓存：同一个 QIcon（含隐式共享副本）在多个控件上
    // 重复出现时，直接跳过 24x24 重渲染、逐像素候选判定与 SHA-256 像素签名。
    QHash<qint64, QIcon>& sourceKeyedIconCache = cachedIconsBySourceKey();
    const qint64 sourceIconKey = sourceIcon.cacheKey();
    const auto sourceCachedIterator = sourceKeyedIconCache.constFind(sourceIconKey);
    if (sourceCachedIterator != sourceKeyedIconCache.constEnd())
    {
        const QIcon sourceCachedIcon = sourceCachedIterator.value();
        if (cacheHitOut != nullptr && !sourceCachedIcon.isNull())
        {
            *cacheHitOut = true;
        }
        return sourceCachedIcon;
    }

    // rememberSourceKeyedResult：
    // - 把本次结论登记进源图身份缓存，空 QIcon 表示“非候选、不着色”；
    // - 原样返回入参，便于各出口一行收尾。
    const auto rememberSourceKeyedResult =
        [&sourceKeyedIconCache, sourceIconKey](const QIcon& resolvedIcon) -> QIcon
        {
            if (sourceKeyedIconCache.size() >= MaximumSourceIconCacheEntries)
            {
                sourceKeyedIconCache.clear();
            }
            sourceKeyedIconCache.insert(sourceIconKey, resolvedIcon);
            return resolvedIcon;
        };

    const QImage normalizedImage = normalizedIconImage(sourceIcon);
    if (!isThemeTintCandidate(sourceIcon, normalizedImage))
    {
        return rememberSourceKeyedResult(QIcon());
    }

    const QByteArray cacheKey = iconCacheKey(normalizedImage, m_themeColor);
    const auto cachedIterator = cachedTintedIcons().constFind(cacheKey);
    if (cachedIterator != cachedTintedIcons().constEnd())
    {
        if (cacheHitOut != nullptr)
        {
            *cacheHitOut = true;
        }
        return rememberSourceKeyedResult(cachedIterator.value());
    }

    // 动态引擎保留源的mode/state/DPR，并在实际请求时按当前底色校准。
    // 背景变化而主体色不变时也不会复用不可读的单态RGB快照。
    const QIcon replacementIcon = MakeThemeAccentIcon(sourceIcon, m_themeColor);
    if (!replacementIcon.isNull())
    {
        cachedTintedIcons().insert(cacheKey, replacementIcon);
    }
    return rememberSourceKeyedResult(replacementIcon);
}
