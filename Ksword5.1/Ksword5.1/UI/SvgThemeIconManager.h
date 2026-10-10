#pragma once

// ============================================================
// SvgThemeIconManager.h
// 作用：
// - 在主界面加载阶段集中适配 SVG/扁平图标的主题色；
// - 用像素签名缓存一次性着色结果，避免每个按钮重复渲染；
// - 默认主题色只适配共享实心按钮，其它槽位恢复原图或维持首次跳过。
// ============================================================

#include <QColor>
#include <QIcon>
#include <QObject>

#include <functional>

class QAction;
class QApplication;
class QEvent;
class QTabWidget;
class QWidget;

namespace ks::ui
{
    // SvgThemeIconApplyResult：
    // - 保存一次集中着色的可观测结果；
    // - MainWindow 用它记录耗时、遍历量和缓存命中情况。
    struct SvgThemeIconApplyResult
    {
        int visitedWidgetCount = 0; // visitedWidgetCount：本次遍历的 QWidget 数量。
        int recoloredIconCount = 0; // recoloredIconCount：实际替换的图标槽位数量。
        int cacheHitCount = 0;      // cacheHitCount：复用已渲染图标的次数。
        bool skippedDefaultTheme = false; // skippedDefaultTheme：是否整轮跳过；共享按钮适配时为 false。
        qint64 elapsedMilliseconds = 0;   // elapsedMilliseconds：完整批处理耗时。
    };

    // SvgThemeIconManager：
    // - 调用 applyToApplication() 完成启动期或主题切换时的集中处理；
    // - 全局事件过滤器只接管后续懒加载页面，调用点无需再自行着色。
    class SvgThemeIconManager final : public QObject
    {
    public:
        // instance：
        // - 返回进程内唯一管理器；
        // - 第一次应用主题时由管理器自行安装全局事件过滤器。
        static SvgThemeIconManager& instance();

        // applyToApplication：
        // - application：当前 QApplication；
        // - themeColor：当前主题强调色；
        // - isDefaultThemeColor：true 时仅适配已审核共享按钮，其它槽位按历史记录还原或跳过；
        // - progressCallback：回传已处理/总控件数，供启动进度条展示；
        // - 控件遍历按时间预算分片：首片同步执行，其余片由事件循环续跑，
        //   本函数返回时批处理可能尚未结束（分片期间新建的控件由事件过滤器兜底）；
        // - 返回批处理统计结果：visitedWidgetCount 是本轮计划遍历的控件总数，
        //   其余计数与耗时只覆盖同步执行的首片。
        SvgThemeIconApplyResult applyToApplication(
            QApplication* application,
            const QColor& themeColor,
            bool isDefaultThemeColor,
            const std::function<void(int, int)>& progressCallback = {});

    protected:
        // eventFilter：
        // - 集中处理主题应用后才创建的懒加载控件与动作；
        // - 命中缓存时不会重新执行 SVG/像素着色。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        SvgThemeIconManager() = default;
        ~SvgThemeIconManager() override = default;
        SvgThemeIconManager(const SvgThemeIconManager&) = delete;
        SvgThemeIconManager& operator=(const SvgThemeIconManager&) = delete;

        // runIconApplySlice：
        // - runGeneration：发起本轮批处理时记录的代次，不符即说明已被新一轮取代；
        // - cacheHitCount：累加缓存命中次数，可为空；
        // - 只处理时间预算内的控件，未处理完则用 QTimer::singleShot(0) 排下一片；
        // - 返回本片实际替换或还原的图标槽位数量。
        int runIconApplySlice(quint64 runGeneration, int* cacheHitCount);

        // scheduleWidgetRefresh：运行期换图标、显示或重绘后排队补色。
        // 入参为待更新控件；同一控件只排一次，销毁后自动放弃，默认色仍适配共享按钮。
        void scheduleWidgetRefresh(QWidget* widgetPointer);

        // 下列函数分别处理 QWidget、QAction、Tab 和单个 QIcon。
        int applyToWidget(QWidget* widgetPointer, int* cacheHitCount);
        bool applyToAction(QAction* actionPointer, int* cacheHitCount);
        int applyToTabWidget(QTabWidget* tabWidgetPointer, int* cacheHitCount);
        QIcon themedIcon(const QIcon& sourceIcon, bool* cacheHitOut);

        bool m_filterInstalled = false; // m_filterInstalled：全局事件过滤器是否已安装。
        bool m_customTintActive = false; // m_customTintActive：是否着色普通槽位；默认色仅管共享按钮。
        QColor m_themeColor; // m_themeColor：本轮集中着色使用的强调色。
    };
}
