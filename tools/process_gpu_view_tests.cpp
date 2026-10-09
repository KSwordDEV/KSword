#include "../Ksword5.1/Ksword5.1/ProcessDock/ProcessGpuTableView.h"

#include "../Ksword5.1/Ksword5.1/UI/TablePresentation.h"
#include "../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/TableFreezeSupport.h"
#include <QTreeWidget>
#include <QTableWidget>
#include <QBrush>
#include <QWheelEvent>
#include <QApplication>
#include <QElapsedTimer>
#include <QOpenGLWidget>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QThread>

#include <iostream>

namespace
{
    int failures = 0; // 独立回归失败计数。
    // 验证一项行为并打印可定位名称，失败最终返回非零。
    void check(bool passed, const char* name)
    {
        std::cout << (passed ? "PASS " : "FAIL ") << name << std::endl;
        if (!passed)
        {
            ++failures;
        }
    }

    // 排空事件并等待真正绘制；不是生产计时器或性能采样。
    void drain()
    {
        QElapsedTimer waitTimer;
        waitTimer.start();
        while (waitTimer.elapsed() < 200)
        {
            QApplication::processEvents();
            QThread::msleep(1);
        }
    }

    // 等待可观察进展，而不是假设繁忙机器必定在固定的 200ms 内推进动画。
    template<typename Predicate>
    bool waitForProgress(Predicate progressed)
    {
        QElapsedTimer deadline;
        deadline.start();
        while (!progressed() && deadline.elapsed() < 1500)
        {
            QApplication::processEvents();
            QThread::msleep(1);
        }
        return progressed();
    }
    // 同尺寸、相同行数据和委托下测量 CPU 绘制提交；不代表 GPU 完成或生产 GUI 性能。
    void benchmark(ks::process_ui::ProcessGpuTableView& table, const char* backend)
    {
        const quint64 initialCount = table.paintCount();
        const qint64 initialTotal = table.totalPaintNs();
        QElapsedTimer wallTimer; // 包含隐藏窗口事件处理的总时间。
        wallTimer.start();
        for (int frame = 0; frame < 80; ++frame)
        {
            table.verticalScrollBar()->setValue(frame % 35);
            table.viewport()->update();
            QApplication::processEvents();
        }
        const quint64 frameCount =
            table.paintCount() - initialCount;
        const qint64 elapsedNs =
            table.totalPaintNs() - initialTotal;
        std::cout << "BENCHMARK " << backend << " frames=" << frameCount
            << " cpu_mean_us=" << (frameCount ? elapsedNs / 1000.0 / frameCount : 0)
            << " wall_ms=" << wallTimer.elapsed() << std::endl;
    }
    // 通过真实委托绘制计数证明 GL 路径没有绕过表格单元格。
    class CountingDelegate final : public QStyledItemDelegate
    {
    public:
        using QStyledItemDelegate::QStyledItemDelegate;
        int hoverEvents = 0; // 验证回退后视口事件过滤器仍可用。
        bool eventFilter(QObject* watched, QEvent* eventObject) override
        {
            if (eventObject->type() == QEvent::Leave)
            {
                ++hoverEvents;
            }
            return QStyledItemDelegate::eventFilter(watched, eventObject);
        }
        mutable int calls = 0; // 本轮真实委托调用次数。
        void paint(QPainter* painter, const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            ++calls;
            QStyledItemDelegate::paint(painter, option, index);
        }
    };

    // 比较实际可见单元格的中心底色，不把字体抗锯齿差异当作丢行。
    void checkCellPixels(QTableView& table, const QImage& image, const char* name)
    {
        const QModelIndex visibleIndex = table.indexAt(QPoint(12, 12));
        const QRect cell = table.visualRect(visibleIndex);
        const QColor expected = visibleIndex.data(Qt::BackgroundRole).value<QColor>();
        const QPoint logicalPixel(cell.right() - 12, cell.center().y());
        const QPoint imagePixel = logicalPixel * image.devicePixelRatio();
        const QColor actual = image.pixelColor(imagePixel);
        check(visibleIndex.isValid() && std::abs(actual.red() - expected.red()) < 5
            && std::abs(actual.green() - expected.green()) < 5
            && std::abs(actual.blue() - expected.blue()) < 5, name);
    }
}

// 使用独立 Qt 表格和合成数据；不枚举/操作用户进程，不启动生产主程序。
int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    application.setStyleSheet(QStringLiteral(
        "QTableView{border:none;color:palette(text);selection-background-color:palette(highlight);"
        "selection-color:palette(highlighted-text);}"));
    ks::ui::InstallGlobalSmoothScrollSupport(&application);
    ks::ui::SetGlobalSmoothScrollingEnabled(true);
    QStandardItemModel model(1000, 3); // 足够发生纵向/横向滚动的稳定模型。
    for (int row = 0; row < model.rowCount(); ++row)
    {
        for (int column = 0; column < model.columnCount(); ++column)
        {
            model.setData(model.index(row, column), QString::number(row));
            model.setData(model.index(row, column),
                QColor(70 + row % 100, 90 + column * 20, 130), Qt::BackgroundRole);
        }
    }

    // 审计公共 QSS 的真实标准委托路径，不能由进程表 opt-out 掩盖其他页面的问题。
    ks::ui::TableActionTableView sharedTable;
    sharedTable.setAttribute(Qt::WA_DontShowOnScreen);
    sharedTable.setModel(&model);
    sharedTable.resize(480, 220);
    sharedTable.setColumnWidth(0, 220);
    ks::ui::ApplyTablePresentation(&sharedTable);
    sharedTable.show();
    drain();
    checkCellPixels(sharedTable, sharedTable.viewport()->grab().toImage(),
        "shared_presentation_background");
    // 真实冻结控制器复用公共样式；确认被钉住的行列仍显示模型语义底色。
    sharedTable.setColumnWidth(0, 150);
    ks::ui::TableFrozenPaneController sharedFreeze;
    sharedFreeze.setTargetTable(&sharedTable);
    check(sharedFreeze.freezeRows({0}) == 1, "shared_freeze_row");
    check(sharedFreeze.freezeColumns({0}) == 1, "shared_freeze_column");
    drain();
    const auto sharedPanes = sharedTable.findChildren<QTableView*>();
    check(!sharedPanes.isEmpty(), "shared_freeze_panes_created");
    for (QTableView* pane : sharedPanes)
    {
        if (pane->isVisible() && pane->viewport()->width() > 24 && pane->viewport()->height() > 20)
        {
            checkCellPixels(*pane, pane->viewport()->grab().toImage(), "frozen_pane_semantic_background");
        }
    }
    sharedFreeze.clearFrozenPanes();

    // 标准 table/tree item 的底色与前景受公共 presentation 保护；同时覆盖深浅主题。
    QTableWidget itemTable(1, 1);
    itemTable.setAttribute(Qt::WA_DontShowOnScreen);
    itemTable.resize(320, 160);
    itemTable.setColumnWidth(0, 200);
    auto* tableItem = new QTableWidgetItem(QStringLiteral("8888"));
    tableItem->setBackground(QColor(70, 90, 130));
    tableItem->setForeground(QColor(245, 215, 65));
    itemTable.setItem(0, 0, tableItem);
    QTreeWidget itemTree;
    itemTree.setAttribute(Qt::WA_DontShowOnScreen);
    itemTree.setColumnCount(1);
    itemTree.resize(320, 160);
    auto* treeItem = new QTreeWidgetItem(&itemTree, {QStringLiteral("8888")});
    treeItem->setBackground(0, QColor(70, 90, 130));
    treeItem->setForeground(0, QColor(245, 215, 65));
    for (int dark = 0; dark < 2; ++dark)
    {
        QPalette themePalette = application.palette();
        themePalette.setColor(QPalette::Base, dark ? QColor(20, 27, 34) : QColor(250, 250, 250));
        themePalette.setColor(QPalette::Text, dark ? Qt::white : Qt::black);
        for (QAbstractItemView* view : {static_cast<QAbstractItemView*>(&itemTable),
            static_cast<QAbstractItemView*>(&itemTree)})
        {
            view->setPalette(themePalette);
            ks::ui::ApplyTablePresentation(view);
            view->show();
            drain();
            const QModelIndex index = view->model()->index(0, 0);
            const QRect cell = view->visualRect(index);
            const QImage frame = view->viewport()->grab().toImage();
            const QColor background = frame.pixelColor(QPoint(cell.right() - 12, cell.center().y())
                * frame.devicePixelRatio());
            check(std::abs(background.red() - 70) < 5 && std::abs(background.green() - 90) < 5
                && std::abs(background.blue() - 130) < 5, "shared_table_tree_theme_background");
            int foregroundPixels = 0; // 检查真实暖色字形，防止状态前景被 palette(text) 覆盖。
            for (int y = cell.top(); y <= cell.bottom(); ++y)
            {
                for (int x = cell.left(); x < cell.left() + 80; ++x)
                {
                    const QColor pixel = frame.pixelColor(QPoint(x, y) * frame.devicePixelRatio());
                    if (pixel.red() > 170 && pixel.green() > 140 && pixel.blue() < 120)
                    {
                        ++foregroundPixels;
                    }
                }
            }
            check(foregroundPixels > 0, "shared_table_tree_theme_foreground");
        }
    }
    itemTable.hide();
    itemTree.hide();
    sharedTable.hide();

    qunsetenv("KSWORD_PROCESS_LIST_GPU");
    qunsetenv("KSWORD_PROCESS_LIST_PROFILE");
    ks::process_ui::ProcessGpuTableView unprofiled;
    unprofiled.setAttribute(Qt::WA_DontShowOnScreen);
    unprofiled.setModel(&model);
    unprofiled.show();
    drain();
    check(unprofiled.paintCount() == 0, "default_no_profiling");
    unprofiled.hide();
    qputenv("KSWORD_PROCESS_LIST_PROFILE", "1");
    ks::process_ui::ProcessGpuTableView raster;
    raster.setAttribute(Qt::WA_DontShowOnScreen);
    raster.setModel(&model);
    CountingDelegate rasterDelegate;
    raster.setItemDelegate(&rasterDelegate);
    raster.setTopActionBarHeight(28);
    raster.resize(480, 300);
    raster.setColumnWidth(0, 220);
    ks::ui::ApplyTablePresentation(&raster);
    raster.show();
    drain();
    check(raster.property("ksword_process_render_backend") == "raster", "default_raster");
    checkCellPixels(raster, raster.viewport()->grab().toImage(), "raster_pixels");
    check(raster.paintCount() > 0, "raster_timing");

    qputenv("KSWORD_PROCESS_LIST_GPU", "1");
    ks::process_ui::ProcessGpuTableView gpu;
    gpu.setAttribute(Qt::WA_DontShowOnScreen);
    gpu.setModel(&model);
    CountingDelegate delegate;
    gpu.setItemDelegate(&delegate);
    gpu.viewport()->installEventFilter(&delegate);
    gpu.setSelectionBehavior(QAbstractItemView::SelectRows);
    gpu.setTopActionBarHeight(28);
    gpu.resize(480, 300);
    gpu.setColumnWidth(0, 220);
    ks::ui::ApplyTablePresentation(&gpu);
    gpu.show();
    drain();

    gpu.verticalScrollBar()->setValue(0);
    QWheelEvent smoothWheel(QPointF(20, 20), QPointF(gpu.viewport()->mapToGlobal(QPoint(20, 20))),
        QPoint(), QPoint(0, -120), Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(gpu.viewport(), &smoothWheel);
    check(gpu.verticalScrollBar()->value() == 0, "gpu_wheel_starts_animation");
    drain();
    check(waitForProgress([&gpu]() { return gpu.verticalScrollBar()->value() > 0; }),
        "gpu_wheel_animates");
    check(!ks::ui::PreservesCustomTablePresentation(&gpu), "gpu_shared_style_keeps_semantic_brushes");
    ks::ui::SetGlobalSmoothScrollingEnabled(false);
    gpu.verticalScrollBar()->setValue(0);
    QWheelEvent nativeWheel(QPointF(20, 20), QPointF(gpu.viewport()->mapToGlobal(QPoint(20, 20))),
        QPoint(), QPoint(0, -120), Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(gpu.viewport(), &nativeWheel);
    check(gpu.verticalScrollBar()->value() > 0, "disabled_setting_uses_native_scroll");
    gpu.verticalScrollBar()->setValue(0);
    ks::ui::SetGlobalSmoothScrollingEnabled(true);
    drain();
    QOpenGLWidget* glViewport = dynamic_cast<QOpenGLWidget*>(gpu.viewport());
    const bool offscreen = QGuiApplication::platformName() == "offscreen";
    if (offscreen)
    {
        check(glViewport == nullptr, "offscreen_no_gl");
        check(gpu.property("ksword_process_gpu_fallback") == "unsupported_platform",
            "offscreen_reason");
    }
    else
    {
        check(glViewport != nullptr && glViewport->isValid(), "hardware_context");
        check(gpu.property("ksword_process_render_backend") == "opengl", "hardware_backend");
        gpu.setFrozenPaneReservation(35, 20);
        drain();
        if (glViewport != nullptr)
        {
            checkCellPixels(gpu, glViewport->grabFramebuffer(), "gpu_frozen_reservation_pixels");
        }
        gpu.setFrozenPaneReservation(0, 0);
        std::cout << "RENDERER " << gpu.property("ksword_process_gpu_renderer")
            .toString().toStdString() << std::endl;
        if (glViewport != nullptr)
        {
            checkCellPixels(gpu, glViewport->grabFramebuffer(), "gpu_pixels");
            gpu.verticalScrollBar()->setValue(450);
            gpu.horizontalScrollBar()->setValue(35);
            drain();
            checkCellPixels(gpu, glViewport->grabFramebuffer(), "gpu_scrolled_pixels");
            gpu.resize(560, 340);
            drain();
            checkCellPixels(gpu, glViewport->grabFramebuffer(), "gpu_resized_pixels");
        }
        check(delegate.calls > 0, "gpu_real_delegate");
        check(gpu.paintCount() > 0, "gpu_timing");

        raster.resize(560, 340);
        drain();
        // 半透明热度与语义前景都通过真实 QSS/模型/委托绘制；比较 GL 与光栅像素。
        ks::ui::SetGlobalSmoothScrollingEnabled(false);
        raster.verticalScrollBar()->setValue(0);
        gpu.verticalScrollBar()->setValue(0);
        const QModelIndex semanticIndex = model.index(0, 0);
        const QVariant originalBrush = semanticIndex.data(Qt::BackgroundRole);
        model.setData(semanticIndex, QColor(58, 156, 255, 80), Qt::BackgroundRole);
        model.setData(semanticIndex, QColor(245, 215, 65), Qt::ForegroundRole);
        drain();
        if (glViewport != nullptr)
        {
            const QImage rasterImage = raster.viewport()->grab().toImage();
            const QImage gpuImage = glViewport->grabFramebuffer();
            const QRect semanticCell = gpu.visualRect(semanticIndex);
            const QPoint sample(semanticCell.right() - 12, semanticCell.center().y());
            const QColor rasterPixel = rasterImage.pixelColor(sample * rasterImage.devicePixelRatio());
            const QColor gpuPixel = gpuImage.pixelColor(sample * gpuImage.devicePixelRatio());
            check(std::abs(rasterPixel.red() - gpuPixel.red()) < 5
                && std::abs(rasterPixel.green() - gpuPixel.green()) < 5
                && std::abs(rasterPixel.blue() - gpuPixel.blue()) < 5,
                "translucent_heat_matches_raster");
            int coloredTextPixels = 0; // 统计暖色前景字形，不能仅验证模型角色存在。
            for (int y = semanticCell.top(); y <= semanticCell.bottom(); ++y)
            {
                for (int x = semanticCell.left(); x < semanticCell.left() + 35; ++x)
                {
                    const QColor pixel = gpuImage.pixelColor(QPoint(x, y) * gpuImage.devicePixelRatio());
                    if (pixel.red() > 170 && pixel.green() > 140 && pixel.blue() < 120)
                    {
                        ++coloredTextPixels;
                    }
                }
            }
            check(coloredTextPixels > 0, "semantic_foreground_visible");
            check(gpuPixel.blue() > gpuPixel.red(), "translucent_heat_visible");
        }
        model.setData(semanticIndex, originalBrush, Qt::BackgroundRole);
        model.setData(semanticIndex, QVariant(), Qt::ForegroundRole);
        ks::ui::SetGlobalSmoothScrollingEnabled(true);
        drain();
        benchmark(raster, "raster");
        benchmark(gpu, "opengl");
        ks::ui::TableFrozenPaneController gpuFreeze;
        gpuFreeze.setTargetTable(&gpu);
        check(gpuFreeze.freezeRows({0}) == 1, "gpu_freeze_before_fallback");
        drain();
        gpu.selectRow(15);
        QItemSelectionModel* originalSelection = gpu.selectionModel();
        const int originalScroll = gpu.verticalScrollBar()->value();
        gpu.scheduleRasterFallback("fixture_context_failure");
        gpu.scheduleRasterFallback("duplicate_failure");
        drain();
        check(dynamic_cast<QOpenGLWidget*>(gpu.viewport()) == nullptr, "fallback_raster");
        check(gpu.model() == &model && gpu.selectionModel() == originalSelection,
            "fallback_keeps_model_selection_object");
        check(gpu.selectionModel()->isRowSelected(15, QModelIndex()), "fallback_keeps_selection");
        check(gpu.verticalScrollBar()->value() == originalScroll, "fallback_keeps_scroll");
        check(gpu.topActionBarHeight() == 28, "fallback_keeps_action_bar");
        const int previousHoverEvents = delegate.hoverEvents;
        QEvent leaveEvent(QEvent::Leave);
        QApplication::sendEvent(gpu.viewport(), &leaveEvent);
        check(delegate.hoverEvents == previousHoverEvents + 1, "fallback_keeps_hover_filter");
        check(gpu.property("ksword_process_gpu_fallback") == "fixture_context_failure",
            "fallback_deduplicated");
        check(gpuFreeze.frozenRowCount() == 1, "fallback_keeps_actual_freeze");
        gpu.resize(620, 380);
        drain();
        for (QTableView* pane : gpu.findChildren<QTableView*>())
        {
            if (pane->isVisible() && pane->viewport()->width() > 24 && pane->viewport()->height() > 20)
            {
                checkCellPixels(*pane, pane->viewport()->grab().toImage(), "fallback_frozen_pane_color");
            }
        }
        gpuFreeze.clearFrozenPanes();
        gpu.clearSelection();
        drain();
        checkCellPixels(gpu, gpu.viewport()->grab().toImage(), "fallback_pixels");
    }
    std::cout << "GPU_TEST_FAILURES=" << failures << std::endl;
    return failures == 0 ? 0 : 1;
}
