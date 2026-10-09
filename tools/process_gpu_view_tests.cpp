#include "../Ksword5.1/Ksword5.1/ProcessDock/ProcessGpuTableView.h"

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
        while (waitTimer.elapsed() < 100)
        {
            QApplication::processEvents();
            QThread::msleep(1);
        }
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
    gpu.show();
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
        benchmark(raster, "raster");
        benchmark(gpu, "opengl");
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
        gpu.clearSelection();
        drain();
        checkCellPixels(gpu, gpu.viewport()->grab().toImage(), "fallback_pixels");
    }
    std::cout << "GPU_TEST_FAILURES=" << failures << std::endl;
    return failures == 0 ? 0 : 1;
}
