#include "./ProcessGpuTableView.h"

#include <QAbstractItemDelegate>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QOpenGLContext>
#include <QOpenGLFunctions>
#include <QOpenGLWidget>
#include <QPainter>
#include <QSurfaceFormat>
#include <QTimer>

namespace
{
    // GL 控件负责上下文与 FBO 生命周期；表格只负责既有委托/样式绘制。
    class ProcessGlViewport final : public QOpenGLWidget
    {
    public:
        // 输入所属表格；无独立所有权，setViewport 接管控件。
        explicit ProcessGlViewport(ks::process_ui::ProcessGpuTableView* table)
            : QOpenGLWidget(table), m_table(table)
        {
            QSurfaceFormat surfaceFormat = format(); // 保持宿主默认 GL profile。
            surfaceFormat.setSamples(0);
            surfaceFormat.setDepthBufferSize(0);
            surfaceFormat.setStencilBufferSize(8);
            setFormat(surfaceFormat);
            setUpdateBehavior(QOpenGLWidget::NoPartialUpdate);
        }

    protected:
        // 读取真实实现，软件 OpenGL 不作为硬件加速成功。
        void initializeGL() override
        {
            QOpenGLFunctions* functions = context()->functions(); // 当前上下文函数表。
            const char* rendererBytes =
                reinterpret_cast<const char*>(functions->glGetString(GL_RENDERER));
            const QString renderer = QString::fromLatin1(rendererBytes ? rendererBytes : "");
            m_table->setProperty("ksword_process_gpu_renderer", renderer);
            const QString normalized = renderer.toLower().replace(QChar(' '), QChar('_')); // 常见软件实现名称。
            if (renderer.isEmpty() || normalized.contains("llvmpipe")
                || normalized.contains("softpipe") || normalized.contains("software")
                || normalized.contains("gdi_generic") || normalized.contains("swiftshader"))
            {
                m_table->scheduleRasterFallback("software_or_unknown_renderer");
                return;
            }
            m_table->setProperty("ksword_process_render_backend", "opengl");
        }

        // 此处上下文已 current，且 Qt 的离屏 framebuffer 已绑定。
        void paintGL() override
        {
            m_table->paintGpuFrame();
        }

        // 基类实际尝试创建上下文之后才检查，避免 show 前误判不可用。
        void paintEvent(QPaintEvent* eventObject) override
        {
            QOpenGLWidget::paintEvent(eventObject);
            if (!isValid())
            {
                m_table->scheduleRasterFallback("invalid_context_or_framebuffer");
            }
        }

    private:
        ks::process_ui::ProcessGpuTableView* m_table; // 由父表格持有，绘制期间有效。
    };
}

namespace ks::process_ui
{
    ProcessGpuTableView::ProcessGpuTableView(QWidget* parent)
        : ProcessGpuTableView(parent, qEnvironmentVariable("KSWORD_PROCESS_LIST_GPU") == QStringLiteral("1"))
    {
    }

    ProcessGpuTableView::ProcessGpuTableView(QWidget* parent, bool gpuEnabled)
        : TableActionTableView(parent)
    {
        setProperty("ksword_process_render_backend", "raster");
        setGpuAccelerationEnabled(gpuEnabled);
    }

    void ProcessGpuTableView::replaceRenderViewport(QWidget* replacement)
    {
        const int verticalPosition = verticalScrollBar()->value(); // 沿用原滚动单位。
        const int horizontalPosition = horizontalScrollBar()->value();
        replacement->setMouseTracking(viewport()->hasMouseTracking());
        setViewport(replacement);
        if (itemDelegate() != nullptr)
        {
            replacement->installEventFilter(itemDelegate());
        }
        verticalScrollBar()->setValue(verticalPosition);
        horizontalScrollBar()->setValue(horizontalPosition);
        replacement->update();
    }

    void ProcessGpuTableView::setGpuAccelerationEnabled(bool enabled)
    {
        m_gpuRequested = enabled;
        m_profileEnabled = enabled || qEnvironmentVariable("KSWORD_PROCESS_LIST_PROFILE") == QStringLiteral("1");
        ++m_backendGeneration;
        m_fallbackQueued = false;
        setProperty("ksword_process_gpu_fallback", QVariant());
        if (!enabled)
        {
            if (m_gpuViewport != nullptr)
            {
                m_gpuViewport = nullptr;
                replaceRenderViewport(new QWidget(this));
            }
            setProperty("ksword_process_render_backend", "raster");
            return;
        }
        // 已启用的有效视口不重建；失败后再次明确开启则允许重新尝试。
        if (m_gpuViewport != nullptr)
        {
            return;
        }
        const QString platform = QGuiApplication::platformName(); // 当前 Qt 平台插件。
        if (platform == QStringLiteral("offscreen") || platform == QStringLiteral("minimal"))
        {
            setProperty("ksword_process_gpu_fallback", "unsupported_platform");
            return;
        }

        m_gpuViewport = new ProcessGlViewport(this);
        setProperty("ksword_process_render_backend", "opengl_pending");
        replaceRenderViewport(m_gpuViewport);
    }

    bool ProcessGpuTableView::viewportEvent(QEvent* eventObject)
    {
        if (m_gpuViewport != nullptr)
        {
            // 不让 QAbstractScrollArea 抢先绘制到尚未绑定的 GL framebuffer。
            if (eventObject->type() == QEvent::Paint)
            {
                return false;
            }
            if (eventObject->type() == QEvent::Resize)
            {
                TableActionTableView::viewportEvent(eventObject);
                return false; // 同时让 QOpenGLWidget 更新其 framebuffer 尺寸。
            }
        }
        return TableActionTableView::viewportEvent(eventObject);
    }

    void ProcessGpuTableView::paintGpuFrame()
    {
        if (m_gpuViewport == nullptr || m_fallbackQueued)
        {
            return;
        }
        QElapsedTimer timer; // CPU 提交计时，不包括 GPU 完成等待或交换时间。
        timer.start();
        {
            // 完整底色和可见区域重绘，避免滚动/局部刷新后残留旧行或空白。
            QPainter backgroundPainter(m_gpuViewport);
            backgroundPainter.fillRect(m_gpuViewport->rect(), palette().brush(QPalette::Base));
        }
        QPaintEvent fullPaint(m_gpuViewport->rect()); // 委托仍读取实时 palette/model。
        TableActionTableView::paintEvent(&fullPaint);
        recordPaint(timer.nsecsElapsed());
    }

    void ProcessGpuTableView::paintEvent(QPaintEvent* eventObject)
    {
        if (!m_profileEnabled)
        {
            TableActionTableView::paintEvent(eventObject);
            return;
        }
        QElapsedTimer timer; // 普通视口使用同一计时口径，便于 A/B 对照。
        timer.start();
        TableActionTableView::paintEvent(eventObject);
        recordPaint(timer.nsecsElapsed());
    }

    void ProcessGpuTableView::scrollContentsBy(int horizontalDelta, int verticalDelta)
    {
        TableActionTableView::scrollContentsBy(horizontalDelta, verticalDelta);
        if (m_gpuViewport != nullptr)
        {
            m_gpuViewport->update();
        }
    }

    void ProcessGpuTableView::recordPaint(qint64 nanoseconds)
    {
        ++m_paintCount;
        m_totalPaintNs += nanoseconds;
        // 仅更新普通成员，避免逐帧触发全局动作条的属性事件处理。
        m_lastPaintNs = nanoseconds;
    }

    void ProcessGpuTableView::scheduleRasterFallback(const char* reason)
    {
        if (m_fallbackQueued || m_gpuViewport == nullptr)
        {
            return;
        }
        m_fallbackQueued = true;
        const quint64 failedGeneration = m_backendGeneration; // 仅回退发生故障的那一代视口。
        setProperty("ksword_process_gpu_fallback", reason);
        // 以表格作回调上下文，表格销毁时自动取消；模型与 selectionModel 不替换。
        QTimer::singleShot(0, this, [this, failedGeneration]()
        {
            if (failedGeneration != m_backendGeneration || m_gpuViewport == nullptr)
            {
                return;
            }
            m_gpuViewport = nullptr;
            replaceRenderViewport(new QWidget(this));
            m_fallbackQueued = false;
            setProperty("ksword_process_render_backend", "raster");
        });
    }
}
