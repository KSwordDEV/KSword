#include "./ProcessGpuTableView.h"

#include <QAbstractItemDelegate>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QOpenGLContext>
#include <QOpenGLFunctions>
#include <QOpenGLWidget>
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
        // 直接清理已绑定的 FBO，每帧只让 QTableView 创建一个 QPainter。
        // 背景 painter 结束后再启动表格 painter 会复用同一 GL 引擎，不能依赖上一轮
        // 的裁剪、模板缓冲或颜色写掩码；这里显式恢复清屏状态，避免黑条与残留像素。
        QOpenGLFunctions* functions = m_gpuViewport->context()->functions();
        functions->glDisable(GL_SCISSOR_TEST);
        functions->glDisable(GL_STENCIL_TEST);
        functions->glDisable(GL_DEPTH_TEST);
        functions->glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
        functions->glStencilMask(~GLuint(0));
        const QColor base = palette().color(QPalette::Base);
        functions->glClearColor(base.redF(), base.greenF(), base.blueF(), base.alphaF());
        functions->glClearStencil(0);
        functions->glClear(GL_COLOR_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
        QPaintEvent fullPaint(m_gpuViewport->rect()); // 委托仍读取实时 palette/model。
        TableActionTableView::paintEvent(&fullPaint);
        recordPaint(timer.nsecsElapsed());
    }

    void ProcessGpuTableView::paintEvent(QPaintEvent* eventObject)
    {
        if (m_gpuViewport != nullptr)
        {
            // GL 绘制只能从 paintGL 进入，普通 viewport 派发不保证上下文/FBO 已绑定。
            m_gpuViewport->update();
            return;
        }
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
        if (m_gpuViewport == nullptr)
        {
            TableActionTableView::scrollContentsBy(horizontalDelta, verticalDelta);
            return;
        }

        // QTableView 的基类路径最终调用 viewport->scroll，复制普通 QWidget 的旧像素。
        // GL FBO 每帧整体重绘，不能沿用该位图缓存及脏区域偏移；仅同步原生表头几何。
        // 两种滚动单位与 Qt 6.9.3 的表头规则一致，隐藏/重排列由 QHeaderView 自行映射。
        const auto syncHeader = [](QHeaderView* header, QScrollBar* bar, ScrollMode mode)
        {
            if (mode == ScrollPerPixel)
            {
                header->setOffset(bar->value());
            }
            else if (bar->maximum() > 0 && bar->value() == bar->maximum())
            {
                header->setOffsetToLastSection();
            }
            else
            {
                header->setOffsetToSectionPosition(bar->value());
            }
        };
        if (horizontalDelta != 0)
        {
            syncHeader(horizontalHeader(), horizontalScrollBar(), horizontalScrollMode());
        }
        if (verticalDelta != 0)
        {
            syncHeader(verticalHeader(), verticalScrollBar(), verticalScrollMode());
        }
        updateEditorGeometries();
        m_gpuViewport->update();
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
