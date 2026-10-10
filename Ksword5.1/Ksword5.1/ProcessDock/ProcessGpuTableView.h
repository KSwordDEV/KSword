#pragma once

#include "../UI/VisibleTableWidget.h"
#include <QElapsedTimer>

class QOpenGLWidget;

namespace ks::process_ui
{
    // 进程表 GPU 绘制：显式设置可即时切换，未配置时沿用启动环境，默认光栅。
    // 继承原动作条宿主，保留模型、选区、菜单、冻结列和快照工作流。
    class ProcessGpuTableView final : public ks::ui::TableActionTableView
    {
    public:
        // 输入父控件；构造视图并根据启动环境选择绘制后端，不改变模型。
        explicit ProcessGpuTableView(QWidget* parent = nullptr);
        // 输入已保存的用户选择，优先于环境变量；不读取或修改模型数据。
        ProcessGpuTableView(QWidget* parent, bool gpuEnabled);
        // GUI 线程切换原表格的视口，保留选区、列宽、滚动位置和冻结窗格。
        void setGpuAccelerationEnabled(bool enabled);
        bool gpuAccelerationEnabled() const
        {
            return m_gpuRequested;
        }

        // OpenGL 视口在上下文/FBO 已绑定的 paintGL 内调用；绘制整张可见区域。
        void paintGpuFrame();

        // GL 视口完成窗口交换后调用，区分实际交换回调与 CPU 绘制次数。
        void recordPresentedFrame();

        // GPU 创建失败或使用软件实现时，排队回退，避免销毁当前绘制栈中的视口。
        void scheduleRasterFallback(const char* reason);

        // GUI 线程诊断读取；不逐帧发送 DynamicPropertyChange 干扰动作条。
        quint64 paintCount() const
        {
            return m_paintCount;
        }
        // 返回累计 CPU 提交纳秒数，用累计值差分比较固定帧数。
        qint64 totalPaintNs() const
        {
            return m_totalPaintNs;
        }
        // 返回最后一帧 CPU 提交纳秒数，不等待 GPU 完成。
        qint64 lastPaintNs() const
        {
            return m_lastPaintNs;
        }

    protected:
        // Paint 交给 GL 控件初始化/绑定 FBO；其它鼠标/键盘事件仍走原表格。
        bool viewportEvent(QEvent* eventObject) override;
        // 光栅路径复用原绘制并记录 CPU 提交时间，不把该时间称为 GPU 帧耗时。
        void paintEvent(QPaintEvent* eventObject) override;
        // GL FBO 不依赖 QWidget backing-store 位图滚动，滚动后重绘完整可见区域。
        void scrollContentsBy(int horizontalDelta, int verticalDelta) override;

    private:
        // 发布最近一次和累计 CPU 绘制提交耗时，供相同负载的 A/B 实验读取。
        void recordPaint(qint64 nanoseconds);
        // 将新视口接回原生滚动对象和行委托，两个后端共用同一条替换路径。
        void replaceRenderViewport(QWidget* replacement);

        QOpenGLWidget* m_gpuViewport = nullptr; // 表格拥有的实验视口。
        bool m_profileEnabled = false;        // 默认光栅模式不计时，实验或 PROFILE=1 才开启。
        bool m_fallbackQueued = false;         // 防止同一错误重复排队回退。
        bool m_gpuRequested = false;           // 用户选择与实际后端分开，失败回退不改偏好。
        quint64 m_backendGeneration = 0;       // 失效旧后端排队的回退，避免覆盖新选择。
        quint64 m_paintCount = 0;               // 完成的绘制次数。
        qint64 m_lastPaintNs = 0;              // 最近一次 CPU 绘制提交耗时。
        qint64 m_totalPaintNs = 0;              // 累计 CPU 绘制提交耗时。
        QElapsedTimer m_presentationClock;      // 活跃重绘的单调呈现时钟。
        qint64 m_lastPresentationNs = -1;
        qint64 m_presentationWindowStartNs = -1;
        qint64 m_pendingFrameCpuNs = 0;         // 下一次交换之前全部绘制的 CPU 耗时。
        qint64 m_windowCpuNs = 0;
        quint64 m_windowPresentedFrames = 0;
        bool m_frameAwaitingPresentation = false;
    };
}
