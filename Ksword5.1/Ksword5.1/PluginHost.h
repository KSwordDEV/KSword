#pragma once

// ============================================================
// PluginHost.h
// 作用：
// - 提供 Ksword GUI 到独立插件命令行入口的唯一桥接；
// - GUI 读取插件清单，但绝不加载第三方插件代码或 DLL；
// - 文件、进程和网络入口共用同一目标上下文与菜单构建逻辑。
// ============================================================

#include <QString>

#include <QtGlobal>

class QMenu;
class QTabWidget;
class QWidget;

namespace ks::plugin_host
{
    enum class TargetKind
    {
        File,
        Process,
        Network,
    };

    struct InvocationContext
    {
        TargetKind targetKind = TargetKind::File;
        QString filePath;
        quint32 processId = 0;
        QString processName;
        quint64 processCreateTime100ns = 0; // 进程记录捕获的原创建时间；零身份不能由插件菜单补授。
        quint64 memoryAddress = 0;
        bool navigateMemoryDump = false;
    };

    // populateTargetMenu：
    // - 从 plugin\<id>\plugin.json 发现已安装插件；
    // - 只展示声明支持当前目标类型的插件，菜单层级始终为“插件 → <插件名>”；
    // - 选择动作后由 Ksword 直接用 QProcess 启动独立入口。
    void populateTargetMenu(QMenu* menu, QWidget* owner, const InvocationContext& context);

    // populateTabPlugins：
    // - 发现 plugin_type=tab 或 hybrid 的外部进程插件；
    // - 在宿主 QTabWidget 中建立原生子窗口容器，不把插件 DLL/代码加载进 KSword；
    // - 插件窗口句柄必须属于刚启动的插件进程，且必须直接挂到宿主提供的 HWND。
    // - 返回成功加入宿主的 Tab 数量。
    int populateTabPlugins(QTabWidget* tabWidget, QWidget* owner);

    // createTabPluginContainer：
    // - 创建顶部“插件”Dock 的内容容器，并注入 KSword 基础主题样式；
    // - 所有 Tab 型插件只进入该容器，不再混入“杂项/Utilities”页面；
    // - 没有已安装 Tab 插件时显示可直接打开插件管理器的空状态页。
    QWidget* createTabPluginContainer(QWidget* parent);

    // showPluginManager：
    // - 打开非模态插件管理窗口；
    // - 管理本地插件，并从商城执行许可证确认、校验和一键安装。
    void showPluginManager(QWidget* owner, const QString& preselectedPluginId = QString());
}
