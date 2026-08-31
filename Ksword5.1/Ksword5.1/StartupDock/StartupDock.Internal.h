#pragma once

// ============================================================
// StartupDock.Internal.h
// 作用：
// 1) 统一 StartupDock 多个实现文件的公共 include；
// 2) 声明内部工具函数，避免跨 .cpp 重复实现；
// 3) 保持 StartupDock 目录内实现解耦。
// ============================================================

#include "StartupDock.h"
#include "../theme.h"
#include "../Internationalization/LanguageManager.h"
#include "../ksword/startup/startup.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QVBoxLayout>

#include <Windows.h>
#include <Shellapi.h>

#include <algorithm>  // std::sort/std::clamp：结果排序与范围控制。
#include <array>      // std::array：固定大小注册表键清单。
#include <cstdint>    // std::uint*_t：系统状态字段。
#include <memory>     // std::unique_ptr：局部对象托管。
#include <optional>   // std::optional：可选字段判断。
#include <string>     // std::string：Win32/Qt 文本桥接。
#include <utility>    // std::pair/std::move：分批落表目标与缓存转移。
#include <vector>     // std::vector：启动项缓存。

namespace startup_dock_detail
{
    // startupText 作用：
    // - 按启动项界面的具体场景读取中英文文本；
    // - 中文模式保留调用点回退文本，英文模式读取场景翻译。
    QString startupText(const char* key, const QString& sourceText);

    // startupTableHeaders 作用：
    // - 生成启动项表格和高级注册表树共用的本地化表头；
    // - 语言切换后由 StartupDock 重新应用到所有视图。
    QStringList startupTableHeaders();

    // StartupTreeNodeKind：
    // - 作用：区分注册表树中的“位置节点 / 条目节点 / 占位节点”。
    enum class StartupTreeNodeKind : int
    {
        Group = 0,      // Group：一级注册表位置节点。
        Entry,          // Entry：实际启动项叶子节点。
        Placeholder     // Placeholder：无条目/无匹配项占位节点。
    };

    // 树节点数据角色：
    // - 统一保存条目索引、节点类型与注册表路径；
    // - UI 和交互逻辑共用，避免散落魔法数字。
    inline constexpr int kStartupEntryIndexRole = Qt::UserRole;
    inline constexpr int kStartupTreeNodeKindRole = Qt::UserRole + 1;
    inline constexpr int kStartupTreeLocationRole = Qt::UserRole + 2;

    // createBlueIcon 作用：
    // - 生成和现有 Dock 一致的蓝色 SVG 图标。
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize = QSize(16, 16));

    // createReadOnlyItem 作用：
    // - 统一创建不可编辑表格单元格。
    QTableWidgetItem* createReadOnlyItem(const QString& textValue);

    // winErrorText 作用：
    // - 把 Win32 错误码转换为可读文本。
    QString winErrorText(DWORD errorCode);


    // buildStatusText 作用：
    // - 把启用状态转成统一文本。
    QString buildStatusText(bool enabled);
    QString buildStatusText(const ks::startup::StartupEntry& entry);

    // startupRiskReasonText 作用：
    // - 优先按后端稳定原因码读取本地化文本；
    // - 后端诊断文本仅作为未配置语言键时的回退。
    QString startupRiskReasonText(const ks::startup::StartupEntry& backendEntry);

    // startupLocalizedDetailText 作用：
    // - 翻译带动态备份标识/路径的启动项说明；
    // - 其它静态说明继续交给 sourceText 处理。
    QString startupLocalizedDetailText(const QString& detailText);

    // parseCsvLine 作用：
    // - 解析一行 CSV 文本，支持引号转义；
    // - 供 `schtasks` 输出解析复用。
    QStringList parseCsvLine(const QString& csvLineText);

    // buildKnownStartupRegistryLocationList 作用：
    // - 返回注册表树应展示的已知 Autoruns 风格位置列表；
    // - 注册表树会按该顺序创建默认展开的一级节点。
    QStringList buildKnownStartupRegistryLocationList();

    // appendBackendStartupEntries 作用：
    // - 把 ks::startup 后端的 UTF-8 记录转换为 StartupDock 的 Qt UI 记录；
    // - 传入 entryListOut：追加目标，允许为空指针并直接返回；
    // - 传入 backendEntryList：后端枚举结果，只读转换且不复制整批容器；
    // - 返回值：无，直接向 entryListOut 追加转换后的记录。
    void appendBackendStartupEntries(
        std::vector<StartupDock::StartupEntry>* entryListOut,
        const std::vector<ks::startup::StartupEntry>& backendEntryList);
}
