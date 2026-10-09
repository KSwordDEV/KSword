#pragma once

// ============================================================
// MemoryDock.Internal.h
// 作用：
// - 汇总 MemoryDock 多个 .cpp 共享的 Qt/Win32 include 与内部工具声明；
// - 替代旧的聚合式源码结构，让 UI、进程区域、搜索和查看器逻辑独立编译；
// - 只服务 MemoryDock 内部实现，不扩大 public API。
// ============================================================

#include "MemoryDock.h"
#include "../theme.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/VisibleTableWidget.h" // ks::ui::VisibleTableWidget：反汇编表等长表格的统一基类。

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QChar>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIODevice>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPlainTextEdit>
#include <QPoint>
#include <QProgressBar>
#include <QPushButton>
#include <QPointer>
#include <QSignalBlocker>
#include <QSize>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <thread>
#include <type_traits>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

namespace ksword::memory_dock_internal
{
    // UI 样式函数：输入为空，返回主题样式表文本。
    // 三个函数都只是全局主题实现的薄封装，表头样式已整体交还 GlobalUiBaseStyle。
    QString buildBlueButtonStyle();
    QString buildBlueComboStyle();
    QString buildBlueInputStyle();

    // ModuleTreeColumn：进程模块树列定义，与 ProcessDetailWindow 模块页对齐。
    enum class ModuleTreeColumn : int
    {
        Path = 0,
        Size,
        Signature,
        EntryOffset,
        State,
        ThreadId,
        Count
    };

    // ModuleTreeHeaders：模块树表头文本，供 UI 构建代码使用。
    extern const QStringList ModuleTreeHeaders;

    // 内部转换和解析工具：输入业务值，返回 Qt/Win32 需要的辅助结果。
    int toModuleTreeColumnIndex(ModuleTreeColumn column);
    DWORD toDwordPid(std::uint32_t pid);
    bool isReadableProtect(std::uint32_t protectValue);
    bool parseHexByte(const QString& text, std::uint8_t& valueOut);
    QIcon resolveIconByPath(const QString& absolutePath, QHash<QString, QIcon>& cache);

    // addOpenInWorkbenchAction：给证据页右键菜单追加"在内存工作台打开"（实现在 MemoryDock.WorkbenchEntry.cpp）。
    // 传入：menu 要追加动作的菜单；table 证据表（用来沿父链找到所属 MemoryDock）；
    //       row 被点击的行（无效行则动作置灰）；addressColumn 地址文本所在的列；
    //       kernelAddress 该表的地址是否为内核虚拟地址（真则切到内核范围，否则按 Dock 附加进程的地址处理）。
    // 传出：已连接好点击处理的动作；找不到所属 Dock 或工作台不可用时返回空指针且不追加任何东西。
    // 调用方法：在 menu.exec() 之前调用即可，不需要再比较 exec 的返回值。
    QAction* addOpenInWorkbenchAction(
        QMenu& menu,
        QTableWidget* table,
        int row,
        int addressColumn,
        bool kernelAddress);
}
