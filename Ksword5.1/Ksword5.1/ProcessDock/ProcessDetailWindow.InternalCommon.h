#pragma once

// ============================================================
// ProcessDetailWindow.InternalCommon.h
// 作用：
// - 为 ProcessDetailWindow 多个实现 cpp 提供统一包含入口；
// - 集中声明跨文件复用的内部辅助类型、列定义与样式工具；
// - 避免再次退回到 .inc 聚合式实现。
// ============================================================

#include "ProcessDetailWindow.h"
#include "ThreadStackWindow.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../theme.h"
#include "../UI/StructuredFieldView.h"
#include <type_traits>
#include "../UI/UI_All.h"
#include "../../../shared/driver/KswordArkDynDataIoctl.h"
#include "../../../shared/ProcessTerminateMethods.h"

#include <QAbstractScrollArea>
#include <QAbstractButton>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QDirIterator>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QFontMetrics>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPalette>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QPlainTextEdit>
#include <QPoint>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScreen>
#include <QScrollArea>
#include <QSet>
#include <QSizePolicy>
#include <QStringList>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTabBar>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QtGlobal>
#include <QVBoxLayout>
#include <QWindow>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <ShlObj.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <sddl.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Uuid.lib")

namespace process_detail_window_internal
{
    inline QString fieldText(const QString& value) { return value; }
    inline QString fieldText(const std::wstring& value) { return QString::fromStdWString(value); }
    inline QString fieldText(const wchar_t* value) { return QString::fromWCharArray(value); }
    template<class Number, std::enable_if_t<std::is_integral_v<Number>, int> = 0>
    QString fieldText(Number value)
    {
        if constexpr (std::is_signed_v<Number>) return QString::number(static_cast<qlonglong>(value));
        return QString::number(static_cast<qulonglong>(value));
    }
    template<class Number, std::enable_if_t<std::is_floating_point_v<Number>, int> = 0>
    QString fieldText(Number value) { return QString::number(value, 'g', 12); }
    inline ks::ui::FieldDocument fieldNotice(const QString& text)
    {
        ks::ui::FieldDocument document; document.note(text); return document;
    }
    inline void appendFields(ks::ui::FieldDocument& into, const ks::ui::FieldDocument& from)
    { into.nodes += from.nodes; }

    // ThreadRowColumn 作用：
    // - 统一线程细节表格列顺序；
    // - 供 UI 初始化和结果回填两端共享。
    enum class ThreadRowColumn : int
    {
        ThreadId = 0,    // 线程 ID。
        State,           // 状态。
        Priority,        // 优先级。
        SwitchCount,     // 上下文切换计数。
        StartAddress,    // 起始地址。
        TebAddress,      // TEB 地址。
        Affinity,        // 亲和性信息。
        RegisterSummary, // 寄存器摘要。
        StackBoundary,   // R0/用户栈边界摘要。
        RuntimeDetail,   // R0 运行时详情：固定 detail IOCTL 的字段覆盖和诊断。
        Count            // 列总数。
    };

    // ThreadInspectHeaders 作用：线程细节表头文本常量。
    extern const QStringList ThreadInspectHeaders;

    // toThreadColumnIndex 作用：把线程列枚举转换成表格索引。
    int toThreadColumnIndex(ThreadRowColumn column);

    // ModuleColumn 作用：
    // - 统一模块表格列顺序；
    // - 避免模块页读写 UserRole 数据时出现魔法数字。
    enum class ModuleColumn : int
    {
        Path = 0,      // 模块路径（含图标）。
        Size,          // 模块大小。
        Signature,     // 数字签名状态。
        EntryOffset,   // 入口偏移量（RVA）。
        State,         // 运行状态。
        ThreadId,      // ThreadID 信息。
        Count          // 列总数。
    };

    // ModuleHeaders 作用：模块表头文本常量。
    extern const QStringList ModuleHeaders;

    // toModuleColumnIndex 作用：把模块列枚举转换成表格索引。
    int toModuleColumnIndex(ModuleColumn column);

    // buildBlueButtonStyle 作用：生成统一蓝色按钮样式。
    QString buildBlueButtonStyle();

    // buildProcessDetailRootStyle 作用：生成详情窗口根样式。
    QString buildProcessDetailRootStyle();

    // buildProcessDetailMenuStyle 作用：
    // - 生成详情页按钮弹出菜单/右键菜单的显式不透明样式；
    // - 输入无，处理时读取当前主题颜色；
    // - 返回可直接 setStyleSheet 到 QMenu 的样式文本。
    QString buildProcessDetailMenuStyle();

    // buildProcessDetailR0ActionIcon 作用：
    // - 输入 iconPath 为 qrc 业务图标路径；
    // - 返回统一尺寸的 QIcon，供已明确标注 R0 的按钮和菜单项使用。
    QIcon buildProcessDetailR0ActionIcon(const QString& iconPath);

    // buildStateLabelStyle 作用：生成状态标签样式文本。
    QString buildStateLabelStyle(const QColor& textColor, int fontWeight);

    // statusIdleColor 作用：返回空闲态文本色。
    QColor statusIdleColor();

    // statusWarningColor 作用：返回警告态文本色。
    QColor statusWarningColor();

    // statusErrorColor 作用：返回错误态文本色。
    QColor statusErrorColor();

    // statusSecondaryColor 作用：返回中性文本色。
    QColor statusSecondaryColor();

    // signatureTrustedColor 作用：返回可信签名文本色。
    QColor signatureTrustedColor();

    // signatureUntrustedColor 作用：返回不可信签名文本色。
    QColor signatureUntrustedColor();

    // formatDoubleText 作用：把浮点数格式化成固定小数位文本。
    QString formatDoubleText(double value, int precision);

    // uint64ToHex 作用：把 64 位数值格式化为十六进制文本。
    QString uint64ToHex(std::uint64_t value);

    // convertSidToText 作用：把 SID 转为“账户名 + SID”可读文本。
    QString convertSidToText(PSID sid);

    // readRemoteUnicodeString 作用：读取远程进程中的 UNICODE_STRING 内容。
    QString readRemoteUnicodeString(HANDLE processHandle, const UNICODE_STRING& remoteUnicode);

    // buildPdbRuntimeCatalogPreview 作用：
    // - 输入 domainName 为 runtimeDetailCatalog 域名，例如 process_detail/thread_detail；
    // - 处理时只读 Release/source profiles\pdb_deep_offsets 中的 ntkrnlmp deep JSON；
    // - 返回一段面向详情页展示的偏移目录预览，找不到 JSON 时返回明确诊断文本。
    ks::ui::FieldDocument buildPdbRuntimeCatalogPreview(const QString& domainName, int maxTypes, int maxFieldsPerType);

    // pdbRuntimeCatalogMatchesKernelIdentity 作用：
    // - 输入当前 R0 DynData 报告的 ntoskrnl TimeDateStamp/SizeOfImage；
    // - 处理时用 deep JSON 的 PDB GUID/Age 反查本地 v4 pack profile，再比较 PE identity；
    // - 返回 true 表示 deep offset 可用于本机 runtime sampler，false 时 detailTextOut 写明跳过原因。
    bool pdbRuntimeCatalogMatchesKernelIdentity(
        std::uint32_t timeDateStamp,
        std::uint32_t sizeOfImage,
        ks::ui::FieldDocument* detailDocumentOut);

    // buildPdbRuntimeSampleItems 作用：
    // - 输入 domainName 为 process_detail/thread_detail，maxItems 为最多采样字段数；
    // - 处理时从 deep offset JSON 中挑选可安全小字段（<=16字节）作为 R0 sampler 请求；
    // - 返回 ArkDriverClient 可直接提交的 runtime field sample item 列表。
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildPdbRuntimeSampleItems(const QString& domainName, int maxItems);

    // calculateStandaloneWindowInitialWidth 作用：
    // - 输入 candidateParent 为优先参考的客户区控件，fallbackWindow 为当前独立窗口；
    // - 处理时先定位目标屏幕，再取父控件/活动窗口/屏幕可用宽度中的可用值；
    // - 返回按 ratio 计算的初始窗口宽度，无法判断时返回 fallbackWidth；不设置最大尺寸。
    int calculateStandaloneWindowInitialWidth(QWidget* candidateParent, QWidget* fallbackWindow, double ratio, int fallbackWidth);
}
