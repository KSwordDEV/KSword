#include "../UI/KeyboardItemActivation.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/TableContextMenu.h"
#include "../UI/WindowTargetPicker.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeBinding.h"
#include "../UI/AsyncOperation.h"
#include "../UI/ResultTableHost.h"
#include "OtherDock.h"

namespace {
const ks::ui::PageNavigationTabDefinition kWindowNavigation[] = {
    {"window.tab.list", "", "window.tab.list", "窗口列表", true},
    {"window.tab.desktop", "", "window.tab.desktop", "桌面管理", false}
};
}

#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/TableHeaderSortingSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "../UI/FlowLayout.h"
#include "../UI/UI_All.h"

// ============================================================
// OtherDock.cpp
// 作用说明：
// 1) 实现窗口列表标签页、过滤分组、右键操作和导出；
// 2) 实现窗口详细信息对话框，覆盖常规/样式/位置/状态等标签；
// 3) 所有枚举流程都走后台线程，避免阻塞 UI 线程。
// ============================================================

#include "../ProcessDock/ProcessDetailWindow.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "WindowCaptureProtection.h"
#include "WindowListInteraction.h"
#include <QSignalBlocker>
#include "WindowInputControl.h"
#include "WindowControlInspection.h"
#include "../theme.h"
#include "../UI/CodeEditorWidget.h"

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QItemSelectionModel>
#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCloseEvent>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QDataStream>
#include <QEvent>
#include <QImage>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QFormLayout>
#include <QGuiApplication>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QScreen>
#include <QSlider>
#include "../UI/ThemedSlider.h"
#include <QSpinBox>
#include <QStackedWidget>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QTimeZone>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QVBoxLayout>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <Shellapi.h>
#include <Objbase.h>
#include <TlHelp32.h>

namespace
{
    // 统一按钮样式：与全局蓝色主题保持一致，避免界面风格割裂。
    QString blueButtonStyle()
    {
        return ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}");
    }

    // 统一输入框样式：过滤框、下拉框、数值输入用同一套视觉反馈。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    // 表头样式：突出列头，方便快速分辨字段。
    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:%2;border:0;border-bottom:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceMutedColorHex())
            .arg(KswordTheme::BorderHex());
    }

    // 转换布尔文本：统一“是/否”显示，避免各处写法不一致。
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // WindowStyleFlagDefinition：
    // - 作用：定义一个“可勾选样式位”条目（名称/位掩码/用途说明）；
    // - 调用：WindowDetailDialog 构建样式复选框组时按此表创建控件；
    // - 传入传出：本结构仅做数据承载，不直接参与系统调用。
    struct WindowStyleFlagDefinition
    {
        const char* styleNameText = nullptr;      // styleNameText：样式位名称（如 WS_VISIBLE）。
        quint64 styleMaskValue = 0;               // styleMaskValue：对应 Win32 样式位掩码。
        const char* styleDescriptionText = nullptr; // styleDescriptionText：悬停提示与导出说明文本。
    };

    // windowStyleFlagDefinitionList：
    // - 作用：返回窗口普通样式（GWL_STYLE）复选框定义；
    // - 调用：WindowDetailDialog::initializeUi 在“样式与外观”页创建 WS_* 复选框时调用；
    // - 传入传出：无入参；返回只读定义列表引用。
    const std::vector<WindowStyleFlagDefinition>& windowStyleFlagDefinitionList()
    {
        static const std::vector<WindowStyleFlagDefinition> kStyleDefinitionList = {
            { "WS_BORDER", static_cast<quint64>(WS_BORDER), "窗口有细边框。" },
            { "WS_CAPTION", static_cast<quint64>(WS_CAPTION), "窗口有标题栏（组合位：边框+对话框框架）。" },
            { "WS_CHILD", static_cast<quint64>(WS_CHILD), "窗口是子窗口，通常依附父窗口。" },
            { "WS_CLIPCHILDREN", static_cast<quint64>(WS_CLIPCHILDREN), "绘制时裁剪子窗口区域，减少重绘覆盖。" },
            { "WS_CLIPSIBLINGS", static_cast<quint64>(WS_CLIPSIBLINGS), "兄弟窗口之间绘制互相裁剪。" },
            { "WS_DISABLED", static_cast<quint64>(WS_DISABLED), "窗口禁用，不接收输入。" },
            { "WS_DLGFRAME", static_cast<quint64>(WS_DLGFRAME), "窗口具备对话框风格边框。" },
            { "WS_GROUP", static_cast<quint64>(WS_GROUP), "控件分组起始标记（常见于 Tab 导航组）。" },
            { "WS_HSCROLL", static_cast<quint64>(WS_HSCROLL), "窗口带水平滚动条。" },
            { "WS_MAXIMIZE", static_cast<quint64>(WS_MAXIMIZE), "窗口当前处于最大化样式状态位。" },
            { "WS_MAXIMIZEBOX", static_cast<quint64>(WS_MAXIMIZEBOX), "窗口显示最大化按钮。" },
            { "WS_MINIMIZE", static_cast<quint64>(WS_MINIMIZE), "窗口当前处于最小化样式状态位。" },
            { "WS_MINIMIZEBOX", static_cast<quint64>(WS_MINIMIZEBOX), "窗口显示最小化按钮。" },
            { "WS_POPUP", static_cast<quint64>(WS_POPUP), "弹出窗口样式（独立于父窗口裁剪关系）。" },
            { "WS_SIZEBOX", static_cast<quint64>(WS_SIZEBOX), "窗口可通过边框拖拽改变大小。" },
            { "WS_SYSMENU", static_cast<quint64>(WS_SYSMENU), "窗口带系统菜单（标题栏图标菜单）。" },
            { "WS_TABSTOP", static_cast<quint64>(WS_TABSTOP), "控件允许通过 Tab 键获得焦点。" },
            { "WS_VISIBLE", static_cast<quint64>(WS_VISIBLE), "窗口可见样式位。" },
            { "WS_VSCROLL", static_cast<quint64>(WS_VSCROLL), "窗口带垂直滚动条。" }
        };
        return kStyleDefinitionList;
    }

    // windowExStyleFlagDefinitionList：
    // - 作用：返回窗口扩展样式（GWL_EXSTYLE）复选框定义；
    // - 调用：WindowDetailDialog::initializeUi 在“样式与外观”页创建 WS_EX_* 复选框时调用；
    // - 传入传出：无入参；返回只读定义列表引用。
    const std::vector<WindowStyleFlagDefinition>& windowExStyleFlagDefinitionList()
    {
        static const std::vector<WindowStyleFlagDefinition> kExStyleDefinitionList = {
            { "WS_EX_ACCEPTFILES", static_cast<quint64>(WS_EX_ACCEPTFILES), "允许窗口接收拖放文件。" },
            { "WS_EX_APPWINDOW", static_cast<quint64>(WS_EX_APPWINDOW), "强制窗口显示在任务栏。" },
            { "WS_EX_CLIENTEDGE", static_cast<quint64>(WS_EX_CLIENTEDGE), "客户区边缘使用凹陷边框效果。" },
            { "WS_EX_COMPOSITED", static_cast<quint64>(WS_EX_COMPOSITED), "对后代窗口启用双缓冲绘制（可能影响性能）。" },
            { "WS_EX_CONTEXTHELP", static_cast<quint64>(WS_EX_CONTEXTHELP), "标题栏显示“帮助”按钮。" },
            { "WS_EX_CONTROLPARENT", static_cast<quint64>(WS_EX_CONTROLPARENT), "父窗口参与 Tab 键焦点导航。" },
            { "WS_EX_DLGMODALFRAME", static_cast<quint64>(WS_EX_DLGMODALFRAME), "对话框模式边框。" },
            { "WS_EX_LAYERED", static_cast<quint64>(WS_EX_LAYERED), "启用分层窗口（透明度/颜色键）。" },
            { "WS_EX_LAYOUTRTL", static_cast<quint64>(WS_EX_LAYOUTRTL), "布局从右到左。" },
            { "WS_EX_LEFTSCROLLBAR", static_cast<quint64>(WS_EX_LEFTSCROLLBAR), "垂直滚动条显示在左侧。" },
            { "WS_EX_MDICHILD", static_cast<quint64>(WS_EX_MDICHILD), "标记为 MDI 子窗口。" },
            { "WS_EX_NOACTIVATE", static_cast<quint64>(WS_EX_NOACTIVATE), "窗口显示时不激活焦点。" },
#ifdef WS_EX_NOREDIRECTIONBITMAP
            { "WS_EX_NOREDIRECTIONBITMAP", static_cast<quint64>(WS_EX_NOREDIRECTIONBITMAP), "禁用 DWM 重定向位图。" },
#endif
            { "WS_EX_NOPARENTNOTIFY", static_cast<quint64>(WS_EX_NOPARENTNOTIFY), "创建/销毁时不通知父窗口。" },
            { "WS_EX_RIGHT", static_cast<quint64>(WS_EX_RIGHT), "文字和布局右对齐。" },
            { "WS_EX_RTLREADING", static_cast<quint64>(WS_EX_RTLREADING), "文本从右到左阅读。" },
            { "WS_EX_STATICEDGE", static_cast<quint64>(WS_EX_STATICEDGE), "三维静态边框样式。" },
            { "WS_EX_TOOLWINDOW", static_cast<quint64>(WS_EX_TOOLWINDOW), "工具窗口样式（小标题栏、通常不在任务栏）。" },
            { "WS_EX_TOPMOST", static_cast<quint64>(WS_EX_TOPMOST), "窗口保持置顶层级。" },
            { "WS_EX_TRANSPARENT", static_cast<quint64>(WS_EX_TRANSPARENT), "通常影响同线程窗口绘制顺序；与 WS_EX_LAYERED 组合时可让鼠标点击穿透。" },
            { "WS_EX_WINDOWEDGE", static_cast<quint64>(WS_EX_WINDOWEDGE), "窗口外框使用凸起边缘效果。" }
        };
        return kExStyleDefinitionList;
    }

    // 把 HWND 数值转十六进制文本，用于表格首列与详情标题。
    QString hwndToText(const quint64 hwndValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(hwndValue), 0, 16)
            .toUpper();
    }

    // toHexText64 作用：
    // - 把 64 位整数统一格式化为 16 位十六进制字符串；
    // - 用于消息监控表中显示 WPARAM/LPARAM/RESULT，便于直接比对内存值。
    QString toHexText64(const quint64 numericValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(numericValue), 16, 16, QChar('0'))
            .toUpper();
    }

    // windowMessageName 作用：
    // - 把常见窗口消息 ID 映射为可读名称；
    // - 未命中的消息返回 WM_0xXXXX 形式，保持可追踪性。
    QString windowMessageName(const UINT messageId)
    {
        switch (messageId)
        {
        case WM_NULL: return QStringLiteral("WM_NULL");
        case WM_CREATE: return QStringLiteral("WM_CREATE");
        case WM_DESTROY: return QStringLiteral("WM_DESTROY");
        case WM_MOVE: return QStringLiteral("WM_MOVE");
        case WM_SIZE: return QStringLiteral("WM_SIZE");
        case WM_ACTIVATE: return QStringLiteral("WM_ACTIVATE");
        case WM_SETFOCUS: return QStringLiteral("WM_SETFOCUS");
        case WM_KILLFOCUS: return QStringLiteral("WM_KILLFOCUS");
        case WM_ENABLE: return QStringLiteral("WM_ENABLE");
        case WM_SETREDRAW: return QStringLiteral("WM_SETREDRAW");
        case WM_SETTEXT: return QStringLiteral("WM_SETTEXT");
        case WM_GETTEXT: return QStringLiteral("WM_GETTEXT");
        case WM_GETTEXTLENGTH: return QStringLiteral("WM_GETTEXTLENGTH");
        case WM_PAINT: return QStringLiteral("WM_PAINT");
        case WM_CLOSE: return QStringLiteral("WM_CLOSE");
        case WM_QUERYENDSESSION: return QStringLiteral("WM_QUERYENDSESSION");
        case WM_QUERYOPEN: return QStringLiteral("WM_QUERYOPEN");
        case WM_ENDSESSION: return QStringLiteral("WM_ENDSESSION");
        case WM_QUIT: return QStringLiteral("WM_QUIT");
        case WM_ERASEBKGND: return QStringLiteral("WM_ERASEBKGND");
        case WM_SYSCOLORCHANGE: return QStringLiteral("WM_SYSCOLORCHANGE");
        case WM_SHOWWINDOW: return QStringLiteral("WM_SHOWWINDOW");
        case WM_ACTIVATEAPP: return QStringLiteral("WM_ACTIVATEAPP");
        case WM_SETCURSOR: return QStringLiteral("WM_SETCURSOR");
        case WM_MOUSEACTIVATE: return QStringLiteral("WM_MOUSEACTIVATE");
        case WM_GETMINMAXINFO: return QStringLiteral("WM_GETMINMAXINFO");
        case WM_NCCREATE: return QStringLiteral("WM_NCCREATE");
        case WM_NCDESTROY: return QStringLiteral("WM_NCDESTROY");
        case WM_NCCALCSIZE: return QStringLiteral("WM_NCCALCSIZE");
        case WM_NCHITTEST: return QStringLiteral("WM_NCHITTEST");
        case WM_NCPAINT: return QStringLiteral("WM_NCPAINT");
        case WM_NCACTIVATE: return QStringLiteral("WM_NCACTIVATE");
        case WM_KEYDOWN: return QStringLiteral("WM_KEYDOWN");
        case WM_KEYUP: return QStringLiteral("WM_KEYUP");
        case WM_CHAR: return QStringLiteral("WM_CHAR");
        case WM_SYSKEYDOWN: return QStringLiteral("WM_SYSKEYDOWN");
        case WM_SYSKEYUP: return QStringLiteral("WM_SYSKEYUP");
        case WM_SYSCHAR: return QStringLiteral("WM_SYSCHAR");
        case WM_COMMAND: return QStringLiteral("WM_COMMAND");
        case WM_SYSCOMMAND: return QStringLiteral("WM_SYSCOMMAND");
        case WM_TIMER: return QStringLiteral("WM_TIMER");
        case WM_HSCROLL: return QStringLiteral("WM_HSCROLL");
        case WM_VSCROLL: return QStringLiteral("WM_VSCROLL");
        case WM_INITMENU: return QStringLiteral("WM_INITMENU");
        case WM_INITMENUPOPUP: return QStringLiteral("WM_INITMENUPOPUP");
        case WM_MENUSELECT: return QStringLiteral("WM_MENUSELECT");
        case WM_MENUCHAR: return QStringLiteral("WM_MENUCHAR");
        case WM_ENTERIDLE: return QStringLiteral("WM_ENTERIDLE");
        case WM_CHANGEUISTATE: return QStringLiteral("WM_CHANGEUISTATE");
        case WM_UPDATEUISTATE: return QStringLiteral("WM_UPDATEUISTATE");
        case WM_QUERYUISTATE: return QStringLiteral("WM_QUERYUISTATE");
        case WM_CTLCOLORMSGBOX: return QStringLiteral("WM_CTLCOLORMSGBOX");
        case WM_CTLCOLOREDIT: return QStringLiteral("WM_CTLCOLOREDIT");
        case WM_CTLCOLORLISTBOX: return QStringLiteral("WM_CTLCOLORLISTBOX");
        case WM_CTLCOLORBTN: return QStringLiteral("WM_CTLCOLORBTN");
        case WM_CTLCOLORDLG: return QStringLiteral("WM_CTLCOLORDLG");
        case WM_CTLCOLORSCROLLBAR: return QStringLiteral("WM_CTLCOLORSCROLLBAR");
        case WM_CTLCOLORSTATIC: return QStringLiteral("WM_CTLCOLORSTATIC");
        case WM_MOUSEMOVE: return QStringLiteral("WM_MOUSEMOVE");
        case WM_LBUTTONDOWN: return QStringLiteral("WM_LBUTTONDOWN");
        case WM_LBUTTONUP: return QStringLiteral("WM_LBUTTONUP");
        case WM_LBUTTONDBLCLK: return QStringLiteral("WM_LBUTTONDBLCLK");
        case WM_RBUTTONDOWN: return QStringLiteral("WM_RBUTTONDOWN");
        case WM_RBUTTONUP: return QStringLiteral("WM_RBUTTONUP");
        case WM_RBUTTONDBLCLK: return QStringLiteral("WM_RBUTTONDBLCLK");
        case WM_MBUTTONDOWN: return QStringLiteral("WM_MBUTTONDOWN");
        case WM_MBUTTONUP: return QStringLiteral("WM_MBUTTONUP");
        case WM_MOUSEWHEEL: return QStringLiteral("WM_MOUSEWHEEL");
        case WM_MOUSEHWHEEL: return QStringLiteral("WM_MOUSEHWHEEL");
        case WM_INPUT: return QStringLiteral("WM_INPUT");
        case WM_CAPTURECHANGED: return QStringLiteral("WM_CAPTURECHANGED");
        case WM_ENTERSIZEMOVE: return QStringLiteral("WM_ENTERSIZEMOVE");
        case WM_EXITSIZEMOVE: return QStringLiteral("WM_EXITSIZEMOVE");
        case WM_DROPFILES: return QStringLiteral("WM_DROPFILES");
        case WM_INPUTLANGCHANGE: return QStringLiteral("WM_INPUTLANGCHANGE");
        case WM_IME_STARTCOMPOSITION: return QStringLiteral("WM_IME_STARTCOMPOSITION");
        case WM_IME_COMPOSITION: return QStringLiteral("WM_IME_COMPOSITION");
        case WM_IME_ENDCOMPOSITION: return QStringLiteral("WM_IME_ENDCOMPOSITION");
        case WM_DEVICECHANGE: return QStringLiteral("WM_DEVICECHANGE");
        case WM_COPYDATA: return QStringLiteral("WM_COPYDATA");
        case WM_NOTIFY: return QStringLiteral("WM_NOTIFY");
        case WM_APP: return QStringLiteral("WM_APP");
        default:
            return QStringLiteral("WM_0x%1")
                .arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0'))
                .toUpper();
        }
    }

    // winEventName 作用：
    // - 为跨进程回退模式（WinEventHook）提供事件名映射；
    // - 方便区分对象创建/焦点/显示等 GUI 事件。
    QString winEventName(const DWORD eventId)
    {
        switch (eventId)
        {
        case EVENT_SYSTEM_FOREGROUND: return QStringLiteral("EVENT_SYSTEM_FOREGROUND");
        case EVENT_SYSTEM_MENUSTART: return QStringLiteral("EVENT_SYSTEM_MENUSTART");
        case EVENT_SYSTEM_MENUEND: return QStringLiteral("EVENT_SYSTEM_MENUEND");
        case EVENT_SYSTEM_MOVESIZESTART: return QStringLiteral("EVENT_SYSTEM_MOVESIZESTART");
        case EVENT_SYSTEM_MOVESIZEEND: return QStringLiteral("EVENT_SYSTEM_MOVESIZEEND");
        case EVENT_SYSTEM_MINIMIZESTART: return QStringLiteral("EVENT_SYSTEM_MINIMIZESTART");
        case EVENT_SYSTEM_MINIMIZEEND: return QStringLiteral("EVENT_SYSTEM_MINIMIZEEND");
        case EVENT_OBJECT_CREATE: return QStringLiteral("EVENT_OBJECT_CREATE");
        case EVENT_OBJECT_DESTROY: return QStringLiteral("EVENT_OBJECT_DESTROY");
        case EVENT_OBJECT_SHOW: return QStringLiteral("EVENT_OBJECT_SHOW");
        case EVENT_OBJECT_HIDE: return QStringLiteral("EVENT_OBJECT_HIDE");
        case EVENT_OBJECT_REORDER: return QStringLiteral("EVENT_OBJECT_REORDER");
        case EVENT_OBJECT_FOCUS: return QStringLiteral("EVENT_OBJECT_FOCUS");
        case EVENT_OBJECT_SELECTION: return QStringLiteral("EVENT_OBJECT_SELECTION");
        case EVENT_OBJECT_SELECTIONADD: return QStringLiteral("EVENT_OBJECT_SELECTIONADD");
        case EVENT_OBJECT_SELECTIONREMOVE: return QStringLiteral("EVENT_OBJECT_SELECTIONREMOVE");
        case EVENT_OBJECT_SELECTIONWITHIN: return QStringLiteral("EVENT_OBJECT_SELECTIONWITHIN");
        case EVENT_OBJECT_STATECHANGE: return QStringLiteral("EVENT_OBJECT_STATECHANGE");
        case EVENT_OBJECT_LOCATIONCHANGE: return QStringLiteral("EVENT_OBJECT_LOCATIONCHANGE");
        case EVENT_OBJECT_NAMECHANGE: return QStringLiteral("EVENT_OBJECT_NAMECHANGE");
        case EVENT_OBJECT_DESCRIPTIONCHANGE: return QStringLiteral("EVENT_OBJECT_DESCRIPTIONCHANGE");
        case EVENT_OBJECT_VALUECHANGE: return QStringLiteral("EVENT_OBJECT_VALUECHANGE");
        case EVENT_OBJECT_PARENTCHANGE: return QStringLiteral("EVENT_OBJECT_PARENTCHANGE");
        default:
            return QStringLiteral("EVENT_0x%1")
                .arg(static_cast<qulonglong>(eventId), 4, 16, QChar('0'))
                .toUpper();
        }
    }

    // 列索引常量：
    // - 统一定义窗口表格列顺序，避免各函数散落魔法数字；
    // - 本次调整把“窗口标题”置于第一列，便于快速浏览。
    constexpr int kWindowColumnTitle = 0;
    constexpr int kWindowColumnHandle = 1;
    constexpr int kWindowColumnEnumApi = 2;
    constexpr int kWindowColumnClassName = 3;
    constexpr int kWindowColumnPid = 4;
    constexpr int kWindowColumnProcessName = 5;
    constexpr int kWindowColumnTid = 6;
    constexpr int kWindowColumnSize = 7;
    constexpr int kWindowColumnVisible = 8;
    constexpr int kWindowColumnEnabled = 9;
    constexpr int kWindowColumnTopMost = 10;
    constexpr int kWindowColumnState = 11;
    constexpr int kWindowColumnAlpha = 12;

    // queryProcessImagePathByPid：
    // - 通过 PID 查询可执行文件完整路径；
    // - 成功返回完整路径，失败返回空字符串。
    QString queryProcessImagePathByPid(const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return QString();
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid);
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        if (processHandle == nullptr)
        {
            return QString();
        }

        wchar_t pathBuffer[MAX_PATH * 2] = {};
        DWORD pathLength = static_cast<DWORD>(std::size(pathBuffer));
        QString fullPath;
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer, &pathLength) != FALSE)
        {
            fullPath = QString::fromWCharArray(pathBuffer, static_cast<int>(pathLength));
        }

        ::CloseHandle(processHandle);
        return fullPath;
    }

    // 进程名查询：通过 PID 获取可执行文件名，并可选输出完整路径。
    QString queryProcessNameByPid(const std::uint32_t pid, QString* imagePathOut)
    {
        if (imagePathOut != nullptr)
        {
            imagePathOut->clear();
        }
        if (pid == 0)
        {
            return QStringLiteral("System");
        }

        const QString fullPath = queryProcessImagePathByPid(pid);
        if (fullPath.trimmed().isEmpty())
        {
            return QStringLiteral("PID_%1").arg(pid);
        }
        if (imagePathOut != nullptr)
        {
            *imagePathOut = fullPath;
        }

        const int slashPos = std::max(fullPath.lastIndexOf('/'), fullPath.lastIndexOf('\\'));
        return slashPos >= 0 ? fullPath.mid(slashPos + 1) : fullPath;
    }

    // 快照状态文本：把最小化/最大化/正常映射到统一字符串。
    QString windowStateText(
        const bool validState,
        const bool minimizedState,
        const bool maximizedState)
    {
        if (!validState)
        {
            return QStringLiteral("无效");
        }
        if (minimizedState)
        {
            return QStringLiteral("最小化");
        }
        if (maximizedState)
        {
            return QStringLiteral("最大化");
        }
        return QStringLiteral("正常");
    }

    // 过滤模式文本：用于日志中输出当前筛选语义，便于排查“看不到窗口”的问题。
    QString filterModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("所有窗口");
        case 1:
            return QStringLiteral("可见窗口");
        case 2:
            return QStringLiteral("隐藏窗口");
        case 3:
            return QStringLiteral("顶层窗口");
        case 4:
            return QStringLiteral("子窗口");
        case 5:
            return QStringLiteral("无效窗口");
        default:
            return QStringLiteral("未知模式");
        }
    }

    // 分组模式文本：统一转换为可读字符串，避免日志里仅出现数字索引。
    QString groupModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("按进程分组");
        case 1:
            return QStringLiteral("按Z序");
        case 2:
            return QStringLiteral("按层级");
        case 3:
            return QStringLiteral("按显示器");
        default:
            return QStringLiteral("未知分组");
        }
    }

    // 视图模式文本：用于记录图标/列表/详情切换。
    QString viewModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("图标视图");
        case 1:
            return QStringLiteral("列表视图");
        case 2:
            return QStringLiteral("详情视图");
        default:
            return QStringLiteral("未知视图");
        }
    }

    // 枚举模式文本：用于日志显示，帮助定位“遗漏窗口”问题。
    QString enumModeText(const int mode)
    {
        switch (mode)
        {
        case 0:
            return QStringLiteral("混合枚举(推荐)");
        case 1:
            return QStringLiteral("EnumWindows+子窗口");
        case 2:
            return QStringLiteral("EnumDesktopWindows+子窗口");
        case 3:
            return QStringLiteral("EnumThreadWindows+子窗口");
        case 4:
            return QStringLiteral("仅EnumWindows顶层");
        default:
            return QStringLiteral("未知模式");
        }
    }

    // 句柄字符串转 HWND：在详情对话框应用改动时需要把缓存句柄还原。
    HWND toHwnd(const quint64 hwndValue)
    {
        return reinterpret_cast<HWND>(static_cast<quintptr>(hwndValue));
    }

    // 枚举窗口属性上下文：用于 EnumPropsExW 回调收集属性名和值。
    struct WindowPropEnumContext
    {
        QStringList* lines = nullptr;   // 输出文本行集合。
        int maxCount = 0;               // 允许收集的最大行数。
    };

    // EnumPropsExW 回调：把每个属性键和值写入 lines，超限后提前终止。
    int CALLBACK enumWindowPropProc(HWND, LPWSTR stringPtr, HANDLE dataHandle, ULONG_PTR lParam)
    {
        WindowPropEnumContext* context = reinterpret_cast<WindowPropEnumContext*>(lParam);
        if (context == nullptr || context->lines == nullptr)
        {
            return FALSE;
        }
        if (context->lines->size() >= context->maxCount)
        {
            return FALSE;
        }

        QString keyText;
        if (stringPtr != nullptr)
        {
            const quintptr rawValue = reinterpret_cast<quintptr>(stringPtr);
            if ((rawValue >> 16) == 0)
            {
                keyText = QStringLiteral("ATOM_%1").arg(static_cast<unsigned int>(rawValue & 0xFFFFu));
            }
            else
            {
                keyText = QString::fromWCharArray(stringPtr);
            }
        }
        else
        {
            keyText = QStringLiteral("<null>");
        }

        context->lines->push_back(
            QStringLiteral("%1 = 0x%2")
            .arg(keyText)
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(dataHandle)), 0, 16));
        return TRUE;
    }

    // fileTimeToUInt64：把 FILETIME 转为 100ns 计数，便于做时间差计算。
    qulonglong fileTimeToUInt64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER fileTimeInteger{};
        fileTimeInteger.LowPart = fileTimeValue.dwLowDateTime;
        fileTimeInteger.HighPart = fileTimeValue.dwHighDateTime;
        return static_cast<qulonglong>(fileTimeInteger.QuadPart);
    }

    // fileTimeToLocalText：把 Windows FILETIME 格式化为本地时间字符串。
    QString fileTimeToLocalText(const FILETIME& fileTimeValue)
    {
        constexpr qulonglong kUnixEpochOffset100ns = 116444736000000000ULL;
        const qulonglong fileTimeTick = fileTimeToUInt64(fileTimeValue);
        if (fileTimeTick <= kUnixEpochOffset100ns)
        {
            return QStringLiteral("<N/A>");
        }

        const qint64 utcMs = static_cast<qint64>((fileTimeTick - kUnixEpochOffset100ns) / 10000ULL);
        return QDateTime::fromMSecsSinceEpoch(utcMs, QTimeZone::UTC).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    // formatDurationFrom100ns：把 100ns 时长格式化为“小时:分钟:秒.毫秒”。
    QString formatDurationFrom100ns(const qulonglong duration100ns)
    {
        const qulonglong totalMs = duration100ns / 10000ULL;
        const qulonglong totalSeconds = totalMs / 1000ULL;
        const qulonglong remainMs = totalMs % 1000ULL;
        const qulonglong hours = totalSeconds / 3600ULL;
        const qulonglong minutes = (totalSeconds % 3600ULL) / 60ULL;
        const qulonglong seconds = totalSeconds % 60ULL;

        return QStringLiteral("%1h %2m %3s %4ms")
            .arg(hours)
            .arg(minutes)
            .arg(seconds)
            .arg(remainMs);
    }

    // 按 PID 采集模块预览，每个模块保留独立身份、地址和大小字段。
    ks::ui::FieldDocument buildModuleSummaryDocument(const std::uint32_t processId, const int maxRenderCount, int* moduleCountOut, const std::function<bool()>& canceled = {})
    {
        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = 0;
        }
        if (processId == 0)
        {
            return ks::ui::FieldDocument{}.note(QStringLiteral("<System PID>"));
        }

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return ks::ui::FieldDocument{}.note(QStringLiteral("<模块枚举失败或无权限>"));
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        ks::ui::FieldDocument document;
        int moduleCount = 0;

        if (::Module32FirstW(snapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                if (canceled && canceled()) break;
                ++moduleCount;
                if (moduleCount <= maxRenderCount)
                {
                    document.section(QStringLiteral("Module"));
                    document.field(QStringLiteral("Index"), QString::number(moduleCount));
                    document.field(QStringLiteral("Name"), QString::fromWCharArray(moduleEntry.szModule));
                    document.field(QStringLiteral("Base"), QStringLiteral("0x%1")
                        .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(moduleEntry.modBaseAddr)), 0, 16));
                    document.field(QStringLiteral("Size"), QString::number(moduleEntry.modBaseSize));
                }

                moduleEntry.dwSize = sizeof(moduleEntry);
            } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);
        }

        ::CloseHandle(snapshotHandle);

        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = moduleCount;
        }

        if (document.isEmpty())
        {
            return ks::ui::FieldDocument{}.note(QStringLiteral("<未读取到模块>"));
        }
        return document;
    }

    // 保存截图只接受真实像素；失败时不得把占位提示保存为成功截图。
    QPixmap grabWindowPreviewPixmap(const quint64 hwndValue, const QSize& targetSize)
    {
        const HWND window = reinterpret_cast<HWND>(static_cast<quintptr>(hwndValue));
        if (!::IsWindow(window) || !::IsWindowVisible(window) || ::IsIconic(window)) return {};
        QPixmap sourcePixmap;
        QScreen* primaryScreen = QGuiApplication::primaryScreen();
        if (primaryScreen != nullptr)
        {
            sourcePixmap = primaryScreen->grabWindow(static_cast<WId>(hwndValue));
        }

        return sourcePixmap.isNull() ? QPixmap() : sourcePixmap.scaled(
            targetSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }

    // 通过 PID 打开进程详情窗口：复用现有 ProcessDetailWindow，便于跳转联动。
    void openProcessDetailWindow(QWidget* parent, const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return;
        }

        // 窗口列表跳转只需要 PID 和名称即可立即开窗。
        // 完整路径/签名/令牌等慢字段由 ProcessDetailWindow 后台补齐。
        ks::process::ProcessRecord record;
        record.pid = pid;
        record.processName = ks::process::GetProcessNameByPID(pid);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pid);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(record, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }

    // 枚举上下文：用于 EnumWindows / EnumDesktopWindows / EnumThreadWindows 回调携带输出容器。
    struct EnumContext
    {
        std::vector<OtherDock::WindowInfo>* outputList = nullptr; // outputList：输出窗口列表。
        std::unordered_set<quint64>* seenHandleSet = nullptr;     // seenHandleSet：去重句柄集合。
        int zOrderCounter = 0;                                    // zOrderCounter：当前枚举序号。
        bool enumerateChildren = true;                            // enumerateChildren：是否递归子窗口。
        QString topEnumApiName = QStringLiteral("EnumWindows");   // topEnumApiName：顶层窗口来源标识。
        QString childEnumApiName = QStringLiteral("EnumChildWindows"); // childEnumApiName：子窗口来源标识。
    };

    // 填充单个 WindowInfo：从 HWND 读取常用属性并写入结构体。
    void fillWindowInfo(
        HWND windowHandle,
        const int zOrderValue,
        const bool childFlag,
        const QString& enumApiName,
        OtherDock::WindowInfo& infoOut)
    {
        infoOut.hwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        infoOut.parentHwndValue = static_cast<quint64>(
            reinterpret_cast<quintptr>(::GetParent(windowHandle)));
        infoOut.ownerHwndValue = static_cast<quint64>(
            reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)));
        infoOut.enumApiName = enumApiName;
        infoOut.isChildWindow = childFlag;
        infoOut.valid = ::IsWindow(windowHandle) != FALSE;
        infoOut.zOrder = zOrderValue;

        wchar_t titleBuffer[1024] = {};
        ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(std::size(titleBuffer)));
        infoOut.titleText = QString::fromWCharArray(titleBuffer);

        wchar_t classBuffer[512] = {};
        ::GetClassNameW(windowHandle, classBuffer, static_cast<int>(std::size(classBuffer)));
        infoOut.classNameText = QString::fromWCharArray(classBuffer);

        RECT rect{};
        if (::GetWindowRect(windowHandle, &rect) != FALSE)
        {
            infoOut.windowRect = QRect(rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top);
        }
        else
        {
            infoOut.windowRect = QRect();
        }

        infoOut.styleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        infoOut.exStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));

        infoOut.visible = ::IsWindowVisible(windowHandle) != FALSE;
        infoOut.enabled = ::IsWindowEnabled(windowHandle) != FALSE;
        infoOut.topMost = (infoOut.exStyleValue & WS_EX_TOPMOST) != 0;
        infoOut.minimized = ::IsIconic(windowHandle) != FALSE;
        infoOut.maximized = ::IsZoomed(windowHandle) != FALSE;
        infoOut.displayAffinityKnown = ks::window::QueryWindowDisplayAffinity(
            infoOut.hwndValue,
            infoOut.displayAffinityValue,
            &infoOut.displayAffinityError);

        std::uint32_t processId = 0;
        const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, reinterpret_cast<DWORD*>(&processId));
        infoOut.processId = processId;
        infoOut.processCreationTime100ns = 0U;
        if (processId != 0U)
        {
            (void)ks::process::QueryProcessCreationTimeByPid(
                processId,
                &infoOut.processCreationTime100ns);
        }
        infoOut.threadId = static_cast<std::uint32_t>(threadId);
        infoOut.processNameText = queryProcessNameByPid(processId, &infoOut.processImagePathText);

        // 透明度：仅当窗口具备分层属性时尝试读取 Alpha。
        infoOut.alphaValue = 255;
        if ((infoOut.exStyleValue & WS_EX_LAYERED) != 0)
        {
            COLORREF colorKey = 0;
            BYTE alpha = 255;
            DWORD flags = 0;
            if (::GetLayeredWindowAttributes(windowHandle, &colorKey, &alpha, &flags) != FALSE)
            {
                Q_UNUSED(colorKey);
                Q_UNUSED(flags);
                infoOut.alphaValue = static_cast<int>(alpha);
            }
        }
    }

    // 子窗口枚举回调：把每个子窗口都纳入快照，满足“层级视图”需求。
    // appendWindowSnapshotIfNeeded 作用：
    // - 根据句柄去重后写入窗口快照；
    // - 返回 true 表示成功写入，false 表示句柄重复或上下文无效。
    bool appendWindowSnapshotIfNeeded(
        EnumContext* context,
        HWND windowHandle,
        const bool isChildWindow,
        const QString& enumApiName)
    {
        if (context == nullptr || context->outputList == nullptr || context->seenHandleSet == nullptr)
        {
            return false;
        }

        const quint64 hwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        if (context->seenHandleSet->find(hwndValue) != context->seenHandleSet->end())
        {
            return false;
        }
        context->seenHandleSet->insert(hwndValue);

        OtherDock::WindowInfo info;
        fillWindowInfo(
            windowHandle,
            context->zOrderCounter++,
            isChildWindow,
            enumApiName,
            info);
        context->outputList->push_back(std::move(info));
        return true;
    }

    BOOL CALLBACK enumChildWindowProc(HWND windowHandle, LPARAM param)
    {
        EnumContext* context = reinterpret_cast<EnumContext*>(param);
        if (context == nullptr)
        {
            return TRUE;
        }
        appendWindowSnapshotIfNeeded(
            context,
            windowHandle,
            true,
            context->childEnumApiName);
        return TRUE;
    }

    // 顶层窗口枚举回调：先记录顶层窗口，再递归枚举其子窗口。
    BOOL CALLBACK enumTopWindowProc(HWND windowHandle, LPARAM param)
    {
        EnumContext* context = reinterpret_cast<EnumContext*>(param);
        if (context == nullptr)
        {
            return TRUE;
        }

        appendWindowSnapshotIfNeeded(
            context,
            windowHandle,
            false,
            context->topEnumApiName);

        if (context->enumerateChildren)
        {
            ::EnumChildWindows(windowHandle, enumChildWindowProc, param);
        }
        return TRUE;
    }

    // enumThreadTopWindowProc 作用：线程窗口枚举回调（用于 EnumThreadWindows）。
    BOOL CALLBACK enumThreadTopWindowProc(HWND windowHandle, LPARAM param)
    {
        return enumTopWindowProc(windowHandle, param);
    }

    // appendByEnumWindows 作用：使用 EnumWindows 枚举窗口并按配置递归子窗口。
    void appendByEnumWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumWindows");
        context.childEnumApiName = QStringLiteral("EnumChildWindows");
        ::EnumWindows(enumTopWindowProc, reinterpret_cast<LPARAM>(&context));
    }

    // appendByEnumDesktopWindows 作用：在当前桌面上下文下枚举窗口。
    void appendByEnumDesktopWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumDesktopWindows");
        context.childEnumApiName = QStringLiteral("EnumDesktopChildWindows");
        ::EnumDesktopWindows(nullptr, enumTopWindowProc, reinterpret_cast<LPARAM>(&context));
    }

    // appendByEnumThreadWindows 作用：遍历线程并调用 EnumThreadWindows，补齐漏项。
    void appendByEnumThreadWindows(EnumContext& context)
    {
        context.topEnumApiName = QStringLiteral("EnumThreadWindows");
        context.childEnumApiName = QStringLiteral("EnumThreadChildWindows");

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return;
        }

        do
        {
            // threadEntry.th32ThreadID 用途：当前遍历到的线程 ID，作为 EnumThreadWindows 入参。
            ::EnumThreadWindows(
                threadEntry.th32ThreadID,
                enumThreadTopWindowProc,
                reinterpret_cast<LPARAM>(&context));
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
    }

    // collectWindowSnapshotByMode 作用：按用户选择的枚举策略收集窗口快照。
    void collectWindowSnapshotByMode(const int enumMode, std::vector<OtherDock::WindowInfo>& snapshotOut)
    {
        snapshotOut.clear();
        snapshotOut.reserve(512);
        std::unordered_set<quint64> seenSet;
        seenSet.reserve(2048);

        EnumContext context;
        context.outputList = &snapshotOut;
        context.seenHandleSet = &seenSet;
        context.zOrderCounter = 0;
        context.enumerateChildren = true;

        if (enumMode == 0)
        {
            // 混合模式：多策略叠加后去重，优先解决“单一 API 漏项”。
            appendByEnumWindows(context);
            appendByEnumDesktopWindows(context);
            appendByEnumThreadWindows(context);
            return;
        }

        if (enumMode == 1)
        {
            appendByEnumWindows(context);
            return;
        }

        if (enumMode == 2)
        {
            appendByEnumDesktopWindows(context);
            return;
        }

        if (enumMode == 3)
        {
            appendByEnumThreadWindows(context);
            return;
        }

        // 模式 4：仅顶层 EnumWindows，不递归子窗口，便于对比排查。
        context.enumerateChildren = false;
        appendByEnumWindows(context);
    }
}

// ============================================================
// WindowDetailDialog
// 作用说明：
// - 独立非模态窗口属性对话框；
// - 提供标签页化属性查看与部分实时修改能力。
// ============================================================
template<class Value, class... Args>
static std::shared_ptr<Value> makeWindowBackgroundValue(Args&&... args)
{
    return std::shared_ptr<Value>(new Value(std::forward<Args>(args)...), [](Value* value) {
        // Large canonical/visual containers can retire from close, cancellation,
        // a menu replacement or a dropped delivery; never destroy them on GUI.
        QThreadPool::globalInstance()->start(QRunnable::create([value] { delete value; }));
    });
}

namespace ks::windowlist
{
    static QString fileIconIdentity(const QString& path)
    {
        if (path.isEmpty()) return {};
        BY_HANDLE_FILE_INFORMATION information{};
        HANDLE file = ::CreateFileW(reinterpret_cast<const wchar_t*>(path.utf16()), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const bool known = file != INVALID_HANDLE_VALUE && ::GetFileInformationByHandle(file, &information);
        if (file != INVALID_HANDLE_VALUE) ::CloseHandle(file);
        return path.toCaseFolded() + QStringLiteral("/%1/%2/%3/%4/%5/%6/%7/%8")
            .arg(known).arg(information.dwVolumeSerialNumber).arg(information.nFileIndexHigh).arg(information.nFileIndexLow)
            .arg(information.ftLastWriteTime.dwHighDateTime).arg(information.ftLastWriteTime.dwLowDateTime)
            .arg(information.nFileSizeHigh).arg(information.nFileSizeLow);
    }
    struct Snapshot
    {
        std::vector<OtherDock::WindowInfo> current;
        std::vector<OtherDock::WindowInfo> records;
        std::vector<QString> searchKeys;
        std::vector<QString> iconKeys;
        QHash<quint64, size_t> byHwnd;
        QSet<QString> newIdentities;
        int total = 0, visible = 0, system = 0;
        quint64 revision = 0;
    };
    inline QString identity(const OtherDock::WindowInfo& value)
    {
        return ks::window::windowIdentityKey(value.hwndValue, value.processId,
            value.threadId, value.processCreationTime100ns);
    }
    static std::shared_ptr<const Snapshot> mergeSnapshot(std::vector<OtherDock::WindowInfo> current,
        const std::shared_ptr<const Snapshot>& previous)
    {
        auto next = makeWindowBackgroundValue<Snapshot>();
        next->revision = previous ? previous->revision + 1 : 1;
        QSet<QString> oldIdentities, currentIdentities;
        if (previous)
            for (const auto& value : previous->current)
                if (value.valid) oldIdentities.insert(identity(value));
        for (const auto& value : current)
        {
            const auto key = identity(value);
            currentIdentities.insert(key);
            if (!oldIdentities.contains(key)) next->newIdentities.insert(key);
        }
        next->current = std::move(current);
        next->records = next->current;
        if (previous)
            for (const auto& old : previous->current)
            {
                if (!old.valid || currentIdentities.contains(identity(old))) continue;
                auto exited = old;
                exited.valid = exited.visible = exited.enabled = exited.topMost = exited.minimized = exited.maximized = false;
                exited.titleText = QStringLiteral("[已退出] %1").arg(old.titleText);
                next->records.push_back(std::move(exited));
            }
        next->searchKeys.reserve(next->records.size());
        next->iconKeys.reserve(next->records.size());
        QHash<QString, QString> iconIdentities;
        for (size_t index = 0; index < next->records.size(); ++index)
        {
            const auto& value = next->records[index];
            const QString imagePath = value.processImagePathText.trimmed().isEmpty() ? QString() : QDir::cleanPath(value.processImagePathText.trimmed());
            const auto foundIdentity = iconIdentities.constFind(imagePath);
            if (foundIdentity == iconIdentities.cend()) iconIdentities.insert(imagePath, fileIconIdentity(imagePath));
            next->iconKeys.push_back(iconIdentities.value(imagePath));
            // Current identity wins over the one-round exited row when HWND is reused.
            if (!next->byHwnd.contains(value.hwndValue)) next->byHwnd.insert(value.hwndValue, index);
            next->searchKeys.push_back(QStringLiteral("%1 %2 %3 %4 %5")
                .arg(value.titleText, value.classNameText, value.processNameText)
                .arg(value.processId).arg(hwndToText(value.hwndValue)).toLower());
            if (!value.valid) continue;
            ++next->total;
            if (value.visible) ++next->visible;
            if (value.processId <= 4 || value.processNameText.compare(QStringLiteral("System"), Qt::CaseInsensitive) == 0 ||
                value.processNameText.compare(QStringLiteral("csrss.exe"), Qt::CaseInsensitive) == 0) ++next->system;
        }
        return next;
    }
    struct Projection;
    struct ProjectionRequest
    {
        std::shared_ptr<const Snapshot> state;
        std::shared_ptr<const Projection> previous;
        QSet<quint32> processIds;
        QString keyword;
        int filter = 0;
        int grouping = 0;
        quint64 desktopHwnd = 0;
        std::vector<std::pair<QRect, QString>> screens;
        ks::i18n::SourceTextSnapshot language;
    };
    struct Node
    {
        std::array<QString, 13> cells;
        std::vector<int> children;
        QString key, iconKey, iconPath;
        size_t record = 0;
        int parent = -1, row = 0;
        bool group = false, newRow = false;
    };
    struct Projection
    {
        std::shared_ptr<const Snapshot> state;
        std::vector<Node> nodes;
        std::vector<int> roots;
        QHash<QString, int> byIdentity;
        int grouping = 0;
    };
    static bool accepts(const ProjectionRequest& request, size_t index)
    {
        const auto& value = request.state->records[index];
        if (!request.processIds.isEmpty() && !request.processIds.contains(value.processId)) return false;
        switch (request.filter)
        {
        case 1: if (!value.visible || !value.valid) return false; break;
        case 2: if (value.visible || !value.valid) return false; break;
        case 3: if (value.isChildWindow || !value.valid) return false; break;
        case 4: if (!value.isChildWindow || !value.valid) return false; break;
        case 5: if (value.valid) return false; break;
        default: break;
        }
        return request.keyword.isEmpty() || request.state->searchKeys[index].contains(request.keyword);
    }
    static std::shared_ptr<const Projection> prepareProjection(const ProjectionRequest& request,
        const ks::ui::AsyncOperationToken* token)
    {
        auto projection = makeWindowBackgroundValue<Projection>();
        projection->state = request.state;
        projection->grouping = request.grouping;
        if (!request.state) return projection;
        std::vector<size_t> order;
        order.reserve(request.state->records.size());
        for (size_t index = 0; index < request.state->records.size(); ++index)
            if (accepts(request, index)) order.push_back(index);
        if (request.grouping == 1)
            std::stable_sort(order.begin(), order.end(), [&request](size_t left, size_t right) {
                return request.state->records[left].zOrder < request.state->records[right].zOrder;
            });
        QHash<QString, int> groups;
        for (const auto record : order)
        {
            if (token && token->isCanceled()) return {};
            const auto& value = request.state->records[record];
            QString groupKey, groupTitle;
            if (request.grouping == 0)
            {
                groupKey = QStringLiteral("pid/%1/%2").arg(value.processId).arg(value.processCreationTime100ns);
                groupTitle = QStringLiteral("%1 (PID:%2)").arg(value.processNameText).arg(value.processId);
            }
            else if (request.grouping == 2)
            {
                groupKey = value.hwndValue == request.desktopHwnd ? QStringLiteral("桌面窗口") : value.isChildWindow ? QStringLiteral("子窗口") :
                    (value.styleValue & WS_POPUP) ? QStringLiteral("弹出窗口") : (value.exStyleValue & WS_EX_TOOLWINDOW) ? QStringLiteral("工具窗口") : QStringLiteral("顶级窗口");
                groupTitle = request.language.sourceText(groupKey);
            }
            else if (request.grouping != 1)
            {
                groupKey = QStringLiteral("unknown-monitor");
                groupTitle = request.language.sourceText(QStringLiteral("未知显示器"));
                for (size_t index = 0; index < request.screens.size(); ++index)
                    if (request.screens[index].first.contains(value.windowRect.center()))
                    {
                        groupKey = QStringLiteral("monitor/%1/%2").arg(index).arg(request.screens[index].second);
                        groupTitle = request.language.sourceText(QStringLiteral("显示器%1: %2")).arg(index + 1).arg(request.screens[index].second);
                        break;
                    }
            }
            const QString iconPath = value.processImagePathText.trimmed().isEmpty() ? QString() : QDir::cleanPath(value.processImagePathText.trimmed());
            const QString iconKey = request.state->iconKeys[record];
            int parent = -1;
            if (!groupKey.isEmpty())
            {
                const auto found = groups.constFind(groupKey);
                if (found == groups.cend())
                {
                    parent = static_cast<int>(projection->nodes.size());
                    Node group;
                    group.group = true; group.record = record;
                    group.key = QStringLiteral("group/%1/%2").arg(request.grouping).arg(groupKey);
                    group.cells[0] = groupTitle;
                    group.row = static_cast<int>(projection->roots.size());
                    if (request.grouping == 0) { group.iconKey = iconKey; group.iconPath = iconPath; }
                    projection->nodes.push_back(std::move(group));
                    projection->roots.push_back(parent);
                    groups.insert(groupKey, parent);
                    projection->byIdentity.insert(projection->nodes[parent].key, parent);
                }
                else parent = found.value();
            }
            Node node;
            node.parent = parent; node.record = record;
            node.key = identity(value); node.iconKey = iconKey; node.iconPath = iconPath;
            node.newRow = request.state->newIdentities.contains(node.key);
            node.cells = {value.titleText.isEmpty() ? request.language.sourceText(QStringLiteral("<无标题>")) : value.titleText,
                hwndToText(value.hwndValue), value.enumApiName, value.classNameText, QString::number(value.processId), value.processNameText,
                QString::number(value.threadId), QStringLiteral("%1 x %2").arg(value.windowRect.width()).arg(value.windowRect.height()),
                request.language.sourceText(boolText(value.visible)), request.language.sourceText(boolText(value.enabled)),
                request.language.sourceText(boolText(value.topMost)), request.language.sourceText(windowStateText(value.valid, value.minimized, value.maximized)),
                QString::number(value.alphaValue)};
            node.row = parent < 0 ? static_cast<int>(projection->roots.size()) : static_cast<int>(projection->nodes[parent].children.size());
            const int index = static_cast<int>(projection->nodes.size());
            projection->nodes.push_back(std::move(node));
            projection->byIdentity.insert(projection->nodes.back().key, index);
            if (parent < 0) projection->roots.push_back(index);
            else projection->nodes[parent].children.push_back(index);
        }
        // An unchanged visible representation retains the exact model/selection
        // and avoids any reset/layout/decoration requests on periodic samples.
        if (request.previous && request.previous->grouping == projection->grouping &&
            request.previous->roots == projection->roots && request.previous->nodes.size() == projection->nodes.size())
        {
            bool equal = true;
            for (size_t index = 0; index < projection->nodes.size(); ++index)
            {
                const auto& left = request.previous->nodes[index]; const auto& right = projection->nodes[index];
                if (left.cells != right.cells || left.children != right.children || left.key != right.key ||
                    left.iconKey != right.iconKey || left.iconPath != right.iconPath || left.parent != right.parent || left.row != right.row ||
                    left.group != right.group || left.newRow != right.newRow ||
                    request.previous->state->records[left.record].valid != projection->state->records[right.record].valid)
                { equal = false; break; }
            }
            if (equal) return request.previous;
        }
        return projection;
    }
    struct IconRequest { QString key, path; };
    struct IconResult { QString key; QImage image; };
    static std::vector<IconResult> prepareIcons(const std::vector<IconRequest>& requests,
        const ks::ui::AsyncOperationToken& token)
    {
        // Native icon pixels are prepared off GUI. Cache identity includes path,
        // file size and write time, never PID alone or a lazy QIcon engine.
        static std::mutex cacheMutex;
        static QHash<QString, QImage> cache;
        const HRESULT initialized = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        std::vector<IconResult> result;
        for (const auto& request : requests)
        {
            if (token.isCanceled()) break;
            // Projection paths are normalized by QDir::cleanPath (forward slashes).
            // Shell parsing requires the native path, while the cache key stays canonical.
            const QString nativePath = QDir::toNativeSeparators(request.path);
            const auto* path = reinterpret_cast<const wchar_t*>(nativePath.utf16());
            const QString identity = fileIconIdentity(request.path);
            QImage image;
            { std::lock_guard<std::mutex> lock(cacheMutex); image = cache.value(identity); }
            if (image.isNull() && !request.path.isEmpty())
            {
                SHFILEINFOW info{};
                if (::SHGetFileInfoW(path, 0, &info, sizeof(info), SHGFI_ICON | SHGFI_LARGEICON) && info.hIcon)
                {
                    image = QImage::fromHICON(info.hIcon);
                    ::DestroyIcon(info.hIcon);
                }
                if (!image.isNull()) { std::lock_guard<std::mutex> lock(cacheMutex); cache.insert(identity, image); }
            }
            result.push_back({request.key, std::move(image)});
        }
        if (SUCCEEDED(initialized)) ::CoUninitialize();
        return result;
    }
    class SnapshotModel final : public QAbstractItemModel
    {
    public:
        explicit SnapshotModel(QObject* parent) : QAbstractItemModel(parent), m_iconOperation(new ks::ui::AsyncOperation(this))
        {
            m_iconOperation->setStateChangedCallback([this] { if (!m_iconOperation->isBusy()) startIconBatch(); });
        }
        ~SnapshotModel() override { m_iconOperation->close(); }
        int columnCount(const QModelIndex& = {}) const override { return 13; }
        int rowCount(const QModelIndex& parent = {}) const override
        {
            if (!snapshot || (parent.isValid() && parent.column() != 0)) return 0;
            const auto* node = get(parent);
            return static_cast<int>(node ? node->children.size() : snapshot->roots.size());
        }
        QModelIndex index(int row, int column, const QModelIndex& parent = {}) const override
        {
            if (!snapshot || row < 0 || column < 0 || column >= 13 || row >= rowCount(parent)) return {};
            const auto* node = get(parent);
            const int number = node ? node->children[row] : snapshot->roots[row];
            return createIndex(row, column, static_cast<quintptr>(number + 1));
        }
        QModelIndex parent(const QModelIndex& child) const override
        {
            const auto* node = get(child);
            return !node || node->parent < 0 ? QModelIndex() : nodeIndex(node->parent);
        }
        QModelIndex nodeIndex(int number, int column = 0) const
        {
            if (!snapshot || number < 0 || number >= static_cast<int>(snapshot->nodes.size())) return {};
            return createIndex(snapshot->nodes[number].row, column, static_cast<quintptr>(number + 1));
        }
        QModelIndex indexForIdentity(const QString& key) const
        {
            if (!snapshot) return {};
            const auto found = snapshot->byIdentity.constFind(key);
            return found == snapshot->byIdentity.cend() ? QModelIndex() : nodeIndex(found.value());
        }
        QString key(const QModelIndex& index) const { const auto* node = get(index); return node ? node->key : QString(); }
        QVariant data(const QModelIndex& index, int role) const override
        {
            const auto* node = get(index);
            if (!node || index.column() < 0 || index.column() >= 13) return {};
            const auto& value = snapshot->state->records[node->record];
            if (role == Qt::DisplayRole || role == Qt::ToolTipRole) return node->cells[index.column()];
            if (role == Qt::UserRole) return node->group ? QVariant() : QVariant::fromValue(value.hwndValue);
            if (role == Qt::UserRole + 1) return node->group;
            if (role == Qt::UserRole + 2) return value.processId;
            if (role == Qt::UserRole + 3) return value.threadId;
            if (role == Qt::UserRole + 4) return QVariant::fromValue<qulonglong>(value.processCreationTime100ns);
            if (role == Qt::UserRole + 5) return node->key;
            if (!node->group && role == Qt::ForegroundRole && !value.valid) return QBrush(KswordTheme::ExitedRowForegroundColor());
            if (!node->group && role == Qt::BackgroundRole)
            {
                if (!value.valid) return QBrush(KswordTheme::ExitedRowBackgroundColor());
                if (node->newRow) return QBrush(KswordTheme::NewRowBackgroundColor());
            }
            if (role == Qt::DecorationRole && ((node->group && index.column() == 0) || (!node->group && index.column() == kWindowColumnProcessName)))
            {
                if (node->group && node->iconPath.isEmpty())
                    return snapshot->grouping == 2 ? m_treeIcon : m_listIcon;
                return logo(node->iconKey, node->iconPath);
            }
            return {};
        }
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override
        {
            if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < headers.size()) return headers[section];
            if (orientation == Qt::Horizontal) return headerRoles.value(section).value(role);
            return QAbstractItemModel::headerData(section, orientation, role);
        }
        bool setHeaderData(int section, Qt::Orientation orientation, const QVariant& value, int role = Qt::EditRole) override
        {
            if (orientation != Qt::Horizontal || section < 0 || section >= headers.size()) return false;
            if (role != Qt::DisplayRole && role != Qt::EditRole) { headerRoles[section].insert(role, value); return true; }
            if (headers[section] == value.toString()) return true;
            headers[section] = value.toString(); emit headerDataChanged(orientation, section, section); return true;
        }
        void publish(std::shared_ptr<const Projection> value)
        {
            const QPointer<SnapshotModel> alive(this);
            beginResetModel();
            if (!alive) return;
            snapshot = std::move(value);
            endResetModel();
        }
        QHash<int, QHash<int, QVariant>> headerRoles;
        QStringList headers;
        std::shared_ptr<const Projection> snapshot;
        std::function<void()> iconsChanged;
    private:
        const Node* get(const QModelIndex& index) const
        {
            const auto number = index.internalId();
            return snapshot && index.isValid() && number && number <= snapshot->nodes.size() ? &snapshot->nodes[number - 1] : nullptr;
        }
        QIcon logo(const QString& key, const QString& path) const
        {
            const auto found = m_icons.constFind(key);
            if (found != m_icons.cend()) return found.value();
            if (!path.isEmpty() && !m_requested.contains(key))
            {
                m_requested.insert(key);
                m_pending.push_back({key, path});
                if (!m_iconWakeQueued)
                {
                    m_iconWakeQueued = true;
                    QTimer::singleShot(0, const_cast<SnapshotModel*>(this), [this] {
                        m_iconWakeQueued = false;
                        const_cast<SnapshotModel*>(this)->startIconBatch();
                    });
                }
            }
            return m_defaultIcon;
        }
        void startIconBatch()
        {
            if (m_pending.empty() || m_iconOperation->isBusy()) return;
            std::vector<IconRequest> batch;
            while (!m_pending.empty() && batch.size() < 16)
            { batch.push_back(std::move(m_pending.front())); m_pending.pop_front(); }
            m_iconOperation->submit<std::vector<IconRequest>, std::vector<IconResult>>(
                std::move(batch), prepareIcons,
                [this](const std::vector<IconResult>& values, std::uint64_t) {
                    for (const auto& value : values)
                        m_icons.insert(value.key, value.image.isNull() ? m_defaultIcon : QIcon(QPixmap::fromImage(value.image)));
                    if (iconsChanged) iconsChanged();
                    return true;
                }, [](std::exception_ptr) {});
        }
        ks::ui::AsyncOperation* m_iconOperation;
        mutable QHash<QString, QIcon> m_icons;
        mutable QSet<QString> m_requested;
        mutable std::deque<IconRequest> m_pending;
        mutable bool m_iconWakeQueued = false;
        QIcon m_defaultIcon{QStringLiteral(":/Icon/process_main.svg")};
        QIcon m_treeIcon{QStringLiteral(":/Icon/process_tree.svg")};
        QIcon m_listIcon{QStringLiteral(":/Icon/process_list.svg")};
    };
}

namespace
{
    struct WindowMessageRecord
    {
        QString channelText;
        quint64 hwndValue = 0;
        quint64 messageId = 0;
        quint64 wParamValue = 0;
        quint64 lParamValue = 0;
        quint64 resultValue = 0;
        QString extraText;
        QDateTime capturedAt;
        quint64 sequence = 0;
    };
    struct WindowMessageArchive
    {
        std::mutex mutex;
        std::deque<std::shared_ptr<const WindowMessageRecord>> rows;
        quint64 nextSequence = 1;
        quint64 revision = 1;
        quint64 clearGeneration = 1;
        quint64 captured = 0;
        quint64 dropped = 0;
        size_t limit = 5000;
    };
    struct WindowMessagePort
    {
        std::shared_ptr<WindowMessageArchive> archive;
        quint64 targetHwnd = 0;
        bool active = true; // protected by archive->mutex, including stop/clear boundaries
    };
    struct WindowMessageDisplayRow
    {
        quint64 sequence = 0;
        std::array<QString, 8> cells;
    };
    struct WindowMessageSnapshot
    {
        std::vector<std::shared_ptr<const WindowMessageDisplayRow>> rows;
        quint64 revision = 0;
        quint64 clearGeneration = 0;
    };
    static void recordWindowMessage(const std::shared_ptr<WindowMessagePort>& port, WindowMessageRecord record)
    {
        if (!port || record.hwndValue != port->targetHwnd) return;
        // Capture time belongs to the event, never to a later GUI flush.
        record.capturedAt = QDateTime::currentDateTime();
        auto value = std::make_shared<WindowMessageRecord>(std::move(record));
        std::lock_guard<std::mutex> lock(port->archive->mutex);
        if (!port->active) return;
        auto& archive = *port->archive;
        value->sequence = archive.nextSequence++;
        ++archive.captured;
        while (archive.rows.size() >= archive.limit)
        {
            archive.rows.pop_front();
            ++archive.dropped;
        }
        archive.rows.push_back(std::move(value));
        ++archive.revision;
    }
    static WindowMessageSnapshot prepareWindowMessages(
        const std::shared_ptr<WindowMessageArchive>& archive,
        const std::shared_ptr<const WindowMessageSnapshot>& previous,
        const ks::ui::AsyncOperationToken* token)
    {
        WindowMessageSnapshot result;
        std::vector<std::shared_ptr<const WindowMessageRecord>> records;
        {
            std::lock_guard<std::mutex> lock(archive->mutex);
            records.assign(archive->rows.begin(), archive->rows.end());
            result.revision = archive->revision;
            result.clearGeneration = archive->clearGeneration;
        }
        result.rows.reserve(records.size());
        const quint64 first = previous && !previous->rows.empty() ? previous->rows.front()->sequence : 0;
        for (const auto& record : records)
        {
            if (token && token->isCanceled()) return {};
            const quint64 offset = record->sequence - first;
            if (previous && first && record->sequence >= first && offset < previous->rows.size() &&
                previous->rows[static_cast<size_t>(offset)]->sequence == record->sequence)
            {
                result.rows.push_back(previous->rows[static_cast<size_t>(offset)]);
                continue;
            }
            auto row = std::make_shared<WindowMessageDisplayRow>();
            row->sequence = record->sequence;
            row->cells = { record->capturedAt.toString(QStringLiteral("HH:mm:ss.zzz")),
                record->channelText, hwndToText(record->hwndValue),
                QStringLiteral("0x%1").arg(record->messageId, 4, 16, QChar('0')).toUpper(),
                record->channelText.contains(QStringLiteral("WinEvent")) ? winEventName(static_cast<DWORD>(record->messageId))
                    : windowMessageName(static_cast<UINT>(record->messageId)),
                toHexText64(record->wParamValue), toHexText64(record->lParamValue),
                record->extraText.trimmed().isEmpty() ? toHexText64(record->resultValue)
                    : QStringLiteral("%1 | %2").arg(toHexText64(record->resultValue), record->extraText) };
            result.rows.push_back(std::move(row));
        }
        return result;
    }
    class WindowMessageModel final : public QAbstractTableModel
    {
    public:
        explicit WindowMessageModel(QObject* parent) : QAbstractTableModel(parent) {}
        int rowCount(const QModelIndex& parent = {}) const override
            { return parent.isValid() || !snapshot ? 0 : static_cast<int>(snapshot->rows.size()); }
        int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 8; }
        QVariant data(const QModelIndex& index, int role) const override
        {
            if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || index.column() < 0 || index.column() >= 8) return {};
            if (role == Qt::DisplayRole || role == Qt::ToolTipRole)
                return snapshot->rows[static_cast<size_t>(index.row())]->cells[static_cast<size_t>(index.column())];
            if (role == Qt::UserRole) return QVariant::fromValue(snapshot->rows[static_cast<size_t>(index.row())]->sequence);
            return {};
        }
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override
        {
            if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < headers.size()) return headers[section];
            if (orientation == Qt::Horizontal) return headerRoles.value(section).value(role);
            return QAbstractTableModel::headerData(section, orientation, role);
        }
        bool setHeaderData(int section, Qt::Orientation orientation, const QVariant& value, int role = Qt::EditRole) override
        {
            if (orientation != Qt::Horizontal || section < 0 || section >= headers.size()) return false;
            if (role != Qt::DisplayRole && role != Qt::EditRole) { headerRoles[section].insert(role, value); return true; }
            if (headers[section] == value.toString()) return true;
            headers[section] = value.toString(); emit headerDataChanged(orientation, section, section); return true;
        }
        void publish(std::shared_ptr<const WindowMessageSnapshot> value)
        {
            const QPointer<WindowMessageModel> alive(this);
            beginResetModel();
            if (!alive) return;
            snapshot = std::move(value);
            endResetModel();
        }
        quint64 sequenceAt(int row) const
            { return row < 0 || row >= rowCount() ? 0 : snapshot->rows[static_cast<size_t>(row)]->sequence; }
        int rowForSequence(quint64 sequence) const
        {
            if (!snapshot || snapshot->rows.empty() || sequence < snapshot->rows.front()->sequence) return -1;
            const auto offset = sequence - snapshot->rows.front()->sequence;
            return offset < snapshot->rows.size() && snapshot->rows[static_cast<size_t>(offset)]->sequence == sequence ? static_cast<int>(offset) : -1;
        }
        QHash<int, QHash<int, QVariant>> headerRoles;
        QStringList headers;
        std::shared_ptr<const WindowMessageSnapshot> snapshot;
    };
}

class WindowDetailDialog final : public QDialog
{
public:
    // 构造函数：
    // - 作用：缓存初始窗口信息，构建 UI 并同步一次运行时数据。
    // - 参数 info：来自窗口列表的快照数据。
    // - 参数 parent：Qt 父控件。
    explicit WindowDetailDialog(const OtherDock::WindowInfo& info, QWidget* parent = nullptr)
        : QDialog(parent)
        , m_info(info)
    {
        setAttribute(Qt::WA_DeleteOnClose, true);
        setObjectName(QStringLiteral("WindowDetailDialogRoot"));
        // Keep the inspected HWND as structured metadata.  Companion pages must
        // not have to parse a localized/user-controlled window title to find it.
        setProperty("ksword.windowDetail.targetHwnd", QVariant::fromValue(info.hwndValue));
        setAttribute(Qt::WA_StyledBackground, true);
        setAutoFillBackground(true);
        setWindowTitle(QStringLiteral("窗口属性 - [%1] (%2)")
            .arg(info.titleText.isEmpty() ? QStringLiteral("<无标题>") : info.titleText,
                hwndToText(info.hwndValue)));
        initializeUi();
        setStyleSheet(ks::ui::BuildDetailDialogChromeStyle());
        ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(1000, 820), QSize(640, 480));
        m_messageSnapshotOperation = new ks::ui::AsyncOperation(this);
        m_messageFlushTimer = new QTimer(this);
        m_messageFlushTimer->setInterval(40);
        connect(m_messageFlushTimer, &QTimer::timeout, this, [this] { flushDeferredMessageRows(); });
        m_messageFlushTimer->start();
        m_runtimeOperation = new ks::ui::AsyncOperation(this);
        RuntimeSnapshot initial;
        initial.info = m_info; initial.valid = m_info.valid; initial.native = false;
        initial.style = runtimeStyleDocument(m_info.styleValue, m_info.exStyleValue);
        applyRuntimeBase(initial);
        const auto unread = ks::ui::FieldDocument{}.note(QStringLiteral("未读取"));
        for (auto* fields : {m_processThreadText, m_classText, m_hookText, m_advancedText}) fields->setDocument(unread);
        for (auto* spin : {m_xSpin, m_ySpin, m_widthSpin, m_heightSpin})
            connect(spin, &QSpinBox::valueChanged, this, [this] { if (!m_runtimeApplying) ++m_runtimeEditRevision; });
        connect(m_tabWidget, &QTabWidget::currentChanged, this, [this] { requestRuntimeInfo(currentRuntimeMask()); });
        requestRuntimeInfo(currentRuntimeMask());
    }

    // 析构函数：
    // - 作用：确保关闭详情窗时释放消息钩子句柄，避免系统残留回调。
    ~WindowDetailDialog() override
    {
        if (m_tabWidget) disconnect(m_tabWidget, nullptr, this, nullptr);
        if (m_messageSnapshotOperation) m_messageSnapshotOperation->close();
        if (m_runtimeOperation) m_runtimeOperation->close();
        stopMessageMonitor();
    }

private:
    // StyleCheckBinding：
    // - 作用：保存“一个复选框”和“对应样式位”之间的绑定关系；
    // - 调用：刷新样式时按绑定回填勾选状态，应用样式时按绑定收集位掩码；
    // - 传入传出：本结构只作为 WindowDetailDialog 内部容器，不跨类传递。
    struct StyleCheckBinding
    {
        QString styleNameText;            // styleNameText：样式位名称（展示与导出使用）。
        QString styleDescriptionText;     // styleDescriptionText：样式说明（用于提示）。
        quint64 styleMaskValue = 0;       // styleMaskValue：Win32 样式位掩码。
        QCheckBox* checkBox = nullptr;    // checkBox：与样式位绑定的勾选控件。
    };

    // appendStyleCheckBoxGroup：
    // - 作用：把一组样式定义转为复选框网格并加入布局；
    // - 调用：initializeUi 创建“窗口样式/扩展样式”两组控件时各调用一次；
    // - 传入 definitionList/bindingList：定义列表与输出绑定容器；
    // - 传出：无，结果直接写入 UI 布局和 bindingList。
    void appendStyleCheckBoxGroup(
        QWidget* parentWidget,
        QVBoxLayout* hostLayout,
        const QString& groupTitleText,
        const std::vector<WindowStyleFlagDefinition>& definitionList,
        std::vector<StyleCheckBinding>* bindingList)
    {
        if (parentWidget == nullptr || hostLayout == nullptr || bindingList == nullptr)
        {
            return;
        }

        QWidget* groupBox = ks::ui::CreateDetailCard(groupTitleText, parentWidget);
        auto* groupLayout = qobject_cast<QVBoxLayout*>(groupBox->layout());
        // 样式位保持原按钮和绑定，流式排列会随可用宽度换行。
        auto* gridLayout = new ks::ui::FlowLayout(nullptr, 0, 16, 8);
        groupLayout->addLayout(gridLayout);

        for (const WindowStyleFlagDefinition& definition : definitionList)
        {
            // checkboxText：显示样式位名称，便于和文档/Win32 常量直接对应。
            const QString checkboxText = QString::fromLatin1(definition.styleNameText);
            QCheckBox* flagCheckBox = new QCheckBox(checkboxText, groupBox);
            // checkboxTip：鼠标悬停时解释该样式位用途。
            const QString checkboxTip = QString::fromUtf8(definition.styleDescriptionText);
            flagCheckBox->setToolTip(checkboxTip);

            gridLayout->addWidget(flagCheckBox);

            StyleCheckBinding binding;
            binding.styleNameText = checkboxText;
            binding.styleDescriptionText = checkboxTip;
            binding.styleMaskValue = definition.styleMaskValue;
            binding.checkBox = flagCheckBox;
            bindingList->push_back(binding);

            connect(flagCheckBox, &QCheckBox::toggled, this, [this](bool) {
                if (m_styleCheckSyncing)
                {
                    return;
                }

                if (!m_runtimeApplying) ++m_runtimeEditRevision;
                // 变更后即时刷新“状态面板”的置顶/分层联动显示。
                updateDerivedStyleControlsFromCheckBoxes();
                if (m_styleApplyButton != nullptr)
                {
                    m_styleApplyButton->setEnabled(true);
                }
                if (m_applyButton != nullptr)
                {
                    m_applyButton->setEnabled(true);
                }
            });
        }

        hostLayout->addWidget(groupBox, 0);
    }

    // collectStyleFlagsFromCheckBoxes：
    // - 作用：把所有复选框状态汇总成 style/exStyle 两个掩码；
    // - 调用：applyStyleCheckBoxChanges、updateDerivedStyleControlsFromCheckBoxes；
    // - 传入传出：通过 styleValueOut/exStyleValueOut 输出目标样式值。
    void collectStyleFlagsFromCheckBoxes(quint64* styleValueOut, quint64* exStyleValueOut) const
    {
        if (styleValueOut != nullptr)
        {
            *styleValueOut = 0;
        }
        if (exStyleValueOut != nullptr)
        {
            *exStyleValueOut = 0;
        }

        if (styleValueOut != nullptr)
        {
            for (const StyleCheckBinding& binding : m_styleCheckBindingList)
            {
                if (binding.checkBox != nullptr && binding.checkBox->isChecked())
                {
                    *styleValueOut |= binding.styleMaskValue;
                }
            }
        }

        if (exStyleValueOut != nullptr)
        {
            for (const StyleCheckBinding& binding : m_exStyleCheckBindingList)
            {
                if (binding.checkBox != nullptr && binding.checkBox->isChecked())
                {
                    *exStyleValueOut |= binding.styleMaskValue;
                }
            }
        }
    }

    // updateDerivedStyleControlsFromCheckBoxes：
    // - 作用：根据样式复选框当前状态回填基础页的置顶控件；
    // - 调用：勾选变化后、刷新样式回填后；
    // - 传入传出：无，回填时阻断用户修改信号。
    void updateDerivedStyleControlsFromCheckBoxes()
    {
        quint64 styleValue = 0;
        quint64 exStyleValue = 0;
        collectStyleFlagsFromCheckBoxes(&styleValue, &exStyleValue);

        if (m_topMostCheck != nullptr)
        {
            Q_UNUSED(styleValue);
            const QSignalBlocker blocker(m_topMostCheck);
            m_topMostCheck->setChecked((exStyleValue & WS_EX_TOPMOST) != 0);
        }
    }

    // 基础页状态控件与样式位共用同一份待应用状态。
    void setExtendedStyleFlag(const quint64 mask, const bool enabled)
    {
        for (const StyleCheckBinding& binding : m_exStyleCheckBindingList)
        {
            if (binding.styleMaskValue == mask && binding.checkBox != nullptr)
            {
                binding.checkBox->setChecked(enabled);
                return;
            }
        }
    }

    void markAppearanceChangesPending()
    {
        if (!m_runtimeApplying) ++m_runtimeEditRevision;
        m_styleApplyButton->setEnabled(true);
        m_applyButton->setEnabled(true);
    }

    void setPendingAlpha(const int value)
    {
        const QSignalBlocker sliderBlocker(m_alphaSlider);
        const QSignalBlocker spinBlocker(m_alphaSpin);
        m_alphaSlider->setValue(value);
        m_alphaSpin->setValue(value);
        m_alphaChanged = true;
        setExtendedStyleFlag(WS_EX_LAYERED, true);
        markAppearanceChangesPending();
    }

    // syncStyleCheckBoxes：
    // - 作用：把系统当前样式值回填到复选框；
    // - 调用：refreshRuntimeInfo 每次读取到最新样式后调用；
    // - 传入 styleValue/exStyleValue：目标窗口实时样式值；
    // - 传出：无，UI 勾选状态被同步到实时值。
    void syncStyleCheckBoxes(const quint64 styleValue, const quint64 exStyleValue)
    {
        m_styleCheckSyncing = true;
        for (const StyleCheckBinding& binding : m_styleCheckBindingList)
        {
            if (binding.checkBox != nullptr)
            {
                binding.checkBox->setChecked((styleValue & binding.styleMaskValue) != 0);
            }
        }
        for (const StyleCheckBinding& binding : m_exStyleCheckBindingList)
        {
            if (binding.checkBox != nullptr)
            {
                binding.checkBox->setChecked((exStyleValue & binding.styleMaskValue) != 0);
            }
        }
        m_styleCheckSyncing = false;
        updateDerivedStyleControlsFromCheckBoxes();
    }

    // applyStyleCheckBoxChanges：
    // - 作用：将复选框状态写回目标窗口的 GWL_STYLE/GWL_EXSTYLE；
    // - 调用：样式页“应用样式位”按钮、底部“应用修改”按钮；
    // - 传入 showSuccessDialog：是否弹出成功提示；
    // - 传出：返回是否完成样式写回（不保证每一位都被系统接受）。
    bool applyStyleCheckBoxChanges(const bool showSuccessDialog)
    {
        HWND windowHandle = toHwnd(m_info.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("应用失败"), QStringLiteral("目标窗口句柄已失效。"));
            return false;
        }

        // selectedStyleValue/selectedExStyleValue：复选框勾选出的“受控位”目标值。
        quint64 selectedStyleValue = 0;
        quint64 selectedExStyleValue = 0;
        collectStyleFlagsFromCheckBoxes(&selectedStyleValue, &selectedExStyleValue);

        // managedStyleMask/managedExStyleMask：当前界面可管理的样式位总掩码。
        quint64 managedStyleMask = 0;
        quint64 managedExStyleMask = 0;
        for (const StyleCheckBinding& binding : m_styleCheckBindingList)
        {
            managedStyleMask |= binding.styleMaskValue;
        }
        for (const StyleCheckBinding& binding : m_exStyleCheckBindingList)
        {
            managedExStyleMask |= binding.styleMaskValue;
        }

        // currentStyleValue/currentExStyleValue：读取系统实时样式，保留未在 UI 暴露的位。
        const quint64 currentStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        const quint64 currentExStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));
        const quint64 desiredStyleValue =
            (currentStyleValue & ~managedStyleMask)
            | (selectedStyleValue & managedStyleMask);
        const quint64 desiredExStyleValue =
            (currentExStyleValue & ~managedExStyleMask)
            | (selectedExStyleValue & managedExStyleMask);

        ::SetLastError(ERROR_SUCCESS);
        ::SetWindowLongPtrW(windowHandle, GWL_STYLE, static_cast<LONG_PTR>(desiredStyleValue));
        const DWORD styleError = ::GetLastError();

        ::SetLastError(ERROR_SUCCESS);
        ::SetWindowLongPtrW(windowHandle, GWL_EXSTYLE, static_cast<LONG_PTR>(desiredExStyleValue));
        const DWORD exStyleError = ::GetLastError();

        // SetWindowPos：触发非客户区重算，确保样式变化立即生效。
        ::SetLastError(ERROR_SUCCESS);
        const BOOL positionApplied = ::SetWindowPos(
            windowHandle,
            (desiredExStyleValue & WS_EX_TOPMOST) != 0 ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        DWORD positionError = positionApplied != FALSE ? ERROR_SUCCESS : ::GetLastError();
        if (positionApplied == FALSE && positionError == ERROR_SUCCESS)
        {
            positionError = ERROR_GEN_FAILURE;
        }

        // 只在用户改过 Alpha 或新启用分层时写入，保留已有的颜色键透明。
        // 单纯调整置顶不触碰 UpdateLayeredWindow 管理的逐像素透明窗口。
        DWORD alphaError = ERROR_SUCCESS;
        if ((desiredExStyleValue & WS_EX_LAYERED) != 0
            && (m_alphaChanged || (currentExStyleValue & WS_EX_LAYERED) == 0))
        {
            COLORREF colorKey = 0;
            BYTE previousAlpha = 255;
            DWORD flags = 0;
            ::GetLayeredWindowAttributes(windowHandle, &colorKey, &previousAlpha, &flags);
            ::SetLastError(ERROR_SUCCESS);
            const BOOL alphaApplied = ::SetLayeredWindowAttributes(
                windowHandle,
                colorKey,
                static_cast<BYTE>(m_alphaSlider->value()),
                (flags & LWA_COLORKEY) | LWA_ALPHA);
            if (alphaApplied == FALSE)
            {
                alphaError = ::GetLastError();
                if (alphaError == ERROR_SUCCESS)
                {
                    alphaError = ERROR_GEN_FAILURE;
                }
            }
        }

        ::RedrawWindow(
            windowHandle,
            nullptr,
            nullptr,
            RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW | RDW_ALLCHILDREN);

        refreshRuntimeInfo();

        const bool styleWriteOk = (styleError == ERROR_SUCCESS);
        const bool exStyleWriteOk = (exStyleError == ERROR_SUCCESS);
        const bool appearanceWriteOk = styleWriteOk && exStyleWriteOk
            && positionError == ERROR_SUCCESS && alphaError == ERROR_SUCCESS;
        if (!appearanceWriteOk)
        {
            // privilegePromptHandled：权限恢复提示已覆盖失败时不再显示部分写入提示。
            const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("修改窗口样式"),
                !styleWriteOk ? styleError : !exStyleWriteOk ? exStyleError
                    : positionError != ERROR_SUCCESS ? positionError : alphaError);
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("样式应用提示"),
                    QStringLiteral("部分窗口设置未能应用：Style=%1, ExStyle=%2, 置顶=%3, Alpha=%4。")
                    .arg(styleError)
                    .arg(exStyleError)
                    .arg(positionError)
                    .arg(alphaError));
            }
        }
        else if (showSuccessDialog)
        {
            QMessageBox::information(this, QStringLiteral("窗口样式"), QStringLiteral("样式已应用。"));
        }
        return appearanceWriteOk;
    }

    // 构建 UI：保留全部属性页，由共享详情侧栏承载导航，并绑定底部操作按钮。
    void initializeUi()
    {
        QVBoxLayout* rootLayout = new QVBoxLayout(this);
        ks::ui::ConfigureDetailDialogRoot(this);

        QWidget* summaryHeader = ks::ui::CreateDetailSummaryHeader(this,
            m_info.titleText.isEmpty() ? QStringLiteral("<无标题>") : m_info.titleText,
            hwndToText(m_info.hwndValue), QIcon(QStringLiteral(":/Icon/process_details.svg")));
        rootLayout->addWidget(summaryHeader);
        m_tabWidget = new QTabWidget(this);
        // 只排列左侧入口；底层页签索引仍由各窗口属性模块保留。
        using NavKind = ks::ui::DetailNavigationKind;
        ks::ui::SetDetailTabGroups(m_tabWidget, {
            {NavKind::General, {0, 2}}, {NavKind::Ownership, {1}},
            {NavKind::Interaction, {3, 6, 4}}, {NavKind::Internals, {5}},
            {NavKind::Display, {7, 8, 9}}});
        // 共享shell已经隔离页签/堆叠控件最小尺寸，并由分组导航替代原TabBar。
        rootLayout->addWidget(ks::ui::CreateDetailTabShell(m_tabWidget, this), 1);

        // ==================== 1. 基础属性 Tab（合并前四个页签） ====================
        QWidget* basicPage = new QWidget(m_tabWidget);
        QWidget* basicContent = ks::ui::EnablePageInnerScroll(basicPage);
        QVBoxLayout* basicLayout = new QVBoxLayout(basicContent);
        basicLayout->setContentsMargins(16, 16, 16, 16);
        basicLayout->setSpacing(12);
        const int fieldHeight = std::max(28, fontMetrics().height() + 12);

        // 常规字段使用独立卡片和自适应双列，不再让四列表格决定窗口最小宽度。
        QWidget* generalGroup = ks::ui::CreateDetailCard(QStringLiteral("常规信息"), basicContent);
        QFormLayout* generalLeft = nullptr;
        QFormLayout* generalRight = nullptr;
        ks::ui::AddDetailFieldColumns(generalGroup, generalLeft, generalRight);
        m_handleLabel = new QLabel(generalGroup);
        m_parentHandleLabel = new QLabel(generalGroup);
        m_ownerHandleLabel = new QLabel(generalGroup);
        m_titleEdit = new QLineEdit(generalGroup);
        m_classNameLabel = new QLabel(generalGroup);
        m_instanceLabel = new QLabel(generalGroup);
        m_stateLabel = new QLabel(generalGroup);
        m_relationLabel = new QLabel(generalGroup);
        m_titleEdit->setReadOnly(true);
        ks::ui::StyleStandaloneInput(m_titleEdit);
        for (QLabel* label : {m_handleLabel, m_parentHandleLabel, m_ownerHandleLabel,
                 m_classNameLabel, m_instanceLabel, m_stateLabel, m_relationLabel})
        {
            label->setTextInteractionFlags(Qt::TextSelectableByMouse);
            label->setWordWrap(true);
            label->setMinimumWidth(0);
            label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        }
        generalLeft->addRow(QStringLiteral("标题"), m_titleEdit);
        generalLeft->addRow(QStringLiteral("类名"), m_classNameLabel);
        generalLeft->addRow(QStringLiteral("句柄"), m_handleLabel);
        generalLeft->addRow(QStringLiteral("父句柄"), m_parentHandleLabel);
        generalRight->addRow(QStringLiteral("实例句柄"), m_instanceLabel);
        generalRight->addRow(QStringLiteral("所有者句柄"), m_ownerHandleLabel);
        generalRight->addRow(QStringLiteral("状态摘要"), m_stateLabel);
        generalRight->addRow(QStringLiteral("关系摘要"), m_relationLabel);
        basicLayout->addWidget(generalGroup);

        // 位置/状态两列沿用原成员控件，窄窗自动纵排并让字段标签换行。
        QWidget* layoutStateGroup = ks::ui::CreateDetailCard(QStringLiteral("位置与状态"), basicContent);
        QFormLayout* positionLayout = nullptr;
        QFormLayout* stateLayout = nullptr;
        ks::ui::AddDetailFieldColumns(layoutStateGroup, positionLayout, stateLayout);
        QWidget* positionPanel = positionLayout->parentWidget();
        QWidget* statePanel = stateLayout->parentWidget();
        m_xSpin = new QSpinBox(positionPanel);
        m_ySpin = new QSpinBox(positionPanel);
        m_widthSpin = new QSpinBox(positionPanel);
        m_heightSpin = new QSpinBox(positionPanel);
        for (QSpinBox* spinBox : { m_xSpin, m_ySpin, m_widthSpin, m_heightSpin })
        {
            spinBox->setRange(-32768, 32768);
            spinBox->setReadOnly(true);
            spinBox->setButtonSymbols(QAbstractSpinBox::NoButtons);
            spinBox->setMinimumHeight(fieldHeight);
            spinBox->setMinimumWidth(0);
        }
        m_widthSpin->setRange(1, 32768);
        m_heightSpin->setRange(1, 32768);
        QPushButton* centerScreenButton = new QPushButton(QIcon(":/Icon/process_tree.svg"), QStringLiteral("居中到屏幕"), positionPanel);
        centerScreenButton->setToolTip(QStringLiteral("把窗口移动到主屏幕中央"));
        ks::ui::ApplyFlatButtonTheme(centerScreenButton, ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
        ks::ui::NormalizeToolbarControl(centerScreenButton);
        positionLayout->addRow(QStringLiteral("X"), m_xSpin);
        positionLayout->addRow(QStringLiteral("Y"), m_ySpin);
        positionLayout->addRow(QStringLiteral("宽度"), m_widthSpin);
        positionLayout->addRow(QStringLiteral("高度"), m_heightSpin);
        positionLayout->addRow(centerScreenButton);

        m_topMostCheck = new QCheckBox(QStringLiteral("置顶窗口"), statePanel);
        m_alphaSlider = new ks::ui::ThemedSlider(Qt::Horizontal, statePanel);
        m_alphaSlider->setRange(0, 255);
        m_alphaSpin = new QSpinBox(statePanel);
        m_alphaSpin->setRange(0, 255);
        m_alphaSpin->setMinimumHeight(fieldHeight);
        ks::i18n::LanguageManager::instance().bindToolTip(m_topMostCheck,
            QStringLiteral("window.detail.topmost.hint"),
            QStringLiteral("切换置顶状态后点击“应用修改”生效。"));
        for (QWidget* control : {static_cast<QWidget*>(m_alphaSlider), static_cast<QWidget*>(m_alphaSpin)})
        {
            ks::i18n::LanguageManager::instance().bindToolTip(control,
                QStringLiteral("window.detail.alpha.hint"),
                QStringLiteral("调整后点击“应用修改”生效；透明度会自动启用分层窗口。"));
        }
        m_topMostCheck->setMinimumHeight(fieldHeight);
        m_alphaSlider->setMinimumHeight(fieldHeight);
        stateLayout->addRow(QStringLiteral("置顶"), m_topMostCheck);
        stateLayout->addRow(QStringLiteral("透明度"), m_alphaSlider);
        stateLayout->addRow(QStringLiteral("当前 Alpha"), m_alphaSpin);

        basicLayout->addWidget(layoutStateGroup, 0);

        // 复选框与报告各占完整宽度，避免代码编辑器工具栏挤占样式列表。
        // 样式编辑作为独立页，复选框页和结构化报告分别滚动，避免基础页再包一层滚动区。
        QWidget* stylePage = new QWidget(m_tabWidget);
        auto* stylePageLayout = new QVBoxLayout(stylePage);
        stylePageLayout->setContentsMargins(16, 16, 16, 16);
        QWidget* styleGroup = ks::ui::CreateDetailCard(QStringLiteral("样式与外观"), stylePage);
        styleGroup->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        QVBoxLayout* styleLayout = qobject_cast<QVBoxLayout*>(styleGroup->layout());
        stylePageLayout->addWidget(styleGroup, 1);

        QHBoxLayout* styleActionLayout = new QHBoxLayout();
        QLabel* styleHintLabel = new QLabel(QStringLiteral("勾选样式位后点击应用"), styleGroup);
        styleHintLabel->setWordWrap(true);
        styleHintLabel->setToolTip(QStringLiteral("通过复选框直接调整 GWL_STYLE / GWL_EXSTYLE。"));
        m_styleRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), styleGroup);
        m_styleApplyButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), styleGroup);
        m_styleRefreshButton->setToolTip(QStringLiteral("刷新窗口样式位"));
        m_styleApplyButton->setToolTip(QStringLiteral("应用当前样式位勾选状态"));
        m_styleRefreshButton->setStyleSheet(blueButtonStyle());
        m_styleApplyButton->setStyleSheet(blueButtonStyle());
        ks::ui::ApplyFlatButtonTheme(m_styleApplyButton, ks::ui::FlatButtonTone::Accent);
        KswordTheme::ApplyCompactIconButtonMetrics(m_styleRefreshButton);
        KswordTheme::ApplyCompactIconButtonMetrics(m_styleApplyButton);
        styleActionLayout->addWidget(styleHintLabel, 1);
        styleActionLayout->addWidget(m_styleRefreshButton, 0);
        styleActionLayout->addWidget(m_styleApplyButton, 0);
        styleLayout->addLayout(styleActionLayout);
        ks::ui::NormalizeToolbarRow(styleActionLayout);

        auto* styleTabs = new QTabWidget(styleGroup);
        ks::ui::StylePageTabs(styleTabs);
        styleTabs->setUsesScrollButtons(true);
        const auto createStylePage = [styleTabs]() {
            auto* page = new QWidget(styleTabs);
            QWidget* content = ks::ui::EnablePageInnerScroll(page);
            auto* layout = new QVBoxLayout(content);
            layout->setContentsMargins(0, 8, 0, 0);
            return std::make_pair(page, layout);
        };
        const auto normalStylePage = createStylePage();
        appendStyleCheckBoxGroup(
            normalStylePage.second->parentWidget(),
            normalStylePage.second,
            QStringLiteral("窗口样式（GWL_STYLE）"),
            windowStyleFlagDefinitionList(),
            &m_styleCheckBindingList);
        normalStylePage.second->addStretch(1);
        styleTabs->addTab(normalStylePage.first, QStringLiteral("窗口样式"));
        ks::i18n::LanguageManager::instance().bindTab(styleTabs, normalStylePage.first,
            QStringLiteral("window.detail.style.normal"), QStringLiteral("窗口样式"));
        const auto extendedStylePage = createStylePage();
        appendStyleCheckBoxGroup(
            extendedStylePage.second->parentWidget(),
            extendedStylePage.second,
            QStringLiteral("扩展样式（GWL_EXSTYLE）"),
            windowExStyleFlagDefinitionList(),
            &m_exStyleCheckBindingList);
        extendedStylePage.second->addStretch(1);
        styleTabs->addTab(extendedStylePage.first, QStringLiteral("扩展样式"));
        ks::i18n::LanguageManager::instance().bindTab(styleTabs, extendedStylePage.first,
            QStringLiteral("window.detail.style.extended"), QStringLiteral("扩展样式"));

        m_styleText = new ks::ui::StructuredFieldView(styleTabs);

        m_styleText->setToolTip(QStringLiteral("显示实时样式值与每个位的解释状态。"));
        ks::ui::IsolateMinimumSize(m_styleText);
        QWidget* styleSummaryPage = ks::ui::CreateDetailFieldProjection(m_styleText, styleTabs);
        styleTabs->addTab(styleSummaryPage, QStringLiteral("样式明细"));
        ks::i18n::LanguageManager::instance().bindTab(styleTabs, styleSummaryPage,
            QStringLiteral("window.detail.style.summary"), QStringLiteral("样式明细"));
        styleLayout->addWidget(styleTabs, 1);
        basicLayout->addStretch(1);

        connect(centerScreenButton, &QPushButton::clicked, this, [this]() {
            QScreen* screen = QGuiApplication::primaryScreen();
            if (screen == nullptr)
            {
                return;
            }
            const QRect screenRect = screen->availableGeometry();
            const int targetX = screenRect.x() + (screenRect.width() - m_widthSpin->value()) / 2;
            const int targetY = screenRect.y() + (screenRect.height() - m_heightSpin->value()) / 2;
            m_xSpin->setValue(targetX);
            m_ySpin->setValue(targetY);
        });
        connect(m_topMostCheck, &QCheckBox::toggled, this, [this](bool checked) {
            setExtendedStyleFlag(WS_EX_TOPMOST, checked);
            markAppearanceChangesPending();
        });
        connect(m_alphaSlider, &QSlider::valueChanged, this, &WindowDetailDialog::setPendingAlpha);
        connect(m_alphaSpin, &QSpinBox::valueChanged, this, &WindowDetailDialog::setPendingAlpha);
        connect(m_styleRefreshButton, &QPushButton::clicked, this, [this]() {
            refreshRuntimeInfo();
        });
        connect(m_styleApplyButton, &QPushButton::clicked, this, [this]() {
            applyStyleCheckBoxChanges(true);
        });
        m_tabWidget->addTab(basicPage, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("基础属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, basicPage, QStringLiteral("window.detail.tab.basic"), QStringLiteral("基础属性"));

        // ==================== 2. 进程线程 Tab ====================
        QWidget* processPage = new QWidget(m_tabWidget);
        QVBoxLayout* processLayout = new QVBoxLayout(processPage);
        processLayout->setContentsMargins(8, 8, 8, 8);
        processLayout->setSpacing(6);
        m_processThreadText = new ks::ui::StructuredFieldView(processPage);
        m_runtimePageMasks.insert(processPage, RuntimeProcess);

        processLayout->addWidget(ks::ui::CreateDetailFieldProjection(m_processThreadText, processLayout->parentWidget()), 1);
        m_tabWidget->addTab(processPage, QIcon(QStringLiteral(":/Icon/process_threads.svg")), QStringLiteral("进程与线程"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, processPage, QStringLiteral("window.detail.tab.process"), QStringLiteral("进程与线程"));

        // ==================== 3. 类信息 Tab ====================
        QWidget* classPage = new QWidget(m_tabWidget);
        QVBoxLayout* classLayout = new QVBoxLayout(classPage);
        classLayout->setContentsMargins(8, 8, 8, 8);
        classLayout->setSpacing(6);
        m_classText = new ks::ui::StructuredFieldView(classPage);
        m_runtimePageMasks.insert(classPage, RuntimeClass);

        classLayout->addWidget(ks::ui::CreateDetailFieldProjection(m_classText, classLayout->parentWidget()), 1);
        m_tabWidget->addTab(classPage, QIcon(QStringLiteral(":/Icon/knowledge_book.svg")), QStringLiteral("类信息"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, classPage, QStringLiteral("window.detail.tab.class"), QStringLiteral("类信息"));

        auto* inspectionPage = ks::control_inspection::CreatePage(toHwnd(m_info.hwndValue),
            m_info.processId, m_info.threadId, m_info.processCreationTime100ns, m_tabWidget);
        m_tabWidget->addTab(inspectionPage, QIcon(QStringLiteral(":/Icon/window_picker_aim.svg")), QStringLiteral("控件检查"));
        ks::i18n::LanguageManager::instance().bindTab(m_tabWidget, inspectionPage,
            QStringLiteral("window.detail.tab.control_inspection"), QStringLiteral("控件检查"));

        // ==================== 4. 消息钩子 Tab ====================
        QWidget* hookPage = new QWidget(m_tabWidget);
        QVBoxLayout* hookLayout = new QVBoxLayout(hookPage);
        hookLayout->setContentsMargins(8, 8, 8, 8);
        hookLayout->setSpacing(6);

        // 概览文本：保留原有消息队列状态、焦点等摘要，便于快速判断窗口活性。
        m_hookText = new ks::ui::StructuredFieldView(hookPage);
        m_runtimePageMasks.insert(hookPage, RuntimeHooks);

        auto* hookSplitter = new QSplitter(Qt::Vertical, hookPage);
        hookSplitter->setChildrenCollapsible(false);
        hookSplitter->addWidget(ks::ui::CreateDetailFieldProjection(m_hookText, hookSplitter));

        // 控制条：开始/停止/清空/自动滚动/最大行数，风格对齐其他按钮。
        QHBoxLayout* monitorControlLayout = new QHBoxLayout();
        m_messageStartButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), hookPage);
        m_messageStopButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), hookPage);
        m_messageClearButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), hookPage);
        m_messageStartButton->setToolTip(QStringLiteral("开始消息监控"));
        m_messageStopButton->setToolTip(QStringLiteral("停止消息监控"));
        m_messageClearButton->setToolTip(QStringLiteral("清空当前消息列表"));
        m_messageStopButton->setEnabled(false);
        for (QPushButton* controlButton : { m_messageStartButton, m_messageStopButton, m_messageClearButton })
        {
            controlButton->setStyleSheet(blueButtonStyle());
            controlButton->setFixedWidth(34);
            monitorControlLayout->addWidget(controlButton);
        }

        m_messageAutoScrollCheck = new QCheckBox(QStringLiteral("自动滚动到底部"), hookPage);
        m_messageAutoScrollCheck->setChecked(true);
        monitorControlLayout->addWidget(m_messageAutoScrollCheck, 0);

        monitorControlLayout->addWidget(new QLabel(QStringLiteral("最大保留行数"), hookPage), 0);
        m_messageMaxRowsSpin = new QSpinBox(hookPage);
        m_messageMaxRowsSpin->setRange(200, 50000);
        m_messageMaxRowsSpin->setValue(5000);
        m_messageMaxRowsSpin->setStyleSheet(blueInputStyle());
        connect(m_messageMaxRowsSpin, &QSpinBox::valueChanged, this, [this](int limit) {
            std::lock_guard<std::mutex> lock(m_messageArchive->mutex);
            m_messageArchive->limit = static_cast<size_t>(limit);
            while (m_messageArchive->rows.size() > m_messageArchive->limit)
            {
                m_messageArchive->rows.pop_front();
                ++m_messageArchive->dropped;
            }
            ++m_messageArchive->revision;
        });
        monitorControlLayout->addWidget(m_messageMaxRowsSpin, 0);

        m_messageModeLabel = new QLabel(QStringLiteral("采集模式：未启动"), hookPage);
        m_messageCountLabel = new QLabel(QStringLiteral("已记录: 0, 丢弃: 0"), hookPage);
        monitorControlLayout->addStretch(1);
        hookLayout->addLayout(monitorControlLayout);
        ks::ui::NormalizeToolbarRow(monitorControlLayout);

        // 状态说明使用独立可换行行，不能和输入/启停动作一起撑宽消息工具条。
        auto* monitorStatusLayout = new QHBoxLayout();
        monitorStatusLayout->setSpacing(16);
        for (QLabel* status : {m_messageModeLabel, m_messageCountLabel})
        {
            status->setWordWrap(true);
            status->setMinimumWidth(0);
            status->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            monitorStatusLayout->addWidget(status, 1);
        }
        hookLayout->addLayout(monitorStatusLayout);

        // 消息表：按行展示捕获数据，接近 Spy++ 的消息流视角。
        m_messageTable = new ks::ui::TableActionTableView(hookPage);
        m_messageModel = new WindowMessageModel(m_messageTable);
        m_messageDisplayModel = new QSortFilterProxyModel(m_messageTable);
        m_messageDisplayModel->setSortRole(Qt::DisplayRole);
        m_messageDisplayModel->setSortCaseSensitivity(Qt::CaseSensitive);
        m_messageDisplayModel->setSortLocaleAware(true);
        m_messageDisplayModel->setDynamicSortFilter(false);
        m_messageDisplayModel->setSourceModel(m_messageModel);
        m_messageTable->setProperty("ks_i18n_preserve_model_data", true);
        // 消息流的顺序由采集器记录，已有启停/清理动作；保留复制导出而非通用快照对比。
        ks::ui::SetTableActionBarMode(m_messageTable, ks::ui::TableActionBarMode::Compact);
        m_messageModel->headers = QStringList{
            QStringLiteral("时间"),
            QStringLiteral("通道"),
            QStringLiteral("HWND"),
            QStringLiteral("消息ID"),
            QStringLiteral("消息名"),
            QStringLiteral("WPARAM"),
            QStringLiteral("LPARAM"),
            QStringLiteral("结果/附加")
        };
        ks::ui::ResultTableCapabilities messageCapabilities;
        messageCapabilities.actionBar = ks::ui::TableActionBarMode::Compact;
        messageCapabilities.headerClickSorting = true;
        ks::ui::ResultTableHost::ensure(m_messageTable)->bindModel(m_messageDisplayModel,
            {{0, QStringLiteral("time")}, {1, QStringLiteral("channel")}, {2, QStringLiteral("hwnd")},
             {3, QStringLiteral("message_id")}, {4, QStringLiteral("message_name")}, {5, QStringLiteral("wparam")},
             {6, QStringLiteral("lparam")}, {7, QStringLiteral("result")}}, messageCapabilities);
        ks::ui::InstallTableHeaderClickSorting(m_messageTable);
        m_messageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_messageTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_messageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_messageTable->setAlternatingRowColors(true);
        m_messageTable->setSortingEnabled(false);
        m_messageTable->verticalHeader()->setVisible(false);
        m_messageTable->horizontalHeader()->setStretchLastSection(true);
        m_messageTable->setContextMenuPolicy(Qt::CustomContextMenu);
        hookSplitter->addWidget(m_messageTable);
        hookSplitter->setStretchFactor(0, 1);
        hookSplitter->setStretchFactor(1, 3);
        hookLayout->addWidget(hookSplitter, 1);

        // 表格右键：支持复制整行，方便与日志或抓包结果做对比分析。
        connect(m_messageTable, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
            if (m_messageTable == nullptr)
            {
                return;
            }
            QMenu menu;
            // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制选中行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            QAction* selectedAction = menu.exec(m_messageTable->viewport()->mapToGlobal(pos));
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QStringList rowTexts;
            const auto rows = m_messageTable->selectionModel()->selectedRows();
            for (const auto& index : rows)
            {
                QStringList singleRow;
                for (int col = 0; col < m_messageModel->columnCount(); ++col)
                    singleRow << index.siblingAtColumn(col).data().toString();
                rowTexts << singleRow.join('\t');
            }
            if (!rowTexts.isEmpty())
            {
                QApplication::clipboard()->setText(rowTexts.join('\n'));
            }
        });

        // 监控控制绑定：开始/停止/清空动作。
        connect(m_messageStartButton, &QPushButton::clicked, this, [this]() {
            m_runtimeMonitorInitialDone = true;
            startMessageMonitor();
        });
        connect(m_messageStopButton, &QPushButton::clicked, this, [this]() {
            m_runtimeMonitorInitialDone = true;
            stopMessageMonitor();
        });
        connect(m_messageClearButton, &QPushButton::clicked, this, [this]() {
            clearMessageTable();
        });

        m_tabWidget->addTab(hookPage, QIcon(QStringLiteral(":/Icon/process_main.svg")), QStringLiteral("消息钩子"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, hookPage, QStringLiteral("window.detail.tab.hooks"), QStringLiteral("消息钩子"));

        // ==================== 5. 高级属性 Tab ====================
        QWidget* advancedPage = new QWidget(m_tabWidget);
        QVBoxLayout* advancedLayout = new QVBoxLayout(advancedPage);
        advancedLayout->setContentsMargins(8, 8, 8, 8);
        advancedLayout->setSpacing(6);
        m_advancedText = new ks::ui::StructuredFieldView(advancedPage);
        m_runtimePageMasks.insert(advancedPage, RuntimeAdvanced);

        advancedLayout->addWidget(ks::ui::CreateDetailFieldProjection(m_advancedText, advancedLayout->parentWidget()), 1);
        m_tabWidget->addTab(advancedPage, QIcon(QStringLiteral(":/Icon/process_settings.svg")), QStringLiteral("高级属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, advancedPage, QStringLiteral("window.detail.tab.advanced"), QStringLiteral("高级属性"));

        const ks::dwm_order::WindowIdentity inputIdentity{m_info.hwndValue,
            m_info.processId, m_info.threadId, m_info.processCreationTime100ns};
        auto* inputPage = ks::window_input::CreateControl(inputIdentity, m_tabWidget);
        inputPage->setObjectName(QStringLiteral("ks_window_input_page"));
        m_tabWidget->addTab(inputPage, QIcon(QStringLiteral(":/Icon/process_hotkey.svg")), QStringLiteral("窗口输入与顺序"));
        ks::i18n::LanguageManager::instance().bindTab(m_tabWidget, inputPage,
            QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));

        // 样式页追加到旧入口之后，原消息/输入/高级索引保持。
        m_tabWidget->addTab(stylePage, QIcon(QStringLiteral(":/Icon/process_settings.svg")), QStringLiteral("样式与外观"));

        // 对象动作置于全宽摘要右侧；窗口内容拥有自己的滚动而动作始终可见。
        QWidget* footer = new QWidget(summaryHeader);
        QHBoxLayout* buttonLayout = new QHBoxLayout(footer);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        qobject_cast<QHBoxLayout*>(summaryHeader->layout())->addWidget(footer);
        m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
        m_applyButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), this);
        m_exportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), this);
        m_closeButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), this);
        auto& language = ks::i18n::LanguageManager::instance();
        language.bindToolTip(m_refreshButton, QStringLiteral("window.detail.action.refresh"), QStringLiteral("刷新"));
        language.bindText(m_applyButton, QStringLiteral("window.detail.action.apply"), QStringLiteral("应用修改"));
        language.bindToolTip(m_exportButton, QStringLiteral("window.detail.action.export"), QStringLiteral("导出信息"));
        language.bindToolTip(m_closeButton, QStringLiteral("window.detail.action.close"), QStringLiteral("关闭"));

        m_refreshButton->setToolTip(QStringLiteral("刷新窗口属性"));
        m_applyButton->setToolTip(QStringLiteral("应用修改"));
        m_applyButton->setEnabled(false);
        m_exportButton->setToolTip(QStringLiteral("导出信息"));
        m_closeButton->setToolTip(QStringLiteral("关闭详情窗口"));

        for (QPushButton* button : { m_refreshButton, m_applyButton, m_exportButton, m_closeButton })
        {
            ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
                ks::ui::FlatButtonAppearance::Solid);
            button->setMinimumHeight(32);
            button->setIconSize(KswordTheme::StandardIconSize());
            buttonLayout->addWidget(button, 0);
        }
        ks::ui::NormalizeToolbarRow(buttonLayout);

        connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
            refreshRuntimeInfo();
        });
        connect(m_applyButton, &QPushButton::clicked, this, [this]() {
            applyChanges();
        });
        connect(m_exportButton, &QPushButton::clicked, this, [this]() {
            exportInfo();
        });
        connect(m_closeButton, &QPushButton::clicked, this, &QDialog::close);
        // 明确登记同一个共享详情框架，扩展页加入后继续使用统一表单和主题规则。
        ks::ui::InstallDetailWindowFramework(this);
    }

    enum : unsigned { RuntimeProcess = 1, RuntimeClass = 2, RuntimeHooks = 4, RuntimeAdvanced = 8, RuntimeAll = 15 };
    struct RuntimeRequest
    {
        OtherDock::WindowInfo info;
        unsigned mask = 0;
        DWORD queueStatus = 0; // caller GUI queue status; not the pool thread queue
        quint64 editRevision = 0;
    };
    struct RuntimeSnapshot
    {
        OtherDock::WindowInfo info;
        unsigned mask = 0;
        quint64 editRevision = 0, instance = 0;
        bool valid = false, native = true;
        QString failure;
        ks::ui::FieldDocument style, process, classInfo, hooks, advanced;
    };
    static ks::ui::FieldDocument runtimeStyleDocument(quint64 style, quint64 extended)
    {
        ks::ui::FieldDocument document;
        document.field(QStringLiteral("Style"), QStringLiteral("0x%1").arg(style, 0, 16));
        document.field(QStringLiteral("ExStyle"), QStringLiteral("0x%1").arg(extended, 0, 16));
        document.section(QStringLiteral("窗口样式 WS_*"));
        for (const auto& value : windowStyleFlagDefinitionList())
            document.field(QString::fromLatin1(value.styleNameText), boolText((style & value.styleMaskValue) != 0));
        document.section(QStringLiteral("扩展样式 WS_EX_*"));
        for (const auto& value : windowExStyleFlagDefinitionList())
            document.field(QString::fromLatin1(value.styleNameText), boolText((extended & value.styleMaskValue) != 0));
        return document;
    }
    static std::shared_ptr<const RuntimeSnapshot> collectRuntime(const RuntimeRequest& request,
        const ks::ui::AsyncOperationToken& token)
    {
        auto snapshot = makeWindowBackgroundValue<RuntimeSnapshot>();
        auto& result = *snapshot;
        result.info = request.info;
        result.mask = request.mask;
        result.editRevision = request.editRevision;
        HWND windowHandle = toHwnd(request.info.hwndValue);
        if (!ks::window::windowIdentityMatches(request.info.hwndValue, request.info.processId,
            request.info.threadId, request.info.processCreationTime100ns))
        {
            result.failure = QStringLiteral("目标窗口身份已变化或无法验证");
            return snapshot;
        }
        result.info.parentHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle)));
        result.info.ownerHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)));
        result.instance = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE));
        result.info.visible = ::IsWindowVisible(windowHandle) != FALSE;
        result.info.enabled = ::IsWindowEnabled(windowHandle) != FALSE;
        result.info.minimized = ::IsIconic(windowHandle) != FALSE;
        result.info.maximized = ::IsZoomed(windowHandle) != FALSE;
        result.info.styleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        result.info.exStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));
        RECT rect{};
        const bool windowRectReady = ::GetWindowRect(windowHandle, &rect) != FALSE;
        result.info.windowRect = windowRectReady ? QRect(rect.left, rect.top, std::max<int>(1, rect.right - rect.left), std::max<int>(1, rect.bottom - rect.top)) : QRect(0, 0, 1, 1);
        result.info.alphaValue = 255;
        if ((result.info.exStyleValue & WS_EX_LAYERED) != 0)
        {
            COLORREF key = 0; BYTE alpha = 255; DWORD flags = 0;
            if (::GetLayeredWindowAttributes(windowHandle, &key, &alpha, &flags) && (flags & LWA_ALPHA)) result.info.alphaValue = alpha;
        }
        result.style = runtimeStyleDocument(result.info.styleValue, result.info.exStyleValue);
        if ((request.mask & 1) != 0 && !token.isCanceled())
        {
        // 进程线程信息：补齐路径、优先级、句柄计数、启动时间和模块摘要，便于排障和行为审计。
        ks::ui::FieldDocument processText;
        processText.field(QStringLiteral("PID"), QStringLiteral("%1").arg(request.info.processId));
        processText.field(QStringLiteral("ProcessName"), QStringLiteral("%1").arg(request.info.processNameText));
        processText.field(QStringLiteral("TID"), QStringLiteral("%1").arg(request.info.threadId));
        if (windowRectReady)
        {
            processText.field(QStringLiteral("WindowRect"), QStringLiteral("[%1,%2,%3,%4]").arg(QStringLiteral("%1").arg(rect.left)).arg(QStringLiteral("%1").arg(rect.top)).arg(QStringLiteral("%1").arg(rect.right)).arg(QStringLiteral("%1").arg(rect.bottom)));
        }
        else
        {
            processText.field(QStringLiteral("WindowRect"), QStringLiteral("<N/A>"), true);
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            request.info.processId);
        if (processHandle != nullptr)
        {
            wchar_t processPathBuffer[MAX_PATH * 2] = {};
            DWORD processPathLength = static_cast<DWORD>(std::size(processPathBuffer));
            if (::QueryFullProcessImageNameW(processHandle, 0, processPathBuffer, &processPathLength) != FALSE)
            {
                processText.field(QStringLiteral("ProcessPath"), QStringLiteral("%1").arg(QString::fromWCharArray(processPathBuffer, static_cast<int>(processPathLength))));
            }

            const DWORD processPriority = ::GetPriorityClass(processHandle);
            processText.field(QStringLiteral("ProcessPriorityClass"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(processPriority), 0, 16)));

            DWORD handleCount = 0;
            if (::GetProcessHandleCount(processHandle, &handleCount) != FALSE)
            {
                processText.field(QStringLiteral("ProcessHandleCount"), QStringLiteral("%1").arg(handleCount));
            }

            FILETIME createTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                processText.field(QStringLiteral("StartTime"), QStringLiteral("%1").arg(fileTimeToLocalText(createTime)));
                const qulonglong cpuTotal = fileTimeToUInt64(kernelTime) + fileTimeToUInt64(userTime);
                processText.field(QStringLiteral("CPUTime(Kernel+User)"), QStringLiteral("%1").arg(formatDurationFrom100ns(cpuTotal)));

                FILETIME nowFileTime{};
                ::GetSystemTimeAsFileTime(&nowFileTime);
                const qulonglong nowTick = fileTimeToUInt64(nowFileTime);
                const qulonglong startTick = fileTimeToUInt64(createTime);
                if (nowTick > startTick)
                {
                    processText.field(QStringLiteral("RunTime"), QStringLiteral("%1").arg(formatDurationFrom100ns(nowTick - startTick)));
                }
            }

            ::CloseHandle(processHandle);
        }
        else
        {
            processText.field(QStringLiteral("ProcessOpen"), QStringLiteral("失败（权限不足或进程已退出）"), true);
        }

        int moduleCount = 0;
        const ks::ui::FieldDocument moduleSummary = buildModuleSummaryDocument(request.info.processId, 8, &moduleCount, [&token] { return token.isCanceled(); });
        processText.field(QStringLiteral("ModuleCount"), QStringLiteral("%1").arg(moduleCount));
        processText.section(QStringLiteral("ModulePreview"));
        processText.nodes += moduleSummary.nodes;

        HANDLE threadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, request.info.threadId);
        if (threadHandle != nullptr)
        {
            const int threadPriority = ::GetThreadPriority(threadHandle);
            processText.field(QStringLiteral("ThreadPriority"), QStringLiteral("%1").arg(threadPriority));

            BOOL priorityBoostDisabled = FALSE;
            if (::GetThreadPriorityBoost(threadHandle, &priorityBoostDisabled) != FALSE)
            {
                processText.field(QStringLiteral("ThreadPriorityBoostDisabled"), QStringLiteral("%1").arg(boolText(priorityBoostDisabled != FALSE)));
            }
            ::CloseHandle(threadHandle);
        }
        else
        {
            processText.field(QStringLiteral("ThreadOpen"), QStringLiteral("失败（线程可能已退出）"), true);
        }
        processText.field(QStringLiteral("提示"), QStringLiteral("可从右键菜单跳转到进程详细信息页。"), true);
        result.process = std::move(processText);

        }
        if ((request.mask & 2) != 0 && !token.isCanceled())
        {
        // 类信息：展示类名、类样式、窗口过程地址以及类资源句柄。
        ks::ui::FieldDocument classText;
        classText.field(QStringLiteral("ClassName"), QStringLiteral("%1").arg(request.info.classNameText));
        classText.field(QStringLiteral("ClassAtom"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCW_ATOM)), 0, 16)));
        classText.field(QStringLiteral("ClassStyle"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCL_STYLE)), 0, 16)));
        classText.field(QStringLiteral("ClassExtraBytes"), QStringLiteral("%1").arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBCLSEXTRA))));
        classText.field(QStringLiteral("WindowExtraBytes"), QStringLiteral("%1").arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBWNDEXTRA))));
        classText.field(QStringLiteral("WndProc"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16)));
        classText.field(QStringLiteral("MenuHandle"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(::GetMenu(windowHandle))), 0, 16)));
        classText.field(QStringLiteral("ClassHCursor"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HCURSOR)), 0, 16)));
        classText.field(QStringLiteral("ClassHIcon"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICON)), 0, 16)));
        classText.field(QStringLiteral("ClassHIconSm"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICONSM)), 0, 16)));
        classText.field(QStringLiteral("ClassHbrBackground"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HBRBACKGROUND)), 0, 16)));

        const HMODULE classModuleHandle = reinterpret_cast<HMODULE>(::GetClassLongPtrW(windowHandle, GCLP_HMODULE));
        classText.field(QStringLiteral("ClassModule"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(classModuleHandle)), 0, 16)));
        if (classModuleHandle != nullptr)
        {
            wchar_t modulePathBuffer[MAX_PATH * 2] = {};
            const DWORD pathLength = ::GetModuleFileNameW(
                classModuleHandle,
                modulePathBuffer,
                static_cast<DWORD>(std::size(modulePathBuffer)));
            if (pathLength > 0)
            {
                classText.field(QStringLiteral("ClassModulePath"), QStringLiteral("%1").arg(QString::fromWCharArray(modulePathBuffer, static_cast<int>(pathLength))));
            }
        }
        result.classInfo = std::move(classText);

        }
        if ((request.mask & 4) != 0 && !token.isCanceled())
        {
        // 钩子/消息页：补齐消息队列状态与 GUI 线程焦点句柄，替代原先占位文本。
        int childWindowCount = 0;
        ::EnumChildWindows(
            windowHandle,
            [](HWND, LPARAM lParam) -> BOOL {
                int* countPtr = reinterpret_cast<int*>(lParam);
                if (countPtr != nullptr)
                {
                    *countPtr += 1;
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&childWindowCount));

        int siblingCount = 0;
        const HWND parentWindowHandle = ::GetParent(windowHandle);
        if (parentWindowHandle != nullptr)
        {
            std::pair<HWND, int*> siblingContext{ windowHandle, &siblingCount };
            ::EnumChildWindows(
                parentWindowHandle,
                [](HWND childHandle, LPARAM lParam) -> BOOL {
                    auto* pairPtr = reinterpret_cast<std::pair<HWND, int*>*>(lParam);
                    if (pairPtr == nullptr || pairPtr->second == nullptr)
                    {
                        return TRUE;
                    }
                    if (childHandle != pairPtr->first)
                    {
                        *(pairPtr->second) += 1;
                    }
                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&siblingContext));
        }

        GUITHREADINFO guiThreadInfo{};
        guiThreadInfo.cbSize = sizeof(guiThreadInfo);
        const bool guiInfoReady = (::GetGUIThreadInfo(request.info.threadId, &guiThreadInfo) != FALSE);

        const DWORD queueStatus = request.queueStatus;
        ks::ui::FieldDocument hookText;
        hookText.field(QStringLiteral("IsHungAppWindow"), QStringLiteral("%1").arg(boolText(::IsHungAppWindow(windowHandle) != FALSE)));
        hookText.field(QStringLiteral("ChildWindowCount"), QStringLiteral("%1").arg(childWindowCount));
        hookText.field(QStringLiteral("SiblingWindowCount"), QStringLiteral("%1").arg(siblingCount));
        hookText.field(QStringLiteral("Visible"), QStringLiteral("%1").arg(boolText(::IsWindowVisible(windowHandle) != FALSE)));
        hookText.field(QStringLiteral("Enabled"), QStringLiteral("%1").arg(boolText(::IsWindowEnabled(windowHandle) != FALSE)));
        hookText.field(QStringLiteral("QueueStatusRaw"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(queueStatus), 0, 16)));
        hookText.field(QStringLiteral("QueueCurrentFlags(LOWORD)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<unsigned int>(LOWORD(queueStatus)), 0, 16)));
        hookText.field(QStringLiteral("QueueNewFlags(HIWORD)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<unsigned int>(HIWORD(queueStatus)), 0, 16)));
        hookText.field(QStringLiteral("GUIThreadInfoReady"), QStringLiteral("%1").arg(boolText(guiInfoReady)));
        if (guiInfoReady)
        {
            hookText.field(QStringLiteral("Focus"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndFocus)))));
            hookText.field(QStringLiteral("Active"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndActive)))));
            hookText.field(QStringLiteral("Capture"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCapture)))));
            hookText.field(QStringLiteral("Caret"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCaret)))));
            hookText.field(QStringLiteral("MenuOwner"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndMenuOwner)))));
        }
        hookText.field(QStringLiteral("ForegroundWindow"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetForegroundWindow())))));
        hookText.field(QStringLiteral("说明"), QStringLiteral("系统级 Hook 链表不提供官方通用枚举接口，当前页聚焦可稳定获取的消息上下文。"), true);
        result.hooks = std::move(hookText);

        }
        if ((request.mask & 8) != 0 && !token.isCanceled())
        {
        // 高级页：补齐 DPI、属性表（GetProp/EnumPropsExW）与窗口额外字节等关键内容。
        ks::ui::FieldDocument advancedText;
        advancedText.field(QStringLiteral("UserData (GWLP_USERDATA)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_USERDATA)), 0, 16)));
        advancedText.field(QStringLiteral("ID (GWLP_ID)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_ID)), 0, 16)));
        advancedText.field(QStringLiteral("WndProc (GWLP_WNDPROC)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16)));
        advancedText.field(QStringLiteral("HINSTANCE (GWLP_HINSTANCE)"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE)), 0, 16)));
        advancedText.field(QStringLiteral("Parent"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle))))));
        advancedText.field(QStringLiteral("Owner"), QStringLiteral("%1").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER))))));

        DWORD displayAffinity = 0;
        if (::GetWindowDisplayAffinity(windowHandle, &displayAffinity) != FALSE)
        {
            advancedText.field(QStringLiteral("DisplayAffinity"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(displayAffinity), 0, 16)));
        }

        RECT clientRect{};
        if (::GetClientRect(windowHandle, &clientRect) != FALSE)
        {
            advancedText.field(QStringLiteral("ClientRect"), QStringLiteral("[%1,%2,%3,%4]").arg(QStringLiteral("%1").arg(clientRect.left)).arg(QStringLiteral("%1").arg(clientRect.top)).arg(QStringLiteral("%1").arg(clientRect.right)).arg(QStringLiteral("%1").arg(clientRect.bottom)));
        }

        // 兼容旧系统：GetDpiForWindow 仅在新系统提供，运行时动态判断。
        using GetDpiForWindowFunc = UINT(WINAPI*)(HWND);
        const HMODULE user32Handle = ::GetModuleHandleW(L"user32.dll");
        GetDpiForWindowFunc getDpiForWindow = nullptr;
        if (user32Handle != nullptr)
        {
            getDpiForWindow = reinterpret_cast<GetDpiForWindowFunc>(::GetProcAddress(user32Handle, "GetDpiForWindow"));
        }
        if (getDpiForWindow != nullptr)
        {
            advancedText.field(QStringLiteral("DPI"), QStringLiteral("%1").arg(getDpiForWindow(windowHandle)));
        }

        // 枚举窗口属性键值：用于发现子类化框架、输入法、UI库挂载的额外状态。
        QStringList propLines;
        WindowPropEnumContext propContext;
        propContext.lines = &propLines;
        propContext.maxCount = 200;
        ::EnumPropsExW(windowHandle, enumWindowPropProc, reinterpret_cast<LPARAM>(&propContext));
        advancedText.field(QStringLiteral("PropCount"), QStringLiteral("%1").arg(propLines.size()));
        if (!propLines.isEmpty())
        {
            advancedText.section(QStringLiteral("Properties"));
            for (const QString& line : propLines)
            {
                advancedText.field(QStringLiteral(""), QStringLiteral("- %1").arg(QStringLiteral("%1").arg(line)));
            }
        }
        else
        {
            advancedText.field(QStringLiteral("Properties"), QStringLiteral("<none>"), true);
        }
        result.advanced = std::move(advancedText);

        }
        if (!token.isCanceled() && ks::window::windowIdentityMatches(request.info.hwndValue,
            request.info.processId, request.info.threadId, request.info.processCreationTime100ns)) result.valid = true;
        else result.failure = QStringLiteral("目标窗口身份已变化或无法验证");
        return snapshot;
    }
    unsigned currentRuntimeMask() const
    { return m_runtimePageMasks.value(m_tabWidget->currentWidget(), 0); }

    void refreshRuntimeInfo() { requestRuntimeInfo(RuntimeAll, true); }
    void requestRuntimeInfo(unsigned mask, bool force = false)
    {
        if (!m_runtimeOperation) return;
        if (!force && m_runtimeBaseLoaded && (mask & ~m_runtimeLoadedMask) == 0) return;
        m_runtimePendingMask |= mask;
        RuntimeRequest request{m_info, m_runtimePendingMask, 0, m_runtimeEditRevision};
        if (request.mask & RuntimeHooks) request.queueStatus = ::GetQueueStatus(QS_ALLINPUT);
        // QueueStatus is explicitly the original caller queue. Every external
        // target query, module/tree/property walk happens only in the worker.
        const QPointer<WindowDetailDialog> alive(this);
        const auto pending = ks::ui::FieldDocument{}.note(QStringLiteral("读取中…"));
        if ((mask & RuntimeProcess) && !(m_runtimeLoadedMask & RuntimeProcess)) m_processThreadText->setDocument(pending);
        if (!alive) return;
        if ((mask & RuntimeClass) && !(m_runtimeLoadedMask & RuntimeClass)) m_classText->setDocument(pending);
        if (!alive) return;
        if ((mask & RuntimeHooks) && !(m_runtimeLoadedMask & RuntimeHooks)) m_hookText->setDocument(pending);
        if (!alive) return;
        if ((mask & RuntimeAdvanced) && !(m_runtimeLoadedMask & RuntimeAdvanced)) m_advancedText->setDocument(pending);
        if (!alive) return;
        m_runtimeOperation->submit<RuntimeRequest, std::shared_ptr<const RuntimeSnapshot>>(
            std::move(request), collectRuntime,
            [this](const std::shared_ptr<const RuntimeSnapshot>& value, std::uint64_t) {
                const QPointer<WindowDetailDialog> alive(this);
                if (!value->valid)
                {
                    failRuntimeRead(value->mask, value->failure);
                    return true;
                }
                applyRuntimeBase(*value);
                if (!alive) return true;
                if (!m_runtimeMonitorInitialDone)
                {
                    m_runtimeMonitorInitialDone = true;
                    startMessageMonitor();
                    if (!alive) return true;
                }
                if (value->mask & RuntimeProcess) { m_processThreadText->setDocument(value->process); if (!alive) return true; }
                if (value->mask & RuntimeClass) { m_classText->setDocument(value->classInfo); if (!alive) return true; }
                if (value->mask & RuntimeHooks) { m_hookText->setDocument(value->hooks); if (!alive) return true; }
                if (value->mask & RuntimeAdvanced) { m_advancedText->setDocument(value->advanced); if (!alive) return true; }
                m_runtimeLoadedMask |= value->mask;
                m_runtimePendingMask &= ~value->mask;
                m_runtimeBaseLoaded = true;
                if (m_runtimeExportPending && (m_runtimeLoadedMask & RuntimeAll) == RuntimeAll)
                {
                    m_runtimeExportPending = false;
                    m_exportButton->setEnabled(true);
                    exportInfoNow();
                }
                return true;
            }, [this](std::exception_ptr) { failRuntimeRead(m_runtimePendingMask, QStringLiteral("刷新失败")); });
    }
    void failRuntimeRead(unsigned mask, const QString& error)
    {
        const QPointer<WindowDetailDialog> alive(this);
        m_stateLabel->setText(error);
        const auto document = ks::ui::FieldDocument{}.note(error);
        if ((mask & RuntimeProcess) && !(m_runtimeLoadedMask & RuntimeProcess)) { m_processThreadText->setDocument(document); if (!alive) return; }
        if ((mask & RuntimeClass) && !(m_runtimeLoadedMask & RuntimeClass)) { m_classText->setDocument(document); if (!alive) return; }
        if ((mask & RuntimeHooks) && !(m_runtimeLoadedMask & RuntimeHooks)) { m_hookText->setDocument(document); if (!alive) return; }
        if ((mask & RuntimeAdvanced) && !(m_runtimeLoadedMask & RuntimeAdvanced)) { m_advancedText->setDocument(document); if (!alive) return; }
        m_applyButton->setEnabled(false);
        m_styleApplyButton->setEnabled(false);
        m_runtimeExportPending = false;
        m_exportButton->setEnabled(true);
    }
    void applyRuntimeBase(const RuntimeSnapshot& value)
    {
        const QPointer<WindowDetailDialog> alive(this);
        m_handleLabel->setText(hwndToText(value.info.hwndValue));
        m_parentHandleLabel->setText(hwndToText(value.info.parentHwndValue));
        m_ownerHandleLabel->setText(hwndToText(value.info.ownerHwndValue));
        m_classNameLabel->setText(value.info.classNameText);
        m_instanceLabel->setText(value.native ? hwndToText(value.instance) : QStringLiteral("未读取"));
        m_stateLabel->setText(QStringLiteral("可见:%1, 可用:%2, 状态:%3")
            .arg(boolText(value.info.visible), boolText(value.info.enabled), windowStateText(value.valid, value.info.minimized, value.info.maximized)));
        m_relationLabel->setText(QStringLiteral("PID=%1, TID=%2").arg(value.info.processId).arg(value.info.threadId));
        m_styleText->setDocument(value.style);
        if (!alive || value.editRevision != m_runtimeEditRevision) return;
        m_runtimeApplying = true;
        m_titleEdit->setText(value.info.titleText);
        syncStyleCheckBoxes(value.info.styleValue, value.info.exStyleValue);
        m_xSpin->setValue(value.info.windowRect.x());
        m_ySpin->setValue(value.info.windowRect.y());
        m_widthSpin->setValue(std::max(1, value.info.windowRect.width()));
        m_heightSpin->setValue(std::max(1, value.info.windowRect.height()));
        m_topMostCheck->setEnabled(value.valid);
        {
            const QSignalBlocker first(m_alphaSlider), second(m_alphaSpin);
            m_alphaSlider->setValue(value.info.alphaValue);
            m_alphaSpin->setValue(value.info.alphaValue);
        }
        m_alphaSlider->setEnabled(value.valid);
        m_alphaSpin->setEnabled(value.valid);
        m_alphaChanged = false;
        m_applyButton->setEnabled(false);
        m_styleApplyButton->setEnabled(false);
        m_runtimeApplying = false;
    }

    // 清空消息表：重置可视列表与计数器。
    void clearMessageTable()
    {
        if (m_messageSnapshotOperation) m_messageSnapshotOperation->cancel();
        auto retired = makeWindowBackgroundValue<std::deque<std::shared_ptr<const WindowMessageRecord>>>();
        {
            std::lock_guard<std::mutex> lock(m_messageArchive->mutex);
            retired->swap(m_messageArchive->rows);
            m_messageArchive->captured = m_messageArchive->dropped = 0;
            ++m_messageArchive->clearGeneration;
            ++m_messageArchive->revision;
        }
        m_messagePrepared.reset();
        m_messagePublishedRevision = 0;
        const QPointer<WindowDetailDialog> alive(this);
        if (m_messageModel) m_messageModel->publish({});
        if (!alive) return;
        m_capturedMessageCount = m_droppedMessageCount = 0;
        updateMessageMonitorUiState();
    }

    // 启动消息监控：
    // - 同进程窗口优先使用线程消息钩子（WH_CALLWNDPROC/WH_GETMESSAGE/WH_CALLWNDPROCRET）；
    // - 跨进程窗口回退为 WinEvent 事件流（不注入 DLL，稳定但不等价于完整消息队列）。
    void startMessageMonitor()
    {
        if (m_messageMonitorRunning.load())
        {
            return;
        }

        HWND windowHandle = toHwnd(m_info.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("消息监控"), QStringLiteral("目标窗口句柄已失效，无法启动监控。"));
            return;
        }

        m_messagePort = std::make_shared<WindowMessagePort>();
        m_messagePort->archive = m_messageArchive;
        m_messagePort->targetHwnd = m_info.hwndValue;
        bool monitorStarted = false;
        m_messageMonitorMode = QStringLiteral("未启动");
        m_winEventHookSnapshot = nullptr;
        const DWORD currentPid = ::GetCurrentProcessId();
        if (m_info.processId == currentPid && m_info.threadId != 0)
        {
            const HINSTANCE moduleHandle = ::GetModuleHandleW(nullptr);
            m_callWndHook = ::SetWindowsHookExW(
                WH_CALLWNDPROC,
                &WindowDetailDialog::callWndHookProc,
                moduleHandle,
                static_cast<DWORD>(m_info.threadId));
            m_getMessageHook = ::SetWindowsHookExW(
                WH_GETMESSAGE,
                &WindowDetailDialog::getMessageHookProc,
                moduleHandle,
                static_cast<DWORD>(m_info.threadId));
            m_callWndRetHook = ::SetWindowsHookExW(
                WH_CALLWNDPROCRET,
                &WindowDetailDialog::callWndRetHookProc,
                moduleHandle,
                static_cast<DWORD>(m_info.threadId));

            if (m_callWndHook != nullptr || m_getMessageHook != nullptr || m_callWndRetHook != nullptr)
            {
                registerThreadDialog(static_cast<DWORD>(m_info.threadId), this);
                m_threadRegistered = true;
                m_messageMonitorMode = QStringLiteral("线程消息钩子（同进程）");
                monitorStarted = true;
            }
        }

        if (!monitorStarted)
        {
            m_winEventHook = ::SetWinEventHook(
                EVENT_MIN,
                EVENT_MAX,
                nullptr,
                &WindowDetailDialog::winEventHookProc,
                static_cast<DWORD>(m_info.processId),
                static_cast<DWORD>(m_info.threadId),
                WINEVENT_OUTOFCONTEXT);
            if (m_winEventHook != nullptr)
            {
                registerEventHookDialog(m_winEventHook, this);
                m_eventRegistered = true;
                m_winEventHookSnapshot = m_winEventHook;
                m_messageMonitorMode = QStringLiteral("WinEvent 回退（跨进程）");
                monitorStarted = true;
            }
        }

        if (!monitorStarted)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("消息监控"),
                QStringLiteral("启动失败：目标线程不允许安装消息钩子，且 WinEvent 回退也失败。"));
            return;
        }

        m_messageMonitorRunning.store(true);
        updateMessageMonitorUiState();

        kLogEvent logEvent;
        info << logEvent
            << "[WindowDetailDialog] 消息监控已启动, hwnd="
            << hwndToText(m_info.hwndValue).toStdString()
            << ", mode="
            << m_messageMonitorMode.toStdString()
            << eol;
    }

    // 停止消息监控：释放所有钩子并反注册回调映射。
    void stopMessageMonitor()
    {
        const bool wasRunning = m_messageMonitorRunning.exchange(false);
        if (m_messagePort)
        {
            std::lock_guard<std::mutex> lock(m_messageArchive->mutex);
            m_messagePort->active = false;
        }

        if (m_callWndHook != nullptr)
        {
            ::UnhookWindowsHookEx(m_callWndHook);
            m_callWndHook = nullptr;
        }
        if (m_getMessageHook != nullptr)
        {
            ::UnhookWindowsHookEx(m_getMessageHook);
            m_getMessageHook = nullptr;
        }
        if (m_callWndRetHook != nullptr)
        {
            ::UnhookWindowsHookEx(m_callWndRetHook);
            m_callWndRetHook = nullptr;
        }
        if (m_winEventHook != nullptr)
        {
            ::UnhookWinEvent(m_winEventHook);
            m_winEventHook = nullptr;
        }

        if (m_threadRegistered)
        {
            unregisterThreadDialog(static_cast<DWORD>(m_info.threadId), this);
            m_threadRegistered = false;
        }
        if (m_eventRegistered)
        {
            unregisterEventHookDialog(m_winEventHookSnapshot, this);
            m_eventRegistered = false;
            m_winEventHookSnapshot = nullptr;
        }

        if (wasRunning)
        {
            kLogEvent logEvent;
            info << logEvent
                << "[WindowDetailDialog] 消息监控已停止, hwnd="
                << hwndToText(m_info.hwndValue).toStdString()
                << eol;
        }

        m_messageMonitorMode = QStringLiteral("已停止");
        updateMessageMonitorUiState();
    }

    // updateMessageMonitorUiState 作用：
    // - 统一更新按钮状态与模式文本，避免多处散落状态刷新逻辑；
    // - 同时刷新“已记录/丢弃”计数标签。
    void updateMessageMonitorUiState()
    {
        const bool running = m_messageMonitorRunning.load();
        if (m_messageStartButton != nullptr)
        {
            m_messageStartButton->setEnabled(!running);
        }
        if (m_messageStopButton != nullptr)
        {
            m_messageStopButton->setEnabled(running);
        }
        if (m_messageModeLabel != nullptr)
        {
            m_messageModeLabel->setText(
                running
                ? QStringLiteral("采集模式：%1").arg(m_messageMonitorMode)
                : QStringLiteral("采集模式：%1").arg(m_messageMonitorMode));
        }
        if (m_messageCountLabel != nullptr)
        {
            m_messageCountLabel->setText(
                QStringLiteral("已记录: %1, 丢弃: %2")
                .arg(m_capturedMessageCount)
                .arg(m_droppedMessageCount));
        }
    }

    // Producers only append to the bounded value archive. The fixed poll never
    // creates per-event Qt tasks; invisible pages retain events without projection.
    void flushDeferredMessageRows()
    {
        quint64 revision = 0;
        {
            std::lock_guard<std::mutex> lock(m_messageArchive->mutex);
            revision = m_messageArchive->revision;
            m_capturedMessageCount = m_messageArchive->captured;
            m_droppedMessageCount = m_messageArchive->dropped;
        }
        updateMessageMonitorUiState();
        if (!m_messageTable->isVisible() || revision == m_messagePublishedRevision ||
            !m_messageSnapshotOperation || m_messageSnapshotOperation->isBusy()) return;
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this,
            QStringLiteral("window-message-stream-flush"), {m_messageTable},
            [this] { flushDeferredMessageRows(); })) return;
        struct Request
        {
            std::shared_ptr<WindowMessageArchive> archive;
            std::shared_ptr<const WindowMessageSnapshot> previous;
        };
        m_messageSnapshotOperation->submit<Request, std::shared_ptr<const WindowMessageSnapshot>>(
            {m_messageArchive, m_messagePrepared},
            [](const Request& value, const ks::ui::AsyncOperationToken& token) {
                return makeWindowBackgroundValue<WindowMessageSnapshot>(prepareWindowMessages(value.archive, value.previous, &token));
            },
            [this](const std::shared_ptr<const WindowMessageSnapshot>& snapshot, std::uint64_t generation) {
                const auto commit = [this, snapshot, generation] {
                    if (!m_messageSnapshotOperation->isCurrent(generation)) return;
                    bool current = false;
                    {
                        std::lock_guard<std::mutex> lock(m_messageArchive->mutex);
                        current = snapshot->clearGeneration == m_messageArchive->clearGeneration;
                    }
                    if (current && m_messageTable->isVisible())
                    {
                        // Preserve selection using sequence ranges, not one index
                        // for each of up to 50000 selected rows.
                        std::vector<std::pair<quint64, quint64>> ranges;
                        const auto sourceSelection = m_messageDisplayModel->mapSelectionToSource(
                            m_messageTable->selectionModel()->selection());
                        for (const auto& range : sourceSelection)
                            ranges.emplace_back(m_messageModel->sequenceAt(range.top()), m_messageModel->sequenceAt(range.bottom()));
                        const auto currentIndex = m_messageTable->currentIndex();
                        const quint64 currentSequence = m_messageModel->sequenceAt(m_messageDisplayModel->mapToSource(currentIndex).row());
                        const int currentColumn = currentIndex.column();
                        const auto topIndex = m_messageTable->indexAt(QPoint(0, 0));
                        const quint64 topSequence = m_messageModel->sequenceAt(m_messageDisplayModel->mapToSource(topIndex).row());
                        const int topOffset = topIndex.isValid() ? m_messageTable->visualRect(topIndex).top() : 0;
                        const QPointer<WindowDetailDialog> alive(this);
                        // A fresh capture invalidated the old widget's one-shot
                        // sort too. Keep canonical FIFO and reset only its view.
                        m_messageDisplayModel->sort(-1);
                        if (!alive) return;
                        m_messagePrepared = snapshot;
                        m_messageModel->publish(snapshot);
                        if (!alive) return;
                        QItemSelection selection;
                        if (!snapshot->rows.empty())
                        {
                            const quint64 first = snapshot->rows.front()->sequence, last = snapshot->rows.back()->sequence;
                            for (const auto& range : ranges)
                            {
                                const quint64 from = std::max(first, range.first), to = std::min(last, range.second);
                                if (from <= to)
                                    selection.select(m_messageModel->index(m_messageModel->rowForSequence(from), 0),
                                        m_messageModel->index(m_messageModel->rowForSequence(to), 7));
                            }
                        }
                        m_messageTable->selectionModel()->select(m_messageDisplayModel->mapSelectionFromSource(selection), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                        if (!alive) return;
                        const int currentRow = m_messageModel->rowForSequence(currentSequence);
                        if (currentRow >= 0) m_messageTable->selectionModel()->setCurrentIndex(
                            m_messageDisplayModel->mapFromSource(m_messageModel->index(currentRow, std::max(0, currentColumn))), QItemSelectionModel::NoUpdate);
                        if (!alive) return;
                        m_messagePublishedRevision = snapshot->revision;
                        if (m_messageAutoScrollCheck->isChecked()) m_messageTable->scrollToBottom();
                        else if (!snapshot->rows.empty())
                        {
                            const int top = std::max(0, m_messageModel->rowForSequence(topSequence));
                            m_messageTable->scrollTo(m_messageDisplayModel->mapFromSource(m_messageModel->index(top, 0)), QAbstractItemView::PositionAtTop);
                            if (m_messageTable->verticalScrollMode() == QAbstractItemView::ScrollPerPixel)
                                m_messageTable->verticalScrollBar()->setValue(m_messageTable->verticalScrollBar()->value() - topOffset);
                        }
                        if (!alive) return;
                    }
                    m_messageSnapshotOperation->completeDeferred(generation);
                };
                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this,
                    QStringLiteral("window-message-stream-publish"), {m_messageTable}, commit)) return false;
                commit();
                return true;
            },
            [](std::exception_ptr) {});
    }

    // threadHookDispatch 作用：
    // - 由静态消息钩子回调调用；
    // - 根据 threadId 找到对应详情窗，并把消息异步转发到 UI 线程。
    static void threadHookDispatch(
        const DWORD threadId,
        const QString& channelText,
        HWND targetHwnd,
        const UINT messageId,
        const WPARAM wParamValue,
        const LPARAM lParamValue,
        const LRESULT resultValue)
    {
        std::vector<std::shared_ptr<WindowMessagePort>> ports;
        {
            std::lock_guard<std::mutex> lock(s_monitorRegistryMutex);
            const auto found = s_threadDialogMap.find(threadId);
            if (found != s_threadDialogMap.end()) ports = found->second;
        }
        if (!targetHwnd) return;
        for (const auto& port : ports)
            recordWindowMessage(port, {channelText,
                static_cast<quint64>(reinterpret_cast<quintptr>(targetHwnd)),
                static_cast<quint64>(messageId), static_cast<quint64>(wParamValue),
                static_cast<quint64>(lParamValue), static_cast<quint64>(resultValue), QString()});
    }

    // callWndHookProc：捕获 SendMessage 路径的入站消息（调用前）。
    static LRESULT CALLBACK callWndHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const CWPSTRUCT* callInfo = reinterpret_cast<const CWPSTRUCT*>(lParam);
            if (callInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_CALLWNDPROC"),
                    callInfo->hwnd,
                    callInfo->message,
                    callInfo->wParam,
                    callInfo->lParam,
                    0);
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // getMessageHookProc：捕获 PostMessage/消息队列路径消息。
    static LRESULT CALLBACK getMessageHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const MSG* msgInfo = reinterpret_cast<const MSG*>(lParam);
            if (msgInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_GETMESSAGE"),
                    msgInfo->hwnd,
                    msgInfo->message,
                    msgInfo->wParam,
                    msgInfo->lParam,
                    static_cast<LRESULT>(wParam));
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // callWndRetHookProc：捕获 SendMessage 返回后消息，可看到 lResult。
    static LRESULT CALLBACK callWndRetHookProc(const int code, const WPARAM wParam, const LPARAM lParam)
    {
        if (code >= 0 && lParam != 0)
        {
            const CWPRETSTRUCT* retInfo = reinterpret_cast<const CWPRETSTRUCT*>(lParam);
            if (retInfo != nullptr)
            {
                threadHookDispatch(
                    ::GetCurrentThreadId(),
                    QStringLiteral("WH_CALLWNDPROCRET"),
                    retInfo->hwnd,
                    retInfo->message,
                    retInfo->wParam,
                    retInfo->lParam,
                    retInfo->lResult);
            }
        }
        return ::CallNextHookEx(nullptr, code, wParam, lParam);
    }

    // winEventHookProc：跨进程回退模式回调（无 DLL 注入）。
    static void CALLBACK winEventHookProc(
        HWINEVENTHOOK hookHandle,
        const DWORD eventId,
        HWND windowHandle,
        const LONG objectId,
        const LONG childId,
        const DWORD eventThreadId,
        const DWORD eventTimeMs)
    {
        std::shared_ptr<WindowMessagePort> port;
        {
            std::lock_guard<std::mutex> lock(s_monitorRegistryMutex);
            const auto found = s_eventHookMap.find(hookHandle);
            if (found != s_eventHookMap.end()) port = found->second;
        }
        const QString extra = QStringLiteral("obj=%1, child=%2, thread=%3, time=%4")
            .arg(objectId).arg(childId).arg(eventThreadId).arg(eventTimeMs);
        recordWindowMessage(port, {QStringLiteral("WinEvent"),
            static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle)),
            static_cast<quint64>(eventId), static_cast<quint64>(static_cast<qint64>(objectId)),
            static_cast<quint64>(static_cast<qint64>(childId)), static_cast<quint64>(eventThreadId),
            extra + QStringLiteral(", tick=%1").arg(eventTimeMs)});
    }

    // 注册 thread -> dialog 映射：支持同一线程被多个详情窗同时观察。
    static void registerThreadDialog(const DWORD threadId, WindowDetailDialog* dialog)
    {
        if (threadId == 0 || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
        std::vector<std::shared_ptr<WindowMessagePort>>& dialogList = s_threadDialogMap[threadId];
        const bool existed = std::find(dialogList.begin(), dialogList.end(), dialog->m_messagePort) != dialogList.end();
        if (!existed)
        {
            dialogList.push_back(dialog->m_messagePort);
        }
    }

    // 反注册 thread -> dialog 映射，避免对已关闭窗口继续投递消息。
    static void unregisterThreadDialog(const DWORD threadId, WindowDetailDialog* dialog)
    {
        if (threadId == 0 || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
        const auto it = s_threadDialogMap.find(threadId);
        if (it == s_threadDialogMap.end())
        {
            return;
        }

        std::vector<std::shared_ptr<WindowMessagePort>>& dialogList = it->second;
        dialogList.erase(std::remove(dialogList.begin(), dialogList.end(), dialog->m_messagePort), dialogList.end());
        if (dialogList.empty())
        {
            s_threadDialogMap.erase(it);
        }
    }

    // 注册 WinEvent hook -> dialog 映射，供回调快速查找目标详情窗。
    static void registerEventHookDialog(HWINEVENTHOOK hookHandle, WindowDetailDialog* dialog)
    {
        if (hookHandle == nullptr || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
        s_eventHookMap[hookHandle] = dialog->m_messagePort;
    }

    // 反注册 WinEvent 映射：窗口关闭或停止监控时必须调用。
    static void unregisterEventHookDialog(HWINEVENTHOOK hookHandle, WindowDetailDialog* dialog)
    {
        if (hookHandle == nullptr || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
        const auto it = s_eventHookMap.find(hookHandle);
        if (it != s_eventHookMap.end() && it->second == dialog->m_messagePort)
        {
            s_eventHookMap.erase(it);
        }
    }

    // 目标窗口句柄访问器：统一从缓存快照里恢复 HWND。
    HWND targetWindowHandle() const
    {
        return toHwnd(m_info.hwndValue);
    }

    // 应用改动：把标题、位置与复选框样式位写回目标窗口。
    void applyChanges()
    {
        HWND windowHandle = toHwnd(m_info.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("应用失败"), QStringLiteral("目标窗口句柄已失效。"));
            return;
        }

        // 标题修改：支持直接编辑后写回。
        const QString titleText = m_titleEdit->text();
        ::SetWindowTextW(windowHandle, reinterpret_cast<const wchar_t*>(titleText.utf16()));

        // 位置尺寸修改：按输入框坐标和尺寸移动窗口。
        ::MoveWindow(
            windowHandle,
            m_xSpin->value(),
            m_ySpin->value(),
            std::max(1, m_widthSpin->value()),
            std::max(1, m_heightSpin->value()),
            TRUE);

        // 样式修改：统一由“样式复选框”计算目标 Style/ExStyle 后应用。
        const bool styleAppliedOk = applyStyleCheckBoxChanges(false);
        if (!styleAppliedOk)
        {
            return;
        }

        QMessageBox::information(this, QStringLiteral("窗口属性"), QStringLiteral("已应用修改。"));
    }

    // 导出信息：把当前所有标签页关键内容写入文本文件。
    void exportInfo()
    {
        if (m_runtimeExportPending) return;
        m_runtimeExportPending = true;
        m_exportButton->setEnabled(false);
        requestRuntimeInfo(RuntimeAll, true);
    }
    void exportInfoNow()
    {
        const QPointer<WindowDetailDialog> alive(this);
        const QString reportText = buildReportText();
        const QString defaultName = QStringLiteral("window_detail_%1_%2.txt")
            .arg(QString::number(m_info.processId))
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

        const QString outputPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出窗口详情"),
            defaultName,
            QStringLiteral("文本文件 (*.txt)"));
        if (!alive || outputPath.trimmed().isEmpty())
        {
            return;
        }

        QFile file(outputPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        {
            QMessageBox::warning(this, QStringLiteral("导出失败"), QStringLiteral("无法写入文件：%1").arg(outputPath));
            return;
        }

        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << reportText;
        file.close();

        QMessageBox::information(this, QStringLiteral("导出成功"), QStringLiteral("已保存到：%1").arg(outputPath));
    }

    WindowMessageSnapshot prepareWindowMessagesForExport() const
    {
        return prepareWindowMessages(m_messageArchive, m_messagePrepared, nullptr);
    }

    // 组装导出文本：集中输出所有页核心内容，便于审计留档。
    QString buildReportText() const
    {
        QString text;
        text += QStringLiteral("[常规]\n");
        text += QStringLiteral("句柄: %1\n").arg(m_handleLabel->text());
        text += QStringLiteral("父句柄: %1\n").arg(m_parentHandleLabel->text());
        text += QStringLiteral("所有者句柄: %1\n").arg(m_ownerHandleLabel->text());
        text += QStringLiteral("标题: %1\n").arg(m_titleEdit->text());
        text += QStringLiteral("类名: %1\n").arg(m_classNameLabel->text());
        text += QStringLiteral("实例句柄: %1\n").arg(m_instanceLabel->text());
        text += QStringLiteral("状态摘要: %1\n").arg(m_stateLabel->text());
        text += QStringLiteral("关系摘要: %1\n\n").arg(m_relationLabel->text());

        text += QStringLiteral("[样式]\n%1\n\n").arg(m_styleText->plainText());
        text += QStringLiteral("[位置]\nX=%1, Y=%2, W=%3, H=%4\n\n")
            .arg(m_xSpin->value())
            .arg(m_ySpin->value())
            .arg(m_widthSpin->value())
            .arg(m_heightSpin->value());
        text += QStringLiteral("[状态]\nTopMost=%1, Alpha=%2\n\n")
            .arg(boolText(m_topMostCheck->isChecked()))
            .arg(m_alphaSlider->value());
        text += QStringLiteral("[进程线程]\n%1\n\n").arg(m_processThreadText->plainText());
        text += QStringLiteral("[类信息]\n%1\n\n").arg(m_classText->plainText());
        text += QStringLiteral("[消息钩子]\n%1\n\n").arg(m_hookText->plainText());
        text += QStringLiteral("[消息记录]\n");
        if (m_messageTable != nullptr)
        {
            text += m_messageModel->headers.join('\t') + QStringLiteral("\n");
            // Explicit export reads the canonical retained archive, not a stale
            // hidden visual snapshot. No accepted record is lost to UI cadence.
            auto snapshot = prepareWindowMessagesForExport();
            for (const auto& row : snapshot.rows)
            {
                QStringList cells;
                for (const auto& cell : row->cells) cells << cell;
                text += cells.join('\t') + QStringLiteral("\n");
            }
        }
        text += QStringLiteral("\n");

        text += QStringLiteral("[高级属性]\n%1\n").arg(m_advancedText->plainText());
        return text;
    }

private:
    OtherDock::WindowInfo m_info;          // 目标窗口快照。
    ks::ui::AsyncOperation* m_runtimeOperation = nullptr;
    QHash<QWidget*, unsigned> m_runtimePageMasks;
    unsigned m_runtimeLoadedMask = 0, m_runtimePendingMask = 0;
    quint64 m_runtimeEditRevision = 0;
    bool m_runtimeBaseLoaded = false, m_runtimeApplying = false, m_runtimeExportPending = false;
    bool m_runtimeMonitorInitialDone = false;


    QTabWidget* m_tabWidget = nullptr;     // 标签页容器。

    QLabel* m_handleLabel = nullptr;       // 句柄显示。
    QLabel* m_parentHandleLabel = nullptr; // 父句柄显示。
    QLabel* m_ownerHandleLabel = nullptr;  // 所有者句柄显示。
    QLineEdit* m_titleEdit = nullptr;      // 可编辑标题输入。
    QLabel* m_classNameLabel = nullptr;    // 类名显示。
    QLabel* m_instanceLabel = nullptr;     // 实例句柄显示。
    QLabel* m_stateLabel = nullptr;        // 状态摘要显示。
    QLabel* m_relationLabel = nullptr;     // 关系摘要显示。

    ks::ui::StructuredFieldView* m_styleText = nullptr;      // 样式文本区域（统一文本编辑器，只读）。
    std::vector<StyleCheckBinding> m_styleCheckBindingList; // 普通样式复选框绑定表（GWL_STYLE）。
    std::vector<StyleCheckBinding> m_exStyleCheckBindingList; // 扩展样式复选框绑定表（GWL_EXSTYLE）。
    bool m_styleCheckSyncing = false;             // 勾选回填防抖标记，避免刷新触发“用户修改”链路。
    QPushButton* m_styleRefreshButton = nullptr;  // 样式区刷新按钮。
    QPushButton* m_styleApplyButton = nullptr;    // 样式区应用按钮。
    QSpinBox* m_xSpin = nullptr;                // X 坐标输入。
    QSpinBox* m_ySpin = nullptr;                // Y 坐标输入。
    QSpinBox* m_widthSpin = nullptr;            // 宽度输入。
    QSpinBox* m_heightSpin = nullptr;           // 高度输入。
    QCheckBox* m_topMostCheck = nullptr;        // 置顶复选框。
    QSlider* m_alphaSlider = nullptr;           // 透明度滑块。
    QSpinBox* m_alphaSpin = nullptr;             // 透明度数值输入。
    bool m_alphaChanged = false;                // 仅用户调整 Alpha 时写入透明度。

    ks::ui::StructuredFieldView* m_processThreadText = nullptr; // 进程线程页文本（统一文本编辑器，只读）。
    ks::ui::StructuredFieldView* m_classText = nullptr;         // 类信息页文本（统一文本编辑器，只读）。
    ks::ui::StructuredFieldView* m_hookText = nullptr;          // 钩子页文本（统一文本编辑器，只读）。
    QPushButton* m_messageStartButton = nullptr;   // 消息监控开始按钮。
    QPushButton* m_messageStopButton = nullptr;    // 消息监控停止按钮。
    QPushButton* m_messageClearButton = nullptr;   // 消息列表清空按钮。
    QCheckBox* m_messageAutoScrollCheck = nullptr; // 自动滚动复选框。
    QSpinBox* m_messageMaxRowsSpin = nullptr;      // 消息表最大保留行数。
    QLabel* m_messageModeLabel = nullptr;          // 当前采集模式标签。
    QLabel* m_messageCountLabel = nullptr;         // 已记录/丢弃计数标签。
    QTableView* m_messageTable = nullptr;
    WindowMessageModel* m_messageModel = nullptr;
    QSortFilterProxyModel* m_messageDisplayModel = nullptr;
    std::shared_ptr<WindowMessageArchive> m_messageArchive = makeWindowBackgroundValue<WindowMessageArchive>();
    std::shared_ptr<WindowMessagePort> m_messagePort;
    std::shared_ptr<const WindowMessageSnapshot> m_messagePrepared;
    ks::ui::AsyncOperation* m_messageSnapshotOperation = nullptr;
    QTimer* m_messageFlushTimer = nullptr;
    quint64 m_messagePublishedRevision = 0;        // 消息列表表格。
    ks::ui::StructuredFieldView* m_advancedText = nullptr;      // 高级页文本（统一文本编辑器，只读）。

    QPushButton* m_refreshButton = nullptr;    // 刷新按钮。
    QPushButton* m_applyButton = nullptr;      // 应用按钮。
    QPushButton* m_exportButton = nullptr;     // 导出按钮。
    QPushButton* m_closeButton = nullptr;      // 关闭按钮。

    HHOOK m_callWndHook = nullptr;             // WH_CALLWNDPROC 句柄。
    HHOOK m_getMessageHook = nullptr;          // WH_GETMESSAGE 句柄。
    HHOOK m_callWndRetHook = nullptr;          // WH_CALLWNDPROCRET 句柄。
    HWINEVENTHOOK m_winEventHook = nullptr;    // WinEvent 回退句柄。
    HWINEVENTHOOK m_winEventHookSnapshot = nullptr; // 用于反注册映射的 hook 快照。
    std::atomic_bool m_messageMonitorRunning{ false }; // 消息监控运行状态。
    bool m_threadRegistered = false;           // 是否已注册 thread->dialog 映射。
    bool m_eventRegistered = false;            // 是否已注册 eventHook->dialog 映射。
    quint64 m_capturedMessageCount = 0;            // 已写入消息表的消息数量。
    quint64 m_droppedMessageCount = 0;             // 因超过最大行数而丢弃的消息数量。
    QString m_messageMonitorMode = QStringLiteral("未启动"); // 当前监控模式文本。

    static std::mutex s_monitorRegistryMutex;  // 回调映射表互斥锁，防止并发竞态。
    static std::unordered_map<DWORD, std::vector<std::shared_ptr<WindowMessagePort>>> s_threadDialogMap; // threadId -> 详情窗列表。
    static std::unordered_map<HWINEVENTHOOK, std::shared_ptr<WindowMessagePort>> s_eventHookMap; // WinEvent hook -> 详情窗。
};

// 静态成员定义：统一管理消息回调分发映射。
std::mutex WindowDetailDialog::s_monitorRegistryMutex;
std::unordered_map<DWORD, std::vector<std::shared_ptr<WindowMessagePort>>> WindowDetailDialog::s_threadDialogMap;
std::unordered_map<HWINEVENTHOOK, std::shared_ptr<WindowMessagePort>> WindowDetailDialog::s_eventHookMap;

OtherDock::OtherDock(QWidget* parent)
    : OtherDock(parent, PageScope::Main, {})
{
}

OtherDock::OtherDock(QWidget* parent, PageScope scope, const QVector<quint32>& processIds)
    : QWidget(parent), m_pageScope(scope)
{
    // Caller scope is complete before controls or the first sampling/projection
    // request exist. A process detail host never creates a hidden desktop page.
    for (quint32 pid : processIds)
        if (pid != 0) m_externalProcessIdFilterSet.insert(pid);

    kLogEvent event;
    info << event << "[OtherDock] 构造开始，初始化窗口管理页。" << eol;

    m_windowState = makeWindowBackgroundValue<ks::windowlist::Snapshot>();
    if (m_pageScope == PageScope::Main) {
        m_desktopOperation = new ks::ui::AsyncOperation(this);
        m_desktopPresentationOperation = new ks::ui::AsyncOperation(this);
    }
    m_windowRefreshOperation = new ks::ui::AsyncOperation(this);
    m_windowProjectionOperation = new ks::ui::AsyncOperation(this);
    m_windowFilterTimer = new QTimer(this);
    m_windowFilterTimer->setSingleShot(true);
    m_windowFilterTimer->setInterval(120);
    connect(m_windowFilterTimer, &QTimer::timeout, this, [this] { rebuildWindowTreeFromSnapshot(); });
    initializeUi();
    initializeConnections();
    m_previewScaleOperation = new ks::ui::AsyncOperation(this);
    m_thumbnailLabel->installEventFilter(this);
    m_previewTimer = new QTimer(this);
    m_previewTimer->setInterval(1000);
    connect(m_previewTimer, &QTimer::timeout, this, [this] {
        m_previewCaptureDue = true;
        if (m_previewWidget->isVisible()) scheduleWindowSelectionUi();
    });
    m_previewTimer->start();
    initializeWindowTransactions();
    m_autoRefreshCheck->setChecked(true);
    applyViewMode();
    refreshWindowListAsync();
}

OtherDock::~OtherDock()
{
    if (m_previewScaleOperation) m_previewScaleOperation->close();
    if (m_windowActionOperation) m_windowActionOperation->close();
    if (m_windowRefreshOperation) m_windowRefreshOperation->close();
    if (m_desktopOperation) m_desktopOperation->close();
    if (m_desktopPresentationOperation) m_desktopPresentationOperation->close();
    if (m_windowProjectionOperation) m_windowProjectionOperation->close();
    if (m_autoRefreshTimer != nullptr)
    {
        m_autoRefreshTimer->stop();
    }

    // 关闭本进程主动保留的新建桌面句柄，避免桌面对象在程序退出后残留引用。
    for (const CreatedDesktopRecord& desktopRecord : m_createdDesktopHandles)
    {
        if (desktopRecord.desktopHandle != nullptr && !desktopRecord.handleLease)
        {
            ::CloseDesktop(reinterpret_cast<HDESK>(desktopRecord.desktopHandle));
        }
    }
    m_createdDesktopHandles.clear();
}

void OtherDock::focusProcessIds(const QVector<quint32>& processIds)
{
    m_externalProcessIdFilterSet.clear();
    for (const quint32 processId : processIds)
    {
        if (processId != 0U)
        {
            m_externalProcessIdFilterSet.insert(processId);
        }
    }
    if (m_contentTabWidget != nullptr && m_windowListPage != nullptr)
    {
        m_contentTabWidget->setCurrentWidget(m_windowListPage);
    }
    if (m_clearExternalProcessFilterButton != nullptr)
    {
        m_clearExternalProcessFilterButton->setEnabled(!m_externalProcessIdFilterSet.isEmpty());
    }
    rebuildWindowTreeFromSnapshot();
}

void OtherDock::clearExternalProcessFilter()
{
    if (m_externalProcessIdFilterSet.isEmpty())
    {
        return;
    }
    m_externalProcessIdFilterSet.clear();
    if (m_clearExternalProcessFilterButton != nullptr)
    {
        m_clearExternalProcessFilterButton->setEnabled(false);
    }
    rebuildWindowTreeFromSnapshot();
}

void OtherDock::setWindowListOnlyScope()
{
    if (m_contentTabWidget == nullptr)
    {
        return;
    }

    for (int tabIndex = 0; tabIndex < m_contentTabWidget->count(); ++tabIndex)
    {
        m_contentTabWidget->setTabVisible(
            tabIndex,
            m_contentTabWidget->widget(tabIndex) == m_windowListPage);
    }

    if (m_windowListPage != nullptr)
    {
        m_contentTabWidget->setCurrentWidget(m_windowListPage);
    }
}

void OtherDock::initializeUi()
{
    // 根布局负责承载“工具栏 + 主分割区 + 状态栏”。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    // 顶部工具栏：覆盖刷新、自动刷新、筛选、分组和导出等控制项。
    m_toolBarWidget = new QWidget(this);
    m_toolBarLayout = new QHBoxLayout(m_toolBarWidget);
    m_toolBarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolBarLayout->setSpacing(4);
    // 仅将枚举工具带与结果Tab合并；底部状态栏继续沿用根布局的分区间隔。
    auto* resultLayout = new QVBoxLayout();
    resultLayout->setContentsMargins(0, 0, 0, 0);
    resultLayout->setSpacing(0);
    m_rootLayout->addLayout(resultLayout, 1);
    resultLayout->addWidget(m_toolBarWidget, 0);

    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_toolBarWidget);
    m_refreshButton->setToolTip(QStringLiteral("刷新窗口列表"));
    m_refreshButton->setStyleSheet(blueButtonStyle());
    m_refreshButton->setFixedWidth(32);

    m_clearExternalProcessFilterButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), m_toolBarWidget);
    m_clearExternalProcessFilterButton->setToolTip(QStringLiteral("清除进程页跳转带入的 PID 筛选"));
    m_clearExternalProcessFilterButton->setStyleSheet(blueButtonStyle());
    m_clearExternalProcessFilterButton->setFixedWidth(32);
    m_clearExternalProcessFilterButton->setEnabled(!m_externalProcessIdFilterSet.isEmpty());

    m_autoRefreshCheck = new QCheckBox(QStringLiteral("自动"), m_toolBarWidget);
    m_autoRefreshCheck->setToolTip(QStringLiteral("启用自动刷新窗口列表"));

    m_autoRefreshIntervalSpin = new QSpinBox(m_toolBarWidget);
    m_autoRefreshIntervalSpin->setRange(300, 5000);
    m_autoRefreshIntervalSpin->setSingleStep(100);
    m_autoRefreshIntervalSpin->setValue(1000);
    m_autoRefreshIntervalSpin->setSuffix(QStringLiteral(" ms"));
    m_autoRefreshIntervalSpin->setToolTip(QStringLiteral("自动刷新间隔（毫秒）"));
    m_autoRefreshIntervalSpin->setStyleSheet(blueInputStyle());

    m_filterEdit = new QLineEdit(m_toolBarWidget);
    // 窗口树的标题/进程/类名过滤使用同一无线框搜索外观。
    ks::ui::BindSearchFieldTheme(m_filterEdit);
    m_filterEdit->setPlaceholderText(QStringLiteral("筛选：标题 / 进程名 / 类名 / HWND"));
    m_filterEdit->setToolTip(QStringLiteral("输入关键字实时过滤窗口"));
    m_filterEdit->setStyleSheet(blueInputStyle());
    ks::ui::StyleSearchField(m_filterEdit);

    m_filterModeCombo = new QComboBox(m_toolBarWidget);
    m_filterModeCombo->addItems({
        QStringLiteral("所有窗口"),
        QStringLiteral("可见窗口"),
        QStringLiteral("隐藏窗口"),
        QStringLiteral("顶层窗口"),
        QStringLiteral("子窗口"),
        QStringLiteral("无效窗口")
        });
    m_filterModeCombo->setToolTip(QStringLiteral("选择窗口过滤条件"));
    m_filterModeCombo->setStyleSheet(blueInputStyle());
    ks::ui::StylePrimaryCombo(m_filterModeCombo);

    m_enumModeCombo = new QComboBox(m_toolBarWidget);
    m_enumModeCombo->addItems({
        QStringLiteral("混合枚举"),
        QStringLiteral("EnumWindows"),
        QStringLiteral("EnumDesktopWindows"),
        QStringLiteral("EnumThreadWindows"),
        QStringLiteral("仅顶层")
        });
    m_enumModeCombo->setToolTip(QStringLiteral("选择窗口枚举策略（用于减少漏项）"));
    m_enumModeCombo->setStyleSheet(blueInputStyle());
    ks::ui::StylePrimaryCombo(m_enumModeCombo);

    m_groupModeCombo = new QComboBox(m_toolBarWidget);
    m_groupModeCombo->addItems({
        QStringLiteral("按进程分组"),
        QStringLiteral("按Z序排列"),
        QStringLiteral("按窗口层级"),
        QStringLiteral("按显示器分组")
        });
    m_groupModeCombo->setToolTip(QStringLiteral("选择窗口分组方式"));
    m_groupModeCombo->setStyleSheet(blueInputStyle());
    ks::ui::StylePrimaryCombo(m_groupModeCombo);

    m_viewModeCombo = new QComboBox(m_toolBarWidget);
    m_viewModeCombo->addItems({
        QStringLiteral("图标视图"),
        QStringLiteral("列表视图"),
        QStringLiteral("详细信息视图")
        });
    m_viewModeCombo->setToolTip(QStringLiteral("切换列表显示样式"));
    m_viewModeCombo->setStyleSheet(blueInputStyle());
    ks::ui::StylePrimaryCombo(m_viewModeCombo);

    m_exportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), m_toolBarWidget);
    m_exportButton->setToolTip(QStringLiteral("导出当前列表为 TSV"));
    m_exportButton->setStyleSheet(blueButtonStyle());
    m_exportButton->setFixedWidth(32);

    m_toolBarLayout->addWidget(m_refreshButton, 0);
    m_toolBarLayout->addWidget(m_clearExternalProcessFilterButton, 0);
    m_toolBarLayout->addWidget(m_autoRefreshCheck, 0);
    m_toolBarLayout->addWidget(m_autoRefreshIntervalSpin, 0);
    m_toolBarLayout->addWidget(m_filterEdit, 1);
    m_toolBarLayout->addWidget(m_filterModeCombo, 0);
    m_toolBarLayout->addWidget(m_enumModeCombo, 0);
    m_toolBarLayout->addWidget(m_groupModeCombo, 0);
    m_toolBarLayout->addWidget(m_viewModeCombo, 0);
    m_toolBarLayout->addWidget(m_exportButton, 0);
    ks::ui::NormalizeToolbarRow(m_toolBarLayout);
    // 枚举与过滤控制保持单行，轻底面标识结果之上的控制层。
    ks::ui::StylePrimaryToolbar(m_toolBarWidget);
    m_toolBarLayout->setContentsMargins(6, 3, 6, 3);
    ks::ui::ApplyFlatButtonTheme(m_refreshButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    ks::ui::ApplyFlatButtonTheme(m_exportButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);

    // 中部主内容：Tab1=窗口列表，Tab2=桌面管理（SwitchDesktop）。
    m_contentTabWidget = new QTabWidget(this);
    ks::ui::StyleJoinedResultTabs(m_contentTabWidget, m_toolBarWidget);
    resultLayout->addWidget(m_contentTabWidget, 1);

    m_windowListPage = new QWidget(m_contentTabWidget);
    m_windowListPageLayout = new QVBoxLayout(m_windowListPage);
    m_windowListPageLayout->setContentsMargins(0, 0, 0, 0);
    m_windowListPageLayout->setSpacing(4);

    // 窗口列表页顶部工具条：新增准星拖拽拾取入口，满足“直接拖到目标窗口看详情”场景。
    m_windowListToolWidget = new QWidget(m_windowListPage);
    m_windowListToolLayout = new QHBoxLayout(m_windowListToolWidget);
    m_windowListToolLayout->setContentsMargins(0, 0, 0, 0);
    m_windowListToolLayout->setSpacing(6);

    auto* pickerButton = new ks::ui::WindowTargetPickerButton(m_windowListToolWidget);
    m_windowPickerButton = pickerButton;
    m_windowPickerButton->setIcon(QIcon(":/Icon/window_picker_target.svg"));
    m_windowPickerButton->setToolTip(QStringLiteral("拖拽准星定位窗口；按住 Ctrl 松开可预览并选择该位置的窗口"));
    ks::ui::ApplyFlatButtonTheme(m_windowPickerButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    KswordTheme::ApplyCompactIconButtonMetrics(m_windowPickerButton);

    m_protectCaptureButton = new QPushButton(QIcon(":/Icon/titlebar_capture_protected.svg"), QString(), m_windowListToolWidget);
    m_protectCaptureButton->setToolTip(QStringLiteral("对选中窗口启用防截图保护：优先从截图/录屏中隐藏，失败时回退黑屏"));
    m_protectCaptureButton->setStyleSheet(blueButtonStyle());
    m_protectCaptureButton->setFixedWidth(32);

    m_unprotectCaptureButton = new QPushButton(QIcon(":/Icon/titlebar_capture_allowed.svg"), QString(), m_windowListToolWidget);
    m_unprotectCaptureButton->setToolTip(QStringLiteral("取消选中窗口的防截图保护，恢复普通截图/录屏捕获"));
    m_unprotectCaptureButton->setStyleSheet(blueButtonStyle());
    m_unprotectCaptureButton->setFixedWidth(32);

    m_windowPickerHintLabel = new QLabel(
        QStringLiteral("拖拽准星定位窗口，Ctrl 松开预览选择；列表支持 Ctrl/Shift 多选"),
        m_windowListToolWidget);
    m_windowPickerHintLabel->setToolTip(QStringLiteral("防截图保护会对顶层窗口写入 DisplayAffinity，外部进程窗口会尝试远程调用"));

    pickerButton->setPickCallback([this](quintptr hwndValue) {
        handleWindowPicked(hwndValue);
    });

    m_windowListToolLayout->addWidget(m_windowPickerButton, 0);
    m_windowListToolLayout->addWidget(m_protectCaptureButton, 0);
    m_windowListToolLayout->addWidget(m_unprotectCaptureButton, 0);
    m_windowInputButton = new QPushButton(m_windowListToolWidget);
    ks::i18n::LanguageManager::instance().bindText(m_windowInputButton,
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));
    m_windowListToolLayout->addWidget(m_windowInputButton);
    connect(m_windowInputButton, &QPushButton::clicked, this, [this]
    {
        const auto windows = selectedWindowSnapshots();
        if (windows.size() == 1) openWindowDetailDialog(windows.front(), true);
    });
    m_expandWindowsButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/detail_node_expanded.svg")), QString(), m_windowListToolWidget);
    m_expandWindowsButton->setObjectName(QStringLiteral("ks_window_list_expand_all"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_expandWindowsButton,
        QStringLiteral("window.list.expand_all"), QStringLiteral("全部展开"));
    ks::ui::ApplyFlatButtonTheme(m_expandWindowsButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    KswordTheme::ApplyCompactIconButtonMetrics(m_expandWindowsButton);
    m_windowListToolLayout->addWidget(m_expandWindowsButton, 0);
    connect(m_expandWindowsButton, &QPushButton::clicked, this, [this] {
        if (m_windowTree) m_windowTree->expandAll();
    });

    m_collapseWindowsButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/detail_node_collapsed.svg")), QString(), m_windowListToolWidget);
    m_collapseWindowsButton->setObjectName(QStringLiteral("ks_window_list_collapse_all"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_collapseWindowsButton,
        QStringLiteral("window.list.collapse_all"), QStringLiteral("全部折叠"));
    ks::ui::ApplyFlatButtonTheme(m_collapseWindowsButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    KswordTheme::ApplyCompactIconButtonMetrics(m_collapseWindowsButton);
    m_windowListToolLayout->addWidget(m_collapseWindowsButton, 0);
    connect(m_collapseWindowsButton, &QPushButton::clicked, this, [this] {
        if (m_windowTree) m_windowTree->collapseAll();
    });
    m_windowListToolLayout->addWidget(m_windowPickerHintLabel, 0);
    m_windowListToolLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(m_windowListToolLayout);
    m_windowListPageLayout->addWidget(m_windowListToolWidget, 0);

    // 窗口列表页：左树右预览。
    m_mainSplitter = new QSplitter(Qt::Horizontal, m_windowListPage);
    // 预览正文允许忽略尺寸提示，但外层分栏必须保留两侧可用空间。
    m_mainSplitter->setChildrenCollapsible(false);
    m_windowListPageLayout->addWidget(m_mainSplitter, 1);

    m_windowTree = new QTreeView(m_mainSplitter);
    m_windowModel = new ks::windowlist::SnapshotModel(m_windowTree);
    m_windowTree->setProperty("ks_i18n_preserve_model_data", true);
    m_windowTree->setModel(m_windowModel);
    m_windowModel->iconsChanged = [this] { m_windowTree->viewport()->update(); };
    m_windowTree->installEventFilter(this);
    m_windowTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_windowTree->setRootIsDecorated(true);
    m_windowTree->setAlternatingRowColors(true);
    m_windowTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_windowTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_windowTree->setUniformRowHeights(true);
    m_windowTree->setSortingEnabled(false);
    m_windowTree->header()->setStyleSheet(blueHeaderStyle());
    m_windowModel->headers = {
        QStringLiteral("窗口标题"),
        QStringLiteral("句柄"),
        QStringLiteral("枚举API"),
        QStringLiteral("类名"),
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("TID"),
        QStringLiteral("大小"),
        QStringLiteral("可见"),
        QStringLiteral("可用"),
        QStringLiteral("顶层"),
        QStringLiteral("状态"),
        QStringLiteral("透明度")
        };
    ks::window::configureWindowListColumnSizing(m_windowTree);

    m_previewWidget = new QWidget(m_mainSplitter);
    // 搜索工具栏在窄列内换行；最小列宽不再依赖初始隐藏的缩略图。
    m_previewWidget->setMinimumWidth(280);
    m_previewLayout = new QVBoxLayout(m_previewWidget);
    m_previewLayout->setContentsMargins(0, 0, 0, 0);
    m_previewLayout->setSpacing(6);

    m_thumbnailLabel = new QLabel(m_previewWidget);
    m_thumbnailLabel->setMinimumSize(0, 0);
    // Image previews have a bounded height; unavailable text uses its wrapped natural height.
    m_thumbnailLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Maximum);
    m_thumbnailLabel->setAlignment(Qt::AlignCenter);
    m_thumbnailLabel->setWordWrap(true);
    m_thumbnailLabel->setMargin(8);
    m_thumbnailLabel->setStyleSheet(QStringLiteral(
        "border:1px solid %1;background:%2;")
        .arg(KswordTheme::BorderHex(), KswordTheme::SurfaceAltHex()));
    m_thumbnailLabel->hide();

    m_captureButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_previewWidget);
    m_captureButton->setToolTip(QStringLiteral("保存当前窗口截图"));
    m_captureButton->setStyleSheet(blueButtonStyle());
    m_captureButton->setFixedWidth(34);

    m_quickInfoText = new ks::ui::StructuredFieldView(m_previewWidget, m_captureButton);

    m_previewLayout->addWidget(m_thumbnailLabel, 0);
    m_previewLayout->addWidget(m_quickInfoText, 1);

    // 默认把左侧窗口列表区域放宽，避免窗口标题被截断。
    m_mainSplitter->setStretchFactor(0, 4);
    m_mainSplitter->setStretchFactor(1, 1);
    // 显式提供首次分配基准，避免右侧零尺寸提示使分栏初始宽度归零。
    m_mainSplitter->setSizes({800, 280});
    m_navigationTabs.add(kWindowNavigation[0], m_contentTabWidget, m_windowListPage);

    // 桌面管理页：列出窗口站与桌面，并补充 SessionId / SID / 权限状态等上下文。
    if (m_pageScope == PageScope::Main)
    {
        m_desktopPage = new QWidget(m_contentTabWidget);
        m_desktopPageLayout = new QVBoxLayout(m_desktopPage);
        m_desktopPageLayout->setContentsMargins(0, 0, 0, 0);
        m_desktopPageLayout->setSpacing(6);

        m_desktopToolLayout = new QHBoxLayout();
        m_desktopToolLayout->setContentsMargins(0, 0, 0, 0);
        m_desktopToolLayout->setSpacing(6);

        m_desktopRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_desktopPage);
        m_desktopRefreshButton->setToolTip(QStringLiteral("刷新可用桌面列表"));
        m_desktopRefreshButton->setStyleSheet(blueButtonStyle());
        m_desktopRefreshButton->setFixedWidth(32);

        m_desktopSwitchButton = new QPushButton(QIcon(":/Icon/desktop_switch.svg"), QString(), m_desktopPage);
        m_desktopSwitchButton->setToolTip(QStringLiteral("切换到选中桌面（SwitchDesktop）"));
        m_desktopSwitchButton->setStyleSheet(blueButtonStyle());
        m_desktopSwitchButton->setFixedWidth(32);

        m_desktopCreateButton = new QPushButton(QIcon(":/Icon/desktop_create.svg"), QString(), m_desktopPage);
        m_desktopCreateButton->setToolTip(QStringLiteral("新建桌面：在弹出窗口中设置名称、权限、安全描述符和私有访问参数"));
        m_desktopCreateButton->setStyleSheet(blueButtonStyle());
        m_desktopCreateButton->setFixedWidth(32);

        m_desktopStatusLabel = new QLabel(
            QStringLiteral("支持枚举窗口站/桌面；切换会尝试“桌面名”和“窗口站\\\\桌面名”两种方式。"),
            m_desktopPage);
        m_desktopStatusLabel->setWordWrap(true);

        m_desktopToolLayout->addWidget(m_desktopRefreshButton, 0);
        m_desktopToolLayout->addWidget(m_desktopSwitchButton, 0);
        m_desktopToolLayout->addWidget(m_desktopCreateButton, 0);
        m_desktopToolLayout->addWidget(m_desktopStatusLabel, 1);
        ks::ui::NormalizeToolbarRow(m_desktopToolLayout);
        m_desktopPageLayout->addLayout(m_desktopToolLayout, 0);

        m_desktopTable = new ks::ui::TableActionTableView(m_desktopPage);
        initializeDesktopTableModel();
        m_desktopTable->installEventFilter(this);
        m_desktopStatusLabel->setToolTip(m_desktopStatusLabel->text());
        m_desktopStatusLabel->setText(QStringLiteral("未读取"));
        m_desktopTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_desktopTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_desktopTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_desktopTable->setAlternatingRowColors(true);
        m_desktopTable->setContextMenuPolicy(Qt::CustomContextMenu);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(10, QHeaderView::Stretch);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(11, QHeaderView::ResizeToContents);
        m_desktopTable->horizontalHeader()->setSectionResizeMode(12, QHeaderView::Stretch);
        m_desktopTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
        m_desktopPageLayout->addWidget(m_desktopTable, 1);

        m_navigationTabs.add(kWindowNavigation[1], m_contentTabWidget, m_desktopPage);

    }

    // 底部状态栏：展示总数、可见数、系统窗口数和当前选中信息。
    m_statusBar = new QStatusBar(this);
    m_totalLabel = new QLabel(QStringLiteral("总数: 0"), m_statusBar);
    m_visibleLabel = new QLabel(QStringLiteral("可见: 0"), m_statusBar);
    m_systemLabel = new QLabel(QStringLiteral("系统: 0"), m_statusBar);
    m_selectedLabel = new QLabel(QStringLiteral("选中: -"), m_statusBar);
    m_statusBar->addWidget(m_totalLabel, 0);
    m_statusBar->addWidget(m_visibleLabel, 0);
    m_statusBar->addWidget(m_systemLabel, 0);
    m_statusBar->addPermanentWidget(m_selectedLabel, 1);
    m_rootLayout->addWidget(m_statusBar, 0);

    // 自动刷新定时器：由勾选框控制启动和停止。
    m_autoRefreshTimer = new QTimer(this);
    m_autoRefreshTimer->setInterval(m_autoRefreshIntervalSpin->value());

    // Desktop enumeration starts on the actual table Show event below.
    // 页头、内容Tab及状态栏共享同一外壳，四角只放在整页根并保留原4px留白。
    ks::ui::StyleWorkspaceContentFrame(this, 4);
}

void OtherDock::initializeConnections()
{
    // 手动刷新：触发后台枚举。
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[OtherDock] 用户点击刷新窗口列表。"
            << eol;
        refreshWindowListAsync();
    });
    connect(m_clearExternalProcessFilterButton, &QPushButton::clicked, this, [this]() {
        clearExternalProcessFilter();
    });

    // 自动刷新开关：勾选后按间隔周期刷新。
    connect(m_autoRefreshCheck, &QCheckBox::toggled, this, [this](bool checked) {
        kLogEvent event;
        info << event
            << "[OtherDock] 自动刷新状态切换, enabled="
            << (checked ? "true" : "false")
            << ", intervalMs="
            << m_autoRefreshIntervalSpin->value()
            << eol;
        if (checked)
        {
            m_autoRefreshTimer->start(m_autoRefreshIntervalSpin->value());
        }
        else
        {
            m_autoRefreshTimer->stop();
        }
    });

    // 自动刷新间隔变化时，立即更新正在运行的定时器。
    connect(m_autoRefreshIntervalSpin, &QSpinBox::valueChanged, this, [this](int value) {
        m_autoRefreshTimer->setInterval(value);
        kLogEvent event;
        info << event
            << "[OtherDock] 自动刷新间隔更新, intervalMs="
            << value
            << ", timerActive="
            << (m_autoRefreshTimer->isActive() ? "true" : "false")
            << eol;
        if (m_autoRefreshCheck->isChecked())
        {
            m_autoRefreshTimer->start(value);
        }
    });

    // 过滤、分组、视图切换均可直接重绘当前快照，无需重新枚举。
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString& text) {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 关键字过滤变更, keyword="
            << text.toStdString()
            << eol;
        m_windowProjectionDirty = true;
        m_windowFilterTimer->start();
    });
    connect(m_filterModeCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        kLogEvent event;
        info << event
            << "[OtherDock] 过滤模式切换, mode="
            << filterModeText(index).toStdString()
            << eol;
        rebuildWindowTreeFromSnapshot();
    });
    connect(m_enumModeCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        kLogEvent event;
        info << event
            << "[OtherDock] 枚举模式切换, mode="
            << enumModeText(index).toStdString()
            << eol;
        refreshWindowListAsync();
    });
    connect(m_groupModeCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        kLogEvent event;
        info << event
            << "[OtherDock] 分组模式切换, mode="
            << groupModeText(index).toStdString()
            << eol;
        rebuildWindowTreeFromSnapshot();
    });
    connect(m_viewModeCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        kLogEvent event;
        info << event
            << "[OtherDock] 视图模式切换, mode="
            << viewModeText(index).toStdString()
            << eol;
        applyViewMode();
    });

    // 导出当前可见行。
    connect(m_exportButton, &QPushButton::clicked, this, [this]() {
        kLogEvent event;
        info << event
            << "[OtherDock] 用户点击导出窗口列表。"
            << eol;
        exportVisibleRowsToTsv();
    });

    // 自动刷新定时器回调。
    connect(m_autoRefreshTimer, &QTimer::timeout, this, [this]() {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 自动刷新定时器触发。"
            << eol;
        refreshWindowListAsync(false);
    });

    // 右键菜单：窗口操作入口。
    connect(m_windowTree, &QTreeView::customContextMenuRequested, this, [this](const QPoint& pos) {
        showWindowContextMenu(pos);
    });

    // 防截图保护按钮：对当前选中窗口执行启用/取消操作。
    connect(m_protectCaptureButton, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindows(true);
    });
    connect(m_unprotectCaptureButton, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindows(false);
    });

    // 双击行：直接打开窗口详细信息。
    ks::ui::InstallKeyboardItemActivation(m_windowTree);
    connect(m_windowTree, &QTreeView::doubleClicked, this, [this](const QModelIndex& item) {
        if (!item.isValid() || item.data(Qt::UserRole + 1).toBool())
        {
            return;
        }
        const quint64 hwndValue = item.data(Qt::UserRole).toULongLong();
        const WindowInfo* windowInfo = findInfoByHwnd(hwndValue);
        if (windowInfo != nullptr && ks::windowlist::identity(*windowInfo) == ks::window::windowItemIdentity(item))
        {
            kLogEvent event;
            info << event
                << "[OtherDock] 双击窗口项，打开详情, hwnd="
                << hwndToText(windowInfo->hwndValue).toStdString()
                << ", pid="
                << windowInfo->processId
                << eol;
            openWindowDetailDialog(*windowInfo);
        }
    });

    // Preview follows the current selected leaf; the status counts the whole selection.
    connect(m_windowTree->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex&, const QModelIndex&) { scheduleWindowSelectionUi(); });
    connect(m_windowTree->selectionModel(), &QItemSelectionModel::selectionChanged, this,
        [this](const QItemSelection&, const QItemSelection&) { scheduleWindowSelectionUi(); });

    // 截图按钮：把当前选中窗口抓图并保存到文件。
    connect(m_captureButton, &QPushButton::clicked, this, [this]() {
        const auto item = m_windowTree->currentIndex();
        if (!item.isValid() || item.data(Qt::UserRole + 1).toBool())
        {
            kLogEvent event;
            warn << event
                << "[OtherDock] 截图失败：未选中有效窗口。"
                << eol;
            QMessageBox::information(this, QStringLiteral("窗口截图"), QStringLiteral("请先选中一个窗口。"));
            return;
        }

        const quint64 hwndValue = item.data(Qt::UserRole).toULongLong();
        const auto selected = selectedWindowSnapshots();
        if (selected.size() != 1 || selected.front().hwndValue != hwndValue ||
            !selected.front().valid || !selected.front().visible || selected.front().minimized ||
            selected.front().windowRect.isEmpty() ||
            (selected.front().displayAffinityKnown && selected.front().displayAffinityValue != WDA_NONE))
        {
            QMessageBox::warning(this, QStringLiteral("窗口截图"), QStringLiteral("抓图失败。"));
            return;
        }
        const QPixmap pixmap = grabWindowPreviewPixmap(hwndValue, QSize(900, 600));
        if (pixmap.isNull())
        {
            kLogEvent event;
            err << event
                << "[OtherDock] 截图抓取失败, hwnd="
                << hwndToText(hwndValue).toStdString()
                << eol;
            QMessageBox::warning(this, QStringLiteral("窗口截图"), QStringLiteral("抓图失败。"));
            return;
        }

        const QString defaultName = QStringLiteral("window_capture_%1_%2.png")
            .arg(QString::number(hwndValue, 16).toUpper())
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
        const QString savePath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("保存窗口截图"),
            defaultName,
            QStringLiteral("PNG 图片 (*.png)"));
        if (savePath.trimmed().isEmpty())
        {
            kLogEvent event;
            dbg << event
                << "[OtherDock] 截图保存取消, hwnd="
                << hwndToText(hwndValue).toStdString()
                << eol;
            return;
        }

        if (!pixmap.save(savePath))
        {
            kLogEvent event;
            err << event
                << "[OtherDock] 截图保存失败, hwnd="
                << hwndToText(hwndValue).toStdString()
                << ", path="
                << savePath.toStdString()
                << eol;
            QMessageBox::warning(this, QStringLiteral("窗口截图"), QStringLiteral("保存失败：%1").arg(savePath));
            return;
        }
        kLogEvent event;
        info << event
            << "[OtherDock] 截图保存成功, hwnd="
            << hwndToText(hwndValue).toStdString()
            << ", path="
            << savePath.toStdString()
            << eol;
        QMessageBox::information(this, QStringLiteral("窗口截图"), QStringLiteral("截图已保存：%1").arg(savePath));
    });

    if (m_desktopTable != nullptr)
    {
        // 桌面管理页连接：刷新、切换、新建、双击和右键菜单分别进入对应桌面操作链路。
        connect(m_desktopRefreshButton, &QPushButton::clicked, this, [this]() {
            kLogEvent event;
            info << event
                << "[OtherDock] 用户点击刷新桌面列表。"
                << eol;
            refreshDesktopList();
        });
        connect(m_desktopSwitchButton, &QPushButton::clicked, this, [this]() {
            switchToSelectedDesktop();
        });
        connect(m_desktopCreateButton, &QPushButton::clicked, this, [this]() {
            showCreateDesktopDialog();
        });
        ks::ui::InstallKeyboardItemActivation(m_desktopTable);
        connect(m_desktopTable, &QTableView::doubleClicked, this, [this](const QModelIndex&) {
            switchToSelectedDesktop();
        });
        connect(m_desktopTable, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
            showDesktopContextMenu(pos);
        });
    }
}

void OtherDock::applyViewMode()
{
    // 图标/列表/详情模式通过列显隐与装饰样式切换实现。
    const int mode = m_viewModeCombo->currentIndex();
    if (mode == 0)
    {
        // 图标视图：保留关键列，降低信息密度。
        for (int col = 0; col < m_windowTree->model()->columnCount(); ++col)
        {
            const bool keepVisible =
                (col == kWindowColumnTitle
                    || col == kWindowColumnHandle
                    || col == kWindowColumnProcessName);
            m_windowTree->setColumnHidden(col, !keepVisible);
        }
        m_windowTree->setIconSize(QSize(20, 20));
    }
    else if (mode == 1)
    {
        // 列表视图：比图标模式多保留 PID、状态、可见性。
        for (int col = 0; col < m_windowTree->model()->columnCount(); ++col)
        {
            const bool keepVisible =
                (col == kWindowColumnTitle
                    || col == kWindowColumnHandle
                    || col == kWindowColumnPid
                    || col == kWindowColumnProcessName
                    || col == kWindowColumnState);
            m_windowTree->setColumnHidden(col, !keepVisible);
        }
        m_windowTree->setIconSize(QSize(16, 16));
    }
    else
    {
        // 详细信息视图：显示所有列，满足审计场景。
        for (int col = 0; col < m_windowTree->model()->columnCount(); ++col)
        {
            m_windowTree->setColumnHidden(col, false);
        }
        m_windowTree->setIconSize(QSize(16, 16));
    }

    // 记录当前视图策略，便于用户反馈“列突然消失”时快速定位。
    kLogEvent event;
    info << event
        << "[OtherDock] 应用视图模式, mode="
        << viewModeText(mode).toStdString()
        << eol;
}

void OtherDock::refreshWindowListAsync(const bool reportProgress)
{
    // Auto ticks never cancel an in-flight sample. Explicit mode/refresh requests
    // merge as latest query; accepted side effects use their separate controller.
    if (!reportProgress && m_windowRefreshOperation->isBusy()) return;
    const int mode = m_enumModeCombo ? m_enumModeCombo->currentIndex() : 0;
    if (reportProgress)
    {
        if (!m_refreshProgressPid) m_refreshProgressPid = kPro.addReusable(this, "窗口", "窗口枚举");
        kPro.set(m_refreshProgressPid, "开始枚举窗口", 0, 5.0f);
    }
    struct Request { int mode; std::shared_ptr<const ks::windowlist::Snapshot> previous; };
    m_windowRefreshOperation->submit<Request, std::shared_ptr<const ks::windowlist::Snapshot>>(
        {mode, m_windowState},
        [](const Request& value, const ks::ui::AsyncOperationToken& token) {
            std::vector<WindowInfo> current;
            collectWindowSnapshotByMode(value.mode, current);
            if (token.isCanceled()) return std::shared_ptr<const ks::windowlist::Snapshot>();
            return ks::windowlist::mergeSnapshot(std::move(current), value.previous);
        },
        [this, reportProgress](const std::shared_ptr<const ks::windowlist::Snapshot>& result, std::uint64_t) {
            if (!result) return true;
            m_windowState = result;
            m_windowProjectionDirty = true;
            updateStatusBar();
            rebuildWindowTreeFromSnapshot();
            if (reportProgress) kPro.set(m_refreshProgressPid, "窗口枚举完成", 0, 100.0f);
            return true;
        }, [](std::exception_ptr) {});
}

void OtherDock::rebuildWindowTreeFromSnapshot()
{
    m_windowProjectionDirty = true;
    if (!m_windowTree->isVisible()) return;
    ks::windowlist::ProjectionRequest request;
    request.state = m_windowState;
    request.previous = m_windowModel->snapshot;
    request.processIds = m_externalProcessIdFilterSet;
    request.keyword = m_filterEdit->text().trimmed().toLower();
    request.filter = m_filterModeCombo->currentIndex();
    request.grouping = m_groupModeCombo->currentIndex();
    request.desktopHwnd = static_cast<quint64>(reinterpret_cast<quintptr>(::GetDesktopWindow()));
    request.language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    for (const auto* screen : QGuiApplication::screens())
        if (screen) request.screens.emplace_back(screen->geometry(), screen->name());
    m_windowProjectionOperation->submit<ks::windowlist::ProjectionRequest, std::shared_ptr<const ks::windowlist::Projection>>(
        std::move(request),
        [](const ks::windowlist::ProjectionRequest& value, const ks::ui::AsyncOperationToken& token) {
            return ks::windowlist::prepareProjection(value, &token);
        },
        [this, sourceState = m_windowState](const std::shared_ptr<const ks::windowlist::Projection>& result, std::uint64_t generation) {
            const auto commit = [this, result, sourceState, generation] {
                if (!m_windowProjectionOperation->isCurrent(generation)) return;
                if (result && sourceState == m_windowState && m_windowTree->isVisible())
                {
                    if (result == m_windowModel->snapshot)
                    {
                        m_windowProjectionDirty = false;
                        scheduleWindowSelectionUi();
                        m_windowProjectionOperation->completeDeferred(generation);
                        return;
                    }
                }
                if (result && sourceState == m_windowState && m_windowTree->isVisible())
                {
                    const auto selected = ks::window::captureWindowSelection(m_windowTree);
                    QSet<QString> expanded;
                    const bool sameGrouping = m_windowModel->snapshot && m_windowModel->snapshot->grouping == result->grouping;
                    if (m_windowModel->snapshot)
                        for (int root : m_windowModel->snapshot->roots)
                        {
                            const auto index = m_windowModel->nodeIndex(root);
                            if (m_windowTree->isExpanded(index)) expanded.insert(m_windowModel->key(index));
                        }
                    const auto top = m_windowTree->indexAt(QPoint(0, 0));
                    const QString topKey = m_windowModel->key(top);
                    const int topOffset = top.isValid() ? m_windowTree->visualRect(top).top() : 0;
                    const QPointer<OtherDock> alive(this);
                    m_windowModel->publish(result);
                    if (!alive) return;
                    if (!sameGrouping) { m_windowTree->expandToDepth(0); if (!alive) return; }
                    else
                    {
                        // One shared view expansion pass avoids requesting a full
                        // layout after each of thousands of process-group roots.
                        m_windowTree->expandToDepth(0);
                        if (!alive) return;
                        for (int root : result->roots)
                        {
                            const auto index = m_windowModel->nodeIndex(root);
                            if (index.data(Qt::UserRole + 1).toBool() && !expanded.contains(m_windowModel->key(index)))
                            {
                                m_windowTree->setExpanded(index, false);
                                if (!alive) return;
                            }
                        }
                    }
                    if (!alive) return;
                    std::vector<int> selectedNodes;
                    selectedNodes.reserve(selected.identities.size());
                    for (const auto& key : selected.identities)
                    {
                        const auto found = result->byIdentity.constFind(key);
                        if (found != result->byIdentity.cend()) selectedNodes.push_back(found.value());
                    }
                    std::sort(selectedNodes.begin(), selectedNodes.end(), [&result](int left, int right) {
                        const auto& a = result->nodes[left]; const auto& b = result->nodes[right];
                        return a.parent != b.parent ? a.parent < b.parent : a.row < b.row;
                    });
                    QItemSelection selection;
                    for (size_t begin = 0; begin < selectedNodes.size();)
                    {
                        size_t end = begin;
                        while (end + 1 < selectedNodes.size() &&
                            result->nodes[selectedNodes[end + 1]].parent == result->nodes[selectedNodes[begin]].parent &&
                            result->nodes[selectedNodes[end + 1]].row == result->nodes[selectedNodes[end]].row + 1) ++end;
                        selection.select(m_windowModel->nodeIndex(selectedNodes[begin]), m_windowModel->nodeIndex(selectedNodes[end], 12));
                        begin = end + 1;
                    }
                    m_windowTree->selectionModel()->select(selection, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    if (!alive) return;
                    const auto current = m_windowModel->indexForIdentity(selected.current);
                    if (current.isValid()) m_windowTree->selectionModel()->setCurrentIndex(current, QItemSelectionModel::NoUpdate);
                    if (!alive) return;
                    const auto anchor = m_windowModel->indexForIdentity(topKey);
                    if (anchor.isValid())
                    {
                        m_windowTree->scrollTo(anchor, QAbstractItemView::PositionAtTop);
                        if (m_windowTree->verticalScrollMode() == QAbstractItemView::ScrollPerPixel)
                            m_windowTree->verticalScrollBar()->setValue(m_windowTree->verticalScrollBar()->value() - topOffset);
                    }
                    if (!alive) return;
                    m_windowProjectionDirty = false;
                    scheduleWindowSelectionUi();
                }
                m_windowProjectionOperation->completeDeferred(generation);
            };
            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
                QStringLiteral("window_tree_rebuild"), {m_windowTree}, commit)) return false;
            commit(); return true;
        }, [](std::exception_ptr) {});
}

void OtherDock::updateStatusBar()
{
    m_totalLabel->setText(QStringLiteral("总数: %1").arg(m_windowState ? m_windowState->total : 0));
    m_visibleLabel->setText(QStringLiteral("可见: %1").arg(m_windowState ? m_windowState->visible : 0));
    m_systemLabel->setText(QStringLiteral("系统: %1").arg(m_windowState ? m_windowState->system : 0));
}

void OtherDock::updatePreviewPanel(const WindowInfo* info)
{
    // 隐藏只延后预览投影，不影响窗口枚举及其新增/退出状态。
    if (!m_previewWidget->isVisible())
    {
        m_previewCaptureDue = true;
        return;
    }
    const QString identity = info ? ks::window::windowIdentityKey(info->hwndValue,
        info->processId, info->threadId, info->processCreationTime100ns) : QString();
    if (!info)
    {
        if (!m_previewIdentity.isEmpty() || m_previewSummaryKey.isEmpty())
        {
            if (m_previewScaleOperation) m_previewScaleOperation->cancel();
            m_thumbnailLabel->clear();
            m_thumbnailLabel->hide();
            m_quickInfoText->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择左侧窗口项查看预览。")));
        }
        m_previewIdentity.clear();
        m_previewSummaryKey = QByteArrayLiteral("empty");
        m_previewCaptureDue = true;
        return;
    }
    const bool targetChanged = identity != m_previewIdentity;
    if (targetChanged)
    {
        m_previewIdentity = identity;
        m_previewCaptureDue = true;
        m_thumbnailLabel->setPixmap(QPixmap());
    }
    const auto showUnavailable = [this](const QString& message)
    {
        if (m_previewScaleOperation && m_previewScaleOperation->isBusy()) m_previewScaleOperation->cancel();
        if (m_thumbnailLabel->margin() != 8) m_thumbnailLabel->setMargin(8);
        m_thumbnailLabel->show();
        if (m_thumbnailLabel->minimumHeight() != 0 || m_thumbnailLabel->maximumHeight() != QWIDGETSIZE_MAX)
        {
            m_thumbnailLabel->setMinimumHeight(0);
            m_thumbnailLabel->setMaximumHeight(QWIDGETSIZE_MAX);
        }
        if (m_thumbnailLabel->sizePolicy().verticalPolicy() != QSizePolicy::Maximum)
            m_thumbnailLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Maximum);
        if (m_previewSize.isValid() || m_thumbnailLabel->text() != message)
        {
            m_thumbnailLabel->clear();
            m_thumbnailLabel->setText(message);
        }
        m_previewSize = QSize();
        m_previewDpr = 0.0;
        m_previewCaptureDue = false;
    };
    const HWND targetWindow = reinterpret_cast<HWND>(static_cast<quintptr>(info->hwndValue));
    const WId hostWindowId = m_previewWidget->window()->effectiveWinId();
    QString unavailable;
    if (!info->valid || info->windowRect.isEmpty() || !::IsWindow(targetWindow))
        unavailable = ks::i18n::contextText(QStringLiteral("other.thumbnail.none"), QStringLiteral("无可用缩略图"));
    else if (!info->visible || !::IsWindowVisible(targetWindow))
        unavailable = ks::i18n::contextText(QStringLiteral("other.thumbnail.hidden"), QStringLiteral("隐藏窗口无法预览"));
    else if (info->minimized || ::IsIconic(targetWindow))
        unavailable = ks::i18n::contextText(QStringLiteral("other.thumbnail.minimized"), QStringLiteral("最小化窗口无法预览"));
    else if (info->displayAffinityKnown && info->displayAffinityValue != WDA_NONE)
        unavailable = ks::i18n::contextText(QStringLiteral("other.thumbnail.restricted"), QStringLiteral("窗口限制截图"));
    else if (hostWindowId != 0 && info->hwndValue == static_cast<quint64>(hostWindowId))
        unavailable = ks::i18n::contextText(QStringLiteral("other.thumbnail.current"), QStringLiteral("当前窗口无法预览"));
    if (!unavailable.isEmpty())
    {
        showUnavailable(unavailable);
    }
    else
    {
        if (m_thumbnailLabel->margin() != 0) m_thumbnailLabel->setMargin(0);
        m_thumbnailLabel->show();
        // previewHeight：沿用原有高度预算；固定纵向策略让布局实际为图片预留空间。
        // Ignored 会让后续字段工具栏按零高度图片排布，覆盖仍有最小高度的 QLabel。
        const int previewHeight = std::clamp(m_previewWidget->height() / 3, 120, 220);
        if (m_thumbnailLabel->minimumHeight() != previewHeight ||
            m_thumbnailLabel->maximumHeight() != previewHeight)
        {
            m_thumbnailLabel->setFixedHeight(previewHeight);
        }
        if (m_thumbnailLabel->sizePolicy().verticalPolicy() != QSizePolicy::Fixed)
            m_thumbnailLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        if (!m_thumbnailLabel->text().isEmpty()) m_thumbnailLabel->setText(QString());
        m_previewLayout->activate();
        const QSize targetSize = m_thumbnailLabel->contentsRect().size();
        const qreal dpr = m_thumbnailLabel->devicePixelRatioF();
        if (targetSize != m_previewSize || dpr != m_previewDpr)
            m_previewCaptureDue = true;
        if (!targetSize.isEmpty() && m_previewCaptureDue && m_previewScaleOperation &&
            (targetChanged || !m_previewScaleOperation->isBusy()))
        {
            // QScreen/QPixmap remain on their GUI thread. Only owned QImage pixels
            // and size/DPR values cross the worker boundary.
            QPixmap source;
            if (info->valid && !info->windowRect.isEmpty())
                if (auto* screen = QGuiApplication::primaryScreen())
                    source = screen->grabWindow(static_cast<WId>(info->hwndValue));
            m_previewCaptureDue = false;
            m_previewSize = targetSize;
            m_previewDpr = dpr;
            if (source.isNull())
            {
                showUnavailable(ks::i18n::contextText(
                    QStringLiteral("other.thumbnail.none"), QStringLiteral("无可用缩略图")));
            }
            else
            {
                struct ScaleRequest { QImage image; QSize size; qreal dpr; QString identity; };
                struct ScaleResult { QImage image; QSize size; qreal dpr; QString identity; };
                m_previewScaleOperation->submit<ScaleRequest, ScaleResult>(
                    {source.toImage(), targetSize, dpr, identity},
                    [](const ScaleRequest& value, const ks::ui::AsyncOperationToken&) {
                        QImage scaled = value.image.scaled(value.size * value.dpr,
                            Qt::KeepAspectRatio, Qt::SmoothTransformation);
                        scaled.setDevicePixelRatio(value.dpr);
                        return ScaleResult{std::move(scaled), value.size, value.dpr, value.identity};
                    },
                    [this](const ScaleResult& result, std::uint64_t) {
                        const auto current = m_windowTree->currentIndex();
                        if (!current.isValid() || !m_windowTree->selectionModel()->isSelected(current) || ks::window::windowItemIdentity(current) != result.identity ||
                            result.identity != m_previewIdentity || !m_thumbnailLabel->isVisible() ||
                            result.size != m_thumbnailLabel->contentsRect().size() || result.dpr != m_thumbnailLabel->devicePixelRatioF())
                        {
                            m_previewCaptureDue = true;
                            return true;
                        }
                        m_thumbnailLabel->setPixmap(QPixmap::fromImage(result.image));
                        return true;
                    },
                    [this](std::exception_ptr) { m_previewCaptureDue = true; });
            }
        }
    }
    QByteArray summaryKey;
    QDataStream summaryStream(&summaryKey, QIODevice::WriteOnly);
    summaryStream << identity << info->titleText << info->classNameText << info->processNameText
        << info->windowRect << info->visible << info->enabled << info->topMost << info->valid
        << info->minimized << info->maximized << info->alphaValue << info->displayAffinityKnown
        << info->displayAffinityValue << info->displayAffinityError
        << KswordTheme::SurfaceColor().rgba() << ks::i18n::LanguageManager::instance().currentLanguageId();
    if (summaryKey == m_previewSummaryKey) return;
    m_previewSummaryKey = summaryKey;

    ks::ui::FieldDocument quickText;
    quickText.field(QStringLiteral("句柄"), QStringLiteral("%1").arg(hwndToText(info->hwndValue)));
    quickText.field(QStringLiteral("标题"), QStringLiteral("%1").arg(info->titleText));
    quickText.field(QStringLiteral("类名"), QStringLiteral("%1").arg(info->classNameText));
    quickText.field(QStringLiteral("PID/TID"), QStringLiteral("%1 / %2").arg(QStringLiteral("%1").arg(info->processId)).arg(QStringLiteral("%1").arg(info->threadId)));
    quickText.field(QStringLiteral("进程名"), QStringLiteral("%1").arg(info->processNameText));
    quickText.field(QStringLiteral("矩形"), QStringLiteral("[%1,%2,%3,%4]").arg(QStringLiteral("%1").arg(info->windowRect.left())).arg(QStringLiteral("%1").arg(info->windowRect.top())).arg(QStringLiteral("%1").arg(info->windowRect.right())).arg(QStringLiteral("%1").arg(info->windowRect.bottom())));
    quickText.field(QStringLiteral("可见"), QStringLiteral("%1").arg(boolText(info->visible)));
    quickText.field(QStringLiteral("可用"), QStringLiteral("%1").arg(boolText(info->enabled)));
    quickText.field(QStringLiteral("顶层"), QStringLiteral("%1").arg(boolText(info->topMost)));
    quickText.field(QStringLiteral("状态"), QStringLiteral("%1").arg(windowStateText(info->valid, info->minimized, info->maximized)));
    quickText.field(QStringLiteral("透明度"), QStringLiteral("%1").arg(info->alphaValue));
    if (info->displayAffinityKnown)
    {
        const QString affinityHexText =
            QString::number(static_cast<qulonglong>(info->displayAffinityValue), 16).toUpper();
        quickText.field(QStringLiteral("DisplayAffinity"), QStringLiteral("0x%1 (%2)").arg(QStringLiteral("%1").arg(affinityHexText)).arg(QStringLiteral("%1").arg(QString::fromStdString(ks::window::DisplayAffinityName(info->displayAffinityValue)))));
    }
    else
    {
        quickText.field(QStringLiteral("DisplayAffinity"), QStringLiteral("未知（错误码=%1）").arg(QStringLiteral("%1").arg(info->displayAffinityError)));
    }
    m_quickInfoText->setDocument(quickText);

    kLogEvent event;
    dbg << event
        << "[OtherDock] 预览面板刷新, hwnd="
        << hwndToText(info->hwndValue).toStdString()
        << ", pid="
        << info->processId
        << eol;
}

void OtherDock::handleWindowPicked(quintptr hwndValue)
{
    kLogEvent pickEvent;
    HWND rawWindowHandle = reinterpret_cast<HWND>(hwndValue);
    HWND rootWindowHandle = rawWindowHandle != nullptr ? ::GetAncestor(rawWindowHandle, GA_ROOT) : nullptr;
    HWND targetWindowHandle = rawWindowHandle != nullptr ? rawWindowHandle : rootWindowHandle;

    if (targetWindowHandle == nullptr || ::IsWindow(targetWindowHandle) == FALSE)
    {
        warn << pickEvent
            << "[OtherDock] 准星拾取失败：WindowFromPoint 未命中有效窗口。"
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("窗口拾取"),
            QStringLiteral("未命中可用窗口，请重试。"));
        return;
    }

    const quint64 rawHwndValue = static_cast<quint64>(
        reinterpret_cast<quintptr>(rawWindowHandle));
    const quint64 rootHwndValue = static_cast<quint64>(
        reinterpret_cast<quintptr>(rootWindowHandle));
    quint64 targetHwndValue = rawHwndValue;

    // 优先按“鼠标下原始窗口”匹配，若未命中再回退到顶级窗口匹配。
    const WindowInfo* pickedInfo = findInfoByHwnd(rawHwndValue);
    if (pickedInfo == nullptr && rootHwndValue != 0 && rootHwndValue != rawHwndValue)
    {
        pickedInfo = findInfoByHwnd(rootHwndValue);
        targetWindowHandle = rootWindowHandle;
        targetHwndValue = rootHwndValue;
    }
    else
    {
        targetWindowHandle = rawWindowHandle;
        targetHwndValue = rawHwndValue;
    }

    // fallbackInfo 用于兜底构造详情数据，避免必须先刷新列表才能查看目标窗口。
    WindowInfo fallbackInfo;
    if (pickedInfo == nullptr)
    {
        const bool childFlag = ::GetParent(targetWindowHandle) != nullptr;
        fillWindowInfo(
            targetWindowHandle,
            -1,
            childFlag,
            QStringLiteral("WindowPicker"),
            fallbackInfo);
        pickedInfo = &fallbackInfo;

        warn << pickEvent
            << "[OtherDock] 准星拾取命中窗口不在当前快照，已使用即时查询兜底, hwnd="
            << hwndToText(targetHwndValue).toStdString()
            << eol;
    }

    if (pickedInfo == nullptr)
    {
        err << pickEvent
            << "[OtherDock] 准星拾取失败：无法构造窗口详情。"
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("窗口拾取"),
            QStringLiteral("读取目标窗口信息失败。"));
        return;
    }

    info << pickEvent
        << "[OtherDock] 准星拾取成功，打开窗口详情, hwnd="
        << hwndToText(pickedInfo->hwndValue).toStdString()
        << ", pid="
        << pickedInfo->processId
        << eol;
    openWindowDetailDialog(*pickedInfo);
}

std::vector<OtherDock::WindowInfo> OtherDock::selectedWindowSnapshots() const
{
    std::vector<WindowInfo> windows;
    const auto selection = ks::window::captureWindowSelection(m_windowTree);
    for (const quint64 hwnd : ks::window::selectedWindowHandles(m_windowTree))
    {
        const auto* window = findInfoByHwnd(hwnd);
        if (window && selection.identities.contains(ks::window::windowIdentityKey(
            window->hwndValue, window->processId, window->threadId, window->processCreationTime100ns)))
            windows.push_back(*window);
    }
    return windows;
}

bool OtherDock::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_desktopTable && event->type() == QEvent::LanguageChange && m_desktopSnapshot)
        refreshDesktopPresentation();
    if (watched == m_windowTree && event->type() == QEvent::LanguageChange)
    {
        m_windowProjectionDirty = true;
        QTimer::singleShot(0, this, [this] { rebuildWindowTreeFromSnapshot(); });
    }
    if (watched == m_desktopTable && event->type() == QEvent::Show)
    {
        if (!m_desktopLoaded) refreshDesktopList();
        else if (m_desktopProjectionDirty) refreshDesktopPresentation();
    }

    if (watched == m_windowTree && event->type() == QEvent::Show && m_windowProjectionDirty)
        QTimer::singleShot(0, this, [this] { if (m_windowProjectionDirty) rebuildWindowTreeFromSnapshot(); });

    if (watched == m_thumbnailLabel &&
        (event->type() == QEvent::Show || event->type() == QEvent::Resize ||
         event->type() == QEvent::DevicePixelRatioChange || event->type() == QEvent::PaletteChange))
    {
        m_previewCaptureDue = true;
        scheduleWindowSelectionUi();
    }
    return QWidget::eventFilter(watched, event);
}

void OtherDock::scheduleWindowSelectionUi()
{
    if (m_selectionUiQueued) return;
    m_selectionUiQueued = true;
    QTimer::singleShot(0, this, [this] {
        m_selectionUiQueued = false;
        updateWindowSelectionUi();
    });
}

void OtherDock::updateWindowSelectionUi()
{
    const auto windows = selectedWindowSnapshots();
    const auto current = m_windowTree->currentIndex();
    const auto previewIt = std::find_if(windows.begin(), windows.end(), [current](const WindowInfo& window) {
        return current.isValid() && !current.data(Qt::UserRole + 1).toBool()
            && window.hwndValue == current.data(Qt::UserRole).toULongLong();
    });
    const WindowInfo* preview = previewIt != windows.end() ? &*previewIt : nullptr;
    updatePreviewPanel(preview);
    if (windows.empty()) m_selectedLabel->setText(QStringLiteral("选中: -"));
    else if (windows.size() == 1)
        m_selectedLabel->setText(QStringLiteral("选中: %1  %2")
            .arg(hwndToText(windows.front().hwndValue), windows.front().titleText));
    else m_selectedLabel->setText(QStringLiteral("选中: %1 个窗口").arg(windows.size()));
    m_protectCaptureButton->setEnabled(!windows.empty() && !windowTransactionBusy());
    m_unprotectCaptureButton->setEnabled(!windows.empty() && !windowTransactionBusy());
    const HWND previewWindow = preview
        ? reinterpret_cast<HWND>(static_cast<quintptr>(preview->hwndValue)) : nullptr;
    const bool previewCapturable = preview && preview->valid && preview->visible &&
        !preview->minimized && !preview->windowRect.isEmpty() &&
        !(preview->displayAffinityKnown && preview->displayAffinityValue != WDA_NONE) &&
        ::IsWindow(previewWindow) && ::IsWindowVisible(previewWindow) && !::IsIconic(previewWindow);
    const bool captureEnabled = windows.size() == 1 && previewCapturable;
    m_captureButton->setEnabled(captureEnabled);
    const QString captureHint = captureEnabled ? QStringLiteral("保存当前窗口截图")
        : (windows.size() != 1 || !preview)
            ? ks::i18n::contextText(QStringLiteral("other.thumbnail.select_one"), QStringLiteral("请选择一个窗口以保存截图"))
            : m_thumbnailLabel->text().isEmpty()
                ? ks::i18n::contextText(QStringLiteral("other.thumbnail.none"), QStringLiteral("无可用缩略图"))
                : m_thumbnailLabel->text();
    if (m_captureButton->toolTip() != captureHint) m_captureButton->setToolTip(captureHint);
    m_windowInputButton->setEnabled(windows.size() == 1);
}

void OtherDock::showWindowContextMenu(const QPoint& localPos)
{
    const auto item = m_windowTree->indexAt(localPos);
    if (!item.isValid()) return;
    // Right-clicking within a selection must keep the other selected rows.
    ks::window::selectContextWindow(m_windowTree, item);
    // Copy before QMenu::exec: timers and asynchronous enumeration can replace
    // snapshots while the menu or an operation feedback dialog is open.
    const auto windows = selectedWindowSnapshots();
    if (windows.empty()) return;
    const bool multiple = windows.size() > 1;

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    if (multiple)
    {
        auto* count = menu.addAction(QStringLiteral("已选中 %1 个窗口").arg(windows.size()));
        count->setEnabled(false);
        menu.addSeparator();
    }
    auto* activate = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("激活窗口"));
    activate->setEnabled(!multiple);
    auto* topMost = menu.addAction(QIcon(":/Icon/process_priority.svg"),
        multiple ? QStringLiteral("置顶窗口") : QStringLiteral("置顶/取消置顶"));
    auto* notTopMost = multiple ? menu.addAction(QStringLiteral("取消置顶")) : nullptr;
    auto* show = menu.addAction(QIcon(":/Icon/process_pause.svg"),
        multiple ? QStringLiteral("显示窗口") : QStringLiteral("显示/隐藏"));
    auto* hide = multiple ? menu.addAction(QStringLiteral("隐藏窗口")) : nullptr;
    auto* enable = menu.addAction(QIcon(":/Icon/process_suspend.svg"),
        multiple ? QStringLiteral("启用窗口") : QStringLiteral("启用/禁用"));
    auto* disable = multiple ? menu.addAction(QStringLiteral("禁用窗口")) : nullptr;
    auto* input = menu.addAction(ks::i18n::text(
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序")));
    input->setEnabled(!multiple);
    auto* markPosition = menu.addAction(QIcon(":/Icon/window_picker_target.svg"), QStringLiteral("标记位置"));
    markPosition->setToolTip(QStringLiteral("在全屏透明层中标记所有选中窗口的位置与基本信息；按鼠标左键或右键关闭"));
    auto* protect = menu.addAction(QIcon(":/Icon/titlebar_capture_protected.svg"), QStringLiteral("启用防截图保护"));
    auto* unprotect = menu.addAction(QIcon(":/Icon/titlebar_capture_allowed.svg"), QStringLiteral("取消防截图保护"));
    menu.addSeparator();
    auto* processDetail = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    auto* windowDetail = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("在详细信息中打开"));
    auto* sendMessage = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("发送测试消息"));
    sendMessage->setEnabled(!multiple && !windowTransactionBusy());
    const WindowInfo uploadSnapshot = windows.front();
    auto* upload = ks::online_scan::addVirusTotalSandboxMenu(&menu, this,
        [uploadSnapshot]() -> ks::online_scan::SandboxUploadTarget {
            ks::online_scan::SandboxUploadTarget target;
            target.filePath = uploadSnapshot.processImagePathText;
            target.sourceText = QStringLiteral("窗口 GUI 线程 PID=%1 TID=%2")
                .arg(uploadSnapshot.processId).arg(uploadSnapshot.threadId);
            return target;
        });
    auto* uploadMenu = upload ? qobject_cast<QMenu*>(upload->parent()) : nullptr;
    if (uploadMenu) uploadMenu->menuAction()->setEnabled(!multiple);
    menu.addSeparator();
    auto* terminate = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("结束进程"));
    protect->setEnabled(!windowTransactionBusy());
    unprotect->setEnabled(!windowTransactionBusy());
    auto* action = menu.exec(m_windowTree->viewport()->mapToGlobal(localPos));
    if (!action || (uploadMenu && uploadMenu->actions().contains(action))) return;
    if (action == protect || action == unprotect)
    {
        setCaptureProtectionForWindows(windows, action == protect);
        return;
    }

    if (action == sendMessage)
    {
        sendTestMessagesForWindows(windows);
        return;
    }

    if (action == markPosition)
    {
        QVector<ks::window::WindowPositionMark> marks;
        QStringList failures;
        for (const auto& window : windows)
        {
            ks::window::WindowPositionMark mark;
            if (!window.valid || !ks::window::windowIdentityMatches(window.hwndValue,
                window.processId, window.threadId, window.processCreationTime100ns)
                || !ks::window::queryWindowMarkRect(toHwnd(window.hwndValue), mark.physicalRect))
            {
                failures.push_back(hwndToText(window.hwndValue));
                continue;
            }
            mark.information = {
                window.titleText.isEmpty() ? ks::i18n::sourceText(QStringLiteral("<无标题>")) : window.titleText,
                ks::i18n::sourceText(QStringLiteral("进程: %1  PID/TID: %2 / %3"))
                    .arg(window.processNameText).arg(window.processId).arg(window.threadId),
                ks::i18n::sourceText(QStringLiteral("类名: %1  句柄: %2"))
                    .arg(window.classNameText, hwndToText(window.hwndValue)),
                ks::i18n::sourceText(QStringLiteral("位置: (%1, %2)  大小: %3 × %4  状态: %5"))
                    .arg(mark.physicalRect.x()).arg(mark.physicalRect.y())
                    .arg(mark.physicalRect.width()).arg(mark.physicalRect.height())
                    .arg(ks::i18n::sourceText(windowStateText(window.valid, window.minimized, window.maximized)))};
            marks.push_back(std::move(mark));
        }
        if (!failures.empty())
            QMessageBox::warning(this, QStringLiteral("标记位置"),
                ks::i18n::sourceText(QStringLiteral("以下窗口已失效或无法读取位置：\n%1")).arg(failures.join('\n')));
        if (!marks.empty())
        {
            const QString hint = ks::i18n::sourceText(QStringLiteral("已标记 %1 个窗口；按鼠标左键或右键关闭"))
                .arg(marks.size());
            new ks::window::WindowPositionOverlay(std::move(marks), hint, this);
        }
        return;
    }

    int succeeded = 0;
    QStringList failures;
    QSet<quint32> processedPids;
    for (const auto& window : windows)
    {
        HWND hwnd = toHwnd(window.hwndValue);
        if ((action == terminate || action == processDetail) && processedPids.contains(window.processId)) continue;
        const int failureCountBefore = failures.size();
        bool ok = window.valid && ks::window::windowIdentityMatches(
            window.hwndValue, window.processId, window.threadId, window.processCreationTime100ns);
        if (ok && (action == terminate || action == processDetail)) processedPids.insert(window.processId);
        if (ok && action == input) openWindowDetailDialog(window, true);
        else if (ok && action == windowDetail) openWindowDetailDialog(window);
        else if (ok && action == processDetail)
        {
            if (window.processCreationTime100ns != 0)
                ks::ui::OpenProcessDetailByIdentity(window.processId, window.processCreationTime100ns);
            else openProcessDetailWindow(this, window.processId);
        }
        else if (ok && action == terminate)
        {
            std::string errorText;
            ok = ks::process::TerminateProcessByWin32IfCreationTimeMatches(
                window.processId, window.processCreationTime100ns, &errorText);
            if (!ok) failures.push_back(QStringLiteral("%1: %2")
                .arg(hwndToText(window.hwndValue), QString::fromStdString(errorText)));
        }
        else if (ok && action == activate)
        {
            ::ShowWindowAsync(hwnd, ::IsIconic(hwnd) ? SW_RESTORE : SW_SHOW);
            ok = ::SetForegroundWindow(hwnd) != FALSE;
        }
        else if (ok && (action == topMost || action == notTopMost))
        {
            const bool target = multiple ? action == topMost
                : (::GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) == 0;
            ok = ks::window::setWindowTopMost(hwnd, target);
        }
        else if (ok && (action == show || action == hide))
        {
            const bool target = multiple ? action == show : !::IsWindowVisible(hwnd);
            ok = ks::window::requestWindowVisible(hwnd, target);
        }
        else if (ok && (action == enable || action == disable))
        {
            const bool target = multiple ? action == enable : !::IsWindowEnabled(hwnd);
            ok = ks::window::setWindowEnabled(hwnd, target);
        }
        if (ok) ++succeeded;
        else if (failures.size() == failureCountBefore)
            failures.push_back(hwndToText(window.hwndValue));
    }
    if (action != input && action != windowDetail && action != processDetail)
        refreshWindowListAsync();
    m_statusBar->showMessage(QStringLiteral("操作：%1；成功：%2；失败或已失效：%3")
        .arg(action->text()).arg(succeeded).arg(failures.size()), 5000);
    if (!failures.empty())
        QMessageBox::warning(this, QStringLiteral("窗口操作"),
            QStringLiteral("操作：%1\n成功：%2\n失败或已失效：%3\n%4")
                .arg(action->text()).arg(succeeded).arg(failures.size()).arg(failures.join('\n')));
}

void OtherDock::exportVisibleRowsToTsv()
{
    // 遍历当前树，导出叶子节点；分组节点不参与导出。
    QStringList lines;

    QStringList header;
    for (int col = 0; col < m_windowTree->model()->columnCount(); ++col)
    {
        if (m_windowTree->isColumnHidden(col))
        {
            continue;
        }
        header << m_windowModel->headerData(col, Qt::Horizontal, Qt::DisplayRole).toString();
    }
    lines << header.join('\t');

    const auto projection = m_windowModel->snapshot;
    if (projection)
        for (const auto& node : projection->nodes)
        {
            if (node.group) continue;
            QStringList values;
            for (int column = 0; column < 13; ++column)
                if (!m_windowTree->isColumnHidden(column)) values << QString(node.cells[column]).replace('\t', ' ');
            lines << values.join('\t');
        }

    if (lines.size() <= 1)
    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 导出取消：当前无可见数据行。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出窗口列表"), QStringLiteral("没有可导出的行。"));
        return;
    }

    const QString defaultName = QStringLiteral("window_list_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出窗口列表"),
        defaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));
    if (outputPath.trimmed().isEmpty())
    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 导出取消：用户未选择输出路径。"
            << eol;
        return;
    }

    QFile file(outputPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        kLogEvent event;
        err << event
            << "[OtherDock] 导出失败：无法写入文件, path="
            << outputPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出窗口列表"), QStringLiteral("无法写入文件：%1").arg(outputPath));
        return;
    }

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    for (const QString& line : lines)
    {
        out << line << '\n';
    }
    file.close();

    kLogEvent event;
    info << event << "[OtherDock] 导出窗口列表成功:" << outputPath.toStdString() << eol;
    QMessageBox::information(this, QStringLiteral("导出窗口列表"), QStringLiteral("导出完成：%1").arg(outputPath));
}

void OtherDock::openWindowDetailDialog(const WindowInfo& windowInfo, bool inputSettings)
{
    kLogEvent event;
    info << event
        << "[OtherDock] 打开窗口详情对话框, hwnd="
        << hwndToText(windowInfo.hwndValue).toStdString()
        << ", pid="
        << windowInfo.processId
        << eol;

    WindowDetailDialog* dialog = new WindowDetailDialog(windowInfo, this);
    if (inputSettings)
    {
        auto* page = dialog->findChild<QWidget*>(QStringLiteral("ks_window_input_page"));
        for (auto* tabs : dialog->findChildren<QTabWidget*>())
            if (page && tabs->indexOf(page) >= 0) tabs->setCurrentWidget(page);
    }
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}

const OtherDock::WindowInfo* OtherDock::findInfoByHwnd(const quint64 hwndValue) const
{
    if (!m_windowState) return nullptr;
    const auto found = m_windowState->byHwnd.constFind(hwndValue);
    return found == m_windowState->byHwnd.cend() ? nullptr : &m_windowState->records[found.value()];
}

ks::ui::PageNavigationCatalog OtherDock::navigationCatalog(const OtherDock* existing)
{
    ks::ui::PageNavigationCatalog schema;
    for (const auto& definition : kWindowNavigation)
        schema.append(ks::ui::PageNavigationTabDescriptor(definition));
    return existing ? existing->m_navigationTabs.describe(std::move(schema)) : schema;
}
QWidget* OtherDock::activateNavigationDescriptor(const QString& id)
{
    return m_navigationTabs.activate(id, navigationCatalog(this));
}
namespace { const bool kWindowNavigationRegistered =
    ks::ui::RegisterTypedPageNavigationCatalog<OtherDock>(QStringLiteral("window")); }
