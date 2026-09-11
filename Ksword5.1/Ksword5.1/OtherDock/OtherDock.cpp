#include "OtherDock.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

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
#include "WindowInputControl.h"
#include "../theme.h"
#include "../UI/CodeEditorWidget.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCloseEvent>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
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
#include <QScreen>
#include <QSlider>
#include <QSpinBox>
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
#include <TlHelp32.h>

namespace
{
    // 统一按钮样式：与全局蓝色主题保持一致，避免界面风格割裂。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
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
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // buildOpaqueWindowDetailDialogStyle 作用：
    // - 覆盖父级 Dock 透明样式，避免“窗口详细信息”在浅色主题出现黑底；
    // - 强制文本编辑器/表格/滚动区使用不透明背景。
    QString buildOpaqueWindowDetailDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTabWidget::pane{"
            "  background-color:palette(window) !important;"
            "  border:1px solid palette(mid) !important;"
            "}"
            "QDialog#%1 QPlainTextEdit,"
            "QDialog#%1 QTextEdit,"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
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

    // WindowPickerDragButton：
    // - 作用：在左键按下后抓取鼠标，实现“按住准星拖拽并在任意位置松开”交互；
    // - 调用：由 OtherDock::initializeUi 创建，并通过 setReleaseCallback 绑定释放回调；
    // - 传入：releaseCallback 接收全局坐标；
    // - 传出：无，回调由外部处理具体窗口拾取与详情弹窗。
    class WindowPickerDragButton final : public QPushButton
    {
    public:
        using ReleaseCallback = std::function<void(const QPoint&)>;

        explicit WindowPickerDragButton(QWidget* parent = nullptr)
            : QPushButton(parent)
        {
            // setMouseTracking(true) 作用：在拖拽过程中即使不按键变化也持续接收移动事件。
            setMouseTracking(true);
        }

        // setReleaseCallback：
        // - 作用：注册鼠标释放回调；
        // - 调用：OtherDock 初始化 UI 时绑定；
        // - 传入 callback：释放时接收全局坐标的函数对象；
        // - 传出：无。
        void setReleaseCallback(ReleaseCallback callback)
        {
            m_releaseCallback = std::move(callback);
        }

    protected:
        void mousePressEvent(QMouseEvent* event) override
        {
            if (event != nullptr && event->button() == Qt::LeftButton)
            {
                // m_dragTracking 用于标记当前是否处于“准星拖拽拾取”过程。
                m_dragTracking = true;
                // m_pressGlobalPos 用于记录拖拽起点，配合阈值区分“点击”和“拖拽”。
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                m_pressGlobalPos = event->globalPosition().toPoint();
#else
                m_pressGlobalPos = event->globalPos();
#endif
                m_hasReachedDragThreshold = false;
                // grabMouse + CrossCursor 组合用于把拖拽过程视觉与输入统一到本按钮。
                grabMouse(QCursor(Qt::CrossCursor));
            }
            QPushButton::mousePressEvent(event);
        }

        void mouseMoveEvent(QMouseEvent* event) override
        {
            if (m_dragTracking && event != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                const QPoint currentGlobalPos = event->globalPosition().toPoint();
#else
                const QPoint currentGlobalPos = event->globalPos();
#endif
                const int moveDistance = (currentGlobalPos - m_pressGlobalPos).manhattanLength();
                // m_hasReachedDragThreshold 用于避免“单击按钮”误触发窗口拾取。
                if (moveDistance >= QApplication::startDragDistance())
                {
                    m_hasReachedDragThreshold = true;
                }
            }
            QPushButton::mouseMoveEvent(event);
        }

        void mouseReleaseEvent(QMouseEvent* event) override
        {
            // shouldDispatch 用于确保仅在左键拖拽链路结束时触发窗口拾取回调。
            const bool shouldDispatch =
                m_dragTracking
                && m_hasReachedDragThreshold
                && event != nullptr
                && event->button() == Qt::LeftButton;

            if (m_dragTracking)
            {
                // releaseMouse 作用：结束全局鼠标抓取，避免后续输入被错误劫持。
                releaseMouse();
                m_dragTracking = false;
            }
            m_hasReachedDragThreshold = false;

            QPoint releaseGlobalPos;
            if (event != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                // releaseGlobalPos 用于记录松开鼠标时的屏幕坐标，后续据此 WindowFromPoint。
                releaseGlobalPos = event->globalPosition().toPoint();
#else
                releaseGlobalPos = event->globalPos();
#endif
            }

            QPushButton::mouseReleaseEvent(event);

            if (shouldDispatch && m_releaseCallback)
            {
                m_releaseCallback(releaseGlobalPos);
            }
        }

    private:
        bool m_dragTracking = false;          // m_dragTracking：记录当前是否在拖拽拾取链路中。
        bool m_hasReachedDragThreshold = false; // m_hasReachedDragThreshold：拖拽距离是否达到最小阈值。
        QPoint m_pressGlobalPos;              // m_pressGlobalPos：记录左键按下时的屏幕坐标。
        ReleaseCallback m_releaseCallback;    // m_releaseCallback：鼠标释放时回调到 OtherDock。
    };

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

    // queryProcessLogoIconByPath：
    // - 根据进程路径获取系统文件图标；
    // - 若路径无效或无法提取图标，则回退默认进程图标。
    QIcon queryProcessLogoIconByPath(const QString& imagePathText)
    {
        static QFileIconProvider iconProvider;
        if (!imagePathText.trimmed().isEmpty())
        {
            const QIcon fileIcon = iconProvider.icon(QFileInfo(imagePathText));
            if (!fileIcon.isNull())
            {
                return fileIcon;
            }
        }
        return QIcon(":/Icon/process_main.svg");
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
            return QStringLiteral("可见窗口");
        case 1:
            return QStringLiteral("隐藏窗口");
        case 2:
            return QStringLiteral("顶层窗口");
        case 3:
            return QStringLiteral("子窗口");
        case 4:
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

    // buildModuleSummaryText：按 PID 枚举模块并生成摘要文本，避免在 UI 中展示过长列表。
    QString buildModuleSummaryText(const std::uint32_t processId, const int maxRenderCount, int* moduleCountOut)
    {
        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = 0;
        }
        if (processId == 0)
        {
            return QStringLiteral("<System PID>");
        }

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QStringLiteral("<模块枚举失败或无权限>");
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        QStringList lineList;
        int moduleCount = 0;

        if (::Module32FirstW(snapshotHandle, &moduleEntry) != FALSE)
        {
            do
            {
                ++moduleCount;
                if (moduleCount <= maxRenderCount)
                {
                    lineList << QStringLiteral("[%1] %2 | Base=0x%3 | Size=%4")
                        .arg(moduleCount)
                        .arg(QString::fromWCharArray(moduleEntry.szModule))
                        .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(moduleEntry.modBaseAddr)), 0, 16)
                        .arg(moduleEntry.modBaseSize);
                }

                moduleEntry.dwSize = sizeof(moduleEntry);
            } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);
        }

        ::CloseHandle(snapshotHandle);

        if (moduleCountOut != nullptr)
        {
            *moduleCountOut = moduleCount;
        }

        if (lineList.isEmpty())
        {
            return QStringLiteral("<未读取到模块>");
        }
        return lineList.join(QChar::LineFeed);
    }

    // 窗口缩略图抓取：优先按句柄抓图，失败时返回占位图。
    QPixmap grabWindowPreviewPixmap(const quint64 hwndValue, const QSize& targetSize)
    {
        QPixmap sourcePixmap;
        QScreen* primaryScreen = QGuiApplication::primaryScreen();
        if (primaryScreen != nullptr)
        {
            sourcePixmap = primaryScreen->grabWindow(static_cast<WId>(hwndValue));
        }

        if (!sourcePixmap.isNull())
        {
            return sourcePixmap.scaled(
                targetSize,
                Qt::KeepAspectRatio,
                Qt::SmoothTransformation);
        }

        QPixmap fallbackPixmap(targetSize);
        fallbackPixmap.fill(KswordTheme::SurfaceColor());
        QPainter painter(&fallbackPixmap);
        painter.setPen(KswordTheme::TextSecondaryColor());
        painter.drawRect(fallbackPixmap.rect().adjusted(0, 0, -1, -1));
        painter.drawText(
            fallbackPixmap.rect(),
            Qt::AlignCenter,
            ks::i18n::contextText(QStringLiteral("other.thumbnail.none"), QStringLiteral("无可用缩略图")));
        painter.end();
        return fallbackPixmap;
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
        setStyleSheet(buildOpaqueWindowDetailDialogStyle(objectName()));
        setWindowTitle(QStringLiteral("窗口属性 - [%1] (%2)")
            .arg(info.titleText.isEmpty() ? QStringLiteral("<无标题>") : info.titleText,
                hwndToText(info.hwndValue)));
        resize(900, 680);

        initializeUi();
        refreshRuntimeInfo();
        startMessageMonitor();
    }

    // 析构函数：
    // - 作用：确保关闭详情窗时释放消息钩子句柄，避免系统残留回调。
    ~WindowDetailDialog() override
    {
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

    // PendingMessageRow：右键菜单打开期间暂存的消息行。
    // 消息流不能使用 latest-wins 丢弃中间事件，因此先保存在对话框队列中。
    struct PendingMessageRow
    {
        QString channelText;
        quint64 hwndValue = 0;
        quint64 messageId = 0;
        quint64 wParamValue = 0;
        quint64 lParamValue = 0;
        quint64 resultValue = 0;
        QString extraText;
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

        QGroupBox* groupBox = new QGroupBox(groupTitleText, parentWidget);
        QGridLayout* gridLayout = new QGridLayout(groupBox);
        gridLayout->setContentsMargins(8, 8, 8, 8);
        gridLayout->setHorizontalSpacing(12);
        gridLayout->setVerticalSpacing(4);

        int itemIndex = 0;
        for (const WindowStyleFlagDefinition& definition : definitionList)
        {
            // checkboxText：显示样式位名称，便于和文档/Win32 常量直接对应。
            const QString checkboxText = QString::fromLatin1(definition.styleNameText);
            QCheckBox* flagCheckBox = new QCheckBox(checkboxText, groupBox);
            // checkboxTip：鼠标悬停时解释该样式位用途。
            const QString checkboxTip = QString::fromUtf8(definition.styleDescriptionText);
            flagCheckBox->setToolTip(checkboxTip);

            const int rowIndex = itemIndex / 2;
            const int colIndex = itemIndex % 2;
            gridLayout->addWidget(flagCheckBox, rowIndex, colIndex);
            ++itemIndex;

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
    // - 作用：根据复选框当前状态，联动“置顶状态”和“透明度控件可用性”；
    // - 调用：勾选变化后、刷新样式回填后；
    // - 传入传出：无，直接更新 m_topMostCheck / m_alphaSlider。
    void updateDerivedStyleControlsFromCheckBoxes()
    {
        quint64 styleValue = 0;
        quint64 exStyleValue = 0;
        collectStyleFlagsFromCheckBoxes(&styleValue, &exStyleValue);

        if (m_topMostCheck != nullptr)
        {
            Q_UNUSED(styleValue);
            m_topMostCheck->setChecked((exStyleValue & WS_EX_TOPMOST) != 0);
        }
        if (m_alphaSlider != nullptr)
        {
            m_alphaSlider->setEnabled((exStyleValue & WS_EX_LAYERED) != 0);
        }
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

    // buildStyleSummaryText：
    // - 作用：拼接“十六进制样式值 + 每个复选框状态”的详细文本；
    // - 调用：refreshRuntimeInfo 刷新样式文本区时调用；
    // - 传入 styleValue/exStyleValue：实时样式值；
    // - 传出：返回可直接写入 m_styleText 的说明文本。
    QString buildStyleSummaryText(const quint64 styleValue, const quint64 exStyleValue) const
    {
        QString styleText;
        styleText += QStringLiteral("Style: 0x%1\n").arg(styleValue, 0, 16);
        styleText += QStringLiteral("ExStyle: 0x%1\n").arg(exStyleValue, 0, 16);
        styleText += QStringLiteral("\n[窗口样式 WS_*]\n");
        for (const StyleCheckBinding& binding : m_styleCheckBindingList)
        {
            const bool enabled = (styleValue & binding.styleMaskValue) != 0;
            styleText += QStringLiteral("%1: %2\n")
                .arg(binding.styleNameText, boolText(enabled));
        }

        styleText += QStringLiteral("\n[扩展样式 WS_EX_*]\n");
        for (const StyleCheckBinding& binding : m_exStyleCheckBindingList)
        {
            const bool enabled = (exStyleValue & binding.styleMaskValue) != 0;
            styleText += QStringLiteral("%1: %2\n")
                .arg(binding.styleNameText, boolText(enabled));
        }
        return styleText;
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
        ::SetWindowPos(
            windowHandle,
            (desiredExStyleValue & WS_EX_TOPMOST) != 0 ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED);

        // 分层窗口透明度：仅在勾选 WS_EX_LAYERED 时应用 Alpha。
        if ((desiredExStyleValue & WS_EX_LAYERED) != 0 && m_alphaSlider != nullptr)
        {
            ::SetLayeredWindowAttributes(
                windowHandle,
                0,
                static_cast<BYTE>(m_alphaSlider->value()),
                LWA_ALPHA);
        }

        ::RedrawWindow(
            windowHandle,
            nullptr,
            nullptr,
            RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW | RDW_ALLCHILDREN);

        refreshRuntimeInfo();

        const bool styleWriteOk = (styleError == ERROR_SUCCESS);
        const bool exStyleWriteOk = (exStyleError == ERROR_SUCCESS);
        if (!styleWriteOk || !exStyleWriteOk)
        {
            // privilegePromptHandled：权限恢复提示已覆盖失败时不再显示部分写入提示。
            const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("修改窗口样式"),
                styleWriteOk ? exStyleError : styleError);
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("样式应用提示"),
                    QStringLiteral("样式写入完成，但部分位返回错误码：Style=%1, ExStyle=%2。")
                    .arg(styleError)
                    .arg(exStyleError));
            }
        }
        else if (showSuccessDialog)
        {
            QMessageBox::information(this, QStringLiteral("窗口样式"), QStringLiteral("样式已应用。"));
        }
        return styleWriteOk && exStyleWriteOk;
    }

    // 构建 UI：创建 5 个标签页（前四类属性合并到“基础属性”）并绑定底部操作按钮。
    void initializeUi()
    {
        QVBoxLayout* rootLayout = new QVBoxLayout(this);

        m_tabWidget = new QTabWidget(this);
        rootLayout->addWidget(m_tabWidget, 1);

        // ==================== 1. 基础属性 Tab（合并前四个页签） ====================
        QWidget* basicPage = new QWidget(m_tabWidget);
        QVBoxLayout* basicLayout = new QVBoxLayout(basicPage);

        // 常规信息分组：集中展示句柄关系和标题类名等关键字段。
        QGroupBox* generalGroup = new QGroupBox(QStringLiteral("常规信息"), basicPage);
        QFormLayout* generalLayout = new QFormLayout(generalGroup);
        m_handleLabel = new QLabel(generalGroup);
        m_parentHandleLabel = new QLabel(generalGroup);
        m_ownerHandleLabel = new QLabel(generalGroup);
        m_titleEdit = new QLineEdit(generalGroup);
        m_classNameLabel = new QLabel(generalGroup);
        m_instanceLabel = new QLabel(generalGroup);
        m_stateLabel = new QLabel(generalGroup);
        m_relationLabel = new QLabel(generalGroup);
        generalLayout->addRow(QStringLiteral("句柄"), m_handleLabel);
        generalLayout->addRow(QStringLiteral("父句柄"), m_parentHandleLabel);
        generalLayout->addRow(QStringLiteral("所有者句柄"), m_ownerHandleLabel);
        m_titleEdit->setReadOnly(true);
        generalLayout->addRow(QStringLiteral("标题"), m_titleEdit);
        generalLayout->addRow(QStringLiteral("类名"), m_classNameLabel);
        generalLayout->addRow(QStringLiteral("实例句柄"), m_instanceLabel);
        generalLayout->addRow(QStringLiteral("状态摘要"), m_stateLabel);
        generalLayout->addRow(QStringLiteral("关系摘要"), m_relationLabel);
        basicLayout->addWidget(generalGroup, 0);

        // 位置与状态分组：把可编辑位置和状态控制并排展示，减少标签切换。
        QGroupBox* layoutStateGroup = new QGroupBox(QStringLiteral("位置与状态"), basicPage);
        QHBoxLayout* layoutStateLayout = new QHBoxLayout(layoutStateGroup);
        QWidget* positionPanel = new QWidget(layoutStateGroup);
        QFormLayout* positionLayout = new QFormLayout(positionPanel);
        QWidget* statePanel = new QWidget(layoutStateGroup);
        QFormLayout* stateLayout = new QFormLayout(statePanel);

        m_xSpin = new QSpinBox(positionPanel);
        m_ySpin = new QSpinBox(positionPanel);
        m_widthSpin = new QSpinBox(positionPanel);
        m_heightSpin = new QSpinBox(positionPanel);
        for (QSpinBox* spinBox : { m_xSpin, m_ySpin, m_widthSpin, m_heightSpin })
        {
            spinBox->setRange(-32768, 32768);
            spinBox->setReadOnly(true);
            spinBox->setButtonSymbols(QAbstractSpinBox::NoButtons);
        }
        m_widthSpin->setRange(1, 32768);
        m_heightSpin->setRange(1, 32768);

        QPushButton* centerScreenButton = new QPushButton(QIcon(":/Icon/process_tree.svg"), QStringLiteral("居中到屏幕"), positionPanel);
        centerScreenButton->setToolTip(QStringLiteral("把窗口移动到主屏幕中央"));
        centerScreenButton->setStyleSheet(blueButtonStyle());
        positionLayout->addRow(QStringLiteral("X"), m_xSpin);
        positionLayout->addRow(QStringLiteral("Y"), m_ySpin);
        positionLayout->addRow(QStringLiteral("宽度"), m_widthSpin);
        positionLayout->addRow(QStringLiteral("高度"), m_heightSpin);
        positionLayout->addRow(QStringLiteral("快捷操作"), centerScreenButton);

        m_topMostCheck = new QCheckBox(QStringLiteral("置顶窗口"), statePanel);
        m_topMostCheck->setEnabled(false);
        m_alphaSlider = new QSlider(Qt::Horizontal, statePanel);
        m_alphaSlider->setRange(20, 255);
        m_alphaSlider->setEnabled(false);
        m_alphaLabel = new QLabel(statePanel);
        stateLayout->addRow(QStringLiteral("置顶"), m_topMostCheck);
        stateLayout->addRow(QStringLiteral("透明度"), m_alphaSlider);
        stateLayout->addRow(QStringLiteral("当前 Alpha"), m_alphaLabel);

        layoutStateLayout->addWidget(positionPanel, 1);
        layoutStateLayout->addWidget(statePanel, 1);
        basicLayout->addWidget(layoutStateGroup, 0);

        // 样式分组：左侧复选框编辑样式位，右侧文本展示当前样式明细。
        QGroupBox* styleGroup = new QGroupBox(QStringLiteral("样式与外观"), basicPage);
        QHBoxLayout* styleLayout = new QHBoxLayout(styleGroup);
        styleLayout->setContentsMargins(6, 6, 6, 6);
        styleLayout->setSpacing(8);

        QWidget* styleEditorPanel = new QWidget(styleGroup);
        QVBoxLayout* styleEditorLayout = new QVBoxLayout(styleEditorPanel);
        styleEditorLayout->setContentsMargins(0, 0, 0, 0);
        styleEditorLayout->setSpacing(6);

        QHBoxLayout* styleActionLayout = new QHBoxLayout();
        QLabel* styleHintLabel = new QLabel(QStringLiteral("勾选样式位后点击应用"), styleEditorPanel);
        styleHintLabel->setToolTip(QStringLiteral("通过复选框直接调整 GWL_STYLE / GWL_EXSTYLE。"));
        m_styleRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), styleEditorPanel);
        m_styleApplyButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), styleEditorPanel);
        m_styleRefreshButton->setToolTip(QStringLiteral("刷新窗口样式位"));
        m_styleApplyButton->setToolTip(QStringLiteral("应用当前样式位勾选状态"));
        m_styleRefreshButton->setStyleSheet(blueButtonStyle());
        m_styleApplyButton->setStyleSheet(blueButtonStyle());
        m_styleRefreshButton->setFixedWidth(34);
        m_styleApplyButton->setFixedWidth(34);
        styleActionLayout->addWidget(styleHintLabel, 1);
        styleActionLayout->addWidget(m_styleRefreshButton, 0);
        styleActionLayout->addWidget(m_styleApplyButton, 0);
        styleEditorLayout->addLayout(styleActionLayout);

        QScrollArea* styleScrollArea = new QScrollArea(styleEditorPanel);
        styleScrollArea->setWidgetResizable(true);
        QWidget* styleCheckContainer = new QWidget(styleScrollArea);
        QVBoxLayout* styleCheckLayout = new QVBoxLayout(styleCheckContainer);
        styleCheckLayout->setContentsMargins(0, 0, 0, 0);
        styleCheckLayout->setSpacing(6);
        appendStyleCheckBoxGroup(
            styleCheckContainer,
            styleCheckLayout,
            QStringLiteral("窗口样式（GWL_STYLE）"),
            windowStyleFlagDefinitionList(),
            &m_styleCheckBindingList);
        appendStyleCheckBoxGroup(
            styleCheckContainer,
            styleCheckLayout,
            QStringLiteral("扩展样式（GWL_EXSTYLE）"),
            windowExStyleFlagDefinitionList(),
            &m_exStyleCheckBindingList);
        styleCheckLayout->addStretch(1);
        styleScrollArea->setWidget(styleCheckContainer);
        styleEditorLayout->addWidget(styleScrollArea, 1);

        m_styleText = new CodeEditorWidget(styleGroup);
        m_styleText->setReadOnly(true);
        m_styleText->setToolTip(QStringLiteral("显示实时样式值与每个位的解释状态。"));
        styleLayout->addWidget(styleEditorPanel, 1);
        styleLayout->addWidget(m_styleText, 1);
        basicLayout->addWidget(styleGroup, 1);

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
        connect(m_alphaSlider, &QSlider::valueChanged, this, [this](int value) {
            m_alphaLabel->setText(QStringLiteral("%1").arg(value));
        });
        connect(m_styleRefreshButton, &QPushButton::clicked, this, [this]() {
            refreshRuntimeInfo();
        });
        connect(m_styleApplyButton, &QPushButton::clicked, this, [this]() {
            applyStyleCheckBoxChanges(true);
        });
        m_tabWidget->addTab(basicPage, QStringLiteral("基础属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, basicPage, QStringLiteral("window.detail.tab.basic"), QStringLiteral("基础属性"));

        // ==================== 2. 进程线程 Tab ====================
        QWidget* processPage = new QWidget(m_tabWidget);
        QVBoxLayout* processLayout = new QVBoxLayout(processPage);
        m_processThreadText = new CodeEditorWidget(processPage);
        m_processThreadText->setReadOnly(true);
        processLayout->addWidget(m_processThreadText, 1);
        m_tabWidget->addTab(processPage, QStringLiteral("进程与线程"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, processPage, QStringLiteral("window.detail.tab.process"), QStringLiteral("进程与线程"));

        // ==================== 3. 类信息 Tab ====================
        QWidget* classPage = new QWidget(m_tabWidget);
        QVBoxLayout* classLayout = new QVBoxLayout(classPage);
        m_classText = new CodeEditorWidget(classPage);
        m_classText->setReadOnly(true);
        classLayout->addWidget(m_classText, 1);
        m_tabWidget->addTab(classPage, QStringLiteral("类信息"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, classPage, QStringLiteral("window.detail.tab.class"), QStringLiteral("类信息"));

        // ==================== 4. 消息钩子 Tab ====================
        QWidget* hookPage = new QWidget(m_tabWidget);
        QVBoxLayout* hookLayout = new QVBoxLayout(hookPage);

        // 概览文本：保留原有消息队列状态、焦点等摘要，便于快速判断窗口活性。
        m_hookText = new CodeEditorWidget(hookPage);
        m_hookText->setReadOnly(true);
        m_hookText->setMaximumHeight(260);
        hookLayout->addWidget(m_hookText, 0);

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
        monitorControlLayout->addWidget(m_messageMaxRowsSpin, 0);

        m_messageModeLabel = new QLabel(QStringLiteral("采集模式：未启动"), hookPage);
        m_messageCountLabel = new QLabel(QStringLiteral("已记录: 0, 丢弃: 0"), hookPage);
        monitorControlLayout->addWidget(m_messageModeLabel, 0);
        monitorControlLayout->addWidget(m_messageCountLabel, 0);
        monitorControlLayout->addStretch(1);
        hookLayout->addLayout(monitorControlLayout);

        // 消息表：按行展示捕获数据，接近 Spy++ 的消息流视角。
        m_messageTable = new ks::ui::VisibleTableWidget(hookPage);
        m_messageTable->setColumnCount(8);
        m_messageTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("时间"),
            QStringLiteral("通道"),
            QStringLiteral("HWND"),
            QStringLiteral("消息ID"),
            QStringLiteral("消息名"),
            QStringLiteral("WPARAM"),
            QStringLiteral("LPARAM"),
            QStringLiteral("结果/附加")
        });
        m_messageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_messageTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        m_messageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_messageTable->setAlternatingRowColors(true);
        m_messageTable->setSortingEnabled(false);
        m_messageTable->verticalHeader()->setVisible(false);
        m_messageTable->horizontalHeader()->setStretchLastSection(true);
        m_messageTable->setContextMenuPolicy(Qt::CustomContextMenu);
        hookLayout->addWidget(m_messageTable, 1);

        // 表格右键：支持复制整行，方便与日志或抓包结果做对比分析。
        connect(m_messageTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
            if (m_messageTable == nullptr)
            {
                return;
            }
            QMenu menu;
            // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制选中行"));
            QAction* selectedAction = menu.exec(m_messageTable->viewport()->mapToGlobal(pos));
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QStringList rowTexts;
            const QList<QTableWidgetSelectionRange> selectionRanges = m_messageTable->selectedRanges();
            for (const QTableWidgetSelectionRange& range : selectionRanges)
            {
                for (int row = range.topRow(); row <= range.bottomRow(); ++row)
                {
                    QStringList singleRow;
                    for (int col = 0; col < m_messageTable->columnCount(); ++col)
                    {
                        QTableWidgetItem* item = m_messageTable->item(row, col);
                        singleRow << (item == nullptr ? QString() : item->text());
                    }
                    rowTexts << singleRow.join('\t');
                }
            }
            if (!rowTexts.isEmpty())
            {
                QApplication::clipboard()->setText(rowTexts.join('\n'));
            }
        });

        // 监控控制绑定：开始/停止/清空动作。
        connect(m_messageStartButton, &QPushButton::clicked, this, [this]() {
            startMessageMonitor();
        });
        connect(m_messageStopButton, &QPushButton::clicked, this, [this]() {
            stopMessageMonitor();
        });
        connect(m_messageClearButton, &QPushButton::clicked, this, [this]() {
            clearMessageTable();
        });

        m_tabWidget->addTab(hookPage, QStringLiteral("消息钩子"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, hookPage, QStringLiteral("window.detail.tab.hooks"), QStringLiteral("消息钩子"));

        // ==================== 5. 高级属性 Tab ====================
        QWidget* advancedPage = new QWidget(m_tabWidget);
        QVBoxLayout* advancedLayout = new QVBoxLayout(advancedPage);
        m_advancedText = new CodeEditorWidget(advancedPage);
        m_advancedText->setReadOnly(true);
        advancedLayout->addWidget(m_advancedText, 1);
        m_tabWidget->addTab(advancedPage, QStringLiteral("高级属性"));
        ks::i18n::LanguageManager::instance().bindTab(
            m_tabWidget, advancedPage, QStringLiteral("window.detail.tab.advanced"), QStringLiteral("高级属性"));

        const ks::dwm_order::WindowIdentity inputIdentity{m_info.hwndValue,
            m_info.processId, m_info.threadId, m_info.processCreationTime100ns};
        auto* inputPage = ks::window_input::CreateControl(inputIdentity, m_tabWidget);
        inputPage->setObjectName(QStringLiteral("ks_window_input_page"));
        m_tabWidget->addTab(inputPage, QStringLiteral("窗口输入与顺序"));
        ks::i18n::LanguageManager::instance().bindTab(m_tabWidget, inputPage,
            QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));

        // ==================== 底部按钮 ====================
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        rootLayout->addLayout(buttonLayout);
        buttonLayout->addStretch(1);
        m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
        m_applyButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), this);
        m_exportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), this);
        m_closeButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), this);

        m_refreshButton->setToolTip(QStringLiteral("刷新窗口属性"));
        m_applyButton->setToolTip(QStringLiteral("应用修改"));
        m_applyButton->setEnabled(false);
        m_exportButton->setToolTip(QStringLiteral("导出信息"));
        m_closeButton->setToolTip(QStringLiteral("关闭详情窗口"));

        for (QPushButton* button : { m_refreshButton, m_applyButton, m_exportButton, m_closeButton })
        {
            button->setStyleSheet(blueButtonStyle());
            button->setFixedWidth(34);
            buttonLayout->addWidget(button, 0);
        }

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
    }

    // 刷新运行时信息：对句柄重新采样，避免显示陈旧数据。
    void refreshRuntimeInfo()
    {
        HWND windowHandle = toHwnd(m_info.hwndValue);
        if (::IsWindow(windowHandle) == FALSE)
        {
            m_stateLabel->setText(QStringLiteral("窗口已失效"));
            return;
        }

        // 句柄与基础状态字段。
        m_handleLabel->setText(hwndToText(m_info.hwndValue));
        m_parentHandleLabel->setText(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle)))));
        m_ownerHandleLabel->setText(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)))));
        m_classNameLabel->setText(m_info.classNameText);
        m_titleEdit->setText(m_info.titleText);
        m_instanceLabel->setText(hwndToText(static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE))));

        const bool visible = ::IsWindowVisible(windowHandle) != FALSE;
        const bool enabled = ::IsWindowEnabled(windowHandle) != FALSE;
        const bool minimized = ::IsIconic(windowHandle) != FALSE;
        const bool maximized = ::IsZoomed(windowHandle) != FALSE;

        m_stateLabel->setText(QStringLiteral("可见:%1, 可用:%2, 状态:%3")
            .arg(boolText(visible), boolText(enabled), windowStateText(true, minimized, maximized)));
        m_relationLabel->setText(QStringLiteral("PID=%1, TID=%2")
            .arg(m_info.processId)
            .arg(m_info.threadId));

        // 样式信息：输出十六进制样式值与常见标记判断。
        const quint64 styleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
        const quint64 exStyleValue = static_cast<quint64>(::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE));
        syncStyleCheckBoxes(styleValue, exStyleValue);
        m_styleText->setText(buildStyleSummaryText(styleValue, exStyleValue));

        // 窗口位置与尺寸写回编辑控件。
        RECT rect{};
        const bool windowRectReady = (::GetWindowRect(windowHandle, &rect) != FALSE);
        if (windowRectReady)
        {
            m_xSpin->setValue(rect.left);
            m_ySpin->setValue(rect.top);
            m_widthSpin->setValue(std::max<int>(1, static_cast<int>(rect.right - rect.left)));
            m_heightSpin->setValue(std::max<int>(1, static_cast<int>(rect.bottom - rect.top)));
        }
        else
        {
            m_xSpin->setValue(0);
            m_ySpin->setValue(0);
            m_widthSpin->setValue(1);
            m_heightSpin->setValue(1);
        }

        // 状态页：置顶与透明度。
        m_topMostCheck->setChecked((exStyleValue & WS_EX_TOPMOST) != 0);
        int alphaValue = 255;
        if ((exStyleValue & WS_EX_LAYERED) != 0)
        {
            COLORREF colorKey = 0;
            BYTE alpha = 255;
            DWORD flags = 0;
            if (::GetLayeredWindowAttributes(windowHandle, &colorKey, &alpha, &flags) != FALSE)
            {
                Q_UNUSED(colorKey);
                Q_UNUSED(flags);
                alphaValue = static_cast<int>(alpha);
            }
        }
        m_alphaSlider->setValue(alphaValue);
        m_alphaSlider->setEnabled((exStyleValue & WS_EX_LAYERED) != 0);
        m_alphaLabel->setText(QString::number(alphaValue));

        // 进程线程信息：补齐路径、优先级、句柄计数、启动时间和模块摘要，便于排障和行为审计。
        QString processText;
        processText += QStringLiteral("PID: %1\n").arg(m_info.processId);
        processText += QStringLiteral("ProcessName: %1\n").arg(m_info.processNameText);
        processText += QStringLiteral("TID: %1\n").arg(m_info.threadId);
        if (windowRectReady)
        {
            processText += QStringLiteral("WindowRect: [%1,%2,%3,%4]\n")
                .arg(rect.left).arg(rect.top).arg(rect.right).arg(rect.bottom);
        }
        else
        {
            processText += QStringLiteral("WindowRect: <N/A>\n");
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            m_info.processId);
        if (processHandle != nullptr)
        {
            wchar_t processPathBuffer[MAX_PATH * 2] = {};
            DWORD processPathLength = static_cast<DWORD>(std::size(processPathBuffer));
            if (::QueryFullProcessImageNameW(processHandle, 0, processPathBuffer, &processPathLength) != FALSE)
            {
                processText += QStringLiteral("ProcessPath: %1\n")
                    .arg(QString::fromWCharArray(processPathBuffer, static_cast<int>(processPathLength)));
            }

            const DWORD processPriority = ::GetPriorityClass(processHandle);
            processText += QStringLiteral("ProcessPriorityClass: 0x%1\n")
                .arg(static_cast<qulonglong>(processPriority), 0, 16);

            DWORD handleCount = 0;
            if (::GetProcessHandleCount(processHandle, &handleCount) != FALSE)
            {
                processText += QStringLiteral("ProcessHandleCount: %1\n").arg(handleCount);
            }

            FILETIME createTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                processText += QStringLiteral("StartTime: %1\n").arg(fileTimeToLocalText(createTime));
                const qulonglong cpuTotal = fileTimeToUInt64(kernelTime) + fileTimeToUInt64(userTime);
                processText += QStringLiteral("CPUTime(Kernel+User): %1\n").arg(formatDurationFrom100ns(cpuTotal));

                FILETIME nowFileTime{};
                ::GetSystemTimeAsFileTime(&nowFileTime);
                const qulonglong nowTick = fileTimeToUInt64(nowFileTime);
                const qulonglong startTick = fileTimeToUInt64(createTime);
                if (nowTick > startTick)
                {
                    processText += QStringLiteral("RunTime: %1\n").arg(formatDurationFrom100ns(nowTick - startTick));
                }
            }

            ::CloseHandle(processHandle);
        }
        else
        {
            processText += QStringLiteral("ProcessOpen: 失败（权限不足或进程已退出）\n");
        }

        int moduleCount = 0;
        const QString moduleSummaryText = buildModuleSummaryText(m_info.processId, 8, &moduleCount);
        processText += QStringLiteral("ModuleCount: %1\n").arg(moduleCount);
        processText += QStringLiteral("ModulePreview:\n%1\n").arg(moduleSummaryText);

        HANDLE threadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, m_info.threadId);
        if (threadHandle != nullptr)
        {
            const int threadPriority = ::GetThreadPriority(threadHandle);
            processText += QStringLiteral("ThreadPriority: %1\n").arg(threadPriority);

            BOOL priorityBoostDisabled = FALSE;
            if (::GetThreadPriorityBoost(threadHandle, &priorityBoostDisabled) != FALSE)
            {
                processText += QStringLiteral("ThreadPriorityBoostDisabled: %1\n")
                    .arg(boolText(priorityBoostDisabled != FALSE));
            }
            ::CloseHandle(threadHandle);
        }
        else
        {
            processText += QStringLiteral("ThreadOpen: 失败（线程可能已退出）\n");
        }
        processText += QStringLiteral("提示：可从右键菜单跳转到进程详细信息页。");
        m_processThreadText->setText(processText);

        // 类信息：展示类名、类样式、窗口过程地址以及类资源句柄。
        QString classText;
        classText += QStringLiteral("ClassName: %1\n").arg(m_info.classNameText);
        classText += QStringLiteral("ClassAtom: 0x%1\n").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCW_ATOM)), 0, 16);
        classText += QStringLiteral("ClassStyle: 0x%1\n").arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCL_STYLE)), 0, 16);
        classText += QStringLiteral("ClassExtraBytes: %1\n")
            .arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBCLSEXTRA)));
        classText += QStringLiteral("WindowExtraBytes: %1\n")
            .arg(static_cast<qlonglong>(::GetClassLongPtrW(windowHandle, GCL_CBWNDEXTRA)));
        classText += QStringLiteral("WndProc: 0x%1\n").arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16);
        classText += QStringLiteral("MenuHandle: 0x%1\n").arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(::GetMenu(windowHandle))), 0, 16);
        classText += QStringLiteral("ClassHCursor: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HCURSOR)), 0, 16);
        classText += QStringLiteral("ClassHIcon: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICON)), 0, 16);
        classText += QStringLiteral("ClassHIconSm: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HICONSM)), 0, 16);
        classText += QStringLiteral("ClassHbrBackground: 0x%1\n")
            .arg(static_cast<qulonglong>(::GetClassLongPtrW(windowHandle, GCLP_HBRBACKGROUND)), 0, 16);

        const HMODULE classModuleHandle = reinterpret_cast<HMODULE>(::GetClassLongPtrW(windowHandle, GCLP_HMODULE));
        classText += QStringLiteral("ClassModule: 0x%1\n")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(classModuleHandle)), 0, 16);
        if (classModuleHandle != nullptr)
        {
            wchar_t modulePathBuffer[MAX_PATH * 2] = {};
            const DWORD pathLength = ::GetModuleFileNameW(
                classModuleHandle,
                modulePathBuffer,
                static_cast<DWORD>(std::size(modulePathBuffer)));
            if (pathLength > 0)
            {
                classText += QStringLiteral("ClassModulePath: %1\n")
                    .arg(QString::fromWCharArray(modulePathBuffer, static_cast<int>(pathLength)));
            }
        }
        m_classText->setText(classText);

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
        const bool guiInfoReady = (::GetGUIThreadInfo(m_info.threadId, &guiThreadInfo) != FALSE);

        const DWORD queueStatus = ::GetQueueStatus(QS_ALLINPUT);
        QString hookText;
        hookText += QStringLiteral("IsHungAppWindow: %1\n")
            .arg(boolText(::IsHungAppWindow(windowHandle) != FALSE));
        hookText += QStringLiteral("ChildWindowCount: %1\n").arg(childWindowCount);
        hookText += QStringLiteral("SiblingWindowCount: %1\n").arg(siblingCount);
        hookText += QStringLiteral("Visible: %1\n").arg(boolText(::IsWindowVisible(windowHandle) != FALSE));
        hookText += QStringLiteral("Enabled: %1\n").arg(boolText(::IsWindowEnabled(windowHandle) != FALSE));
        hookText += QStringLiteral("QueueStatusRaw: 0x%1\n")
            .arg(static_cast<qulonglong>(queueStatus), 0, 16);
        hookText += QStringLiteral("QueueCurrentFlags(LOWORD): 0x%1\n")
            .arg(static_cast<unsigned int>(LOWORD(queueStatus)), 0, 16);
        hookText += QStringLiteral("QueueNewFlags(HIWORD): 0x%1\n")
            .arg(static_cast<unsigned int>(HIWORD(queueStatus)), 0, 16);
        hookText += QStringLiteral("GUIThreadInfoReady: %1\n").arg(boolText(guiInfoReady));
        if (guiInfoReady)
        {
            hookText += QStringLiteral("Focus: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndFocus))));
            hookText += QStringLiteral("Active: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndActive))));
            hookText += QStringLiteral("Capture: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCapture))));
            hookText += QStringLiteral("Caret: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndCaret))));
            hookText += QStringLiteral("MenuOwner: %1\n")
                .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(guiThreadInfo.hwndMenuOwner))));
        }
        hookText += QStringLiteral("ForegroundWindow: %1\n")
            .arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetForegroundWindow()))));
        hookText += QStringLiteral("说明：系统级 Hook 链表不提供官方通用枚举接口，当前页聚焦可稳定获取的消息上下文。");
        m_hookText->setText(hookText);

        // 高级页：补齐 DPI、属性表（GetProp/EnumPropsExW）与窗口额外字节等关键内容。
        QString advancedText;
        advancedText += QStringLiteral("UserData (GWLP_USERDATA): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_USERDATA)), 0, 16);
        advancedText += QStringLiteral("ID (GWLP_ID): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_ID)), 0, 16);
        advancedText += QStringLiteral("WndProc (GWLP_WNDPROC): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_WNDPROC)), 0, 16);
        advancedText += QStringLiteral("HINSTANCE (GWLP_HINSTANCE): 0x%1\n")
            .arg(static_cast<qulonglong>(::GetWindowLongPtrW(windowHandle, GWLP_HINSTANCE)), 0, 16);
        advancedText += QStringLiteral("Parent: %1\n").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetParent(windowHandle)))));
        advancedText += QStringLiteral("Owner: %1\n").arg(hwndToText(static_cast<quint64>(reinterpret_cast<quintptr>(::GetWindow(windowHandle, GW_OWNER)))));

        DWORD displayAffinity = 0;
        if (::GetWindowDisplayAffinity(windowHandle, &displayAffinity) != FALSE)
        {
            advancedText += QStringLiteral("DisplayAffinity: 0x%1\n")
                .arg(static_cast<qulonglong>(displayAffinity), 0, 16);
        }

        RECT clientRect{};
        if (::GetClientRect(windowHandle, &clientRect) != FALSE)
        {
            advancedText += QStringLiteral("ClientRect: [%1,%2,%3,%4]\n")
                .arg(clientRect.left)
                .arg(clientRect.top)
                .arg(clientRect.right)
                .arg(clientRect.bottom);
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
            advancedText += QStringLiteral("DPI: %1\n").arg(getDpiForWindow(windowHandle));
        }

        // 枚举窗口属性键值：用于发现子类化框架、输入法、UI库挂载的额外状态。
        QStringList propLines;
        WindowPropEnumContext propContext;
        propContext.lines = &propLines;
        propContext.maxCount = 200;
        ::EnumPropsExW(windowHandle, enumWindowPropProc, reinterpret_cast<LPARAM>(&propContext));
        advancedText += QStringLiteral("PropCount: %1\n").arg(propLines.size());
        if (!propLines.isEmpty())
        {
            advancedText += QStringLiteral("Properties:\n");
            for (const QString& line : propLines)
            {
                advancedText += QStringLiteral("  - %1\n").arg(line);
            }
        }
        else
        {
            advancedText += QStringLiteral("Properties: <none>\n");
        }
        m_advancedText->setText(advancedText);

        // 刷新时同步更新消息监控状态标签，避免页面切换后显示陈旧模式文本。
        updateMessageMonitorUiState();
    }

    // 清空消息表：重置可视列表与计数器。
    void clearMessageTable()
    {
        m_deferredMessageRows.clear();
        if (m_messageTable != nullptr)
        {
            m_messageTable->setRowCount(0);
        }
        m_capturedMessageCount = 0;
        m_droppedMessageCount = 0;
        if (m_messageCountLabel != nullptr)
        {
            m_messageCountLabel->setText(QStringLiteral("已记录: 0, 丢弃: 0"));
        }
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

    // appendMessageRow 作用：
    // - 仅在 UI 线程向表格追加一条消息记录；
    // - 当超过最大行数时删除最早行，并累计丢弃计数。
    void appendMessageRow(
        const QString& channelText,
        const quint64 hwndValue,
        const quint64 messageId,
        const quint64 wParamValue,
        const quint64 lParamValue,
        const quint64 resultValue,
        const QString& extraText)
    {
        if (m_messageTable == nullptr)
        {
            return;
        }

        if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_messageTable}))
        {
            const int maxDeferredRows =
                (m_messageMaxRowsSpin == nullptr) ? 5000 : m_messageMaxRowsSpin->value();
            while (static_cast<int>(m_deferredMessageRows.size()) >= maxDeferredRows)
            {
                m_deferredMessageRows.pop_front();
                ++m_droppedMessageCount;
            }
            m_deferredMessageRows.push_back({
                channelText,
                hwndValue,
                messageId,
                wParamValue,
                lParamValue,
                resultValue,
                extraText
            });

            const QPointer<WindowDetailDialog> safeThis(this);
            ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("window-message-stream-flush"),
                {m_messageTable},
                [safeThis]()
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->flushDeferredMessageRows();
                    }
                });
            updateMessageMonitorUiState();
            return;
        }

        const int maxRows = (m_messageMaxRowsSpin == nullptr) ? 5000 : m_messageMaxRowsSpin->value();
        while (m_messageTable->rowCount() >= maxRows)
        {
            m_messageTable->removeRow(0);
            ++m_droppedMessageCount;
        }

        const int rowIndex = m_messageTable->rowCount();
        m_messageTable->insertRow(rowIndex);

        const QString messageNameText = (channelText.contains(QStringLiteral("WinEvent")))
            ? winEventName(static_cast<DWORD>(messageId))
            : windowMessageName(static_cast<UINT>(messageId));

        const QString messageIdText = channelText.contains(QStringLiteral("WinEvent"))
            ? QStringLiteral("0x%1").arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0')).toUpper()
            : QStringLiteral("0x%1").arg(static_cast<qulonglong>(messageId), 4, 16, QChar('0')).toUpper();

        const QString resultColumnText = extraText.trimmed().isEmpty()
            ? toHexText64(resultValue)
            : QStringLiteral("%1 | %2").arg(toHexText64(resultValue), extraText);

        m_messageTable->setItem(rowIndex, 0, new QTableWidgetItem(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"))));
        m_messageTable->setItem(rowIndex, 1, new QTableWidgetItem(channelText));
        m_messageTable->setItem(rowIndex, 2, new QTableWidgetItem(hwndToText(hwndValue)));
        m_messageTable->setItem(rowIndex, 3, new QTableWidgetItem(messageIdText));
        m_messageTable->setItem(rowIndex, 4, new QTableWidgetItem(messageNameText));
        m_messageTable->setItem(rowIndex, 5, new QTableWidgetItem(toHexText64(wParamValue)));
        m_messageTable->setItem(rowIndex, 6, new QTableWidgetItem(toHexText64(lParamValue)));
        m_messageTable->setItem(rowIndex, 7, new QTableWidgetItem(resultColumnText));

        ++m_capturedMessageCount;
        updateMessageMonitorUiState();

        if (m_messageAutoScrollCheck != nullptr && m_messageAutoScrollCheck->isChecked())
        {
            m_messageTable->scrollToBottom();
        }
    }

    // flushDeferredMessageRows 作用：
    // - 菜单关闭后按原始顺序补写全部暂存消息；
    // - 若另一个菜单已打开，继续保留队列并等待下一次安全回投。
    void flushDeferredMessageRows()
    {
        if (m_deferredMessageRows.empty())
        {
            return;
        }

        const QPointer<WindowDetailDialog> safeThis(this);
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("window-message-stream-flush"),
            {m_messageTable},
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->flushDeferredMessageRows();
                }
            }))
        {
            return;
        }

        std::deque<PendingMessageRow> pendingRows;
        pendingRows.swap(m_deferredMessageRows);
        for (const PendingMessageRow& pendingRow : pendingRows)
        {
            appendMessageRow(
                pendingRow.channelText,
                pendingRow.hwndValue,
                pendingRow.messageId,
                pendingRow.wParamValue,
                pendingRow.lParamValue,
                pendingRow.resultValue,
                pendingRow.extraText);
        }
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
        std::vector<WindowDetailDialog*> dialogList;
        {
            std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
            const auto it = s_threadDialogMap.find(threadId);
            if (it != s_threadDialogMap.end())
            {
                dialogList = it->second;
            }
        }

        if (dialogList.empty() || targetHwnd == nullptr)
        {
            return;
        }

        for (WindowDetailDialog* dialog : dialogList)
        {
            if (dialog == nullptr || !dialog->m_messageMonitorRunning.load())
            {
                continue;
            }
            if (targetHwnd != dialog->targetWindowHandle())
            {
                continue;
            }

            const QPointer<WindowDetailDialog> guardDialog(dialog);
            const quint64 hwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(targetHwnd));
            QMetaObject::invokeMethod(qApp, [guardDialog, channelText, hwndValue, messageId, wParamValue, lParamValue, resultValue]() {
                if (guardDialog == nullptr)
                {
                    return;
                }
                guardDialog->appendMessageRow(
                    channelText,
                    hwndValue,
                    static_cast<quint64>(messageId),
                    static_cast<quint64>(wParamValue),
                    static_cast<quint64>(lParamValue),
                    static_cast<quint64>(resultValue),
                    QString());
                }, Qt::QueuedConnection);
        }
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
        WindowDetailDialog* dialog = nullptr;
        {
            std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
            const auto it = s_eventHookMap.find(hookHandle);
            if (it != s_eventHookMap.end())
            {
                dialog = it->second;
            }
        }
        if (dialog == nullptr || !dialog->m_messageMonitorRunning.load())
        {
            return;
        }
        if (windowHandle == nullptr || windowHandle != dialog->targetWindowHandle())
        {
            return;
        }

        const QPointer<WindowDetailDialog> guardDialog(dialog);
        const quint64 hwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(windowHandle));
        const QString extraText = QStringLiteral("obj=%1, child=%2, thread=%3, time=%4")
            .arg(objectId)
            .arg(childId)
            .arg(eventThreadId)
            .arg(eventTimeMs);
        QMetaObject::invokeMethod(qApp, [guardDialog, hwndValue, eventId, objectId, childId, eventThreadId, eventTimeMs, extraText]() {
            if (guardDialog == nullptr)
            {
                return;
            }
            guardDialog->appendMessageRow(
                QStringLiteral("WinEvent"),
                hwndValue,
                static_cast<quint64>(eventId),
                static_cast<quint64>(static_cast<qint64>(objectId)),
                static_cast<quint64>(static_cast<qint64>(childId)),
                static_cast<quint64>(eventThreadId),
                extraText + QStringLiteral(", tick=%1").arg(eventTimeMs));
            }, Qt::QueuedConnection);
    }

    // 注册 thread -> dialog 映射：支持同一线程被多个详情窗同时观察。
    static void registerThreadDialog(const DWORD threadId, WindowDetailDialog* dialog)
    {
        if (threadId == 0 || dialog == nullptr)
        {
            return;
        }
        std::lock_guard<std::mutex> lockGuard(s_monitorRegistryMutex);
        std::vector<WindowDetailDialog*>& dialogList = s_threadDialogMap[threadId];
        const bool existed = std::find(dialogList.begin(), dialogList.end(), dialog) != dialogList.end();
        if (!existed)
        {
            dialogList.push_back(dialog);
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

        std::vector<WindowDetailDialog*>& dialogList = it->second;
        dialogList.erase(std::remove(dialogList.begin(), dialogList.end(), dialog), dialogList.end());
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
        s_eventHookMap[hookHandle] = dialog;
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
        if (it != s_eventHookMap.end() && it->second == dialog)
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
        const QString defaultName = QStringLiteral("window_detail_%1_%2.txt")
            .arg(QString::number(m_info.processId))
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

        const QString outputPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出窗口详情"),
            defaultName,
            QStringLiteral("文本文件 (*.txt)"));
        if (outputPath.trimmed().isEmpty())
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
        out << buildReportText();
        file.close();

        QMessageBox::information(this, QStringLiteral("导出成功"), QStringLiteral("已保存到：%1").arg(outputPath));
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

        text += QStringLiteral("[样式]\n%1\n\n").arg(m_styleText->text());
        text += QStringLiteral("[位置]\nX=%1, Y=%2, W=%3, H=%4\n\n")
            .arg(m_xSpin->value())
            .arg(m_ySpin->value())
            .arg(m_widthSpin->value())
            .arg(m_heightSpin->value());
        text += QStringLiteral("[状态]\nTopMost=%1, Alpha=%2\n\n")
            .arg(boolText(m_topMostCheck->isChecked()))
            .arg(m_alphaSlider->value());
        text += QStringLiteral("[进程线程]\n%1\n\n").arg(m_processThreadText->text());
        text += QStringLiteral("[类信息]\n%1\n\n").arg(m_classText->text());
        text += QStringLiteral("[消息钩子]\n%1\n\n").arg(m_hookText->text());
        text += QStringLiteral("[消息记录]\n");
        if (m_messageTable != nullptr)
        {
            QStringList headerList;
            for (int col = 0; col < m_messageTable->columnCount(); ++col)
            {
                const QTableWidgetItem* headerItem = m_messageTable->horizontalHeaderItem(col);
                headerList << (headerItem == nullptr ? QStringLiteral("Col%1").arg(col) : headerItem->text());
            }
            text += headerList.join('\t');
            text += QStringLiteral("\n");

            for (int row = 0; row < m_messageTable->rowCount(); ++row)
            {
                QStringList rowTextList;
                for (int col = 0; col < m_messageTable->columnCount(); ++col)
                {
                    QTableWidgetItem* item = m_messageTable->item(row, col);
                    rowTextList << (item == nullptr ? QString() : item->text());
                }
                text += rowTextList.join('\t');
                text += QStringLiteral("\n");
            }
        }
        text += QStringLiteral("\n");
        text += QStringLiteral("[高级属性]\n%1\n").arg(m_advancedText->text());
        return text;
    }

private:
    OtherDock::WindowInfo m_info;          // 目标窗口快照。

    QTabWidget* m_tabWidget = nullptr;     // 标签页容器。

    QLabel* m_handleLabel = nullptr;       // 句柄显示。
    QLabel* m_parentHandleLabel = nullptr; // 父句柄显示。
    QLabel* m_ownerHandleLabel = nullptr;  // 所有者句柄显示。
    QLineEdit* m_titleEdit = nullptr;      // 可编辑标题输入。
    QLabel* m_classNameLabel = nullptr;    // 类名显示。
    QLabel* m_instanceLabel = nullptr;     // 实例句柄显示。
    QLabel* m_stateLabel = nullptr;        // 状态摘要显示。
    QLabel* m_relationLabel = nullptr;     // 关系摘要显示。

    CodeEditorWidget* m_styleText = nullptr;      // 样式文本区域（统一文本编辑器，只读）。
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
    QLabel* m_alphaLabel = nullptr;             // 透明度文本。

    CodeEditorWidget* m_processThreadText = nullptr; // 进程线程页文本（统一文本编辑器，只读）。
    CodeEditorWidget* m_classText = nullptr;         // 类信息页文本（统一文本编辑器，只读）。
    CodeEditorWidget* m_hookText = nullptr;          // 钩子页文本（统一文本编辑器，只读）。
    QPushButton* m_messageStartButton = nullptr;   // 消息监控开始按钮。
    QPushButton* m_messageStopButton = nullptr;    // 消息监控停止按钮。
    QPushButton* m_messageClearButton = nullptr;   // 消息列表清空按钮。
    QCheckBox* m_messageAutoScrollCheck = nullptr; // 自动滚动复选框。
    QSpinBox* m_messageMaxRowsSpin = nullptr;      // 消息表最大保留行数。
    QLabel* m_messageModeLabel = nullptr;          // 当前采集模式标签。
    QLabel* m_messageCountLabel = nullptr;         // 已记录/丢弃计数标签。
    QTableWidget* m_messageTable = nullptr;        // 消息列表表格。
    CodeEditorWidget* m_advancedText = nullptr;      // 高级页文本（统一文本编辑器，只读）。

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
    int m_capturedMessageCount = 0;            // 已写入消息表的消息数量。
    int m_droppedMessageCount = 0;             // 因超过最大行数而丢弃的消息数量。
    std::deque<PendingMessageRow> m_deferredMessageRows; // 菜单期间保持顺序的待提交消息。
    QString m_messageMonitorMode = QStringLiteral("未启动"); // 当前监控模式文本。

    static std::mutex s_monitorRegistryMutex;  // 回调映射表互斥锁，防止并发竞态。
    static std::unordered_map<DWORD, std::vector<WindowDetailDialog*>> s_threadDialogMap; // threadId -> 详情窗列表。
    static std::unordered_map<HWINEVENTHOOK, WindowDetailDialog*> s_eventHookMap; // WinEvent hook -> 详情窗。
};

// 静态成员定义：统一管理消息回调分发映射。
std::mutex WindowDetailDialog::s_monitorRegistryMutex;
std::unordered_map<DWORD, std::vector<WindowDetailDialog*>> WindowDetailDialog::s_threadDialogMap;
std::unordered_map<HWINEVENTHOOK, WindowDetailDialog*> WindowDetailDialog::s_eventHookMap;

OtherDock::OtherDock(QWidget* parent)
    : QWidget(parent)
{
    kLogEvent event;
    info << event << "[OtherDock] 构造开始，初始化窗口管理页。" << eol;

    initializeUi();
    initializeConnections();
    applyViewMode();
    refreshWindowListAsync();
}

OtherDock::~OtherDock()
{
    if (m_autoRefreshTimer != nullptr)
    {
        m_autoRefreshTimer->stop();
    }

    // 关闭本进程主动保留的新建桌面句柄，避免桌面对象在程序退出后残留引用。
    for (const CreatedDesktopRecord& desktopRecord : m_createdDesktopHandles)
    {
        if (desktopRecord.desktopHandle != nullptr)
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
    m_rootLayout->addWidget(m_toolBarWidget, 0);

    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_toolBarWidget);
    m_refreshButton->setToolTip(QStringLiteral("刷新窗口列表"));
    m_refreshButton->setStyleSheet(blueButtonStyle());
    m_refreshButton->setFixedWidth(32);

    m_clearExternalProcessFilterButton = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), m_toolBarWidget);
    m_clearExternalProcessFilterButton->setToolTip(QStringLiteral("清除进程页跳转带入的 PID 筛选"));
    m_clearExternalProcessFilterButton->setStyleSheet(blueButtonStyle());
    m_clearExternalProcessFilterButton->setFixedWidth(32);
    m_clearExternalProcessFilterButton->setEnabled(false);

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
    m_filterEdit->setPlaceholderText(QStringLiteral("筛选：标题 / 进程名 / 类名 / HWND"));
    m_filterEdit->setToolTip(QStringLiteral("输入关键字实时过滤窗口"));
    m_filterEdit->setStyleSheet(blueInputStyle());

    m_filterModeCombo = new QComboBox(m_toolBarWidget);
    m_filterModeCombo->addItems({
        QStringLiteral("可见窗口"),
        QStringLiteral("隐藏窗口"),
        QStringLiteral("顶层窗口"),
        QStringLiteral("子窗口"),
        QStringLiteral("无效窗口")
        });
    m_filterModeCombo->setToolTip(QStringLiteral("选择窗口过滤条件"));
    m_filterModeCombo->setStyleSheet(blueInputStyle());

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

    m_groupModeCombo = new QComboBox(m_toolBarWidget);
    m_groupModeCombo->addItems({
        QStringLiteral("按进程分组"),
        QStringLiteral("按Z序排列"),
        QStringLiteral("按窗口层级"),
        QStringLiteral("按显示器分组")
        });
    m_groupModeCombo->setToolTip(QStringLiteral("选择窗口分组方式"));
    m_groupModeCombo->setStyleSheet(blueInputStyle());

    m_viewModeCombo = new QComboBox(m_toolBarWidget);
    m_viewModeCombo->addItems({
        QStringLiteral("图标视图"),
        QStringLiteral("列表视图"),
        QStringLiteral("详细信息视图")
        });
    m_viewModeCombo->setToolTip(QStringLiteral("切换列表显示样式"));
    m_viewModeCombo->setStyleSheet(blueInputStyle());

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

    // 中部主内容：Tab1=窗口列表，Tab2=桌面管理（SwitchDesktop）。
    m_contentTabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_contentTabWidget, 1);

    m_windowListPage = new QWidget(m_contentTabWidget);
    m_windowListPageLayout = new QVBoxLayout(m_windowListPage);
    m_windowListPageLayout->setContentsMargins(0, 0, 0, 0);
    m_windowListPageLayout->setSpacing(4);

    // 窗口列表页顶部工具条：新增准星拖拽拾取入口，满足“直接拖到目标窗口看详情”场景。
    m_windowListToolWidget = new QWidget(m_windowListPage);
    m_windowListToolLayout = new QHBoxLayout(m_windowListToolWidget);
    m_windowListToolLayout->setContentsMargins(0, 0, 0, 0);
    m_windowListToolLayout->setSpacing(6);

    auto* pickerButton = new WindowPickerDragButton(m_windowListToolWidget);
    m_windowPickerButton = pickerButton;
    m_windowPickerButton->setIcon(QIcon(":/Icon/window_picker_target.svg"));
    m_windowPickerButton->setToolTip(QStringLiteral("按住并拖拽准星，松开后打开鼠标下方窗口的详细信息"));
    m_windowPickerButton->setStyleSheet(blueButtonStyle());
    m_windowPickerButton->setFixedWidth(32);

    m_protectCaptureButton = new QPushButton(QIcon(":/Icon/titlebar_capture_protected.svg"), QString(), m_windowListToolWidget);
    m_protectCaptureButton->setToolTip(QStringLiteral("对选中窗口启用防截图保护：优先从截图/录屏中隐藏，失败时回退黑屏"));
    m_protectCaptureButton->setStyleSheet(blueButtonStyle());
    m_protectCaptureButton->setFixedWidth(32);

    m_unprotectCaptureButton = new QPushButton(QIcon(":/Icon/titlebar_capture_allowed.svg"), QString(), m_windowListToolWidget);
    m_unprotectCaptureButton->setToolTip(QStringLiteral("取消选中窗口的防截图保护，恢复普通截图/录屏捕获"));
    m_unprotectCaptureButton->setStyleSheet(blueButtonStyle());
    m_unprotectCaptureButton->setFixedWidth(32);

    m_windowPickerHintLabel = new QLabel(
        QStringLiteral("拖拽准星可定位窗口；选中窗口后可启用或取消防截图保护"),
        m_windowListToolWidget);
    m_windowPickerHintLabel->setToolTip(QStringLiteral("防截图保护会对顶层窗口写入 DisplayAffinity，外部进程窗口会尝试远程调用"));

    pickerButton->setReleaseCallback([this](const QPoint& globalPos) {
        handleWindowPickerRelease(globalPos);
    });

    m_windowListToolLayout->addWidget(m_windowPickerButton, 0);
    m_windowListToolLayout->addWidget(m_protectCaptureButton, 0);
    m_windowListToolLayout->addWidget(m_unprotectCaptureButton, 0);
    auto* inputButton = new QPushButton(m_windowListToolWidget);
    ks::i18n::LanguageManager::instance().bindText(inputButton,
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序"));
    m_windowListToolLayout->addWidget(inputButton);
    connect(inputButton, &QPushButton::clicked, this, [this]
    {
        const auto* item = m_windowTree->currentItem();
        if (!item || item->data(0, Qt::UserRole + 1).toBool()) return;
        const auto* selected = findInfoByHwnd(item->data(0, Qt::UserRole).toULongLong());
        if (selected) openWindowDetailDialog(*selected, true);
    });
    m_windowListToolLayout->addWidget(m_windowPickerHintLabel, 0);
    m_windowListToolLayout->addStretch(1);
    m_windowListPageLayout->addWidget(m_windowListToolWidget, 0);

    // 窗口列表页：左树右预览。
    m_mainSplitter = new QSplitter(Qt::Horizontal, m_windowListPage);
    m_windowListPageLayout->addWidget(m_mainSplitter, 1);

    m_windowTree = new QTreeWidget(m_mainSplitter);
    m_windowTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_windowTree->setRootIsDecorated(true);
    m_windowTree->setAlternatingRowColors(true);
    m_windowTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_windowTree->setUniformRowHeights(true);
    m_windowTree->setSortingEnabled(false);
    m_windowTree->header()->setStyleSheet(blueHeaderStyle());
    m_windowTree->setColumnCount(13);
    m_windowTree->setHeaderLabels({
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
        });
    m_windowTree->header()->setStretchLastSection(false);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnTitle, QHeaderView::Interactive);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnHandle, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnEnumApi, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnClassName, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnPid, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnProcessName, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnTid, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnSize, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnVisible, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnEnabled, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnTopMost, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnState, QHeaderView::ResizeToContents);
    m_windowTree->header()->setSectionResizeMode(kWindowColumnAlpha, QHeaderView::ResizeToContents);
    m_windowTree->setColumnWidth(kWindowColumnTitle, 420);

    m_previewWidget = new QWidget(m_mainSplitter);
    m_previewLayout = new QVBoxLayout(m_previewWidget);
    m_previewLayout->setContentsMargins(6, 6, 6, 6);
    m_previewLayout->setSpacing(6);

    m_thumbnailLabel = new QLabel(m_previewWidget);
    m_thumbnailLabel->setMinimumSize(320, 220);
    m_thumbnailLabel->setAlignment(Qt::AlignCenter);
    m_thumbnailLabel->setStyleSheet(QStringLiteral(
        "border:1px solid %1;background:%2;")
        .arg(KswordTheme::BorderHex(), KswordTheme::SurfaceAltHex()));

    m_captureButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_previewWidget);
    m_captureButton->setToolTip(QStringLiteral("保存当前窗口截图"));
    m_captureButton->setStyleSheet(blueButtonStyle());
    m_captureButton->setFixedWidth(34);

    m_quickInfoText = new CodeEditorWidget(m_previewWidget);
    m_quickInfoText->setReadOnly(true);
    m_quickInfoText->setStyleSheet(blueInputStyle());

    QHBoxLayout* captureLayout = new QHBoxLayout();
    captureLayout->addStretch(1);
    captureLayout->addWidget(m_captureButton, 0);

    m_previewLayout->addWidget(m_thumbnailLabel, 0);
    m_previewLayout->addLayout(captureLayout);
    m_previewLayout->addWidget(m_quickInfoText, 1);

    // 默认把左侧窗口列表区域放宽，避免窗口标题被截断。
    m_mainSplitter->setStretchFactor(0, 4);
    m_mainSplitter->setStretchFactor(1, 1);
    m_contentTabWidget->addTab(m_windowListPage, QStringLiteral("窗口列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_contentTabWidget, m_windowListPage, QStringLiteral("window.tab.list"), QStringLiteral("窗口列表"));

    // 桌面管理页：列出窗口站与桌面，并补充 SessionId / SID / 权限状态等上下文。
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
    m_desktopPageLayout->addLayout(m_desktopToolLayout, 0);

    m_desktopTable = new ks::ui::VisibleTableWidget(m_desktopPage);
    m_desktopTable->setColumnCount(13);
    m_desktopTable->setHorizontalHeaderLabels({
        QStringLiteral("窗口站"),
        QStringLiteral("桌面名称"),
        QStringLiteral("当前站"),
        QStringLiteral("当前桌面"),
        QStringLiteral("交互式"),
        QStringLiteral("可读"),
        QStringLiteral("可切换"),
        QStringLiteral("SessionId"),
        QStringLiteral("所有者"),
        QStringLiteral("SID"),
        QStringLiteral("SID详情"),
        QStringLiteral("堆(KB)"),
        QStringLiteral("备注")
        });
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

    m_contentTabWidget->addTab(m_desktopPage, QStringLiteral("桌面管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_contentTabWidget, m_desktopPage, QStringLiteral("window.tab.desktop"), QStringLiteral("桌面管理"));

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

    // 初始化一次桌面列表，确保打开页签后立即可见。
    refreshDesktopList();
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
        rebuildWindowTreeFromSnapshot();
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
        refreshWindowListAsync();
    });

    // 右键菜单：窗口操作入口。
    connect(m_windowTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showWindowContextMenu(pos);
    });

    // 防截图保护按钮：对当前选中窗口执行启用/取消操作。
    connect(m_protectCaptureButton, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindow(true);
    });
    connect(m_unprotectCaptureButton, &QPushButton::clicked, this, [this]() {
        setCaptureProtectionForSelectedWindow(false);
    });

    // 双击行：直接打开窗口详细信息。
    connect(m_windowTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item, int) {
        if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
        {
            return;
        }
        const quint64 hwndValue = item->data(0, Qt::UserRole).toULongLong();
        const WindowInfo* windowInfo = findInfoByHwnd(hwndValue);
        if (windowInfo != nullptr)
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

    // 选中项变化：更新右侧预览与状态栏“选中”文本。
    connect(m_windowTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* current, QTreeWidgetItem*) {
        const bool isLeaf = current != nullptr && !current->data(0, Qt::UserRole + 1).toBool();
        if (!isLeaf)
        {
            updatePreviewPanel(nullptr);
            m_selectedLabel->setText(QStringLiteral("选中: -"));
            return;
        }

        const quint64 hwndValue = current->data(0, Qt::UserRole).toULongLong();
        const WindowInfo* windowInfo = findInfoByHwnd(hwndValue);
        updatePreviewPanel(windowInfo);
        if (windowInfo != nullptr)
        {
            m_selectedLabel->setText(QStringLiteral("选中: %1  %2")
                .arg(hwndToText(windowInfo->hwndValue), windowInfo->titleText));
            kLogEvent event;
            dbg << event
                << "[OtherDock] 选中窗口变更, hwnd="
                << hwndToText(windowInfo->hwndValue).toStdString()
                << ", title="
                << windowInfo->titleText.toStdString()
                << eol;
        }
    });

    // 截图按钮：把当前选中窗口抓图并保存到文件。
    connect(m_captureButton, &QPushButton::clicked, this, [this]() {
        QTreeWidgetItem* item = m_windowTree->currentItem();
        if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
        {
            kLogEvent event;
            warn << event
                << "[OtherDock] 截图失败：未选中有效窗口。"
                << eol;
            QMessageBox::information(this, QStringLiteral("窗口截图"), QStringLiteral("请先选中一个窗口。"));
            return;
        }

        const quint64 hwndValue = item->data(0, Qt::UserRole).toULongLong();
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
    connect(m_desktopTable, &QTableWidget::cellDoubleClicked, this, [this](int, int) {
        switchToSelectedDesktop();
    });
    connect(m_desktopTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showDesktopContextMenu(pos);
    });
}

void OtherDock::applyViewMode()
{
    // 图标/列表/详情模式通过列显隐与装饰样式切换实现。
    const int mode = m_viewModeCombo->currentIndex();
    if (mode == 0)
    {
        // 图标视图：保留关键列，降低信息密度。
        for (int col = 0; col < m_windowTree->columnCount(); ++col)
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
        for (int col = 0; col < m_windowTree->columnCount(); ++col)
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
        for (int col = 0; col < m_windowTree->columnCount(); ++col)
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

void OtherDock::refreshWindowListAsync()
{
    // 防并发刷新：上一轮未完成时直接忽略当前请求。
    if (m_refreshRunning.exchange(true))
    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 跳过刷新：已有枚举任务在执行。"
            << eol;
        return;
    }

    // 异步刷新链路统一复用 refreshEvent，确保“开始/完成”日志可按同一 GUID 追踪。
    kLogEvent refreshEvent;
    const int enumMode = m_enumModeCombo != nullptr ? m_enumModeCombo->currentIndex() : 0;
    info << refreshEvent
        << "[OtherDock] 启动异步窗口枚举, filterMode="
        << filterModeText(m_filterModeCombo->currentIndex()).toStdString()
        << ", groupMode="
        << groupModeText(m_groupModeCombo->currentIndex()).toStdString()
        << ", enumMode="
        << enumModeText(enumMode).toStdString()
        << ", keyword="
        << m_filterEdit->text().toStdString()
        << eol;

    if (m_refreshProgressPid == 0)
    {
        m_refreshProgressPid = kPro.addReusable(this, "窗口", "窗口枚举");
    }
    kPro.set(m_refreshProgressPid, "开始枚举窗口", 0, 5.0f);

    QPointer<OtherDock> guardThis(this);
    std::thread([guardThis, refreshEvent, enumMode]() {
        std::vector<WindowInfo> snapshot;
        // collectWindowSnapshotByMode 用途：根据用户选择策略采集窗口并去重。
        collectWindowSnapshotByMode(enumMode, snapshot);

        if (guardThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(qApp, [guardThis, snapshot = std::move(snapshot), refreshEvent, enumMode]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            kPro.set(guardThis->m_refreshProgressPid, "合并窗口快照", 0, 70.0f);

            // 记录上一轮有效窗口，作为“新增/退出”对比基线。
            std::vector<WindowInfo> previousValidList;
            previousValidList.reserve(guardThis->m_windowSnapshot.size());
            for (const WindowInfo& info : guardThis->m_windowSnapshot)
            {
                if (info.valid)
                {
                    previousValidList.push_back(info);
                }
            }

            std::unordered_set<quint64> currentHandleSet;
            currentHandleSet.reserve(snapshot.size());
            for (const WindowInfo& info : snapshot)
            {
                currentHandleSet.insert(info.hwndValue);
            }

            std::unordered_set<quint64> previousHandleSet;
            previousHandleSet.reserve(previousValidList.size());
            for (const WindowInfo& info : previousValidList)
            {
                previousHandleSet.insert(info.hwndValue);
            }

            // 计算新增窗口，用于绿色高亮。
            guardThis->m_newWindowHandles.clear();
            for (const WindowInfo& info : snapshot)
            {
                if (previousHandleSet.find(info.hwndValue) == previousHandleSet.end())
                {
                    guardThis->m_newWindowHandles.push_back(info.hwndValue);
                }
            }

            // 计算退出窗口：保留一轮并置灰显示。
            guardThis->m_exitedOneRound.clear();
            for (const WindowInfo& oldInfo : previousValidList)
            {
                if (currentHandleSet.find(oldInfo.hwndValue) != currentHandleSet.end())
                {
                    continue;
                }

                WindowInfo exitedInfo = oldInfo;
                exitedInfo.valid = false;
                exitedInfo.visible = false;
                exitedInfo.enabled = false;
                exitedInfo.topMost = false;
                exitedInfo.minimized = false;
                exitedInfo.maximized = false;
                exitedInfo.titleText = QStringLiteral("[已退出] %1").arg(oldInfo.titleText);
                guardThis->m_exitedOneRound.push_back(exitedInfo);
            }

            // 当前显示列表 = 当前快照 + 退出保留一轮。
            guardThis->m_previousSnapshot = snapshot;
            guardThis->m_windowSnapshot = snapshot;
            guardThis->m_windowSnapshot.insert(
                guardThis->m_windowSnapshot.end(),
                guardThis->m_exitedOneRound.begin(),
                guardThis->m_exitedOneRound.end());

            guardThis->rebuildWindowTreeFromSnapshot();
            guardThis->updateStatusBar();
            guardThis->m_refreshRunning.store(false);
            kPro.set(guardThis->m_refreshProgressPid, "窗口枚举完成", 0, 100.0f);

            info << refreshEvent
                << "[OtherDock] 枚举完成，当前窗口="
                << snapshot.size()
                << ", enumMode="
                << enumModeText(enumMode).toStdString()
                << ", 退出保留="
                << guardThis->m_exitedOneRound.size()
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

bool OtherDock::passFilter(const WindowInfo& info) const
{
    // 外部 PID 过滤（从进程页“查看窗口”跳过来时设置）只是一层额外收窄，
    // 不能顶替下拉条件和关键字：此前这里直接 return，导致跳转过来之后
    // “过滤模式”下拉和关键字输入框还亮着、还能改，却对结果毫无影响——
    // 界面显示“可见窗口”，实际按“该 PID 的全部窗口”执行。
    if (!m_externalProcessIdFilterSet.isEmpty() &&
        !m_externalProcessIdFilterSet.contains(static_cast<quint32>(info.processId)))
    {
        return false;
    }

    // 条件过滤：先按下拉条件筛掉不符合的项。
    const int mode = m_filterModeCombo->currentIndex();
    switch (mode)
    {
    case 0:
        if (!info.visible || !info.valid)
        {
            return false;
        }
        break;
    case 1:
        if (info.visible || !info.valid)
        {
            return false;
        }
        break;
    case 2:
        if (info.isChildWindow || !info.valid)
        {
            return false;
        }
        break;
    case 3:
        if (!info.isChildWindow || !info.valid)
        {
            return false;
        }
        break;
    case 4:
        if (info.valid)
        {
            return false;
        }
        break;
    default:
        break;
    }

    // 关键字过滤：支持标题、类名、进程名和句柄文本。
    const QString keyword = m_filterEdit->text().trimmed();
    if (keyword.isEmpty())
    {
        return true;
    }

    const QString keywordLower = keyword.toLower();
    const QString joinedText = QStringLiteral("%1 %2 %3 %4 %5")
        .arg(info.titleText)
        .arg(info.classNameText)
        .arg(info.processNameText)
        .arg(info.processId)
        .arg(hwndToText(info.hwndValue))
        .toLower();
    return joinedText.contains(keywordLower);
}

void OtherDock::rebuildWindowTreeFromSnapshot()
{
    // 重建树链路统一复用 rebuildEvent，确保“开始/完成”日志可按同一 GUID 追踪。
    kLogEvent rebuildEvent;
    dbg << rebuildEvent
        << "[OtherDock] 重建窗口树开始, snapshotCount="
        << m_windowSnapshot.size()
        << ", filterMode="
        << filterModeText(m_filterModeCombo->currentIndex()).toStdString()
        << ", groupMode="
        << groupModeText(m_groupModeCombo->currentIndex()).toStdString()
        << eol;

    m_windowTree->clear();

    // 进程图标缓存：
    // - 以 PID 作为 key，避免同一进程重复提取图标；
    // - 缓存命中可显著降低刷新时的图标查询开销。
    std::unordered_map<std::uint32_t, QIcon> processLogoCache;
    auto resolveProcessLogo = [&processLogoCache](const WindowInfo& info) -> QIcon {
        const auto found = processLogoCache.find(info.processId);
        if (found != processLogoCache.end())
        {
            return found->second;
        }
        const QIcon processLogo = queryProcessLogoIconByPath(info.processImagePathText);
        processLogoCache.emplace(info.processId, processLogo);
        return processLogo;
    };

    // 公共叶子节点生成函数：统一填充列与高亮规则。
    auto appendLeafItem = [this, &resolveProcessLogo](QTreeWidgetItem* parent, const WindowInfo& info) {
        QTreeWidgetItem* item = nullptr;
        if (parent != nullptr)
        {
            item = new QTreeWidgetItem(parent);
        }
        else
        {
            item = new QTreeWidgetItem(m_windowTree);
        }

        const QString sizeText = QStringLiteral("%1 x %2")
            .arg(info.windowRect.width())
            .arg(info.windowRect.height());

        item->setText(kWindowColumnTitle, info.titleText.isEmpty() ? QStringLiteral("<无标题>") : info.titleText);
        item->setText(kWindowColumnHandle, hwndToText(info.hwndValue));
        item->setText(kWindowColumnEnumApi, info.enumApiName);
        item->setText(kWindowColumnClassName, info.classNameText);
        item->setText(kWindowColumnPid, QString::number(info.processId));
        item->setText(kWindowColumnProcessName, info.processNameText);
        item->setText(kWindowColumnTid, QString::number(info.threadId));
        item->setText(kWindowColumnSize, sizeText);
        item->setText(kWindowColumnVisible, boolText(info.visible));
        item->setText(kWindowColumnEnabled, boolText(info.enabled));
        item->setText(kWindowColumnTopMost, boolText(info.topMost));
        item->setText(kWindowColumnState, windowStateText(info.valid, info.minimized, info.maximized));
        item->setText(kWindowColumnAlpha, QString::number(info.alphaValue));

        item->setData(kWindowColumnTitle, Qt::UserRole, QVariant::fromValue(static_cast<qulonglong>(info.hwndValue)));
        item->setData(kWindowColumnTitle, Qt::UserRole + 1, false);

        // 叶子图标改为显示“进程 logo”，并放到进程列，避免标题列图标干扰阅读。
        item->setIcon(kWindowColumnProcessName, resolveProcessLogo(info));

        // 新增窗口高亮绿色，退出窗口置灰。
        const bool isNew = std::find(
            m_newWindowHandles.begin(),
            m_newWindowHandles.end(),
            info.hwndValue) != m_newWindowHandles.end();

        if (!info.valid)
        {
            for (int col = 0; col < m_windowTree->columnCount(); ++col)
            {
                item->setForeground(col, QBrush(KswordTheme::ExitedRowForegroundColor()));
                item->setBackground(col, QBrush(KswordTheme::ExitedRowBackgroundColor()));
            }
        }
        else if (isNew)
        {
            for (int col = 0; col < m_windowTree->columnCount(); ++col)
            {
                item->setBackground(col, QBrush(KswordTheme::NewRowBackgroundColor()));
            }
        }
    };

    // 根据分组选项重建树结构。
    const int groupMode = m_groupModeCombo->currentIndex();

    if (groupMode == 0)
    {
        // 按进程分组：进程节点下挂对应窗口子节点。
        std::map<QString, QTreeWidgetItem*> processMap;
        for (const WindowInfo& info : m_windowSnapshot)
        {
            if (!passFilter(info))
            {
                continue;
            }

            const QString processKey = QStringLiteral("%1 (PID:%2)")
                .arg(info.processNameText, QString::number(info.processId));
            QTreeWidgetItem* groupItem = nullptr;
            auto found = processMap.find(processKey);
            if (found == processMap.end())
            {
                groupItem = new QTreeWidgetItem(m_windowTree);
                groupItem->setText(0, processKey);
                // 进程分组节点同样展示进程 logo，满足“所有进程都显示图标”的需求。
                groupItem->setIcon(0, resolveProcessLogo(info));
                groupItem->setData(0, Qt::UserRole + 1, true);
                processMap.emplace(processKey, groupItem);
            }
            else
            {
                groupItem = found->second;
            }
            appendLeafItem(groupItem, info);
        }
    }
    else if (groupMode == 1)
    {
        // 按 Z 序：平铺显示，按枚举顺序排序。
        std::vector<WindowInfo> orderedList = m_windowSnapshot;
        std::sort(
            orderedList.begin(),
            orderedList.end(),
            [](const WindowInfo& left, const WindowInfo& right) {
                return left.zOrder < right.zOrder;
            });
        for (const WindowInfo& info : orderedList)
        {
            if (!passFilter(info))
            {
                continue;
            }
            appendLeafItem(nullptr, info);
        }
    }
    else if (groupMode == 2)
    {
        // 按层级：桌面/顶层/子窗口/弹出窗口/工具窗口分类。
        std::map<QString, QTreeWidgetItem*> levelGroupMap;
        auto getLevelGroup = [this, &levelGroupMap](const QString& key) -> QTreeWidgetItem* {
            auto found = levelGroupMap.find(key);
            if (found != levelGroupMap.end())
            {
                return found->second;
            }
            QTreeWidgetItem* item = new QTreeWidgetItem(m_windowTree);
            item->setText(0, key);
            item->setIcon(0, QIcon(":/Icon/process_tree.svg"));
            item->setData(0, Qt::UserRole + 1, true);
            levelGroupMap.emplace(key, item);
            return item;
        };

        for (const WindowInfo& info : m_windowSnapshot)
        {
            if (!passFilter(info))
            {
                continue;
            }

            QString groupKey = QStringLiteral("顶级窗口");
            if (info.hwndValue == static_cast<quint64>(reinterpret_cast<quintptr>(::GetDesktopWindow())))
            {
                groupKey = QStringLiteral("桌面窗口");
            }
            else if (info.isChildWindow)
            {
                groupKey = QStringLiteral("子窗口");
            }
            else if ((info.styleValue & WS_POPUP) != 0)
            {
                groupKey = QStringLiteral("弹出窗口");
            }
            else if ((info.exStyleValue & WS_EX_TOOLWINDOW) != 0)
            {
                groupKey = QStringLiteral("工具窗口");
            }

            appendLeafItem(getLevelGroup(groupKey), info);
        }
    }
    else
    {
        // 按显示器：依据窗口中心点所在屏幕分组。
        std::map<QString, QTreeWidgetItem*> monitorGroupMap;
        const QList<QScreen*> screenList = QGuiApplication::screens();

        auto getMonitorGroup = [this, &monitorGroupMap](const QString& key) -> QTreeWidgetItem* {
            auto found = monitorGroupMap.find(key);
            if (found != monitorGroupMap.end())
            {
                return found->second;
            }
            QTreeWidgetItem* item = new QTreeWidgetItem(m_windowTree);
            item->setText(0, key);
            item->setIcon(0, QIcon(":/Icon/process_list.svg"));
            item->setData(0, Qt::UserRole + 1, true);
            monitorGroupMap.emplace(key, item);
            return item;
        };

        for (const WindowInfo& info : m_windowSnapshot)
        {
            if (!passFilter(info))
            {
                continue;
            }

            QString groupKey = QStringLiteral("未知显示器");
            const QPoint centerPoint = info.windowRect.center();
            for (int i = 0; i < screenList.size(); ++i)
            {
                QScreen* screen = screenList.at(i);
                if (screen != nullptr && screen->geometry().contains(centerPoint))
                {
                    groupKey = QStringLiteral("显示器%1: %2")
                        .arg(i + 1)
                        .arg(screen->name());
                    break;
                }
            }
            appendLeafItem(getMonitorGroup(groupKey), info);
        }
    }

    // 统一展开第一层节点，便于用户直接看到数据。
    for (int i = 0; i < m_windowTree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* topItem = m_windowTree->topLevelItem(i);
        if (topItem != nullptr && topItem->data(0, Qt::UserRole + 1).toBool())
        {
            topItem->setExpanded(true);
        }
    }

    dbg << rebuildEvent
        << "[OtherDock] 重建窗口树完成, topLevelCount="
        << m_windowTree->topLevelItemCount()
        << eol;
}

void OtherDock::updateStatusBar()
{
    int totalCount = 0;
    int visibleCount = 0;
    int systemCount = 0;
    for (const WindowInfo& info : m_windowSnapshot)
    {
        if (!info.valid)
        {
            continue;
        }
        ++totalCount;
        if (info.visible)
        {
            ++visibleCount;
        }
        if (info.processId <= 4
            || info.processNameText.compare(QStringLiteral("System"), Qt::CaseInsensitive) == 0
            || info.processNameText.compare(QStringLiteral("csrss.exe"), Qt::CaseInsensitive) == 0)
        {
            ++systemCount;
        }
    }

    m_totalLabel->setText(QStringLiteral("总数: %1").arg(totalCount));
    m_visibleLabel->setText(QStringLiteral("可见: %1").arg(visibleCount));
    m_systemLabel->setText(QStringLiteral("系统: %1").arg(systemCount));

    kLogEvent event;
    dbg << event
        << "[OtherDock] 状态栏更新, total="
        << totalCount
        << ", visible="
        << visibleCount
        << ", system="
        << systemCount
        << eol;
}

void OtherDock::updatePreviewPanel(const WindowInfo* info)
{
    // 无选中项时清空预览，防止显示过期信息。
    if (info == nullptr)
    {
        m_thumbnailLabel->setPixmap(QPixmap());
        m_quickInfoText->setText(QStringLiteral("请选择左侧窗口项查看预览。"));
        kLogEvent event;
        dbg << event
            << "[OtherDock] 预览面板清空（无有效选中项）。"
            << eol;
        return;
    }

    // 抓取缩略图并更新右侧关键属性摘要。
    const QPixmap previewPixmap = grabWindowPreviewPixmap(
        info->hwndValue,
        m_thumbnailLabel->size());
    m_thumbnailLabel->setPixmap(previewPixmap);

    QString quickText;
    quickText += QStringLiteral("句柄: %1\n").arg(hwndToText(info->hwndValue));
    quickText += QStringLiteral("标题: %1\n").arg(info->titleText);
    quickText += QStringLiteral("类名: %1\n").arg(info->classNameText);
    quickText += QStringLiteral("PID/TID: %1 / %2\n").arg(info->processId).arg(info->threadId);
    quickText += QStringLiteral("进程名: %1\n").arg(info->processNameText);
    quickText += QStringLiteral("矩形: [%1,%2,%3,%4]\n")
        .arg(info->windowRect.left())
        .arg(info->windowRect.top())
        .arg(info->windowRect.right())
        .arg(info->windowRect.bottom());
    quickText += QStringLiteral("可见:%1  可用:%2  顶层:%3\n")
        .arg(boolText(info->visible))
        .arg(boolText(info->enabled))
        .arg(boolText(info->topMost));
    quickText += QStringLiteral("状态:%1  透明度:%2\n")
        .arg(windowStateText(info->valid, info->minimized, info->maximized))
        .arg(info->alphaValue);
    if (info->displayAffinityKnown)
    {
        const QString affinityHexText =
            QString::number(static_cast<qulonglong>(info->displayAffinityValue), 16).toUpper();
        quickText += QStringLiteral("DisplayAffinity: 0x%1 (%2)\n")
            .arg(affinityHexText)
            .arg(QString::fromStdString(ks::window::DisplayAffinityName(info->displayAffinityValue)));
    }
    else
    {
        quickText += QStringLiteral("DisplayAffinity: 未知（错误码=%1）\n")
            .arg(info->displayAffinityError);
    }
    m_quickInfoText->setText(quickText);

    kLogEvent event;
    dbg << event
        << "[OtherDock] 预览面板刷新, hwnd="
        << hwndToText(info->hwndValue).toStdString()
        << ", pid="
        << info->processId
        << eol;
}

void OtherDock::handleWindowPickerRelease(const QPoint& globalPos)
{
    // 拾取链路统一复用 pickEvent，保证从“拖拽释放”到“打开详情”全程可追踪。
    kLogEvent pickEvent;
    info << pickEvent
        << "[OtherDock] 准星拾取释放, x="
        << globalPos.x()
        << ", y="
        << globalPos.y()
        << eol;

    POINT nativePoint{};
    nativePoint.x = globalPos.x();
    nativePoint.y = globalPos.y();

    // rawWindowHandle 直接对应鼠标下最细粒度窗口；rootWindowHandle 作为顶级窗口回退。
    HWND rawWindowHandle = ::WindowFromPoint(nativePoint);
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

void OtherDock::showWindowContextMenu(const QPoint& localPos)
{
    QTreeWidgetItem* item = m_windowTree->itemAt(localPos);
    if (item == nullptr || item->data(0, Qt::UserRole + 1).toBool())
    {
        return;
    }

    const quint64 hwndValue = item->data(0, Qt::UserRole).toULongLong();
    const WindowInfo* windowInfo = findInfoByHwnd(hwndValue);
    if (windowInfo == nullptr)
    {
        return;
    }

    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 打开右键菜单, hwnd="
            << hwndToText(hwndValue).toStdString()
            << ", pid="
            << windowInfo->processId
            << eol;
    }

    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* activateAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("激活窗口"));
    QAction* topMostAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("置顶/取消置顶"));
    QAction* showHideAction = menu.addAction(QIcon(":/Icon/process_pause.svg"), QStringLiteral("显示/隐藏"));
    QAction* enableDisableAction = menu.addAction(QIcon(":/Icon/process_suspend.svg"), QStringLiteral("启用/禁用"));
    const WindowInfo inputSnapshot = *windowInfo;
    QAction* inputAction = menu.addAction(ks::i18n::text(
        QStringLiteral("window.input.tab"), QStringLiteral("窗口输入与顺序")));
    QAction* flashAction = menu.addAction(QIcon(":/Icon/window_picker_target.svg"), QStringLiteral("闪烁窗口"));
    QAction* protectCaptureAction = menu.addAction(QIcon(":/Icon/titlebar_capture_protected.svg"), QStringLiteral("启用防截图保护"));
    QAction* unprotectCaptureAction = menu.addAction(QIcon(":/Icon/titlebar_capture_allowed.svg"), QStringLiteral("取消防截图保护"));
    menu.addSeparator();
    QAction* processDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* windowDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("在详细信息中打开"));
    QAction* sendMessageAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("发送测试消息"));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [windowInfo]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：窗口列表当前右键窗口快照。
            // 处理：按 GUI 线程所属 PID 上传对应进程文件；窗口线程 ID 仅用于来源说明。
            // 返回：VT 上传目标；PID 为空或进程路径无法解析时交由统一 helper 提示。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (windowInfo == nullptr || windowInfo->processId == 0)
            {
                uploadTarget.errorText = QStringLiteral("当前窗口没有可解析的 GUI 线程进程 PID。");
                return uploadTarget;
            }
            uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(windowInfo->processId));
            uploadTarget.sourceText = QStringLiteral("窗口 GUI 线程 PID=%1 TID=%2")
                .arg(windowInfo->processId)
                .arg(windowInfo->threadId);
            return uploadTarget;
        });
    menu.addSeparator();
    QAction* terminateAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("结束进程"));

    QAction* selectedAction = menu.exec(m_windowTree->viewport()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 右键菜单取消, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        return;
    }

    if (selectedAction == inputAction)
    {
        openWindowDetailDialog(inputSnapshot, true);
        return;
    }
    HWND windowHandle = toHwnd(windowInfo->hwndValue);
    if (selectedAction == activateAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：激活窗口, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        ::ShowWindow(windowHandle, SW_SHOW);
        ::SetForegroundWindow(windowHandle);
    }
    else if (selectedAction == topMostAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：切换置顶, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        const bool currentTopMost = (::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
        ::SetWindowPos(
            windowHandle,
            currentTopMost ? HWND_NOTOPMOST : HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    else if (selectedAction == showHideAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：显示/隐藏, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        const bool currentlyVisible = ::IsWindowVisible(windowHandle) != FALSE;
        ::ShowWindow(windowHandle, currentlyVisible ? SW_HIDE : SW_SHOW);
    }
    else if (selectedAction == enableDisableAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：启用/禁用, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        const bool currentlyEnabled = ::IsWindowEnabled(windowHandle) != FALSE;
        ::EnableWindow(windowHandle, currentlyEnabled ? FALSE : TRUE);
    }
    else if (selectedAction == flashAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：闪烁窗口, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        FLASHWINFO flashInfo{};
        flashInfo.cbSize = sizeof(flashInfo);
        flashInfo.hwnd = windowHandle;
        flashInfo.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
        flashInfo.uCount = 3;
        flashInfo.dwTimeout = 0;
        ::FlashWindowEx(&flashInfo);
    }
    else if (selectedAction == protectCaptureAction)
    {
        setCaptureProtectionForWindow(*windowInfo, true);
    }
    else if (selectedAction == unprotectCaptureAction)
    {
        setCaptureProtectionForWindow(*windowInfo, false);
    }
    else if (selectedAction == processDetailAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：打开进程详情, pid="
            << windowInfo->processId
            << eol;
        openProcessDetailWindow(this, windowInfo->processId);
    }
    else if (selectedAction == windowDetailAction)
    {
        kLogEvent event;
        info << event
            << "[OtherDock] 执行操作：打开窗口详情, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        openWindowDetailDialog(*windowInfo);
    }
    else if (selectedAction == sendMessageAction)
    {
        kLogEvent event;
        dbg << event
            << "[OtherDock] 执行操作：发送测试消息, hwnd="
            << hwndToText(hwndValue).toStdString()
            << eol;
        DWORD_PTR resultValue = 0;
        ::SendMessageTimeoutW(
            windowHandle,
            WM_NULL,
            0,
            0,
            SMTO_ABORTIFHUNG,
            1200,
            &resultValue);
        Q_UNUSED(resultValue);
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == terminateAction)
    {
        const QString targetDescription = ks::i18n::sourceText(QStringLiteral("PID %1（%2）"))
            .arg(windowInfo->processId)
            .arg(windowInfo->processNameText);
        if (!ks::ui::confirmDestructiveAction(
                this,
                QStringLiteral("process-termination-r3"),
                ks::i18n::sourceText(QStringLiteral("结束进程")),
                targetDescription))
        {
            return;
        }

        // 结束进程动作：确认后执行，结果继续通过统一日志记录。
        kLogEvent actionEvent;
        warn << actionEvent
            << "[OtherDock] 执行操作：结束进程, pid="
            << windowInfo->processId
            << eol;

        std::string terminateErrorText;
        const bool terminateOk = ks::process::TerminateProcessByWin32IfCreationTimeMatches(
            static_cast<std::uint32_t>(windowInfo->processId),
            windowInfo->processCreationTime100ns,
            &terminateErrorText);
        if (!terminateOk)
        {
            err << actionEvent
                << "[OtherDock] 结束进程失败, pid="
                << windowInfo->processId
                << ", detail=" << terminateErrorText
                << eol;
        }
        else
        {
            warn << actionEvent
                << "[OtherDock] 结束进程成功, pid="
                << windowInfo->processId
                << eol;
        }
        dbg << actionEvent
            << "[OtherDock] 结束进程操作处理完毕, pid="
            << windowInfo->processId
            << ", processName="
            << windowInfo->processNameText.toStdString()
            << eol;
    }

    // 任意状态类动作后都刷新一次，确保列表与真实状态一致。
    if (selectedAction != protectCaptureAction && selectedAction != unprotectCaptureAction)
    {
        refreshWindowListAsync();
    }
}

void OtherDock::exportVisibleRowsToTsv()
{
    // 遍历当前树，导出叶子节点；分组节点不参与导出。
    QStringList lines;

    QStringList header;
    for (int col = 0; col < m_windowTree->columnCount(); ++col)
    {
        if (m_windowTree->isColumnHidden(col))
        {
            continue;
        }
        header << m_windowTree->headerItem()->text(col);
    }
    lines << header.join('\t');

    QTreeWidgetItemIterator iterator(m_windowTree);
    while (*iterator != nullptr)
    {
        QTreeWidgetItem* item = *iterator;
        ++iterator;

        if (item->data(0, Qt::UserRole + 1).toBool())
        {
            continue;
        }

        QStringList rowValues;
        for (int col = 0; col < m_windowTree->columnCount(); ++col)
        {
            if (m_windowTree->isColumnHidden(col))
            {
                continue;
            }
            rowValues << item->text(col).replace('\t', ' ');
        }
        lines << rowValues.join('\t');
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
    const auto finder = [hwndValue](const WindowInfo& info) {
        return info.hwndValue == hwndValue;
    };

    const auto currentIt = std::find_if(
        m_windowSnapshot.begin(),
        m_windowSnapshot.end(),
        finder);
    if (currentIt != m_windowSnapshot.end())
    {
        return &(*currentIt);
    }

    const auto exitIt = std::find_if(
        m_exitedOneRound.begin(),
        m_exitedOneRound.end(),
        finder);
    if (exitIt != m_exitedOneRound.end())
    {
        return &(*exitIt);
    }

    return nullptr;
}
