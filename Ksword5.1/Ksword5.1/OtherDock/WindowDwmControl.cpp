// ============================================================
// WindowDwmControl.cpp
// 作用说明：
// 1) 给“窗口属性”详情对话框追加一个 DWM 合成控制页；
// 2) 对任意目标窗口读写 DWMWA_* 属性（非客户区渲染策略、过渡动画、
//    Flip3D 策略、Peek 策略、Cloak 隐藏、暗色标题栏、圆角策略、
//    边框/标题栏/标题文字配色、Mica/Acrylic 背景材质等）；
// 3) 提供 DwmExtendFrameIntoClientArea / DwmEnableBlurBehindWindow /
//    SetWindowCompositionAttribute(ACCENT_POLICY) 三类合成效果控制；
// 4) 通过 DwmRegisterThumbnail 在页面内嵌入目标窗口的实时缩略图；
// 5) 汇总系统级合成状态（合成开关、主题色、合成时序）并支持导出报告。
// 设计说明：
// - 与 WindowLayerDiagnostics 一致，本页通过应用级事件过滤器注入到
//   WindowDetailDialogRoot，不需要改动 WindowDetailDialog 自身；
// - DWM 属性调用会跨进程转发到 DWM，本页对每次调用都保留 HRESULT，
//   失败原因如实展示，不做“看起来成功”的伪装。
// ============================================================

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSlider>
#include <QSpinBox>
#include <QSplitter>
#include <QString>
#include <QStringList>
#include <QTabWidget>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextStream>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>
#include <QWidget>

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <array>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <uxtheme.h>
#include <dwmapi.h>

#pragma comment(lib, "Dwmapi.lib")

namespace ks::window::dwmctl
{
    // kAttachedProperty 作用：标记某个详情对话框已经注入过 DWM 页，避免重复添加。
    constexpr char kAttachedProperty[] = "ksword.windowDwmControl.attached";
    // kTargetHwndProperty 作用：WindowDetailDialog 发布的目标 HWND 元数据键。
    constexpr char kTargetHwndProperty[] = "ksword.windowDetail.targetHwnd";

    // ============ DWMWINDOWATTRIBUTE 编号 ============
    // 说明：这里不直接引用 SDK 枚举，保证在较旧 SDK 上也能编译，
    //       并且让“系统是否支持”完全由运行期 HRESULT 决定。
    constexpr DWORD kAttrNcRenderingEnabled = 1;          // [读] 非客户区是否正在由 DWM 渲染。
    constexpr DWORD kAttrNcRenderingPolicy = 2;           // [写] 非客户区渲染策略。
    constexpr DWORD kAttrTransitionsForceDisabled = 3;    // [读写] 强制关闭窗口过渡动画。
    constexpr DWORD kAttrAllowNcPaint = 4;                // [写] 允许窗口自绘非客户区。
    constexpr DWORD kAttrCaptionButtonBounds = 5;         // [读] 标题栏按钮区域矩形。
    constexpr DWORD kAttrNonClientRtlLayout = 6;          // [写] 非客户区右到左布局。
    constexpr DWORD kAttrForceIconicRepresentation = 7;   // [写] 强制使用静态缩略图。
    constexpr DWORD kAttrFlip3DPolicy = 8;                // [写] Flip3D 中的显示策略。
    constexpr DWORD kAttrExtendedFrameBounds = 9;         // [读] 含阴影修正的真实边框矩形。
    constexpr DWORD kAttrHasIconicBitmap = 10;            // [写] 声明提供 iconic 位图。
    constexpr DWORD kAttrDisallowPeek = 11;               // [写] 禁止本窗口触发 Aero Peek。
    constexpr DWORD kAttrExcludedFromPeek = 12;           // [写] Peek 时排除本窗口。
    constexpr DWORD kAttrCloak = 13;                      // [写] 对 DWM 隐藏窗口（窗口仍存在）。
    constexpr DWORD kAttrCloaked = 14;                    // [读] 当前 Cloak 来源位。
    constexpr DWORD kAttrFreezeRepresentation = 15;       // [写] 冻结缩略图表示。
    constexpr DWORD kAttrPassiveUpdateMode = 16;          // [写] 被动更新模式。
    constexpr DWORD kAttrUseHostBackdropBrush = 17;       // [写] 使用宿主背景画刷。
    constexpr DWORD kAttrImmersiveDarkModeLegacy = 19;    // [写] 暗色标题栏（1809~1903 旧编号）。
    constexpr DWORD kAttrImmersiveDarkMode = 20;          // [写] 暗色标题栏（1909+ 编号）。
    constexpr DWORD kAttrWindowCornerPreference = 33;     // [写] 窗口圆角策略（Win11）。
    constexpr DWORD kAttrBorderColor = 34;                // [写] 窗口边框颜色（Win11）。
    constexpr DWORD kAttrCaptionColor = 35;               // [写] 标题栏背景色（Win11）。
    constexpr DWORD kAttrTextColor = 36;                  // [写] 标题栏文字色（Win11）。
    constexpr DWORD kAttrVisibleFrameBorderThickness = 37;// [读] 可见边框厚度（Win11）。
    constexpr DWORD kAttrSystemBackdropType = 38;         // [读写] 背景材质 Mica/Acrylic（Win11 22H2）。

    // kColorDefault / kColorNone 作用：DWMWA_*_COLOR 的两个特殊值。
    constexpr DWORD kColorDefault = 0xFFFFFFFFu;
    constexpr DWORD kColorNone = 0xFFFFFFFEu;

    // 构建号门槛：仅用于界面提示，不阻止用户实际尝试调用。
    constexpr DWORD kBuildWin10Dark = 17763;
    constexpr DWORD kBuildWin10DarkNew = 18362;
    constexpr DWORD kBuildWin11 = 22000;
    constexpr DWORD kBuildWin11_22H2 = 22621;

    // SetWindowCompositionAttribute 相关（未公开接口，用于 Acrylic/模糊）。
    constexpr DWORD kWcaAccentPolicy = 19;        // WCA_ACCENT_POLICY。
    constexpr DWORD kWcaUseDarkModeColors = 26;   // WCA_USEDARKMODECOLORS。

    // kThumbnailRefreshMs 作用：缩略图目标矩形跟随刷新周期，兼顾跟手与开销。
    constexpr int kThumbnailRefreshMs = 120;
    // kLogBlockLimit 作用：操作日志最大保留行数。
    constexpr int kLogBlockLimit = 2000;

    // AccentPolicyData 说明：对应未公开的 ACCENT_POLICY 结构体布局。
    struct AccentPolicyData
    {
        DWORD accentState = 0;     // accentState：ACCENT_STATE 枚举值。
        DWORD accentFlags = 0;     // accentFlags：绘制标志位。
        DWORD gradientColor = 0;   // gradientColor：0xAABBGGRR 顺序的着色值。
        DWORD animationId = 0;     // animationId：动画标识，通常填 0。
    };

    // WindowCompositionAttributeData 说明：对应未公开的 WINDOWCOMPOSITIONATTRIBDATA。
    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;       // attribute：WCA_* 特性编号。
        void* data = nullptr;      // data：特性数据缓冲区。
        SIZE_T dataSize = 0;       // dataSize：缓冲区字节数。
    };

    // ============ 通用小工具 ============

    // uiText：
    // - 作用：按语义键取译文，缺失时回落到内置中文；
    // - 传入 key：语言包语义键；传入 fallback：中文兜底文案；
    // - 传出：当前语言下应显示的文本。
    QString uiText(const char* key, const char* fallback)
    {
        return ks::i18n::text(QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    // bindUiText：
    // - 作用：把控件文本与语义键绑定，运行期切换语言时自动重绘；
    // - 传入 object：目标控件；传入 key/fallback：同 uiText。
    void bindUiText(QObject* object, const char* key, const char* fallback)
    {
        ks::i18n::LanguageManager::instance().bindText(
            object, QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    // makeButton：
    // - 作用：创建按钮并同时完成语言绑定，避免每处重复两行；
    // - 传出：已设置文本与绑定的按钮指针。
    QPushButton* makeButton(QWidget* parent, const char* key, const char* label)
    {
        QPushButton* button = new QPushButton(uiText(key, label), parent);
        bindUiText(button, key, label);
        return button;
    }

    // makeGroup：
    // - 作用：创建分组框并完成语言绑定。
    QGroupBox* makeGroup(QWidget* parent, const char* key, const char* label)
    {
        QGroupBox* group = new QGroupBox(uiText(key, label), parent);
        bindUiText(group, key, label);
        return group;
    }

    // makeLabel：
    // - 作用：创建静态文本标签并完成语言绑定。
    QLabel* makeLabel(QWidget* parent, const char* key, const char* label)
    {
        QLabel* widget = new QLabel(uiText(key, label), parent);
        bindUiText(widget, key, label);
        return widget;
    }

    // hwndText：把窗口句柄格式化为大写十六进制文本。
    QString hwndText(HWND hwnd)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(hwnd)), 0, 16)
            .toUpper();
    }

    // hexText：把无符号整数格式化为大写十六进制文本。
    QString hexText(quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    }

    // rectText：把 RECT 格式化为 [l,t,r,b] 及尺寸。
    QString rectText(const RECT& rect)
    {
        return QStringLiteral("[%1,%2,%3,%4] %5x%6")
            .arg(rect.left).arg(rect.top).arg(rect.right).arg(rect.bottom)
            .arg(rect.right - rect.left).arg(rect.bottom - rect.top);
    }

    // windowsBuild：
    // - 作用：用 RtlGetVersion 读取真实构建号，绕开兼容性清单造成的版本谎报；
    // - 传出：构建号，取不到时返回 0。
    DWORD windowsBuild()
    {
        static const DWORD buildNumber = []() -> DWORD {
            using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
            const HMODULE ntdllModuleHandle = ::GetModuleHandleW(L"ntdll.dll");
            if (ntdllModuleHandle == nullptr)
            {
                return 0;
            }
            const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFunction>(
                ::GetProcAddress(ntdllModuleHandle, "RtlGetVersion"));
            if (rtlGetVersion == nullptr)
            {
                return 0;
            }
            OSVERSIONINFOW versionInfo{};
            versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
            return rtlGetVersion(&versionInfo) == 0 ? versionInfo.dwBuildNumber : 0;
        }();
        return buildNumber;
    }

    // darkModeAttribute：
    // - 作用：1809~1903 之间暗色标题栏用编号 19，之后改为 20，这里按构建号选择；
    // - 传出：当前系统应使用的属性编号。
    DWORD darkModeAttribute()
    {
        const DWORD build = windowsBuild();
        return (build != 0 && build < kBuildWin10DarkNew) ? kAttrImmersiveDarkModeLegacy : kAttrImmersiveDarkMode;
    }

    // hresultText：
    // - 作用：把 HRESULT 翻成“十六进制 + 常见语义解释”，让失败可诊断；
    // - 传入 result：DWM 调用返回值；
    // - 传出：可直接写进状态栏与日志的短文本。
    QString hresultText(HRESULT result)
    {
        if (SUCCEEDED(result))
        {
            return QStringLiteral("S_OK");
        }

        QString explanation;
        switch (static_cast<unsigned long>(result))
        {
        case 0x80070057ul:
            explanation = uiText("window.dwm.hr.invalid_arg", "当前系统不支持该属性，或数据长度不匹配");
            break;
        case 0x80070006ul:
            explanation = uiText("window.dwm.hr.invalid_handle", "窗口句柄无效或已销毁");
            break;
        case 0x80070005ul:
            explanation = uiText("window.dwm.hr.access_denied",
                "访问被拒绝：该属性只允许窗口所属进程设置，或目标完整性级别更高");
            break;
        case 0x80263001ul:
            explanation = uiText("window.dwm.hr.composition_disabled", "桌面窗口管理器合成当前处于关闭状态");
            break;
        case 0x80263002ul:
            explanation = uiText("window.dwm.hr.remoting", "远程会话不支持该合成能力");
            break;
        case 0x800706BAul:
            explanation = uiText("window.dwm.hr.rpc_unavailable", "DWM 服务不可用");
            break;
        case 0x80004001ul:
            explanation = uiText("window.dwm.hr.not_impl", "该接口在当前系统上未实现");
            break;
        default:
            break;
        }

        const QString code = hexText(static_cast<quint64>(static_cast<quint32>(result)));
        return explanation.isEmpty() ? code : QStringLiteral("%1 (%2)").arg(code, explanation);
    }

    // ============ DWM 读写封装 ============

    // DwordResult：一次 4 字节属性读取的完整结果。
    struct DwordResult
    {
        bool ok = false;              // ok：HRESULT 是否成功。
        HRESULT hr = S_OK;            // hr：原始返回值。
        DWORD value = 0;              // value：读到的属性值。
    };

    // readDwordAttribute：
    // - 作用：读取一个 4 字节的 DWMWA_* 属性；
    // - 传入 hwnd/attribute：目标窗口与属性编号；
    // - 传出：DwordResult，失败时 ok=false 且保留 HRESULT。
    DwordResult readDwordAttribute(HWND hwnd, DWORD attribute)
    {
        DwordResult result;
        DWORD value = 0;
        result.hr = ::DwmGetWindowAttribute(hwnd, attribute, &value, sizeof(value));
        result.ok = SUCCEEDED(result.hr);
        result.value = result.ok ? value : 0;
        return result;
    }

    // writeDwordAttribute：
    // - 作用：写入一个 4 字节的 DWMWA_* 属性；
    // - 传出：DWM 返回的 HRESULT，调用方负责展示。
    HRESULT writeDwordAttribute(HWND hwnd, DWORD attribute, DWORD value)
    {
        return ::DwmSetWindowAttribute(hwnd, attribute, &value, sizeof(value));
    }

    // RectResult：一次 RECT 属性读取的完整结果。
    struct RectResult
    {
        bool ok = false;
        HRESULT hr = S_OK;
        RECT value{};
    };

    // readRectAttribute：读取 RECT 型只读属性（边框矩形、标题按钮区域）。
    RectResult readRectAttribute(HWND hwnd, DWORD attribute)
    {
        RectResult result;
        RECT value{};
        result.hr = ::DwmGetWindowAttribute(hwnd, attribute, &value, sizeof(value));
        result.ok = SUCCEEDED(result.hr);
        result.value = result.ok ? value : RECT{};
        return result;
    }

    // resolveSetWindowCompositionAttribute：
    // - 作用：解析 user32 中未公开的 SetWindowCompositionAttribute；
    // - 传出：函数指针，系统不提供时返回 nullptr。
    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);
    SetWindowCompositionAttributeFunction resolveSetWindowCompositionAttribute()
    {
        static const SetWindowCompositionAttributeFunction function =
            []() -> SetWindowCompositionAttributeFunction {
                const HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
                if (user32ModuleHandle == nullptr)
                {
                    return nullptr;
                }
                return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetWindowCompositionAttribute"));
            }();
        return function;
    }

    // ============ 属性行规格 ============

    // RowKind 作用：决定属性行使用哪种编辑控件。
    enum class RowKind
    {
        Boolean,   // 布尔属性：下拉选择 TRUE/FALSE。
        Enumerated,// 枚举属性：下拉选择具名取值。
        Color      // 配色属性：默认/无/自定义三种模式。
    };

    // EnumOption 作用：枚举属性的一个候选项。
    struct EnumOption
    {
        DWORD value = 0;         // value：写入 DWM 的原始数值。
        const char* key = "";    // key：语言包语义键。
        const char* label = "";  // label：中文兜底文案。
    };

    // RowSpec 作用：描述一条可控 DWM 属性的全部静态信息。
    struct RowSpec
    {
        DWORD attribute = 0;              // attribute：DWMWA_* 编号。
        const char* apiName = "";         // apiName：Win32 常量名，直接对照文档。
        const char* tipKey = "";          // tipKey：说明文本语义键。
        const char* tip = "";             // tip：说明文本中文兜底。
        RowKind kind = RowKind::Boolean;  // kind：控件形态。
        DWORD minimumBuild = 0;           // minimumBuild：官方引入的构建号，0 表示 Vista 起可用。
        bool destructive = false;         // destructive：是否需要二次确认（会让窗口消失等）。
        std::vector<EnumOption> options;  // options：枚举候选项。
    };

    // booleanRowSpecs：
    // - 作用：返回全部布尔型 DWM 属性的规格表；
    // - 说明：暗色标题栏的属性编号在运行期按构建号决定，这里先占位。
    const std::vector<RowSpec>& booleanRowSpecs()
    {
        static const std::vector<RowSpec> specs = {
            { kAttrTransitionsForceDisabled, "DWMWA_TRANSITIONS_FORCEDISABLED",
              "window.dwm.attr.transitions", "强制关闭该窗口的最小化/最大化等过渡动画。",
              RowKind::Boolean, 0, false, {} },
            { kAttrAllowNcPaint, "DWMWA_ALLOW_NCPAINT",
              "window.dwm.attr.allow_ncpaint", "允许窗口自己在非客户区绘制，通常配合自绘标题栏使用。",
              RowKind::Boolean, 0, false, {} },
            { kAttrNonClientRtlLayout, "DWMWA_NONCLIENT_RTL_LAYOUT",
              "window.dwm.attr.rtl_layout", "把非客户区改为从右到左布局，标题栏按钮会镜像到左侧。",
              RowKind::Boolean, 0, false, {} },
            { kAttrForceIconicRepresentation, "DWMWA_FORCE_ICONIC_REPRESENTATION",
              "window.dwm.attr.force_iconic", "强制任务栏使用窗口提供的静态缩略图，而不是实时画面。",
              RowKind::Boolean, 0, false, {} },
            { kAttrHasIconicBitmap, "DWMWA_HAS_ICONIC_BITMAP",
              "window.dwm.attr.has_iconic_bitmap", "声明窗口会提供 iconic 位图，需与强制静态缩略图配合。",
              RowKind::Boolean, 0, false, {} },
            { kAttrDisallowPeek, "DWMWA_DISALLOW_PEEK",
              "window.dwm.attr.disallow_peek", "禁止在该窗口上触发 Aero Peek 桌面透视。",
              RowKind::Boolean, 0, false, {} },
            { kAttrExcludedFromPeek, "DWMWA_EXCLUDED_FROM_PEEK",
              "window.dwm.attr.excluded_from_peek", "执行桌面透视时把该窗口一并隐藏。",
              RowKind::Boolean, 0, false, {} },
            { kAttrFreezeRepresentation, "DWMWA_FREEZE_REPRESENTATION",
              "window.dwm.attr.freeze_representation", "冻结缩略图内容，窗口后续变化不再反映到预览。",
              RowKind::Boolean, 0, false, {} },
            { kAttrPassiveUpdateMode, "DWMWA_PASSIVE_UPDATE_MODE",
              "window.dwm.attr.passive_update", "被动更新模式：DWM 只在窗口重绘时同步内容。",
              RowKind::Boolean, kBuildWin11, false, {} },
            { kAttrUseHostBackdropBrush, "DWMWA_USE_HOSTBACKDROPBRUSH",
              "window.dwm.attr.host_backdrop", "使用宿主背景画刷，让分层子窗口获得亚克力底色。",
              RowKind::Boolean, kBuildWin11, false, {} },
            { kAttrImmersiveDarkMode, "DWMWA_USE_IMMERSIVE_DARK_MODE",
              "window.dwm.attr.dark_mode", "把系统标题栏切换为暗色。1809~1903 使用旧编号 19，本页已按构建号自动选择。",
              RowKind::Boolean, kBuildWin10Dark, false, {} },
            { kAttrCloak, "DWMWA_CLOAK",
              "window.dwm.attr.cloak",
              "对 DWM 隐藏窗口：窗口仍然存在且可交互，但不再被合成显示。"
              "实测 DWM 只允许进程隐藏自己的窗口，对其他进程的窗口会返回 E_ACCESSDENIED。",
              RowKind::Boolean, 0, true, {} },
        };
        return specs;
    }

    // enumeratedRowSpecs：返回全部枚举型 DWM 属性的规格表。
    const std::vector<RowSpec>& enumeratedRowSpecs()
    {
        static const std::vector<RowSpec> specs = {
            { kAttrNcRenderingPolicy, "DWMWA_NCRENDERING_POLICY",
              "window.dwm.attr.nc_policy", "决定非客户区是否交给 DWM 渲染，关闭后窗口会退回经典边框。",
              RowKind::Enumerated, 0, false,
              {
                  { 0, "window.dwm.enum.ncrp_usewindowstyle", "DWMNCRP_USEWINDOWSTYLE (随窗口样式)" },
                  { 1, "window.dwm.enum.ncrp_disabled", "DWMNCRP_DISABLED (禁用 DWM 渲染)" },
                  { 2, "window.dwm.enum.ncrp_enabled", "DWMNCRP_ENABLED (启用 DWM 渲染)" },
              } },
            { kAttrFlip3DPolicy, "DWMWA_FLIP3D_POLICY",
              "window.dwm.attr.flip3d", "Flip3D 切换器中该窗口的排布策略，Win8 之后大多无实际效果。",
              RowKind::Enumerated, 0, false,
              {
                  { 0, "window.dwm.enum.flip3d_default", "DWMFLIP3D_DEFAULT (默认)" },
                  { 1, "window.dwm.enum.flip3d_excludebelow", "DWMFLIP3D_EXCLUDEBELOW (排在下方)" },
                  { 2, "window.dwm.enum.flip3d_excludeabove", "DWMFLIP3D_EXCLUDEABOVE (排在上方)" },
              } },
            { kAttrWindowCornerPreference, "DWMWA_WINDOW_CORNER_PREFERENCE",
              "window.dwm.attr.corner", "Windows 11 窗口圆角策略，可强制直角或小圆角。",
              RowKind::Enumerated, kBuildWin11, false,
              {
                  { 0, "window.dwm.enum.corner_default", "DWMWCP_DEFAULT (系统决定)" },
                  { 1, "window.dwm.enum.corner_donotround", "DWMWCP_DONOTROUND (直角)" },
                  { 2, "window.dwm.enum.corner_round", "DWMWCP_ROUND (标准圆角)" },
                  { 3, "window.dwm.enum.corner_roundsmall", "DWMWCP_ROUNDSMALL (小圆角)" },
              } },
            { kAttrSystemBackdropType, "DWMWA_SYSTEMBACKDROP_TYPE",
              "window.dwm.attr.backdrop", "Windows 11 22H2 背景材质。目标窗口客户区必须允许透出，否则只有边框区域可见。",
              RowKind::Enumerated, kBuildWin11_22H2, false,
              {
                  { 0, "window.dwm.enum.backdrop_auto", "DWMSBT_AUTO (系统决定)" },
                  { 1, "window.dwm.enum.backdrop_none", "DWMSBT_NONE (无材质)" },
                  { 2, "window.dwm.enum.backdrop_mainwindow", "DWMSBT_MAINWINDOW (云母 Mica)" },
                  { 3, "window.dwm.enum.backdrop_transient", "DWMSBT_TRANSIENTWINDOW (亚克力 Acrylic)" },
                  { 4, "window.dwm.enum.backdrop_tabbed", "DWMSBT_TABBEDWINDOW (云母替代 Mica Alt)" },
              } },
        };
        return specs;
    }

    // colorRowSpecs：返回全部配色型 DWM 属性的规格表。
    const std::vector<RowSpec>& colorRowSpecs()
    {
        static const std::vector<RowSpec> specs = {
            { kAttrBorderColor, "DWMWA_BORDER_COLOR",
              "window.dwm.attr.border_color", "窗口外边框颜色。选择“无”可让边框完全不绘制。",
              RowKind::Color, kBuildWin11, false, {} },
            { kAttrCaptionColor, "DWMWA_CAPTION_COLOR",
              "window.dwm.attr.caption_color", "系统标题栏背景色，仅对使用原生标题栏的窗口有效。",
              RowKind::Color, kBuildWin11, false, {} },
            { kAttrTextColor, "DWMWA_TEXT_COLOR",
              "window.dwm.attr.text_color", "系统标题栏文字颜色，建议与标题栏背景色一起设置以保证对比度。",
              RowKind::Color, kBuildWin11, false, {} },
        };
        return specs;
    }

    // AttributeRow 作用：一条属性在界面上的运行期状态（控件指针与当前选色）。
    struct AttributeRow
    {
        RowSpec spec;                        // spec：静态规格。
        QComboBox* valueCombo = nullptr;     // valueCombo：取值选择控件。
        QPushButton* colorButton = nullptr;  // colorButton：配色属性的取色按钮。
        QLabel* statusLabel = nullptr;       // statusLabel：读回值与 HRESULT 展示。
        QColor customColor{ 0, 120, 215 };   // customColor：配色属性的自定义颜色。
        bool touched = false;                // touched：本页是否写过该属性，用于恢复默认。
    };

    // ============ DWM 控制页 ============

    class Page final : public QWidget
    {
    public:
        // 构造函数：
        // - 作用：锁定目标窗口、构建界面并做一次全量读取；
        // - 传入 target：被检查的窗口句柄；传入 parent：Qt 父控件。
        explicit Page(HWND target, QWidget* parent = nullptr)
            : QWidget(parent)
            , m_target(target)
        {
            buildUi();
            readAllAttributes(false);
            refreshDiagnostics();

            m_thumbnailTimer = new QTimer(this);
            m_thumbnailTimer->setInterval(kThumbnailRefreshMs);
            connect(m_thumbnailTimer, &QTimer::timeout, this, [this]() {
                updateThumbnailPlacement();
            });
        }

        // 析构函数：
        // - 作用：注销 DWM 缩略图，避免 DWM 侧残留句柄。
        ~Page() override
        {
            releaseThumbnail();
        }

    protected:
        // showEvent：页面可见时才注册缩略图，避免后台白占 DWM 资源。
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (m_thumbnailEnableCheck != nullptr && m_thumbnailEnableCheck->isChecked())
            {
                ensureThumbnail();
            }
            if (m_thumbnailTimer != nullptr)
            {
                m_thumbnailTimer->start();
            }
            updateThumbnailPlacement();
        }

        // hideEvent：页面隐藏（切到别的标签页或关闭）时立即收起缩略图。
        void hideEvent(QHideEvent* event) override
        {
            QWidget::hideEvent(event);
            if (m_thumbnailTimer != nullptr)
            {
                m_thumbnailTimer->stop();
            }
            updateThumbnailPlacement();
        }

        // resizeEvent：尺寸变化会改变缩略图目标矩形，需要立即同步。
        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            updateThumbnailPlacement();
        }

    private:
        // ---------- 界面构建 ----------

        // buildUi：
        // - 作用：搭建“左侧属性控制 + 右侧实时预览与日志”的整体布局；
        // - 调用：仅构造函数一次。
        void buildUi()
        {
            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(8, 8, 8, 8);
            rootLayout->setSpacing(6);

            rootLayout->addLayout(buildHeaderRow());

            QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
            splitter->addWidget(buildControlSide(splitter));
            splitter->addWidget(buildPreviewSide(splitter));
            splitter->setStretchFactor(0, 3);
            splitter->setStretchFactor(1, 2);
            rootLayout->addWidget(splitter, 1);
        }

        // buildHeaderRow：
        // - 作用：构建顶部信息条（目标句柄、系统构建号、全局动作按钮）；
        // - 传出：可直接加入根布局的水平布局。
        QHBoxLayout* buildHeaderRow()
        {
            QHBoxLayout* headerLayout = new QHBoxLayout();

            QLabel* targetLabel = new QLabel(
                uiText("window.dwm.header.target", "目标 HWND: %1    系统构建号: %2")
                    .arg(hwndText(m_target))
                    .arg(windowsBuild() == 0
                        ? uiText("window.dwm.header.build_unknown", "未知")
                        : QString::number(windowsBuild())),
                this);
            targetLabel->setWordWrap(true);
            headerLayout->addWidget(targetLabel, 1);

            m_frameChangeCheck = new QCheckBox(
                uiText("window.dwm.header.force_frame_change", "写入后强制重算边框"), this);
            m_frameChangeCheck->setChecked(true);
            m_frameChangeCheck->setToolTip(uiText(
                "window.dwm.header.force_frame_change_tip",
                "部分属性只有在窗口重新计算非客户区之后才会显示出来；使用异步 SetWindowPos，不会因目标线程卡死而挂起本程序。"));
            bindUiText(m_frameChangeCheck, "window.dwm.header.force_frame_change", "写入后强制重算边框");
            headerLayout->addWidget(m_frameChangeCheck, 0);

            QPushButton* readAllButton = makeButton(this, "window.dwm.action.read_all", "读取全部");
            QPushButton* restoreButton = makeButton(this, "window.dwm.action.restore_default", "恢复系统默认");
            QPushButton* copyButton = makeButton(this, "window.dwm.action.copy_report", "复制报告");
            QPushButton* exportButton = makeButton(this, "window.dwm.action.export_report", "导出报告");
            headerLayout->addWidget(readAllButton, 0);
            headerLayout->addWidget(restoreButton, 0);
            headerLayout->addWidget(copyButton, 0);
            headerLayout->addWidget(exportButton, 0);

            connect(readAllButton, &QPushButton::clicked, this, [this]() {
                readAllAttributes(true);
                refreshDiagnostics();
            });
            connect(restoreButton, &QPushButton::clicked, this, [this]() {
                restoreSystemDefaults();
            });
            connect(copyButton, &QPushButton::clicked, this, [this]() {
                QApplication::clipboard()->setText(buildReportText());
                appendLog(uiText("window.dwm.log.report_copied", "报告已复制到剪贴板。"));
            });
            connect(exportButton, &QPushButton::clicked, this, [this]() {
                exportReport();
            });

            return headerLayout;
        }

        // buildControlSide：
        // - 作用：构建左侧滚动区，容纳全部属性分组；
        // - 传出：可加入分割器的滚动区控件。
        QWidget* buildControlSide(QWidget* parent)
        {
            QScrollArea* scrollArea = new QScrollArea(parent);
            scrollArea->setWidgetResizable(true);

            QWidget* container = new QWidget(scrollArea);
            QVBoxLayout* containerLayout = new QVBoxLayout(container);
            containerLayout->setContentsMargins(0, 0, 0, 0);
            containerLayout->setSpacing(8);

            containerLayout->addWidget(buildPresetGroup(container));
            containerLayout->addWidget(buildEnumeratedGroup(container));
            containerLayout->addWidget(buildColorGroup(container));
            containerLayout->addWidget(buildBooleanGroup(container));
            containerLayout->addWidget(buildFrameGroup(container));
            containerLayout->addWidget(buildAccentGroup(container));
            containerLayout->addStretch(1);

            scrollArea->setWidget(container);
            return scrollArea;
        }

        // buildPresetGroup：
        // - 作用：提供常用组合的一键预设，减少逐项设置的操作成本。
        QGroupBox* buildPresetGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.preset", "一键预设");
            QHBoxLayout* layout = new QHBoxLayout(group);

            m_presetCombo = new QComboBox(group);
            m_presetCombo->addItem(uiText("window.dwm.preset.dark_round", "暗色标题栏 + 标准圆角"));
            m_presetCombo->addItem(uiText("window.dwm.preset.square", "强制直角、无边框色"));
            m_presetCombo->addItem(uiText("window.dwm.preset.mica", "云母背景 + 暗色标题栏"));
            m_presetCombo->addItem(uiText("window.dwm.preset.acrylic", "亚克力背景 + 系统圆角"));
            m_presetCombo->addItem(uiText("window.dwm.preset.no_animation", "关闭过渡动画并排除桌面透视"));
            layout->addWidget(m_presetCombo, 1);

            QPushButton* applyButton = makeButton(group, "window.dwm.action.apply_preset", "应用预设");
            layout->addWidget(applyButton, 0);
            connect(applyButton, &QPushButton::clicked, this, [this]() {
                applySelectedPreset();
            });
            return group;
        }

        // buildEnumeratedGroup / buildColorGroup / buildBooleanGroup：
        // - 作用：按属性类别铺三张网格，每行一个属性；
        // - 说明：三者共用 appendAttributeRow，行为完全一致。
        QGroupBox* buildEnumeratedGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.enum", "枚举属性（渲染策略 / 圆角 / 背景材质）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : enumeratedRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        QGroupBox* buildColorGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.color", "配色属性（边框 / 标题栏 / 标题文字）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : colorRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        QGroupBox* buildBooleanGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(parent, "window.dwm.group.boolean", "布尔属性（动画 / 缩略图 / 透视 / 隐藏）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);
            for (const RowSpec& spec : booleanRowSpecs())
            {
                appendAttributeRow(group, grid, spec);
            }
            return group;
        }

        // appendAttributeRow：
        // - 作用：把一条属性规格实例化为界面上的一行并登记到 m_rows；
        // - 传入 group/grid：宿主分组与网格；传入 spec：属性静态规格。
        void appendAttributeRow(QGroupBox* group, QGridLayout* grid, const RowSpec& spec)
        {
            const int rowIndex = grid->rowCount();
            const std::size_t rowSlot = m_rows.size();
            m_rows.push_back(AttributeRow{ spec, nullptr, nullptr, nullptr, QColor(0, 120, 215), false });
            AttributeRow& row = m_rows.back();

            // 属性名一列直接显示 Win32 常量名，便于和微软文档一一对照。
            QLabel* nameLabel = new QLabel(
                QStringLiteral("%1 (%2)").arg(QString::fromLatin1(spec.apiName)).arg(spec.attribute), group);
            nameLabel->setToolTip(buildRowTip(spec));
            grid->addWidget(nameLabel, rowIndex, 0);

            row.valueCombo = new QComboBox(group);
            row.valueCombo->setToolTip(buildRowTip(spec));
            if (spec.kind == RowKind::Boolean)
            {
                row.valueCombo->addItem(uiText("window.dwm.value.true", "TRUE (1)"), QVariant(1u));
                row.valueCombo->addItem(uiText("window.dwm.value.false", "FALSE (0)"), QVariant(0u));
            }
            else if (spec.kind == RowKind::Enumerated)
            {
                for (const EnumOption& option : spec.options)
                {
                    // DWORD 是 unsigned long，QVariant 没有对应重载，必须先收敛到 uint。
                    row.valueCombo->addItem(
                        uiText(option.key, option.label), QVariant(static_cast<uint>(option.value)));
                }
            }
            else
            {
                row.valueCombo->addItem(
                    uiText("window.dwm.color.default", "系统默认"), QVariant(static_cast<uint>(kColorDefault)));
                row.valueCombo->addItem(
                    uiText("window.dwm.color.none", "无（不绘制）"), QVariant(static_cast<uint>(kColorNone)));
                row.valueCombo->addItem(uiText("window.dwm.color.custom", "自定义颜色"), QVariant(0u));
            }

            QWidget* valueHost = row.valueCombo;
            if (spec.kind == RowKind::Color)
            {
                // 配色行需要在下拉旁边补一个取色按钮，因此外包一层容器。
                QWidget* colorHost = new QWidget(group);
                QHBoxLayout* colorLayout = new QHBoxLayout(colorHost);
                colorLayout->setContentsMargins(0, 0, 0, 0);
                colorLayout->setSpacing(4);
                row.colorButton = new QPushButton(colorHost);
                row.colorButton->setFixedWidth(52);
                colorLayout->addWidget(row.valueCombo, 1);
                colorLayout->addWidget(row.colorButton, 0);
                valueHost = colorHost;

                updateColorButton(row);
                connect(row.colorButton, &QPushButton::clicked, this, [this, rowSlot]() {
                    AttributeRow& target = m_rows[rowSlot];
                    const QColor picked = QColorDialog::getColor(
                        target.customColor,
                        this,
                        uiText("window.dwm.color.dialog_title", "选择 DWM 配色"));
                    if (!picked.isValid())
                    {
                        return;
                    }
                    target.customColor = picked;
                    updateColorButton(target);
                    // 选完颜色后自动切到自定义模式，避免用户以为没生效。
                    target.valueCombo->setCurrentIndex(2);
                });
            }
            grid->addWidget(valueHost, rowIndex, 1);

            QPushButton* readButton = makeButton(group, "window.dwm.action.read", "读取");
            QPushButton* writeButton = makeButton(group, "window.dwm.action.write", "写入");
            readButton->setFixedWidth(56);
            writeButton->setFixedWidth(56);
            grid->addWidget(readButton, rowIndex, 2);
            grid->addWidget(writeButton, rowIndex, 3);

            row.statusLabel = new QLabel(uiText("window.dwm.status.unread", "未读取"), group);
            row.statusLabel->setWordWrap(true);
            grid->addWidget(row.statusLabel, rowIndex, 4);
            grid->setColumnStretch(4, 1);

            connect(readButton, &QPushButton::clicked, this, [this, rowSlot]() {
                readAttributeRow(m_rows[rowSlot], true);
            });
            connect(writeButton, &QPushButton::clicked, this, [this, rowSlot]() {
                writeAttributeRow(m_rows[rowSlot]);
            });
        }

        // buildRowTip：
        // - 作用：拼接属性说明与“当前系统可能不支持”的提示；
        // - 传出：控件 ToolTip 文本。
        QString buildRowTip(const RowSpec& spec) const
        {
            QString tip = uiText(spec.tipKey, spec.tip);
            const DWORD build = windowsBuild();
            if (spec.minimumBuild != 0 && build != 0 && build < spec.minimumBuild)
            {
                tip += QChar::LineFeed;
                tip += uiText("window.dwm.tip.build_required", "该属性需要构建号 %1 及以上，当前系统为 %2，调用大概率返回 E_INVALIDARG。")
                    .arg(spec.minimumBuild)
                    .arg(build);
            }
            if (spec.destructive)
            {
                tip += QChar::LineFeed;
                tip += uiText("window.dwm.tip.destructive", "该操作会改变窗口的可见性，写入前会要求确认。");
            }
            return tip;
        }

        // buildFrameGroup：
        // - 作用：构建“框架扩展与模糊”分组（DwmExtendFrameIntoClientArea / DwmEnableBlurBehindWindow）。
        QGroupBox* buildFrameGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(
                parent, "window.dwm.group.frame", "框架扩展、模糊与过渡");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);

            QLabel* marginHint = makeLabel(
                group, "window.dwm.frame.margin_hint",
                "DwmExtendFrameIntoClientArea 把玻璃边框向客户区延伸，四个边距填 -1 表示整窗玻璃。");
            marginHint->setWordWrap(true);
            grid->addWidget(marginHint, 0, 0, 1, 5);

            // 语义键与文案成对书写：i18n 抽取按“相邻字面量对”识别，拆成两个数组会串位。
            struct MarginField
            {
                const char* key;
                const char* label;
            };
            const std::array<MarginField, 4> marginFields{ {
                { "window.dwm.frame.left", "左" },
                { "window.dwm.frame.top", "上" },
                { "window.dwm.frame.right", "右" },
                { "window.dwm.frame.bottom", "下" },
            } };
            for (int index = 0; index < 4; ++index)
            {
                grid->addWidget(
                    makeLabel(group, marginFields[index].key, marginFields[index].label), 1, index);
                m_marginSpins[index] = new QSpinBox(group);
                m_marginSpins[index]->setRange(-1, 4096);
                m_marginSpins[index]->setValue(0);
                grid->addWidget(m_marginSpins[index], 2, index);
            }

            QPushButton* applyMarginButton = makeButton(group, "window.dwm.action.apply_margin", "应用边距");
            QPushButton* fullGlassButton = makeButton(group, "window.dwm.action.full_glass", "整窗玻璃");
            QPushButton* resetMarginButton = makeButton(group, "window.dwm.action.reset_margin", "重置边距");
            grid->addWidget(applyMarginButton, 2, 4);
            grid->addWidget(fullGlassButton, 3, 4);

            QHBoxLayout* blurLayout = new QHBoxLayout();
            m_blurTransitionCheck = new QCheckBox(
                uiText("window.dwm.frame.blur_transition", "最大化时过渡"), group);
            bindUiText(m_blurTransitionCheck, "window.dwm.frame.blur_transition", "最大化时过渡");
            QPushButton* blurOnButton = makeButton(group, "window.dwm.action.blur_on", "启用模糊");
            QPushButton* blurOffButton = makeButton(group, "window.dwm.action.blur_off", "关闭模糊");
            blurLayout->addWidget(m_blurTransitionCheck, 0);
            blurLayout->addWidget(blurOnButton, 0);
            blurLayout->addWidget(blurOffButton, 0);
            blurLayout->addWidget(resetMarginButton, 0);
            blurLayout->addStretch(1);
            grid->addLayout(blurLayout, 3, 0, 1, 4);

            QHBoxLayout* transitionLayout = new QHBoxLayout();
            QPushButton* invalidateIconicButton =
                makeButton(group, "window.dwm.action.invalidate_iconic", "作废静态缩略图缓存");
            invalidateIconicButton->setToolTip(uiText(
                "window.dwm.action.invalidate_iconic_tip",
                "DwmInvalidateIconicBitmaps：丢弃 DWM 为该窗口缓存的静态缩略图与实时预览位图，强制下次重新采集。"
                "实测仅对本进程窗口有效，跨进程调用返回 E_INVALIDARG。"));
            QPushButton* transitionOwnedButton =
                makeButton(group, "window.dwm.action.transition_owned", "触发属主窗口重定位过渡");
            transitionOwnedButton->setToolTip(uiText(
                "window.dwm.action.transition_owned_tip",
                "DwmTransitionOwnedWindow：让 DWM 对该窗口播放一次 REPOSITION 过渡动画，可用于验证过渡是否被禁用。"
                "实测仅对本进程窗口有效，跨进程调用返回 E_INVALIDARG。"));
            transitionLayout->addWidget(invalidateIconicButton, 0);
            transitionLayout->addWidget(transitionOwnedButton, 0);
            transitionLayout->addStretch(1);
            grid->addLayout(transitionLayout, 4, 0, 1, 5);

            connect(invalidateIconicButton, &QPushButton::clicked, this, [this]() {
                if (!targetAlive())
                {
                    return;
                }
                const HRESULT result = ::DwmInvalidateIconicBitmaps(m_target);
                appendLog(uiText("window.dwm.log.invalidate_iconic", "DwmInvalidateIconicBitmaps → %1")
                    .arg(hresultText(result)));
            });
            connect(transitionOwnedButton, &QPushButton::clicked, this, [this]() {
                if (!targetAlive())
                {
                    return;
                }
                const HRESULT result =
                    ::DwmTransitionOwnedWindow(m_target, DWMTRANSITION_OWNEDWINDOW_REPOSITION);
                appendLog(uiText("window.dwm.log.transition_owned", "DwmTransitionOwnedWindow(REPOSITION) → %1")
                    .arg(hresultText(result)));
            });

            connect(applyMarginButton, &QPushButton::clicked, this, [this]() {
                applyFrameMargins(
                    m_marginSpins[0]->value(), m_marginSpins[1]->value(),
                    m_marginSpins[2]->value(), m_marginSpins[3]->value());
            });
            connect(fullGlassButton, &QPushButton::clicked, this, [this]() {
                for (QSpinBox* spinBox : m_marginSpins)
                {
                    spinBox->setValue(-1);
                }
                applyFrameMargins(-1, -1, -1, -1);
            });
            connect(resetMarginButton, &QPushButton::clicked, this, [this]() {
                for (QSpinBox* spinBox : m_marginSpins)
                {
                    spinBox->setValue(0);
                }
                applyFrameMargins(0, 0, 0, 0);
            });
            connect(blurOnButton, &QPushButton::clicked, this, [this]() {
                applyBlurBehind(true);
            });
            connect(blurOffButton, &QPushButton::clicked, this, [this]() {
                applyBlurBehind(false);
            });
            return group;
        }

        // buildAccentGroup：
        // - 作用：构建未公开的 SetWindowCompositionAttribute 控制分组；
        // - 说明：这是 Win10 之后真正能对任意窗口开出亚克力/模糊的通道。
        QGroupBox* buildAccentGroup(QWidget* parent)
        {
            QGroupBox* group = makeGroup(
                parent, "window.dwm.group.accent", "窗口合成特性（SetWindowCompositionAttribute，未公开接口）");
            QGridLayout* grid = new QGridLayout(group);
            grid->setHorizontalSpacing(8);
            grid->setVerticalSpacing(4);

            QLabel* accentHint = makeLabel(
                group, "window.dwm.accent.hint",
                "该接口未被微软文档化，不同版本行为存在差异；亚克力状态在部分版本会造成拖动窗口时卡顿。");
            accentHint->setWordWrap(true);
            grid->addWidget(accentHint, 0, 0, 1, 4);

            grid->addWidget(makeLabel(group, "window.dwm.accent.state", "合成状态"), 1, 0);
            m_accentStateCombo = new QComboBox(group);
            m_accentStateCombo->addItem(uiText("window.dwm.accent.disabled", "ACCENT_DISABLED (关闭)"), QVariant(0u));
            m_accentStateCombo->addItem(uiText("window.dwm.accent.gradient", "ACCENT_ENABLE_GRADIENT (纯色)"), QVariant(1u));
            m_accentStateCombo->addItem(uiText("window.dwm.accent.transparent_gradient", "ACCENT_ENABLE_TRANSPARENTGRADIENT (半透明)"), QVariant(2u));
            m_accentStateCombo->addItem(uiText("window.dwm.accent.blur", "ACCENT_ENABLE_BLURBEHIND (模糊)"), QVariant(3u));
            m_accentStateCombo->addItem(uiText("window.dwm.accent.acrylic", "ACCENT_ENABLE_ACRYLICBLURBEHIND (亚克力)"), QVariant(4u));
            m_accentStateCombo->addItem(uiText("window.dwm.accent.host_backdrop", "ACCENT_ENABLE_HOSTBACKDROP (宿主背景)"), QVariant(5u));
            m_accentStateCombo->setCurrentIndex(4);
            grid->addWidget(m_accentStateCombo, 1, 1, 1, 3);

            grid->addWidget(makeLabel(group, "window.dwm.accent.tint", "着色"), 2, 0);
            m_accentColorButton = new QPushButton(group);
            m_accentColorButton->setFixedWidth(52);
            grid->addWidget(m_accentColorButton, 2, 1);
            grid->addWidget(makeLabel(group, "window.dwm.accent.alpha", "透明度"), 2, 2);
            m_accentAlphaSlider = new QSlider(Qt::Horizontal, group);
            m_accentAlphaSlider->setRange(0, 255);
            m_accentAlphaSlider->setValue(160);
            grid->addWidget(m_accentAlphaSlider, 2, 3);

            grid->addWidget(makeLabel(group, "window.dwm.accent.flags", "标志位"), 3, 0);
            m_accentFlagsSpin = new QSpinBox(group);
            m_accentFlagsSpin->setRange(0, 0x7FFFFFFF);
            m_accentFlagsSpin->setValue(2);
            m_accentFlagsSpin->setToolTip(uiText(
                "window.dwm.accent.flags_tip",
                "常见取值：0 不绘制边框，2 绘制全部边框。该字段同样没有公开文档。"));
            grid->addWidget(m_accentFlagsSpin, 3, 1);

            QPushButton* applyAccentButton = makeButton(group, "window.dwm.action.apply_accent", "应用合成特性");
            QPushButton* darkColorsOnButton = makeButton(group, "window.dwm.action.dark_colors_on", "启用暗色配色");
            QPushButton* darkColorsOffButton = makeButton(group, "window.dwm.action.dark_colors_off", "关闭暗色配色");
            grid->addWidget(applyAccentButton, 3, 2);
            grid->addWidget(darkColorsOnButton, 4, 2);
            grid->addWidget(darkColorsOffButton, 4, 3);

            m_accentStatusLabel = new QLabel(uiText("window.dwm.status.unread", "未读取"), group);
            m_accentStatusLabel->setWordWrap(true);
            grid->addWidget(m_accentStatusLabel, 4, 0, 1, 2);

            updateAccentColorButton();
            connect(m_accentColorButton, &QPushButton::clicked, this, [this]() {
                const QColor picked = QColorDialog::getColor(
                    m_accentColor, this, uiText("window.dwm.color.dialog_title", "选择 DWM 配色"));
                if (picked.isValid())
                {
                    m_accentColor = picked;
                    updateAccentColorButton();
                }
            });
            connect(applyAccentButton, &QPushButton::clicked, this, [this]() {
                applyAccentPolicy();
            });
            connect(darkColorsOnButton, &QPushButton::clicked, this, [this]() {
                applyDarkModeColors(true);
            });
            connect(darkColorsOffButton, &QPushButton::clicked, this, [this]() {
                applyDarkModeColors(false);
            });
            return group;
        }

        // buildPreviewSide：
        // - 作用：构建右侧“实时缩略图 + 合成诊断 + 操作日志”面板。
        QWidget* buildPreviewSide(QWidget* parent)
        {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(container);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(6);

            QGroupBox* thumbnailGroup = makeGroup(container, "window.dwm.group.thumbnail", "实时缩略图（DWM Thumbnail）");
            QVBoxLayout* thumbnailLayout = new QVBoxLayout(thumbnailGroup);

            QHBoxLayout* thumbnailControlLayout = new QHBoxLayout();
            m_thumbnailEnableCheck = new QCheckBox(uiText("window.dwm.thumbnail.enable", "启用预览"), thumbnailGroup);
            bindUiText(m_thumbnailEnableCheck, "window.dwm.thumbnail.enable", "启用预览");
            m_thumbnailClientOnlyCheck = new QCheckBox(
                uiText("window.dwm.thumbnail.client_only", "仅客户区"), thumbnailGroup);
            bindUiText(m_thumbnailClientOnlyCheck, "window.dwm.thumbnail.client_only", "仅客户区");
            m_thumbnailOpacitySlider = new QSlider(Qt::Horizontal, thumbnailGroup);
            m_thumbnailOpacitySlider->setRange(0, 255);
            m_thumbnailOpacitySlider->setValue(255);
            thumbnailControlLayout->addWidget(m_thumbnailEnableCheck, 0);
            thumbnailControlLayout->addWidget(m_thumbnailClientOnlyCheck, 0);
            thumbnailControlLayout->addWidget(
                makeLabel(thumbnailGroup, "window.dwm.thumbnail.opacity", "不透明度"), 0);
            thumbnailControlLayout->addWidget(m_thumbnailOpacitySlider, 1);
            thumbnailLayout->addLayout(thumbnailControlLayout);

            // 缩略图由 DWM 直接合成到本对话框上层，这里只保留一块带边框的占位区域，
            // 让用户在预览关闭时也能看出画面会出现在哪里。
            QFrame* thumbnailHost = new QFrame(thumbnailGroup);
            thumbnailHost->setFrameShape(QFrame::StyledPanel);
            thumbnailHost->setMinimumHeight(180);
            thumbnailHost->setAutoFillBackground(false);
            m_thumbnailHost = thumbnailHost;
            thumbnailLayout->addWidget(m_thumbnailHost, 1);

            m_thumbnailStatusLabel = new QLabel(
                uiText("window.dwm.thumbnail.idle", "勾选“启用预览”后在此实时显示目标窗口画面。"), thumbnailGroup);
            m_thumbnailStatusLabel->setWordWrap(true);
            thumbnailLayout->addWidget(m_thumbnailStatusLabel, 0);
            layout->addWidget(thumbnailGroup, 0);

            // 系统等宽字体缺少中文字形时会回退到宋体，显式追加雅黑承接中文。
            QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
            fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });

            QGroupBox* diagnosticsGroup = makeGroup(container, "window.dwm.group.diagnostics", "合成诊断（只读）");
            QVBoxLayout* diagnosticsLayout = new QVBoxLayout(diagnosticsGroup);
            m_diagnosticsText = new QPlainTextEdit(diagnosticsGroup);
            m_diagnosticsText->setReadOnly(true);
            m_diagnosticsText->setLineWrapMode(QPlainTextEdit::NoWrap);
            m_diagnosticsText->setFont(fixedFont);
            diagnosticsLayout->addWidget(m_diagnosticsText, 1);
            QHBoxLayout* diagnosticsActionLayout = new QHBoxLayout();
            QPushButton* refreshDiagnosticsButton =
                makeButton(diagnosticsGroup, "window.dwm.action.refresh_diagnostics", "刷新诊断");
            QPushButton* flushButton = makeButton(diagnosticsGroup, "window.dwm.action.flush", "DwmFlush");
            diagnosticsActionLayout->addWidget(refreshDiagnosticsButton, 0);
            diagnosticsActionLayout->addWidget(flushButton, 0);
            diagnosticsActionLayout->addStretch(1);
            diagnosticsLayout->addLayout(diagnosticsActionLayout);
            layout->addWidget(diagnosticsGroup, 1);

            QGroupBox* logGroup = makeGroup(container, "window.dwm.group.log", "操作日志");
            QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
            m_logText = new QPlainTextEdit(logGroup);
            m_logText->setReadOnly(true);
            m_logText->setLineWrapMode(QPlainTextEdit::NoWrap);
            m_logText->setFont(fixedFont);
            logLayout->addWidget(m_logText, 1);
            QPushButton* clearLogButton = makeButton(logGroup, "window.dwm.action.clear_log", "清空日志");
            logLayout->addWidget(clearLogButton, 0, Qt::AlignRight);
            layout->addWidget(logGroup, 1);

            connect(refreshDiagnosticsButton, &QPushButton::clicked, this, [this]() {
                refreshDiagnostics();
            });
            connect(flushButton, &QPushButton::clicked, this, [this]() {
                const HRESULT result = ::DwmFlush();
                appendLog(uiText("window.dwm.log.flush", "DwmFlush → %1").arg(hresultText(result)));
            });
            connect(clearLogButton, &QPushButton::clicked, this, [this]() {
                m_logText->clear();
            });
            connect(m_thumbnailEnableCheck, &QCheckBox::toggled, this, [this](bool checked) {
                if (checked)
                {
                    ensureThumbnail();
                }
                else
                {
                    releaseThumbnail();
                    m_thumbnailStatusLabel->setText(uiText("window.dwm.thumbnail.idle", "勾选“启用预览”后在此实时显示目标窗口画面。"));
                }
                updateThumbnailPlacement();
            });
            connect(m_thumbnailClientOnlyCheck, &QCheckBox::toggled, this, [this](bool) {
                updateThumbnailPlacement();
            });
            connect(m_thumbnailOpacitySlider, &QSlider::valueChanged, this, [this](int) {
                updateThumbnailPlacement();
            });
            return container;
        }

        // ---------- 属性读写 ----------

        // targetAlive：
        // - 作用：所有写操作前统一校验句柄，避免对已销毁窗口反复调用；
        // - 传出：句柄有效返回 true，否则记录日志并返回 false。
        bool targetAlive()
        {
            if (::IsWindow(m_target) != FALSE)
            {
                return true;
            }
            appendLog(uiText("window.dwm.log.target_invalid", "目标 HWND 已失效，操作被跳过。"));
            return false;
        }

        // readAttributeRow：
        // - 作用：读取一行属性并把结果回填到状态标签与取值控件；
        // - 传入 row：目标行；传入 syncControl：是否把读回值同步到下拉框；
        // - 传出：读取成功返回 true（只写属性读失败属正常情况）。
        bool readAttributeRow(AttributeRow& row, bool syncControl)
        {
            if (::IsWindow(m_target) == FALSE)
            {
                row.statusLabel->setText(uiText("window.dwm.status.invalid_target", "目标窗口已失效"));
                return false;
            }

            const DWORD attribute = effectiveAttribute(row.spec);
            const DwordResult result = readDwordAttribute(m_target, attribute);
            if (!result.ok)
            {
                // 大量 DWMWA_* 是只写属性，DWM 对它们的读取一律返回 E_INVALIDARG。
                // 这种情况不是错误，单独措辞以免被误读成“写入也不支持”。
                row.statusLabel->setText(result.hr == E_INVALIDARG
                    ? uiText("window.dwm.status.write_only", "不可回读（只写属性，或当前系统不支持）")
                    : uiText("window.dwm.status.read_failed", "读取失败: %1").arg(hresultText(result.hr)));
                return false;
            }

            row.statusLabel->setText(
                uiText("window.dwm.status.current", "当前值: %1").arg(describeValue(row.spec, result.value)));
            if (syncControl)
            {
                syncRowControl(row, result.value);
            }
            return true;
        }

        // writeAttributeRow：
        // - 作用：把一行属性的界面取值写回目标窗口；
        // - 传入 row：目标行。危险属性会先弹确认框。
        void writeAttributeRow(AttributeRow& row)
        {
            if (!targetAlive())
            {
                return;
            }

            const DWORD value = currentRowValue(row);
            if (row.spec.destructive && !confirmDestructiveWrite(row.spec, value))
            {
                return;
            }

            const DWORD attribute = effectiveAttribute(row.spec);
            const HRESULT result = ::DwmSetWindowAttribute(m_target, attribute, &value, sizeof(value));
            row.touched = row.touched || SUCCEEDED(result);
            appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                .arg(QString::fromLatin1(row.spec.apiName), describeValue(row.spec, value), hresultText(result)));

            if (m_frameChangeCheck != nullptr && m_frameChangeCheck->isChecked())
            {
                requestFrameChange();
            }
            readAttributeRow(row, false);
            refreshDiagnostics();
        }

        // effectiveAttribute：
        // - 作用：把规格里的静态编号换算为当前系统真正应使用的编号；
        // - 说明：目前只有暗色标题栏存在新旧两套编号。
        DWORD effectiveAttribute(const RowSpec& spec) const
        {
            return spec.attribute == kAttrImmersiveDarkMode ? darkModeAttribute() : spec.attribute;
        }

        // currentRowValue：
        // - 作用：把界面控件状态换算为要写入 DWM 的原始 DWORD；
        // - 传出：布尔/枚举取下拉数据；配色的自定义模式取 COLORREF。
        DWORD currentRowValue(const AttributeRow& row) const
        {
            if (row.spec.kind == RowKind::Color && row.valueCombo->currentIndex() == 2)
            {
                const QColor color = row.customColor;
                return static_cast<DWORD>(RGB(color.red(), color.green(), color.blue()));
            }
            return row.valueCombo->currentData().toUInt();
        }

        // syncRowControl：
        // - 作用：把读回的原始值反映到下拉框（配色值会落到自定义模式）；
        // - 传入 row/value：目标行与读回值。
        void syncRowControl(AttributeRow& row, DWORD value)
        {
            if (row.spec.kind == RowKind::Color)
            {
                if (value == kColorDefault)
                {
                    row.valueCombo->setCurrentIndex(0);
                }
                else if (value == kColorNone)
                {
                    row.valueCombo->setCurrentIndex(1);
                }
                else
                {
                    row.customColor = QColor(GetRValue(value), GetGValue(value), GetBValue(value));
                    updateColorButton(row);
                    row.valueCombo->setCurrentIndex(2);
                }
                return;
            }

            for (int index = 0; index < row.valueCombo->count(); ++index)
            {
                if (row.valueCombo->itemData(index).toUInt() == value)
                {
                    row.valueCombo->setCurrentIndex(index);
                    return;
                }
            }
        }

        // describeValue：
        // - 作用：把原始 DWORD 翻译成人可读文本（枚举名 / 颜色 / 布尔）；
        // - 传出：用于状态标签、日志和报告的统一描述。
        QString describeValue(const RowSpec& spec, DWORD value) const
        {
            if (spec.kind == RowKind::Boolean)
            {
                return value != 0
                    ? uiText("window.dwm.value.true", "TRUE (1)")
                    : uiText("window.dwm.value.false", "FALSE (0)");
            }
            if (spec.kind == RowKind::Enumerated)
            {
                for (const EnumOption& option : spec.options)
                {
                    if (option.value == value)
                    {
                        return uiText(option.key, option.label);
                    }
                }
                return QStringLiteral("%1 (%2)").arg(value).arg(hexText(value));
            }
            if (value == kColorDefault)
            {
                return uiText("window.dwm.color.default", "系统默认");
            }
            if (value == kColorNone)
            {
                return uiText("window.dwm.color.none", "无（不绘制）");
            }
            return QStringLiteral("#%1%2%3 (COLORREF %4)")
                .arg(GetRValue(value), 2, 16, QChar('0'))
                .arg(GetGValue(value), 2, 16, QChar('0'))
                .arg(GetBValue(value), 2, 16, QChar('0'))
                .arg(hexText(value))
                .toUpper();
        }

        // confirmDestructiveWrite：
        // - 作用：对会让窗口从画面上消失的写入做二次确认；
        // - 传出：用户确认返回 true。
        bool confirmDestructiveWrite(const RowSpec& spec, DWORD value)
        {
            if (value == 0)
            {
                // 取消 Cloak 属于恢复动作，不需要打断用户。
                return true;
            }
            const QMessageBox::StandardButton answer = QMessageBox::question(
                this,
                uiText("window.dwm.confirm.title", "确认 DWM 写入"),
                uiText("window.dwm.confirm.cloak",
                    "即将对窗口 %1 设置 %2。\n\n窗口会立刻从画面上消失，但进程与句柄仍然存在，可以在本页把该属性改回 FALSE 恢复显示。\n\n确定继续吗？")
                    .arg(hwndText(m_target), QString::fromLatin1(spec.apiName)),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            return answer == QMessageBox::Yes;
        }

        // readAllAttributes：
        // - 作用：批量读取全部属性行；
        // - 传入 logSummary：是否在日志中记录本轮读取结果统计。
        void readAllAttributes(bool logSummary)
        {
            int readableCount = 0;
            for (AttributeRow& row : m_rows)
            {
                if (readAttributeRow(row, true))
                {
                    ++readableCount;
                }
            }
            if (logSummary)
            {
                appendLog(uiText("window.dwm.log.read_all", "已尝试 %1 项属性，其中 %2 项可回读。")
                    .arg(m_rows.size()).arg(readableCount));
            }
        }

        // restoreSystemDefaults：
        // - 作用：把本页改动过的属性全部写回系统默认值；
        // - 说明：多数 DWMWA_* 不可回读，因此以“文档默认值”为准而不是快照值。
        void restoreSystemDefaults()
        {
            if (!targetAlive())
            {
                return;
            }

            const QMessageBox::StandardButton answer = QMessageBox::question(
                this,
                uiText("window.dwm.confirm.title", "确认 DWM 写入"),
                uiText("window.dwm.confirm.restore",
                    "即将把本页涉及的全部 DWM 属性写回系统默认值，并清除框架扩展与合成特性。\n\n确定继续吗？"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (answer != QMessageBox::Yes)
            {
                return;
            }

            for (AttributeRow& row : m_rows)
            {
                const DWORD defaultValue = row.spec.kind == RowKind::Color ? kColorDefault : 0u;
                const DWORD attribute = effectiveAttribute(row.spec);
                const HRESULT result = ::DwmSetWindowAttribute(m_target, attribute, &defaultValue, sizeof(defaultValue));
                row.touched = false;
                appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                    .arg(QString::fromLatin1(row.spec.apiName),
                        describeValue(row.spec, defaultValue),
                        hresultText(result)));
            }

            for (QSpinBox* spinBox : m_marginSpins)
            {
                spinBox->setValue(0);
            }
            applyFrameMargins(0, 0, 0, 0);
            applyBlurBehind(false);
            if (m_accentStateCombo != nullptr)
            {
                m_accentStateCombo->setCurrentIndex(0);
            }
            applyAccentState(0);
            requestFrameChange();
            readAllAttributes(false);
            refreshDiagnostics();
        }

        // applySelectedPreset：
        // - 作用：按下拉选择执行一组预设写入；
        // - 说明：预设只调用已有的行写入逻辑，保证日志与状态同样被更新。
        void applySelectedPreset()
        {
            if (!targetAlive() || m_presetCombo == nullptr)
            {
                return;
            }

            switch (m_presetCombo->currentIndex())
            {
            case 0:
                setRowValue(kAttrImmersiveDarkMode, 1);
                setRowValue(kAttrWindowCornerPreference, 2);
                break;
            case 1:
                setRowValue(kAttrWindowCornerPreference, 1);
                setRowValue(kAttrBorderColor, kColorNone);
                break;
            case 2:
                setRowValue(kAttrSystemBackdropType, 2);
                setRowValue(kAttrImmersiveDarkMode, 1);
                break;
            case 3:
                setRowValue(kAttrSystemBackdropType, 3);
                setRowValue(kAttrWindowCornerPreference, 0);
                break;
            case 4:
                setRowValue(kAttrTransitionsForceDisabled, 1);
                setRowValue(kAttrExcludedFromPeek, 1);
                break;
            default:
                return;
            }
            requestFrameChange();
            refreshDiagnostics();
        }

        // setRowValue：
        // - 作用：按属性编号定位界面行、同步控件并立即写入；
        // - 传入 attribute/value：属性编号与目标值。
        void setRowValue(DWORD attribute, DWORD value)
        {
            for (AttributeRow& row : m_rows)
            {
                if (row.spec.attribute != attribute)
                {
                    continue;
                }
                syncRowControl(row, value);
                const HRESULT result = ::DwmSetWindowAttribute(
                    m_target, effectiveAttribute(row.spec), &value, sizeof(value));
                row.touched = row.touched || SUCCEEDED(result);
                appendLog(uiText("window.dwm.log.write", "写入 %1 = %2 → %3")
                    .arg(QString::fromLatin1(row.spec.apiName), describeValue(row.spec, value), hresultText(result)));
                readAttributeRow(row, false);
                return;
            }
        }

        // ---------- 框架扩展 / 模糊 / 合成特性 ----------

        // applyFrameMargins：
        // - 作用：调用 DwmExtendFrameIntoClientArea 设置玻璃边距；
        // - 传入 left/top/right/bottom：四边像素值，-1 表示整窗玻璃。
        void applyFrameMargins(int left, int top, int right, int bottom)
        {
            if (!targetAlive())
            {
                return;
            }
            MARGINS margins{ left, right, top, bottom };
            const HRESULT result = ::DwmExtendFrameIntoClientArea(m_target, &margins);
            appendLog(uiText("window.dwm.log.margins", "DwmExtendFrameIntoClientArea(%1,%2,%3,%4) → %5")
                .arg(left).arg(top).arg(right).arg(bottom).arg(hresultText(result)));
        }

        // applyBlurBehind：
        // - 作用：调用 DwmEnableBlurBehindWindow 开关窗口背后的模糊；
        // - 传入 enable：是否启用。
        void applyBlurBehind(bool enable)
        {
            if (!targetAlive())
            {
                return;
            }
            DWM_BLURBEHIND blurBehind{};
            blurBehind.dwFlags = DWM_BB_ENABLE | DWM_BB_TRANSITIONONMAXIMIZED;
            blurBehind.fEnable = enable ? TRUE : FALSE;
            blurBehind.fTransitionOnMaximized =
                (m_blurTransitionCheck != nullptr && m_blurTransitionCheck->isChecked()) ? TRUE : FALSE;
            const HRESULT result = ::DwmEnableBlurBehindWindow(m_target, &blurBehind);
            appendLog(uiText("window.dwm.log.blur", "DwmEnableBlurBehindWindow(enable=%1) → %2")
                .arg(enable ? 1 : 0).arg(hresultText(result)));
        }

        // applyAccentPolicy：
        // - 作用：按界面参数下发 ACCENT_POLICY；
        // - 说明：着色值按 0xAABBGGRR 排布，与 COLORREF 的字节序不同。
        void applyAccentPolicy()
        {
            if (m_accentStateCombo == nullptr)
            {
                return;
            }
            applyAccentState(m_accentStateCombo->currentData().toUInt());
        }

        // applyAccentState：
        // - 作用：以指定 ACCENT_STATE 调用 SetWindowCompositionAttribute；
        // - 传入 accentState：ACCENT_STATE 枚举值。
        void applyAccentState(DWORD accentState)
        {
            if (!targetAlive())
            {
                return;
            }
            const SetWindowCompositionAttributeFunction function = resolveSetWindowCompositionAttribute();
            if (function == nullptr)
            {
                const QString message = uiText(
                    "window.dwm.log.accent_unavailable", "当前系统没有导出 SetWindowCompositionAttribute。");
                appendLog(message);
                if (m_accentStatusLabel != nullptr)
                {
                    m_accentStatusLabel->setText(message);
                }
                return;
            }

            AccentPolicyData policy{};
            policy.accentState = accentState;
            policy.accentFlags = m_accentFlagsSpin != nullptr
                ? static_cast<DWORD>(m_accentFlagsSpin->value())
                : 0u;
            const int alpha = m_accentAlphaSlider != nullptr ? m_accentAlphaSlider->value() : 255;
            policy.gradientColor =
                (static_cast<DWORD>(alpha) << 24)
                | (static_cast<DWORD>(m_accentColor.blue()) << 16)
                | (static_cast<DWORD>(m_accentColor.green()) << 8)
                | static_cast<DWORD>(m_accentColor.red());

            WindowCompositionAttributeData data{};
            data.attribute = kWcaAccentPolicy;
            data.data = &policy;
            data.dataSize = sizeof(policy);

            ::SetLastError(ERROR_SUCCESS);
            const BOOL ok = function(m_target, &data);
            const DWORD lastError = ::GetLastError();
            const QString status = ok != FALSE
                ? uiText("window.dwm.status.accent_ok", "已下发 ACCENT_STATE=%1，着色 %2")
                    .arg(accentState).arg(hexText(policy.gradientColor))
                : uiText("window.dwm.status.accent_failed", "下发失败，Win32 错误码 %1").arg(lastError);
            if (m_accentStatusLabel != nullptr)
            {
                m_accentStatusLabel->setText(status);
            }
            appendLog(status);
        }

        // applyDarkModeColors：
        // - 作用：通过 WCA_USEDARKMODECOLORS 切换窗口的暗色系统配色；
        // - 传入 enable：是否启用暗色。
        void applyDarkModeColors(bool enable)
        {
            if (!targetAlive())
            {
                return;
            }
            const SetWindowCompositionAttributeFunction function = resolveSetWindowCompositionAttribute();
            if (function == nullptr)
            {
                appendLog(uiText(
                    "window.dwm.log.accent_unavailable", "当前系统没有导出 SetWindowCompositionAttribute。"));
                return;
            }

            BOOL darkModeValue = enable ? TRUE : FALSE;
            WindowCompositionAttributeData data{};
            data.attribute = kWcaUseDarkModeColors;
            data.data = &darkModeValue;
            data.dataSize = sizeof(darkModeValue);

            ::SetLastError(ERROR_SUCCESS);
            const BOOL ok = function(m_target, &data);
            const DWORD lastError = ::GetLastError();
            appendLog(uiText("window.dwm.log.dark_colors", "WCA_USEDARKMODECOLORS(%1) → %2")
                .arg(enable ? 1 : 0)
                .arg(ok != FALSE
                    ? uiText("window.dwm.log.ok", "成功")
                    : uiText("window.dwm.log.failed_error", "失败(%1)").arg(lastError)));
            requestFrameChange();
        }

        // requestFrameChange：
        // - 作用：让目标窗口重算非客户区，使刚写入的属性立刻可见；
        // - 说明：必须使用 SWP_ASYNCWINDOWPOS，否则目标线程无响应时会拖住本程序。
        void requestFrameChange()
        {
            if (::IsWindow(m_target) == FALSE)
            {
                return;
            }
            ::SetWindowPos(
                m_target,
                nullptr,
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_ASYNCWINDOWPOS);
        }

        // ---------- 诊断与报告 ----------

        // refreshDiagnostics：
        // - 作用：重新采样只读诊断信息并刷新右侧文本；
        // - 调用：初始化、写入之后、点击刷新按钮时。
        void refreshDiagnostics()
        {
            if (m_diagnosticsText == nullptr)
            {
                return;
            }
            const int scrollValue = m_diagnosticsText->verticalScrollBar() != nullptr
                ? m_diagnosticsText->verticalScrollBar()->value()
                : 0;
            m_diagnosticsText->setPlainText(buildDiagnosticsText());
            if (m_diagnosticsText->verticalScrollBar() != nullptr)
            {
                m_diagnosticsText->verticalScrollBar()->setValue(scrollValue);
            }
        }

        // buildDiagnosticsText：
        // - 作用：汇总系统级合成状态与目标窗口的只读 DWM 属性；
        // - 传出：多行诊断文本。
        QString buildDiagnosticsText() const
        {
            QStringList lines;

            lines << uiText("window.dwm.diag.section_system", "[系统合成状态]");
            BOOL compositionEnabled = FALSE;
            const HRESULT compositionResult = ::DwmIsCompositionEnabled(&compositionEnabled);
            lines << QStringLiteral("DwmIsCompositionEnabled: %1")
                .arg(SUCCEEDED(compositionResult)
                    ? (compositionEnabled != FALSE
                        ? uiText("window.dwm.value.yes", "是")
                        : uiText("window.dwm.value.no", "否"))
                    : hresultText(compositionResult));

            DWORD colorization = 0;
            BOOL opaqueBlend = FALSE;
            const HRESULT colorizationResult = ::DwmGetColorizationColor(&colorization, &opaqueBlend);
            lines << QStringLiteral("DwmGetColorizationColor: %1")
                .arg(SUCCEEDED(colorizationResult)
                    ? QStringLiteral("%1 (%2 %3)")
                        .arg(hexText(colorization))
                        .arg(uiText("window.dwm.diag.opaque_blend", "不透明混合"))
                        .arg(opaqueBlend != FALSE
                            ? uiText("window.dwm.value.yes", "是")
                            : uiText("window.dwm.value.no", "否"))
                    : hresultText(colorizationResult));

            DWM_TIMING_INFO timingInfo{};
            timingInfo.cbSize = sizeof(timingInfo);
            const HRESULT timingResult = ::DwmGetCompositionTimingInfo(nullptr, &timingInfo);
            if (SUCCEEDED(timingResult))
            {
                const double refreshRate = timingInfo.rateRefresh.uiDenominator != 0
                    ? static_cast<double>(timingInfo.rateRefresh.uiNumerator)
                        / static_cast<double>(timingInfo.rateRefresh.uiDenominator)
                    : 0.0;
                const double composeRate = timingInfo.rateCompose.uiDenominator != 0
                    ? static_cast<double>(timingInfo.rateCompose.uiNumerator)
                        / static_cast<double>(timingInfo.rateCompose.uiDenominator)
                    : 0.0;
                lines << QStringLiteral("MonitorRefreshRate: %1 Hz").arg(refreshRate, 0, 'f', 3);
                lines << QStringLiteral("CompositionRate: %1 Hz").arg(composeRate, 0, 'f', 3);
                lines << QStringLiteral("cRefresh / cFrame: %1 / %2")
                    .arg(static_cast<qulonglong>(timingInfo.cRefresh))
                    .arg(static_cast<qulonglong>(timingInfo.cFrame));
                lines << QStringLiteral("cFramesLate / cFramesDropped: %1 / %2")
                    .arg(static_cast<qulonglong>(timingInfo.cFramesLate))
                    .arg(static_cast<qulonglong>(timingInfo.cFramesDropped));
            }
            else
            {
                lines << QStringLiteral("DwmGetCompositionTimingInfo: %1").arg(hresultText(timingResult));
            }

            lines << QString() << uiText("window.dwm.diag.section_window", "[目标窗口只读属性]");
            if (::IsWindow(m_target) == FALSE)
            {
                lines << uiText("window.dwm.status.invalid_target", "目标窗口已失效");
                return lines.join(QChar::LineFeed);
            }

            const DwordResult ncRendering = readDwordAttribute(m_target, kAttrNcRenderingEnabled);
            lines << QStringLiteral("DWMWA_NCRENDERING_ENABLED (1): %1")
                .arg(ncRendering.ok
                    ? (ncRendering.value != 0
                        ? uiText("window.dwm.value.yes", "是")
                        : uiText("window.dwm.value.no", "否"))
                    : hresultText(ncRendering.hr));

            const DwordResult cloaked = readDwordAttribute(m_target, kAttrCloaked);
            lines << QStringLiteral("DWMWA_CLOAKED (14): %1")
                .arg(cloaked.ok ? describeCloaked(cloaked.value) : hresultText(cloaked.hr));

            const DwordResult borderThickness = readDwordAttribute(m_target, kAttrVisibleFrameBorderThickness);
            lines << QStringLiteral("DWMWA_VISIBLE_FRAME_BORDER_THICKNESS (37): %1")
                .arg(borderThickness.ok ? QString::number(borderThickness.value) : hresultText(borderThickness.hr));

            const RectResult extendedFrame = readRectAttribute(m_target, kAttrExtendedFrameBounds);
            lines << QStringLiteral("DWMWA_EXTENDED_FRAME_BOUNDS (9): %1")
                .arg(extendedFrame.ok ? rectText(extendedFrame.value) : hresultText(extendedFrame.hr));

            const RectResult captionButtons = readRectAttribute(m_target, kAttrCaptionButtonBounds);
            lines << QStringLiteral("DWMWA_CAPTION_BUTTON_BOUNDS (5): %1")
                .arg(captionButtons.ok ? rectText(captionButtons.value) : hresultText(captionButtons.hr));

            RECT windowRect{};
            if (::GetWindowRect(m_target, &windowRect) != FALSE)
            {
                lines << QStringLiteral("GetWindowRect: %1").arg(rectText(windowRect));
                if (extendedFrame.ok)
                {
                    // 两个矩形之差就是 DWM 预留的不可见阴影边距，排版类问题常卡在这里。
                    lines << uiText("window.dwm.diag.shadow_inset", "阴影内缩(左/上/右/下): %1 / %2 / %3 / %4")
                        .arg(extendedFrame.value.left - windowRect.left)
                        .arg(extendedFrame.value.top - windowRect.top)
                        .arg(windowRect.right - extendedFrame.value.right)
                        .arg(windowRect.bottom - extendedFrame.value.bottom);
                }
            }

            return lines.join(QChar::LineFeed);
        }

        // describeCloaked：
        // - 作用：解释 DWMWA_CLOAKED 的来源位组合；
        // - 传出：形如 “0x2 (Shell 隐藏)” 的文本。
        QString describeCloaked(DWORD value) const
        {
            if (value == 0)
            {
                return uiText("window.dwm.cloak.visible", "0 (未隐藏)");
            }
            QStringList parts;
            if ((value & 0x1u) != 0)
            {
                parts << uiText("window.dwm.cloak.app", "应用自身隐藏");
            }
            if ((value & 0x2u) != 0)
            {
                parts << uiText("window.dwm.cloak.shell", "Shell 隐藏");
            }
            if ((value & 0x4u) != 0)
            {
                parts << uiText("window.dwm.cloak.inherited", "继承自属主窗口");
            }
            if (parts.isEmpty())
            {
                parts << uiText("window.dwm.cloak.unknown", "未知来源");
            }
            return QStringLiteral("%1 (%2)").arg(hexText(value), parts.join(QStringLiteral(", ")));
        }

        // buildReportText：
        // - 作用：把诊断信息与全部属性行的当前状态汇总成一份可归档文本；
        // - 传出：完整报告。
        QString buildReportText() const
        {
            QStringList lines;
            lines << uiText("window.dwm.report.title", "KSword DWM 合成报告");
            lines << uiText("window.dwm.report.time", "生成时间: %1")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
            lines << uiText("window.dwm.report.target", "目标 HWND: %1").arg(hwndText(m_target));
            lines << uiText("window.dwm.report.build", "系统构建号: %1").arg(windowsBuild());
            lines << QString();
            lines << buildDiagnosticsText();
            lines << QString() << uiText("window.dwm.report.section_rows", "[可控属性当前状态]");
            for (const AttributeRow& row : m_rows)
            {
                lines << QStringLiteral("%1 (%2): %3")
                    .arg(QString::fromLatin1(row.spec.apiName))
                    .arg(effectiveAttribute(row.spec))
                    .arg(row.statusLabel != nullptr ? row.statusLabel->text() : QString());
            }
            return lines.join(QChar::LineFeed);
        }

        // exportReport：
        // - 作用：把报告写入用户选择的文本文件；
        // - 说明：失败时给出明确的文件路径与原因，不静默吞掉。
        void exportReport()
        {
            const QString filePath = QFileDialog::getSaveFileName(
                this,
                uiText("window.dwm.export.title", "导出 DWM 报告"),
                QStringLiteral("dwm_%1.txt").arg(hwndText(m_target)),
                uiText("window.dwm.export.filter", "文本文件 (*.txt);;所有文件 (*)"));
            if (filePath.isEmpty())
            {
                return;
            }

            QFile file(filePath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
            {
                QMessageBox::warning(
                    this,
                    uiText("window.dwm.export.failed_title", "导出失败"),
                    uiText("window.dwm.export.failed_text", "无法写入文件 %1：%2")
                        .arg(filePath, file.errorString()));
                return;
            }
            QTextStream stream(&file);
            stream << buildReportText();
            file.close();
            appendLog(uiText("window.dwm.log.exported", "报告已导出到 %1").arg(filePath));
        }

        // appendLog：
        // - 作用：向操作日志追加一行带时间戳的记录，并做行数封顶；
        // - 传入 message：已经本地化的文本。
        void appendLog(const QString& message)
        {
            if (m_logText == nullptr)
            {
                return;
            }
            m_logText->appendPlainText(QStringLiteral("[%1] %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), message));
            while (m_logText->document()->blockCount() > kLogBlockLimit)
            {
                QTextCursor cursor(m_logText->document());
                cursor.movePosition(QTextCursor::Start);
                cursor.select(QTextCursor::BlockUnderCursor);
                cursor.removeSelectedText();
                cursor.deleteChar();
            }
        }

        // updateColorButton / updateAccentColorButton：
        // - 作用：把当前选色刷到取色按钮上，作为直观的颜色预览。
        void updateColorButton(AttributeRow& row)
        {
            if (row.colorButton == nullptr)
            {
                return;
            }
            // 描边取 palette(mid)：写死的半透明黑在深色主题下会和底色糊成一片，
            // 选到深色时连按钮边界都看不出来。
            row.colorButton->setStyleSheet(
                QStringLiteral("QPushButton{background:%1;border:1px solid %2;border-radius:4px; }")
                    .arg(row.customColor.name(QColor::HexRgb), KswordTheme::BorderHex()));
            row.colorButton->setToolTip(row.customColor.name(QColor::HexRgb).toUpper());
        }

        void updateAccentColorButton()
        {
            if (m_accentColorButton == nullptr)
            {
                return;
            }
            m_accentColorButton->setStyleSheet(
                QStringLiteral("QPushButton{background:%1;border:1px solid %2;border-radius:4px; }")
                    .arg(m_accentColor.name(QColor::HexRgb), KswordTheme::BorderHex()));
            m_accentColorButton->setToolTip(m_accentColor.name(QColor::HexRgb).toUpper());
        }

        // ---------- DWM 实时缩略图 ----------

        // ensureThumbnail：
        // - 作用：把目标窗口注册为本对话框上的 DWM 缩略图源；
        // - 说明：宿主必须是顶层窗口，注册失败时把 HRESULT 展示在状态标签上。
        void ensureThumbnail()
        {
            if (m_thumbnail != nullptr)
            {
                return;
            }
            if (::IsWindow(m_target) == FALSE)
            {
                m_thumbnailStatusLabel->setText(uiText("window.dwm.status.invalid_target", "目标窗口已失效"));
                return;
            }

            QWidget* topLevel = window();
            if (topLevel == nullptr)
            {
                return;
            }
            const HWND destination = reinterpret_cast<HWND>(topLevel->winId());
            if (destination == nullptr)
            {
                return;
            }

            HTHUMBNAIL thumbnail = nullptr;
            const HRESULT result = ::DwmRegisterThumbnail(destination, m_target, &thumbnail);
            if (FAILED(result))
            {
                m_thumbnailStatusLabel->setText(
                    uiText("window.dwm.thumbnail.register_failed", "注册缩略图失败: %1").arg(hresultText(result)));
                appendLog(uiText("window.dwm.thumbnail.register_failed", "注册缩略图失败: %1").arg(hresultText(result)));
                return;
            }
            m_thumbnail = thumbnail;
            m_thumbnailDestination = destination;
            appendLog(uiText("window.dwm.thumbnail.registered", "已注册 DWM 缩略图，宿主窗口 %1")
                .arg(hwndText(destination)));
        }

        // releaseThumbnail：
        // - 作用：注销缩略图句柄；
        // - 调用：关闭预览、页面析构、宿主窗口句柄变化时。
        void releaseThumbnail()
        {
            if (m_thumbnail == nullptr)
            {
                return;
            }
            ::DwmUnregisterThumbnail(m_thumbnail);
            m_thumbnail = nullptr;
            m_thumbnailDestination = nullptr;
        }

        // updateThumbnailPlacement：
        // - 作用：把占位控件的位置换算成 DWM 目标矩形并提交；
        // - 说明：DWM 使用物理像素且以宿主客户区左上角为原点，因此需要乘设备像素比。
        void updateThumbnailPlacement()
        {
            if (m_thumbnailStatusLabel == nullptr || m_thumbnailHost == nullptr)
            {
                return;
            }

            const bool wantVisible =
                m_thumbnailEnableCheck != nullptr
                && m_thumbnailEnableCheck->isChecked()
                && isVisible()
                && m_thumbnailHost->isVisible();

            if (!wantVisible)
            {
                if (m_thumbnail != nullptr)
                {
                    DWM_THUMBNAIL_PROPERTIES properties{};
                    properties.dwFlags = DWM_TNP_VISIBLE;
                    properties.fVisible = FALSE;
                    ::DwmUpdateThumbnailProperties(m_thumbnail, &properties);
                }
                return;
            }

            QWidget* topLevel = window();
            if (topLevel == nullptr)
            {
                return;
            }
            const HWND destination = reinterpret_cast<HWND>(topLevel->winId());
            if (m_thumbnail != nullptr && destination != m_thumbnailDestination)
            {
                // Qt 重建原生窗口后旧句柄已失效，必须重新注册才能继续显示。
                releaseThumbnail();
            }
            if (m_thumbnail == nullptr)
            {
                ensureThumbnail();
                if (m_thumbnail == nullptr)
                {
                    return;
                }
            }

            SIZE sourceSize{};
            const HRESULT sizeResult = ::DwmQueryThumbnailSourceSize(m_thumbnail, &sourceSize);
            if (FAILED(sizeResult) || sourceSize.cx <= 0 || sourceSize.cy <= 0)
            {
                m_thumbnailStatusLabel->setText(
                    uiText("window.dwm.thumbnail.size_failed", "查询源尺寸失败: %1").arg(hresultText(sizeResult)));
                return;
            }

            const qreal pixelRatio = topLevel->devicePixelRatioF();
            const QPoint hostOrigin = m_thumbnailHost->mapTo(topLevel, QPoint(0, 0));
            const QSize hostSize = m_thumbnailHost->size();
            const int hostLeft = qRound(hostOrigin.x() * pixelRatio);
            const int hostTop = qRound(hostOrigin.y() * pixelRatio);
            const int hostWidth = qRound(hostSize.width() * pixelRatio);
            const int hostHeight = qRound(hostSize.height() * pixelRatio);
            if (hostWidth <= 0 || hostHeight <= 0)
            {
                return;
            }

            // 等比缩放并居中，避免目标窗口画面被拉伸变形。
            const double scale = qMin(
                static_cast<double>(hostWidth) / static_cast<double>(sourceSize.cx),
                static_cast<double>(hostHeight) / static_cast<double>(sourceSize.cy));
            const int drawWidth = qMax(1, static_cast<int>(sourceSize.cx * scale));
            const int drawHeight = qMax(1, static_cast<int>(sourceSize.cy * scale));
            const int offsetX = hostLeft + (hostWidth - drawWidth) / 2;
            const int offsetY = hostTop + (hostHeight - drawHeight) / 2;

            DWM_THUMBNAIL_PROPERTIES properties{};
            properties.dwFlags =
                DWM_TNP_RECTDESTINATION | DWM_TNP_VISIBLE | DWM_TNP_OPACITY | DWM_TNP_SOURCECLIENTAREAONLY;
            properties.rcDestination = RECT{ offsetX, offsetY, offsetX + drawWidth, offsetY + drawHeight };
            properties.fVisible = TRUE;
            properties.opacity = static_cast<BYTE>(
                m_thumbnailOpacitySlider != nullptr ? m_thumbnailOpacitySlider->value() : 255);
            properties.fSourceClientAreaOnly =
                (m_thumbnailClientOnlyCheck != nullptr && m_thumbnailClientOnlyCheck->isChecked()) ? TRUE : FALSE;

            const HRESULT updateResult = ::DwmUpdateThumbnailProperties(m_thumbnail, &properties);
            if (FAILED(updateResult))
            {
                m_thumbnailStatusLabel->setText(
                    uiText("window.dwm.thumbnail.update_failed", "更新缩略图失败: %1").arg(hresultText(updateResult)));
                return;
            }
            m_thumbnailStatusLabel->setText(
                uiText("window.dwm.thumbnail.active", "源尺寸 %1x%2，显示 %3x%4")
                    .arg(sourceSize.cx).arg(sourceSize.cy).arg(drawWidth).arg(drawHeight));
        }

    private:
        HWND m_target = nullptr;                       // m_target：被控制的目标窗口。
        std::vector<AttributeRow> m_rows;              // m_rows：全部可控属性行。

        QCheckBox* m_frameChangeCheck = nullptr;       // 写入后是否强制重算边框。
        QComboBox* m_presetCombo = nullptr;            // 一键预设选择。

        std::array<QSpinBox*, 4> m_marginSpins{ nullptr, nullptr, nullptr, nullptr }; // 玻璃边距四边。
        QCheckBox* m_blurTransitionCheck = nullptr;    // 模糊是否随最大化过渡。

        QComboBox* m_accentStateCombo = nullptr;       // ACCENT_STATE 选择。
        QPushButton* m_accentColorButton = nullptr;    // 合成着色取色按钮。
        QSlider* m_accentAlphaSlider = nullptr;        // 合成着色透明度。
        QSpinBox* m_accentFlagsSpin = nullptr;         // ACCENT_POLICY 标志位。
        QLabel* m_accentStatusLabel = nullptr;         // 合成特性状态。
        QColor m_accentColor{ 32, 32, 32 };            // 合成着色当前颜色。

        QCheckBox* m_thumbnailEnableCheck = nullptr;   // 是否启用实时缩略图。
        QCheckBox* m_thumbnailClientOnlyCheck = nullptr; // 是否只显示客户区。
        QSlider* m_thumbnailOpacitySlider = nullptr;   // 缩略图不透明度。
        QWidget* m_thumbnailHost = nullptr;            // 缩略图占位区域。
        QLabel* m_thumbnailStatusLabel = nullptr;      // 缩略图状态提示。
        QTimer* m_thumbnailTimer = nullptr;            // 目标矩形跟随定时器。
        HTHUMBNAIL m_thumbnail = nullptr;              // DWM 缩略图句柄。
        HWND m_thumbnailDestination = nullptr;         // 注册时使用的宿主窗口句柄。

        QPlainTextEdit* m_diagnosticsText = nullptr;   // 只读诊断输出。
        QPlainTextEdit* m_logText = nullptr;           // 操作日志输出。
    };

    // ============ 注入到窗口详情对话框 ============

    // targetFromDialog：
    // - 作用：从详情对话框读取结构化的目标 HWND；
    // - 传出：解析成功返回句柄，失败返回空。
    std::optional<HWND> targetFromDialog(const QDialog* dialog)
    {
        bool propertyOk = false;
        const qulonglong propertyValue = dialog->property(kTargetHwndProperty).toULongLong(&propertyOk);
        if (propertyOk && propertyValue != 0)
        {
            return reinterpret_cast<HWND>(static_cast<quintptr>(propertyValue));
        }
        return std::nullopt;
    }

    // hostTabs：
    // - 作用：找到详情对话框中承载页签的 QTabWidget；
    // - 传出：最合适的 QTabWidget，找不到返回 nullptr。
    QTabWidget* hostTabs(QDialog* dialog)
    {
        QTabWidget* best = nullptr;
        int bestScore = -1;
        for (QTabWidget* tabs : dialog->findChildren<QTabWidget*>())
        {
            const int score = tabs->count() + (tabs->parentWidget() == dialog ? 1000 : 0);
            if (score > bestScore)
            {
                best = tabs;
                bestScore = score;
            }
        }
        return best;
    }

    // attach：
    // - 作用：给一个窗口详情对话框追加 DWM 合成页；
    // - 说明：使用独立的附着标记，与层级诊断页互不干扰。
    void attach(QDialog* dialog)
    {
        if (dialog == nullptr || dialog->property(kAttachedProperty).toBool())
        {
            return;
        }
        const std::optional<HWND> target = targetFromDialog(dialog);
        QTabWidget* tabs = hostTabs(dialog);
        if (!target.has_value() || tabs == nullptr)
        {
            return;
        }
        Page* page = new Page(*target, tabs);
        tabs->addTab(page, uiText("window.dwm.tab.title", "DWM 合成"));
        ks::i18n::LanguageManager::instance().bindTab(
            tabs, page, QStringLiteral("window.dwm.tab.title"), QStringLiteral("DWM 合成"));
        dialog->setProperty(kAttachedProperty, true);
    }

    // Injector：
    // - 作用：应用级事件过滤器，在窗口详情对话框首次显示时注入本页。
    class Injector final : public QObject
    {
    public:
        explicit Injector(QObject* parent) : QObject(parent) {}

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event != nullptr && event->type() == QEvent::Show)
            {
                auto* dialog = qobject_cast<QDialog*>(watched);
                if (dialog != nullptr && dialog->objectName() == QStringLiteral("WindowDetailDialogRoot"))
                {
                    const QPointer<QDialog> safeDialog(dialog);
                    QTimer::singleShot(0, dialog, [safeDialog]() {
                        if (!safeDialog.isNull())
                        {
                            attach(safeDialog.data());
                        }
                    });
                }
            }
            return QObject::eventFilter(watched, event);
        }
    };

    // install：进程启动时安装注入器。
    void install()
    {
        QCoreApplication* app = QCoreApplication::instance();
        if (app == nullptr)
        {
            return;
        }
        auto* injector = new Injector(app);
        app->installEventFilter(injector);
    }
}

static void installKswordWindowDwmControl()
{
    ks::window::dwmctl::install();
}

Q_COREAPP_STARTUP_FUNCTION(installKswordWindowDwmControl)
