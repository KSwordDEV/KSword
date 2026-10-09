#include "GlobalUiBaseStyle.h"
#include "./FlatButtonTheme.h"

#include "ThemeStatusRole.h"

#include "../theme.h"

namespace ks::ui
{
    QString BuildGlobalBaseControlStyleBlock()
    {
        // 所有颜色都来自 KswordTheme 动态角色，深浅色与自定义主题色变化时整块重建。
        QString baseControlStyle = QString::fromLatin1(
            "\n__BEGIN_MARKER__\n"

            // ---------- 按钮基线 ----------
            // 未被局部样式接管的普通按钮统一为“中性表面 + 主题色交互”。
            // 基线只允许颜色/边框属性：min-height、padding 等几何属性会穿透
            // 局部样式改变紧凑布局（如标题栏图标按钮）的尺寸，一律禁止。
            "QPushButton{"
            "  background-color:__SURFACE_ALT__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "}"
            "QPushButton:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:pressed{"
            "  background-color:__ACCENT_PRESSED__;"
            "  color:__ON_ACCENT_PRESSED__;"
            "  border-color:__ACCENT_PRESSED__;"
            "}"
            "QPushButton:checked{"
            "  background-color:__ACCENT__;"
            "  color:__ON_ACCENT__;"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:default{"
            "  border-color:__ACCENT__;"
            "}"
            "QPushButton:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "  border-color:__BORDER__;"
            "}"
            "QPushButton:flat{"
            "  background-color:transparent;"
            "  border:none;"
            "}"

            // ---------- 输入控件基线 ----------
            // 单行字段用一致的中性实底标明编辑面，焦点只轻染主题色，不画亮色线框。
            // 不改 padding、字号或高度，保持现有紧凑工具条及编辑器布局。
            "QLineEdit,QSpinBox,QDoubleSpinBox,QDateEdit,QTimeEdit,QDateTimeEdit{"
            "  background-color:__INPUT_SURFACE__;"
            "  color:__TEXT__;"
            "  border:none;"
            "  border-radius:3px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QLineEdit:hover,QSpinBox:hover,QDoubleSpinBox:hover,QDateEdit:hover,QTimeEdit:hover,QDateTimeEdit:hover{"
            "  background-color:__INPUT_HOVER__;"
            "  border:none;"
            "}"
            "QLineEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QDateEdit:focus,QTimeEdit:focus,QDateTimeEdit:focus{"
            "  background-color:__INPUT_FOCUS__;"
            "  border:none;"
            "}"
            "QLineEdit:disabled,QSpinBox:disabled,QDoubleSpinBox:disabled,QDateEdit:disabled,QTimeEdit:disabled,QDateTimeEdit:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "  border:none;"
            "}"
            "QLineEdit:read-only,QLineEdit:read-only:hover,QLineEdit:read-only:focus{"
            "  background-color:__SURFACE_MUTED__;"
            "  border:none;"
            "}"
            // QSS 设置文字色后 Qt 会重建默认半透明 placeholder，明确指定不透明提示角色。
            "QLineEdit{placeholder-text-color:__INPUT_PLACEHOLDER__;}"
            "QLineEdit:disabled{placeholder-text-color:__TEXT_DISABLED__;}"
            // 内嵌编辑器使用外层控件的同一表面，避免上下按钮/下拉区拼出第二层输入框。
            "QAbstractSpinBox QLineEdit,QComboBox QLineEdit{"
            "  background:transparent;"
            "  border:none;"
            "}"
            "QAbstractSpinBox QLineEdit:hover,QAbstractSpinBox QLineEdit:focus,QComboBox QLineEdit:hover,QComboBox QLineEdit:focus{"
            "  background:transparent;"
            "  border:none;"
            "}"

            // 多行编辑器仍是独立内容面；保留轻边界帮助辨认报告和可编辑文档的范围。
            "QPlainTextEdit,QTextEdit{"
            "  background-color:__SURFACE__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QPlainTextEdit:focus,QTextEdit:focus{border-color:__BORDER_STRONG__;}"
            "QPlainTextEdit:disabled,QTextEdit:disabled{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT_DISABLED__;"
            "}"
            "QPlainTextEdit:read-only,QTextEdit:read-only{background-color:__SURFACE_MUTED__;}"

            // ---------- 数字/日期输入框的步进按钮 ----------
            // 只要有任意一条 QSS 命中 QSpinBox，Qt 就会改用 QStyleSheetStyle 绘制
            // CC_SpinBox。此时若不显式给出 up-button/down-button 与箭头规则，
            // 上下按钮既不画箭头也不画完整背景，只在右边缘留下几段残缺边线——
            // 用户看到的就是“一个点”，既认不出是加减，也不知道该点哪里。
            // 类型选择器对子类同样生效，这一组同时覆盖 QSpinBox、QDoubleSpinBox
            // 和 QDateEdit/QTimeEdit/QDateTimeEdit。
            "QAbstractSpinBox::up-button{"
            "  subcontrol-origin:border;"
            "  subcontrol-position:top right;"
            "  width:18px;"
            "  margin:1px 1px 0px 0px;"
            "  border:none;"
            "  border-top-right-radius:2px;"
            "  background-color:__INPUT_SURFACE__;"
            "}"
            "QAbstractSpinBox::down-button{"
            "  subcontrol-origin:border;"
            "  subcontrol-position:bottom right;"
            "  width:18px;"
            "  margin:0px 1px 1px 0px;"
            "  border:none;"
            "  border-bottom-right-radius:2px;"
            "  background-color:__INPUT_SURFACE__;"
            "}"
            "QAbstractSpinBox::up-button:hover,QAbstractSpinBox::down-button:hover{"
            "  background-color:__INPUT_HOVER__;"
            "}"
            "QAbstractSpinBox::up-button:pressed,QAbstractSpinBox::down-button:pressed{"
            "  background-color:__INPUT_FOCUS__;"
            "}"
            // :off 表示已经到达上下限，和 :disabled 一样必须给出可见反馈，
            // 否则用户会以为按钮又坏了。
            "QAbstractSpinBox::up-button:off,QAbstractSpinBox::down-button:off,QAbstractSpinBox::up-button:disabled,QAbstractSpinBox::down-button:disabled{"
            "  background-color:__SURFACE_MUTED__;"

            "}"
            "QAbstractSpinBox::up-arrow{"
            "  image:url(__ARROW_UP__);"
            "  width:10px;"
            "  height:10px;"
            "}"
            "QAbstractSpinBox::down-arrow{"
            "  image:url(__ARROW_DOWN__);"
            "  width:10px;"
            "  height:10px;"
            "}"
            "QAbstractSpinBox::up-arrow:off,QAbstractSpinBox::up-arrow:disabled{"
            "  image:url(__ARROW_UP_OFF__);"
            "}"
            "QAbstractSpinBox::down-arrow:off,QAbstractSpinBox::down-arrow:disabled{"
            "  image:url(__ARROW_DOWN_OFF__);"
            "}"

            // ---------- 分组框基线 ----------
            // margin-top 是标题行所需的最小空间，与 Qt 原生标题高度一致。
            // 四周实色边框会让密集页面（一屏七八个分组）变成一堆套嵌方框，
            // 因此只保留标题下方的一条分隔线：分组关系照样读得出来，线框少四分之三。
            "QGroupBox{"
            "  border:none;"
            "  border-top:1px solid __BORDER__;"
            "  margin-top:12px;"
            "}"
            "QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  subcontrol-position:top left;"
            "  left:8px;"
            "  padding:0px 4px;"
            "  color:__TEXT_SECONDARY__;"
            "  font-weight:600;"
            "}"

            // ---------- 表格/树基线 ----------
            // 只保留表头下方的分隔；逐格网格和外框由 TablePresentation 关闭。
            // 间距、密度和专业视图例外都在控件层处理，全局块不增加几何属性。
            "QTableView,QTableWidget,QTreeView,QTreeWidget{"
            "  border:none;"
            "  color:__TEXT__;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QHeaderView{"
            "  background-color:transparent;"
            "  border:none;"
            "}"
            "QHeaderView::section{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT__;"
            "  font-weight:600;"
            "  border:none;"
            "  border-bottom:1px solid __BORDER__;"
            "}"
            "QHeaderView::section:hover{"
            "  background-color:__SURFACE_MUTED__;"
            "}"

            // ---------- 进度条基线 ----------
            "QProgressBar{"
            "  background-color:__SURFACE_MUTED__;"
            "  color:__TEXT__;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QProgressBar::chunk{"
            "  background-color:__ACCENT__;"
            "  border-radius:2px;"
            "}"

            // ---------- 分割条基线 ----------
            // QFrame 的 HLine/VLine 是布局明确声明的结构线，保留轻中性线而非控件外框。
            "QFrame[frameShape=\"4\"]{background:transparent;border:none;border-top:1px solid __BORDER__;}"
            "QFrame[frameShape=\"5\"]{background:transparent;border:none;border-left:1px solid __BORDER__;}"
            "QSplitter::handle{"
            "  background-color:transparent;"
            "}"
            "QSplitter::handle:hover{"
            "  background-color:__ACCENT__;"
            "}"

            // ---------- 状态栏基线 ----------
            "QStatusBar{"
            "  background-color:__WINDOW__;"
            "  color:__TEXT_SECONDARY__;"
            "}"
            "QStatusBar::item{"
            "  border:none;"
            "}"

            // ---------- 语义状态色基线 ----------
            // 规则文本由 ThemeStatusRole 生成；状态标签只带 ksword_status_role 属性，
            // 不再自己持有 styleSheet，颜色随本样式块整体重建跟随主题。
            "__STATUS_ROLE_RULES__"

            "__END_MARKER__\n");

        // 步进与下拉箭头共用主题前景派生链；SVG 缓存弥补 QSS 本身不能为图片着色。
        // 返回带引号的 URL 参数，缓存目录包含空格时也能被 QSS 正确解析。
        const auto arrowResourcePath = [](const QColor& backgroundColor,
                                         const bool pointingUp,
                                         const bool disabled) {
            const QString resourcePath = pointingUp
                ? QStringLiteral(":/Icon/ks_control_up_white.svg")
                : QStringLiteral(":/Icon/ks_control_down_white.svg");
            const QColor foregroundColor = KswordTheme::ControlGlyphColor(backgroundColor, disabled);
            return QStringLiteral("\"%1\"").arg(
                ThemedControlGlyphPath(resourcePath, foregroundColor));
        };

        baseControlStyle.replace(QStringLiteral("__BEGIN_MARKER__"), QString::fromLatin1(kBaseControlStyleBeginMarker));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_UP_OFF__"),
            arrowResourcePath(KswordTheme::SurfaceMutedColor(), true, true));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_DOWN_OFF__"),
            arrowResourcePath(KswordTheme::SurfaceMutedColor(), false, true));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_UP__"),
            arrowResourcePath(KswordTheme::ControlInputSurfaceColor(), true, false));
        baseControlStyle.replace(
            QStringLiteral("__ARROW_DOWN__"),
            arrowResourcePath(KswordTheme::ControlInputSurfaceColor(), false, false));
        baseControlStyle.replace(QStringLiteral("__STATUS_ROLE_RULES__"), BuildStatusRoleStyleRules());
        baseControlStyle.replace(QStringLiteral("__END_MARKER__"), QString::fromLatin1(kBaseControlStyleEndMarker));
        baseControlStyle.replace(QStringLiteral("__WINDOW__"), KswordTheme::MainBackgroundColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE__"), KswordTheme::SurfaceColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_ALT__"), KswordTheme::SurfaceAltColorHex());
        baseControlStyle.replace(QStringLiteral("__SURFACE_MUTED__"), KswordTheme::SurfaceMutedColorHex());
        // 同一中性输入面配方同时用于搜索、数值框和组合框，不改变面板边界角色。
        baseControlStyle.replace(QStringLiteral("__INPUT_SURFACE__"), KswordTheme::ControlInputSurfaceColor().name());
        baseControlStyle.replace(QStringLiteral("__INPUT_HOVER__"), KswordTheme::ControlInputHoverColor().name());
        baseControlStyle.replace(QStringLiteral("__INPUT_FOCUS__"), KswordTheme::ControlInputFocusColor().name());
        const QColor inputBackgrounds[] = {KswordTheme::ControlInputSurfaceColor(),
            KswordTheme::ControlInputHoverColor(), KswordTheme::ControlInputFocusColor()};
        baseControlStyle.replace(QStringLiteral("__INPUT_PLACEHOLDER__"),
            KswordTheme::EnsureTextContrastForBackgrounds(
                KswordTheme::TextSecondaryColor(), inputBackgrounds, 3).name());
        baseControlStyle.replace(QStringLiteral("__BORDER_STRONG__"), KswordTheme::BorderStrongColorHex());
        baseControlStyle.replace(QStringLiteral("__BORDER__"), KswordTheme::BorderColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_SECONDARY__"), KswordTheme::TextSecondaryColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT_DISABLED__"), KswordTheme::TextDisabledColorHex());
        baseControlStyle.replace(QStringLiteral("__TEXT__"), KswordTheme::TextPrimaryColorHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT_PRESSED__"), KswordTheme::ControlAccentPressedHex());
        baseControlStyle.replace(QStringLiteral("__ACCENT__"), KswordTheme::ControlAccentHex());
        baseControlStyle.replace(
            QStringLiteral("__ON_ACCENT__"),
            KswordTheme::ThemeColorName(
                KswordTheme::OnAccentColor(KswordTheme::ControlAccentColor())));
        baseControlStyle.replace(
            QStringLiteral("__ON_ACCENT_PRESSED__"),
            KswordTheme::OnAccentHex(KswordTheme::ControlAccentPressedColor()));
        // 默认控件仅获得按钮状态基线；业务本地几何与语义色仍由逐页接入负责。
        return baseControlStyle + BuildFlatButtonStyle(FlatButtonTone::Neutral);
    }
}
