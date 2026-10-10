#include "KernelDock.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/VisibleTableWidget.h"

#include "KernelDock.CallbackIntercept.h"
#include "KernelDock.CallbackPromptManager.h"
#include "../SettingsDock/AppearanceSettings.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHash>
#include <QIcon>
#include <QMenu>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QClipboard>
#include <QIODevice>
#include <QPlainTextEdit>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSize>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QStyledItemDelegate>
#include <QStyle>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QTimeZone>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>
#include <QVector>

#include <Windows.h>
#include <sddl.h>

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class GroupColumn : int
    {
        Id = 0,
        Name,
        Enabled,
        Priority,
        Comment,
        Count
    };

    enum class RuleColumn : int
    {
        Enabled,
        RuleId,
        GroupId,
        RuleName,
        OperationMask,
        MatchMode,
        Action,
        TimeoutMs,
        TimeoutDefaultDecision,
        Priority,
        Count
    };

    enum class FileMonitorColumn : int
    {
        Time = 0,
        Pid,
        Process,
        Path,
        FsctlName,
        ControlCode,
        Status,
        FileObject,
        InputLength,
        OutputLength,
        Count
    };

    enum class MinifilterBypassPidColumn : int
    {
        Pid = 0,
        Process,
        Count
    };

    enum class ProcessProtectRuleColumn : int
    {
        Enabled = 0,
        Kind,
        Target,
        AccessMask,
        ProtectThreads,
        KernelProtection,
        Guard,
        RuleName,
        HitCount,
        KernelApplyCount,
        Count
    };

    enum class ProcessProtectTrustedColumn : int
    {
        Kind = 0,
        Target,
        Count
    };

    // callbackBackgroundImageReady 作用：
    // - 输入 rawImagePath：外观设置中的背景图路径，可为绝对路径或相对 exe 目录路径；
    // - 处理：只判断文件是否存在，不加载图片，避免样式判断带来额外开销；
    // - 返回：背景图可用返回 true，否则返回 false。
    bool callbackBackgroundImageReady(const QString& rawImagePath)
    {
        const QString trimmedPath = rawImagePath.trimmed();
        if (trimmedPath.isEmpty())
        {
            return false;
        }

        const QString resolvedPath = QDir::isAbsolutePath(trimmedPath)
            ? QDir::cleanPath(trimmedPath)
            : QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(trimmedPath);
        const QFileInfo imageFileInfo(QDir::cleanPath(resolvedPath));
        return imageFileInfo.exists() && imageFileInfo.isFile();
    }

    // callbackAllowWallpaperThroughControls 作用：
    // - 输入：无，读取当前外观配置；
    // - 处理：用于驱动回调 Tab 判断局部表格/面板是否应透明；
    // - 返回：true 表示应透出后方内容，局部容器应尽量透明。
    //
    // 两个条件必须都算，与 MainWindow::shouldRenderTransparentDockContent() 保持同一口径：
    // 只看背景图存不存在，会把「开了透明窗口背景但没设背景图」这个常见配置判成不透明，
    // 而控件自身 styleSheet 压过 MainWindow 下发的全局 QSS，错判之后没有任何东西能纠正它。
    // 这正是 issue #161 的成因（另见 KernelDock.cpp 中同一问题的注释）。
    bool callbackAllowWallpaperThroughControls()
    {
        const ks::settings::AppearanceSettings settings = ks::settings::loadAppearanceSettings();
        return callbackBackgroundImageReady(settings.backgroundImagePath)
            || settings.backgroundTransparencyEnabled;
    }

    class OpaqueTableEditorDelegate final : public QStyledItemDelegate
    {
    public:
        explicit OpaqueTableEditorDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , m_tableView(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool rowSelected = (itemOption.state & QStyle::State_Selected) != 0;
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, itemOption, index);
            if (rowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

        QWidget* createEditor(
            QWidget* parent,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const override
        {
            QWidget* editor = QStyledItemDelegate::createEditor(parent, option, index);
            auto* lineEdit = qobject_cast<QLineEdit*>(editor);
            if (lineEdit != nullptr)
            {
                lineEdit->setAutoFillBackground(true);
                lineEdit->setFrame(true);
                lineEdit->setStyleSheet(
                    QStringLiteral(
                        "QLineEdit{"
                        "  background:%1;"
                        "  color:%2;"
                        "  border:1px solid %3;"
                        "  border-radius:2px;"
                        "  padding:0px 4px;"
                        "}")
                    .arg(KswordTheme::SurfaceHex())
                    .arg(KswordTheme::TextPrimaryHex())
                    .arg(KswordTheme::BorderHex()));
            }
            return editor;
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || m_tableView == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = m_tableView->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int columnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
            {
                if (m_tableView->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int visualIndex = headerView->visualIndex(columnIndex);
                if (visualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, visualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, visualIndex);
            }

            const int currentVisualIndex = headerView->visualIndex(index.column());
            if (currentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect borderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!borderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(KswordTheme::PrimaryBlueColor, 3.0));
            painter->drawLine(borderRect.topLeft(), borderRect.topRight());
            painter->drawLine(borderRect.bottomLeft(), borderRect.bottomRight());
            if (currentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topLeft(), borderRect.bottomLeft());
            }
            if (currentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topRight(), borderRect.bottomRight());
            }
            painter->restore();
        }

        QPointer<QTableView> m_tableView;
    };

    quint32 defaultOperationMaskByType(const quint32 callbackType)
    {
        // 作用：为新增规则提供默认操作掩码，只包含当前 UI 暴露的基础操作位。
        // 返回：协议层 operationMask，后续仍可通过“自定义掩码”补充额外位。
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return KSWORD_ARK_REG_OP_CREATE_KEY |
                KSWORD_ARK_REG_OP_OPEN_KEY |
                KSWORD_ARK_REG_OP_DELETE_KEY |
                KSWORD_ARK_REG_OP_SET_VALUE |
                KSWORD_ARK_REG_OP_DELETE_VALUE |
                KSWORD_ARK_REG_OP_RENAME_KEY |
                KSWORD_ARK_REG_OP_SET_INFO |
                KSWORD_ARK_REG_OP_QUERY_VALUE;
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE: return KSWORD_ARK_PROCESS_OP_CREATE;
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE: return KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT;
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD: return KSWORD_ARK_IMAGE_OP_LOAD;
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return KSWORD_ARK_OBJECT_OP_HANDLE_CREATE |
                KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE |
                KSWORD_ARK_OBJECT_OP_TYPE_PROCESS |
                KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return KSWORD_ARK_MINIFILTER_OP_ALL;
        default:
            return 0U;
        }
    }

    QList<QPair<QString, quint32>> allowedActionListByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.ask_user", QStringLiteral("询问用户")), KSWORD_ARK_RULE_ACTION_ASK_USER },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return {
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.strip_access", QStringLiteral("降权拦截")), KSWORD_ARK_RULE_ACTION_STRIP_ACCESS },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return {
                { kernelText("kernel.callback.intercept.action.allow", QStringLiteral("允许")), KSWORD_ARK_RULE_ACTION_ALLOW },
                { kernelText("kernel.callback.intercept.action.deny", QStringLiteral("拒绝")), KSWORD_ARK_RULE_ACTION_DENY },
                { kernelText("kernel.callback.intercept.action.ask_user", QStringLiteral("询问用户")), KSWORD_ARK_RULE_ACTION_ASK_USER },
                { kernelText("kernel.callback.intercept.action.log_only", QStringLiteral("记录日志")), KSWORD_ARK_RULE_ACTION_LOG_ONLY }
            };
        default:
            return {};
        }
    }

    QList<QPair<QString, quint32>> allowedMatchModeListByType(const quint32 callbackType)
    {
        // 注册表和文件系统微过滤器都支持 ASK_USER 前置的 Regex 规则。
        // 这里必须与 R0 blob 校验保持一致，否则 UI 无法选择已支持的匹配模式。
        if (callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
            callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER)
        {
            return {
                { kernelText("kernel.callback.intercept.match.exact", QStringLiteral("精确匹配")), KSWORD_ARK_MATCH_MODE_EXACT },
                { kernelText("kernel.callback.intercept.match.prefix", QStringLiteral("前缀匹配")), KSWORD_ARK_MATCH_MODE_PREFIX },
                { kernelText("kernel.callback.intercept.match.wildcard", QStringLiteral("通配符匹配")), KSWORD_ARK_MATCH_MODE_WILDCARD },
                { kernelText("kernel.callback.intercept.match.regex", QStringLiteral("正则匹配")), KSWORD_ARK_MATCH_MODE_REGEX }
            };
        }

        return {
            { kernelText("kernel.callback.intercept.match.exact", QStringLiteral("精确匹配")), KSWORD_ARK_MATCH_MODE_EXACT },
            { kernelText("kernel.callback.intercept.match.prefix", QStringLiteral("前缀匹配")), KSWORD_ARK_MATCH_MODE_PREFIX },
            { kernelText("kernel.callback.intercept.match.wildcard", QStringLiteral("通配符匹配")), KSWORD_ARK_MATCH_MODE_WILDCARD }
        };
    }

    bool hasActiveMinifilterRule(const CallbackConfigDocument& configDocument)
    {
        // 作用：判断应用后的配置中是否存在真正会进入 R0 快路径的 Minifilter 规则。
        // 返回：存在“规则启用 + 规则组启用”的文件系统微过滤器规则时返回 true。
        QHash<quint32, bool> groupEnabledById;
        for (const CallbackRuleGroupModel& groupModel : configDocument.groups)
        {
            groupEnabledById.insert(groupModel.groupId, groupModel.enabled);
        }

        for (const CallbackRuleModel& ruleModel : configDocument.rules)
        {
            if (!ruleModel.enabled)
            {
                continue;
            }
            if (ruleModel.callbackType != KSWORD_ARK_CALLBACK_TYPE_MINIFILTER)
            {
                continue;
            }
            if (!groupEnabledById.value(ruleModel.groupId, false))
            {
                continue;
            }
            return true;
        }
        return false;
    }

    QString formatCallbackNtStatusHex(const long statusValue)
    {
        // 作用：将 R0 返回的 NTSTATUS 统一格式化为 8 位十六进制。
        // 返回：形如 0xC0000184 的字符串，便于和驱动日志、WinDbg 常量对齐。
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    QList<QPair<QString, quint32>> decisionOptionList()
    {
        return {
            { kernelText("kernel.callback.intercept.decision.allow", QStringLiteral("允许")), KSWORD_ARK_DECISION_ALLOW },
            { kernelText("kernel.callback.intercept.decision.deny", QStringLiteral("拒绝")), KSWORD_ARK_DECISION_DENY }
        };
    }

    bool containsOptionValue(
        const QList<QPair<QString, quint32>>& optionList,
        const quint32 valueToFind)
    {
        for (const QPair<QString, quint32>& optionPair : optionList)
        {
            if (optionPair.second == valueToFind)
            {
                return true;
            }
        }
        return false;
    }

    bool parseUnsignedText(const QString& rawText, quint32* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        QString textValue = rawText.trimmed();
        int base = 10;
        if (textValue.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            textValue = textValue.mid(2);
            base = 16;
        }

        bool convertOk = false;
        const qulonglong parsedValue = textValue.toULongLong(&convertOk, base);
        if (!convertOk || parsedValue > std::numeric_limits<quint32>::max())
        {
            return false;
        }

        *valueOut = static_cast<quint32>(parsedValue);
        return true;
    }

    QString operationMaskToText(const quint32 operationMask)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(operationMask), 8, 16, QChar('0'))
            .toUpper();
    }

    QList<QPair<QString, quint32>> operationCheckboxListByType(const quint32 callbackType)
    {
        // 作用：把原来的“操作类型下拉预设”拆成可直接勾选的基础位。
        // 入参 callbackType：当前回调 Tab 类型；返回值：显示名称与协议掩码位。
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return {
                { kernelText("kernel.callback.intercept.operation.registry.create_key", QStringLiteral("创建键")), KSWORD_ARK_REG_OP_CREATE_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.open_key", QStringLiteral("打开键")), KSWORD_ARK_REG_OP_OPEN_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.delete_key", QStringLiteral("删除键")), KSWORD_ARK_REG_OP_DELETE_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.set_value", QStringLiteral("写入值")), KSWORD_ARK_REG_OP_SET_VALUE },
                { kernelText("kernel.callback.intercept.operation.registry.delete_value", QStringLiteral("删除值")), KSWORD_ARK_REG_OP_DELETE_VALUE },
                { kernelText("kernel.callback.intercept.operation.registry.rename_key", QStringLiteral("重命名键")), KSWORD_ARK_REG_OP_RENAME_KEY },
                { kernelText("kernel.callback.intercept.operation.registry.set_info", QStringLiteral("设置键信息")), KSWORD_ARK_REG_OP_SET_INFO },
                { kernelText("kernel.callback.intercept.operation.registry.query_value", QStringLiteral("查询值")), KSWORD_ARK_REG_OP_QUERY_VALUE }
            };

        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return {
                { kernelText("kernel.callback.intercept.operation.process.create", QStringLiteral("进程创建")), KSWORD_ARK_PROCESS_OP_CREATE }
            };

        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return {
                { kernelText("kernel.callback.intercept.operation.thread.create", QStringLiteral("线程创建")), KSWORD_ARK_THREAD_OP_CREATE },
                { kernelText("kernel.callback.intercept.operation.thread.exit", QStringLiteral("线程退出")), KSWORD_ARK_THREAD_OP_EXIT }
            };

        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return {
                { kernelText("kernel.callback.intercept.operation.image.load", QStringLiteral("镜像加载")), KSWORD_ARK_IMAGE_OP_LOAD }
            };

        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return {
                { kernelText("kernel.callback.intercept.operation.object.handle_create", QStringLiteral("句柄创建")), KSWORD_ARK_OBJECT_OP_HANDLE_CREATE },
                { kernelText("kernel.callback.intercept.operation.object.handle_duplicate", QStringLiteral("句柄复制")), KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE },
                { kernelText("kernel.callback.intercept.operation.object.process", QStringLiteral("进程对象")), KSWORD_ARK_OBJECT_OP_TYPE_PROCESS },
                { kernelText("kernel.callback.intercept.operation.object.thread", QStringLiteral("线程对象")), KSWORD_ARK_OBJECT_OP_TYPE_THREAD }
            };
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return {
                { kernelText("kernel.callback.intercept.operation.minifilter.create", QStringLiteral("创建/打开")), KSWORD_ARK_MINIFILTER_OP_CREATE },
                { kernelText("kernel.callback.intercept.operation.minifilter.read", QStringLiteral("读取")), KSWORD_ARK_MINIFILTER_OP_READ },
                { kernelText("kernel.callback.intercept.operation.minifilter.write", QStringLiteral("写入")), KSWORD_ARK_MINIFILTER_OP_WRITE },
                { kernelText("kernel.callback.intercept.operation.minifilter.set_info", QStringLiteral("设置信息")), KSWORD_ARK_MINIFILTER_OP_SETINFO },
                { kernelText("kernel.callback.intercept.operation.minifilter.rename", QStringLiteral("重命名/硬链")), KSWORD_ARK_MINIFILTER_OP_RENAME },
                { kernelText("kernel.callback.intercept.operation.minifilter.delete", QStringLiteral("删除")), KSWORD_ARK_MINIFILTER_OP_DELETE },
                { kernelText("kernel.callback.intercept.operation.minifilter.cleanup", QStringLiteral("清理")), KSWORD_ARK_MINIFILTER_OP_CLEANUP },
                { kernelText("kernel.callback.intercept.operation.minifilter.close", QStringLiteral("关闭")), KSWORD_ARK_MINIFILTER_OP_CLOSE }
            };

        default:
            return {};
        }
    }

    QString normalizeMaskTextForEdit(const QString& rawText)
    {
        // 作用：规范用户输入的自定义掩码，缺少 0x 前缀时自动补齐。
        // 入参 rawText：用户原始输入；返回值：空文本或大写 0x 十六进制文本。
        QString textValue = rawText.trimmed();
        if (textValue.isEmpty())
        {
            return QString();
        }

        if (!textValue.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            textValue.prepend(QStringLiteral("0x"));
        }

        return textValue.left(2).toLower() + textValue.mid(2).toUpper();
    }

    QString callbackRulePanelStyle()
    {
        // 作用：提供自定义单元格面板样式；背景图模式下透明，普通主题下保持实底。
        // 返回：Qt stylesheet 字符串，供第一排操作复选区和第二排详情区复用。
        const QString panelBackground = callbackAllowWallpaperThroughControls()
            ? QStringLiteral("transparent")
            : KswordTheme::SurfaceHex();
        return QStringLiteral(
            "QWidget#ksCallbackRuleOperationPanel,"
            "QWidget#ksCallbackRuleDetailPanel{"
            "  background:%1;"
            "  background-color:%1;"
            "  color:%2;"
            "}"
            "QWidget#ksCallbackRuleOperationPanel QCheckBox,"
            "QWidget#ksCallbackRuleDetailPanel QLabel{"
            "  color:%2;"
            "}"
            "QLabel#ksCallbackRuleFieldTitle{"
            "  color:%3;"
            "  font-weight:600;"
            "}")
            .arg(panelBackground)
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    QString callbackRuleTableStyle()
    {
        // 作用：统一回调规则表格的背景、表头、选中态和网格颜色。
        // 返回：Qt stylesheet 字符串，所有回调类型 Tab 共享。
        const bool allowWallpaperThrough = callbackAllowWallpaperThroughControls();
        const QString tableBackground = allowWallpaperThrough
            ? QStringLiteral("transparent")
            : KswordTheme::SurfaceHex();
        const QString alternateBackground = allowWallpaperThrough
            ? QStringLiteral("transparent")
            : KswordTheme::SurfaceAltHex();
        return QStringLiteral(
            "QTableWidget{"
            "  background:%1;"
            "  background-color:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "  gridline-color:%4;"
            "}"
            "QTableWidget::viewport{"
            "  background:%1;"
            "  background-color:%1;"
            "}"
            "QHeaderView::section{"
            "  background:transparent; /* %2 */"
            "  color:%5;"
            "  border:1px solid %4;"
            "  padding:3px 6px;"
            "  font-weight:600;"
            "}")
            .arg(tableBackground)
            .arg(alternateBackground)
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    QString callbackRuleContextMenuStyle()
    {
        // 作用：右键菜单强制使用不透明背景，避免浅色模式继承黑底黑字。
        // 返回：Qt stylesheet 字符串，仅用于驱动回调规则表菜单。
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  background:transparent;"
            "  color:%2;"
            "  padding:5px 26px 5px 26px;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:palette(highlighted-text);"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:4px 8px;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::TextDisabledColorHex());
    }

    // callbackRuleIoMessageText：
    // - 输入：ArkDriverClient 返回的原始 IO/状态 message；
    // - 处理：识别 DeviceIoControl/unsupported/capability/buffer/version 等底层词汇；
    // - 返回：回调拦截页日志、状态栏和详情框可直接展示的人读说明。
    QString callbackRuleIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return kernelText("kernel.callback.intercept.message.no_driver_details", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.intercept.message.io_failure", QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。"));
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.intercept.message.unsupported", QStringLiteral("当前驱动暂不支持该回调/文件监控接口。"));
        }
        if (lowerText.contains(QStringLiteral("capability")) ||
            lowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.intercept.message.capability", QStringLiteral("动态偏移能力未满足，相关回调或文件监控字段暂不可用。"));
        }
        if (lowerText.contains(QStringLiteral("version mismatch")) ||
            lowerText.contains(QStringLiteral("protocol")))
        {
            return kernelText("kernel.callback.intercept.message.protocol", QStringLiteral("R3/R0 协议版本不匹配，请同步 shared 协议与驱动。"));
        }
        if (lowerText.contains(QStringLiteral("buffer")) &&
            (lowerText.contains(QStringLiteral("small")) || lowerText.contains(QStringLiteral("trunc"))))
        {
            return kernelText("kernel.callback.intercept.message.buffer_short", QStringLiteral("驱动返回缓冲区不足，当前结果可能被截断。"));
        }
        return trimmedText;
    }

    void installCallbackTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installCallbackTableCopyMenu：
        // - 输入：回调拦截页内需要复制证据行的表格；
        // - 处理：右键选中当前行，并把所有列按 TSV 写入剪贴板；
        // - 返回：无。只读复制，不修改规则、驱动状态或监控状态。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const auto clickedIndex = tableWidget->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu contextMenu(tableWidget);
            contextMenu.setStyleSheet(callbackRuleContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.callback.intercept.menu.copy_current_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            const QTableWidgetItem* processIdItem =
                processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() && tableWidget->currentRow() >= 0
                ? tableWidget->item(tableWidget->currentRow(), processIdColumn)
                : nullptr;
            bool processIdOk = false;
            const quint32 processId = processIdItem != nullptr
                ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && processId != 0U);
            }

            QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int rowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList rowFields;
            rowFields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                rowFields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
        });
    }

    // applyCallbackTableTransparency 作用：
    // - 输入 tableWidget：驱动回调 Tab 内的表格；
    // - 处理：背景图模式下关闭表格和 viewport 的自动填充，确保背景图能透过表格空白区；
    // - 返回：无返回值。
    void applyCallbackTableTransparency(QTableWidget* tableWidget)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        const bool allowWallpaperThrough = callbackAllowWallpaperThroughControls();
        tableWidget->setAutoFillBackground(!allowWallpaperThrough);
        tableWidget->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThrough);
        tableWidget->viewport()->setAutoFillBackground(!allowWallpaperThrough);
        tableWidget->viewport()->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThrough);
        if (allowWallpaperThrough)
        {
            tableWidget->setAlternatingRowColors(false);
        }
    }

    QString normalizeCustomMaskEditText(QLineEdit* maskEdit)
    {
        // 作用：在用户离开自定义掩码输入框时补齐 0x 前缀，并同步规范显示。
        // 入参 maskEdit：自定义掩码输入框；返回：规范后的文本，空指针时返回空串。
        if (maskEdit == nullptr)
        {
            return QString();
        }

        const QString normalizedText = normalizeMaskTextForEdit(maskEdit->text());
        if (normalizedText != maskEdit->text())
        {
            maskEdit->setText(normalizedText);
        }
        return normalizedText;
    }

    QString initiatorPlaceholderByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return kernelText("kernel.callback.intercept.placeholder.initiator.registry", QStringLiteral("例如：* 或 C:\\Windows\\System32\\reg.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.initiator.process", QStringLiteral("例如：* 或 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.initiator.thread", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return kernelText("kernel.callback.intercept.placeholder.initiator.image", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return kernelText("kernel.callback.intercept.placeholder.initiator.object", QStringLiteral("例如：* 或 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return kernelText("kernel.callback.intercept.placeholder.initiator.minifilter", QStringLiteral("例如：* 或 C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        default:
            return kernelText("kernel.callback.intercept.placeholder.initiator.default", QStringLiteral("例如：*"));
        }
    }

    QString targetPlaceholderByType(const quint32 callbackType)
    {
        switch (callbackType)
        {
        case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
            return kernelText("kernel.callback.intercept.placeholder.target.registry", QStringLiteral("例如：HKCU\\Software\\KswordDemo 或 \\REGISTRY\\USER\\*\\Software\\KswordDemo"));
        case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.target.process", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
            return kernelText("kernel.callback.intercept.placeholder.target.thread", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（目标进程镜像，支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
            return kernelText("kernel.callback.intercept.placeholder.target.image", QStringLiteral("例如：C:\\Windows\\System32\\kernel32.dll（支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
            return kernelText("kernel.callback.intercept.placeholder.target.object", QStringLiteral("例如：C:\\Windows\\System32\\notepad.exe（被打开句柄的目标进程，支持自动转换）"));
        case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
            return kernelText("kernel.callback.intercept.placeholder.target.minifilter", QStringLiteral("例如：C:\\Users\\*\\Documents\\*.docx 或 \\Device\\HarddiskVolume*\\*.sys"));
        default:
            return kernelText("kernel.callback.intercept.placeholder.target.default", QStringLiteral("例如：*"));
        }
    }

    quint32 currentOperationMaskFromPanel(const QWidget* operationPanel, bool* okOut)
    {
        // 作用：从“操作类型”复选区和自定义掩码输入框合成最终 operationMask。
        // 入参 operationPanel：表格第一排操作单元格控件；okOut：返回解析状态。
        if (okOut != nullptr)
        {
            *okOut = false;
        }
        if (operationPanel == nullptr)
        {
            return 0U;
        }

        quint32 operationMask = 0U;
        const QList<QCheckBox*> checkBoxList = operationPanel->findChildren<QCheckBox*>(
            QString(),
            Qt::FindDirectChildrenOnly);
        for (const QCheckBox* checkBox : checkBoxList)
        {
            if (checkBox == nullptr || !checkBox->isChecked())
            {
                continue;
            }

            bool bitOk = false;
            const quint32 bitValue = checkBox->property("operationMaskBit").toUInt(&bitOk);
            if (bitOk)
            {
                operationMask |= bitValue;
            }
        }

        const auto* customMaskEdit = operationPanel->findChild<QLineEdit*>(
            QStringLiteral("ksCallbackRuleCustomMaskEdit"),
            Qt::FindDirectChildrenOnly);
        if (customMaskEdit != nullptr)
        {
            const QString maskText = customMaskEdit->text().trimmed();
            if (!maskText.isEmpty())
            {
                quint32 customMask = 0U;
                if (!parseUnsignedText(normalizeMaskTextForEdit(maskText), &customMask))
                {
                    return 0U;
                }
                operationMask |= customMask;
            }
        }

        if (okOut != nullptr)
        {
            *okOut = true;
        }
        return operationMask;
    }

    QString normalizeMatchAllPattern(const QString& rawPatternText)
    {
        const QString trimmedText = rawPatternText.trimmed();
        if (trimmedText == QStringLiteral("*") || trimmedText == QStringLiteral("**"))
        {
            return QString();
        }
        return rawPatternText;
    }

    QString normalizeUserModeFilePathPatternForKernel(const QString& rawPatternText)
    {
        QString pathPattern = rawPatternText.trimmed();
        if (pathPattern.isEmpty())
        {
            return pathPattern;
        }

        pathPattern.replace('/', '\\');

        auto startsWithInsensitive = [](const QString& textValue, const QString& prefixText) -> bool
            {
                return textValue.startsWith(prefixText, Qt::CaseInsensitive);
            };

        // 已是内核常见路径格式则直接透传。
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\Device\\")) ||
            startsWithInsensitive(pathPattern, QStringLiteral("\\REGISTRY\\")) ||
            startsWithInsensitive(pathPattern, QStringLiteral("\\??\\")))
        {
            return pathPattern;
        }

        // 兼容 "\\??\\C:\..." 这种多一个反斜杠的写法。
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\??\\")))
        {
            pathPattern.remove(0, 1);
            return pathPattern;
        }

        // 兼容 Win32 扩展前缀 "\\?\C:\..." / "\\?\UNC\server\share\..."
        if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\?\\UNC\\")))
        {
            pathPattern = QStringLiteral("\\\\") + pathPattern.mid(8);
        }
        else if (startsWithInsensitive(pathPattern, QStringLiteral("\\\\?\\")))
        {
            pathPattern = pathPattern.mid(4);
        }

        // UNC 路径转换：\\server\share\foo -> \Device\Mup\server\share\foo
        if (pathPattern.startsWith(QStringLiteral("\\\\")))
        {
            QString uncRest = pathPattern.mid(2);
            while (uncRest.startsWith('\\'))
            {
                uncRest.remove(0, 1);
            }
            if (uncRest.isEmpty())
            {
                return QStringLiteral("\\Device\\Mup");
            }
            return QStringLiteral("\\Device\\Mup\\%1").arg(uncRest);
        }

        // 盘符路径转换：C:\foo -> \Device\HarddiskVolumeX\foo（优先），失败回退 \??\C:\foo。
        if (pathPattern.size() >= 2 &&
            pathPattern[0].isLetter() &&
            pathPattern[1] == QLatin1Char(':'))
        {
            const QString driveText = pathPattern.left(2).toUpper();
            wchar_t targetBuffer[1024] = {};
            const DWORD queryChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(driveText.utf16()),
                targetBuffer,
                static_cast<DWORD>(sizeof(targetBuffer) / sizeof(targetBuffer[0])));

            QString restPath = pathPattern.mid(2);
            while (restPath.startsWith('\\'))
            {
                restPath.remove(0, 1);
            }

            if (queryChars > 0U && targetBuffer[0] != L'\0')
            {
                const QString ntDevicePrefix = QString::fromWCharArray(targetBuffer);
                if (!ntDevicePrefix.trimmed().isEmpty())
                {
                    return restPath.isEmpty()
                        ? ntDevicePrefix
                        : QStringLiteral("%1\\%2").arg(ntDevicePrefix, restPath);
                }
            }

            return QStringLiteral("\\??\\%1").arg(pathPattern);
        }

        return pathPattern;
    }

    QString normalizeRegistryTargetPatternForKernel(const QString& rawTargetPattern)
    {
        // 输入：用户在注册表规则“目标程序/路径”里输入的 Win32 注册表路径或内核路径。
        // 处理：剥离 regedit 地址栏常见的“计算机\”显示根，并把 HK* 根别名转换为
        //       Cm callback 实际用于匹配的 \REGISTRY\... 对象名。
        // 返回：可直接下发给 R0 规则引擎的匹配 pattern；无法识别时保留用户原文。
        QString targetPattern = rawTargetPattern.trimmed();
        if (targetPattern.isEmpty())
        {
            return targetPattern;
        }

        targetPattern.replace('/', '\\');

        auto stripDisplayComputerRoot = [&targetPattern](const QString& displayRootText) {
            // 输入：regedit 地址栏展示层根名，例如“计算机”或英文系统上的“Computer”。
            // 处理：仅当根名后面确实跟路径分隔符时剥离，避免误伤普通键名。
            // 返回：无；通过捕获的 targetPattern 原地更新。
            if (targetPattern.compare(displayRootText, Qt::CaseInsensitive) == 0)
            {
                targetPattern.clear();
                return;
            }
            const QString rootPrefix = QStringLiteral("%1\\").arg(displayRootText);
            if (targetPattern.startsWith(rootPrefix, Qt::CaseInsensitive))
            {
                targetPattern.remove(0, rootPrefix.size());
            }
        };

        auto trimLeadingSlash = [](QString* textValue) {
            if (textValue == nullptr)
            {
                return;
            }
            while (textValue->startsWith('\\'))
            {
                textValue->remove(0, 1);
            }
        };

        auto queryDwordRegistryValue = [](
            const HKEY rootKey,
            const QString& subKeyText,
            const QString& valueNameText,
            DWORD* valueOut) -> bool {
            // 输入：注册表根、子键和值名。
            // 处理：用 Win32 API 读取 REG_DWORD，用于把 HKCC 的两个别名层解析成
            //       Cm callback 已确认会返回的真实 ControlSet/Profile 对象名。
            // 返回：读取到 DWORD 时返回 true；失败时返回 false，调用方使用兼容回退。
            HKEY keyHandle = nullptr;
            DWORD valueType = 0U;
            DWORD valueData = 0U;
            DWORD valueBytes = sizeof(valueData);

            if (valueOut == nullptr)
            {
                return false;
            }
            *valueOut = 0U;

            if (::RegOpenKeyExW(
                rootKey,
                reinterpret_cast<LPCWSTR>(subKeyText.utf16()),
                0U,
                KEY_QUERY_VALUE,
                &keyHandle) != ERROR_SUCCESS)
            {
                return false;
            }

            const LONG queryStatus = ::RegQueryValueExW(
                keyHandle,
                reinterpret_cast<LPCWSTR>(valueNameText.utf16()),
                nullptr,
                &valueType,
                reinterpret_cast<LPBYTE>(&valueData),
                &valueBytes);
            ::RegCloseKey(keyHandle);

            if (queryStatus != ERROR_SUCCESS ||
                valueType != REG_DWORD ||
                valueBytes != sizeof(valueData) ||
                valueData == 0U)
            {
                return false;
            }

            *valueOut = valueData;
            return true;
        };

        auto currentConfigRegistryRoot = [&queryDwordRegistryValue]() -> QString {
            // 输入：无；读取本机 HKLM\SYSTEM\Select\Current 和
            //       HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\CurrentConfig。
            // 处理：把 HKCC/HKEY_CURRENT_CONFIG 解析成注册表回调实际观察到的
            //       \REGISTRY\MACHINE\SYSTEM\ControlSet00X\Hardware Profiles\000Y。
            // 返回：成功时返回真实 HKCC 内核根；读取失败时回退到历史别名路径。
            DWORD controlSetIndex = 0U;
            DWORD hardwareProfileIndex = 0U;

            if (!queryDwordRegistryValue(
                HKEY_LOCAL_MACHINE,
                QStringLiteral("SYSTEM\\Select"),
                QStringLiteral("Current"),
                &controlSetIndex))
            {
                return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");
            }

            if (!queryDwordRegistryValue(
                HKEY_LOCAL_MACHINE,
                QStringLiteral("SYSTEM\\CurrentControlSet\\Control\\IDConfigDB"),
                QStringLiteral("CurrentConfig"),
                &hardwareProfileIndex))
            {
                return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet%1\\Hardware Profiles\\Current")
                    .arg(controlSetIndex, 3, 10, QChar('0'));
            }

            return QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet%1\\Hardware Profiles\\%2")
                .arg(controlSetIndex, 3, 10, QChar('0'))
                .arg(hardwareProfileIndex, 4, 10, QChar('0'));
        };

        auto restPathAfterRoot = [&](const QString& rootText) {
            QString restText = targetPattern.mid(rootText.size());
            trimLeadingSlash(&restText);
            return restText;
        };

        auto buildWithRoot = [](const QString& kernelRootText, const QString& restText) {
            if (restText.trimmed().isEmpty())
            {
                return kernelRootText;
            }
            return QStringLiteral("%1\\%2").arg(kernelRootText, restText);
        };

        auto currentUserSidText = []() -> QString {
            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                return QString();
            }

            DWORD tokenBytes = 0;
            (void)::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenBytes);
            if (tokenBytes == 0U)
            {
                ::CloseHandle(tokenHandle);
                return QString();
            }

            QByteArray tokenBuffer(static_cast<int>(tokenBytes), 0);
            if (::GetTokenInformation(tokenHandle, TokenUser, tokenBuffer.data(), tokenBytes, &tokenBytes) == FALSE)
            {
                ::CloseHandle(tokenHandle);
                return QString();
            }
            ::CloseHandle(tokenHandle);

            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
            if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
            {
                return QString();
            }

            LPWSTR sidWideText = nullptr;
            if (::ConvertSidToStringSidW(tokenUser->User.Sid, &sidWideText) == FALSE || sidWideText == nullptr)
            {
                return QString();
            }

            const QString sidText = QString::fromWCharArray(sidWideText);
            ::LocalFree(sidWideText);
            return sidText;
        };

        stripDisplayComputerRoot(QStringLiteral("计算机"));
        stripDisplayComputerRoot(QStringLiteral("Computer"));
        if (targetPattern.isEmpty())
        {
            return targetPattern;
        }

        if (targetPattern.startsWith(QStringLiteral("\\REGISTRY\\"), Qt::CaseInsensitive) ||
            targetPattern.compare(QStringLiteral("\\REGISTRY"), Qt::CaseInsensitive) == 0)
        {
            return targetPattern;
        }

        if (targetPattern.startsWith(QStringLiteral("HKLM"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKLM")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_LOCAL_MACHINE"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKEY_LOCAL_MACHINE")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKU"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKU")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_USERS"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKEY_USERS")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCR"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKCR")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKEY_CLASSES_ROOT")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCC"), Qt::CaseInsensitive))
        {
            return buildWithRoot(currentConfigRegistryRoot(), restPathAfterRoot(QStringLiteral("HKCC")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CURRENT_CONFIG"), Qt::CaseInsensitive))
        {
            return buildWithRoot(currentConfigRegistryRoot(), restPathAfterRoot(QStringLiteral("HKEY_CURRENT_CONFIG")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive))
        {
            const QString sidText = currentUserSidText();
            const QString rootText = sidText.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER\\*")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(sidText);
            return buildWithRoot(rootText, restPathAfterRoot(QStringLiteral("HKCU")));
        }
        if (targetPattern.startsWith(QStringLiteral("HKEY_CURRENT_USER"), Qt::CaseInsensitive))
        {
            const QString sidText = currentUserSidText();
            const QString rootText = sidText.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER\\*")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(sidText);
            return buildWithRoot(rootText, restPathAfterRoot(QStringLiteral("HKEY_CURRENT_USER")));
        }

        return targetPattern;
    }

    QString utc100nsToDisplayText(const quint64 utc100ns)
    {
        if (utc100ns == 0ULL)
        {
            return QStringLiteral("-");
        }

        constexpr qint64 kFileTimeToUnixEpoch100ns = 116444736000000000LL;
        const qint64 value100ns = static_cast<qint64>(utc100ns);
        if (value100ns < kFileTimeToUnixEpoch100ns)
        {
            return QStringLiteral("-");
        }

        const qint64 unixMs = (value100ns - kFileTimeToUnixEpoch100ns) / 10000LL;
        const QDateTime utcDateTime = QDateTime::fromMSecsSinceEpoch(unixMs, QTimeZone::UTC);
        if (!utcDateTime.isValid())
        {
            return QStringLiteral("-");
        }
        return utcDateTime.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QTableWidgetItem* makeReadOnlyItem(const QString& textValue)
    {
        auto* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString formatFileMonitorHex32(const quint32 value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    // processProtectFixedWideToQString：
    // - 输入 textBuffer/maxChars：R0 定长宽字符字段，未必带终止符；
    // - 处理：在容量内查找终止符，越界时按满长度截断；
    // - 返回：安全转换后的 QString。
    QString processProtectFixedWideToQString(const wchar_t* const textBuffer, const std::size_t maxChars)
    {
        if (textBuffer == nullptr || maxChars == 0U)
        {
            return {};
        }
        std::size_t textLength = 0U;
        while (textLength < maxChars && textBuffer[textLength] != L'\0')
        {
            ++textLength;
        }
        return QString::fromWCharArray(textBuffer, static_cast<int>(textLength));
    }

    // processProtectCopyQStringToFixedWide：
    // - 输入 sourceText 与目标定长缓冲；
    // - 处理：按容量截断并强制写入终止符，保证 R0 侧按 NUL 结尾比较不会越界；
    // - 返回：无。
    void processProtectCopyQStringToFixedWide(
        const QString& sourceText,
        wchar_t* const destination,
        const std::size_t maxChars)
    {
        if (destination == nullptr || maxChars == 0U)
        {
            return;
        }
        const int copyChars = std::min<int>(sourceText.size(), static_cast<int>(maxChars) - 1);
        if (copyChars > 0)
        {
            sourceText.left(copyChars).toWCharArray(destination);
        }
        destination[copyChars > 0 ? copyChars : 0] = L'\0';
    }

    QString processProtectKindText(const quint32 targetKind)
    {
        switch (targetKind)
        {
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID:
            return kernelText("kernel.callback.intercept.process_protect.kind.pid", QStringLiteral("PID"));
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME:
            return kernelText("kernel.callback.intercept.process_protect.kind.image_name", QStringLiteral("映像名"));
        case KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH:
            return kernelText("kernel.callback.intercept.process_protect.kind.image_path", QStringLiteral("完整路径"));
        default:
            return kernelText("kernel.callback.intercept.process_protect.kind.unknown", QStringLiteral("未知"));
        }
    }

    // processProtectAccessSummaryText：
    // - 输入 accessMask：KSWORD_ARK_PROCESS_PROTECT_ACCESS_* 组合；
    // - 处理：逐位翻译成人类可读的短标签；
    // - 返回：以 "+" 连接的摘要，空掩码返回占位符。
    // processProtectKernelProtectionText：
    // - 输入 protectionByte：PS_PROTECTION 原始字节，0 表示不施加内核保护；
    // - 处理：拆出 Type/Signer 译成 "PP WinTcb [0x62]" 形式；
    // - 返回：表格与菜单共用的展示文本。
    QString processProtectKernelProtectionText(const quint32 protectionByte)
    {
        if (protectionByte == 0U)
        {
            return kernelText("kernel.callback.intercept.process_protect.kernel.none", QStringLiteral("不施加"));
        }

        const quint32 protectionType = protectionByte & 0x07U;
        const quint32 signerValue = (protectionByte & 0xF0U) >> 4U;
        const QString typeText = (protectionType == KSWORD_PS_PROTECTED_TYPE_FULL)
            ? QStringLiteral("PP")
            : QStringLiteral("PPL");
        static const char* const signerNames[] = {
            "None", "Authenticode", "CodeGen", "Antimalware",
            "Lsa", "Windows", "WinTcb", "WinSystem", "App"
        };
        const QString signerText = (signerValue < (sizeof(signerNames) / sizeof(signerNames[0])))
            ? QString::fromLatin1(signerNames[signerValue])
            : QString::number(signerValue);
        return QStringLiteral("%1 %2 [0x%3]")
            .arg(typeText)
            .arg(signerText)
            .arg(protectionByte, 2, 16, QChar('0'));
    }

    // processProtectGuardSummaryText：
    // - 输入规则 flags 与 hardenFlags；
    // - 处理：把"创建即用/自愈/清调试端口"拼成一列摘要；
    // - 返回：无任何守护动作时给占位符。
    QString processProtectGuardSummaryText(const quint32 ruleFlags, const quint32 hardenFlags)
    {
        QStringList parts;
        if ((ruleFlags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.on_create", QStringLiteral("创建即用"));
        }
        if ((ruleFlags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.self_heal", QStringLiteral("自愈"));
        }
        if ((hardenFlags & KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port", QStringLiteral("清调试端口"));
        }
        if (parts.isEmpty())
        {
            return QStringLiteral("-");
        }
        return parts.join(QStringLiteral(" + "));
    }

    QString processProtectAccessSummaryText(const quint32 accessMask)
    {
        QStringList parts;
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.terminate", QStringLiteral("结束进程"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.vm_read", QStringLiteral("读内存"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.vm_write", QStringLiteral("写内存"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.create_thread", QStringLiteral("远程建线程"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.suspend", QStringLiteral("挂起恢复"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.set_information", QStringLiteral("改属性"));
        }
        if ((accessMask & KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE) != 0U)
        {
            parts << kernelText("kernel.callback.intercept.process_protect.access.dup_handle", QStringLiteral("复制句柄"));
        }
        if (parts.isEmpty())
        {
            return kernelText("kernel.callback.intercept.process_protect.access.none", QStringLiteral("（未选择）"));
        }
        return parts.join(QStringLiteral(" + "));
    }

    QString formatFileMonitorHex64(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper();
    }

    QString fileMonitorFsctlNameText(const quint32 fsControlCode)
    {
        const wchar_t* nameText = KswordARKFileMonitorFsctlCodeToText(fsControlCode);
        return nameText != nullptr
            ? QString::fromWCharArray(nameText)
            : QStringLiteral("UNKNOWN_FSCTL");
    }

    void applyRuleLineEditStyle(QLineEdit* lineEdit)
    {
        if (lineEdit == nullptr)
        {
            return;
        }
        lineEdit->setAutoFillBackground(true);
        lineEdit->setStyleSheet(
            QStringLiteral(
                "QLineEdit{"
                "  background:%1;"
                "  color:%2;"
                "  border:1px solid %3;"
                "  border-radius:2px;"
                "  padding:2px 6px;"
                "}"
                "QLineEdit:focus{"
                "  border:1px solid %4;"
                "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex));
    }

    QString encodeRuleClipboardText(const QString& rawText)
    {
        return QString::fromLatin1(QUrl::toPercentEncoding(rawText));
    }

    QString decodeRuleClipboardText(const QString& encodedText)
    {
        return QUrl::fromPercentEncoding(encodedText.toLatin1());
    }

    QString serializeRuleToClipboardText(const CallbackRuleModel& ruleModel)
    {
        QStringList lineList;
        lineList.push_back(QStringLiteral("KSWORD_CALLBACK_RULE_V1"));
        lineList.push_back(QStringLiteral("enabled=%1").arg(ruleModel.enabled ? 1 : 0));
        lineList.push_back(QStringLiteral("ruleId=%1").arg(ruleModel.ruleId));
        lineList.push_back(QStringLiteral("groupId=%1").arg(ruleModel.groupId));
        lineList.push_back(QStringLiteral("ruleName=%1").arg(encodeRuleClipboardText(ruleModel.ruleName)));
        lineList.push_back(QStringLiteral("callbackType=%1").arg(ruleModel.callbackType));
        lineList.push_back(QStringLiteral("operationMask=%1").arg(operationMaskToText(ruleModel.operationMask)));
        lineList.push_back(QStringLiteral("initiatorPattern=%1").arg(encodeRuleClipboardText(ruleModel.initiatorPattern)));
        lineList.push_back(QStringLiteral("targetPattern=%1").arg(encodeRuleClipboardText(ruleModel.targetPattern)));
        lineList.push_back(QStringLiteral("matchMode=%1").arg(ruleModel.matchMode));
        lineList.push_back(QStringLiteral("action=%1").arg(ruleModel.action));
        lineList.push_back(QStringLiteral("timeoutMs=%1").arg(ruleModel.timeoutMs));
        lineList.push_back(QStringLiteral("timeoutDefaultDecision=%1").arg(ruleModel.timeoutDefaultDecision));
        lineList.push_back(QStringLiteral("priority=%1").arg(ruleModel.priority));
        lineList.push_back(QStringLiteral("comment=%1").arg(encodeRuleClipboardText(ruleModel.comment)));
        return lineList.join(QLatin1Char('\n'));
    }

    bool deserializeRuleFromClipboardText(
        const QString& clipboardText,
        CallbackRuleModel* ruleOut,
        QString* errorTextOut)
    {
        if (ruleOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.rule_out_null", QStringLiteral("解析失败：ruleOut 为空。"));
            }
            return false;
        }

        QString textValue = clipboardText;
        textValue.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        textValue.replace(QStringLiteral("\r"), QStringLiteral("\n"));
        const QStringList rawLineList = textValue.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        if (rawLineList.isEmpty() || rawLineList.front().trimmed() != QStringLiteral("KSWORD_CALLBACK_RULE_V1"))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.unsupported_format", QStringLiteral("解析失败：不是支持的规则文本格式。"));
            }
            return false;
        }

        QHash<QString, QString> valueMap;
        for (int lineIndex = 1; lineIndex < rawLineList.size(); ++lineIndex)
        {
            const QString lineText = rawLineList[lineIndex].trimmed();
            const int separatorIndex = lineText.indexOf('=');
            if (separatorIndex <= 0)
            {
                continue;
            }
            const QString keyText = lineText.left(separatorIndex).trimmed();
            const QString valueTextPart = lineText.mid(separatorIndex + 1);
            valueMap.insert(keyText, valueTextPart);
        }

        CallbackRuleModel parsedRuleModel;
        parsedRuleModel.enabled = (valueMap.value(QStringLiteral("enabled")).trimmed() != QStringLiteral("0"));

        auto parseUIntField = [&](const QString& keyText, quint32* valueOut) -> bool {
            return parseUnsignedText(valueMap.value(keyText).trimmed(), valueOut);
        };

        if (!parseUIntField(QStringLiteral("ruleId"), &parsedRuleModel.ruleId) ||
            !parseUIntField(QStringLiteral("groupId"), &parsedRuleModel.groupId) ||
            !parseUIntField(QStringLiteral("callbackType"), &parsedRuleModel.callbackType) ||
            !parseUIntField(QStringLiteral("operationMask"), &parsedRuleModel.operationMask) ||
            !parseUIntField(QStringLiteral("matchMode"), &parsedRuleModel.matchMode) ||
            !parseUIntField(QStringLiteral("action"), &parsedRuleModel.action) ||
            !parseUIntField(QStringLiteral("timeoutMs"), &parsedRuleModel.timeoutMs) ||
            !parseUIntField(QStringLiteral("timeoutDefaultDecision"), &parsedRuleModel.timeoutDefaultDecision))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.numeric_invalid", QStringLiteral("解析失败：数值字段不合法。"));
            }
            return false;
        }

        bool priorityOk = false;
        parsedRuleModel.priority = valueMap.value(QStringLiteral("priority")).trimmed().toInt(&priorityOk);
        if (!priorityOk)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.clipboard.parse.priority_invalid", QStringLiteral("解析失败：priority 不合法。"));
            }
            return false;
        }

        parsedRuleModel.ruleName = decodeRuleClipboardText(valueMap.value(QStringLiteral("ruleName")));
        parsedRuleModel.initiatorPattern = decodeRuleClipboardText(valueMap.value(QStringLiteral("initiatorPattern")));
        parsedRuleModel.targetPattern = decodeRuleClipboardText(valueMap.value(QStringLiteral("targetPattern")));
        parsedRuleModel.comment = decodeRuleClipboardText(valueMap.value(QStringLiteral("comment")));

        *ruleOut = parsedRuleModel;
        return true;
    }

    QString callbackRuleComboStyle()
    {
        return KswordTheme::ThemedComboBoxStyle();
    }

    void applyRuleComboStyle(QComboBox* comboBox)
    {
        if (comboBox == nullptr)
        {
            return;
        }

        comboBox->setStyleSheet(callbackRuleComboStyle());
        if (comboBox->view() != nullptr)
        {
            comboBox->view()->setStyleSheet(KswordTheme::ThemedComboBoxPopupViewStyle());
        }
    }

    // resolveFileMonitorProcessNameText：
    // - 输入 processId：R0 事件的发起进程；nameCache：调用方私有的 PID→进程名缓存；
    // - 处理：命中缓存直接返回，未命中才 OpenProcess + QueryFullProcessImageNameW 取镜像名；
    // - 返回：可直接填表的进程名文本；解析失败回落到 "PID %1"。
    // 说明：只用 Win32 与 Qt 值类型，可在后台线程调用。
    QString resolveFileMonitorProcessNameText(const quint32 processId, QHash<quint32, QString>& nameCache)
    {
        if (processId == 0U)
        {
            return QStringLiteral("Idle");
        }
        if (processId == 4U)
        {
            return QStringLiteral("System");
        }
        const auto cacheIterator = nameCache.constFind(processId);
        if (cacheIterator != nameCache.constEnd())
        {
            return cacheIterator.value();
        }

        QString processName;
        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (processHandle != nullptr)
        {
            wchar_t imagePathBuffer[MAX_PATH * 4] = {};
            DWORD imagePathChars = static_cast<DWORD>(sizeof(imagePathBuffer) / sizeof(imagePathBuffer[0]));
            if (::QueryFullProcessImageNameW(processHandle, 0, imagePathBuffer, &imagePathChars) != FALSE)
            {
                processName = QFileInfo(QString::fromWCharArray(imagePathBuffer, static_cast<int>(imagePathChars))).fileName();
            }
            ::CloseHandle(processHandle);
        }
        if (processName.isEmpty())
        {
            processName = QStringLiteral("PID %1").arg(processId);
        }
        nameCache.insert(processId, processName);
        return processName;
    }

    // FileMonitorPreparedEvent：
    // - 用途：后台 drain 任务回投给 UI 线程的纯值类型行数据；
    // - 输入：R0 事件行加上后台已经解析好的进程名；
    // - 输出：UI 线程只需按字段填表，不再触碰 OpenProcess。
    struct FileMonitorPreparedEvent
    {
        ksword::ark::FileMonitorEventRow eventRow;  // eventRow：R0 原始事件行。
        QString processNameText;                    // processNameText：后台解析好的进程名。
    };

    // FileMonitorDrainSnapshot：
    // - 用途：一次后台 drain 的完整结果，全部是值类型；
    // - 输入：由 QThreadPool 任务填充；
    // - 输出：UI 线程据此追加表格行并刷新状态标签。
    struct FileMonitorDrainSnapshot
    {
        bool ioOk = false;                          // ioOk：drain IOCTL 是否成功。
        unsigned long win32Error = 0UL;             // win32Error：失败时的 Win32 错误码。
        quint32 totalQueuedBeforeDrain = 0U;        // totalQueuedBeforeDrain：取出前队列深度。
        quint32 droppedCount = 0U;                  // droppedCount：累计丢弃事件数。
        QVector<FileMonitorPreparedEvent> events;   // events：已解析完进程名的事件行。
        QHash<quint32, QString> resolvedNames;      // resolvedNames：本轮解析出的 PID→进程名，回投后并回主缓存。
    };
}

class CallbackInterceptController final : public QObject
{
public:
    explicit CallbackInterceptController(QWidget* hostPage, QObject* parent = nullptr)
        : QObject(parent)
        , m_hostPage(hostPage)
    {
        initializeUi();
        initializeConnections();

        addDefaultGroupIfNeeded();
        refreshRuleGroupComboOptions();
        reloadRuntimeState();

        m_promptManager = CallbackPromptManager::ensureGlobalManager(
            m_hostPage != nullptr ? m_hostPage->window() : nullptr);
        if (m_promptManager != nullptr)
        {
            connect(
                m_promptManager,
                &CallbackPromptManager::logLineGenerated,
                m_hostPage,
                [this](const QString& logText) {
                    appendEventLog(logText);
                });
            m_promptManager->start();
            appendAppLog(kernelText("kernel.callback.intercept.log.prompt_manager_started", QStringLiteral("驱动回调询问管理器已启动。")));
        }
    }

    ~CallbackInterceptController() override = default;

private:
    void initializeUi()
    {
        if (m_hostPage == nullptr)
        {
            return;
        }

        auto* outerLayout = new QVBoxLayout(m_hostPage);
        outerLayout->setContentsMargins(0, 0, 0, 0);
        outerLayout->setSpacing(0);

        auto* scrollArea = new QScrollArea(m_hostPage);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setAutoFillBackground(false);
        scrollArea->setAttribute(Qt::WA_StyledBackground, false);
        scrollArea->viewport()->setAutoFillBackground(false);
        scrollArea->viewport()->setAttribute(Qt::WA_StyledBackground, false);
        scrollArea->setStyleSheet(QStringLiteral(
            "QScrollArea,QScrollArea > QWidget,QScrollArea::viewport{"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"));
        outerLayout->addWidget(scrollArea, 1);

        auto* scrollContent = new QWidget(scrollArea);
        scrollContent->setObjectName(QStringLiteral("ksCallbackInterceptScrollContent"));
        scrollContent->setAutoFillBackground(false);
        scrollContent->setAttribute(Qt::WA_StyledBackground, false);
        if (callbackAllowWallpaperThroughControls())
        {
            scrollContent->setStyleSheet(QStringLiteral(
                "QWidget#ksCallbackInterceptScrollContent,"
                "QWidget#ksCallbackInterceptScrollContent QWidget,"
                "QWidget#ksCallbackInterceptScrollContent QSplitter,"
                "QWidget#ksCallbackInterceptScrollContent QTabWidget::pane,"
                "QWidget#ksCallbackInterceptScrollContent QTabBar::tab:!selected{"
                "  background:transparent;"
                "  background-color:transparent;"
                "}"));
        }
        scrollArea->setWidget(scrollContent);

        auto* rootLayout = new QVBoxLayout(scrollContent);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(6);

        auto* topBarLayout = new QHBoxLayout();
        topBarLayout->setContentsMargins(0, 0, 0, 0);
        topBarLayout->setSpacing(6);

        m_globalEnabledCheck = new QCheckBox(kernelText("kernel.callback.intercept.toolbar.global_enabled", QStringLiteral("全局启用")), scrollContent);
        m_globalEnabledCheck->setChecked(true);
        m_applyButton = new QPushButton(kernelText("kernel.callback.intercept.toolbar.apply", QStringLiteral("应用")), scrollContent);
        m_reloadStateButton = new QPushButton(kernelText("kernel.callback.intercept.toolbar.reload_state", QStringLiteral("重新加载驱动状态")), scrollContent);
        m_importButton = new QPushButton(kernelText("kernel.callback.intercept.toolbar.import", QStringLiteral("导入配置")), scrollContent);
        m_exportButton = new QPushButton(kernelText("kernel.callback.intercept.toolbar.export", QStringLiteral("导出配置")), scrollContent);

        const auto setupIconButton = [this](QPushButton* button, const QIcon& iconValue, const QString& tipText) {
            if (button == nullptr || m_hostPage == nullptr)
            {
                return;
            }
            button->setText(QString());
            button->setIcon(iconValue);
            button->setToolTip(tipText);
            button->setFixedSize(30, 26);
            button->setIconSize(QSize(16, 16));
        };
        setupIconButton(m_applyButton, QIcon(QStringLiteral(":/Icon/process_start.svg")), kernelText("kernel.callback.intercept.tooltip.apply", QStringLiteral("应用规则")));
        setupIconButton(m_reloadStateButton, QIcon(QStringLiteral(":/Icon/process_refresh.svg")), kernelText("kernel.callback.intercept.tooltip.reload_state", QStringLiteral("重新加载驱动状态")));
        setupIconButton(m_importButton, QIcon(QStringLiteral(":/Icon/codeeditor_open.svg")), kernelText("kernel.callback.intercept.tooltip.import", QStringLiteral("导入配置")));
        setupIconButton(m_exportButton, QIcon(QStringLiteral(":/Icon/log_export.svg")), kernelText("kernel.callback.intercept.tooltip.export", QStringLiteral("导出配置")));

        topBarLayout->addWidget(m_globalEnabledCheck, 0);
        topBarLayout->addWidget(m_applyButton, 0);
        topBarLayout->addWidget(m_reloadStateButton, 0);
        topBarLayout->addWidget(m_importButton, 0);
        topBarLayout->addWidget(m_exportButton, 0);
        topBarLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(topBarLayout);
        rootLayout->addLayout(topBarLayout, 0);

        m_statusLabel = new QLabel(kernelText("kernel.callback.intercept.status.waiting_refresh", QStringLiteral("状态：等待刷新")), scrollContent);
        m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
        rootLayout->addWidget(m_statusLabel, 0);

        auto* mainSplitter = new QSplitter(Qt::Horizontal, scrollContent);
        rootLayout->addWidget(mainSplitter, 1);

        auto* groupPane = new QWidget(mainSplitter);
        auto* groupLayout = new QVBoxLayout(groupPane);
        groupLayout->setContentsMargins(0, 0, 0, 0);
        groupLayout->setSpacing(6);

        auto* groupButtonLayout = new QHBoxLayout();
        groupButtonLayout->setContentsMargins(0, 0, 0, 0);
        groupButtonLayout->setSpacing(6);
        m_addGroupButton = new QPushButton(kernelText("kernel.callback.intercept.group.add", QStringLiteral("新增组")), groupPane);
        m_removeGroupButton = new QPushButton(kernelText("kernel.callback.intercept.group.remove", QStringLiteral("删除组")), groupPane);
        m_renameGroupButton = new QPushButton(kernelText("kernel.callback.intercept.group.rename", QStringLiteral("重命名")), groupPane);
        m_moveGroupUpButton = new QPushButton(kernelText("kernel.callback.intercept.group.move_up_short", QStringLiteral("上移")), groupPane);
        m_moveGroupDownButton = new QPushButton(kernelText("kernel.callback.intercept.group.move_down_short", QStringLiteral("下移")), groupPane);
        setupIconButton(m_addGroupButton, QIcon(QStringLiteral(":/Icon/plus.svg")), kernelText("kernel.callback.intercept.group.add_tooltip", QStringLiteral("新增规则组")));
        setupIconButton(m_removeGroupButton, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.group.remove_tooltip", QStringLiteral("删除当前规则组")));
        setupIconButton(m_renameGroupButton, QIcon(QStringLiteral(":/Icon/process_details.svg")), kernelText("kernel.callback.intercept.group.rename_tooltip", QStringLiteral("重命名当前规则组")));
        setupIconButton(m_moveGroupUpButton, QIcon(QStringLiteral(":/Icon/file_nav_up.svg")), kernelText("kernel.callback.intercept.group.move_up_tooltip", QStringLiteral("规则组上移")));
        setupIconButton(m_moveGroupDownButton, QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), kernelText("kernel.callback.intercept.group.move_down_tooltip", QStringLiteral("规则组下移")));
        groupButtonLayout->addWidget(m_addGroupButton, 0);
        groupButtonLayout->addWidget(m_removeGroupButton, 0);
        groupButtonLayout->addWidget(m_renameGroupButton, 0);
        groupButtonLayout->addWidget(m_moveGroupUpButton, 0);
        groupButtonLayout->addWidget(m_moveGroupDownButton, 0);
        groupButtonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(groupButtonLayout);
        groupLayout->addLayout(groupButtonLayout, 0);

        m_groupTable = new ks::ui::VisibleTableWidget(groupPane);
        // 规则组为可编辑配置，页面已有导入导出，不需要快照栏。
        ks::ui::SetTableActionBarMode(m_groupTable, ks::ui::TableActionBarMode::None);
        m_groupTable->setColumnCount(static_cast<int>(GroupColumn::Count));
        m_groupTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("groupId"),
            kernelText("kernel.callback.intercept.group.header.name", QStringLiteral("组名称")),
            kernelText("kernel.callback.intercept.group.header.enabled", QStringLiteral("启用")),
            kernelText("kernel.callback.intercept.group.header.priority", QStringLiteral("优先级")),
            kernelText("kernel.callback.intercept.group.header.comment", QStringLiteral("备注"))
            });
        m_groupTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_groupTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_groupTable->setEditTriggers(
            QAbstractItemView::DoubleClicked |
            QAbstractItemView::SelectedClicked |
            QAbstractItemView::EditKeyPressed);
        m_groupTable->setItemDelegate(new OpaqueTableEditorDelegate(m_groupTable));
        m_groupTable->setProperty("ksword_preserve_custom_table_delegate", true);
        m_groupTable->verticalHeader()->setVisible(false);
        m_groupTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        m_groupTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(GroupColumn::Comment), QHeaderView::Stretch);
        m_groupTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(m_groupTable);
        installCallbackTableCopyMenu(m_groupTable, -1);
        groupLayout->addWidget(m_groupTable, 1);

        auto* rightPane = new QWidget(mainSplitter);
        auto* rightLayout = new QVBoxLayout(rightPane);
        rightLayout->setContentsMargins(0, 0, 0, 0);
        rightLayout->setSpacing(6);

        auto* ruleToolbarLayout = new QHBoxLayout();
        ruleToolbarLayout->setContentsMargins(0, 0, 0, 0);
        ruleToolbarLayout->setSpacing(6);
        m_addRuleButton = new QPushButton(kernelText("kernel.callback.intercept.rule.add", QStringLiteral("新增规则")), rightPane);
        m_removeRuleButton = new QPushButton(kernelText("kernel.callback.intercept.rule.remove", QStringLiteral("删除规则")), rightPane);
        m_moveRuleUpButton = new QPushButton(kernelText("kernel.callback.intercept.rule.move_up", QStringLiteral("规则上移")), rightPane);
        m_moveRuleDownButton = new QPushButton(kernelText("kernel.callback.intercept.rule.move_down", QStringLiteral("规则下移")), rightPane);
        setupIconButton(m_addRuleButton, QIcon(QStringLiteral(":/Icon/plus.svg")), kernelText("kernel.callback.intercept.rule.add_tooltip", QStringLiteral("新增规则")));
        setupIconButton(m_removeRuleButton, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.rule.remove_tooltip", QStringLiteral("删除当前规则")));
        setupIconButton(m_moveRuleUpButton, QIcon(QStringLiteral(":/Icon/file_nav_up.svg")), kernelText("kernel.callback.intercept.rule.move_up_tooltip", QStringLiteral("规则上移")));
        setupIconButton(m_moveRuleDownButton, QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")), kernelText("kernel.callback.intercept.rule.move_down_tooltip", QStringLiteral("规则下移")));
        ruleToolbarLayout->addWidget(m_addRuleButton, 0);
        ruleToolbarLayout->addWidget(m_removeRuleButton, 0);
        ruleToolbarLayout->addWidget(m_moveRuleUpButton, 0);
        ruleToolbarLayout->addWidget(m_moveRuleDownButton, 0);
        ruleToolbarLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(ruleToolbarLayout);
        rightLayout->addLayout(ruleToolbarLayout, 0);

        m_ruleTabWidget = new QTabWidget(rightPane);
        ks::ui::StylePageTabs(m_ruleTabWidget);
        rightLayout->addWidget(m_ruleTabWidget, 1);

        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_REGISTRY, kernelText("kernel.callback.intercept.tab.registry", QStringLiteral("注册表")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE, kernelText("kernel.callback.intercept.tab.process", QStringLiteral("进程创建")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE, kernelText("kernel.callback.intercept.tab.thread", QStringLiteral("线程创建")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD, kernelText("kernel.callback.intercept.tab.image", QStringLiteral("镜像加载")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_OBJECT, kernelText("kernel.callback.intercept.tab.object", QStringLiteral("对象管理器")));
        createRuleTableTab(KSWORD_ARK_CALLBACK_TYPE_MINIFILTER, kernelText("kernel.callback.intercept.tab.minifilter", QStringLiteral("文件系统微过滤器")));
        createMinifilterBypassPidTab(m_ruleTabWidget);
        createProcessProtectTab(m_ruleTabWidget);

        auto* logTabWidget = new QTabWidget(scrollContent);
        ks::ui::StylePageTabs(logTabWidget);
        m_appLogEditor = new CodeTextEdit(logTabWidget);
        static_cast<CodeTextEdit*>(m_appLogEditor)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        m_eventLogEditor = new CodeTextEdit(logTabWidget);
        static_cast<CodeTextEdit*>(m_eventLogEditor)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        m_appLogEditor->setReadOnly(true);
        m_eventLogEditor->setReadOnly(true);
        logTabWidget->addTab(m_appLogEditor, kernelText("kernel.callback.intercept.log_tab.application", QStringLiteral("应用日志")));
        logTabWidget->addTab(m_eventLogEditor, kernelText("kernel.callback.intercept.log_tab.events", QStringLiteral("事件日志")));
        rootLayout->addWidget(logTabWidget, 0);

        auto* fileMonitorFrame = new QFrame(scrollContent);
        fileMonitorFrame->setFrameShape(QFrame::StyledPanel);
        const bool allowWallpaperThroughFileMonitor = callbackAllowWallpaperThroughControls();
        fileMonitorFrame->setAutoFillBackground(!allowWallpaperThroughFileMonitor);
        fileMonitorFrame->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThroughFileMonitor);
        fileMonitorFrame->setStyleSheet(allowWallpaperThroughFileMonitor
            ? QStringLiteral("QFrame{background:transparent;background-color:transparent;border:1px solid %1;}")
                .arg(KswordTheme::BorderHex())
            : QStringLiteral("QFrame{background:%1;background-color:%1;border:1px solid %2;}")
                .arg(KswordTheme::SurfaceHex())
                .arg(KswordTheme::BorderHex()));
        auto* fileMonitorLayout = new QVBoxLayout(fileMonitorFrame);
        fileMonitorLayout->setContentsMargins(8, 8, 8, 8);
        fileMonitorLayout->setSpacing(6);

        auto* fileMonitorToolbar = new QHBoxLayout();
        fileMonitorToolbar->setContentsMargins(0, 0, 0, 0);
        fileMonitorToolbar->setSpacing(6);
        auto* fileMonitorTitleLabel = new QLabel(kernelText("kernel.callback.intercept.file_monitor.title", QStringLiteral("文件监控：Oplock / FSCTL")), fileMonitorFrame);
        fileMonitorTitleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));
        m_startFileMonitorFsctlButton = new QPushButton(fileMonitorFrame);
        m_drainFileMonitorButton = new QPushButton(fileMonitorFrame);
        m_clearFileMonitorButton = new QPushButton(fileMonitorFrame);
        m_exportFileMonitorButton = new QPushButton(fileMonitorFrame);
        setupIconButton(m_startFileMonitorFsctlButton, QIcon(QStringLiteral(":/Icon/process_start.svg")), kernelText("kernel.callback.intercept.file_monitor.start_tooltip", QStringLiteral("启动/补充 FSCTL 文件监控")));
        setupIconButton(m_drainFileMonitorButton, QIcon(QStringLiteral(":/Icon/process_refresh.svg")), kernelText("kernel.callback.intercept.file_monitor.read_tooltip", QStringLiteral("读取文件监控事件")));
        setupIconButton(m_clearFileMonitorButton, QIcon(QStringLiteral(":/Icon/log_clear.svg")), kernelText("kernel.callback.intercept.file_monitor.clear_tooltip", QStringLiteral("清空当前文件监控表格")));
        setupIconButton(m_exportFileMonitorButton, QIcon(QStringLiteral(":/Icon/log_export.svg")), kernelText("kernel.callback.intercept.file_monitor.export_tooltip", QStringLiteral("导出当前可见文件监控事件")));
        m_fileMonitorFsctlOnlyCheck = new QCheckBox(kernelText("kernel.callback.intercept.file_monitor.fsctl_only", QStringLiteral("仅显示 Oplock / FSCTL")), fileMonitorFrame);
        m_fileMonitorFsctlOnlyCheck->setChecked(true);
        m_fileMonitorStatusLabel = new QLabel(kernelText("kernel.callback.intercept.file_monitor.waiting", QStringLiteral("等待启动或读取事件")), fileMonitorFrame);
        m_fileMonitorStatusLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));

        fileMonitorToolbar->addWidget(fileMonitorTitleLabel, 0);
        fileMonitorToolbar->addWidget(m_startFileMonitorFsctlButton, 0);
        fileMonitorToolbar->addWidget(m_drainFileMonitorButton, 0);
        fileMonitorToolbar->addWidget(m_clearFileMonitorButton, 0);
        fileMonitorToolbar->addWidget(m_exportFileMonitorButton, 0);
        fileMonitorToolbar->addWidget(m_fileMonitorFsctlOnlyCheck, 0);
        fileMonitorToolbar->addStretch(1);
        fileMonitorToolbar->addWidget(m_fileMonitorStatusLabel, 0);
        ks::ui::NormalizeToolbarRow(fileMonitorToolbar);
        fileMonitorLayout->addLayout(fileMonitorToolbar, 0);

        m_fileMonitorTable = new ks::ui::VisibleTableWidget(fileMonitorFrame);
        // 事件流水已有读取/清理/导出业务条，紧凑辅助动作避免重复。
        ks::ui::SetTableActionBarMode(m_fileMonitorTable, ks::ui::TableActionBarMode::Compact);
        m_fileMonitorTable->setColumnCount(static_cast<int>(FileMonitorColumn::Count));
        m_fileMonitorTable->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.file_monitor.header.time", QStringLiteral("时间")),
            QStringLiteral("PID"),
            kernelText("kernel.callback.intercept.file_monitor.header.process", QStringLiteral("进程")),
            kernelText("kernel.callback.intercept.file_monitor.header.path", QStringLiteral("文件路径")),
            kernelText("kernel.callback.intercept.file_monitor.header.fsctl", QStringLiteral("FSCTL 名称")),
            kernelText("kernel.callback.intercept.file_monitor.header.control_code", QStringLiteral("控制码")),
            kernelText("kernel.callback.intercept.file_monitor.header.status", QStringLiteral("状态码")),
            QStringLiteral("FileObject"),
            QStringLiteral("In"),
            QStringLiteral("Out")
            });
        m_fileMonitorTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_fileMonitorTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_fileMonitorTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_fileMonitorTable->setAlternatingRowColors(true);
        m_fileMonitorTable->setWordWrap(false);
        m_fileMonitorTable->verticalHeader()->setVisible(false);
        m_fileMonitorTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        m_fileMonitorTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(FileMonitorColumn::Path), QHeaderView::Stretch);
        m_fileMonitorTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(m_fileMonitorTable);
        installCallbackTableCopyMenu(m_fileMonitorTable, static_cast<int>(FileMonitorColumn::Pid));
        fileMonitorLayout->addWidget(m_fileMonitorTable, 1);
        rootLayout->addWidget(fileMonitorFrame, 1);

        m_fileMonitorDrainTimer = new QTimer(m_hostPage);
        m_fileMonitorDrainTimer->setInterval(1500);

        mainSplitter->setStretchFactor(0, 3);
        mainSplitter->setStretchFactor(1, 7);
    }

    void initializeConnections()
    {
        if (m_globalEnabledCheck != nullptr)
        {
            connect(m_globalEnabledCheck, &QCheckBox::toggled, m_hostPage, [this](bool) {
                setDirtyState(true);
            });
        }

        connect(m_applyButton, &QPushButton::clicked, m_hostPage, [this]() {
            applyRulesToDriver();
        });
        connect(m_reloadStateButton, &QPushButton::clicked, m_hostPage, [this]() {
            reloadRuntimeState();
        });
        connect(m_importButton, &QPushButton::clicked, m_hostPage, [this]() {
            importConfigFromFile();
        });
        connect(m_exportButton, &QPushButton::clicked, m_hostPage, [this]() {
            exportConfigToFile();
        });

        connect(m_addGroupButton, &QPushButton::clicked, m_hostPage, [this]() {
            addGroupRow(0U);
        });
        connect(m_removeGroupButton, &QPushButton::clicked, m_hostPage, [this]() {
            removeCurrentGroup();
        });
        connect(m_renameGroupButton, &QPushButton::clicked, m_hostPage, [this]() {
            renameCurrentGroup();
        });
        connect(m_moveGroupUpButton, &QPushButton::clicked, m_hostPage, [this]() {
            moveCurrentGroup(-1);
        });
        connect(m_moveGroupDownButton, &QPushButton::clicked, m_hostPage, [this]() {
            moveCurrentGroup(1);
        });

        connect(m_addRuleButton, &QPushButton::clicked, m_hostPage, [this]() {
            addRuleToCurrentTab();
        });
        connect(m_removeRuleButton, &QPushButton::clicked, m_hostPage, [this]() {
            removeCurrentRule();
        });
        connect(m_moveRuleUpButton, &QPushButton::clicked, m_hostPage, [this]() {
            moveCurrentRule(-1);
        });
        connect(m_moveRuleDownButton, &QPushButton::clicked, m_hostPage, [this]() {
            moveCurrentRule(1);
        });

        connect(m_minifilterBypassAddButton, &QPushButton::clicked, m_hostPage, [this]() {
            addMinifilterBypassPidFromEdit();
        });
        connect(m_minifilterBypassRemoveButton, &QPushButton::clicked, m_hostPage, [this]() {
            removeCurrentMinifilterBypassPid();
        });
        connect(m_minifilterBypassApplyButton, &QPushButton::clicked, m_hostPage, [this]() {
            applyMinifilterBypassPidsToDriver();
        });
        connect(m_minifilterBypassClearButton, &QPushButton::clicked, m_hostPage, [this]() {
            clearMinifilterBypassPidsAndApply();
        });
        connect(m_minifilterBypassRefreshButton, &QPushButton::clicked, m_hostPage, [this]() {
            refreshMinifilterBypassPidsFromDriver();
        });

        connect(m_processProtectAddRuleButton, &QPushButton::clicked, m_hostPage, [this]() {
            addProcessProtectRuleFromInput();
        });
        connect(m_processProtectApplyPresetButton, &QPushButton::clicked, m_hostPage, [this]() {
            applyProcessProtectPresetToSelection();
        });
        connect(m_processProtectApplyKernelButton, &QPushButton::clicked, m_hostPage, [this]() {
            applyProcessProtectKernelPresetToSelection();
        });
        connect(m_processProtectRemoveRuleButton, &QPushButton::clicked, m_hostPage, [this]() {
            removeCurrentProcessProtectRule();
        });
        connect(m_processProtectTargetEdit, &QLineEdit::returnPressed, m_hostPage, [this]() {
            addProcessProtectRuleFromInput();
        });
        connect(m_processProtectTrustedAddButton, &QPushButton::clicked, m_hostPage, [this]() {
            addProcessProtectTrustedFromInput();
        });
        connect(m_processProtectTrustedRemoveButton, &QPushButton::clicked, m_hostPage, [this]() {
            removeCurrentProcessProtectTrusted();
        });
        connect(m_processProtectTrustedTargetEdit, &QLineEdit::returnPressed, m_hostPage, [this]() {
            addProcessProtectTrustedFromInput();
        });
        connect(m_processProtectApplyButton, &QPushButton::clicked, m_hostPage, [this]() {
            applyProcessProtectToDriver();
        });
        connect(m_processProtectRefreshButton, &QPushButton::clicked, m_hostPage, [this]() {
            refreshProcessProtectFromDriver();
        });
        connect(m_processProtectClearButton, &QPushButton::clicked, m_hostPage, [this]() {
            clearProcessProtectAndApply();
        });
        connect(m_minifilterBypassPidEdit, &QLineEdit::returnPressed, m_hostPage, [this]() {
            addMinifilterBypassPidFromEdit();
        });

        connect(m_groupTable, &QTableWidget::itemChanged, m_hostPage, [this](QTableWidgetItem*) {
            if (m_ignoreUiSignal)
            {
                return;
            }
            refreshRuleGroupComboOptions();
            setDirtyState(true);
        });

        connect(m_ruleTabWidget, &QTabWidget::currentChanged, m_hostPage, [this](int) {
            // 当前所有回调类型均已经接入规则表；切换 Tab 时保持工具按钮可用。
            m_addRuleButton->setEnabled(currentRuleTable() != nullptr);
            m_removeRuleButton->setEnabled(currentRuleTable() != nullptr);
            m_moveRuleUpButton->setEnabled(currentRuleTable() != nullptr);
            m_moveRuleDownButton->setEnabled(currentRuleTable() != nullptr);
        });

        connect(m_startFileMonitorFsctlButton, &QPushButton::clicked, m_hostPage, [this]() {
            startFileMonitorFsctlCapture();
        });
        connect(m_drainFileMonitorButton, &QPushButton::clicked, m_hostPage, [this]() {
            drainFileMonitorEvents();
        });
        connect(m_clearFileMonitorButton, &QPushButton::clicked, m_hostPage, [this]() {
            clearFileMonitorEvents();
        });
        connect(m_exportFileMonitorButton, &QPushButton::clicked, m_hostPage, [this]() {
            exportVisibleFileMonitorEvents();
        });
        connect(m_fileMonitorFsctlOnlyCheck, &QCheckBox::toggled, m_hostPage, [this](bool) {
            applyFileMonitorEventFilter();
        });
        connect(m_fileMonitorDrainTimer, &QTimer::timeout, m_hostPage, [this]() {
            drainFileMonitorEvents();
        });
    }

    QString resolveProcessNameForFileMonitor(const quint32 processId)
    {
        // resolveProcessNameForFileMonitor：
        // - 输入 processId：需要展示进程名的 PID；
        // - 处理：复用控制器自己的 PID→进程名缓存，交给文件级解析函数完成 Win32 查询；
        // - 返回：可直接填表的进程名文本。
        // 说明：仅供 UI 线程的单次、低频路径（白名单表）使用；文件监控 drain 的批量
        // 解析已经搬到后台线程，不再走这里。
        return resolveFileMonitorProcessNameText(processId, m_fileMonitorProcessNameCache);
    }

    void startFileMonitorFsctlCapture()
    {
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::FileMonitorStatusResult beforeStatus = driverClient.queryFileMonitorStatus();
        unsigned long requestedMask = KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        if (beforeStatus.io.ok &&
            (beforeStatus.runtimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) != 0U)
        {
            requestedMask = beforeStatus.operationMask | KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        }

        const ksword::ark::IoResult startResult = driverClient.controlFileMonitor(
            KSWORD_ARK_FILE_MONITOR_ACTION_START,
            requestedMask,
            beforeStatus.io.ok ? beforeStatus.processIdFilter : 0UL,
            0UL);
        if (!startResult.ok)
        {
            const QString detailText = callbackRuleIoMessageText(QString::fromStdString(startResult.message));
            m_fileMonitorStatusLabel->setText(kernelText("kernel.callback.intercept.file_monitor.status.start_failed", QStringLiteral("启动失败：error=%1")).arg(startResult.win32Error));
            appendAppLog(kernelText("kernel.callback.intercept.file_monitor.log.start_failed", QStringLiteral("文件监控 FSCTL 启动失败：%1")).arg(detailText));
            return;
        }

        m_fileMonitorStatusLabel->setText(kernelText("kernel.callback.intercept.file_monitor.status.started", QStringLiteral("FSCTL 文件监控已启动，mask=0x%1"))
            .arg(requestedMask, 8, 16, QChar('0')).toUpper());
        appendAppLog(kernelText("kernel.callback.intercept.file_monitor.log.started", QStringLiteral("文件监控 FSCTL 已启动：mask=0x%1"))
            .arg(requestedMask, 8, 16, QChar('0')).toUpper());
        if (m_fileMonitorDrainTimer != nullptr && !m_fileMonitorDrainTimer->isActive())
        {
            m_fileMonitorDrainTimer->start();
        }
        drainFileMonitorEvents();
    }

    void drainFileMonitorEvents()
    {
        if (m_fileMonitorTable == nullptr)
        {
            return;
        }

        // 定时读取本身会消费驱动队列；菜单打开时必须在 drain IOCTL 前延后，
        // 否则 latest-wins 只能保留最后一个已消费批次。
        const QPointer<CallbackInterceptController> guardThis(this);
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-callback-file-monitor-drain"),
            { m_fileMonitorTable },
            [guardThis]()
            {
                if (!guardThis.isNull())
                {
                    guardThis->drainFileMonitorEvents();
                }
            }))
        {
            return;
        }

        // drain IOCTL 每次都要 CreateFileW + 同步 DeviceIoControl，单批还要为每个新 PID
        // 做一次 OpenProcess + QueryFullProcessImageNameW；1500ms 周期定时器直接在 UI
        // 线程跑会持续掉帧。这里只投递后台任务，UI 线程仅负责回投后的填表。
        if (m_fileMonitorDrainInFlight)
        {
            return;
        }
        m_fileMonitorDrainInFlight = true;

        const QHash<quint32, QString> nameCacheSnapshot = m_fileMonitorProcessNameCache;
        QThreadPool::globalInstance()->start(
            [guardThis, nameCacheSnapshot]()
            {
                QHash<quint32, QString> workerNameCache = nameCacheSnapshot;
                FileMonitorDrainSnapshot snapshot;

                const ksword::ark::DriverClient driverClient;
                const ksword::ark::FileMonitorDrainResult drainResult = driverClient.drainFileMonitor(128UL, 0UL);
                snapshot.ioOk = drainResult.io.ok;
                snapshot.win32Error = drainResult.io.win32Error;
                snapshot.totalQueuedBeforeDrain = drainResult.totalQueuedBeforeDrain;
                snapshot.droppedCount = drainResult.droppedCount;
                if (snapshot.ioOk)
                {
                    snapshot.events.reserve(static_cast<qsizetype>(drainResult.events.size()));
                    for (const ksword::ark::FileMonitorEventRow& eventRow : drainResult.events)
                    {
                        FileMonitorPreparedEvent preparedEvent;
                        preparedEvent.eventRow = eventRow;
                        preparedEvent.processNameText =
                            resolveFileMonitorProcessNameText(eventRow.processId, workerNameCache);
                        snapshot.events.push_back(std::move(preparedEvent));
                    }
                    snapshot.resolvedNames = std::move(workerNameCache);
                }

                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(appInstance,
                    [guardThis, snapshot = std::move(snapshot)]() mutable
                    {
                        if (guardThis.isNull())
                        {
                            return;
                        }
                        guardThis->applyFileMonitorDrainSnapshot(std::move(snapshot));
                    });
            });
    }

    void applyFileMonitorDrainSnapshot(FileMonitorDrainSnapshot snapshot)
    {
        // applyFileMonitorDrainSnapshot：
        // - 输入 snapshot：后台 drain 任务产出的纯值类型结果；
        // - 处理：合并进程名缓存、追加表格行、刷新过滤与状态标签；
        // - 返回：无返回值，并清除在途标志允许下一次周期性 drain。
        m_fileMonitorDrainInFlight = false;
        if (m_fileMonitorTable == nullptr || m_fileMonitorStatusLabel == nullptr)
        {
            return;
        }

        if (!snapshot.ioOk)
        {
            m_fileMonitorStatusLabel->setText(kernelText("kernel.callback.intercept.file_monitor.status.read_failed", QStringLiteral("读取失败：error=%1")).arg(snapshot.win32Error));
            return;
        }

        for (auto nameIterator = snapshot.resolvedNames.constBegin();
             nameIterator != snapshot.resolvedNames.constEnd();
             ++nameIterator)
        {
            m_fileMonitorProcessNameCache.insert(nameIterator.key(), nameIterator.value());
        }

        for (const FileMonitorPreparedEvent& preparedEvent : snapshot.events)
        {
            appendFileMonitorEventRow(preparedEvent.eventRow, preparedEvent.processNameText);
        }
        applyFileMonitorEventFilter();
        m_fileMonitorStatusLabel->setText(
            kernelText("kernel.callback.intercept.file_monitor.status.drained", QStringLiteral("读取 %1 条，队列前=%2，丢弃=%3"))
            .arg(snapshot.events.size())
            .arg(snapshot.totalQueuedBeforeDrain)
            .arg(snapshot.droppedCount));
    }

    void appendFileMonitorEventRow(const ksword::ark::FileMonitorEventRow& eventRow, const QString& processNameText)
    {
        if (m_fileMonitorTable == nullptr)
        {
            return;
        }

        const bool isFsctlEvent =
            (eventRow.operationType & KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL) != 0U;
        const int rowIndex = m_fileMonitorTable->rowCount();
        m_fileMonitorTable->insertRow(rowIndex);

        QTableWidgetItem* timeItem = makeReadOnlyItem(utc100nsToDisplayText(static_cast<quint64>(eventRow.timeUtc100ns)));
        timeItem->setData(Qt::UserRole, isFsctlEvent);
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::Time), timeItem);
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::Pid), makeReadOnlyItem(QString::number(eventRow.processId)));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::Process), makeReadOnlyItem(processNameText));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::Path), makeReadOnlyItem(QString::fromStdWString(eventRow.path)));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::FsctlName), makeReadOnlyItem(isFsctlEvent ? fileMonitorFsctlNameText(eventRow.fsControlCode) : QStringLiteral("-")));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::ControlCode), makeReadOnlyItem(isFsctlEvent ? formatFileMonitorHex32(eventRow.fsControlCode) : QStringLiteral("-")));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::Status), makeReadOnlyItem(
            (eventRow.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT) != 0U
            ? formatFileMonitorHex32(static_cast<quint32>(eventRow.resultStatus))
            : QStringLiteral("-")));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::FileObject), makeReadOnlyItem(formatFileMonitorHex64(eventRow.fileObjectAddress)));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::InputLength), makeReadOnlyItem(isFsctlEvent ? QString::number(eventRow.fsInputBufferLength) : QStringLiteral("-")));
        m_fileMonitorTable->setItem(rowIndex, static_cast<int>(FileMonitorColumn::OutputLength), makeReadOnlyItem(isFsctlEvent ? QString::number(eventRow.fsOutputBufferLength) : QStringLiteral("-")));
    }

    void applyFileMonitorEventFilter()
    {
        if (m_fileMonitorTable == nullptr || m_fileMonitorFsctlOnlyCheck == nullptr)
        {
            return;
        }

        const bool fsctlOnly = m_fileMonitorFsctlOnlyCheck->isChecked();
        for (int rowIndex = 0; rowIndex < m_fileMonitorTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* markerItem = m_fileMonitorTable->item(rowIndex, static_cast<int>(FileMonitorColumn::Time));
            const bool isFsctlEvent = markerItem != nullptr && markerItem->data(Qt::UserRole).toBool();
            m_fileMonitorTable->setRowHidden(rowIndex, fsctlOnly && !isFsctlEvent);
        }
    }

    void clearFileMonitorEvents()
    {
        if (m_fileMonitorTable != nullptr)
        {
            m_fileMonitorTable->setRowCount(0);
        }
        if (m_fileMonitorStatusLabel != nullptr)
        {
            m_fileMonitorStatusLabel->setText(kernelText("kernel.callback.intercept.file_monitor.status.cleared", QStringLiteral("当前表格已清空")));
        }
    }

    void exportVisibleFileMonitorEvents()
    {
        if (m_fileMonitorTable == nullptr)
        {
            return;
        }

        const QString filePath = QFileDialog::getSaveFileName(
            m_hostPage,
            kernelText("kernel.callback.intercept.file_monitor.dialog.export_title", QStringLiteral("导出文件监控事件")),
            QStringLiteral("file_monitor_fsctl.tsv"),
            kernelText("kernel.callback.intercept.file_monitor.dialog.file_filter", QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*.*)")));
        if (filePath.isEmpty())
        {
            return;
        }

        QFile outputFile(filePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        {
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.file_monitor.dialog.title", QStringLiteral("文件监控")),
                kernelText("kernel.callback.intercept.file_monitor.status.export_failed", QStringLiteral("无法写入导出文件：%1")).arg(filePath));
            return;
        }

        QStringList lines;
        QStringList headerCells;
        for (int columnIndex = 0; columnIndex < m_fileMonitorTable->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* headerItem = m_fileMonitorTable->horizontalHeaderItem(columnIndex);
            headerCells << (headerItem != nullptr ? headerItem->text() : QString());
        }
        lines << headerCells.join(QLatin1Char('\t'));

        for (int rowIndex = 0; rowIndex < m_fileMonitorTable->rowCount(); ++rowIndex)
        {
            if (m_fileMonitorTable->isRowHidden(rowIndex))
            {
                continue;
            }
            QStringList rowCells;
            for (int columnIndex = 0; columnIndex < m_fileMonitorTable->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* cellItem = m_fileMonitorTable->item(rowIndex, columnIndex);
                QString cellText = cellItem != nullptr ? cellItem->text() : QString();
                cellText.replace(QLatin1Char('\t'), QLatin1Char(' '));
                cellText.replace(QLatin1Char('\n'), QLatin1Char(' '));
                cellText.replace(QLatin1Char('\r'), QLatin1Char(' '));
                rowCells << cellText;
            }
            lines << rowCells.join(QLatin1Char('\t'));
        }

        outputFile.write(lines.join(QLatin1Char('\n')).toUtf8());
        outputFile.write("\n");
        m_fileMonitorStatusLabel->setText(kernelText("kernel.callback.intercept.file_monitor.status.exported", QStringLiteral("已导出：%1")).arg(filePath));
    }

    void createMinifilterBypassPidTab(QWidget* parentWidget)
    {
        // 输入：父 TabWidget；处理：创建 PID 白名单输入区、表格和状态栏；
        // 返回：无，控件指针保存在成员变量中供按钮槽函数使用。
        if (m_ruleTabWidget == nullptr)
        {
            return;
        }

        auto* tabPage = new QWidget(parentWidget);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(8, 8, 8, 8);
        tabLayout->setSpacing(8);

        auto* hintLabel = new QLabel(
            kernelText("kernel.callback.intercept.minifilter.hint", QStringLiteral("白名单 PID 的文件系统请求会在 minifilter 入口直接放行，跳过回调规则、重定向和文件监控采集。")),
            tabPage);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        tabLayout->addWidget(hintLabel, 0);

        auto* inputLayout = new QHBoxLayout();
        inputLayout->setContentsMargins(0, 0, 0, 0);
        inputLayout->setSpacing(6);

        auto* pidLabel = new QLabel(kernelText("kernel.callback.intercept.minifilter.pid_allowlist", QStringLiteral("PID 白名单")), tabPage);
        pidLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));
        m_minifilterBypassPidEdit = new QLineEdit(tabPage);
        m_minifilterBypassPidEdit->setPlaceholderText(kernelText("kernel.callback.intercept.minifilter.input_placeholder", QStringLiteral("输入 PID，支持 1234 / 0x4D2；多个 PID 用空格、逗号或换行分隔")));
        applyRuleLineEditStyle(m_minifilterBypassPidEdit);
        m_minifilterBypassAddButton = new QPushButton(kernelText("kernel.callback.intercept.minifilter.add", QStringLiteral("添加")), tabPage);
        m_minifilterBypassRemoveButton = new QPushButton(kernelText("kernel.callback.intercept.minifilter.remove_selected", QStringLiteral("移除选中")), tabPage);
        m_minifilterBypassApplyButton = new QPushButton(kernelText("kernel.callback.intercept.minifilter.apply", QStringLiteral("应用到驱动")), tabPage);
        m_minifilterBypassClearButton = new QPushButton(kernelText("kernel.callback.intercept.minifilter.clear_apply", QStringLiteral("清空并应用")), tabPage);
        m_minifilterBypassRefreshButton = new QPushButton(kernelText("kernel.callback.intercept.minifilter.refresh", QStringLiteral("从驱动刷新")), tabPage);

        inputLayout->addWidget(pidLabel, 0);
        inputLayout->addWidget(m_minifilterBypassPidEdit, 1);
        inputLayout->addWidget(m_minifilterBypassAddButton, 0);
        inputLayout->addWidget(m_minifilterBypassRemoveButton, 0);
        inputLayout->addWidget(m_minifilterBypassApplyButton, 0);
        inputLayout->addWidget(m_minifilterBypassClearButton, 0);
        inputLayout->addWidget(m_minifilterBypassRefreshButton, 0);
        ks::ui::NormalizeToolbarRow(inputLayout);
        tabLayout->addLayout(inputLayout, 0);

        m_minifilterBypassPidTable = new ks::ui::VisibleTableWidget(tabPage);
        // PID 白名单是待应用配置，不需要冻结或快照比较。
        ks::ui::SetTableActionBarMode(m_minifilterBypassPidTable, ks::ui::TableActionBarMode::None);
        m_minifilterBypassPidTable->setColumnCount(static_cast<int>(MinifilterBypassPidColumn::Count));
        m_minifilterBypassPidTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("PID"),
            kernelText("kernel.callback.intercept.minifilter.header.process", QStringLiteral("进程"))
            });
        m_minifilterBypassPidTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_minifilterBypassPidTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_minifilterBypassPidTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_minifilterBypassPidTable->setSortingEnabled(false);
        m_minifilterBypassPidTable->setWordWrap(false);
        m_minifilterBypassPidTable->verticalHeader()->setVisible(false);
        m_minifilterBypassPidTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(MinifilterBypassPidColumn::Pid), QHeaderView::ResizeToContents);
        m_minifilterBypassPidTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(MinifilterBypassPidColumn::Process), QHeaderView::Stretch);
        m_minifilterBypassPidTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(m_minifilterBypassPidTable);
        installCallbackTableCopyMenu(m_minifilterBypassPidTable, static_cast<int>(MinifilterBypassPidColumn::Pid));
        tabLayout->addWidget(m_minifilterBypassPidTable, 1);

        m_minifilterBypassStatusLabel = new QLabel(kernelText("kernel.callback.intercept.minifilter.status.not_refreshed", QStringLiteral("尚未从驱动刷新；编辑后点击“应用到驱动”生效。")), tabPage);
        m_minifilterBypassStatusLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        tabLayout->addWidget(m_minifilterBypassStatusLabel, 0);

        m_ruleTabWidget->addTab(tabPage, kernelText("kernel.callback.intercept.minifilter.tab", QStringLiteral("Minifilter PID 放行")));
    }

    QList<quint32> parseMinifilterBypassPidText(const QString& rawText, QString* errorTextOut) const
    {
        // 输入：用户输入的 PID 字符串；处理：按空白/逗号/分号拆分并支持 0x 十六进制；
        // 返回：去重后的 PID 列表，失败时返回空列表并写入 errorTextOut。
        QList<quint32> pidList;
        QString normalizedText = rawText;
        normalizedText.replace(QLatin1Char(','), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char(';'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\n'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\r'), QLatin1Char(' '));
        normalizedText.replace(QLatin1Char('\t'), QLatin1Char(' '));

        const QStringList tokenList = normalizedText.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (tokenList.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.minifilter.error.empty", QStringLiteral("请输入至少一个 PID。"));
            }
            return {};
        }

        for (const QString& tokenText : tokenList)
        {
            quint32 processId = 0U;
            if (!parseUnsignedText(tokenText, &processId) || processId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.minifilter.error.invalid_pid", QStringLiteral("PID 无效：%1")).arg(tokenText);
                }
                return {};
            }
            if (!pidList.contains(processId))
            {
                pidList.append(processId);
            }
        }
        return pidList;
    }

    int findMinifilterBypassPidRow(const quint32 processId) const
    {
        // 输入：目标 PID；处理：扫描白名单表格 PID 列的 UserRole/文本；
        // 返回：命中的行号，未命中返回 -1。
        if (m_minifilterBypassPidTable == nullptr)
        {
            return -1;
        }

        for (int rowIndex = 0; rowIndex < m_minifilterBypassPidTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* pidItem =
                m_minifilterBypassPidTable->item(rowIndex, static_cast<int>(MinifilterBypassPidColumn::Pid));
            if (pidItem != nullptr && static_cast<quint32>(pidItem->data(Qt::UserRole).toUInt()) == processId)
            {
                return rowIndex;
            }
        }
        return -1;
    }

    bool appendMinifilterBypassPidRow(const quint32 processId)
    {
        // 输入：一个有效 PID；处理：跳过重复项并追加 PID/进程名只读行；
        // 返回：成功追加返回 true，重复或超限返回 false。
        if (m_minifilterBypassPidTable == nullptr ||
            processId == 0U ||
            findMinifilterBypassPidRow(processId) >= 0)
        {
            return false;
        }
        if (m_minifilterBypassPidTable->rowCount() >= static_cast<int>(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT))
        {
            return false;
        }

        const int rowIndex = m_minifilterBypassPidTable->rowCount();
        m_minifilterBypassPidTable->insertRow(rowIndex);
        QTableWidgetItem* pidItem = makeReadOnlyItem(QString::number(processId));
        pidItem->setData(Qt::UserRole, processId);
        m_minifilterBypassPidTable->setItem(rowIndex, static_cast<int>(MinifilterBypassPidColumn::Pid), pidItem);
        m_minifilterBypassPidTable->setItem(
            rowIndex,
            static_cast<int>(MinifilterBypassPidColumn::Process),
            makeReadOnlyItem(resolveProcessNameForFileMonitor(processId)));
        return true;
    }

    void addMinifilterBypassPidFromEdit()
    {
        // 输入：PID 输入框文本；处理：解析并追加到本地白名单表；
        // 返回：无；错误通过状态栏和弹窗提示。
        if (m_minifilterBypassPidEdit == nullptr)
        {
            return;
        }

        QString errorText;
        const QList<quint32> pidList = parseMinifilterBypassPidText(m_minifilterBypassPidEdit->text(), &errorText);
        if (!errorText.isEmpty())
        {
            if (m_minifilterBypassStatusLabel != nullptr)
            {
                m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.add_failed", QStringLiteral("添加失败：%1")).arg(errorText));
            }
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")), errorText);
            return;
        }

        int addedCount = 0;
        for (const quint32 processId : pidList)
        {
            if (appendMinifilterBypassPidRow(processId))
            {
                ++addedCount;
            }
        }

        if (m_minifilterBypassPidTable != nullptr &&
            m_minifilterBypassPidTable->rowCount() >= static_cast<int>(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) &&
            addedCount < static_cast<int>(pidList.size()))
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")),
                kernelText("kernel.callback.intercept.minifilter.warning.limit", QStringLiteral("白名单最多 %1 个 PID，超出的项目未添加。"))
                .arg(KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT));
        }

        if (addedCount > 0)
        {
            m_minifilterBypassPidEdit->clear();
        }
        if (m_minifilterBypassStatusLabel != nullptr)
        {
            m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.added", QStringLiteral("已添加 %1 个 PID；点击“应用到驱动”后生效。")).arg(addedCount));
        }
    }

    void removeCurrentMinifilterBypassPid()
    {
        // 输入：当前表格选择；处理：删除选中行；
        // 返回：无；删除只影响 UI，需用户点击应用下发。
        if (m_minifilterBypassPidTable == nullptr)
        {
            return;
        }

        const int rowIndex = m_minifilterBypassPidTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }

        m_minifilterBypassPidTable->removeRow(rowIndex);
        if (m_minifilterBypassStatusLabel != nullptr)
        {
            m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.removed", QStringLiteral("已移除选中 PID；点击“应用到驱动”后生效。")));
        }
    }

    std::vector<std::uint32_t> collectMinifilterBypassPidsFromUi() const
    {
        // 输入：当前白名单表格；处理：按行读取 PID 并跳过无效/重复项；
        // 返回：用于 ArkDriverClient 下发的 std::vector PID 列表。
        std::vector<std::uint32_t> processIds;
        if (m_minifilterBypassPidTable == nullptr)
        {
            return processIds;
        }

        for (int rowIndex = 0; rowIndex < m_minifilterBypassPidTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* pidItem =
                m_minifilterBypassPidTable->item(rowIndex, static_cast<int>(MinifilterBypassPidColumn::Pid));
            const quint32 processId = pidItem != nullptr
                ? static_cast<quint32>(pidItem->data(Qt::UserRole).toUInt())
                : 0U;
            if (processId == 0U)
            {
                continue;
            }
            if (std::find(processIds.cbegin(), processIds.cend(), static_cast<std::uint32_t>(processId)) == processIds.cend())
            {
                processIds.push_back(static_cast<std::uint32_t>(processId));
            }
        }
        return processIds;
    }

    void populateMinifilterBypassPids(const std::vector<std::uint32_t>& processIds)
    {
        // 输入：驱动返回或本地整理后的 PID 列表；处理：重建表格；
        // 返回：无，表格内容变为 PID 快照。
        if (m_minifilterBypassPidTable == nullptr)
        {
            return;
        }

        m_minifilterBypassPidTable->setRowCount(0);
        for (const std::uint32_t processId : processIds)
        {
            appendMinifilterBypassPidRow(static_cast<quint32>(processId));
        }
    }

    void applyMinifilterBypassPidsToDriver()
    {
        // 输入：当前白名单表格；处理：通过 ArkDriverClient 设置驱动白名单；
        // 返回：无；失败弹窗并写应用日志。
        const std::vector<std::uint32_t> processIds = collectMinifilterBypassPidsFromUi();
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult ioResult = driverClient.setMinifilterBypassPids(processIds);
        if (!ioResult.ok)
        {
            const QString detailText = callbackRuleIoMessageText(QString::fromStdString(ioResult.message));
            if (m_minifilterBypassStatusLabel != nullptr)
            {
                m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.apply_failed", QStringLiteral("应用失败：error=%1")).arg(ioResult.win32Error));
            }
            appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.apply_failed", QStringLiteral("Minifilter PID 放行应用失败：error=%1，detail=%2"))
                .arg(ioResult.win32Error)
                .arg(detailText));
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.minifilter.title", QStringLiteral("Minifilter PID 放行")),
                kernelText("kernel.callback.intercept.minifilter.error.apply_to_driver", QStringLiteral("应用到驱动失败，error=%1。")).arg(ioResult.win32Error));
            return;
        }

        if (m_minifilterBypassStatusLabel != nullptr)
        {
            m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.applied", QStringLiteral("已应用到驱动：%1 个 PID。")).arg(static_cast<qulonglong>(processIds.size())));
        }
        appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.applied", QStringLiteral("Minifilter PID 放行已应用：count=%1。")).arg(static_cast<qulonglong>(processIds.size())));
    }

    void clearMinifilterBypassPidsAndApply()
    {
        // 输入：无；处理：清空 UI 表格并立即向驱动下发空白名单；
        // 返回：无，失败时驱动状态可能仍保持原白名单。
        if (m_minifilterBypassPidTable != nullptr)
        {
            m_minifilterBypassPidTable->setRowCount(0);
        }
        applyMinifilterBypassPidsToDriver();
    }

    void refreshMinifilterBypassPidsFromDriver()
    {
        // 输入：无；处理：查询驱动当前白名单并刷新表格；
        // 返回：无；失败只更新状态栏/日志，不改变本地表格。
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::MinifilterBypassPidResult queryResult =
            driverClient.queryMinifilterBypassPids();
        if (!queryResult.io.ok)
        {
            const QString detailText = callbackRuleIoMessageText(QString::fromStdString(queryResult.io.message));
            if (m_minifilterBypassStatusLabel != nullptr)
            {
                m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.refresh_failed", QStringLiteral("刷新失败：error=%1")).arg(queryResult.io.win32Error));
            }
            appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.refresh_failed", QStringLiteral("Minifilter PID 放行刷新失败：error=%1，detail=%2"))
                .arg(queryResult.io.win32Error)
                .arg(detailText));
            return;
        }

        const unsigned long safeCount = std::min<unsigned long>(
            queryResult.response.pidCount,
            KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
        std::vector<std::uint32_t> processIds;
        processIds.reserve(static_cast<std::size_t>(safeCount));
        for (unsigned long pidIndex = 0UL; pidIndex < safeCount; ++pidIndex)
        {
            const unsigned long processId = queryResult.response.processIds[pidIndex];
            if (processId != 0UL)
            {
                processIds.push_back(static_cast<std::uint32_t>(processId));
            }
        }

        populateMinifilterBypassPids(processIds);
        if (m_minifilterBypassStatusLabel != nullptr)
        {
            m_minifilterBypassStatusLabel->setText(kernelText("kernel.callback.intercept.minifilter.status.refreshed", QStringLiteral("已从驱动刷新：%1 个 PID。")).arg(static_cast<qulonglong>(processIds.size())));
        }
        appendAppLog(kernelText("kernel.callback.intercept.minifilter.log.refreshed", QStringLiteral("Minifilter PID 放行已刷新：count=%1。")).arg(static_cast<qulonglong>(processIds.size())));
    }

    void createProcessProtectTab(QWidget* parentWidget)
    {
        // 输入：父 TabWidget；
        // 处理：搭出总开关、保护规则表、信任白名单表和统计区；
        // 返回：无，控件指针保存在成员变量中供按钮槽函数使用。
        if (m_ruleTabWidget == nullptr)
        {
            return;
        }

        auto* tabPage = new QWidget(parentWidget);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(8, 8, 8, 8);
        tabLayout->setSpacing(8);

        auto* hintLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.hint",
                QStringLiteral("命中保护规则的进程/线程句柄会在对象管理器前置回调里被削权：OpenProcess 仍然成功，但拿到的句柄不再带有被禁用的权限位。目标进程打开自己始终放行；信任项优先于保护规则。")),
            tabPage);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        tabLayout->addWidget(hintLabel, 0);

        auto* switchLayout = new QHBoxLayout();
        switchLayout->setContentsMargins(0, 0, 0, 0);
        switchLayout->setSpacing(12);
        m_processProtectEnabledCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.enabled", QStringLiteral("启用进程保护")), tabPage);
        m_processProtectLogCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.log", QStringLiteral("命中写驱动日志")), tabPage);
        m_processProtectTrustSystemCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_system", QStringLiteral("信任 System 进程")), tabPage);
        m_processProtectTrustSystemCheck->setChecked(true);
        m_processProtectTrustSystemCheck->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_system_tip",
                QStringLiteral("System(4) 负责进程创建与退出清理。关闭后这些系统路径也会被削权，可能导致进程无法正常结束。")));
        m_processProtectTrustPeersCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.trust_peers", QStringLiteral("受保护进程互信")), tabPage);
        m_processProtectKernelCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.kernel", QStringLiteral("启用内核 PP 层")), tabPage);
        m_processProtectKernelCheck->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.kernel_tip",
                QStringLiteral("把目标进程打成 PP/PPL，交给 Windows 内核在所有句柄路径上强制执行；绕过本驱动回调也依然生效。")));
        m_processProtectSelfHealCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.switch.self_heal", QStringLiteral("自愈巡检")), tabPage);
        m_processProtectSelfHealCheck->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.switch.self_heal_tip",
                QStringLiteral("周期性回读受保护进程的 Protection 字节，被外部改回时自动恢复并记一次篡改。")));
        m_processProtectScanIntervalSpin = new QSpinBox(tabPage);
        m_processProtectScanIntervalSpin->setRange(
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS),
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS));
        m_processProtectScanIntervalSpin->setSingleStep(500);
        m_processProtectScanIntervalSpin->setValue(
            static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS));
        m_processProtectScanIntervalSpin->setSuffix(
            kernelText("kernel.callback.intercept.process_protect.scan_interval_suffix", QStringLiteral(" ms")));
        m_processProtectScanIntervalSpin->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.scan_interval_tip", QStringLiteral("自愈巡检周期")));
        switchLayout->addWidget(m_processProtectEnabledCheck, 0);
        switchLayout->addWidget(m_processProtectLogCheck, 0);
        switchLayout->addWidget(m_processProtectTrustSystemCheck, 0);
        switchLayout->addWidget(m_processProtectTrustPeersCheck, 0);
        switchLayout->addWidget(m_processProtectKernelCheck, 0);
        switchLayout->addWidget(m_processProtectSelfHealCheck, 0);
        switchLayout->addWidget(m_processProtectScanIntervalSpin, 0);
        switchLayout->addStretch(1);
        m_processProtectApplyButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply", QStringLiteral("应用到驱动")), tabPage);
        m_processProtectRefreshButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.refresh", QStringLiteral("从驱动刷新")), tabPage);
        m_processProtectClearButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.clear_apply", QStringLiteral("清空并应用")), tabPage);
        switchLayout->addWidget(m_processProtectApplyButton, 0);
        switchLayout->addWidget(m_processProtectRefreshButton, 0);
        switchLayout->addWidget(m_processProtectClearButton, 0);
        ks::ui::NormalizeToolbarRow(switchLayout);
        tabLayout->addLayout(switchLayout, 0);

        auto* ruleInputLayout = new QHBoxLayout();
        ruleInputLayout->setContentsMargins(0, 0, 0, 0);
        ruleInputLayout->setSpacing(6);
        m_processProtectKindCombo = new QComboBox(tabPage);
        m_processProtectKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME));
        m_processProtectKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID));
        m_processProtectKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH));
        m_processProtectTargetEdit = new QLineEdit(tabPage);
        m_processProtectTargetEdit->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.target_placeholder",
                QStringLiteral("受保护目标：映像名 notepad.exe / PID 1234 / 完整路径 C:\\Windows\\notepad.exe")));
        applyRuleLineEditStyle(m_processProtectTargetEdit);
        m_processProtectPresetCombo = new QComboBox(tabPage);
        m_processProtectPresetCombo->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.standard", QStringLiteral("标准：结束/写内存/建线程/挂起")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_DEFAULT));
        m_processProtectPresetCombo->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.strict", QStringLiteral("严格：全部危险权限")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL));
        m_processProtectPresetCombo->addItem(
            kernelText("kernel.callback.intercept.process_protect.preset.terminate_only", QStringLiteral("仅防结束进程")),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE));
        m_processProtectThreadsCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.protect_threads", QStringLiteral("含线程句柄")), tabPage);
        m_processProtectThreadsCheck->setChecked(true);
        m_processProtectRuleNameEdit = new QLineEdit(tabPage);
        m_processProtectRuleNameEdit->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.rule_name_placeholder", QStringLiteral("规则名（可选）")));
        applyRuleLineEditStyle(m_processProtectRuleNameEdit);
        m_processProtectAddRuleButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.add_rule", QStringLiteral("添加规则")), tabPage);
        m_processProtectApplyPresetButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply_preset", QStringLiteral("套用到选中")), tabPage);
        m_processProtectRemoveRuleButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.remove_rule", QStringLiteral("移除选中")), tabPage);
        ruleInputLayout->addWidget(m_processProtectKindCombo, 0);
        ruleInputLayout->addWidget(m_processProtectTargetEdit, 2);
        ruleInputLayout->addWidget(m_processProtectPresetCombo, 0);
        ruleInputLayout->addWidget(m_processProtectThreadsCheck, 0);
        ruleInputLayout->addWidget(m_processProtectRuleNameEdit, 1);
        ruleInputLayout->addWidget(m_processProtectAddRuleButton, 0);
        ruleInputLayout->addWidget(m_processProtectApplyPresetButton, 0);
        ruleInputLayout->addWidget(m_processProtectRemoveRuleButton, 0);
        ks::ui::NormalizeToolbarRow(ruleInputLayout);
        tabLayout->addLayout(ruleInputLayout, 0);

        // 内核 PP 层的参数单独一行：它决定的是"让 Windows 自己执行保护"，
        // 与上面那行的句柄削权是两回事，混在一行容易被当成同一组开关。
        auto* kernelInputLayout = new QHBoxLayout();
        kernelInputLayout->setContentsMargins(0, 0, 0, 0);
        kernelInputLayout->setSpacing(6);
        auto* kernelLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.kernel_label", QStringLiteral("内核保护档位")), tabPage);
        kernelLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));
        m_processProtectKernelCombo = new QComboBox(tabPage);
        m_processProtectKernelCombo->addItem(
            processProtectKernelProtectionText(0U), static_cast<uint>(0U));
        {
            static const char* const signerNames[] = {
                "Authenticode", "CodeGen", "Antimalware", "Lsa", "Windows", "WinTcb", "WinSystem"
            };
            const unsigned int typeValues[] = {
                KSWORD_PS_PROTECTED_TYPE_LIGHT,
                KSWORD_PS_PROTECTED_TYPE_FULL
            };
            for (const unsigned int typeValue : typeValues)
            {
                for (unsigned int signerIndex = 0U;
                     signerIndex < (sizeof(signerNames) / sizeof(signerNames[0]));
                     ++signerIndex)
                {
                    const unsigned int protectionByte = ((signerIndex + 1U) << 4U) | typeValue;
                    m_processProtectKernelCombo->addItem(
                        processProtectKernelProtectionText(protectionByte),
                        static_cast<uint>(protectionByte));
                }
            }
        }
        m_processProtectApplyOnCreateCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.on_create", QStringLiteral("创建即用")), tabPage);
        m_processProtectApplyOnCreateCheck->setChecked(true);
        m_processProtectApplyOnCreateCheck->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.guard.on_create_tip",
                QStringLiteral("目标进程重启后，在它开始执行之前重新打上保护。")));
        m_processProtectSelfHealRuleCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.self_heal", QStringLiteral("自愈")), tabPage);
        m_processProtectSelfHealRuleCheck->setChecked(true);
        m_processProtectClearDebugPortCheck = new QCheckBox(
            kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port", QStringLiteral("清调试端口")), tabPage);
        m_processProtectClearDebugPortCheck->setToolTip(
            kernelText("kernel.callback.intercept.process_protect.guard.clear_debug_port_tip",
                QStringLiteral("清空 EPROCESS.DebugPort，让已附加的用户态调试器失去调试对象。")));
        m_processProtectApplyKernelButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.apply_kernel", QStringLiteral("套用内核档位到选中")), tabPage);
        kernelInputLayout->addWidget(kernelLabel, 0);
        kernelInputLayout->addWidget(m_processProtectKernelCombo, 0);
        kernelInputLayout->addWidget(m_processProtectApplyOnCreateCheck, 0);
        kernelInputLayout->addWidget(m_processProtectSelfHealRuleCheck, 0);
        kernelInputLayout->addWidget(m_processProtectClearDebugPortCheck, 0);
        kernelInputLayout->addWidget(m_processProtectApplyKernelButton, 0);
        kernelInputLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(kernelInputLayout);
        tabLayout->addLayout(kernelInputLayout, 0);

        m_processProtectRuleTable = new ks::ui::VisibleTableWidget(tabPage);
        // 保护规则属于编辑配置，保留页面应用/刷新动作。
        ks::ui::SetTableActionBarMode(m_processProtectRuleTable, ks::ui::TableActionBarMode::None);
        m_processProtectRuleTable->setColumnCount(static_cast<int>(ProcessProtectRuleColumn::Count));
        m_processProtectRuleTable->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.process_protect.header.enabled", QStringLiteral("启用")),
            kernelText("kernel.callback.intercept.process_protect.header.kind", QStringLiteral("匹配方式")),
            kernelText("kernel.callback.intercept.process_protect.header.target", QStringLiteral("受保护目标")),
            kernelText("kernel.callback.intercept.process_protect.header.access", QStringLiteral("拦截的权限")),
            kernelText("kernel.callback.intercept.process_protect.header.threads", QStringLiteral("含线程")),
            kernelText("kernel.callback.intercept.process_protect.header.kernel", QStringLiteral("内核保护")),
            kernelText("kernel.callback.intercept.process_protect.header.guard", QStringLiteral("守护")),
            kernelText("kernel.callback.intercept.process_protect.header.rule_name", QStringLiteral("规则名")),
            kernelText("kernel.callback.intercept.process_protect.header.hits", QStringLiteral("削权次数")),
            kernelText("kernel.callback.intercept.process_protect.header.kernel_hits", QStringLiteral("施加次数"))
            });
        m_processProtectRuleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_processProtectRuleTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_processProtectRuleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_processProtectRuleTable->setSortingEnabled(false);
        m_processProtectRuleTable->setWordWrap(false);
        m_processProtectRuleTable->verticalHeader()->setVisible(false);
        m_processProtectRuleTable->setAlternatingRowColors(true);
        {
            QHeaderView* ruleHeader = m_processProtectRuleTable->horizontalHeader();
            ruleHeader->setSectionResizeMode(QHeaderView::Interactive);
            ruleHeader->setStretchLastSection(false);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::Enabled), 48);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::Kind), 86);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::Target), 280);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::AccessMask), 280);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::ProtectThreads), 62);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::KernelProtection), 168);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::Guard), 190);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::RuleName), 130);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::HitCount), 76);
            m_processProtectRuleTable->setColumnWidth(static_cast<int>(ProcessProtectRuleColumn::KernelApplyCount), 76);
        }
        m_processProtectRuleTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(m_processProtectRuleTable);
        installCallbackTableCopyMenu(m_processProtectRuleTable, -1);
        tabLayout->addWidget(m_processProtectRuleTable, 3);

        auto* trustedLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.trusted_title",
                QStringLiteral("信任白名单（这些发起方打开受保护进程时不削权）")),
            tabPage);
        trustedLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));
        tabLayout->addWidget(trustedLabel, 0);

        auto* trustedInputLayout = new QHBoxLayout();
        trustedInputLayout->setContentsMargins(0, 0, 0, 0);
        trustedInputLayout->setSpacing(6);
        m_processProtectTrustedKindCombo = new QComboBox(tabPage);
        m_processProtectTrustedKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME));
        m_processProtectTrustedKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID));
        m_processProtectTrustedKindCombo->addItem(
            processProtectKindText(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH),
            static_cast<uint>(KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH));
        m_processProtectTrustedTargetEdit = new QLineEdit(tabPage);
        m_processProtectTrustedTargetEdit->setPlaceholderText(
            kernelText("kernel.callback.intercept.process_protect.trusted_placeholder",
                QStringLiteral("信任的发起方：映像名 / PID / 完整路径")));
        applyRuleLineEditStyle(m_processProtectTrustedTargetEdit);
        m_processProtectTrustedAddButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.trusted_add", QStringLiteral("添加信任")), tabPage);
        m_processProtectTrustedRemoveButton = new QPushButton(
            kernelText("kernel.callback.intercept.process_protect.trusted_remove", QStringLiteral("移除选中")), tabPage);
        trustedInputLayout->addWidget(m_processProtectTrustedKindCombo, 0);
        trustedInputLayout->addWidget(m_processProtectTrustedTargetEdit, 1);
        trustedInputLayout->addWidget(m_processProtectTrustedAddButton, 0);
        trustedInputLayout->addWidget(m_processProtectTrustedRemoveButton, 0);
        ks::ui::NormalizeToolbarRow(trustedInputLayout);
        tabLayout->addLayout(trustedInputLayout, 0);

        m_processProtectTrustedTable = new ks::ui::VisibleTableWidget(tabPage);
        // 受信发起方的小配置列表不需要快照工具条。
        ks::ui::SetTableActionBarMode(m_processProtectTrustedTable, ks::ui::TableActionBarMode::None);
        m_processProtectTrustedTable->setColumnCount(static_cast<int>(ProcessProtectTrustedColumn::Count));
        m_processProtectTrustedTable->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.process_protect.header.kind", QStringLiteral("匹配方式")),
            kernelText("kernel.callback.intercept.process_protect.header.trusted_target", QStringLiteral("信任的发起方"))
            });
        m_processProtectTrustedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_processProtectTrustedTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_processProtectTrustedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_processProtectTrustedTable->setSortingEnabled(false);
        m_processProtectTrustedTable->setWordWrap(false);
        m_processProtectTrustedTable->verticalHeader()->setVisible(false);
        m_processProtectTrustedTable->horizontalHeader()->setSectionResizeMode(
            static_cast<int>(ProcessProtectTrustedColumn::Kind), QHeaderView::ResizeToContents);
        m_processProtectTrustedTable->horizontalHeader()->setSectionResizeMode(
            static_cast<int>(ProcessProtectTrustedColumn::Target), QHeaderView::Stretch);
        m_processProtectTrustedTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(m_processProtectTrustedTable);
        installCallbackTableCopyMenu(m_processProtectTrustedTable, -1);
        tabLayout->addWidget(m_processProtectTrustedTable, 1);

        m_processProtectStatusLabel = new QLabel(
            kernelText("kernel.callback.intercept.process_protect.status.not_refreshed",
                QStringLiteral("尚未从驱动刷新；编辑后点击“应用到驱动”生效。")),
            tabPage);
        m_processProtectStatusLabel->setWordWrap(true);
        m_processProtectStatusLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        tabLayout->addWidget(m_processProtectStatusLabel, 0);

        m_ruleTabWidget->addTab(
            tabPage,
            kernelText("kernel.callback.intercept.process_protect.tab", QStringLiteral("进程保护")));
    }

    QTableWidgetItem* makeProcessProtectCheckItem(const bool checkedState) const
    {
        auto* checkItem = new QTableWidgetItem();
        checkItem->setFlags((checkItem->flags() & ~Qt::ItemIsEditable) | Qt::ItemIsUserCheckable);
        checkItem->setCheckState(checkedState ? Qt::Checked : Qt::Unchecked);
        return checkItem;
    }

    bool appendProcessProtectRuleRow(
        const quint32 targetKind,
        const quint32 targetProcessId,
        const QString& targetImageText,
        const quint32 accessMask,
        const bool protectThreads,
        const bool ruleEnabled,
        const QString& ruleNameText,
        const qint64 hitCount,
        const quint32 kernelProtection,
        const quint32 guardRuleFlags,
        const quint32 hardenFlags,
        const qint64 kernelApplyCount)
    {
        // 输入：一条完整的保护规则；处理：查重后追加只读行，勾选列可直接点选；
        // 返回：成功追加返回 true，重复或超限返回 false。
        if (m_processProtectRuleTable == nullptr)
        {
            return false;
        }
        if (m_processProtectRuleTable->rowCount() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES))
        {
            return false;
        }

        const QString targetText = (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            ? QString::number(targetProcessId)
            : targetImageText;
        for (int rowIndex = 0; rowIndex < m_processProtectRuleTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Kind));
            const QTableWidgetItem* targetItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Target));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }
            if (static_cast<quint32>(kindItem->data(Qt::UserRole).toUInt()) == targetKind &&
                targetItem->text().compare(targetText, Qt::CaseInsensitive) == 0)
            {
                return false;
            }
        }

        const int rowIndex = m_processProtectRuleTable->rowCount();
        m_processProtectRuleTable->insertRow(rowIndex);

        m_processProtectRuleTable->setItem(
            rowIndex, static_cast<int>(ProcessProtectRuleColumn::Enabled), makeProcessProtectCheckItem(ruleEnabled));

        QTableWidgetItem* kindItem = makeReadOnlyItem(processProtectKindText(targetKind));
        kindItem->setData(Qt::UserRole, targetKind);
        m_processProtectRuleTable->setItem(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Kind), kindItem);

        QTableWidgetItem* targetItem = makeReadOnlyItem(targetText);
        targetItem->setData(Qt::UserRole, targetProcessId);
        targetItem->setToolTip(targetText);
        m_processProtectRuleTable->setItem(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Target), targetItem);

        QTableWidgetItem* accessItem = makeReadOnlyItem(processProtectAccessSummaryText(accessMask));
        accessItem->setData(Qt::UserRole, accessMask);
        m_processProtectRuleTable->setItem(rowIndex, static_cast<int>(ProcessProtectRuleColumn::AccessMask), accessItem);

        m_processProtectRuleTable->setItem(
            rowIndex, static_cast<int>(ProcessProtectRuleColumn::ProtectThreads), makeProcessProtectCheckItem(protectThreads));

        QTableWidgetItem* kernelItem = makeReadOnlyItem(processProtectKernelProtectionText(kernelProtection));
        kernelItem->setData(Qt::UserRole, kernelProtection);
        m_processProtectRuleTable->setItem(
            rowIndex, static_cast<int>(ProcessProtectRuleColumn::KernelProtection), kernelItem);

        // 守护列同时承载规则标志与加固标志：UserRole 存规则位，UserRole+1 存加固位。
        QTableWidgetItem* guardItem =
            makeReadOnlyItem(processProtectGuardSummaryText(guardRuleFlags, hardenFlags));
        guardItem->setData(Qt::UserRole, guardRuleFlags);
        guardItem->setData(Qt::UserRole + 1, hardenFlags);
        m_processProtectRuleTable->setItem(
            rowIndex, static_cast<int>(ProcessProtectRuleColumn::Guard), guardItem);

        m_processProtectRuleTable->setItem(
            rowIndex, static_cast<int>(ProcessProtectRuleColumn::RuleName), makeReadOnlyItem(ruleNameText));

        m_processProtectRuleTable->setItem(
            rowIndex,
            static_cast<int>(ProcessProtectRuleColumn::HitCount),
            makeReadOnlyItem(hitCount >= 0 ? QString::number(hitCount) : QStringLiteral("-")));
        m_processProtectRuleTable->setItem(
            rowIndex,
            static_cast<int>(ProcessProtectRuleColumn::KernelApplyCount),
            makeReadOnlyItem(kernelApplyCount >= 0 ? QString::number(kernelApplyCount) : QStringLiteral("-")));
        return true;
    }

    // collectProcessProtectKernelInputs：
    // - 输入：内核档位下拉框与三个守护勾选；
    // - 处理：读出 PS_PROTECTION 字节、规则守护位与加固位；
    // - 返回：无；三个 out 参数在控件缺失时保持 0。
    void collectProcessProtectKernelInputs(
        quint32* const kernelProtectionOut,
        quint32* const guardRuleFlagsOut,
        quint32* const hardenFlagsOut) const
    {
        if (kernelProtectionOut != nullptr)
        {
            *kernelProtectionOut = m_processProtectKernelCombo != nullptr
                ? static_cast<quint32>(m_processProtectKernelCombo->currentData().toUInt())
                : 0U;
        }
        if (guardRuleFlagsOut != nullptr)
        {
            quint32 guardFlags = 0U;
            if (m_processProtectApplyOnCreateCheck != nullptr && m_processProtectApplyOnCreateCheck->isChecked())
            {
                guardFlags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE;
            }
            if (m_processProtectSelfHealRuleCheck != nullptr && m_processProtectSelfHealRuleCheck->isChecked())
            {
                guardFlags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL;
            }
            *guardRuleFlagsOut = guardFlags;
        }
        if (hardenFlagsOut != nullptr)
        {
            *hardenFlagsOut =
                (m_processProtectClearDebugPortCheck != nullptr && m_processProtectClearDebugPortCheck->isChecked())
                ? KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT
                : 0U;
        }
    }

    void applyProcessProtectKernelPresetToSelection()
    {
        // 输入：当前选中行与内核档位控件；处理：改写该行的内核保护与守护列；
        // 返回：无；改动只作用于 UI，需点击应用下发。
        if (m_processProtectRuleTable == nullptr)
        {
            return;
        }
        const int rowIndex = m_processProtectRuleTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }

        quint32 kernelProtection = 0U;
        quint32 guardRuleFlags = 0U;
        quint32 hardenFlags = 0U;
        collectProcessProtectKernelInputs(&kernelProtection, &guardRuleFlags, &hardenFlags);

        QTableWidgetItem* kernelItem =
            m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::KernelProtection));
        if (kernelItem != nullptr)
        {
            kernelItem->setText(processProtectKernelProtectionText(kernelProtection));
            kernelItem->setData(Qt::UserRole, kernelProtection);
        }
        QTableWidgetItem* guardItem =
            m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Guard));
        if (guardItem != nullptr)
        {
            guardItem->setText(processProtectGuardSummaryText(guardRuleFlags, hardenFlags));
            guardItem->setData(Qt::UserRole, guardRuleFlags);
            guardItem->setData(Qt::UserRole + 1, hardenFlags);
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.kernel_preset_applied",
                QStringLiteral("已套用内核档位到选中规则；点击“应用到驱动”后生效。")));
    }

    bool appendProcessProtectTrustedRow(
        const quint32 targetKind,
        const quint32 processId,
        const QString& imageText)
    {
        if (m_processProtectTrustedTable == nullptr)
        {
            return false;
        }
        if (m_processProtectTrustedTable->rowCount() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED))
        {
            return false;
        }

        const QString targetText = (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            ? QString::number(processId)
            : imageText;
        for (int rowIndex = 0; rowIndex < m_processProtectTrustedTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                m_processProtectTrustedTable->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Kind));
            const QTableWidgetItem* targetItem =
                m_processProtectTrustedTable->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Target));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }
            if (static_cast<quint32>(kindItem->data(Qt::UserRole).toUInt()) == targetKind &&
                targetItem->text().compare(targetText, Qt::CaseInsensitive) == 0)
            {
                return false;
            }
        }

        const int rowIndex = m_processProtectTrustedTable->rowCount();
        m_processProtectTrustedTable->insertRow(rowIndex);

        QTableWidgetItem* kindItem = makeReadOnlyItem(processProtectKindText(targetKind));
        kindItem->setData(Qt::UserRole, targetKind);
        m_processProtectTrustedTable->setItem(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Kind), kindItem);

        QTableWidgetItem* targetItem = makeReadOnlyItem(targetText);
        targetItem->setData(Qt::UserRole, processId);
        targetItem->setToolTip(targetText);
        m_processProtectTrustedTable->setItem(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Target), targetItem);
        return true;
    }

    // parseProcessProtectTargetInput：
    // - 输入：匹配方式与用户输入文本；
    // - 处理：PID 方式要求可解析成非零数值，映像方式要求非空；
    // - 返回：解析成功返回 true 并写出 PID/映像文本，失败写出错误说明。
    bool parseProcessProtectTargetInput(
        const quint32 targetKind,
        const QString& rawText,
        quint32* processIdOut,
        QString* imageTextOut,
        QString* errorTextOut) const
    {
        const QString trimmedText = rawText.trimmed();
        if (processIdOut != nullptr)
        {
            *processIdOut = 0U;
        }
        if (imageTextOut != nullptr)
        {
            imageTextOut->clear();
        }

        if (trimmedText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.empty_target", QStringLiteral("请输入受保护目标。"));
            }
            return false;
        }

        if (targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
        {
            quint32 processId = 0U;
            if (!parseUnsignedText(trimmedText, &processId) || processId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.invalid_pid", QStringLiteral("PID 无效：%1")).arg(trimmedText);
                }
                return false;
            }
            if (processIdOut != nullptr)
            {
                *processIdOut = processId;
            }
            return true;
        }

        if (trimmedText.size() >= static_cast<int>(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.process_protect.error.target_too_long", QStringLiteral("目标文本超过 %1 个字符。"))
                    .arg(KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS - 1U);
            }
            return false;
        }
        if (imageTextOut != nullptr)
        {
            *imageTextOut = trimmedText;
        }
        return true;
    }

    void addProcessProtectRuleFromInput()
    {
        if (m_processProtectKindCombo == nullptr ||
            m_processProtectTargetEdit == nullptr ||
            m_processProtectPresetCombo == nullptr)
        {
            return;
        }

        const quint32 targetKind = static_cast<quint32>(m_processProtectKindCombo->currentData().toUInt());
        quint32 processId = 0U;
        QString imageText;
        QString errorText;
        if (!parseProcessProtectTargetInput(targetKind, m_processProtectTargetEdit->text(), &processId, &imageText, &errorText))
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                errorText);
            return;
        }

        const quint32 accessMask = static_cast<quint32>(m_processProtectPresetCombo->currentData().toUInt());
        const QString ruleNameText = m_processProtectRuleNameEdit != nullptr
            ? m_processProtectRuleNameEdit->text().trimmed().left(KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS - 1U)
            : QString();
        const bool protectThreads = m_processProtectThreadsCheck != nullptr && m_processProtectThreadsCheck->isChecked();
        quint32 kernelProtection = 0U;
        quint32 guardRuleFlags = 0U;
        quint32 hardenFlags = 0U;
        collectProcessProtectKernelInputs(&kernelProtection, &guardRuleFlags, &hardenFlags);

        if (!appendProcessProtectRuleRow(
                targetKind,
                processId,
                imageText,
                accessMask,
                protectThreads,
                true,
                ruleNameText,
                -1,
                kernelProtection,
                guardRuleFlags,
                hardenFlags,
                -1))
        {
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.add_rejected",
                    QStringLiteral("规则未添加：目标重复或已达上限 %1 条。")).arg(KSWORD_ARK_PROCESS_PROTECT_MAX_RULES));
            return;
        }

        m_processProtectTargetEdit->clear();
        if (m_processProtectRuleNameEdit != nullptr)
        {
            m_processProtectRuleNameEdit->clear();
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.rule_added",
                QStringLiteral("已添加规则；点击“应用到驱动”后生效。")));
    }

    void removeCurrentProcessProtectRule()
    {
        if (m_processProtectRuleTable == nullptr)
        {
            return;
        }
        const int rowIndex = m_processProtectRuleTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }
        m_processProtectRuleTable->removeRow(rowIndex);
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.rule_removed",
                QStringLiteral("已移除选中规则；点击“应用到驱动”后生效。")));
    }

    void applyProcessProtectPresetToSelection()
    {
        // 输入：当前选中行与预设下拉框；处理：改写该行的权限掩码与线程开关；
        // 返回：无；改动只作用于 UI，需点击应用下发。
        if (m_processProtectRuleTable == nullptr || m_processProtectPresetCombo == nullptr)
        {
            return;
        }
        const int rowIndex = m_processProtectRuleTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }

        const quint32 accessMask = static_cast<quint32>(m_processProtectPresetCombo->currentData().toUInt());
        QTableWidgetItem* accessItem =
            m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::AccessMask));
        if (accessItem != nullptr)
        {
            accessItem->setText(processProtectAccessSummaryText(accessMask));
            accessItem->setData(Qt::UserRole, accessMask);
        }
        QTableWidgetItem* threadItem =
            m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::ProtectThreads));
        if (threadItem != nullptr && m_processProtectThreadsCheck != nullptr)
        {
            threadItem->setCheckState(m_processProtectThreadsCheck->isChecked() ? Qt::Checked : Qt::Unchecked);
        }
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.preset_applied",
                QStringLiteral("已套用预设到选中规则；点击“应用到驱动”后生效。")));
    }

    void addProcessProtectTrustedFromInput()
    {
        if (m_processProtectTrustedKindCombo == nullptr || m_processProtectTrustedTargetEdit == nullptr)
        {
            return;
        }

        const quint32 targetKind = static_cast<quint32>(m_processProtectTrustedKindCombo->currentData().toUInt());
        quint32 processId = 0U;
        QString imageText;
        QString errorText;
        if (!parseProcessProtectTargetInput(targetKind, m_processProtectTrustedTargetEdit->text(), &processId, &imageText, &errorText))
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                errorText);
            return;
        }

        if (!appendProcessProtectTrustedRow(targetKind, processId, imageText))
        {
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.trusted_rejected",
                    QStringLiteral("信任项未添加：重复或已达上限 %1 条。")).arg(KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED));
            return;
        }

        m_processProtectTrustedTargetEdit->clear();
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.trusted_added",
                QStringLiteral("已添加信任项；点击“应用到驱动”后生效。")));
    }

    void removeCurrentProcessProtectTrusted()
    {
        if (m_processProtectTrustedTable == nullptr)
        {
            return;
        }
        const int rowIndex = m_processProtectTrustedTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }
        m_processProtectTrustedTable->removeRow(rowIndex);
        setProcessProtectStatusText(
            kernelText("kernel.callback.intercept.process_protect.status.trusted_removed",
                QStringLiteral("已移除选中信任项；点击“应用到驱动”后生效。")));
    }

    quint32 collectProcessProtectGlobalFlags() const
    {
        quint32 globalFlags = 0U;
        if (m_processProtectEnabledCheck != nullptr && m_processProtectEnabledCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED;
        }
        if (m_processProtectLogCheck != nullptr && m_processProtectLogCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED;
        }
        if (m_processProtectTrustSystemCheck != nullptr && m_processProtectTrustSystemCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM;
        }
        if (m_processProtectTrustPeersCheck != nullptr && m_processProtectTrustPeersCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS;
        }
        if (m_processProtectKernelCheck != nullptr && m_processProtectKernelCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION;
        }
        if (m_processProtectSelfHealCheck != nullptr && m_processProtectSelfHealCheck->isChecked())
        {
            globalFlags |= KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN;
        }
        return globalFlags;
    }

    std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> collectProcessProtectRulesFromUi() const
    {
        // 输入：规则表格；处理：逐行装配共享协议行，ruleId 按行序重新编号；
        // 返回：可直接交给 ArkDriverClient 的规则数组。
        std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> ruleList;
        if (m_processProtectRuleTable == nullptr)
        {
            return ruleList;
        }

        for (int rowIndex = 0; rowIndex < m_processProtectRuleTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* enabledItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Enabled));
            const QTableWidgetItem* kindItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Kind));
            const QTableWidgetItem* targetItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Target));
            const QTableWidgetItem* accessItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::AccessMask));
            const QTableWidgetItem* threadItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::ProtectThreads));
            const QTableWidgetItem* nameItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::RuleName));
            const QTableWidgetItem* kernelItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::KernelProtection));
            const QTableWidgetItem* guardItem =
                m_processProtectRuleTable->item(rowIndex, static_cast<int>(ProcessProtectRuleColumn::Guard));
            if (kindItem == nullptr || targetItem == nullptr || accessItem == nullptr)
            {
                continue;
            }

            KSWORD_ARK_PROCESS_PROTECT_RULE protectRule{};
            protectRule.ruleId = static_cast<unsigned long>(rowIndex) + 1UL;
            protectRule.targetKind = static_cast<unsigned long>(kindItem->data(Qt::UserRole).toUInt());
            protectRule.protectAccessMask = static_cast<unsigned long>(accessItem->data(Qt::UserRole).toUInt());
            protectRule.kernelProtection = kernelItem != nullptr
                ? static_cast<unsigned long>(kernelItem->data(Qt::UserRole).toUInt())
                : 0UL;
            protectRule.hardenFlags = guardItem != nullptr
                ? static_cast<unsigned long>(guardItem->data(Qt::UserRole + 1).toUInt())
                : 0UL;
            if (guardItem != nullptr)
            {
                protectRule.flags |= static_cast<unsigned long>(guardItem->data(Qt::UserRole).toUInt());
            }
            if (enabledItem != nullptr && enabledItem->checkState() == Qt::Checked)
            {
                protectRule.flags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED;
            }
            if (threadItem != nullptr && threadItem->checkState() == Qt::Checked)
            {
                protectRule.flags |= KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS;
            }
            if (protectRule.targetKind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            {
                protectRule.targetProcessId = static_cast<unsigned long>(targetItem->data(Qt::UserRole).toUInt());
            }
            else
            {
                processProtectCopyQStringToFixedWide(
                    targetItem->text(), protectRule.targetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            }
            processProtectCopyQStringToFixedWide(
                nameItem != nullptr ? nameItem->text() : QString(),
                protectRule.ruleName,
                KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS);

            ruleList.push_back(protectRule);
        }
        return ruleList;
    }

    std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> collectProcessProtectTrustedFromUi() const
    {
        std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> trustedList;
        if (m_processProtectTrustedTable == nullptr)
        {
            return trustedList;
        }

        for (int rowIndex = 0; rowIndex < m_processProtectTrustedTable->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* kindItem =
                m_processProtectTrustedTable->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Kind));
            const QTableWidgetItem* targetItem =
                m_processProtectTrustedTable->item(rowIndex, static_cast<int>(ProcessProtectTrustedColumn::Target));
            if (kindItem == nullptr || targetItem == nullptr)
            {
                continue;
            }

            KSWORD_ARK_PROCESS_PROTECT_TRUSTED trustedEntry{};
            trustedEntry.flags = KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED;
            trustedEntry.kind = static_cast<unsigned long>(kindItem->data(Qt::UserRole).toUInt());
            if (trustedEntry.kind == KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID)
            {
                trustedEntry.processId = static_cast<unsigned long>(targetItem->data(Qt::UserRole).toUInt());
            }
            else
            {
                processProtectCopyQStringToFixedWide(
                    targetItem->text(), trustedEntry.image, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            }
            trustedList.push_back(trustedEntry);
        }
        return trustedList;
    }

    void setProcessProtectStatusText(const QString& statusText)
    {
        if (m_processProtectStatusLabel != nullptr)
        {
            m_processProtectStatusLabel->setText(statusText);
        }
    }

    void applyProcessProtectToDriver()
    {
        // 输入：当前表格与开关；处理：整表下发到 R0；
        // 返回：无；成功后立即回读一次，让统计与能力状态与驱动对齐。
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE> ruleList = collectProcessProtectRulesFromUi();
        const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED> trustedList = collectProcessProtectTrustedFromUi();
        const quint32 globalFlags = collectProcessProtectGlobalFlags();

        const unsigned long scanIntervalMs = m_processProtectScanIntervalSpin != nullptr
            ? static_cast<unsigned long>(m_processProtectScanIntervalSpin->value())
            : KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult ioResult =
            driverClient.setProcessProtectConfig(globalFlags, ruleList, trustedList, scanIntervalMs);
        if (!ioResult.ok)
        {
            const QString detailText = callbackRuleIoMessageText(QString::fromStdString(ioResult.message));
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.apply_failed", QStringLiteral("应用失败：error=%1"))
                .arg(ioResult.win32Error));
            appendAppLog(
                kernelText("kernel.callback.intercept.process_protect.log.apply_failed", QStringLiteral("进程保护配置应用失败：error=%1，detail=%2"))
                .arg(ioResult.win32Error)
                .arg(detailText));
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.process_protect.title", QStringLiteral("进程保护")),
                kernelText("kernel.callback.intercept.process_protect.error.apply_to_driver", QStringLiteral("应用到驱动失败，error=%1。"))
                .arg(ioResult.win32Error));
            return;
        }

        appendAppLog(
            kernelText("kernel.callback.intercept.process_protect.log.applied", QStringLiteral("进程保护配置已应用：rules=%1，trusted=%2，flags=0x%3。"))
            .arg(static_cast<qulonglong>(ruleList.size()))
            .arg(static_cast<qulonglong>(trustedList.size()))
            .arg(globalFlags, 8, 16, QChar('0')));
        refreshProcessProtectFromDriver();
    }

    void clearProcessProtectAndApply()
    {
        if (m_processProtectRuleTable != nullptr)
        {
            m_processProtectRuleTable->setRowCount(0);
        }
        if (m_processProtectTrustedTable != nullptr)
        {
            m_processProtectTrustedTable->setRowCount(0);
        }
        if (m_processProtectEnabledCheck != nullptr)
        {
            m_processProtectEnabledCheck->setChecked(false);
        }
        applyProcessProtectToDriver();
    }

    void refreshProcessProtectFromDriver()
    {
        // 输入：无；处理：回读 R0 当前配置并重建两张表；
        // 返回：无；失败只更新状态栏与日志，不清空本地编辑内容。
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessProtectStateResult queryResult = driverClient.queryProcessProtectState();
        if (!queryResult.io.ok)
        {
            const QString detailText = callbackRuleIoMessageText(QString::fromStdString(queryResult.io.message));
            setProcessProtectStatusText(
                kernelText("kernel.callback.intercept.process_protect.status.refresh_failed", QStringLiteral("刷新失败：error=%1"))
                .arg(queryResult.io.win32Error));
            appendAppLog(
                kernelText("kernel.callback.intercept.process_protect.log.refresh_failed", QStringLiteral("进程保护状态刷新失败：error=%1，detail=%2"))
                .arg(queryResult.io.win32Error)
                .arg(detailText));
            return;
        }

        const KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE& stateResponse = queryResult.response;
        if (m_processProtectEnabledCheck != nullptr)
        {
            m_processProtectEnabledCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED) != 0U);
        }
        if (m_processProtectLogCheck != nullptr)
        {
            m_processProtectLogCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED) != 0U);
        }
        if (m_processProtectTrustSystemCheck != nullptr)
        {
            m_processProtectTrustSystemCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM) != 0U);
        }
        if (m_processProtectTrustPeersCheck != nullptr)
        {
            m_processProtectTrustPeersCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS) != 0U);
        }
        if (m_processProtectKernelCheck != nullptr)
        {
            m_processProtectKernelCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION) != 0U);
        }
        if (m_processProtectSelfHealCheck != nullptr)
        {
            m_processProtectSelfHealCheck->setChecked((stateResponse.globalFlags & KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN) != 0U);
        }
        if (m_processProtectScanIntervalSpin != nullptr && stateResponse.scanIntervalMs != 0U)
        {
            m_processProtectScanIntervalSpin->setValue(static_cast<int>(stateResponse.scanIntervalMs));
        }

        if (m_processProtectRuleTable != nullptr)
        {
            m_processProtectRuleTable->setRowCount(0);
        }
        const unsigned long safeRuleCount =
            std::min<unsigned long>(stateResponse.ruleCount, KSWORD_ARK_PROCESS_PROTECT_MAX_RULES);
        for (unsigned long ruleIndex = 0UL; ruleIndex < safeRuleCount; ++ruleIndex)
        {
            const KSWORD_ARK_PROCESS_PROTECT_RULE& protectRule = stateResponse.rules[ruleIndex];
            appendProcessProtectRuleRow(
                static_cast<quint32>(protectRule.targetKind),
                static_cast<quint32>(protectRule.targetProcessId),
                processProtectFixedWideToQString(protectRule.targetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS),
                static_cast<quint32>(protectRule.protectAccessMask),
                (protectRule.flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS) != 0UL,
                (protectRule.flags & KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED) != 0UL,
                processProtectFixedWideToQString(protectRule.ruleName, KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS),
                static_cast<qint64>(stateResponse.ruleHitCounts[ruleIndex]),
                static_cast<quint32>(protectRule.kernelProtection),
                static_cast<quint32>(protectRule.flags &
                    (KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE |
                     KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL)),
                static_cast<quint32>(protectRule.hardenFlags),
                static_cast<qint64>(stateResponse.ruleKernelApplyCounts[ruleIndex]));
        }

        if (m_processProtectTrustedTable != nullptr)
        {
            m_processProtectTrustedTable->setRowCount(0);
        }
        const unsigned long safeTrustedCount =
            std::min<unsigned long>(stateResponse.trustedCount, KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED);
        for (unsigned long trustedIndex = 0UL; trustedIndex < safeTrustedCount; ++trustedIndex)
        {
            const KSWORD_ARK_PROCESS_PROTECT_TRUSTED& trustedEntry = stateResponse.trusted[trustedIndex];
            appendProcessProtectTrustedRow(
                static_cast<quint32>(trustedEntry.kind),
                static_cast<quint32>(trustedEntry.processId),
                processProtectFixedWideToQString(trustedEntry.image, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS));
        }

        setProcessProtectStatusText(buildProcessProtectStatusText(stateResponse));
    }

    // buildProcessProtectStatusText：
    // - 输入：R0 状态包；
    // - 处理：拼接能力状态、计数器和最近一次拦截；
    // - 返回：状态栏展示文本。
    QString buildProcessProtectStatusText(const KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE& stateResponse) const
    {
        QStringList statusParts;
        if (stateResponse.capabilityStatus == KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE)
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.callback_unavailable",
                QStringLiteral("对象回调未注册（status=0x%1），本机无法执行进程保护。"))
                .arg(static_cast<quint32>(stateResponse.objectCallbackStatus), 8, 16, QChar('0'));
        }
        else
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.summary",
                QStringLiteral("已从驱动刷新：规则 %1 条，信任 %2 条，配置版本 %3。"))
                .arg(stateResponse.ruleCount)
                .arg(stateResponse.trustedCount)
                .arg(static_cast<qulonglong>(stateResponse.configVersion));
        }

        statusParts << kernelText("kernel.callback.intercept.process_protect.status.counters",
            QStringLiteral("判定 %1 次，削权 %2 次，信任放行 %3 次。"))
            .arg(static_cast<qulonglong>(stateResponse.evaluatedCount))
            .arg(static_cast<qulonglong>(stateResponse.strippedCount))
            .arg(static_cast<qulonglong>(stateResponse.trustedBypassCount));

        statusParts << kernelText("kernel.callback.intercept.process_protect.status.kernel_counters",
            QStringLiteral("内核层：施加 %1 次，自愈 %2 次，失败 %3 次，加固 %4 次，在管进程 %5 个，巡检 %6ms。"))
            .arg(static_cast<qulonglong>(stateResponse.kernelApplyCount))
            .arg(static_cast<qulonglong>(stateResponse.selfHealCount))
            .arg(static_cast<qulonglong>(stateResponse.kernelApplyFailureCount))
            .arg(static_cast<qulonglong>(stateResponse.hardenApplyCount))
            .arg(stateResponse.trackedProcessCount)
            .arg(stateResponse.scanIntervalMs);

        if (stateResponse.lastKernelApplyStatus != 0)
        {
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.kernel_last_failure",
                QStringLiteral("最近一次施加失败 status=0x%1（通常是本机 DynData 缺少 EPROCESS 偏移）。"))
                .arg(static_cast<quint32>(stateResponse.lastKernelApplyStatus), 8, 16, QChar('0'));
        }

        if (stateResponse.lastTamperUtc100ns != 0ULL)
        {
            const QString tamperImageText =
                processProtectFixedWideToQString(stateResponse.lastTamperImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.last_tamper",
                QStringLiteral("最近一次篡改：%1 PID %2（%3）的保护被改成 0x%4，已恢复为 0x%5，规则 %6。"))
                .arg(utc100nsToDisplayText(static_cast<quint64>(stateResponse.lastTamperUtc100ns)))
                .arg(stateResponse.lastTamperProcessId)
                .arg(tamperImageText.isEmpty() ? QStringLiteral("-") : tamperImageText)
                .arg(stateResponse.lastTamperObservedProtection, 2, 16, QChar('0'))
                .arg(stateResponse.lastTamperExpectedProtection, 2, 16, QChar('0'))
                .arg(stateResponse.lastTamperRuleId);
        }

        if (stateResponse.lastBlockedUtc100ns != 0ULL)
        {
            const QString initiatorText =
                processProtectFixedWideToQString(stateResponse.lastBlockedInitiatorImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            const QString targetText =
                processProtectFixedWideToQString(stateResponse.lastBlockedTargetImage, KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS);
            statusParts << kernelText("kernel.callback.intercept.process_protect.status.last_blocked",
                QStringLiteral("最近一次：%1 发起方 PID %2（%3）访问 PID %4（%5），规则 %6，0x%7 → 0x%8。"))
                .arg(utc100nsToDisplayText(static_cast<quint64>(stateResponse.lastBlockedUtc100ns)))
                .arg(stateResponse.lastBlockedInitiatorPid)
                .arg(initiatorText.isEmpty() ? QStringLiteral("-") : initiatorText)
                .arg(stateResponse.lastBlockedTargetPid)
                .arg(targetText.isEmpty() ? QStringLiteral("-") : targetText)
                .arg(stateResponse.lastBlockedRuleId)
                .arg(stateResponse.lastBlockedOriginalAccess, 8, 16, QChar('0'))
                .arg(stateResponse.lastBlockedGrantedAccess, 8, 16, QChar('0'));
        }
        return statusParts.join(QLatin1Char(' '));
    }

    void createRuleTableTab(quint32 callbackType, const QString& titleText)
    {
        auto* tabPage = new QWidget(m_ruleTabWidget);
        auto* tabLayout = new QVBoxLayout(tabPage);
        tabLayout->setContentsMargins(0, 0, 0, 0);
        tabLayout->setSpacing(0);

        auto* ruleTable = new ks::ui::VisibleTableWidget(tabPage);
        // 六类回调规则编辑表沿用配置导入导出，不混入现场快照动作。
        ks::ui::SetTableActionBarMode(ruleTable, ks::ui::TableActionBarMode::None);
        ruleTable->setColumnCount(static_cast<int>(RuleColumn::Count));
        ruleTable->setHorizontalHeaderLabels(QStringList{
            kernelText("kernel.callback.intercept.rule.header.enabled", QStringLiteral("启用")),
            QStringLiteral("RuleID"),
            QStringLiteral("GroupID"),
            kernelText("kernel.callback.intercept.rule.header.name", QStringLiteral("规则名称")),
            kernelText("kernel.callback.intercept.rule.header.operation", QStringLiteral("操作类型")),
            kernelText("kernel.callback.intercept.rule.header.match_mode", QStringLiteral("匹配模式")),
            kernelText("kernel.callback.intercept.rule.header.action", QStringLiteral("动作")),
            kernelText("kernel.callback.intercept.rule.header.timeout_ms", QStringLiteral("超时毫秒")),
            kernelText("kernel.callback.intercept.rule.header.timeout_decision", QStringLiteral("超时决策")),
            kernelText("kernel.callback.intercept.rule.header.priority", QStringLiteral("优先级"))
            });
        ruleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        ruleTable->setSelectionMode(QAbstractItemView::SingleSelection);
        ruleTable->setEditTriggers(
            QAbstractItemView::DoubleClicked |
            QAbstractItemView::SelectedClicked |
            QAbstractItemView::EditKeyPressed);
        ruleTable->setItemDelegate(new OpaqueTableEditorDelegate(ruleTable));
        ruleTable->setProperty("ksword_preserve_custom_table_delegate", true);
        ruleTable->setSortingEnabled(false);
        ruleTable->setWordWrap(false);
        ruleTable->setContextMenuPolicy(Qt::CustomContextMenu);
        ruleTable->verticalHeader()->setVisible(false);
        ruleTable->setAlternatingRowColors(true);
        ruleTable->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        ruleTable->setStyleSheet(callbackRuleTableStyle());
        applyCallbackTableTransparency(ruleTable);

        // 表头允许用户拖动调整列宽；默认宽度优先压缩身份列，把空间留给操作和匹配字段。
        QHeaderView* ruleHeader = ruleTable->horizontalHeader();
        ruleHeader->setSectionResizeMode(QHeaderView::Interactive);
        ruleHeader->setStretchLastSection(false);
        ruleHeader->setSectionsMovable(false);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::Enabled), 42);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::RuleId), 58);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::GroupId), 96);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::RuleName), 170);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::OperationMask), 480);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::MatchMode), 104);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::Action), 104);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::TimeoutMs), 72);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::TimeoutDefaultDecision), 78);
        ruleTable->setColumnWidth(static_cast<int>(RuleColumn::Priority), 58);
        tabLayout->addWidget(ruleTable, 1);

        connect(ruleTable, &QTableWidget::itemChanged, m_hostPage, [this](QTableWidgetItem*) {
            if (m_ignoreUiSignal)
            {
                return;
            }
            setDirtyState(true);
        });
        connect(ruleTable, &QWidget::customContextMenuRequested, m_hostPage, [this, ruleTable, callbackType](const QPoint& localPos) {
            showRuleTableContextMenu(ruleTable, callbackType, localPos);
        });

        const int tabIndex = m_ruleTabWidget->addTab(tabPage, titleText);
        m_tabCallbackTypeMap.insert(tabIndex, callbackType);
        m_ruleTableMap.insert(callbackType, ruleTable);
    }

    bool collectRuleByLogicalIndex(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const int logicalRuleIndex,
        CallbackRuleModel* ruleOut,
        QString* errorTextOut) const
    {
        if (ruleOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_out_null", QStringLiteral("内部错误：ruleOut 为空。"));
            }
            return false;
        }
        if (ruleTable == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_table_null", QStringLiteral("内部错误：ruleTable 为空。"));
            }
            return false;
        }

        QList<CallbackRuleModel> ruleList;
        if (!collectRuleListFromTable(ruleTable, callbackType, &ruleList, errorTextOut))
        {
            return false;
        }
        if (logicalRuleIndex < 0 || logicalRuleIndex >= ruleList.size())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.no_selected_rule", QStringLiteral("当前未选中有效规则。"));
            }
            return false;
        }

        *ruleOut = ruleList.at(logicalRuleIndex);
        return true;
    }

    void copyCurrentRuleToClipboard(
        QTableWidget* ruleTable,
        const quint32 callbackType)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int logicalRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (logicalRuleIndex < 0)
        {
            return;
        }

        CallbackRuleModel selectedRuleModel;
        QString errorText;
        if (!collectRuleByLogicalIndex(
            ruleTable,
            callbackType,
            logicalRuleIndex,
            &selectedRuleModel,
            &errorText))
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.copy_failed", QStringLiteral("复制规则失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.copy_failed", QStringLiteral("复制规则失败：%1")).arg(errorText));
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr)
        {
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.unavailable_copy", QStringLiteral("复制规则失败：系统剪贴板不可用。")));
            return;
        }

        clipboard->setText(serializeRuleToClipboardText(selectedRuleModel));
        appendAppLog(
            kernelText("kernel.callback.intercept.clipboard.copy_success", QStringLiteral("已复制规则到剪贴板：ruleId=%1，类型=%2"))
            .arg(selectedRuleModel.ruleId)
            .arg(callbackTypeToDisplayText(callbackType)));
    }

    void pasteRuleFromClipboard(
        QTableWidget* ruleTable,
        const quint32 callbackType)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr)
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.unavailable_paste", QStringLiteral("粘贴失败：系统剪贴板不可用。")));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.unavailable_paste", QStringLiteral("粘贴失败：系统剪贴板不可用。")));
            return;
        }

        const QString clipboardText = clipboard->text().trimmed();
        if (clipboardText.isEmpty())
        {
            QMessageBox::information(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.empty", QStringLiteral("剪贴板为空，无法粘贴规则。")));
            return;
        }

        CallbackRuleModel pastedRuleModel;
        QString parseErrorText;
        if (!deserializeRuleFromClipboardText(clipboardText, &pastedRuleModel, &parseErrorText))
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.paste_failed", QStringLiteral("粘贴失败：%1")).arg(parseErrorText));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.paste_failed", QStringLiteral("粘贴失败：%1")).arg(parseErrorText));
            return;
        }

        const quint32 sourceCallbackType = pastedRuleModel.callbackType;
        pastedRuleModel.ruleId = allocateNextRuleId();
        pastedRuleModel.callbackType = callbackType;
        pastedRuleModel.initiatorPattern = normalizeMatchAllPattern(pastedRuleModel.initiatorPattern);
        pastedRuleModel.targetPattern = normalizeMatchAllPattern(pastedRuleModel.targetPattern);
        if (pastedRuleModel.ruleName.trimmed().isEmpty())
        {
            pastedRuleModel.ruleName = kernelText("kernel.callback.intercept.clipboard.default_rule_name", QStringLiteral("规则%1")).arg(pastedRuleModel.ruleId);
        }
        if (pastedRuleModel.comment.trimmed().isEmpty())
        {
            pastedRuleModel.comment = kernelText("kernel.callback.intercept.clipboard.pasted_rule_comment", QStringLiteral("粘贴规则"));
        }

        addDefaultGroupIfNeeded();
        if (!groupExists(pastedRuleModel.groupId))
        {
            pastedRuleModel.groupId = firstGroupId();
        }
        if (pastedRuleModel.groupId == 0U)
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.clipboard.no_group", QStringLiteral("粘贴失败：当前没有可用规则组。")));
            appendAppLog(kernelText("kernel.callback.intercept.clipboard.no_group", QStringLiteral("粘贴失败：当前没有可用规则组。")));
            return;
        }

        if (pastedRuleModel.operationMask == 0U)
        {
            pastedRuleModel.operationMask = defaultOperationMaskByType(callbackType);
        }

        const QList<QPair<QString, quint32>> matchModeOptionList = allowedMatchModeListByType(callbackType);
        if (!containsOptionValue(matchModeOptionList, pastedRuleModel.matchMode))
        {
            pastedRuleModel.matchMode = matchModeOptionList.isEmpty()
                ? KSWORD_ARK_MATCH_MODE_EXACT
                : matchModeOptionList.front().second;
        }

        const QList<QPair<QString, quint32>> actionOptionList = allowedActionListByType(callbackType);
        if (!containsOptionValue(actionOptionList, pastedRuleModel.action))
        {
            pastedRuleModel.action = actionOptionList.isEmpty()
                ? KSWORD_ARK_RULE_ACTION_LOG_ONLY
                : actionOptionList.front().second;
        }

        if ((callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
            callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
            pastedRuleModel.matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
            pastedRuleModel.action != KSWORD_ARK_RULE_ACTION_ASK_USER &&
            containsOptionValue(actionOptionList, KSWORD_ARK_RULE_ACTION_ASK_USER))
        {
            pastedRuleModel.action = KSWORD_ARK_RULE_ACTION_ASK_USER;
        }

        if (pastedRuleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER)
        {
            if (pastedRuleModel.timeoutMs == 0U)
            {
                pastedRuleModel.timeoutMs = 5000U;
            }
        }
        else
        {
            pastedRuleModel.timeoutMs = 0U;
        }
        if (pastedRuleModel.timeoutDefaultDecision != KSWORD_ARK_DECISION_ALLOW &&
            pastedRuleModel.timeoutDefaultDecision != KSWORD_ARK_DECISION_DENY)
        {
            pastedRuleModel.timeoutDefaultDecision = KSWORD_ARK_DECISION_ALLOW;
        }

        pastedRuleModel.priority = (ruleCountOfTable(ruleTable) + 1) * 10;

        m_ignoreUiSignal = true;
        appendRuleRow(ruleTable, callbackType, pastedRuleModel);
        m_ignoreUiSignal = false;

        const int newHeaderRow = ruleTable->rowCount() - 2;
        if (newHeaderRow >= 0)
        {
            ruleTable->setCurrentCell(newHeaderRow, static_cast<int>(RuleColumn::RuleName));
        }
        setDirtyState(true);

        if (sourceCallbackType != callbackType)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.clipboard.type_converted", QStringLiteral("剪贴板规则类型已转换：%1 -> %2"))
                .arg(callbackTypeToDisplayText(sourceCallbackType))
                .arg(callbackTypeToDisplayText(callbackType)));
        }
        appendAppLog(kernelText("kernel.callback.intercept.clipboard.paste_success", QStringLiteral("已从剪贴板粘贴规则：newRuleId=%1")).arg(pastedRuleModel.ruleId));
    }

    void showRuleTableContextMenu(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const QPoint& localPos)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int clickedRow = ruleTable->rowAt(localPos.y());
        if (clickedRow >= 0)
        {
            const int headerRow = normalizeRuleHeaderRow(clickedRow);
            if (headerRow >= 0)
            {
                ruleTable->setCurrentCell(headerRow, static_cast<int>(RuleColumn::RuleName));
            }
        }

        const int logicalRuleIndex = currentRuleLogicalIndex(ruleTable);
        const int ruleCount = ruleCountOfTable(ruleTable);
        const bool hasCurrentRule = (logicalRuleIndex >= 0 && logicalRuleIndex < ruleCount);

        QMenu contextMenu(ruleTable);
        contextMenu.setStyleSheet(callbackRuleContextMenuStyle());
        QAction* addRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/plus.svg")),
            kernelText("kernel.callback.intercept.context_menu.add_rule", QStringLiteral("新增规则")));
        QAction* removeRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/log_clear.svg")),
            kernelText("kernel.callback.intercept.context_menu.remove_rule", QStringLiteral("删除当前规则")));
        QAction* moveUpRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/file_nav_up.svg")),
            kernelText("kernel.callback.intercept.context_menu.move_up", QStringLiteral("上移当前规则")));
        QAction* moveDownRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/codeeditor_goto.svg")),
            kernelText("kernel.callback.intercept.context_menu.move_down", QStringLiteral("下移当前规则")));
        contextMenu.addSeparator();
        QAction* copyRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.callback.intercept.context_menu.copy_rule", QStringLiteral("复制规则文本")));
        QAction* pasteRuleAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/codeeditor_paste.svg")),
            kernelText("kernel.callback.intercept.context_menu.paste_rule", QStringLiteral("粘贴为新规则")));

        removeRuleAction->setEnabled(hasCurrentRule);
        moveUpRuleAction->setEnabled(hasCurrentRule && logicalRuleIndex > 0);
        moveDownRuleAction->setEnabled(hasCurrentRule && logicalRuleIndex < (ruleCount - 1));
        copyRuleAction->setEnabled(hasCurrentRule);
        pasteRuleAction->setEnabled(QApplication::clipboard() != nullptr &&
            !QApplication::clipboard()->text().trimmed().isEmpty());

        QAction* selectedAction = contextMenu.exec(ruleTable->viewport()->mapToGlobal(localPos));
        if (selectedAction == nullptr)
        {
            return;
        }

        if (m_ruleTabWidget != nullptr)
        {
            const int tabIndex = m_tabCallbackTypeMap.key(callbackType, -1);
            if (tabIndex >= 0 && tabIndex != m_ruleTabWidget->currentIndex())
            {
                m_ruleTabWidget->setCurrentIndex(tabIndex);
            }
        }

        if (selectedAction == addRuleAction)
        {
            addRuleToCurrentTab();
            return;
        }
        if (selectedAction == removeRuleAction)
        {
            removeCurrentRule();
            return;
        }
        if (selectedAction == moveUpRuleAction)
        {
            moveCurrentRule(-1);
            return;
        }
        if (selectedAction == moveDownRuleAction)
        {
            moveCurrentRule(1);
            return;
        }
        if (selectedAction == copyRuleAction)
        {
            copyCurrentRuleToClipboard(ruleTable, callbackType);
            return;
        }
        if (selectedAction == pasteRuleAction)
        {
            pasteRuleFromClipboard(ruleTable, callbackType);
            return;
        }
    }

    void addDefaultGroupIfNeeded()
    {
        if (m_groupTable->rowCount() > 0)
        {
            return;
        }

        CallbackRuleGroupModel defaultGroup;
        defaultGroup.groupId = 1U;
        defaultGroup.groupName = kernelText("kernel.callback.intercept.default_group.name", QStringLiteral("默认组"));
        defaultGroup.enabled = true;
        defaultGroup.priority = 10;
        defaultGroup.comment = kernelText("kernel.callback.intercept.default_group.comment", QStringLiteral("默认规则组"));
        appendGroupRow(defaultGroup);
        m_groupTable->setCurrentCell(0, static_cast<int>(GroupColumn::Name));
    }

    void appendGroupRow(const CallbackRuleGroupModel& groupModel)
    {
        const int rowIndex = m_groupTable->rowCount();
        m_groupTable->insertRow(rowIndex);

        m_groupTable->setItem(rowIndex, static_cast<int>(GroupColumn::Id), makeReadOnlyItem(QString::number(groupModel.groupId)));
        m_groupTable->setItem(rowIndex, static_cast<int>(GroupColumn::Name), new QTableWidgetItem(groupModel.groupName));

        auto* enabledItem = new QTableWidgetItem();
        enabledItem->setFlags(enabledItem->flags() | Qt::ItemIsUserCheckable);
        enabledItem->setCheckState(groupModel.enabled ? Qt::Checked : Qt::Unchecked);
        m_groupTable->setItem(rowIndex, static_cast<int>(GroupColumn::Enabled), enabledItem);

        m_groupTable->setItem(rowIndex, static_cast<int>(GroupColumn::Priority), new QTableWidgetItem(QString::number(groupModel.priority)));
        m_groupTable->setItem(rowIndex, static_cast<int>(GroupColumn::Comment), new QTableWidgetItem(groupModel.comment));
    }

    void setDirtyState(const bool dirtyState)
    {
        m_dirty = dirtyState;
        updateStatusLabel();
    }

    void appendAppLog(const QString& logText)
    {
        if (m_appLogEditor == nullptr)
        {
            return;
        }
        const QString lineText = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(logText);
        m_appLogEditor->appendPlainText(lineText);
    }

    void appendEventLog(const QString& logText)
    {
        if (m_eventLogEditor == nullptr)
        {
            return;
        }
        const QString lineText = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(logText);
        m_eventLogEditor->appendPlainText(lineText);
    }

    quint32 allocateNextGroupId() const
    {
        quint32 maxGroupId = 0U;
        for (int rowIndex = 0; rowIndex < m_groupTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 groupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &groupId))
            {
                maxGroupId = std::max(maxGroupId, groupId);
            }
        }
        return maxGroupId + 1U;
    }

    quint32 allocateNextRuleId() const
    {
        quint32 maxRuleId = 0U;
        for (auto iterator = m_ruleTableMap.begin(); iterator != m_ruleTableMap.end(); ++iterator)
        {
            const QTableWidget* ruleTable = iterator.value();
            if (ruleTable == nullptr)
            {
                continue;
            }
            for (int rowIndex = 0; rowIndex < ruleTable->rowCount(); ++rowIndex)
            {
                const QTableWidgetItem* ruleIdItem = ruleTable->item(rowIndex, static_cast<int>(RuleColumn::RuleId));
                if (ruleIdItem == nullptr)
                {
                    continue;
                }
                quint32 ruleId = 0U;
                if (parseUnsignedText(ruleIdItem->text(), &ruleId))
                {
                    maxRuleId = std::max(maxRuleId, ruleId);
                }
            }
        }
        return maxRuleId + 1U;
    }

    quint32 firstGroupId() const
    {
        for (int rowIndex = 0; rowIndex < m_groupTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 groupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &groupId))
            {
                return groupId;
            }
        }
        return 0U;
    }

    bool groupExists(const quint32 groupId) const
    {
        if (groupId == 0U)
        {
            return false;
        }

        for (int rowIndex = 0; rowIndex < m_groupTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
            if (groupIdItem == nullptr)
            {
                continue;
            }
            quint32 currentGroupId = 0U;
            if (parseUnsignedText(groupIdItem->text(), &currentGroupId) && currentGroupId == groupId)
            {
                return true;
            }
        }
        return false;
    }

    void setRuleHeaderCell(
        QTableWidget* ruleTable,
        const int headerRow,
        const RuleColumn column,
        QTableWidgetItem* item)
    {
        // 作用：写入第一排普通单元格，同时清理旧 span，保证重建表格后列宽可调。
        // 入参 ruleTable/headerRow/column/item：目标表、第一排、列枚举和待接管 item。
        if (ruleTable == nullptr || item == nullptr)
        {
            delete item;
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(column), 1, 1);
        ruleTable->setItem(headerRow, static_cast<int>(column), item);
    }

    void setRuleHeaderWidget(
        QTableWidget* ruleTable,
        const int headerRow,
        const RuleColumn column,
        QWidget* widget)
    {
        // 作用：写入第一排控件单元格，所有字段保持表头约束。
        // 入参 widget：Qt 会接管生命周期，空指针时只清理 span。
        if (ruleTable == nullptr)
        {
            delete widget;
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(column), 1, 1);
        ruleTable->setCellWidget(headerRow, static_cast<int>(column), widget);
    }

    void setRuleDetailWidget(
        QTableWidget* ruleTable,
        const int detailRow,
        QWidget* detailWidget)
    {
        // 作用：让第二排从 GroupID 列开始横跨右侧字段区，保留左侧固定身份列。
        // 入参 detailWidget：包含发起程序、目标程序、备注三段 1:1:1 布局的容器。
        if (ruleTable == nullptr)
        {
            delete detailWidget;
            return;
        }

        const int firstColumn = static_cast<int>(RuleColumn::GroupId);
        const int columnCount = static_cast<int>(RuleColumn::Count) - firstColumn;
        ruleTable->setSpan(detailRow, firstColumn, 1, columnCount);
        ruleTable->setCellWidget(detailRow, firstColumn, detailWidget);
    }

    void setRuleIdentityColumnSpan(
        QTableWidget* ruleTable,
        const int headerRow)
    {
        // 作用：把“启用”和 RuleID 固定为跨两排的窄列，右侧再承载规则主体和匹配详情。
        // 入参 ruleTable/headerRow：目标规则表与当前规则第一排；无返回值。
        if (ruleTable == nullptr)
        {
            return;
        }

        ruleTable->setSpan(headerRow, static_cast<int>(RuleColumn::Enabled), 2, 1);
        ruleTable->setSpan(headerRow, static_cast<int>(RuleColumn::RuleId), 2, 1);
    }

    QWidget* createOperationMaskPanel(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const quint32 operationMask)
    {
        // 作用：创建第一排“操作类型”复选框面板，并追加“自定义掩码”输入。
        // 入参 operationMask：当前规则掩码；返回：可直接放入 QTableWidget 的 QWidget。
        auto* operationPanel = new QWidget(ruleTable);
        operationPanel->setObjectName(QStringLiteral("ksCallbackRuleOperationPanel"));
        const bool allowWallpaperThroughOperationPanel = callbackAllowWallpaperThroughControls();
        operationPanel->setAutoFillBackground(!allowWallpaperThroughOperationPanel);
        operationPanel->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThroughOperationPanel);
        operationPanel->setStyleSheet(callbackRulePanelStyle());

        auto* panelLayout = new QGridLayout(operationPanel);
        panelLayout->setContentsMargins(3, 1, 3, 1);
        panelLayout->setHorizontalSpacing(6);
        panelLayout->setVerticalSpacing(2);

        // kOperationCheckColumns 作用：基础操作位按四列排布，注册表 8 个位正好压成两排。
        constexpr int kOperationCheckColumns = 4;
        constexpr int kOperationTotalColumns = 6;
        const QList<QPair<QString, quint32>> operationBitList = operationCheckboxListByType(callbackType);
        for (int bitIndex = 0; bitIndex < operationBitList.size(); ++bitIndex)
        {
            const QPair<QString, quint32>& bitPair = operationBitList.at(bitIndex);
            auto* checkBox = new QCheckBox(bitPair.first, operationPanel);
            checkBox->setProperty("operationMaskBit", QVariant::fromValue(bitPair.second));
            checkBox->setChecked((operationMask & bitPair.second) == bitPair.second);
            checkBox->setToolTip(
                kernelText("kernel.callback.intercept.operation.tooltip", QStringLiteral("%1：%2"))
                .arg(bitPair.first, operationMaskToText(bitPair.second)));
            connect(checkBox, &QCheckBox::toggled, m_hostPage, [this](bool) {
                if (!m_ignoreUiSignal)
                {
                    setDirtyState(true);
                }
            });

            const int rowIndex = bitIndex / kOperationCheckColumns;
            const int columnIndex = bitIndex % kOperationCheckColumns;
            panelLayout->addWidget(checkBox, rowIndex, columnIndex, Qt::Alignment());
        }

        quint32 checkedOperationMask = 0U;
        for (const QPair<QString, quint32>& bitPair : operationBitList)
        {
            if ((operationMask & bitPair.second) == bitPair.second)
            {
                checkedOperationMask |= bitPair.second;
            }
        }

        const quint32 customMask = operationMask & ~checkedOperationMask;
        auto* customMaskEdit = new QLineEdit(operationPanel);
        customMaskEdit->setObjectName(QStringLiteral("ksCallbackRuleCustomMaskEdit"));
        customMaskEdit->setPlaceholderText(kernelText("kernel.callback.intercept.operation.custom_mask", QStringLiteral("自定义掩码")));
        customMaskEdit->setText(customMask != 0U ? operationMaskToText(customMask) : QString());
        customMaskEdit->setToolTip(kernelText("kernel.callback.intercept.operation.custom_mask_tooltip", QStringLiteral("输入十六进制或十进制掩码；缺少 0x 前缀时会自动补全（大小写不敏感）。")));
        applyRuleLineEditStyle(customMaskEdit);

        connect(customMaskEdit, &QLineEdit::textEdited, m_hostPage, [this](const QString&) {
            if (!m_ignoreUiSignal)
            {
                setDirtyState(true);
            }
        });
        connect(customMaskEdit, &QLineEdit::editingFinished, m_hostPage, [customMaskEdit]() {
            normalizeCustomMaskEditText(customMaskEdit);
        });

        // customRowIndex 作用：小类型把自定义掩码放在第一排；注册表等多位类型放在第二排右侧。
        const int operationBitCount = static_cast<int>(operationBitList.size());
        const int customRowIndex = (operationBitCount > kOperationCheckColumns) ? 1 : 0;
        auto* customMaskLabel = new QLabel(kernelText("kernel.callback.intercept.operation.custom_mask", QStringLiteral("自定义掩码")), operationPanel);
        customMaskLabel->setObjectName(QStringLiteral("ksCallbackRuleFieldTitle"));
        panelLayout->addWidget(customMaskLabel, customRowIndex, 4, 1, 1);
        panelLayout->addWidget(customMaskEdit, customRowIndex, 5, 1, 1);
        for (int columnIndex = 0; columnIndex < kOperationTotalColumns; ++columnIndex)
        {
            const int stretchValue = (columnIndex == 5) ? 2 : 1;
            panelLayout->setColumnStretch(columnIndex, stretchValue);
        }

        return operationPanel;
    }

    QLineEdit* createRuleDetailEdit(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& valueText,
        const QString& placeholderText)
    {
        // 作用：创建第二排三等分字段编辑器，统一标题、占位符和样式。
        // 返回：QLineEdit 指针，调用方用 objectName 再区分字段用途。
        auto* edit = new QLineEdit(parentWidget);
        edit->setText(valueText);
        edit->setPlaceholderText(placeholderText);
        edit->setToolTip(titleText);
        applyRuleLineEditStyle(edit);
        return edit;
    }

    QWidget* createRuleDetailPanel(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const CallbackRuleModel& ruleModel)
    {
        // 作用：创建第二排横向贯通详情面板，三段字段按 1:1:1 自动分配宽度。
        // 入参 ruleModel：当前规则值；返回：可放入 detailRow 的 QWidget。
        auto* detailPanel = new QWidget(ruleTable);
        detailPanel->setObjectName(QStringLiteral("ksCallbackRuleDetailPanel"));
        const bool allowWallpaperThroughDetailPanel = callbackAllowWallpaperThroughControls();
        detailPanel->setAutoFillBackground(!allowWallpaperThroughDetailPanel);
        detailPanel->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThroughDetailPanel);
        detailPanel->setStyleSheet(callbackRulePanelStyle());

        auto* detailLayout = new QGridLayout(detailPanel);
        detailLayout->setContentsMargins(6, 4, 6, 4);
        detailLayout->setHorizontalSpacing(8);
        detailLayout->setVerticalSpacing(3);

        const QStringList titleList{
            kernelText("kernel.callback.intercept.detail.initiator", QStringLiteral("发起程序匹配")),
            kernelText("kernel.callback.intercept.detail.target", QStringLiteral("目标程序匹配")),
            kernelText("kernel.callback.intercept.detail.comment", QStringLiteral("备注"))
        };
        for (int columnIndex = 0; columnIndex < titleList.size(); ++columnIndex)
        {
            auto* titleLabel = new QLabel(titleList.at(columnIndex), detailPanel);
            titleLabel->setObjectName(QStringLiteral("ksCallbackRuleFieldTitle"));
            detailLayout->addWidget(titleLabel, 0, columnIndex);
            detailLayout->setColumnStretch(columnIndex, 1);
        }

        QLineEdit* initiatorEdit = createRuleDetailEdit(
            detailPanel,
            titleList.at(0),
            ruleModel.initiatorPattern,
            initiatorPlaceholderByType(callbackType));
        initiatorEdit->setObjectName(QStringLiteral("ksCallbackRuleInitiatorEdit"));

        QLineEdit* targetEdit = createRuleDetailEdit(
            detailPanel,
            titleList.at(1),
            ruleModel.targetPattern,
            targetPlaceholderByType(callbackType));
        targetEdit->setObjectName(QStringLiteral("ksCallbackRuleTargetEdit"));

        QLineEdit* commentEdit = createRuleDetailEdit(
            detailPanel,
            titleList.at(2),
            ruleModel.comment,
            kernelText("kernel.callback.intercept.detail.comment_placeholder", QStringLiteral("备注")));
        commentEdit->setObjectName(QStringLiteral("ksCallbackRuleCommentEdit"));

        const QList<QLineEdit*> editList{ initiatorEdit, targetEdit, commentEdit };
        for (int columnIndex = 0; columnIndex < editList.size(); ++columnIndex)
        {
            QLineEdit* edit = editList.at(columnIndex);
            connect(edit, &QLineEdit::textEdited, m_hostPage, [this](const QString&) {
                if (!m_ignoreUiSignal)
                {
                    setDirtyState(true);
                }
            });
            detailLayout->addWidget(edit, 1, columnIndex);
        }

        return detailPanel;
    }

    int ruleCountOfTable(const QTableWidget* ruleTable) const
    {
        if (ruleTable == nullptr || ruleTable->rowCount() <= 0)
        {
            return 0;
        }
        return ruleTable->rowCount() / 2;
    }

    int normalizeRuleHeaderRow(const int anyRowIndex) const
    {
        if (anyRowIndex < 0)
        {
            return -1;
        }
        return (anyRowIndex % 2 == 0) ? anyRowIndex : (anyRowIndex - 1);
    }

    int currentRuleLogicalIndex(const QTableWidget* ruleTable) const
    {
        if (ruleTable == nullptr)
        {
            return -1;
        }
        const int headerRow = normalizeRuleHeaderRow(ruleTable->currentRow());
        if (headerRow < 0)
        {
            return -1;
        }
        return headerRow / 2;
    }

    void addGroupRow(const quint32 preferredId)
    {
        CallbackRuleGroupModel newGroup;
        newGroup.groupId = (preferredId == 0U) ? allocateNextGroupId() : preferredId;
        newGroup.groupName = kernelText("kernel.callback.intercept.group.default_name", QStringLiteral("规则组%1")).arg(newGroup.groupId);
        newGroup.enabled = true;
        newGroup.priority = (m_groupTable->rowCount() + 1) * 10;
        newGroup.comment = kernelText("kernel.callback.intercept.group.default_comment", QStringLiteral("新建规则组"));

        m_ignoreUiSignal = true;
        appendGroupRow(newGroup);
        m_ignoreUiSignal = false;

        refreshRuleGroupComboOptions();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.added_log", QStringLiteral("新增规则组成功：groupId=%1")).arg(newGroup.groupId));
    }

    void removeCurrentGroup()
    {
        const int rowIndex = m_groupTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }

        QTableWidgetItem* groupIdItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
        if (groupIdItem == nullptr)
        {
            return;
        }

        quint32 groupId = 0U;
        if (!parseUnsignedText(groupIdItem->text(), &groupId))
        {
            return;
        }

        QList<CallbackRuleModel> allRuleList;
        QString ruleErrorText;
        if (!collectAllRulesFromUi(&allRuleList, &ruleErrorText))
        {
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), ruleErrorText);
            return;
        }
        allRuleList.erase(
            std::remove_if(
                allRuleList.begin(),
                allRuleList.end(),
                [groupId](const CallbackRuleModel& ruleModel) {
                    return ruleModel.groupId == groupId;
                }),
            allRuleList.end());

        m_ignoreUiSignal = true;
        m_groupTable->removeRow(rowIndex);
        for (auto iterator = m_ruleTableMap.begin(); iterator != m_ruleTableMap.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable != nullptr)
            {
                ruleTable->setRowCount(0);
            }
        }
        for (const CallbackRuleModel& ruleModel : allRuleList)
        {
            QTableWidget* targetRuleTable = m_ruleTableMap.value(ruleModel.callbackType, nullptr);
            if (targetRuleTable != nullptr)
            {
                appendRuleRow(targetRuleTable, ruleModel.callbackType, ruleModel);
            }
        }
        m_ignoreUiSignal = false;

        refreshRuleGroupComboOptions();
        addDefaultGroupIfNeeded();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.removed_log", QStringLiteral("删除规则组成功：groupId=%1")).arg(groupId));
    }

    void renameCurrentGroup()
    {
        const int rowIndex = m_groupTable->currentRow();
        if (rowIndex < 0)
        {
            return;
        }

        QTableWidgetItem* groupNameItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Name));
        if (groupNameItem == nullptr)
        {
            return;
        }

        bool okPressed = false;
        const QString newNameText = QInputDialog::getText(
            m_hostPage,
            kernelText("kernel.callback.intercept.group.rename_dialog.title", QStringLiteral("重命名规则组")),
            kernelText("kernel.callback.intercept.group.rename_dialog.prompt", QStringLiteral("请输入组名称：")),
            QLineEdit::Normal,
            groupNameItem->text(),
            &okPressed).trimmed();
        if (!okPressed || newNameText.isEmpty())
        {
            return;
        }

        groupNameItem->setText(newNameText);
        refreshRuleGroupComboOptions();
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.group.renamed_log", QStringLiteral("规则组重命名成功：%1")).arg(newNameText));
    }

    void moveCurrentGroup(const int direction)
    {
        const int currentRow = m_groupTable->currentRow();
        if (currentRow < 0)
        {
            return;
        }

        const int targetRow = currentRow + direction;
        if (targetRow < 0 || targetRow >= m_groupTable->rowCount())
        {
            return;
        }

        QList<CallbackRuleGroupModel> groupList;
        QString errorText;
        if (!collectGroupsFromUi(&groupList, &errorText))
        {
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        std::swap(groupList[currentRow], groupList[targetRow]);
        for (int index = 0; index < groupList.size(); ++index)
        {
            groupList[index].priority = (index + 1) * 10;
        }

        m_ignoreUiSignal = true;
        m_groupTable->setRowCount(0);
        for (const CallbackRuleGroupModel& groupModel : groupList)
        {
            appendGroupRow(groupModel);
        }
        m_groupTable->setCurrentCell(targetRow, static_cast<int>(GroupColumn::Name));
        m_ignoreUiSignal = false;

        refreshRuleGroupComboOptions();
        setDirtyState(true);
    }

    void addRuleToCurrentTab()
    {
        const quint32 callbackType = currentRuleCallbackType();
        QTableWidget* ruleTable = currentRuleTable();
        if (ruleTable == nullptr)
        {
            return;
        }

        CallbackRuleModel ruleModel;
        ruleModel.ruleId = allocateNextRuleId();
        ruleModel.groupId = firstGroupId();
        ruleModel.ruleName = kernelText("kernel.callback.intercept.rule.default_name", QStringLiteral("规则%1")).arg(ruleModel.ruleId);
        ruleModel.enabled = true;
        ruleModel.callbackType = callbackType;
        ruleModel.operationMask = defaultOperationMaskByType(callbackType);
        ruleModel.initiatorPattern.clear();
        ruleModel.targetPattern.clear();
        ruleModel.matchMode = allowedMatchModeListByType(callbackType).isEmpty()
            ? KSWORD_ARK_MATCH_MODE_EXACT
            : allowedMatchModeListByType(callbackType).front().second;
        ruleModel.action = allowedActionListByType(callbackType).isEmpty()
            ? KSWORD_ARK_RULE_ACTION_LOG_ONLY
            : allowedActionListByType(callbackType).front().second;
        ruleModel.timeoutMs = (ruleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER) ? 5000U : 0U;
        ruleModel.timeoutDefaultDecision = KSWORD_ARK_DECISION_ALLOW;
        ruleModel.priority = (ruleCountOfTable(ruleTable) + 1) * 10;
        ruleModel.comment = kernelText("kernel.callback.intercept.rule.default_comment", QStringLiteral("新建规则"));

        m_ignoreUiSignal = true;
        appendRuleRow(ruleTable, callbackType, ruleModel);
        m_ignoreUiSignal = false;

        ruleTable->setCurrentCell(ruleTable->rowCount() - 2, static_cast<int>(RuleColumn::RuleName));
        setDirtyState(true);
        appendAppLog(
            kernelText("kernel.callback.intercept.rule.added_log", QStringLiteral("新增规则成功：ruleId=%1，类型=%2"))
            .arg(ruleModel.ruleId)
            .arg(callbackTypeToDisplayText(callbackType)));
    }

    void removeCurrentRule()
    {
        QTableWidget* ruleTable = currentRuleTable();
        const quint32 callbackType = currentRuleCallbackType();
        if (ruleTable == nullptr)
        {
            return;
        }

        QList<CallbackRuleModel> ruleList;
        QString errorText;
        if (!collectRuleListFromTable(ruleTable, callbackType, &ruleList, &errorText))
        {
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        const int currentRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (currentRuleIndex < 0 || currentRuleIndex >= ruleList.size())
        {
            return;
        }
        ruleList.removeAt(currentRuleIndex);

        m_ignoreUiSignal = true;
        ruleTable->setRowCount(0);
        for (const CallbackRuleModel& ruleModel : ruleList)
        {
            appendRuleRow(ruleTable, callbackType, ruleModel);
        }
        m_ignoreUiSignal = false;

        if (ruleCountOfTable(ruleTable) > 0)
        {
            const int targetRuleIndex = std::min(currentRuleIndex, ruleCountOfTable(ruleTable) - 1);
            ruleTable->setCurrentCell(targetRuleIndex * 2, static_cast<int>(RuleColumn::RuleName));
        }
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.rule.removed_log", QStringLiteral("删除规则成功。")));
    }

    void moveCurrentRule(const int direction)
    {
        QTableWidget* ruleTable = currentRuleTable();
        const quint32 callbackType = currentRuleCallbackType();
        if (ruleTable == nullptr)
        {
            return;
        }

        const int currentRuleIndex = currentRuleLogicalIndex(ruleTable);
        if (currentRuleIndex < 0)
        {
            return;
        }

        QList<CallbackRuleModel> ruleList;
        QString errorText;
        if (!collectRuleListFromTable(ruleTable, callbackType, &ruleList, &errorText))
        {
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            return;
        }

        const int targetRuleIndex = currentRuleIndex + direction;
        if (targetRuleIndex < 0 || targetRuleIndex >= ruleList.size())
        {
            return;
        }

        std::swap(ruleList[currentRuleIndex], ruleList[targetRuleIndex]);
        for (int index = 0; index < ruleList.size(); ++index)
        {
            ruleList[index].priority = (index + 1) * 10;
        }

        m_ignoreUiSignal = true;
        ruleTable->setRowCount(0);
        for (const CallbackRuleModel& ruleModel : ruleList)
        {
            appendRuleRow(ruleTable, callbackType, ruleModel);
        }
        m_ignoreUiSignal = false;

        ruleTable->setCurrentCell(targetRuleIndex * 2, static_cast<int>(RuleColumn::RuleName));
        setDirtyState(true);
    }

    void appendRuleRow(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        const CallbackRuleModel& ruleModel)
    {
        if (ruleTable == nullptr)
        {
            return;
        }

        const int headerRow = ruleTable->rowCount();
        const int detailRow = headerRow + 1;
        ruleTable->insertRow(headerRow);
        ruleTable->insertRow(detailRow);

        // 每条规则使用两排展示：左侧启用/RuleID 跨两排，右侧第一排放规则属性。
        // 第二排从 GroupID 开始放匹配详情，避免匹配条件脱离表格布局。
        const int operationBitCount = operationCheckboxListByType(callbackType).size();
        const int headerRowHeight = (operationBitCount > 4) ? 60 : 46;
        ruleTable->setRowHeight(headerRow, headerRowHeight);
        ruleTable->setRowHeight(detailRow, 52);

        auto* enabledItem = new QTableWidgetItem();
        enabledItem->setFlags(enabledItem->flags() | Qt::ItemIsUserCheckable);
        enabledItem->setCheckState(ruleModel.enabled ? Qt::Checked : Qt::Unchecked);
        setRuleHeaderCell(ruleTable, headerRow, RuleColumn::Enabled, enabledItem);
        setRuleHeaderCell(ruleTable, headerRow, RuleColumn::RuleId, makeReadOnlyItem(QString::number(ruleModel.ruleId)));
        setRuleIdentityColumnSpan(ruleTable, headerRow);

        auto* groupCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(groupCombo);
        setRuleHeaderWidget(ruleTable, headerRow, RuleColumn::GroupId, groupCombo);
        connect(groupCombo, &QComboBox::currentIndexChanged, m_hostPage, [this](int) {
            if (!m_ignoreUiSignal)
            {
                setDirtyState(true);
            }
        });
        setRuleHeaderCell(ruleTable, headerRow, RuleColumn::RuleName, new QTableWidgetItem(ruleModel.ruleName));

        QWidget* operationPanel = createOperationMaskPanel(
            ruleTable,
            callbackType,
            ruleModel.operationMask);
        setRuleHeaderWidget(
            ruleTable,
            headerRow,
            RuleColumn::OperationMask,
            operationPanel);

        auto* matchModeCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(matchModeCombo);
        for (const QPair<QString, quint32>& optionPair : allowedMatchModeListByType(callbackType))
        {
            matchModeCombo->addItem(optionPair.first, optionPair.second);
        }
        const int matchModeIndex = matchModeCombo->findData(ruleModel.matchMode);
        matchModeCombo->setCurrentIndex(matchModeIndex >= 0 ? matchModeIndex : 0);
        connect(matchModeCombo, &QComboBox::currentIndexChanged, m_hostPage, [this, ruleTable, headerRow, callbackType](int) {
            if (m_ignoreUiSignal)
            {
                return;
            }

            auto* currentMatchCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::MatchMode)));
            auto* currentActionCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::Action)));
            const quint32 matchMode =
                (currentMatchCombo != nullptr)
                ? static_cast<quint32>(currentMatchCombo->currentData().toUInt())
                : KSWORD_ARK_MATCH_MODE_EXACT;
            const quint32 actionType =
                (currentActionCombo != nullptr)
                ? static_cast<quint32>(currentActionCombo->currentData().toUInt())
                : KSWORD_ARK_RULE_ACTION_ALLOW;

            if ((callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
                callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
                matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
                actionType != KSWORD_ARK_RULE_ACTION_ASK_USER &&
                currentActionCombo != nullptr)
            {
                const int askUserIndex = currentActionCombo->findData(
                    QVariant::fromValue(static_cast<uint>(KSWORD_ARK_RULE_ACTION_ASK_USER)));
                if (askUserIndex >= 0)
                {
                    m_ignoreUiSignal = true;
                    currentActionCombo->setCurrentIndex(askUserIndex);
                    m_ignoreUiSignal = false;
                }
            }
            setDirtyState(true);
        });
        setRuleHeaderWidget(ruleTable, headerRow, RuleColumn::MatchMode, matchModeCombo);

        auto* actionCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(actionCombo);
        for (const QPair<QString, quint32>& optionPair : allowedActionListByType(callbackType))
        {
            actionCombo->addItem(optionPair.first, optionPair.second);
        }
        const int actionIndex = actionCombo->findData(ruleModel.action);
        actionCombo->setCurrentIndex(actionIndex >= 0 ? actionIndex : 0);
        connect(actionCombo, &QComboBox::currentIndexChanged, m_hostPage, [this, ruleTable, headerRow](int) {
            if (m_ignoreUiSignal)
            {
                return;
            }
            auto* currentActionCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::Action)));
            auto* currentMatchCombo = qobject_cast<QComboBox*>(
                ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::MatchMode)));
            const quint32 actionType = (currentActionCombo != nullptr)
                ? static_cast<quint32>(currentActionCombo->currentData().toUInt())
                : KSWORD_ARK_RULE_ACTION_ALLOW;
            const quint32 matchMode = (currentMatchCombo != nullptr)
                ? static_cast<quint32>(currentMatchCombo->currentData().toUInt())
                : KSWORD_ARK_MATCH_MODE_EXACT;
            QTableWidgetItem* timeoutItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::TimeoutMs));
            if (timeoutItem != nullptr && actionType != KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                timeoutItem->setText(QStringLiteral("0"));
            }
            if (timeoutItem != nullptr && actionType == KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                quint32 timeoutValue = 0U;
                if (!parseUnsignedText(timeoutItem->text(), &timeoutValue) || timeoutValue == 0U)
                {
                    timeoutItem->setText(QStringLiteral("5000"));
                }
            }

            if (actionType != KSWORD_ARK_RULE_ACTION_ASK_USER &&
                matchMode == KSWORD_ARK_MATCH_MODE_REGEX &&
                currentMatchCombo != nullptr)
            {
                const int exactIndex = currentMatchCombo->findData(
                    QVariant::fromValue(static_cast<uint>(KSWORD_ARK_MATCH_MODE_EXACT)));
                if (exactIndex >= 0)
                {
                    m_ignoreUiSignal = true;
                    currentMatchCombo->setCurrentIndex(exactIndex);
                    m_ignoreUiSignal = false;
                }
            }
            setDirtyState(true);
        });
        setRuleHeaderWidget(ruleTable, headerRow, RuleColumn::Action, actionCombo);

        setRuleHeaderCell(
            ruleTable,
            headerRow,
            RuleColumn::TimeoutMs,
            new QTableWidgetItem(QString::number(ruleModel.timeoutMs)));

        auto* timeoutDecisionCombo = new QComboBox(ruleTable);
        applyRuleComboStyle(timeoutDecisionCombo);
        for (const QPair<QString, quint32>& optionPair : decisionOptionList())
        {
            timeoutDecisionCombo->addItem(optionPair.first, optionPair.second);
        }
        const int timeoutDecisionIndex = timeoutDecisionCombo->findData(ruleModel.timeoutDefaultDecision);
        timeoutDecisionCombo->setCurrentIndex(timeoutDecisionIndex >= 0 ? timeoutDecisionIndex : 0);
        connect(timeoutDecisionCombo, &QComboBox::currentIndexChanged, m_hostPage, [this](int) {
            if (!m_ignoreUiSignal)
            {
                setDirtyState(true);
            }
        });
        setRuleHeaderWidget(
            ruleTable,
            headerRow,
            RuleColumn::TimeoutDefaultDecision,
            timeoutDecisionCombo);

        setRuleHeaderCell(
            ruleTable,
            headerRow,
            RuleColumn::Priority,
            new QTableWidgetItem(QString::number(ruleModel.priority)));

        QWidget* detailPanel = createRuleDetailPanel(ruleTable, callbackType, ruleModel);
        setRuleDetailWidget(ruleTable, detailRow, detailPanel);

        refreshRuleGroupComboForCell(groupCombo, ruleModel.groupId);
    }

    void refreshRuleGroupComboForCell(QComboBox* groupCombo, const quint32 selectedGroupId)
    {
        if (groupCombo == nullptr)
        {
            return;
        }

        applyRuleComboStyle(groupCombo);
        groupCombo->blockSignals(true);
        groupCombo->clear();
        for (int rowIndex = 0; rowIndex < m_groupTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* groupIdItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
            QTableWidgetItem* groupNameItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Name));
            if (groupIdItem == nullptr || groupNameItem == nullptr)
            {
                continue;
            }

            quint32 groupId = 0U;
            if (!parseUnsignedText(groupIdItem->text(), &groupId))
            {
                continue;
            }
            groupCombo->addItem(
                QStringLiteral("[%1] %2").arg(groupId).arg(groupNameItem->text().trimmed()),
                groupId);
        }

        int targetIndex = groupCombo->findData(selectedGroupId);
        if (targetIndex < 0)
        {
            targetIndex = 0;
        }
        groupCombo->setCurrentIndex(targetIndex);
        groupCombo->blockSignals(false);
    }

    void refreshRuleGroupComboOptions()
    {
        for (auto iterator = m_ruleTableMap.begin(); iterator != m_ruleTableMap.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable == nullptr)
            {
                continue;
            }

            for (int rowIndex = 0; rowIndex < ruleTable->rowCount(); rowIndex += 2)
            {
                auto* groupCombo = qobject_cast<QComboBox*>(
                    ruleTable->cellWidget(rowIndex, static_cast<int>(RuleColumn::GroupId)));
                quint32 selectedGroupId = firstGroupId();
                if (groupCombo != nullptr)
                {
                    selectedGroupId = static_cast<quint32>(groupCombo->currentData().toUInt());
                }
                refreshRuleGroupComboForCell(groupCombo, selectedGroupId);
            }
        }
    }

    quint32 currentRuleCallbackType() const
    {
        return m_tabCallbackTypeMap.value(
            m_ruleTabWidget != nullptr ? m_ruleTabWidget->currentIndex() : -1,
            KSWORD_ARK_CALLBACK_TYPE_NONE);
    }

    QTableWidget* currentRuleTable() const
    {
        const quint32 callbackType = currentRuleCallbackType();
        return m_ruleTableMap.value(callbackType, nullptr);
    }

    bool collectGroupsFromUi(
        QList<CallbackRuleGroupModel>* groupListOut,
        QString* errorTextOut) const
    {
        if (groupListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.group_list_out_null", QStringLiteral("内部错误：groupListOut 为空。"));
            }
            return false;
        }

        groupListOut->clear();
        for (int rowIndex = 0; rowIndex < m_groupTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* idItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Id));
            QTableWidgetItem* nameItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Name));
            QTableWidgetItem* enabledItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Enabled));
            QTableWidgetItem* priorityItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Priority));
            QTableWidgetItem* commentItem = m_groupTable->item(rowIndex, static_cast<int>(GroupColumn::Comment));
            if (idItem == nullptr || nameItem == nullptr || enabledItem == nullptr || priorityItem == nullptr || commentItem == nullptr)
            {
                continue;
            }

            CallbackRuleGroupModel groupModel;
            if (!parseUnsignedText(idItem->text(), &groupModel.groupId))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.group_id_invalid", QStringLiteral("规则组行 %1 的 groupId 非法。")).arg(rowIndex + 1);
                }
                return false;
            }

            bool priorityOk = false;
            groupModel.priority = priorityItem->text().trimmed().toInt(&priorityOk);
            if (!priorityOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.group_priority_invalid", QStringLiteral("规则组行 %1 的优先级非法。")).arg(rowIndex + 1);
                }
                return false;
            }

            groupModel.groupName = nameItem->text().trimmed();
            groupModel.enabled = (enabledItem->checkState() == Qt::Checked);
            groupModel.comment = commentItem->text().trimmed();
            groupListOut->push_back(groupModel);
        }

        return true;
    }

    bool collectRuleListFromTable(
        QTableWidget* ruleTable,
        const quint32 callbackType,
        QList<CallbackRuleModel>* ruleListOut,
        QString* errorTextOut) const
    {
        if (ruleTable == nullptr || ruleListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_table_or_list_null", QStringLiteral("内部错误：ruleTable 或 ruleListOut 为空。"));
            }
            return false;
        }

        ruleListOut->clear();
        const int totalRuleCount = ruleCountOfTable(ruleTable);
        for (int logicalRuleIndex = 0; logicalRuleIndex < totalRuleCount; ++logicalRuleIndex)
        {
            const int headerRow = logicalRuleIndex * 2;
            const int detailRow = headerRow + 1;

            QTableWidgetItem* ruleIdItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::RuleId));
            QTableWidgetItem* ruleNameItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::RuleName));
            QTableWidgetItem* enabledItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::Enabled));
            QTableWidgetItem* timeoutItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::TimeoutMs));
            QTableWidgetItem* priorityItem = ruleTable->item(headerRow, static_cast<int>(RuleColumn::Priority));
            auto* groupCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::GroupId)));
            auto* operationPanel = ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::OperationMask));
            auto* matchModeCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::MatchMode)));
            auto* actionCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::Action)));
            auto* timeoutDecisionCombo = qobject_cast<QComboBox*>(ruleTable->cellWidget(headerRow, static_cast<int>(RuleColumn::TimeoutDefaultDecision)));
            auto* detailPanel = ruleTable->cellWidget(detailRow, static_cast<int>(RuleColumn::GroupId));
            auto* initiatorEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleInitiatorEdit"))
                : nullptr;
            auto* targetEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleTargetEdit"))
                : nullptr;
            auto* commentEdit = detailPanel != nullptr
                ? detailPanel->findChild<QLineEdit*>(QStringLiteral("ksCallbackRuleCommentEdit"))
                : nullptr;

            if (ruleIdItem == nullptr || ruleNameItem == nullptr || enabledItem == nullptr ||
                timeoutItem == nullptr || priorityItem == nullptr ||
                groupCombo == nullptr || operationPanel == nullptr ||
                matchModeCombo == nullptr || actionCombo == nullptr || timeoutDecisionCombo == nullptr ||
                initiatorEdit == nullptr || targetEdit == nullptr || commentEdit == nullptr)
            {
                continue;
            }

            CallbackRuleModel ruleModel;
            if (!parseUnsignedText(ruleIdItem->text(), &ruleModel.ruleId))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_id_invalid", QStringLiteral("规则 %1 的 ruleId 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            ruleModel.groupId = static_cast<quint32>(groupCombo->currentData().toUInt());
            if (ruleModel.groupId == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_group_invalid", QStringLiteral("规则 %1 未选择有效规则组。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool operationParseOk = false;
            ruleModel.operationMask = currentOperationMaskFromPanel(operationPanel, &operationParseOk);
            if (!operationParseOk || ruleModel.operationMask == 0U)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.operation_mask_invalid", QStringLiteral("规则 %1 的 operationMask 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool timeoutOk = false;
            const quint32 timeoutMs = static_cast<quint32>(timeoutItem->text().trimmed().toUInt(&timeoutOk));
            if (!timeoutOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.timeout_invalid", QStringLiteral("规则 %1 的 timeoutMs 非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            bool priorityOk = false;
            const qint32 rulePriority = priorityItem->text().trimmed().toInt(&priorityOk);
            if (!priorityOk)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_priority_invalid", QStringLiteral("规则 %1 的优先级非法。")).arg(logicalRuleIndex + 1);
                }
                return false;
            }

            ruleModel.ruleName = ruleNameItem->text().trimmed();
            ruleModel.enabled = (enabledItem->checkState() == Qt::Checked);
            ruleModel.callbackType = callbackType;
            ruleModel.initiatorPattern = normalizeMatchAllPattern(initiatorEdit->text());
            ruleModel.targetPattern = normalizeMatchAllPattern(targetEdit->text());
            ruleModel.matchMode = static_cast<quint32>(matchModeCombo->currentData().toUInt());
            ruleModel.action = static_cast<quint32>(actionCombo->currentData().toUInt());
            ruleModel.timeoutMs = timeoutMs;
            ruleModel.timeoutDefaultDecision = static_cast<quint32>(timeoutDecisionCombo->currentData().toUInt());
            ruleModel.priority = rulePriority;
            ruleModel.comment = commentEdit->text().trimmed();

            if (!ruleModel.initiatorPattern.trimmed().isEmpty())
            {
                // 所有回调类型的 initiator 最终都与内核采集到的进程镜像路径比较，
                // 这里统一把常见用户态路径（如 C:\...）转换到内核可匹配形式。
                ruleModel.initiatorPattern =
                    normalizeUserModeFilePathPatternForKernel(ruleModel.initiatorPattern);
            }

            if (ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY)
            {
                ruleModel.targetPattern = normalizeRegistryTargetPatternForKernel(ruleModel.targetPattern);
            }
            else if (!ruleModel.targetPattern.trimmed().isEmpty())
            {
                ruleModel.targetPattern =
                    normalizeUserModeFilePathPatternForKernel(ruleModel.targetPattern);
            }

            if (ruleModel.action != KSWORD_ARK_RULE_ACTION_ASK_USER)
            {
                ruleModel.timeoutMs = 0U;
            }

            ruleListOut->push_back(ruleModel);
        }

        return true;
    }

    bool collectAllRulesFromUi(
        QList<CallbackRuleModel>* ruleListOut,
        QString* errorTextOut) const
    {
        if (ruleListOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.rule_list_out_null", QStringLiteral("内部错误：ruleListOut 为空。"));
            }
            return false;
        }

        ruleListOut->clear();
        for (auto iterator = m_ruleTableMap.begin(); iterator != m_ruleTableMap.end(); ++iterator)
        {
            const quint32 callbackType = iterator.key();
            QTableWidget* ruleTable = iterator.value();
            QList<CallbackRuleModel> typeRuleList;
            if (!collectRuleListFromTable(ruleTable, callbackType, &typeRuleList, errorTextOut))
            {
                return false;
            }
            ruleListOut->append(typeRuleList);
        }

        return true;
    }

    bool collectConfigFromUi(
        CallbackConfigDocument* configOut,
        QString* errorTextOut)
    {
        if (configOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.config_out_null", QStringLiteral("内部错误：configOut 为空。"));
            }
            return false;
        }

        CallbackConfigDocument configDocument;
        configDocument.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
        configDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        configDocument.appVersion = QStringLiteral("Ksword5.1");
        configDocument.globalEnabled = (m_globalEnabledCheck != nullptr) ? m_globalEnabledCheck->isChecked() : true;
        configDocument.ruleVersion = m_nextRuleVersion;

        if (!collectGroupsFromUi(&configDocument.groups, errorTextOut))
        {
            return false;
        }
        if (!collectAllRulesFromUi(&configDocument.rules, errorTextOut))
        {
            return false;
        }

        const CallbackValidationResult validationResult = validateCallbackConfig(configDocument);
        if (!validationResult.success)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = validationResult.errorList.join(QStringLiteral("；"));
            }
            return false;
        }

        for (const QString& warningText : validationResult.warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.config.warning", QStringLiteral("配置警告：%1")).arg(warningText));
        }

        *configOut = configDocument;
        return true;
    }

    void updateStatusLabel()
    {
        if (m_statusLabel == nullptr)
        {
            return;
        }

        const QString statusText = kernelText("kernel.callback.intercept.status.runtime", QStringLiteral(
            "状态：%1 | 驱动%2 | 规则版本=%3 | 规则数=%4 | 等待接收者=%5 | 待决策=%6 | 生效时间=%7 | 未应用修改=%8"))
            .arg(m_rulesApplied
                ? kernelText("kernel.callback.intercept.status.applied", QStringLiteral("已应用"))
                : kernelText("kernel.callback.intercept.status.not_applied", QStringLiteral("未应用")))
            .arg(m_runtimeState.driverOnline != 0U
                ? kernelText("kernel.callback.intercept.status.online", QStringLiteral("在线"))
                : kernelText("kernel.callback.intercept.status.offline", QStringLiteral("离线")))
            .arg(m_runtimeState.appliedRuleVersion)
            .arg(m_runtimeState.ruleCount)
            .arg(m_runtimeState.waitingReceiverCount)
            .arg(m_runtimeState.pendingDecisionCount)
            .arg(utc100nsToDisplayText(m_runtimeState.appliedAtUtc100ns))
            .arg(m_dirty
                ? kernelText("kernel.callback.intercept.status.yes", QStringLiteral("是"))
                : kernelText("kernel.callback.intercept.status.no", QStringLiteral("否")));
        m_statusLabel->setText(statusText);
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;")
            .arg(m_runtimeState.driverOnline != 0U
                ? KswordTheme::SuccessHex()
                : KswordTheme::WarningAccentColor().name()));
    }

    // describeDegradedCallbacks 列出本机上注册失败的内核回调。
    // 驱动在这些情况下仍然正常加载，因此界面必须能说明"哪一项能力缺失、
    // 原始 NTSTATUS 是多少"，而不是让用户以为规则失效是软件出错。
    QString describeDegradedCallbacks(const KSWORD_ARK_CALLBACK_RUNTIME_STATE& runtimeState) const
    {
        const auto appendItem = [](QStringList& itemList, const QString& capabilityText, const long statusValue) {
            if (statusValue == 0)
            {
                return;
            }
            itemList.append(
                kernelText("kernel.callback.intercept.runtime.degraded_item", QStringLiteral("%1（status=0x%2）"))
                .arg(capabilityText)
                .arg(static_cast<unsigned long>(statusValue), 8, 16, QLatin1Char('0')));
        };

        QStringList degradedItems;
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.ask_user", QStringLiteral("用户询问队列")),
            runtimeState.waitQueueStatus);
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.registry", QStringLiteral("注册表回调")),
            runtimeState.registryCallbackStatus);
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.process", QStringLiteral("进程回调")),
            runtimeState.processCallbackStatus);
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.thread", QStringLiteral("线程回调")),
            runtimeState.threadCallbackStatus);
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.image", QStringLiteral("映像加载回调")),
            runtimeState.imageCallbackStatus);
        appendItem(
            degradedItems,
            kernelText("kernel.callback.intercept.runtime.capability.object", QStringLiteral("对象句柄回调")),
            runtimeState.objectCallbackStatus);

        return degradedItems.join(QStringLiteral("、"));
    }

    bool queryRuntimeState(KSWORD_ARK_CALLBACK_RUNTIME_STATE* runtimeStateOut, QString* errorTextOut) const
    {
        if (runtimeStateOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.validation.runtime_state_out_null", QStringLiteral("内部错误：runtimeStateOut 为空。"));
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::CallbackRuntimeResult runtimeResult = driverClient.queryCallbackRuntimeState();
        if (!runtimeResult.io.ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = kernelText("kernel.callback.intercept.runtime.query_failed", QStringLiteral("获取驱动状态失败，error=%1，detail=%2"))
                    .arg(runtimeResult.io.win32Error)
                    .arg(callbackRuleIoMessageText(QString::fromStdString(runtimeResult.io.message)));
            }
            return false;
        }

        *runtimeStateOut = runtimeResult.state;
        return true;
    }

    void reloadRuntimeState()
    {
        KSWORD_ARK_CALLBACK_RUNTIME_STATE runtimeState{};
        QString errorText;
        if (!queryRuntimeState(&runtimeState, &errorText))
        {
            RtlZeroMemory(&m_runtimeState, sizeof(m_runtimeState));
            appendAppLog(kernelText("kernel.callback.intercept.runtime.reload_failed", QStringLiteral("重新加载驱动状态失败：%1")).arg(errorText));
            updateStatusLabel();
            return;
        }

        m_runtimeState = runtimeState;
        m_rulesApplied = (m_runtimeState.rulesApplied != 0U);
        if (m_runtimeState.appliedRuleVersion >= m_nextRuleVersion)
        {
            m_nextRuleVersion = m_runtimeState.appliedRuleVersion + 1ULL;
        }

        appendAppLog(
            kernelText("kernel.callback.intercept.runtime.refreshed", QStringLiteral("驱动状态已刷新：online=%1, groups=%2, rules=%3, pending=%4, waiting=%5"))
            .arg(m_runtimeState.driverOnline)
            .arg(m_runtimeState.groupCount)
            .arg(m_runtimeState.ruleCount)
            .arg(m_runtimeState.pendingDecisionCount)
            .arg(m_runtimeState.waitingReceiverCount));

        // 少数机器上会因 altitude 冲突或回调槽位耗尽而缺少某几类回调，
        // 驱动照常加载，这里把缺失项和原始状态明确告知用户。
        const QString degradedText = describeDegradedCallbacks(m_runtimeState);
        if (!degradedText.isEmpty())
        {
            appendAppLog(
                kernelText(
                    "kernel.callback.intercept.runtime.degraded",
                    QStringLiteral("本机以降级模式运行，以下内核回调不可用：%1。KSword 其余功能不受影响。"))
                .arg(degradedText));
        }
        updateStatusLabel();
    }

    void ensureMinifilterRuntimeStarted(
        const CallbackConfigDocument& configDocument,
        const ksword::ark::DriverClient& driverClient)
    {
        // 作用：应用含 Minifilter 规则后自动启动共享 file-monitor minifilter。
        // 处理：只发 START，不主动 STOP，避免覆盖用户在文件监控页已有的运行意图。
        // 返回：无；失败只写应用日志，规则应用本身仍然保持成功。
        if (!hasActiveMinifilterRule(configDocument))
        {
            return;
        }

        const ksword::ark::FileMonitorStatusResult beforeStatus =
            driverClient.queryFileMonitorStatus();
        if (beforeStatus.io.ok &&
            (beforeStatus.runtimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) != 0U)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.already_started", QStringLiteral("文件系统微过滤器已处于启动状态：mask=0x%1, queued=%2, dropped=%3。"))
                .arg(beforeStatus.operationMask, 8, 16, QChar('0')).toUpper()
                .arg(beforeStatus.queuedCount)
                .arg(beforeStatus.droppedCount));
            return;
        }

        if (!beforeStatus.io.ok)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.query_failed", QStringLiteral("查询文件系统微过滤器状态失败，仍尝试启动：error=%1，detail=%2"))
                .arg(beforeStatus.io.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(beforeStatus.io.message))));
        }

        ksword::ark::IoResult startResult = driverClient.controlFileMonitor(
            KSWORD_ARK_FILE_MONITOR_ACTION_START,
            KSWORD_ARK_FILE_MONITOR_OPERATION_ALL,
            0UL,
            0UL);
        if (!startResult.ok)
        {
            const unsigned long legacyOperationMask =
                KSWORD_ARK_FILE_MONITOR_OPERATION_ALL & ~KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
            const ksword::ark::IoResult legacyStartResult = driverClient.controlFileMonitor(
                KSWORD_ARK_FILE_MONITOR_ACTION_START,
                legacyOperationMask,
                0UL,
                0UL);
            if (legacyStartResult.ok)
            {
                appendAppLog(
                    kernelText("kernel.callback.intercept.runtime.minifilter.legacy_started", QStringLiteral("文件系统微过滤器以旧掩码启动：mask=0x%1；当前驱动可能尚未支持 FSCTL 事件。"))
                    .arg(legacyOperationMask, 8, 16, QChar('0')).toUpper());
                startResult = legacyStartResult;
            }
        }
        if (!startResult.ok)
        {
            const ksword::ark::FileMonitorStatusResult failStatus =
                driverClient.queryFileMonitorStatus();
            const QString statusSuffix = failStatus.io.ok
                ? kernelText("kernel.callback.intercept.runtime.minifilter.status_suffix", QStringLiteral("；status=%1，flags=0x%2，mask=0x%3，register=%4，start=%5，last=%6，queued=%7，dropped=%8"))
                    .arg(callbackRuleIoMessageText(QString::fromStdString(failStatus.io.message)))
                    .arg(failStatus.runtimeFlags, 8, 16, QChar('0')).toUpper()
                    .arg(failStatus.operationMask, 8, 16, QChar('0')).toUpper()
                    .arg(formatCallbackNtStatusHex(failStatus.registerStatus))
                    .arg(formatCallbackNtStatusHex(failStatus.startStatus))
                    .arg(formatCallbackNtStatusHex(failStatus.lastErrorStatus))
                    .arg(failStatus.queuedCount)
                    .arg(failStatus.droppedCount)
                : kernelText("kernel.callback.intercept.runtime.minifilter.status_query_failed", QStringLiteral("；status-query-failed error=%1，detail=%2"))
                    .arg(failStatus.io.win32Error)
                    .arg(callbackRuleIoMessageText(QString::fromStdString(failStatus.io.message)));
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.start_warning", QStringLiteral("警告：文件系统微过滤器启动失败，Minifilter 自定义规则暂时不会收到文件事件：error=%1，detail=%2%3"))
                .arg(startResult.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(startResult.message)))
                .arg(statusSuffix));
            return;
        }

        const ksword::ark::FileMonitorStatusResult afterStatus =
            driverClient.queryFileMonitorStatus();
        if (afterStatus.io.ok)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.started", QStringLiteral("文件系统微过滤器已启动：flags=0x%1, mask=0x%2, register=%3, start=%4, last=%5。"))
                .arg(afterStatus.runtimeFlags, 8, 16, QChar('0')).toUpper()
                .arg(afterStatus.operationMask, 8, 16, QChar('0')).toUpper()
                .arg(formatCallbackNtStatusHex(afterStatus.registerStatus))
                .arg(formatCallbackNtStatusHex(afterStatus.startStatus))
                .arg(formatCallbackNtStatusHex(afterStatus.lastErrorStatus)));
        }
        else
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.runtime.minifilter.post_check_failed", QStringLiteral("文件系统微过滤器启动命令已下发，但状态复查失败：error=%1，detail=%2"))
                .arg(afterStatus.io.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(afterStatus.io.message))));
        }
    }

    void applyRulesToDriver()
    {
        CallbackConfigDocument configDocument;
        QString errorText;
        if (!collectConfigFromUi(&configDocument, &errorText))
        {
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.failed", QStringLiteral("应用失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.apply.failed", QStringLiteral("应用失败：%1")).arg(errorText));
            return;
        }

        QByteArray blobBytes;
        if (!buildCallbackRuleBlobFromConfig(configDocument, &blobBytes, &errorText))
        {
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.compile_failed", QStringLiteral("规则编译失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.apply.compile_failed", QStringLiteral("规则编译失败：%1")).arg(errorText));
            return;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult applyResult = driverClient.setCallbackRules(
            blobBytes.data(),
            static_cast<unsigned long>(blobBytes.size()));

        if (!applyResult.ok)
        {
            QMessageBox::warning(
                m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.apply.error", QStringLiteral("应用到驱动失败，error=%1。")).arg(applyResult.win32Error));
            appendAppLog(kernelText("kernel.callback.intercept.apply.log_failed", QStringLiteral("应用到驱动失败，error=%1，detail=%2"))
                .arg(applyResult.win32Error)
                .arg(callbackRuleIoMessageText(QString::fromStdString(applyResult.message))));
            return;
        }

        m_rulesApplied = true;
        m_dirty = false;
        m_nextRuleVersion = configDocument.ruleVersion + 1ULL;

        appendAppLog(
            kernelText("kernel.callback.intercept.apply.success", QStringLiteral("应用成功：ruleVersion=%1, groupCount=%2, ruleCount=%3, blobBytes=%4"))
            .arg(configDocument.ruleVersion)
            .arg(configDocument.groups.size())
            .arg(configDocument.rules.size())
            .arg(blobBytes.size()));

        ensureMinifilterRuntimeStarted(configDocument, driverClient);
        reloadRuntimeState();
        const bool hasAskUserRule = std::any_of(
            configDocument.rules.cbegin(),
            configDocument.rules.cend(),
            [](const CallbackRuleModel& ruleModel) {
                return ruleModel.enabled &&
                    (ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_REGISTRY ||
                        ruleModel.callbackType == KSWORD_ARK_CALLBACK_TYPE_MINIFILTER) &&
                    ruleModel.action == KSWORD_ARK_RULE_ACTION_ASK_USER;
            });
        if (hasAskUserRule && m_runtimeState.waitingReceiverCount == 0U)
        {
            appendAppLog(
                kernelText("kernel.callback.intercept.apply.ask_user_warning", QStringLiteral("警告：检测到“询问用户”规则，但当前等待接收者为 0。请确认弹窗管理器已启动，否则驱动将按默认决策回退。")));
        }
        updateStatusLabel();
    }

    void importConfigFromFile()
    {
        const QString filePath = QFileDialog::getOpenFileName(
            m_hostPage,
            kernelText("kernel.callback.intercept.import.dialog_title", QStringLiteral("导入回调规则")),
            QString(),
            QStringLiteral("Ksword Rule File (*.kswrules);;JSON (*.json);;All Files (*)"));
        if (filePath.trimmed().isEmpty())
        {
            return;
        }

        QFile inputFile(filePath);
        if (!inputFile.open(QIODevice::ReadOnly))
        {
            const QString errorText = kernelText("kernel.callback.intercept.import.open_failed", QStringLiteral("打开文件失败：%1")).arg(inputFile.errorString());
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            appendAppLog(kernelText("kernel.callback.intercept.import.failed", QStringLiteral("导入失败：%1")).arg(errorText));
            return;
        }

        const QByteArray jsonBytes = inputFile.readAll();
        inputFile.close();

        CallbackConfigDocument importedDocument;
        QStringList warningList;
        QString errorText;
        if (!importCallbackConfigFromJson(jsonBytes, &importedDocument, &warningList, &errorText))
        {
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), errorText);
            appendAppLog(kernelText("kernel.callback.intercept.import.failed", QStringLiteral("导入失败：%1")).arg(errorText));
            return;
        }

        const CallbackValidationResult validationResult = validateCallbackConfig(importedDocument);
        if (!validationResult.success)
        {
            const QString validateError = validationResult.errorList.join(QStringLiteral("；"));
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.import.invalid", QStringLiteral("导入配置不合法：%1")).arg(validateError));
            appendAppLog(kernelText("kernel.callback.intercept.import.invalid", QStringLiteral("导入配置不合法：%1")).arg(validateError));
            return;
        }

        for (const QString& warningText : warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.import.warning", QStringLiteral("导入警告：%1")).arg(warningText));
        }
        for (const QString& warningText : validationResult.warningList)
        {
            appendAppLog(kernelText("kernel.callback.intercept.config.warning", QStringLiteral("配置警告：%1")).arg(warningText));
        }

        populateUiFromConfig(importedDocument);
        m_nextRuleVersion = std::max(m_nextRuleVersion, importedDocument.ruleVersion + 1ULL);
        setDirtyState(true);
        appendAppLog(kernelText("kernel.callback.intercept.import.success", QStringLiteral("导入成功：%1")).arg(filePath));
    }

    void exportConfigToFile()
    {
        CallbackConfigDocument configDocument;
        QString errorText;
        if (!collectConfigFromUi(&configDocument, &errorText))
        {
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            return;
        }

        const QString filePath = QFileDialog::getSaveFileName(
            m_hostPage,
            kernelText("kernel.callback.intercept.export.dialog_title", QStringLiteral("导出回调规则")),
            QStringLiteral("callback_rules.kswrules"),
            QStringLiteral("Ksword Rule File (*.kswrules);;JSON (*.json);;All Files (*)"));
        if (filePath.trimmed().isEmpty())
        {
            return;
        }

        QByteArray jsonBytes;
        if (!exportCallbackConfigToJson(configDocument, &jsonBytes, &errorText))
        {
            QMessageBox::warning(m_hostPage,
                kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")),
                kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(errorText));
            return;
        }

        QFile outputFile(filePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            const QString ioError = kernelText("kernel.callback.intercept.export.write_failed", QStringLiteral("写入失败：%1")).arg(outputFile.errorString());
            QMessageBox::warning(m_hostPage, kernelText("kernel.callback.intercept.dialog.title", QStringLiteral("驱动回调")), ioError);
            appendAppLog(kernelText("kernel.callback.intercept.export.failed", QStringLiteral("导出失败：%1")).arg(ioError));
            return;
        }
        outputFile.write(jsonBytes);
        outputFile.close();

        appendAppLog(kernelText("kernel.callback.intercept.export.success", QStringLiteral("导出成功：%1")).arg(filePath));
    }

    void populateUiFromConfig(const CallbackConfigDocument& configDocument)
    {
        m_ignoreUiSignal = true;

        if (m_globalEnabledCheck != nullptr)
        {
            m_globalEnabledCheck->setChecked(configDocument.globalEnabled);
        }

        m_groupTable->setRowCount(0);
        QList<CallbackRuleGroupModel> sortedGroups = configDocument.groups;
        std::sort(sortedGroups.begin(), sortedGroups.end(), [](const CallbackRuleGroupModel& left, const CallbackRuleGroupModel& right) {
            if (left.priority != right.priority)
            {
                return left.priority < right.priority;
            }
            return left.groupId < right.groupId;
        });
        for (const CallbackRuleGroupModel& groupModel : sortedGroups)
        {
            appendGroupRow(groupModel);
        }
        addDefaultGroupIfNeeded();

        for (auto iterator = m_ruleTableMap.begin(); iterator != m_ruleTableMap.end(); ++iterator)
        {
            QTableWidget* ruleTable = iterator.value();
            if (ruleTable != nullptr)
            {
                ruleTable->setRowCount(0);
            }
        }

        QList<CallbackRuleModel> sortedRules = configDocument.rules;
        std::sort(sortedRules.begin(), sortedRules.end(), [](const CallbackRuleModel& left, const CallbackRuleModel& right) {
            if (left.callbackType != right.callbackType)
            {
                return left.callbackType < right.callbackType;
            }
            if (left.priority != right.priority)
            {
                return left.priority < right.priority;
            }
            return left.ruleId < right.ruleId;
        });
        for (const CallbackRuleModel& ruleModel : sortedRules)
        {
            QTableWidget* ruleTable = m_ruleTableMap.value(ruleModel.callbackType, nullptr);
            if (ruleTable == nullptr)
            {
                continue;
            }
            appendRuleRow(ruleTable, ruleModel.callbackType, ruleModel);
        }

        m_ignoreUiSignal = false;
        refreshRuleGroupComboOptions();
    }

private:
    QWidget* m_hostPage = nullptr;
    QPointer<CallbackPromptManager> m_promptManager;

    QCheckBox* m_globalEnabledCheck = nullptr;
    QPushButton* m_applyButton = nullptr;
    QPushButton* m_reloadStateButton = nullptr;
    QPushButton* m_importButton = nullptr;
    QPushButton* m_exportButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QPushButton* m_addGroupButton = nullptr;
    QPushButton* m_removeGroupButton = nullptr;
    QPushButton* m_renameGroupButton = nullptr;
    QPushButton* m_moveGroupUpButton = nullptr;
    QPushButton* m_moveGroupDownButton = nullptr;
    QTableWidget* m_groupTable = nullptr;

    QPushButton* m_addRuleButton = nullptr;
    QPushButton* m_removeRuleButton = nullptr;
    QPushButton* m_moveRuleUpButton = nullptr;
    QPushButton* m_moveRuleDownButton = nullptr;
    QTabWidget* m_ruleTabWidget = nullptr;
    QHash<quint32, QTableWidget*> m_ruleTableMap;
    QHash<int, quint32> m_tabCallbackTypeMap;

    QLineEdit* m_minifilterBypassPidEdit = nullptr;
    QPushButton* m_minifilterBypassAddButton = nullptr;
    QPushButton* m_minifilterBypassRemoveButton = nullptr;
    QPushButton* m_minifilterBypassApplyButton = nullptr;
    QPushButton* m_minifilterBypassClearButton = nullptr;
    QPushButton* m_minifilterBypassRefreshButton = nullptr;
    QLabel* m_minifilterBypassStatusLabel = nullptr;
    QTableWidget* m_minifilterBypassPidTable = nullptr;

    QCheckBox* m_processProtectEnabledCheck = nullptr;
    QCheckBox* m_processProtectLogCheck = nullptr;
    QCheckBox* m_processProtectTrustSystemCheck = nullptr;
    QCheckBox* m_processProtectTrustPeersCheck = nullptr;
    QComboBox* m_processProtectKindCombo = nullptr;
    QLineEdit* m_processProtectTargetEdit = nullptr;
    QComboBox* m_processProtectPresetCombo = nullptr;
    QCheckBox* m_processProtectThreadsCheck = nullptr;
    QLineEdit* m_processProtectRuleNameEdit = nullptr;
    QPushButton* m_processProtectAddRuleButton = nullptr;
    QPushButton* m_processProtectApplyPresetButton = nullptr;
    QPushButton* m_processProtectRemoveRuleButton = nullptr;
    QTableWidget* m_processProtectRuleTable = nullptr;
    QComboBox* m_processProtectTrustedKindCombo = nullptr;
    QLineEdit* m_processProtectTrustedTargetEdit = nullptr;
    QPushButton* m_processProtectTrustedAddButton = nullptr;
    QPushButton* m_processProtectTrustedRemoveButton = nullptr;
    QTableWidget* m_processProtectTrustedTable = nullptr;
    QPushButton* m_processProtectApplyButton = nullptr;
    QPushButton* m_processProtectRefreshButton = nullptr;
    QPushButton* m_processProtectClearButton = nullptr;
    QLabel* m_processProtectStatusLabel = nullptr;

    QCheckBox* m_processProtectKernelCheck = nullptr;
    QCheckBox* m_processProtectSelfHealCheck = nullptr;
    QSpinBox* m_processProtectScanIntervalSpin = nullptr;
    QComboBox* m_processProtectKernelCombo = nullptr;
    QCheckBox* m_processProtectApplyOnCreateCheck = nullptr;
    QCheckBox* m_processProtectSelfHealRuleCheck = nullptr;
    QCheckBox* m_processProtectClearDebugPortCheck = nullptr;
    QPushButton* m_processProtectApplyKernelButton = nullptr;

    QPlainTextEdit* m_appLogEditor = nullptr;
    QPlainTextEdit* m_eventLogEditor = nullptr;

    QPushButton* m_startFileMonitorFsctlButton = nullptr;
    QPushButton* m_drainFileMonitorButton = nullptr;
    QPushButton* m_clearFileMonitorButton = nullptr;
    QPushButton* m_exportFileMonitorButton = nullptr;
    QCheckBox* m_fileMonitorFsctlOnlyCheck = nullptr;
    QLabel* m_fileMonitorStatusLabel = nullptr;
    QTableWidget* m_fileMonitorTable = nullptr;
    QTimer* m_fileMonitorDrainTimer = nullptr;
    QHash<quint32, QString> m_fileMonitorProcessNameCache;
    bool m_fileMonitorDrainInFlight = false;    // m_fileMonitorDrainInFlight：后台 drain 任务在途标志，只在 UI 线程读写，防止周期定时器堆积请求。

    KSWORD_ARK_CALLBACK_RUNTIME_STATE m_runtimeState{};
    quint64 m_nextRuleVersion = 1ULL;
    bool m_rulesApplied = false;
    bool m_dirty = false;
    bool m_ignoreUiSignal = false;
};

void KernelDock::initializeCallbackInterceptTab()
{
    if (m_callbackInterceptPage == nullptr || m_callbackInterceptController != nullptr)
    {
        return;
    }

    m_callbackInterceptController = new CallbackInterceptController(m_callbackInterceptPage, this);
}
