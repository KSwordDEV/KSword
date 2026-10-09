#include "CommandExecutionPopup.h"
#include "ThemeBinding.h"

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QIntValidator>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    // 弹层尺寸常量：宽度与全局搜索弹层保持同一档位，避免两种模式跳变。
    constexpr int kPopupMinimumWidth = 460;
    constexpr int kPopupMaximumExtraWidth = 220;
    constexpr int kPopupMinimumHeight = 250;
    constexpr int kPopupHostMargin = 8;
    constexpr int kPopupAnchorGap = 6;
    constexpr int kSmallToolButtonSize = 28;

    // comboDataToInt：读取下拉框当前枚举值，并在控件尚未创建时回退到默认值。
    int comboDataToInt(const QComboBox* comboBox, const int fallbackValue)
    {
        if (comboBox == nullptr)
        {
            return fallbackValue;
        }
        bool conversionOk = false;
        const int value = comboBox->currentData().toInt(&conversionOk);
        return conversionOk ? value : fallbackValue;
    }
}

namespace ks::ui
{
    CommandExecutionPopup::CommandExecutionPopup(
        QWidget* popupHostWindow,
        QWidget* popupAnchorWidget,
        QLineEdit* commandInputEdit,
        QObject* parentObject)
        : QFrame(popupHostWindow)
        , m_popupHostWindow(popupHostWindow)
        , m_popupAnchorWidget(popupAnchorWidget)
        , m_commandInputEdit(commandInputEdit)
    {
        // popupHostWindow 已经同时承担 QWidget 与 QObject 父关系；保留 parentObject 参数
        // 是为了与其它 UI 控制器的构造约定一致，当前不重复改写 QWidget 父链。
        Q_UNUSED(parentObject);

        initializeUi();
        if (m_commandInputEdit != nullptr)
        {
            m_commandInputEdit->installEventFilter(this);
        }
        if (m_popupHostWindow != nullptr)
        {
            m_popupHostWindow->installEventFilter(this);
        }
        if (m_popupAnchorWidget != nullptr)
        {
            m_popupAnchorWidget->installEventFilter(this);
        }
        if (qApp != nullptr)
        {
            // 应用级过滤器只用于点击弹层和标题栏输入组之外时收起弹层。
            qApp->installEventFilter(this);
        }
        hide();
    }

    void CommandExecutionPopup::setCommandModeActive(const bool commandModeActive)
    {
        m_commandModeActive = commandModeActive;
        if (!m_commandModeActive)
        {
            dismissPopup();
            return;
        }

        // 切换到 CMD 模式立即展示选项，用户无需先猜测还有可配置参数。
        showPopupPanel();
    }

    CommandExecutionOptions CommandExecutionPopup::currentOptions() const
    {
        CommandExecutionOptions options;
        options.workingDirectory = m_workingDirectoryEdit != nullptr
            ? m_workingDirectoryEdit->text().trimmed()
            : QDir::currentPath();
        options.userMode = static_cast<CommandExecutionOptions::UserMode>(
            comboDataToInt(m_userModeCombo, static_cast<int>(CommandExecutionOptions::UserMode::CurrentUser)));
        options.tokenSourcePid = m_tokenPidEdit != nullptr
            ? m_tokenPidEdit->text().trimmed().toUInt()
            : 0U;
        options.privilegeMode = static_cast<CommandExecutionOptions::PrivilegeMode>(
            comboDataToInt(m_privilegeCombo, static_cast<int>(CommandExecutionOptions::PrivilegeMode::Current)));
        options.openConsoleWindow = m_openConsoleCheckBox == nullptr
            || m_openConsoleCheckBox->isChecked();
        return options;
    }

    bool CommandExecutionPopup::isPopupVisible() const
    {
        return isVisible();
    }

    void CommandExecutionPopup::dismissPopup()
    {
        if (isVisible())
        {
            hide();
        }
    }

    void CommandExecutionPopup::initializeUi()
    {
        // 弹层本身是宿主窗口的子控件，显式启用样式背景以避免透明主窗口透出黑底。
        setObjectName(QStringLiteral("ksCommandExecutionPopup"));
        setAttribute(Qt::WA_StyledBackground, true);
        setFrameShape(QFrame::NoFrame);

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(10, 8, 10, 8);
        rootLayout->setSpacing(7);

        auto* headerLayout = new QHBoxLayout();
        headerLayout->setContentsMargins(0, 0, 0, 0);
        headerLayout->setSpacing(4);

        m_titleLabel = new QLabel(this);
        m_titleLabel->setObjectName(QStringLiteral("ksCommandExecutionPopupTitle"));
        m_titleLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        m_closeButton = new QToolButton(this);
        m_closeButton->setObjectName(QStringLiteral("ksCommandExecutionPopupCloseButton"));
        m_closeButton->setAutoRaise(true);
        m_closeButton->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_close.svg")));
        m_closeButton->setIconSize(QSize(14, 14));
        m_closeButton->setFixedSize(kSmallToolButtonSize, kSmallToolButtonSize);

        headerLayout->addWidget(m_titleLabel, 1);
        headerLayout->addWidget(m_closeButton, 0);
        rootLayout->addLayout(headerLayout, 0);

        auto* formLayout = new QFormLayout();
        formLayout->setContentsMargins(0, 0, 0, 0);
        formLayout->setHorizontalSpacing(8);
        formLayout->setVerticalSpacing(6);
        formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

        m_workingDirectoryLabel = new QLabel(this);
        m_workingDirectoryEdit = new QLineEdit(this);
        m_workingDirectoryEdit->setClearButtonEnabled(true);
        m_workingDirectoryEdit->setText(QDir::currentPath());
        m_browseDirectoryButton = new QToolButton(this);
        m_browseDirectoryButton->setObjectName(QStringLiteral("ksCommandExecutionPopupBrowseButton"));
        m_browseDirectoryButton->setAutoRaise(true);
        m_browseDirectoryButton->setIcon(QIcon(QStringLiteral(":/Icon/settings_background_browse.svg")));
        m_browseDirectoryButton->setIconSize(QSize(16, 16));
        m_browseDirectoryButton->setFixedSize(kSmallToolButtonSize, kSmallToolButtonSize);

        auto* directoryRow = new QWidget(this);
        auto* directoryLayout = new QHBoxLayout(directoryRow);
        directoryLayout->setContentsMargins(0, 0, 0, 0);
        directoryLayout->setSpacing(4);
        directoryLayout->addWidget(m_workingDirectoryEdit, 1);
        directoryLayout->addWidget(m_browseDirectoryButton, 0);
        formLayout->addRow(m_workingDirectoryLabel, directoryRow);

        m_userModeLabel = new QLabel(this);
        m_userModeCombo = new QComboBox(this);
        m_userModeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::CurrentUser));
        m_userModeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::System));
        m_userModeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::UserMode::ProcessToken));
        formLayout->addRow(m_userModeLabel, m_userModeCombo);

        m_tokenPidLabel = new QLabel(this);
        m_tokenPidEdit = new QLineEdit(this);
        m_tokenPidEdit->setValidator(new QIntValidator(1, 0x7fffffff, m_tokenPidEdit));
        formLayout->addRow(m_tokenPidLabel, m_tokenPidEdit);

        m_privilegeLabel = new QLabel(this);
        m_privilegeCombo = new QComboBox(this);
        m_privilegeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::Current));
        m_privilegeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::Administrator));
        m_privilegeCombo->addItem(QString(), static_cast<int>(CommandExecutionOptions::PrivilegeMode::Standard));
        formLayout->addRow(m_privilegeLabel, m_privilegeCombo);

        rootLayout->addLayout(formLayout, 0);

        m_openConsoleCheckBox = new QCheckBox(this);
        m_openConsoleCheckBox->setChecked(true);
        rootLayout->addWidget(m_openConsoleCheckBox, 0);

        m_hintLabel = new QLabel(this);
        m_hintLabel->setObjectName(QStringLiteral("ksCommandExecutionPopupHint"));
        m_hintLabel->setWordWrap(true);
        rootLayout->addWidget(m_hintLabel, 0);

        auto* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->addStretch(1);

        m_executeButton = new QToolButton(this);
        m_executeButton->setObjectName(QStringLiteral("ksCommandExecutionPopupExecuteButton"));
        m_executeButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        m_executeButton->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
        m_executeButton->setIconSize(QSize(16, 16));
        m_executeButton->setMinimumWidth(88);
        m_executeButton->setMinimumHeight(28);
        actionLayout->addWidget(m_executeButton, 0);
        rootLayout->addLayout(actionLayout, 0);

        connect(m_closeButton, &QToolButton::clicked, this, [this]() {
            dismissPopup();
        });
        connect(m_browseDirectoryButton, &QToolButton::clicked, this, [this]() {
            selectWorkingDirectory();
        });
        connect(m_userModeCombo, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](const int) {
            updateUserModeUi();
        });
        connect(m_executeButton, &QToolButton::clicked, this, [this]() {
            requestExecution();
        });

        updateUserModeUi();
        refreshTextAndStyle();
        // 已创建的弹层也按明确角色更新；调度器在下一轮 GUI 事件循环刷新以保护下拉弹层。
        BindWidgetTheme(this, [this]() { refreshTextAndStyle(); });
    }

    void CommandExecutionPopup::refreshTextAndStyle()
    {
        if (m_titleLabel == nullptr)
        {
            return;
        }

        // 文本集中从语义键读取，语言切换后再次打开弹层即可刷新全部文案。
        m_titleLabel->setText(text(QStringLiteral("cmd.popup.title"), QStringLiteral("CMD 命令执行选项")));
        m_workingDirectoryLabel->setText(
            text(QStringLiteral("cmd.popup.directory"), QStringLiteral("执行目录")));
        m_userModeLabel->setText(text(QStringLiteral("cmd.popup.user"), QStringLiteral("用户")));
        m_tokenPidLabel->setText(text(QStringLiteral("cmd.popup.token_pid"), QStringLiteral("令牌 PID")));
        m_privilegeLabel->setText(text(QStringLiteral("cmd.popup.privilege"), QStringLiteral("权限")));
        m_userModeCombo->setItemText(
            0,
            text(QStringLiteral("cmd.popup.user.current"), QStringLiteral("当前用户（跟随 KSword）")));
        m_userModeCombo->setItemText(
            1,
            text(QStringLiteral("cmd.popup.user.system"), QStringLiteral("SYSTEM（PID 4）")));
        m_userModeCombo->setItemText(
            2,
            text(QStringLiteral("cmd.popup.user.process"), QStringLiteral("指定进程令牌")));
        m_privilegeCombo->setItemText(
            0,
            text(QStringLiteral("cmd.popup.privilege.current"), QStringLiteral("当前权限")));
        m_privilegeCombo->setItemText(
            1,
            text(QStringLiteral("cmd.popup.privilege.admin"), QStringLiteral("管理员（UAC）")));
        m_privilegeCombo->setItemText(
            2,
            text(QStringLiteral("cmd.popup.privilege.standard"), QStringLiteral("普通用户（Shell 令牌）")));
        m_tokenPidEdit->setPlaceholderText(
            text(QStringLiteral("cmd.popup.token_pid.placeholder"), QStringLiteral("指定进程的 PID")));
        m_openConsoleCheckBox->setText(
            text(QStringLiteral("cmd.popup.console"), QStringLiteral("打开 CMD 窗口（/K）")));
        m_hintLabel->setText(
            text(QStringLiteral("cmd.popup.hint"), QStringLiteral("回车或点击执行按钮；关闭窗口时使用 /C 后台执行。")));
        m_executeButton->setText(text(QStringLiteral("cmd.popup.execute"), QStringLiteral("执行")));

        m_closeButton->setToolTip(
            text(QStringLiteral("cmd.popup.collapse"), QStringLiteral("收起命令执行选项")));
        m_browseDirectoryButton->setToolTip(
            text(QStringLiteral("cmd.popup.directory.browse"), QStringLiteral("选择命令执行目录")));
        m_openConsoleCheckBox->setToolTip(text(
            QStringLiteral("cmd.popup.console.tooltip"),
            QStringLiteral("勾选后在可见 CMD 窗口中执行并保持窗口；取消后使用 /C 后台执行。")));
        m_executeButton->setToolTip(text(
            QStringLiteral("cmd.popup.execute.tooltip"),
            QStringLiteral("按当前目录、用户、权限和窗口设置执行命令")));

        const QString backgroundHex = KswordTheme::SurfaceHex();
        const QString alternateBackgroundHex = KswordTheme::SurfaceAltHex();
        const QString borderHex = KswordTheme::BorderStrongHex();
        const QString textPrimaryHex = KswordTheme::TextPrimaryHex();
        const QString textSecondaryHex = KswordTheme::TextSecondaryHex();
        const QString accentHex = KswordTheme::AccentHex(KswordTheme::AccentRole::Blue);
        const QString accentHoverHex = KswordTheme::PrimaryBlueSolidHoverHex();
        const QString accentTextHex = KswordTheme::OnAccentHex(
            KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));
        const QString accentHoverTextHex = KswordTheme::OnAccentHex(
            KswordTheme::PrimaryBlueSolidHoverColor());

        // 弹层显式设置各类控件背景，避免透明主窗口下继承黑色默认底色。
        setStyleSheet(QStringLiteral(
            "#ksCommandExecutionPopup{"
            "background:%1;"
            "border:1px solid %2;"
            "border-radius:6px;"
            "}"
            "#ksCommandExecutionPopup QLabel{"
            "color:%3;"
            "}"
            "#ksCommandExecutionPopup QLabel#ksCommandExecutionPopupTitle{"
            "color:%4;"
            "font-weight:600;"
            "}"
            "#ksCommandExecutionPopup QLineEdit,"
            "#ksCommandExecutionPopup QComboBox{"
            "background:%5;"
            "color:%4;"
            "border:1px solid %2;"
            "border-radius:3px;"
            "padding:3px 6px;"
            "min-height:22px;"
            "}"
            "#ksCommandExecutionPopup QLineEdit:focus,"
            "#ksCommandExecutionPopup QComboBox:focus{"
            "border:1px solid %6;"
            "}"
            "#ksCommandExecutionPopup QToolButton{"
            "color:%4;"
            "background:transparent;"
            "border:1px solid transparent;"
            "border-radius:3px;"
            "}"
            "#ksCommandExecutionPopup QToolButton:hover{"
            "background:%7;"
            "}"
            "#ksCommandExecutionPopup QToolButton#ksCommandExecutionPopupExecuteButton{"
            "background:%6;"
            "color:%8;"
            "border:1px solid %6;"
            "font-weight:600;"
            "padding:3px 10px;"
            "}"
            "#ksCommandExecutionPopup QToolButton#ksCommandExecutionPopupExecuteButton:hover{"
            "background:%7;"
            "border:1px solid %7;"
            "color:__EXECUTE_HOVER_TEXT__;"
            "}"
            "#ksCommandExecutionPopup QLabel#ksCommandExecutionPopupHint{"
            "color:%3;"
            "}"
            "#ksCommandExecutionPopup QCheckBox{"
            "color:%4;"
            "}")
            .arg(
                backgroundHex,
                borderHex,
                textSecondaryHex,
                textPrimaryHex,
                alternateBackgroundHex,
                accentHex,
                accentHoverHex,
                accentTextHex)
            .replace(QStringLiteral("__EXECUTE_HOVER_TEXT__"), accentHoverTextHex));
    }

    void CommandExecutionPopup::showPopupPanel()
    {
        if (!m_commandModeActive || m_popupHostWindow == nullptr || m_popupAnchorWidget == nullptr)
        {
            return;
        }

        refreshTextAndStyle();
        updateUserModeUi();
        if (layout() != nullptr)
        {
            layout()->activate();
        }

        const int hostWidth = std::max(320, m_popupHostWindow->width() - 24);
        const int minimumWidth = std::min(kPopupMinimumWidth, hostWidth);
        const int panelWidth = std::clamp(
            m_popupAnchorWidget->width() + kPopupMaximumExtraWidth,
            minimumWidth,
            hostWidth);
        const int panelHeight = std::max(
            kPopupMinimumHeight,
            layout() != nullptr ? layout()->sizeHint().height() + 4 : kPopupMinimumHeight);
        setFixedSize(panelWidth, panelHeight);

        repositionPopupPanel();
        show();
        raise();
        QTimer::singleShot(0, this, [this]()
        {
            if (isVisible())
            {
                repositionPopupPanel();
            }
        });
    }

    void CommandExecutionPopup::repositionPopupPanel()
    {
        if (m_popupHostWindow == nullptr || m_popupAnchorWidget == nullptr)
        {
            return;
        }

        const QPoint anchorBottomLeftGlobal = m_popupAnchorWidget->mapToGlobal(
            QPoint(0, m_popupAnchorWidget->height()));
        const QPoint anchorBottomLeftInHost = m_popupHostWindow->mapFromGlobal(anchorBottomLeftGlobal);
        const int maxPanelLeft = std::max(
            kPopupHostMargin,
            m_popupHostWindow->width() - width() - kPopupHostMargin);
        const int panelLeft = std::clamp(
            anchorBottomLeftInHost.x() + (m_popupAnchorWidget->width() - width()) / 2,
            kPopupHostMargin,
            maxPanelLeft);
        const int panelTop = anchorBottomLeftInHost.y() + kPopupAnchorGap;
        move(panelLeft, panelTop);
    }

    void CommandExecutionPopup::updateUserModeUi()
    {
        if (m_userModeCombo == nullptr || m_tokenPidLabel == nullptr || m_tokenPidEdit == nullptr)
        {
            return;
        }

        const bool currentUserSelected = comboDataToInt(
            m_userModeCombo,
            static_cast<int>(CommandExecutionOptions::UserMode::CurrentUser))
            == static_cast<int>(CommandExecutionOptions::UserMode::CurrentUser);
        const bool processTokenSelected = comboDataToInt(
            m_userModeCombo,
            static_cast<int>(CommandExecutionOptions::UserMode::CurrentUser))
            == static_cast<int>(CommandExecutionOptions::UserMode::ProcessToken);

        m_tokenPidLabel->setVisible(processTokenSelected);
        m_tokenPidEdit->setVisible(processTokenSelected);

        // SYSTEM 与指定进程令牌的权限由所选令牌决定，不再追加 UAC/降级选择。
        if (m_privilegeCombo != nullptr)
        {
            m_privilegeCombo->setEnabled(currentUserSelected);
            if (!currentUserSelected && m_privilegeCombo->currentIndex() != 0)
            {
                m_privilegeCombo->setCurrentIndex(0);
            }
        }
    }

    void CommandExecutionPopup::selectWorkingDirectory()
    {
        const QString currentPath = m_workingDirectoryEdit != nullptr
            ? m_workingDirectoryEdit->text().trimmed()
            : QDir::currentPath();
        const QString selectedPath = QFileDialog::getExistingDirectory(
            m_popupHostWindow != nullptr ? m_popupHostWindow.data() : this,
            text(QStringLiteral("cmd.popup.directory.dialog.title"), QStringLiteral("选择命令执行目录")),
            QFileInfo(currentPath).isDir() ? currentPath : QDir::currentPath());
        if (!selectedPath.isEmpty() && m_workingDirectoryEdit != nullptr)
        {
            m_workingDirectoryEdit->setText(QDir::toNativeSeparators(selectedPath));
        }
    }

    void CommandExecutionPopup::requestExecution()
    {
        if (m_commandInputEdit == nullptr)
        {
            return;
        }

        const QString commandText = m_commandInputEdit->text().trimmed();
        if (commandText.isEmpty())
        {
            m_commandInputEdit->setFocus(Qt::OtherFocusReason);
            return;
        }

        const CommandExecutionOptions options = currentOptions();
        if (options.userMode == CommandExecutionOptions::UserMode::ProcessToken
            && options.tokenSourcePid == 0U)
        {
            QMessageBox::warning(
                m_popupHostWindow != nullptr ? m_popupHostWindow.data() : this,
                text(QStringLiteral("cmd.popup.token.invalid.title"), QStringLiteral("令牌 PID 无效")),
                text(
                    QStringLiteral("cmd.popup.token.invalid.message"),
                    QStringLiteral("请输入有效的进程 PID。")));
            return;
        }

        emit executeRequested(commandText, options);
    }

    bool CommandExecutionPopup::widgetBelongsToBranch(QWidget* widget, QWidget* branchRoot)
    {
        if (widget == nullptr || branchRoot == nullptr)
        {
            return false;
        }
        QWidget* currentWidget = widget;
        while (currentWidget != nullptr)
        {
            if (currentWidget == branchRoot)
            {
                return true;
            }
            currentWidget = currentWidget->parentWidget();
        }
        return false;
    }

    bool CommandExecutionPopup::isComboPopupEvent(QObject* watchedObject) const
    {
        QWidget* watchedWidget = qobject_cast<QWidget*>(watchedObject);
        if (watchedWidget == nullptr || QApplication::activePopupWidget() == nullptr)
        {
            return false;
        }

        const QComboBox* comboBoxList[] = {m_userModeCombo, m_privilegeCombo};
        for (const QComboBox* comboBox : comboBoxList)
        {
            if (comboBox == nullptr || comboBox->view() == nullptr)
            {
                continue;
            }

            // QComboBox 的列表通常位于独立 Qt::Popup 窗口，不能只沿 parentWidget 判断归属。
            QWidget* comboPopupWindow = comboBox->view()->window();
            if (comboPopupWindow == nullptr)
            {
                continue;
            }
            if (watchedWidget == comboPopupWindow
                || widgetBelongsToBranch(watchedWidget, comboPopupWindow))
            {
                return true;
            }
        }
        return false;
    }

    QString CommandExecutionPopup::text(const QString& key, const QString& fallbackText)
    {
        return ks::i18n::text(key, fallbackText);
    }

    bool CommandExecutionPopup::eventFilter(QObject* watchedObject, QEvent* eventObject)
    {
        if (eventObject == nullptr)
        {
            return false;
        }
        const QEvent::Type eventType = eventObject->type();
        if (watchedObject == m_commandInputEdit)
        {
            if (m_commandModeActive
                && (eventType == QEvent::FocusIn || eventType == QEvent::MouseButtonPress))
            {
                showPopupPanel();
            }
            if (m_commandModeActive && eventType == QEvent::KeyPress)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->key() == Qt::Key_Escape && isVisible())
                {
                    dismissPopup();
                    return true;
                }
                if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
                {
                    // 在 CMD 模式由弹层统一校验令牌输入；权限确认由 MainWindow 执行入口统一处理。
                    requestExecution();
                    return true;
                }
            }
            return false;
        }

        if (watchedObject == m_popupHostWindow || watchedObject == m_popupAnchorWidget)
        {
            if (isVisible()
                && (eventType == QEvent::Move
                    || eventType == QEvent::Resize
                    || eventType == QEvent::LayoutRequest
                    || eventType == QEvent::Show))
            {
                QTimer::singleShot(0, this, [this]()
                {
                    if (isVisible())
                    {
                        repositionPopupPanel();
                    }
                });
            }
            else if (watchedObject == m_popupHostWindow
                && isVisible()
                && eventType == QEvent::WindowDeactivate)
            {
                dismissPopup();
            }
            return false;
        }

        if (eventType == QEvent::MouseButtonPress && isVisible())
        {
            // 下拉列表是独立 Popup：放行其鼠标事件，不能在选项点击过程中隐藏本弹层。
            if (isComboPopupEvent(watchedObject))
            {
                return false;
            }

            QWidget* clickedWidget = qobject_cast<QWidget*>(watchedObject);
            if (clickedWidget != nullptr
                && !widgetBelongsToBranch(clickedWidget, this)
                && !widgetBelongsToBranch(clickedWidget, m_popupAnchorWidget))
            {
                dismissPopup();
            }
        }
        return false;
    }
}
