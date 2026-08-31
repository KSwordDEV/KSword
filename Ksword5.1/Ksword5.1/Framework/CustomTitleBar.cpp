#include "CustomTitleBar.h"

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPushButton>
#include <QResizeEvent>
#include <QScreen>
#include <QToolButton>
#include <QWidget>
#include <QWindow>

#include <Windows.h>

#include <algorithm>
#include <array>

namespace
{
    // 标题栏尺寸常量：
    // - kTitleBarHeight：标题栏固定高度；
    // - kControlButtonWidth：右上角控制按钮固定宽度；
    // - kControlButtonHeight：右上角控制按钮固定高度；
    // - kControlIconSize：右上角控制按钮图标尺寸；
    // - kCommandLineMinWidth：命令输入框最小宽度；
    // - kCommandLineMaxWidth：命令输入框最大宽度；
    // - kAppIconSize：左侧应用图标绘制尺寸。
    constexpr int kTitleBarHeight = 30;
    constexpr int kControlButtonWidth = 32;
    constexpr int kControlButtonHeight = 24;
    constexpr int kControlIconSize = 16;
    constexpr int kCommandLineMinWidth = 210;
    constexpr int kCommandLineMaxWidth = 760;
    constexpr int kAppIconSize = 18;

#ifdef Q_OS_WIN
    // readWindowsCurrentVersionStringValue：
    // - 作用：从 CurrentVersion 注册表项读取字符串值；
    // - 调用：resolveWindowsVersionText 读取 DisplayVersion/ReleaseId 时调用；
    // - 传入 valueName：要读取的注册表值名；
    // - 传出：读取成功时返回去除空白的文本，失败时返回空字符串。
    QString readWindowsCurrentVersionStringValue(const wchar_t* valueName)
    {
        constexpr wchar_t kCurrentVersionRegistryPath[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        HKEY currentVersionKeyHandle = nullptr;
        const LSTATUS openStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kCurrentVersionRegistryPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &currentVersionKeyHandle);
        if (openStatus != ERROR_SUCCESS)
        {
            return {};
        }

        wchar_t valueBuffer[128] = {};
        DWORD valueType = 0;
        DWORD valueSize = sizeof(valueBuffer);
        const LSTATUS queryStatus = ::RegQueryValueExW(
            currentVersionKeyHandle,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(valueBuffer),
            &valueSize);
        ::RegCloseKey(currentVersionKeyHandle);
        if (queryStatus != ERROR_SUCCESS
            || (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return {};
        }

        return QString::fromWCharArray(valueBuffer).trimmed();
    }

    // readWindowsCurrentVersionDwordValue：
    // - 作用：从 CurrentVersion 注册表项读取 DWORD 值；
    // - 调用：resolveWindowsVersionText 读取 UBR 时调用；
    // - 传入 valueName：要读取的注册表值名。
    // - 传出：读取成功时返回数值，失败时返回 0。
    DWORD readWindowsCurrentVersionDwordValue(const wchar_t* valueName)
    {
        constexpr wchar_t kCurrentVersionRegistryPath[] =
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        HKEY currentVersionKeyHandle = nullptr;
        const LSTATUS openStatus = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kCurrentVersionRegistryPath,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &currentVersionKeyHandle);
        if (openStatus != ERROR_SUCCESS)
        {
            return 0;
        }

        DWORD valueData = 0;
        DWORD valueType = 0;
        DWORD valueSize = sizeof(valueData);
        const LSTATUS queryStatus = ::RegQueryValueExW(
            currentVersionKeyHandle,
            valueName,
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(&valueData),
            &valueSize);
        ::RegCloseKey(currentVersionKeyHandle);
        if (queryStatus != ERROR_SUCCESS
            || valueType != REG_DWORD
            || valueSize != sizeof(valueData))
        {
            return 0;
        }

        return valueData;
    }
#endif

    // widgetBelongsTo：
    // - 作用：判断某个命中控件是否属于指定祖先控件分支；
    // - 调用：isPointInDraggableRegion 内部用于区分可拖拽区和交互控件区；
    // - 传入 widgetObject：命中控件；
    // - 传入 expectedAncestor：期望祖先控件；
    // - 传出：true=属于该祖先分支。
    bool widgetBelongsTo(const QWidget* widgetObject, const QWidget* expectedAncestor)
    {
        if (widgetObject == nullptr || expectedAncestor == nullptr)
        {
            return false;
        }

        const QWidget* cursorWidget = widgetObject;
        while (cursorWidget != nullptr)
        {
            if (cursorWidget == expectedAncestor)
            {
                return true;
            }
            cursorWidget = cursorWidget->parentWidget();
        }
        return false;
    }

#ifdef Q_OS_WIN
    // makeMouseScreenLParam：
    // - 输入 globalPoint：Qt 鼠标事件给出的全局屏幕坐标；
    // - 处理：按 Windows 鼠标消息约定把 signed x/y 打包到 LPARAM；
    // - 返回：可直接传给 WM_NCLBUTTONDOWN 的坐标参数。
    LPARAM makeMouseScreenLParam(const QPoint& globalPoint)
    {
        return MAKELPARAM(
            static_cast<SHORT>(globalPoint.x()),
            static_cast<SHORT>(globalPoint.y()));
    }

    // resolveTopLevelMoveResizeHitTest：
    // - 输入 hostWindowHandle：标题栏所属顶层窗口 HWND；
    // - 输入 globalPoint：当前鼠标全局坐标；
    // - 处理：在标题栏子控件主动桥接非客户区消息时，先判断是否落在窗口边框/角落；
    // - 返回：边框返回 HTLEFT/HTTOP...，普通标题栏返回 HTCAPTION。
    WPARAM resolveTopLevelMoveResizeHitTest(HWND hostWindowHandle, const QPoint& globalPoint)
    {
        if (hostWindowHandle == nullptr || ::IsWindow(hostWindowHandle) == FALSE)
        {
            return HTCAPTION;
        }
        if (::IsZoomed(hostWindowHandle) != FALSE)
        {
            return HTCAPTION;
        }

        RECT windowRectValue = {};
        if (::GetWindowRect(hostWindowHandle, &windowRectValue) == FALSE)
        {
            return HTCAPTION;
        }

        const int frameWidthValue = windowRectValue.right - windowRectValue.left;
        const int frameHeightValue = windowRectValue.bottom - windowRectValue.top;
        if (frameWidthValue <= 0 || frameHeightValue <= 0)
        {
            return HTCAPTION;
        }

        const int borderWidth = std::max(
            8,
            static_cast<int>(
                ::GetSystemMetrics(SM_CXSIZEFRAME)
                + ::GetSystemMetrics(SM_CXPADDEDBORDER)));
        const int frameLocalX = globalPoint.x() - windowRectValue.left;
        const int frameLocalY = globalPoint.y() - windowRectValue.top;

        const bool hitLeft = frameLocalX >= 0 && frameLocalX < borderWidth;
        const bool hitRight = frameLocalX <= frameWidthValue && frameLocalX > (frameWidthValue - borderWidth);
        const bool hitTop = frameLocalY >= 0 && frameLocalY < borderWidth;
        const bool hitBottom = frameLocalY <= frameHeightValue && frameLocalY > (frameHeightValue - borderWidth);

        if (hitTop && hitLeft)
        {
            return HTTOPLEFT;
        }
        if (hitTop && hitRight)
        {
            return HTTOPRIGHT;
        }
        if (hitBottom && hitLeft)
        {
            return HTBOTTOMLEFT;
        }
        if (hitBottom && hitRight)
        {
            return HTBOTTOMRIGHT;
        }
        if (hitLeft)
        {
            return HTLEFT;
        }
        if (hitRight)
        {
            return HTRIGHT;
        }
        if (hitTop)
        {
            return HTTOP;
        }
        if (hitBottom)
        {
            return HTBOTTOM;
        }

        return HTCAPTION;
    }
#endif

    // resolveApplicationPreviewIcon：
    // - 作用：优先从可执行文件路径提取系统壳层图标；
    // - 目标：让左上角图标与资源管理器中文件预览保持一致；
    // - 传出：成功返回可执行文件图标，失败返回空图标。
    QIcon resolveApplicationPreviewIcon()
    {
        // executablePathText 用途：保存当前进程可执行文件绝对路径。
        const QString executablePathText = QCoreApplication::applicationFilePath();
        if (executablePathText.trimmed().isEmpty())
        {
            return QIcon();
        }

        // executableFileInfo 用途：描述当前可执行文件路径，供壳层图标提供器读取。
        const QFileInfo executableFileInfo(executablePathText);
        if (!executableFileInfo.exists())
        {
            return QIcon();
        }

        // iconProvider 用途：向系统壳层查询与资源管理器一致的文件图标。
        QFileIconProvider iconProvider;
        return iconProvider.icon(executableFileInfo);
    }
}

namespace ks::ui
{
    CustomTitleBar::CustomTitleBar(QWidget* parentWidget)
        : QWidget(parentWidget)
    {
        initializeUi();
        initializeConnections();
        updateVisualState();
    }

    void CustomTitleBar::setPinnedState(const bool pinnedState)
    {
        m_isPinned = pinnedState;
        updateVisualState();
    }

    void CustomTitleBar::setCaptureProtectionState(const bool protectedState)
    {
        m_captureProtectionEnabled = protectedState;
        updateVisualState();
    }

    void CustomTitleBar::setMaximizedState(const bool maximizedState)
    {
        m_isMaximized = maximizedState;
        updateVisualState();
    }

    void CustomTitleBar::setDarkModeEnabled(const bool darkModeEnabled)
    {
        m_darkModeEnabled = darkModeEnabled;
        updateVisualState();
    }

    void CustomTitleBar::setCustomLeftWidget(QWidget* customLeftWidget)
    {
        if (m_leftLayout == nullptr || m_leftWidget == nullptr)
        {
            return;
        }

        if (m_customLeftWidget == customLeftWidget)
        {
            return;
        }

        if (m_customLeftWidget != nullptr)
        {
            m_leftLayout->removeWidget(m_customLeftWidget);
            m_customLeftWidget->hide();
        }

        m_customLeftWidget = customLeftWidget;
        if (m_customLeftWidget == nullptr)
        {
            return;
        }

        if (m_customLeftWidget->parentWidget() != m_leftWidget)
        {
            m_customLeftWidget->setParent(m_leftWidget);
        }
        m_customLeftWidget->setVisible(true);
        m_leftLayout->addWidget(m_customLeftWidget, 0);
    }

    void CustomTitleBar::setCustomRightWidget(QWidget* customRightWidget)
    {
        if (m_rightLayout == nullptr)
        {
            return;
        }

        if (m_customRightWidget == customRightWidget)
        {
            return;
        }

        if (m_customRightWidget != nullptr)
        {
            m_rightLayout->removeWidget(m_customRightWidget);
            m_customRightWidget->hide();
        }

        // m_customRightWidget 用途：保存右侧扩展控件实例，便于后续替换或移除。
        m_customRightWidget = customRightWidget;
        if (m_customRightWidget == nullptr)
        {
            return;
        }

        if (m_customRightWidget->parentWidget() != m_rightWidget)
        {
            m_customRightWidget->setParent(m_rightWidget);
        }
        m_customRightWidget->setVisible(true);
        m_rightLayout->insertWidget(0, m_customRightWidget, 0, Qt::AlignVCenter);
    }

    bool CustomTitleBar::isPointInDraggableRegion(const QPoint& localPos) const
    {
        if (!rect().contains(localPos))
        {
            return false;
        }

        // hitWidget 用于识别当前命中的子控件，避免交互控件也被当成拖动区。
        QWidget* hitWidget = childAt(localPos);
        if (hitWidget == nullptr)
        {
            return true;
        }

        if (widgetBelongsTo(hitWidget, m_centerInputGroup))
        {
            return false;
        }
        if (widgetBelongsTo(hitWidget, m_customLeftWidget))
        {
            return false;
        }
        if (widgetBelongsTo(hitWidget, m_systemVersionLabel))
        {
            return true;
        }
        if (widgetBelongsTo(hitWidget, m_rightWidget))
        {
            return false;
        }

        return true;
    }

    int CustomTitleBar::titleBarHeight() const
    {
        return kTitleBarHeight;
    }

    void CustomTitleBar::resizeEvent(QResizeEvent* resizeEventPointer)
    {
        QWidget::resizeEvent(resizeEventPointer);
        updateCommandLineWidth();
    }

    void CustomTitleBar::mousePressEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // Windows 下标题栏移动由原生非客户区消息处理。
        // 处理逻辑：
        // - 输入：左键按在可拖动标题栏区域；
        // - 处理：主动向顶层 HWND 投递 WM_NCLBUTTONDOWN/HTCAPTION；
        // - 返回：系统接管移动、Aero Snap、最大化拖下还原；函数本身无返回值。
        // 背景：
        // - 自绘标题栏是 Qt 子控件，普通鼠标消息未必会先触发顶层窗口 WM_NCHITTEST；
        // - 仅依赖 HTCAPTION 命中会导致“最大化后拖不下来”；
        // - 这里显式桥接到原生非客户区，避免重新使用 showNormal()+setGeometry() 模拟拖动。
        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            m_dragCandidateActive = false;
            m_dragInProgress = false;
            QWidget* hostWindowWidget = window();
            const HWND hostWindowHandleValue =
                hostWindowWidget != nullptr
                ? reinterpret_cast<HWND>(hostWindowWidget->winId())
                : nullptr;
            if (hostWindowHandleValue != nullptr && ::IsWindow(hostWindowHandleValue) != FALSE)
            {
                const QPoint globalPoint = mouseEventPointer->globalPosition().toPoint();
                const WPARAM hitTestCode = resolveTopLevelMoveResizeHitTest(hostWindowHandleValue, globalPoint);
                ::ReleaseCapture();
                ::SendMessageW(
                    hostWindowHandleValue,
                    WM_NCLBUTTONDOWN,
                    hitTestCode,
                    makeMouseScreenLParam(globalPoint));
                mouseEventPointer->accept();
                return;
            }

            QWidget::mousePressEvent(mouseEventPointer);
            return;
        }
#endif

        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            // m_dragCandidateActive 用途：标记本次左键按下可进入标题栏拖动候选状态。
            m_dragCandidateActive = true;
            // m_dragInProgress 用途：新的按压序列开始时重置“系统拖动已启动”标记。
            m_dragInProgress = false;
            // m_dragPressLocalPos 用途：保存按下时的标题栏局部坐标，供恢复窗口时计算相对位置。
            m_dragPressLocalPos = mouseEventPointer->position().toPoint();
            // m_dragPressGlobalPos 用途：保存按下时的全局坐标，供拖动阈值判断与恢复定位使用。
            m_dragPressGlobalPos = mouseEventPointer->globalPosition().toPoint();
            mouseEventPointer->accept();
            return;
        }

        m_dragCandidateActive = false;
        m_dragInProgress = false;
        QWidget::mousePressEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseMoveEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // Windows 下不再使用 showNormal()+setGeometry()+startSystemMove()
        // 手工模拟标题栏拖动。该旧链路会让 Qt::WindowMaximized 与
        // Win32 IsZoomed 脱节，表现为从最大化拖下后仍被认为最大化、
        // 最大化按钮无效、边框缩放命中异常。
        QWidget::mouseMoveEvent(mouseEventPointer);
        return;
#endif

        if (mouseEventPointer != nullptr
            && m_dragCandidateActive
            && !m_dragInProgress
            && (mouseEventPointer->buttons() & Qt::LeftButton))
        {
            // currentLocalPos 用途：记录本次 move 时相对标题栏左上角的坐标。
            const QPoint currentLocalPos = mouseEventPointer->position().toPoint();
            // dragDistance 用途：判断当前移动是否达到系统拖动阈值，避免点击被误判为拖动。
            const int dragDistance = (currentLocalPos - m_dragPressLocalPos).manhattanLength();
            if (dragDistance >= QApplication::startDragDistance())
            {
                // currentGlobalPos 用途：当前鼠标全局坐标，供恢复窗口和发起系统拖动复用。
                const QPoint currentGlobalPos = mouseEventPointer->globalPosition().toPoint();
                QWidget* hostWindowWidget = window();
                if (hostWindowWidget != nullptr)
                {
                    const bool hostWindowMaximized =
                        hostWindowWidget->isMaximized()
                        || ((hostWindowWidget->windowState() & Qt::WindowMaximized) != 0);
                    if (hostWindowMaximized)
                    {
                        restoreWindowFromMaximizedForDrag(hostWindowWidget, currentGlobalPos);
                    }

                    if (tryStartWindowSystemMove(currentGlobalPos))
                    {
                        m_dragCandidateActive = false;
                        m_dragInProgress = true;
                        mouseEventPointer->accept();
                        return;
                    }
                }
            }
        }

        QWidget::mouseMoveEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseReleaseEvent(QMouseEvent* mouseEventPointer)
    {
        m_dragCandidateActive = false;
        m_dragInProgress = false;
        QWidget::mouseReleaseEvent(mouseEventPointer);
    }

    void CustomTitleBar::mouseDoubleClickEvent(QMouseEvent* mouseEventPointer)
    {
#ifdef Q_OS_WIN
        // Windows 下双击标题栏同样由 HTCAPTION -> WM_NCLBUTTONDBLCLK 处理。
        // 这里不再发 requestToggleMaximizeWindow，防止 Qt 双击事件与原生
        // 非客户区双击各切换一次，导致最大化/还原互相抵消。
        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            m_dragCandidateActive = false;
            m_dragInProgress = false;
            QWidget* hostWindowWidget = window();
            const HWND hostWindowHandleValue =
                hostWindowWidget != nullptr
                ? reinterpret_cast<HWND>(hostWindowWidget->winId())
                : nullptr;
            if (hostWindowHandleValue != nullptr && ::IsWindow(hostWindowHandleValue) != FALSE)
            {
                ::SendMessageW(
                    hostWindowHandleValue,
                    WM_NCLBUTTONDBLCLK,
                    static_cast<WPARAM>(HTCAPTION),
                    makeMouseScreenLParam(mouseEventPointer->globalPosition().toPoint()));
                mouseEventPointer->accept();
                return;
            }

            QWidget::mouseDoubleClickEvent(mouseEventPointer);
            return;
        }
#endif

        if (mouseEventPointer != nullptr
            && mouseEventPointer->button() == Qt::LeftButton
            && isPointInDraggableRegion(mouseEventPointer->position().toPoint()))
        {
            m_dragCandidateActive = false;
            m_dragInProgress = false;
            emit requestToggleMaximizeWindow();
            mouseEventPointer->accept();
            return;
        }

        QWidget::mouseDoubleClickEvent(mouseEventPointer);
    }

    void CustomTitleBar::initializeUi()
    {
        setObjectName(QStringLiteral("ksCustomTitleBar"));
        setFixedHeight(kTitleBarHeight);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setAttribute(Qt::WA_StyledBackground, true);

        m_rootLayout = new QGridLayout(this);
        m_rootLayout->setContentsMargins(6, 1, 12, 1);
        m_rootLayout->setHorizontalSpacing(6);
        m_rootLayout->setVerticalSpacing(0);
        m_rootLayout->setColumnStretch(0, 1);
        m_rootLayout->setColumnStretch(1, 1);
        m_rootLayout->setColumnStretch(2, 1);

        // 左侧信息区：程序图标 + 固定标题文本 + 主窗口功能入口。
        m_leftWidget = new QWidget(this);
        m_leftLayout = new QHBoxLayout(m_leftWidget);
        m_leftLayout->setContentsMargins(0, 0, 0, 0);
        m_leftLayout->setSpacing(4);

        m_appIconLabel = new QLabel(m_leftWidget);
        m_appIconLabel->setFixedSize(kAppIconSize, kAppIconSize);
        m_appIconLabel->setAlignment(Qt::AlignCenter);

        m_titleTextLabel = new QLabel(m_leftWidget);
        m_titleTextLabel->setText(ks::i18n::sourceText(QStringLiteral("KswordARK")));
        m_titleTextLabel->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);

        m_leftLayout->addWidget(m_appIconLabel, 0);
        m_leftLayout->addWidget(m_titleTextLabel, 0);

        // 中间输入组：左侧模式按钮（搜索/CMD）+ 输入框，外观合并为一个整体。
        // 默认“搜索”模式做全局页面文本搜索；切到 CMD 模式后回车在新控制台执行。
        m_centerInputGroup = new QWidget(this);
        m_centerInputGroup->setObjectName(QStringLiteral("ksTitleInputGroup"));
        m_centerInputGroup->setAttribute(Qt::WA_StyledBackground, true);
        m_centerInputGroup->setFixedHeight(22);
        m_centerInputLayout = new QHBoxLayout(m_centerInputGroup);
        m_centerInputLayout->setContentsMargins(1, 1, 1, 1);
        m_centerInputLayout->setSpacing(0);

        m_inputModeButton = new QToolButton(m_centerInputGroup);
        m_inputModeButton->setObjectName(QStringLiteral("ksTitleInputModeButton"));
        m_inputModeButton->setPopupMode(QToolButton::InstantPopup);
        m_inputModeButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
        m_inputModeButton->setCursor(Qt::PointingHandCursor);
        m_inputModeButton->setFocusPolicy(Qt::NoFocus);
        m_inputModeButton->setFixedHeight(20);
        m_inputModeButton->setToolTip(QStringLiteral("切换输入模式：页面搜索或 CMD 命令执行"));

        m_inputModeMenu = new QMenu(m_inputModeButton);
        m_searchModeAction = m_inputModeMenu->addAction(QStringLiteral("搜索"));
        m_searchModeAction->setCheckable(true);
        m_commandModeAction = m_inputModeMenu->addAction(QStringLiteral("CMD 命令"));
        m_commandModeAction->setCheckable(true);
        m_inputModeButton->setMenu(m_inputModeMenu);

        m_commandLineEdit = new QLineEdit(m_centerInputGroup);
        m_commandLineEdit->setProperty("ksword_global_ui_search_input", true);
        m_commandLineEdit->setClearButtonEnabled(true);
        m_commandLineEdit->setFixedHeight(20);

        m_centerInputLayout->addWidget(m_inputModeButton, 0);
        m_centerInputLayout->addWidget(m_commandLineEdit, 1);

        // 右侧控制区：系统版本 + 截屏屏蔽 + 图钉 + 窗口按钮。
        m_rightWidget = new QWidget(this);
        m_rightLayout = new QHBoxLayout(m_rightWidget);
        m_rightLayout->setContentsMargins(0, 0, 2, 0);
        m_rightLayout->setSpacing(1);

        m_systemVersionLabel = new QLabel(m_rightWidget);
        m_systemVersionLabel->setObjectName(QStringLiteral("ksTitleSystemVersionLabel"));
        m_systemVersionLabel->setText(resolveWindowsVersionText());
        m_systemVersionLabel->setAlignment(Qt::AlignVCenter | Qt::AlignRight);
        m_systemVersionLabel->setFixedHeight(kControlButtonHeight);
        m_systemVersionLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

        m_captureProtectionButton = new QPushButton(m_rightWidget);
        m_pinButton = new QPushButton(m_rightWidget);
        m_minButton = new QPushButton(m_rightWidget);
        m_maxButton = new QPushButton(m_rightWidget);
        m_closeButton = new QPushButton(m_rightWidget);

        m_captureProtectionButton->setObjectName(QStringLiteral("ksTitleCaptureProtectionButton"));
        m_pinButton->setObjectName(QStringLiteral("ksTitlePinButton"));
        m_minButton->setObjectName(QStringLiteral("ksTitleMinButton"));
        m_maxButton->setObjectName(QStringLiteral("ksTitleMaxButton"));
        m_closeButton->setObjectName(QStringLiteral("ksTitleCloseButton"));

        m_rightLayout->addWidget(m_systemVersionLabel, 0, Qt::AlignVCenter);

        const std::array<QPushButton*, 5> controlButtons = {
            m_captureProtectionButton,
            m_pinButton,
            m_minButton,
            m_maxButton,
            m_closeButton
        };\
        for (QPushButton* buttonObject : controlButtons)
        {
            if (buttonObject == nullptr)
            {
                continue;
            }

            buttonObject->setFixedSize(kControlButtonWidth, kControlButtonHeight);
            buttonObject->setCursor(Qt::PointingHandCursor);
            buttonObject->setFocusPolicy(Qt::NoFocus);
            m_rightLayout->addWidget(buttonObject, 0);
        }

        m_captureProtectionButton->setToolTip(QStringLiteral("切换截屏屏蔽"));
        m_pinButton->setToolTip(QStringLiteral("切换窗口置顶状态"));
        m_minButton->setToolTip(QStringLiteral("最小化主窗口"));
        m_maxButton->setToolTip(QStringLiteral("最大化或还原主窗口"));
        m_closeButton->setToolTip(QStringLiteral("关闭主窗口"));

        m_rootLayout->addWidget(m_leftWidget, 0, 0, Qt::AlignLeft | Qt::AlignVCenter);
        m_rootLayout->addWidget(m_centerInputGroup, 0, 1, Qt::AlignCenter);
        m_rootLayout->addWidget(m_rightWidget, 0, 2, Qt::AlignRight | Qt::AlignVCenter);

        updateCommandLineWidth();
    }

    void CustomTitleBar::initializeConnections()
    {
        connect(m_captureProtectionButton, &QPushButton::clicked, this, [this]() {
            emit requestToggleCaptureProtection();
        });
        connect(m_pinButton, &QPushButton::clicked, this, [this]() {
            emit requestTogglePinned();
        });
        connect(m_minButton, &QPushButton::clicked, this, [this]() {
            emit requestMinimizeWindow();
        });
        connect(m_maxButton, &QPushButton::clicked, this, [this]() {
            emit requestToggleMaximizeWindow();
        });
        connect(m_closeButton, &QPushButton::clicked, this, [this]() {
            emit requestCloseWindow();
        });
        connect(m_commandLineEdit, &QLineEdit::returnPressed, this, [this]() {
            // 搜索模式的回车由 GlobalUiSearchController 的事件过滤器消费，
            // 走不到这里；此处只负责 CMD 模式的命令提交。
            if (m_searchInputModeActive)
            {
                return;
            }
            const QString commandText = m_commandLineEdit->text().trimmed();
            if (commandText.isEmpty())
            {
                return;
            }
            emit commandSubmitted(commandText);
        });
        connect(m_commandLineEdit, &QLineEdit::textChanged, this, [this](const QString& changedText) {
            if (m_searchInputModeActive)
            {
                emit searchTextEdited(changedText);
            }
        });
        connect(m_searchModeAction, &QAction::triggered, this, [this]() {
            setTitleInputMode(true);
        });
        connect(m_commandModeAction, &QAction::triggered, this, [this]() {
            setTitleInputMode(false);
        });
    }

    void CustomTitleBar::updateVisualState()
    {
        const QString titleBarBackgroundText = KswordTheme::MainBackgroundColorHex();
        const QString titleBarBorderText = KswordTheme::BorderColorHex();
        const QString titleTextColorText = KswordTheme::MainBackgroundTextColorHex();
        const QString commandBackgroundText = KswordTheme::SurfaceColorHex();
        const QString commandTextColorText = KswordTheme::TextPrimaryColorHex();
        const QString commandBorderText = KswordTheme::BorderStrongColorHex();

        const QString titleBarStyleSheetText = QStringLiteral(
            "#ksCustomTitleBar{"
            "  background:%1;"
            "  border-bottom:1px solid %2;"
            "}"
            "#ksCustomTitleBar QLabel{"
            "  color:%3;"
            "  font-weight:600;"
            "}"
            "#ksCustomTitleBar QLabel#ksTitleSystemVersionLabel{"
            "  color:%3;"
            "  font-weight:500;"
            "  padding:0 4px;"
            "}"
            "#ksCustomTitleBar #ksTitleInputGroup{"
            "  background:%4;"
            "  border:1px solid %6;"
            "  border-radius:3px;"
            "}"
            "#ksCustomTitleBar #ksTitleInputGroup QLineEdit{"
            "  background:transparent;"
            "  color:%5;"
            "  border:none;"
            "  padding:0 6px;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton{"
            "  background:transparent;"
            "  color:%5;"
            "  border:none;"
            "  border-right:1px solid %6;"
            "  border-top-left-radius:2px;"
            "  border-bottom-left-radius:2px;"
            "  padding:0 7px;"
            "  font-weight:600;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton::menu-indicator{"
            "  image:none;"
            "  width:0;"
            "}"
            "#ksCustomTitleBar QToolButton#ksTitleInputModeButton:hover{"
            "  background:__TITLE_BUTTON_HOVER__;"
            "  color:__TITLE_MODE_HOVER_TEXT__;"
            "}"
            "#ksCustomTitleBar QPushButton{"
            "  background:transparent;"
            "  color:%3;"
            "  border:none;"
            "  border-radius:3px;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCaptureProtectionButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitlePinButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitleMinButton:hover,"
            "#ksCustomTitleBar QPushButton#ksTitleMaxButton:hover{"
            "  background:__TITLE_BUTTON_HOVER__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCaptureProtectionButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitlePinButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitleMinButton:pressed,"
            "#ksCustomTitleBar QPushButton#ksTitleMaxButton:pressed{"
            "  background:__TITLE_BUTTON_PRESSED__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCloseButton:hover{"
            "  background:__TITLE_CLOSE_HOVER__;"
            "}"
            "#ksCustomTitleBar QPushButton#ksTitleCloseButton:pressed{"
            "  background:__TITLE_CLOSE_PRESSED__;"
            "}"
            "#ksCustomTitleBar QPushButton:disabled{"
            "  background:%4;"
            "  color:%5;"
            "  border:1px solid %6;"
            "  padding:0 6px;"
            "  font-weight:700;"
            "}")
            .arg(titleBarBackgroundText)
            .arg(titleBarBorderText)
            .arg(titleTextColorText)
            .arg(commandBackgroundText)
            .arg(commandTextColorText)
            .arg(commandBorderText)
            .replace(QStringLiteral("__TITLE_BUTTON_HOVER__"), KswordTheme::PrimaryBlueSolidHoverHex())
            .replace(QStringLiteral("__TITLE_MODE_HOVER_TEXT__"), KswordTheme::OnAccentHex())
            .replace(QStringLiteral("__TITLE_BUTTON_PRESSED__"), KswordTheme::PrimaryBluePressedHex)
            .replace(QStringLiteral("__TITLE_CLOSE_HOVER__"), KswordTheme::AccentHex(KswordTheme::AccentRole::Red, 53, 27))
            .replace(QStringLiteral("__TITLE_CLOSE_PRESSED__"), KswordTheme::AccentHex(KswordTheme::AccentRole::Red, 30, 4));
        setStyleSheet(titleBarStyleSheetText);

        // 图标与按钮文案同步：
        // - 截屏屏蔽按钮根据保护状态切换眼睛/闭眼；
        // - 图钉根据置顶状态切换空心/实心；
        // - 最大化按钮根据窗口状态切换最大化/还原图标。
        m_captureProtectionButton->setIcon(QIcon(
            m_captureProtectionEnabled
            ? QStringLiteral(":/Icon/titlebar_capture_protected.svg")
            : QStringLiteral(":/Icon/titlebar_capture_allowed.svg")));
        m_captureProtectionButton->setToolTip(m_captureProtectionEnabled
            ? QStringLiteral("截屏屏蔽已开启：点击后允许截屏")
            : QStringLiteral("截屏屏蔽已关闭：点击后在截图/录屏中隐藏或黑屏"));
        m_captureProtectionButton->setIconSize(QSize(kControlIconSize, kControlIconSize));

        m_pinButton->setIcon(QIcon(
            m_isPinned
            ? QStringLiteral(":/Icon/titlebar_pin_fill.svg")
            : QStringLiteral(":/Icon/titlebar_pin_line.svg")));
        m_pinButton->setToolTip(m_isPinned
            ? QStringLiteral("取消窗口置顶")
            : QStringLiteral("置顶窗口"));
        m_pinButton->setIconSize(QSize(kControlIconSize, kControlIconSize));

        m_minButton->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_minimize.svg")));
        m_minButton->setIconSize(QSize(kControlIconSize, kControlIconSize));

        m_maxButton->setIcon(QIcon(
            m_isMaximized
            ? QStringLiteral(":/Icon/titlebar_restore.svg")
            : QStringLiteral(":/Icon/titlebar_maximize.svg")));
        m_maxButton->setToolTip(m_isMaximized
            ? QStringLiteral("还原主窗口")
            : QStringLiteral("最大化主窗口"));
        m_maxButton->setIconSize(QSize(kControlIconSize, kControlIconSize));

        m_closeButton->setIcon(QIcon(QStringLiteral(":/Icon/titlebar_close.svg")));
        m_closeButton->setIconSize(QSize(kControlIconSize, kControlIconSize));

        updateTitleInputModeVisuals();

        QIcon appIcon = resolveApplicationPreviewIcon();
        if (appIcon.isNull() && window() != nullptr)
        {
            appIcon = window()->windowIcon();
        }
        if (appIcon.isNull())
        {
            appIcon = QApplication::windowIcon();
        }
        if (appIcon.isNull())
        {
            appIcon = QIcon(QStringLiteral(":/Image/Resource/Logo/MainLogo.png"));
        }
        m_appIconLabel->setPixmap(appIcon.pixmap(kAppIconSize, kAppIconSize));
    }

    void CustomTitleBar::updateCommandLineWidth()
    {
        if (m_centerInputGroup == nullptr)
        {
            return;
        }

        const int commandLineWidth = std::clamp(width() / 3, kCommandLineMinWidth, kCommandLineMaxWidth);
        m_centerInputGroup->setFixedWidth(commandLineWidth);
    }

    QLineEdit* CustomTitleBar::titleInputLineEdit() const
    {
        return m_commandLineEdit;
    }

    QWidget* CustomTitleBar::titleInputAnchorWidget() const
    {
        return m_centerInputGroup;
    }

    bool CustomTitleBar::isSearchInputModeActive() const
    {
        return m_searchInputModeActive;
    }

    void CustomTitleBar::activateSearchInput(const bool focusInput)
    {
        setTitleInputMode(true, focusInput);
    }

    void CustomTitleBar::setSearchScopeDisplayText(const QString& displayText)
    {
        const QString normalizedText = displayText.trimmed();
        m_searchScopeDisplayText = normalizedText.isEmpty()
            ? ks::i18n::sourceText(QStringLiteral("全局"))
            : normalizedText;
        updateTitleInputModeVisuals();
    }

    void CustomTitleBar::setTitleInputMode(
        const bool searchModeActive,
        const bool focusInput)
    {
        if (m_searchInputModeActive == searchModeActive)
        {
            updateTitleInputModeVisuals();
            if (focusInput && m_commandLineEdit != nullptr)
            {
                m_commandLineEdit->setFocus(Qt::OtherFocusReason);
            }
            return;
        }

        m_searchInputModeActive = searchModeActive;
        updateTitleInputModeVisuals();
        emit inputModeChanged(searchModeActive);
        if (searchModeActive && m_commandLineEdit != nullptr
            && !m_commandLineEdit->text().trimmed().isEmpty())
        {
            // 切回搜索模式时把已有文本重新交给搜索控制器恢复结果弹层。
            emit searchTextEdited(m_commandLineEdit->text());
        }
        if (focusInput && m_commandLineEdit != nullptr)
        {
            m_commandLineEdit->setFocus(Qt::OtherFocusReason);
        }
    }

    void CustomTitleBar::updateTitleInputModeVisuals()
    {
        if (m_inputModeButton == nullptr
            || m_commandLineEdit == nullptr
            || m_searchModeAction == nullptr
            || m_commandModeAction == nullptr)
        {
            return;
        }

        m_searchModeAction->setChecked(m_searchInputModeActive);
        m_commandModeAction->setChecked(!m_searchInputModeActive);
        if (m_searchInputModeActive)
        {
            m_inputModeButton->setText(
                ks::i18n::sourceText(QStringLiteral("搜索")) + QStringLiteral(" ▾"));
            m_inputModeButton->setToolTip(
                ks::i18n::sourceText(QStringLiteral("搜索范围：%1。聚焦输入框后按 Tab 切换范围。"))
                    .arg(m_searchScopeDisplayText));
            m_commandLineEdit->setPlaceholderText(
                ks::i18n::sourceText(QStringLiteral("搜索")));
        }
        else
        {
            m_inputModeButton->setText(QStringLiteral("CMD ▾"));
            m_commandLineEdit->setPlaceholderText(
                QStringLiteral("输入命令后回车：将使用 cmd /K 在新控制台执行"));
        }
    }

    bool CustomTitleBar::tryStartWindowSystemMove(const QPoint& globalPoint)
    {
        Q_UNUSED(globalPoint);

        // hostWindowWidget 用途：获取标题栏所属顶层窗口，后续向系统发起窗口拖动。
        QWidget* hostWindowWidget = window();
        if (hostWindowWidget == nullptr)
        {
            return false;
        }

        // hostWindowHandle 用途：Qt 提供的顶层原生窗口句柄封装。
        QWindow* hostWindowHandle = hostWindowWidget->windowHandle();
        if (hostWindowHandle != nullptr && hostWindowHandle->startSystemMove())
        {
            return true;
        }

#ifdef Q_OS_WIN
        // hostWindowHandleValue 用途：Win32 兜底拖动链路所需窗口句柄。
        const HWND hostWindowHandleValue = reinterpret_cast<HWND>(hostWindowWidget->winId());
        if (hostWindowHandleValue != nullptr && ::IsWindow(hostWindowHandleValue) != FALSE)
        {
            ::ReleaseCapture();
            ::SendMessageW(
                hostWindowHandleValue,
                WM_SYSCOMMAND,
                static_cast<WPARAM>(SC_MOVE | HTCAPTION),
                0);
            return true;
        }
#endif

        return false;
    }

    void CustomTitleBar::restoreWindowFromMaximizedForDrag(
        QWidget* hostWindowWidget,
        const QPoint& globalPoint)
    {
        if (hostWindowWidget == nullptr)
        {
            return;
        }

        // restoredGeometry 用途：读取窗口最大化前的正常几何信息，供拖下还原时复用。
        QRect restoredGeometry = hostWindowWidget->normalGeometry();
        if (!restoredGeometry.isValid()
            || restoredGeometry.width() <= 0
            || restoredGeometry.height() <= 0)
        {
            restoredGeometry = hostWindowWidget->geometry();
        }

        const int windowWidth = std::max(1, hostWindowWidget->width());
        // horizontalRatio 用途：保存按下点在整窗宽度中的比例，恢复后让鼠标仍落在相近位置。
        const double horizontalRatio = std::clamp(
            static_cast<double>(m_dragPressLocalPos.x()) / static_cast<double>(windowWidth),
            0.0,
            1.0);
        // restoredLeft 用途：计算恢复为窗口化后窗口左上角 X 坐标。
        int restoredLeft = globalPoint.x() - static_cast<int>(restoredGeometry.width() * horizontalRatio);
        // restoredTopOffset 用途：让窗口恢复后标题栏仍贴近鼠标，而不是直接跳到屏幕顶端。
        const int restoredTopOffset = std::clamp(m_dragPressLocalPos.y(), 12, 24);
        // restoredTop 用途：计算恢复为窗口化后窗口左上角 Y 坐标。
        int restoredTop = globalPoint.y() - restoredTopOffset;

        // screenObject 用途：找到当前鼠标所在屏幕，避免恢复后窗口跑出可用工作区。
        QScreen* screenObject = QGuiApplication::screenAt(globalPoint);
        if (screenObject == nullptr && hostWindowWidget->windowHandle() != nullptr)
        {
            screenObject = hostWindowWidget->windowHandle()->screen();
        }
        if (screenObject != nullptr)
        {
            const QRect availableGeometry = screenObject->availableGeometry();
            restoredLeft = std::clamp(
                restoredLeft,
                availableGeometry.left(),
                availableGeometry.right() - restoredGeometry.width() + 1);
            restoredTop = std::clamp(
                restoredTop,
                availableGeometry.top(),
                availableGeometry.bottom() - restoredGeometry.height() + 1);
        }

        hostWindowWidget->showNormal();
        hostWindowWidget->setGeometry(
            restoredLeft,
            restoredTop,
            restoredGeometry.width(),
            restoredGeometry.height());
    }

    QString CustomTitleBar::resolveWindowsVersionText() const
    {
#ifdef Q_OS_WIN
        using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
        const HMODULE ntdllModuleHandle = ::GetModuleHandleW(L"ntdll.dll");
        const auto rtlGetVersion = ntdllModuleHandle != nullptr
            ? reinterpret_cast<RtlGetVersionFunction>(
                ::GetProcAddress(ntdllModuleHandle, "RtlGetVersion"))
            : nullptr;
        if (rtlGetVersion == nullptr)
        {
            return {};
        }

        OSVERSIONINFOW versionInfo = {};
        versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
        if (rtlGetVersion(&versionInfo) != 0)
        {
            return {};
        }

        QString releaseVersionText = readWindowsCurrentVersionStringValue(L"DisplayVersion");
        if (releaseVersionText.isEmpty())
        {
            releaseVersionText = readWindowsCurrentVersionStringValue(L"ReleaseId");
        }
        if (releaseVersionText.isEmpty())
        {
            releaseVersionText = QString::number(versionInfo.dwBuildNumber);
        }

        const DWORD displayMajorVersion =
            versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 22000
            ? 11
            : versionInfo.dwMajorVersion;
        const DWORD updateBuildRevision = readWindowsCurrentVersionDwordValue(L"UBR");

        return QStringLiteral("Win")
            + QString::number(displayMajorVersion)
            + QStringLiteral(" ")
            + releaseVersionText
            + QStringLiteral("[")
            + QString::number(versionInfo.dwMajorVersion)
            + QStringLiteral(".")
            + QString::number(versionInfo.dwMinorVersion)
            + QStringLiteral(".")
            + QString::number(versionInfo.dwBuildNumber)
            + QStringLiteral(".")
            + QString::number(updateBuildRevision)
            + QStringLiteral("]");
#else
        return {};
#endif
    }
}
