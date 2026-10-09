#include "OtherDock.h"
#include "../UI/CodeEditorWidget.h"
#include "../theme.h"

// ============================================================
// OtherDock.DesktopCreate.cpp
// 作用说明：
// 1) 承载“桌面管理”页的新建桌面弹窗与 CreateDesktop/CreateDesktopEx 调用；
// 2) 把名称、堆大小、访问掩码、继承句柄、安全描述符等详细参数放入弹窗集中设置；
// 3) “其他进程不可访问”通过私有 DACL + 保留/继承创建句柄实现，避免其它进程按名称打开。
// ============================================================

#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include "../UI/CodeTextEdit.h"
#include <QPushButton>
#include <QSpinBox>
#include <QStringList>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

#ifndef DF_ALLOWOTHERACCOUNTHOOK
#define DF_ALLOWOTHERACCOUNTHOOK 0x0001
#endif

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace
{
    // CreateDesktopExWProc：
    // - 作用：动态绑定 CreateDesktopExW，避免旧 SDK 宏条件导致声明缺失；
    // - 返回：成功时返回新桌面句柄，失败时返回 nullptr 并设置 GetLastError。
    using CreateDesktopExWProc = HDESK(WINAPI*)(
        LPCWSTR,
        LPCWSTR,
        DEVMODEW*,
        DWORD,
        ACCESS_MASK,
        LPSECURITY_ATTRIBUTES,
        ULONG,
        PVOID);

    // AccessFlagControl：
    // - 作用：把一个访问掩码位和弹窗里的复选框绑定；
    // - 输入：mask 为 DESKTOP_* 或标准访问权限；
    // - 输出：collectDesiredAccess 会按 checked 状态合成最终 dwDesiredAccess。
    struct AccessFlagControl
    {
        QCheckBox* checkBox = nullptr;      // checkBox：弹窗中的参数开关。
        ACCESS_MASK mask = 0;               // mask：对应 Win32 访问掩码。
        QString nameText;                   // nameText：摘要中展示的权限名。
    };

    // SecurityDescriptorHolder：
    // - 作用：让 SECURITY_DESCRIPTOR / ACL / LocalFree 缓冲在 CreateDesktop 调用期间保持有效；
    // - 输入：由 buildSecurityDescriptorHolder 按默认/私有/SDDL 三种模式填充；
    // - 输出：descriptor() 返回可传给 SECURITY_ATTRIBUTES 的指针。
    struct SecurityDescriptorHolder
    {
        SECURITY_DESCRIPTOR descriptorStorage{}; // descriptorStorage：私有 DACL 模式下的绝对安全描述符。
        bool descriptorInitialized = false;       // descriptorInitialized：descriptorStorage 是否已初始化。
        std::vector<BYTE> aclBuffer;              // aclBuffer：私有 DACL 内存。
        PSECURITY_DESCRIPTOR localDescriptor = nullptr; // localDescriptor：SDDL API 分配的描述符。

        ~SecurityDescriptorHolder()
        {
            if (localDescriptor != nullptr)
            {
                ::LocalFree(localDescriptor);
            }
        }

        PSECURITY_DESCRIPTOR descriptor() const
        {
            if (localDescriptor != nullptr)
            {
                return localDescriptor;
            }
            if (descriptorInitialized)
            {
                return const_cast<SECURITY_DESCRIPTOR*>(&descriptorStorage);
            }
            return nullptr;
        }
    };

    // queryUserObjectNameForCreateDialog：
    // - 作用：读取当前窗口站名称，用于弹窗展示“创建目标”；
    // - 输入：Win32 用户对象句柄；
    // - 输出：成功返回对象名，失败返回空字符串。
    QString queryUserObjectNameForCreateDialog(HANDLE userObjectHandle)
    {
        if (userObjectHandle == nullptr)
        {
            return QString();
        }

        DWORD requiredBytes = 0;
        ::GetUserObjectInformationW(userObjectHandle, UOI_NAME, nullptr, 0, &requiredBytes);
        if (requiredBytes < sizeof(wchar_t))
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(requiredBytes / sizeof(wchar_t) + 1, L'\0');
        const BOOL queryOk = ::GetUserObjectInformationW(
            userObjectHandle,
            UOI_NAME,
            nameBuffer.data(),
            static_cast<DWORD>(nameBuffer.size() * sizeof(wchar_t)),
            &requiredBytes);
        return queryOk != FALSE
            ? QString::fromWCharArray(nameBuffer.data()).trimmed()
            : QString();
    }

    // desktopCreateInputStyle：
    // - 作用：给弹窗输入框使用与主界面一致的蓝色边框风格；
    // - 输入：无；
    // - 输出：Qt stylesheet 字符串。
    QString desktopCreateInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox,QPlainTextEdit{"
            "  border:1px solid %1;"
            "  border-radius:3px;"
            "  background:%2;"
            "  color:%3;"
            "  padding:3px 6px;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // desktopCreateDefaultAccess：
    // - 作用：提供适合 UI 创建/切换/查询的默认桌面访问掩码；
    // - 输入：无；
    // - 输出：DESKTOP_* 与标准访问权限的组合。
    ACCESS_MASK desktopCreateDefaultAccess()
    {
        return DESKTOP_CREATEWINDOW
            | DESKTOP_CREATEMENU
            | DESKTOP_ENUMERATE
            | DESKTOP_HOOKCONTROL
            | DESKTOP_READOBJECTS
            | DESKTOP_SWITCHDESKTOP
            | DESKTOP_WRITEOBJECTS
            | READ_CONTROL
            | WRITE_DAC;
    }

    // collectDesiredAccess：
    // - 作用：从权限复选框收集 dwDesiredAccess；
    // - 输入：accessControls 为弹窗中所有权限项；
    // - 输出：最终访问掩码，必要时自动补齐 READOBJECTS/WRITEOBJECTS。
    ACCESS_MASK collectDesiredAccess(const std::vector<AccessFlagControl>& accessControls)
    {
        ACCESS_MASK desiredAccess = 0;
        for (const AccessFlagControl& control : accessControls)
        {
            if (control.checkBox != nullptr && control.checkBox->isChecked())
            {
                desiredAccess |= control.mask;
            }
        }

        const bool standardSecurityRequested =
            (desiredAccess & (READ_CONTROL | WRITE_DAC | WRITE_OWNER)) != 0;
        if (standardSecurityRequested)
        {
            desiredAccess |= DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS;
        }
        return desiredAccess;
    }

    // accessMaskToText：
    // - 作用：把访问掩码转换成十六进制和权限名列表；
    // - 输入：accessControls 用于反查已勾选的名称；
    // - 输出：弹窗摘要和日志中的可读文本。
    QString accessMaskToText(
        const ACCESS_MASK desiredAccess,
        const std::vector<AccessFlagControl>& accessControls)
    {
        QStringList nameList;
        for (const AccessFlagControl& control : accessControls)
        {
            if ((desiredAccess & control.mask) != 0)
            {
                nameList << control.nameText;
            }
        }
        return QStringLiteral("0x%1 (%2)")
            .arg(static_cast<qulonglong>(desiredAccess), 8, 16, QChar('0'))
            .arg(nameList.isEmpty() ? QStringLiteral("无") : nameList.join(QStringLiteral(" | ")))
            .toUpper();
    }

    // buildPrivateDenyAllDescriptor：
    // - 作用：构造“空 DACL”安全描述符，阻止其它进程通过 OpenDesktopW 按名称重新打开；
    // - 输入：holder 用于保存 SECURITY_DESCRIPTOR 和 ACL 内存；
    // - 输出：成功返回 true，失败返回 false 并填充 errorText。
    bool buildPrivateDenyAllDescriptor(SecurityDescriptorHolder& holder, QString& errorText)
    {
        holder.aclBuffer.resize(sizeof(ACL));

        PSECURITY_DESCRIPTOR descriptor = &holder.descriptorStorage;
        PACL privateAcl = reinterpret_cast<PACL>(holder.aclBuffer.data());
        if (::InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) == FALSE)
        {
            errorText = QStringLiteral("InitializeSecurityDescriptor 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        holder.descriptorInitialized = true;
        if (::InitializeAcl(privateAcl, static_cast<DWORD>(holder.aclBuffer.size()), ACL_REVISION) == FALSE)
        {
            errorText = QStringLiteral("InitializeAcl 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        if (::SetSecurityDescriptorDacl(descriptor, TRUE, privateAcl, FALSE) == FALSE)
        {
            errorText = QStringLiteral("SetSecurityDescriptorDacl 失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        return true;
    }

    // buildSddlDescriptor：
    // - 作用：把用户输入的 SDDL 转换为 SECURITY_DESCRIPTOR；
    // - 输入：sddlText 为弹窗中的自定义安全描述符；
    // - 输出：成功返回 true，holder.localDescriptor 负责 LocalFree。
    bool buildSddlDescriptor(
        const QString& sddlText,
        SecurityDescriptorHolder& holder,
        QString& errorText)
    {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const BOOL convertOk = ::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            reinterpret_cast<LPCWSTR>(sddlText.utf16()),
            SDDL_REVISION_1,
            &descriptor,
            nullptr);
        if (convertOk == FALSE || descriptor == nullptr)
        {
            errorText = QStringLiteral("SDDL 转换失败，错误码=%1").arg(::GetLastError());
            return false;
        }
        holder.localDescriptor = descriptor;
        return true;
    }

    // loadCreateDesktopExW：
    // - 作用：从 user32.dll 动态获取 CreateDesktopExW；
    // - 输入：无；
    // - 输出：函数指针，系统不支持时返回 nullptr。
    CreateDesktopExWProc loadCreateDesktopExW()
    {
        HMODULE user32Module = ::GetModuleHandleW(L"user32.dll");
        if (user32Module == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<CreateDesktopExWProc>(
            ::GetProcAddress(user32Module, "CreateDesktopExW"));
    }

    // createDesktopWithParameters：
    // - 作用：根据弹窗参数调用 CreateDesktopW 或 CreateDesktopExW；
    // - 输入：desktopName/flags/access/securityAttributes/heapSizeKb；
    // - 输出：成功返回 HDESK，失败返回 nullptr 并填充 errorCodeOut。
    HDESK createDesktopWithParameters(
        const QString& desktopName,
        const DWORD flags,
        const ACCESS_MASK desiredAccess,
        SECURITY_ATTRIBUTES* securityAttributes,
        const DWORD heapSizeKb,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        if (heapSizeKb > 0)
        {
            CreateDesktopExWProc createDesktopExW = loadCreateDesktopExW();
            if (createDesktopExW == nullptr)
            {
                errorCodeOut = ERROR_PROC_NOT_FOUND;
                return nullptr;
            }
            HDESK desktopHandle = createDesktopExW(
                reinterpret_cast<LPCWSTR>(desktopName.utf16()),
                nullptr,
                nullptr,
                flags,
                desiredAccess,
                securityAttributes,
                heapSizeKb,
                nullptr);
            errorCodeOut = desktopHandle != nullptr ? ERROR_SUCCESS : ::GetLastError();
            return desktopHandle;
        }

        HDESK desktopHandle = ::CreateDesktopW(
            reinterpret_cast<LPCWSTR>(desktopName.utf16()),
            nullptr,
            nullptr,
            flags,
            desiredAccess,
            securityAttributes);
        errorCodeOut = desktopHandle != nullptr ? ERROR_SUCCESS : ::GetLastError();
        return desktopHandle;
    }
}

void OtherDock::showCreateDesktopDialog()
{
    kLogEvent dialogEvent;
    info << dialogEvent << "[OtherDock] 打开新建桌面参数弹窗。" << eol;

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("新建桌面 - 参数设置"));
    dialog.setMinimumWidth(760);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
    QLabel* introLabel = new QLabel(
        QStringLiteral("创建目标为当前进程窗口站；详细参数会直接传入 CreateDesktopW/CreateDesktopExW。"),
        &dialog);
    introLabel->setWordWrap(true);
    rootLayout->addWidget(introLabel);

    QGroupBox* basicGroup = new QGroupBox(QStringLiteral("基础参数"), &dialog);
    QFormLayout* basicLayout = new QFormLayout(basicGroup);
    QLineEdit* desktopNameEdit = new QLineEdit(
        QStringLiteral("KswordDesktop_%1").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        basicGroup);
    QLineEdit* windowStationEdit = new QLineEdit(
        queryUserObjectNameForCreateDialog(::GetProcessWindowStation()),
        basicGroup);
    QSpinBox* heapSizeSpin = new QSpinBox(basicGroup);
    QCheckBox* allowOtherAccountHookCheck = new QCheckBox(QStringLiteral("DF_ALLOWOTHERACCOUNTHOOK"), basicGroup);
    desktopNameEdit->setStyleSheet(desktopCreateInputStyle());
    windowStationEdit->setReadOnly(true);
    windowStationEdit->setStyleSheet(desktopCreateInputStyle());
    heapSizeSpin->setRange(0, 262144);
    heapSizeSpin->setSuffix(QStringLiteral(" KB"));
    heapSizeSpin->setSpecialValueText(QStringLiteral("默认"));
    heapSizeSpin->setToolTip(QStringLiteral("该桌面可用的界面内存上限，窗口很多时可调大；填 0 表示使用系统默认值"));
    allowOtherAccountHookCheck->setToolTip(QStringLiteral("允许其它用户帐户的程序在该桌面上设置钩子；出于安全考虑通常不勾选"));
    heapSizeSpin->setStyleSheet(desktopCreateInputStyle());
    basicLayout->addRow(QStringLiteral("桌面名称"), desktopNameEdit);
    basicLayout->addRow(QStringLiteral("目标窗口站"), windowStationEdit);
    basicLayout->addRow(QStringLiteral("桌面堆大小"), heapSizeSpin);
    basicLayout->addRow(QStringLiteral("创建标志"), allowOtherAccountHookCheck);
    rootLayout->addWidget(basicGroup);

    QGroupBox* accessGroup = new QGroupBox(QStringLiteral("访问掩码（dwDesiredAccess）"), &dialog);
    QGridLayout* accessLayout = new QGridLayout(accessGroup);
    std::vector<AccessFlagControl> accessControls;
    const std::array<std::pair<const char*, ACCESS_MASK>, 12> accessDefinitions = { {
        { "DESKTOP_CREATEWINDOW", DESKTOP_CREATEWINDOW },
        { "DESKTOP_CREATEMENU", DESKTOP_CREATEMENU },
        { "DESKTOP_ENUMERATE", DESKTOP_ENUMERATE },
        { "DESKTOP_HOOKCONTROL", DESKTOP_HOOKCONTROL },
        { "DESKTOP_JOURNALPLAYBACK", DESKTOP_JOURNALPLAYBACK },
        { "DESKTOP_JOURNALRECORD", DESKTOP_JOURNALRECORD },
        { "DESKTOP_READOBJECTS", DESKTOP_READOBJECTS },
        { "DESKTOP_SWITCHDESKTOP", DESKTOP_SWITCHDESKTOP },
        { "DESKTOP_WRITEOBJECTS", DESKTOP_WRITEOBJECTS },
        { "READ_CONTROL", READ_CONTROL },
        { "WRITE_DAC", WRITE_DAC },
        { "WRITE_OWNER", WRITE_OWNER }
    } };
    const ACCESS_MASK defaultAccess = desktopCreateDefaultAccess();
    for (int i = 0; i < static_cast<int>(accessDefinitions.size()); ++i)
    {
        QCheckBox* checkBox = new QCheckBox(QString::fromLatin1(accessDefinitions[i].first), accessGroup);
        checkBox->setChecked((defaultAccess & accessDefinitions[i].second) != 0);
        accessLayout->addWidget(checkBox, i / 3, i % 3);
        accessControls.push_back(AccessFlagControl{ checkBox, accessDefinitions[i].second, checkBox->text() });
    }
    rootLayout->addWidget(accessGroup);

    QGroupBox* securityGroup = new QGroupBox(QStringLiteral("安全与继承"), &dialog);
    QVBoxLayout* securityLayout = new QVBoxLayout(securityGroup);
    QCheckBox* privateAccessCheck = new QCheckBox(QStringLiteral("其他进程不可访问（仅当前进程和继承句柄的子进程可访问）"), securityGroup);
    QCheckBox* inheritableHandleCheck = new QCheckBox(QStringLiteral("返回句柄可继承"), securityGroup);
    QCheckBox* keepHandleCheck = new QCheckBox(QStringLiteral("创建后在本进程保留桌面句柄"), securityGroup);
    QCheckBox* switchAfterCreateCheck = new QCheckBox(QStringLiteral("创建成功后立即切换到该桌面"), securityGroup);
    QCheckBox* customSddlCheck = new QCheckBox(QStringLiteral("使用自定义 SDDL 安全描述符"), securityGroup);
    privateAccessCheck->setToolTip(QStringLiteral("限制只有本程序及其子进程能使用该桌面，其它程序无法访问"));
    inheritableHandleCheck->setToolTip(QStringLiteral("允许本程序启动的子进程继承这个桌面句柄"));
    keepHandleCheck->setToolTip(QStringLiteral("创建后不关闭句柄，保持桌面存在；取消勾选则桌面可能在无人使用时被系统回收"));
    switchAfterCreateCheck->setToolTip(QStringLiteral("创建完成后立刻切换过去（切换后原桌面窗口会暂时看不到）"));
    customSddlCheck->setToolTip(QStringLiteral("改用下方手写的 SDDL 字符串精确指定谁能访问该桌面，而不使用上面的勾选项"));
    auto* sddlEdit = new CodeTextEdit(securityGroup);
    sddlEdit->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    sddlEdit->setLineNumbersVisible(false);
    sddlEdit->setCompactMode(true);
    privateAccessCheck->setToolTip(QStringLiteral("使用空 DACL 阻止其它进程按名称打开；当前进程使用创建返回句柄，子进程需要继承该句柄。"));
    inheritableHandleCheck->setChecked(true);
    keepHandleCheck->setChecked(true);
    sddlEdit->setPlaceholderText(QStringLiteral("示例：D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"));
    sddlEdit->setEnabled(false);
    sddlEdit->setFixedHeight(58);
    sddlEdit->setStyleSheet(desktopCreateInputStyle());
    securityLayout->addWidget(privateAccessCheck);
    securityLayout->addWidget(inheritableHandleCheck);
    securityLayout->addWidget(keepHandleCheck);
    securityLayout->addWidget(switchAfterCreateCheck);
    securityLayout->addWidget(customSddlCheck);
    securityLayout->addWidget(sddlEdit);
    rootLayout->addWidget(securityGroup);

    // 参数摘要由本页按控件状态生成，使用统一编辑器以支持英语模式下的即时重绘。
    CodeEditorWidget* summaryEdit = new CodeEditorWidget(&dialog);
    summaryEdit->setReadOnly(true);
    summaryEdit->setFixedHeight(164);
    rootLayout->addWidget(summaryEdit);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("创建"));
    buttonBox->button(QDialogButtonBox::Ok)->setIcon(QIcon(":/Icon/desktop_create.svg"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    rootLayout->addWidget(buttonBox);

    std::function<void()> updateSummary = [&]() {
        const ACCESS_MASK desiredAccess = collectDesiredAccess(accessControls);
        const DWORD flags = allowOtherAccountHookCheck->isChecked() ? DF_ALLOWOTHERACCOUNTHOOK : 0;
        QStringList lines;
        lines << QStringLiteral("桌面：%1\\%2").arg(windowStationEdit->text(), desktopNameEdit->text().trimmed());
        lines << QStringLiteral("堆大小：%1").arg(heapSizeSpin->value() == 0 ? QStringLiteral("系统默认") : heapSizeSpin->text());
        lines << QStringLiteral("创建标志：0x%1").arg(static_cast<qulonglong>(flags), 8, 16, QChar('0')).toUpper();
        lines << QStringLiteral("访问掩码：%1").arg(accessMaskToText(desiredAccess, accessControls));
        lines << QStringLiteral("安全模式：%1").arg(privateAccessCheck->isChecked()
            ? QStringLiteral("私有空 DACL，外部进程不能按名称 OpenDesktopW")
            : (customSddlCheck->isChecked() ? QStringLiteral("自定义 SDDL") : QStringLiteral("默认 Token DACL")));
        lines << QStringLiteral("句柄策略：继承=%1；保留=%2；创建后切换=%3")
            .arg(inheritableHandleCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(keepHandleCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(switchAfterCreateCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"));
        summaryEdit->setLocalizedText(lines.join('\n'));
    };

    auto syncSecurityOptions = [&]() {
        const bool privateMode = privateAccessCheck->isChecked();
        inheritableHandleCheck->setChecked(privateMode ? true : inheritableHandleCheck->isChecked());
        keepHandleCheck->setChecked(privateMode ? true : keepHandleCheck->isChecked());
        inheritableHandleCheck->setEnabled(!privateMode);
        keepHandleCheck->setEnabled(!privateMode);
        customSddlCheck->setEnabled(!privateMode);
        sddlEdit->setEnabled(!privateMode && customSddlCheck->isChecked());
        updateSummary();
    };

    for (const AccessFlagControl& control : accessControls)
    {
        QObject::connect(control.checkBox, &QCheckBox::toggled, &dialog, [&](bool) {
            updateSummary();
        });
    }
    QObject::connect(desktopNameEdit, &QLineEdit::textChanged, &dialog, [&](const QString&) {
        updateSummary();
    });
    QObject::connect(heapSizeSpin, QOverload<int>::of(&QSpinBox::valueChanged), &dialog, [&](int) {
        updateSummary();
    });
    QObject::connect(allowOtherAccountHookCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(privateAccessCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        syncSecurityOptions();
    });
    QObject::connect(inheritableHandleCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(keepHandleCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(switchAfterCreateCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        updateSummary();
    });
    QObject::connect(customSddlCheck, &QCheckBox::toggled, &dialog, [&](bool) {
        syncSecurityOptions();
    });
    QObject::connect(sddlEdit, &QPlainTextEdit::textChanged, &dialog, [&]() {
        updateSummary();
    });
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dialog, [&]() {
        const QString desktopName = desktopNameEdit->text().trimmed();
        if (desktopName.isEmpty() || desktopName.contains(QChar('\\')) || desktopName.contains(QChar('/')))
        {
            QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), QStringLiteral("桌面名称不能为空，也不能包含路径分隔符。"));
            return;
        }

        SecurityDescriptorHolder securityHolder;
        QString securityErrorText;
        if (privateAccessCheck->isChecked())
        {
            if (!buildPrivateDenyAllDescriptor(securityHolder, securityErrorText))
            {
                QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), securityErrorText);
                return;
            }
        }
        else if (customSddlCheck->isChecked())
        {
            if (!buildSddlDescriptor(sddlEdit->toPlainText().trimmed(), securityHolder, securityErrorText))
            {
                QMessageBox::warning(&dialog, QStringLiteral("新建桌面"), securityErrorText);
                return;
            }
        }

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        securityAttributes.bInheritHandle = privateAccessCheck->isChecked() || inheritableHandleCheck->isChecked();
        securityAttributes.lpSecurityDescriptor = securityHolder.descriptor();

        const DWORD createFlags = allowOtherAccountHookCheck->isChecked() ? DF_ALLOWOTHERACCOUNTHOOK : 0;
        const ACCESS_MASK desiredAccess = collectDesiredAccess(accessControls);
        DWORD createErrorCode = ERROR_SUCCESS;
        HDESK desktopHandle = createDesktopWithParameters(
            desktopName,
            createFlags,
            desiredAccess,
            &securityAttributes,
            static_cast<DWORD>(heapSizeSpin->value()),
            createErrorCode);
        if (desktopHandle == nullptr)
        {
            err << dialogEvent
                << "[OtherDock] 新建桌面失败, desktop="
                << desktopName.toStdString()
                << ", code="
                << createErrorCode
                << eol;
            QMessageBox::warning(
                &dialog,
                QStringLiteral("新建桌面"),
                QStringLiteral("CreateDesktop 失败，错误码=%1。").arg(createErrorCode));
            return;
        }

        // 句柄继承位再次显式同步到返回句柄上，避免不同 API 路径对 SECURITY_ATTRIBUTES 的处理差异。
        const BOOL inheritHandleFlag = privateAccessCheck->isChecked() || inheritableHandleCheck->isChecked();
        if (::SetHandleInformation(
            desktopHandle,
            HANDLE_FLAG_INHERIT,
            inheritHandleFlag ? HANDLE_FLAG_INHERIT : 0) == FALSE)
        {
            warn << dialogEvent
                << "[OtherDock] 新建桌面后设置句柄继承位失败, desktop="
                << desktopName.toStdString()
                << ", code="
                << ::GetLastError()
                << eol;
        }

        const bool shouldKeepHandle = privateAccessCheck->isChecked() || keepHandleCheck->isChecked();
        if (shouldKeepHandle)
        {
            CreatedDesktopRecord record;
            record.windowStationName = windowStationEdit->text().trimmed();
            record.desktopName = desktopName;
            record.desktopHandle = desktopHandle;
            record.desiredAccess = desiredAccess;
            record.privateAccess = privateAccessCheck->isChecked();
            record.inheritableHandle = inheritHandleFlag != FALSE;
            m_createdDesktopHandles.push_back(record);
        }

        bool switched = false;
        DWORD switchErrorCode = ERROR_SUCCESS;
        if (switchAfterCreateCheck->isChecked())
        {
            switched = ::SwitchDesktop(desktopHandle) != FALSE;
            switchErrorCode = switched ? ERROR_SUCCESS : ::GetLastError();
        }
        if (!shouldKeepHandle)
        {
            ::CloseDesktop(desktopHandle);
        }

        const QString statusText = QStringLiteral("新建桌面成功：%1\\%2；私有=%3；保留句柄=%4%5")
            .arg(windowStationEdit->text().trimmed(), desktopName)
            .arg(privateAccessCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(shouldKeepHandle ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(switchAfterCreateCheck->isChecked()
                ? QStringLiteral("；切换=%1").arg(switched ? QStringLiteral("成功") : QStringLiteral("失败:%1").arg(switchErrorCode))
                : QString());
        if (m_desktopStatusLabel != nullptr)
        {
            m_desktopStatusLabel->setText(statusText);
        }

        info << dialogEvent
            << "[OtherDock] 新建桌面成功, desktop="
            << desktopName.toStdString()
            << ", desiredAccess="
            << static_cast<unsigned long>(desiredAccess)
            << ", privateAccess="
            << (privateAccessCheck->isChecked() ? 1 : 0)
            << ", keepHandle="
            << (shouldKeepHandle ? 1 : 0)
            << eol;
        refreshDesktopList();
        dialog.accept();
    });

    syncSecurityOptions();
    dialog.exec();
}
