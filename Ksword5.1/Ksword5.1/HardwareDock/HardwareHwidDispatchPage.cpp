#include "../UI/StructuredFieldView.h"
#include "HardwareHwidDispatchPage.h"
#include "../UI/VisibleTableWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"
#include "../UI/CodeEditorWidget.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPixmap>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <cwchar>

namespace
{
    // copyQStringToWide：
    // - 输入：Qt 字符串、固定宽字符缓冲区和容量；
    // - 处理：截断复制并强制 NUL 结尾；
    // - 返回：无返回值。
    void copyQStringToWide(const QString& text, wchar_t* destination, const std::size_t destinationChars)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }

        std::fill(destination, destination + destinationChars, L'\0');
        const std::wstring wideText = text.trimmed().toStdWString();
        const std::size_t copyChars = std::min(destinationChars - 1U, wideText.size());
        if (copyChars > 0U)
        {
            std::wmemcpy(destination, wideText.c_str(), copyChars);
        }
        destination[copyChars] = L'\0';
    }

    // fixedWideToQString：
    // - 输入：共享协议固定宽字符数组；
    // - 处理：按 NUL 终止转换为 QString；
    // - 返回：Qt 文本。
    QString fixedWideToQString(const wchar_t* text)
    {
        return text != nullptr ? QString::fromWCharArray(text) : QString();
    }

    // ntStatusText：
    // - 输入：NTSTATUS 数值；
    // - 处理：固定 8 位十六进制展示；
    // - 返回：例如 0xC0000001。
    QString ntStatusText(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // addressText：
    // - 输入：64 位地址；
    // - 处理：0 时展示短横线，非 0 时展示 16 位十六进制；
    // - 返回：界面地址文本。
    QString addressText(const unsigned long long address)
    {
        if (address == 0ULL)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper();
    }

    // createReadOnlyItem：
    // - 输入：单元格文本；
    // - 处理：创建不可编辑表格项；
    // - 返回：由 QTableWidget 接管生命周期的 item。
    QTableWidgetItem* createReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // targetNameFromFlag：
    // - 输入：KSWORD_ARK_HWID_DISPATCH_TARGET_*；
    // - 处理：转换为页面标题；
    // - 返回：目标名称。
    QString targetNameFromFlag(const unsigned long targetFlag)
    {
        switch (targetFlag)
        {
        case KSWORD_ARK_HWID_DISPATCH_TARGET_DISK:
            return QStringLiteral("磁盘序列号");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR:
            return QStringLiteral("分区/GPT GUID");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR:
            return QStringLiteral("卷唯一标识");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA:
            return QStringLiteral("NVIDIA GPU");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY:
            return QStringLiteral("NSI/ARP");
        default:
            return QStringLiteral("未知目标");
        }
    }
}

HardwareHwidDispatchPage::HardwareHwidDispatchPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    updatePlanPreview();
}

void HardwareHwidDispatchPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    showBlueScreenWarningOnce();
    refreshStatus();
}

void HardwareHwidDispatchPage::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("HWID Dispatch 派遣函数"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    m_rootLayout->addWidget(titleLabel, 0);

    m_statusLabel = new QLabel(QStringLiteral("状态：尚未查询驱动。"), this);
    m_statusLabel->setStyleSheet(QStringLiteral("font-weight:600;color:%1;").arg(KswordTheme::PrimaryBlueHex));
    m_rootLayout->addWidget(m_statusLabel, 0);

    // 风险说明改为常驻文字：真实下发前仍会弹出确认框，
    // 不再要求先勾选确认框（重复门槛，且忘记勾选只会得到一句报错）。
    auto* riskNoticeLabel = new QLabel(
        QStringLiteral("注意：启用/卸载派遣钩子可能导致蓝屏，请先保存工作并准备好恢复方案。"),
        this);
    riskNoticeLabel->setWordWrap(true);
    riskNoticeLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
    m_rootLayout->addWidget(riskNoticeLabel, 0);

    QGroupBox* targetGroup = new QGroupBox(QStringLiteral("Dispatch 目标驱动"), this);
    QGridLayout* targetLayout = new QGridLayout(targetGroup);
    m_diskCheck = new QCheckBox(QStringLiteral("\\Driver\\Disk - 磁盘查询派遣"), targetGroup);
    m_partMgrCheck = new QCheckBox(QStringLiteral("\\Driver\\partmgr - 分区信息派遣"), targetGroup);
    m_mountMgrCheck = new QCheckBox(QStringLiteral("\\Driver\\mountmgr - 卷唯一标识派遣"), targetGroup);
    m_nvidiaCheck = new QCheckBox(QStringLiteral("\\Driver\\nvlddmkm - NVIDIA GPU 派遣"), targetGroup);
    m_nsiProxyCheck = new QCheckBox(QStringLiteral("\\Driver\\nsiproxy - NSI/ARP 派遣"), targetGroup);
    m_diskCheck->setChecked(true);
    m_partMgrCheck->setChecked(true);
    m_mountMgrCheck->setChecked(true);
    targetLayout->addWidget(m_diskCheck, 0, 0);
    targetLayout->addWidget(m_partMgrCheck, 0, 1);
    targetLayout->addWidget(m_mountMgrCheck, 1, 0);
    targetLayout->addWidget(m_nvidiaCheck, 1, 1);
    targetLayout->addWidget(m_nsiProxyCheck, 2, 0);
    m_rootLayout->addWidget(targetGroup, 0);

    QGroupBox* profileGroup = new QGroupBox(QStringLiteral("派遣函数方案参数"), this);
    QGridLayout* profileLayout = new QGridLayout(profileGroup);
    m_diskModeCombo = new QComboBox(profileGroup);
    m_diskModeCombo->addItem(
        QStringLiteral("自定义序列号/产品/固件"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM)));
    m_diskModeCombo->addItem(
        QStringLiteral("随机化序列号"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM)));
    m_diskModeCombo->addItem(
        QStringLiteral("清空序列号"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_NULL)));
    m_macModeCombo = new QComboBox(profileGroup);
    m_macModeCombo->addItem(
        QStringLiteral("随机化物理 MAC"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM)));
    m_macModeCombo->addItem(
        QStringLiteral("自定义物理 MAC"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_MAC_MODE_CUSTOM)));
    m_macModeCombo->setToolTip(QStringLiteral("当前版本不会修改网卡 MAC 地址。"));
    m_diskSerialEdit = new QLineEdit(profileGroup);
    m_diskProductEdit = new QLineEdit(profileGroup);
    m_diskRevisionEdit = new QLineEdit(profileGroup);
    m_gpuSerialEdit = new QLineEdit(profileGroup);
    m_permanentMacEdit = new QLineEdit(profileGroup);
    m_currentMacEdit = new QLineEdit(profileGroup);
    m_permanentMacEdit->setToolTip(QStringLiteral("保留设置；当前版本不会修改此地址。"));
    m_currentMacEdit->setToolTip(QStringLiteral("保留设置；当前版本不会修改此地址。"));
    m_diskGuidCheck = new QCheckBox(QStringLiteral("随机化 GPT GUID 查询结果"), profileGroup);
    m_volumeCleanCheck = new QCheckBox(QStringLiteral("清理 MountMgr 卷唯一标识查询结果"), profileGroup);
    m_arpCleanCheck = new QCheckBox(QStringLiteral("清理 ARP Table 查询结果"), profileGroup);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘模式"), profileGroup), 0, 0);
    profileLayout->addWidget(m_diskModeCombo, 0, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘序列号"), profileGroup), 1, 0);
    profileLayout->addWidget(m_diskSerialEdit, 1, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘产品名"), profileGroup), 2, 0);
    profileLayout->addWidget(m_diskProductEdit, 2, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘固件值"), profileGroup), 3, 0);
    profileLayout->addWidget(m_diskRevisionEdit, 3, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("GPU 序列号"), profileGroup), 0, 2);
    profileLayout->addWidget(m_gpuSerialEdit, 0, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("MAC 模式(预留)"), profileGroup), 1, 2);
    profileLayout->addWidget(m_macModeCombo, 1, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("永久 MAC"), profileGroup), 2, 2);
    profileLayout->addWidget(m_permanentMacEdit, 2, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("当前 MAC"), profileGroup), 3, 2);
    profileLayout->addWidget(m_currentMacEdit, 3, 3);
    profileLayout->addWidget(m_diskGuidCheck, 4, 0, 1, 2);
    profileLayout->addWidget(m_volumeCleanCheck, 4, 2, 1, 2);
    profileLayout->addWidget(m_arpCleanCheck, 5, 0, 1, 2);
    m_rootLayout->addWidget(profileGroup, 0);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    m_refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("查询状态"), this);
    m_refreshButton->setToolTip(QStringLiteral("查询 KswordARK 驱动当前保存的 HWID Dispatch hook 状态。"));
    m_dryRunButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("干跑验证"), this);
    m_dryRunButton->setToolTip(QStringLiteral("只验证目标驱动对象是否可引用，不实际替换派遣函数。"));
    m_enableButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QStringLiteral("启用派遣函数"), this);
    // 作用域边界并入这个按钮：它是唯一真正改变系统行为的动作，说明放在这里最有机会被读到。
    m_enableButton->setToolTip(QStringLiteral("按所选目标替换 IRP_MJ_DEVICE_CONTROL 派遣函数；高风险，可能蓝屏。只改变所选设备的查询结果，不直接写入物理内存、固件或磁盘；网络选项目前仅影响 NSI/ARP 查询结果。"));
    m_disableButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("卸载全部派遣函数"), this);
    m_disableButton->setToolTip(QStringLiteral("恢复本页安装过的全部 Dispatch hook；高风险，可能蓝屏。"));
    m_copyPlanButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制计划"), this);
    m_copyPlanButton->setToolTip(QStringLiteral("复制当前目标、参数和风险说明，便于留档或复核。"));
    buttonLayout->addWidget(m_refreshButton);
    buttonLayout->addWidget(m_dryRunButton);
    buttonLayout->addWidget(m_enableButton);
    buttonLayout->addWidget(m_disableButton);
    buttonLayout->addWidget(m_copyPlanButton);
    buttonLayout->addStretch(1);
    m_rootLayout->addLayout(buttonLayout, 0);

    m_statusTable = new ks::ui::VisibleTableWidget(this);
    m_statusTable->setColumnCount(7);
    m_statusTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("目标"),
        QStringLiteral("驱动对象"),
        QStringLiteral("Active"),
        QStringLiteral("LastStatus"),
        QStringLiteral("DriverObject"),
        QStringLiteral("OriginalDispatch"),
        QStringLiteral("CurrentDispatch")
        });
    m_statusTable->verticalHeader()->setVisible(false);
    m_statusTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_statusTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_statusTable->setAlternatingRowColors(true);
    m_statusTable->horizontalHeader()->setStretchLastSection(true);
    m_rootLayout->addWidget(m_statusTable, 1);

    QWidget* editorPanel = new QWidget(this);
    QHBoxLayout* editorLayout = new QHBoxLayout(editorPanel);
    editorLayout->setContentsMargins(0, 0, 0, 0);
    editorLayout->setSpacing(8);
    m_planEditor = new ks::ui::StructuredFieldView(editorPanel);

    editorLayout->addWidget(m_planEditor, 1);
    m_rootLayout->addWidget(editorPanel, 1);
}

void HardwareHwidDispatchPage::initializeConnections()
{
    const QList<QObject*> planSources{
        m_diskCheck, m_partMgrCheck, m_mountMgrCheck, m_nvidiaCheck, m_nsiProxyCheck,
        m_diskGuidCheck, m_volumeCleanCheck, m_arpCleanCheck,
        m_diskModeCombo, m_macModeCombo,
        m_diskSerialEdit, m_diskProductEdit, m_diskRevisionEdit,
        m_gpuSerialEdit, m_permanentMacEdit, m_currentMacEdit
    };
    for (QObject* sourceObject : planSources)
    {
        if (auto* checkBox = qobject_cast<QCheckBox*>(sourceObject))
        {
            connect(checkBox, &QCheckBox::toggled, this, [this]() { updatePlanPreview(); });
        }
        else if (auto* comboBox = qobject_cast<QComboBox*>(sourceObject))
        {
            connect(comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { updatePlanPreview(); });
        }
        else if (auto* lineEdit = qobject_cast<QLineEdit*>(sourceObject))
        {
            connect(lineEdit, &QLineEdit::textChanged, this, [this](const QString&) { updatePlanPreview(); });
        }
    }

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshStatus(); });
    connect(m_dryRunButton, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, true);
    });
    connect(m_enableButton, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, false);
    });
    connect(m_disableButton, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL, false);
    });
    connect(m_copyPlanButton, &QPushButton::clicked, this, [this]() {
        if (QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(buildPlanText().toPlainText(true));
        }
    });
}

void HardwareHwidDispatchPage::showBlueScreenWarningOnce()
{
    if (m_warningShown)
    {
        return;
    }
    m_warningShown = true;
    QMessageBox::warning(
        this,
        QStringLiteral("蓝屏风险提示"),
        QStringLiteral("本页会接触内核驱动派遣函数 MajorFunction。启用或卸载 Dispatch hook 可能立即蓝屏，继续前请确认已保存工作、准备好 WinDbg 或恢复方案。"));
}

void HardwareHwidDispatchPage::refreshStatus()
{
    const ksword::ark::DriverClient client;
    applyResponseToUi(client.queryHwidDispatchState());
}

void HardwareHwidDispatchPage::sendControlRequest(const unsigned long action, const bool dryRun)
{
    if (!dryRun)
    {
        const QMessageBox::StandardButton answer = QMessageBox::warning(
            this,
            QStringLiteral("二次确认"),
            QStringLiteral("即将修改或恢复目标驱动的 IRP_MJ_DEVICE_CONTROL 派遣函数，存在蓝屏风险。是否继续？"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (answer != QMessageBox::Yes)
        {
            appendLogLine(QStringLiteral("[%1] 用户取消真实 Dispatch 操作。")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
            return;
        }
    }

    const ksword::ark::DriverClient client;
    applyResponseToUi(client.controlHwidDispatch(buildControlRequest(action, dryRun)));
}

KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST HardwareHwidDispatchPage::buildControlRequest(
    const unsigned long action,
    const bool dryRun) const
{
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.action = action;
    request.requestFlags = KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED;
    if (dryRun)
    {
        request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN;
    }
    request.profile.size = sizeof(request.profile);
    request.profile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.profile.targetFlags = selectedTargetFlags();
    request.profile.diskMode = static_cast<unsigned long>(m_diskModeCombo->currentData().toULongLong());
    request.profile.macMode = static_cast<unsigned long>(m_macModeCombo->currentData().toULongLong());
    request.profile.behaviorFlags =
        (m_diskGuidCheck->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_DISK_GUID_RANDOM : 0UL) |
        (m_volumeCleanCheck->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_VOLUME_ID_CLEAN : 0UL) |
        (m_arpCleanCheck->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_ARP_TABLE_CLEAN : 0UL);
    copyQStringToWide(m_diskSerialEdit->text(), request.profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(m_diskProductEdit->text(), request.profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(m_diskRevisionEdit->text(), request.profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(m_gpuSerialEdit->text(), request.profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(m_permanentMacEdit->text(), request.profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(m_currentMacEdit->text(), request.profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    return request;
}

unsigned long HardwareHwidDispatchPage::selectedTargetFlags() const
{
    unsigned long flags = 0UL;
    flags |= (m_diskCheck != nullptr && m_diskCheck->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_DISK : 0UL;
    flags |= (m_partMgrCheck != nullptr && m_partMgrCheck->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR : 0UL;
    flags |= (m_mountMgrCheck != nullptr && m_mountMgrCheck->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR : 0UL;
    flags |= (m_nvidiaCheck != nullptr && m_nvidiaCheck->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA : 0UL;
    flags |= (m_nsiProxyCheck != nullptr && m_nsiProxyCheck->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY : 0UL;
    return flags;
}

ks::ui::FieldDocument HardwareHwidDispatchPage::buildPlanText() const
{
    ks::ui::FieldDocument lines;
    lines.note(QStringLiteral("HWID Dispatch 派遣函数接入计划"));
    lines.field(QStringLiteral("来源"), QStringLiteral("https://github.com/FiYHer/EASY-HWID-SPOOFER"), true);
    lines.field(QStringLiteral("保留原理"), QStringLiteral("修改驱动程序的派遣函数(兼容性强)"), true);
    lines.field(QStringLiteral("排除原理"), QStringLiteral("定位物理内存直接修改硬件数据(兼容性弱)"), true);
    lines.field(QStringLiteral("网络范围"), QStringLiteral("仅 NSI/ARP 查询输出清理；NDIS 私有块 MAC 改写不接入。"), true);

    lines.field(QStringLiteral("目标 flags"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(selectedTargetFlags(), 8, 16, QChar('0')).toUpper()));
    lines.field(QStringLiteral("- \\Driver\\Disk"), QStringLiteral("%1").arg(m_diskCheck->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过")));
    lines.field(QStringLiteral("- \\Driver\\partmgr"), QStringLiteral("%1").arg(m_partMgrCheck->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过")));
    lines.field(QStringLiteral("- \\Driver\\mountmgr"), QStringLiteral("%1").arg(m_mountMgrCheck->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过")));
    lines.field(QStringLiteral("- \\Driver\\nvlddmkm"), QStringLiteral("%1").arg(m_nvidiaCheck->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过")));
    lines.field(QStringLiteral("- \\Driver\\nsiproxy"), QStringLiteral("%1").arg(m_nsiProxyCheck->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过")));

    lines.field(QStringLiteral("磁盘模式"), QStringLiteral("%1").arg(m_diskModeCombo->currentText()));
    lines.field(QStringLiteral("磁盘序列号"), QStringLiteral("%1").arg(m_diskSerialEdit->text().trimmed()));
    lines.field(QStringLiteral("磁盘产品名"), QStringLiteral("%1").arg(m_diskProductEdit->text().trimmed()));
    lines.field(QStringLiteral("磁盘固件值"), QStringLiteral("%1").arg(m_diskRevisionEdit->text().trimmed()));
    lines.field(QStringLiteral("GPU 序列号"), QStringLiteral("%1").arg(m_gpuSerialEdit->text().trimmed()));
    lines.field(QStringLiteral("MAC 模式"), QStringLiteral("%1").arg(m_macModeCombo->currentText()));
    lines.field(QStringLiteral("永久 MAC"), QStringLiteral("%1").arg(m_permanentMacEdit->text().trimmed()));
    lines.field(QStringLiteral("当前 MAC"), QStringLiteral("%1").arg(m_currentMacEdit->text().trimmed()));
    lines.field(QStringLiteral("MAC 字段说明"), QStringLiteral("当前仅随协议下发并作为预留，不触发 NDIS 私有链表扫描。"), true);
    lines.field(QStringLiteral("GPT GUID 随机化"), QStringLiteral("%1").arg(m_diskGuidCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否")));
    lines.field(QStringLiteral("卷唯一标识清理"), QStringLiteral("%1").arg(m_volumeCleanCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否")));
    lines.field(QStringLiteral("ARP Table 清理"), QStringLiteral("%1").arg(m_arpCleanCheck->isChecked() ? QStringLiteral("是") : QStringLiteral("否")));

    lines.field(QStringLiteral("风险"), QStringLiteral("启用/卸载 Dispatch hook 可能蓝屏；页面真实操作前仍需二次确认。"), true);
    return lines;
}

void HardwareHwidDispatchPage::updatePlanPreview()
{
    if (m_planEditor != nullptr)
    {
        m_planEditor->setDocument(buildPlanText());
    }
}

void HardwareHwidDispatchPage::applyResponseToUi(const ksword::ark::HwidDispatchResult& result)
{
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(result.unsupported
            ? QStringLiteral("状态：当前驱动未注册 HWID Dispatch IOCTL。")
            : QStringLiteral("状态：%1，Win32=%2，NT=%3，Active=0x%4")
                .arg(result.io.ok ? QStringLiteral("IOCTL 成功") : QStringLiteral("IOCTL 失败"))
                .arg(result.io.win32Error)
                .arg(ntStatusText(result.response.lastStatus))
                .arg(result.response.activeTargetFlags, 8, 16, QChar('0')).toUpper());
    }

    if (m_statusTable != nullptr)
    {
        m_statusTable->setRowCount(KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT);
        for (int rowIndex = 0; rowIndex < static_cast<int>(KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT); ++rowIndex)
        {
            const KSWORD_ARK_HWID_DISPATCH_ENTRY& entry = result.response.entries[rowIndex];
            m_statusTable->setItem(rowIndex, 0, createReadOnlyItem(targetNameFromFlag(entry.targetFlag)));
            m_statusTable->setItem(rowIndex, 1, createReadOnlyItem(fixedWideToQString(entry.driverName)));
            m_statusTable->setItem(rowIndex, 2, createReadOnlyItem(entry.active != 0UL ? QStringLiteral("是") : QStringLiteral("否")));
            m_statusTable->setItem(rowIndex, 3, createReadOnlyItem(ntStatusText(entry.lastStatus)));
            m_statusTable->setItem(rowIndex, 4, createReadOnlyItem(addressText(entry.driverObjectAddress)));
            m_statusTable->setItem(rowIndex, 5, createReadOnlyItem(addressText(entry.originalDispatchAddress)));
            m_statusTable->setItem(rowIndex, 6, createReadOnlyItem(addressText(entry.currentDispatchAddress)));
        }
        m_statusTable->resizeColumnsToContents();
    }

    appendLogLine(QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(QString::fromStdString(result.io.message)));
}

void HardwareHwidDispatchPage::appendLogLine(const QString& lineText)
{
    if (m_planEditor == nullptr) return;
    auto document = m_planEditor->document();
    if (document.isEmpty()) document = buildPlanText();
    document.note(lineText);
    m_planEditor->setDocument(document);
}
