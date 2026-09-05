#include "KvmCrPolicyDialog.h"

#include "KvmControl.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // 常用的钉住目标，按位给出，避免用户手算掩码。
    constexpr unsigned long long kCr0WriteProtect = 1ull << 16;
    constexpr unsigned long long kCr4Smep = 1ull << 20;
    constexpr unsigned long long kCr4Smap = 1ull << 21;
    constexpr unsigned long long kCr4Umip = 1ull << 11;

    // parseHexOrZero：空输入视为零，其余按十六进制解析。
    bool parseHexOrZero(const QString& text, unsigned long long* valueOut)
    {
        QString compact = text.trimmed();
        if (compact.isEmpty())
        {
            *valueOut = 0;
            return true;
        }
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        bool converted = false;
        const unsigned long long value = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = value;
        return true;
    }
}

KvmCrPolicyDialog::KvmCrPolicyDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(
        ks::i18n::sourceText(QStringLiteral("KVM 控制寄存器策略")));
    setObjectName(QStringLiteral("KvmCrPolicyDialog"));
    buildUi();
    updateEnabledState();
    refreshPolicy();
}

void KvmCrPolicyDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    QLabel* const hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("被钉住的位由 hypervisor 持有：guest 改它会被驳回，但影子仍回报改成功。掩码在建 VMCS 时消费，必须在常驻启动前配置。")),
        this);
    hintLabel->setWordWrap(true);
    rootLayout->addWidget(hintLabel);

    QFormLayout* const formLayout = new QFormLayout();
    m_pinWpCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR0.WP（内核写保护）")), this);
    m_pinSmepCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.SMEP")), this);
    m_pinSmapCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.SMAP")), this);
    m_pinUmipCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("钉住 CR4.UMIP")), this);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("常用钉住位")),
        m_pinWpCheck);
    formLayout->addRow(QString(), m_pinSmepCheck);
    formLayout->addRow(QString(), m_pinSmapCheck);
    formLayout->addRow(QString(), m_pinUmipCheck);

    m_cr0MaskEdit = new QLineEdit(this);
    m_cr0MaskEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("额外的 CR0 掩码位，十六进制")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("CR0 附加掩码")),
        m_cr0MaskEdit);

    m_cr4MaskEdit = new QLineEdit(this);
    m_cr4MaskEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("额外的 CR4 掩码位，十六进制")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("CR4 附加掩码")),
        m_cr4MaskEdit);

    m_trackCr3Check = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("跟踪地址空间切换（每次切换一次 VM-exit，非常昂贵）")),
        this);
    m_interceptDrCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("拦截调试寄存器访问（只记录，不改变行为）")),
        this);
    m_logCheck = new QCheckBox(
        ks::i18n::sourceText(QStringLiteral("把拦截写进事件环")), this);
    formLayout->addRow(QString(), m_trackCr3Check);
    formLayout->addRow(QString(), m_interceptDrCheck);
    formLayout->addRow(QString(), m_logCheck);
    rootLayout->addLayout(formLayout);

    m_currentLabel = new QLabel(QString(), this);
    m_currentLabel->setWordWrap(true);
    m_currentLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(m_currentLabel, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_applyButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("应用配置")), this);
    m_clearButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("清除配置")), this);
    m_refreshButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("刷新")), this);
    buttonLayout->addWidget(m_applyButton, 0, 0);
    buttonLayout->addWidget(m_clearButton, 0, 1);
    buttonLayout->addWidget(m_refreshButton, 0, 2);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_applyButton, &QPushButton::clicked, this, [this]() {
        startApply();
    });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() {
        startClear();
    });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshPolicy();
    });
    resize(640, 520);
}

void KvmCrPolicyDialog::updateEnabledState()
{
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString writeHint = writeAllowed
        ? QString()
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能配置策略"));
    if (m_applyButton != nullptr)
    {
        m_applyButton->setEnabled(writeAllowed && !m_busy);
        m_applyButton->setToolTip(writeHint);
    }
    if (m_clearButton != nullptr)
    {
        m_clearButton->setEnabled(writeAllowed && !m_busy);
        m_clearButton->setToolTip(writeHint);
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(!m_busy);
    }
}

void KvmCrPolicyDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

bool KvmCrPolicyDialog::collectMasks(
    unsigned long long* const cr0Out,
    unsigned long long* const cr4Out)
{
    unsigned long long cr0Extra = 0;
    unsigned long long cr4Extra = 0;
    if (!parseHexOrZero(m_cr0MaskEdit->text(), &cr0Extra))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("CR0 附加掩码不是合法的十六进制数。")));
        return false;
    }
    if (!parseHexOrZero(m_cr4MaskEdit->text(), &cr4Extra))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("CR4 附加掩码不是合法的十六进制数。")));
        return false;
    }
    // 快捷勾选与手工输入是叠加关系，不是互斥。
    *cr0Out = cr0Extra |
        (m_pinWpCheck->isChecked() ? kCr0WriteProtect : 0ull);
    *cr4Out = cr4Extra |
        (m_pinSmepCheck->isChecked() ? kCr4Smep : 0ull) |
        (m_pinSmapCheck->isChecked() ? kCr4Smap : 0ull) |
        (m_pinUmipCheck->isChecked() ? kCr4Umip : 0ull);
    return true;
}

void KvmCrPolicyDialog::refreshPolicy()
{
    if (m_busy)
    {
        return;
    }
    setBusy(true);
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmCrPolicyResult result =
            ksword::kvm::readCrPolicy();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                if (!result.ok)
                {
                    safeThis->m_statusLabel->setText(result.message);
                    return;
                }
                safeThis->m_currentLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("当前配置：CR0 掩码 0x%1（捕获值 0x%2），CR4 掩码 0x%3（捕获值 0x%4）；驳回写入 %5 次，地址空间切换 %6 次，调试寄存器访问 %7 次。"))
                        .arg(result.cr0PinnedMask, 0, 16)
                        .arg(result.cr0PinnedValue, 0, 16)
                        .arg(result.cr4PinnedMask, 0, 16)
                        .arg(result.cr4PinnedValue, 0, 16)
                        .arg(result.refusedWriteCount)
                        .arg(result.cr3SwitchCount)
                        .arg(result.debugAccessCount));
                // 把界面开关同步到驱动侧真实配置，避免显示与实际脱节。
                safeThis->m_trackCr3Check->setChecked(result.trackCr3);
                safeThis->m_interceptDrCheck->setChecked(result.interceptDr);
                safeThis->m_logCheck->setChecked(result.log);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmCrPolicyDialog::startApply()
{
    unsigned long long cr0Mask = 0;
    unsigned long long cr4Mask = 0;
    if (!collectMasks(&cr0Mask, &cr4Mask))
    {
        return;
    }
    // 跟踪 CR3 的代价大到必须单独确认一次，而不是混在通用写权限里。
    if (m_trackCr3Check->isChecked())
    {
        const bool confirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmTrackCr3"),
            ks::i18n::sourceText(QStringLiteral("开启地址空间切换跟踪")),
            ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
            ks::i18n::sourceText(QStringLiteral("每次 CR3 加载都会变成一次 VM-exit。Windows 每秒切换地址空间数千次，整机会明显变慢，事件环也会迅速被填满并开始丢弃。")));
        if (!confirmed)
        {
            return;
        }
    }

    const bool trackCr3 = m_trackCr3Check->isChecked();
    const bool interceptDr = m_interceptDrCheck->isChecked();
    const bool log = m_logCheck->isChecked();

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在应用配置...")));
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis, cr0Mask, cr4Mask, trackCr3, interceptDr, log]() {
        const ksword::kvm::KvmCrPolicyResult result =
            ksword::kvm::applyCrPolicy(
                cr0Mask, cr4Mask, trackCr3, interceptDr, log);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshPolicy();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmCrPolicyDialog::startClear()
{
    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在清除配置...")));
    QPointer<KvmCrPolicyDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmCrPolicyResult result =
            ksword::kvm::clearCrPolicy();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.message);
                safeThis->refreshPolicy();
            },
            Qt::QueuedConnection);
    }).detach();
}
