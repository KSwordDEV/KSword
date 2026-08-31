// DisableDsePage.cpp
// 说明见 DisableDsePage.h。所有内核访问都在 DisableDseBackend 里，本文件只做界面与调度。

#include "DisableDsePage.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../theme.h"

#include <QApplication>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QVBoxLayout>

#include <thread>

namespace
{
    using ks::misc::disable_dse::ApplyResult;
    using ks::misc::disable_dse::BlockReason;
    using ks::misc::disable_dse::CodeIntegrityPosture;

    // formatHex32：
    // - 输入 value：32 位值；
    // - 作用：统一成 0xXXXXXXXX 的写法，便于和其他工具的输出对照；
    // - 返回：定宽十六进制文本。
    QString formatHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0'));
    }

    // formatHex64：
    // - 输入 value：64 位地址；
    // - 作用：统一成 0x 前缀的定宽地址写法；
    // - 返回：定宽十六进制文本。
    QString formatHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0'));
    }

    // onOffText：
    // - 输入 enabled：开关状态；
    // - 作用：统一“开启/关闭”文案；
    // - 返回：状态文本。
    // 这里刻意不写成单行三元：两个 QStringLiteral 挤在一行会让 i18n 提取器
    // 把中间的 `") : QStringLiteral("` 误当成一条待翻译字面量。
    QString onOffText(const bool enabled)
    {
        if (enabled)
        {
            return QStringLiteral("开启");
        }
        return QStringLiteral("关闭");
    }

    // askConfirmation：
    // - 作用：对改内核数据这类不可撤销的操作做一次显式确认；
    // - 返回：true 表示用户选择继续。
    bool askConfirmation(
        QWidget* const parent,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksDisableDseConfirmBox"));
        dialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(QMessageBox::Warning);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        dialog.setDefaultButton(QMessageBox::No);
        return dialog.exec() == QMessageBox::Yes;
    }
}

namespace ks::misc
{
    DisableDsePage::DisableDsePage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        updateStateDisplay();
        updateButtons();
    }

    DisableDsePage::~DisableDsePage()
    {
        // 用户可能加载完驱动就直接关了程序。g_CiOptions 停在被改过的状态会被
        // PatchGuard 巡检判定为内核数据被篡改，因此这里做最后一次同步写回。
        if (!m_hasSavedOriginal || !m_location.ok)
        {
            return;
        }

        const disable_dse::ReadbackResult readback =
            disable_dse::readCiOptions(m_location);
        if (!readback.ok || readback.value == m_savedOriginalValue)
        {
            return;
        }

        const disable_dse::ApplyResult result = disable_dse::writeCiOptions(
            m_location, readback.value, m_savedOriginalValue);

        kLogEvent closeEvent;
        if (result.ok)
        {
            const QString message =
                QStringLiteral("[DisableDSE] 页面关闭时已把 g_CiOptions 写回原值 %1。")
                    .arg(formatHex32(m_savedOriginalValue));
            info << closeEvent << message.toStdString() << eol;
        }
        else
        {
            const QString message =
                QStringLiteral("[DisableDSE] 页面关闭时恢复 g_CiOptions 失败：%1 请立即手动恢复或重启系统。")
                    .arg(result.detailText);
            err << closeEvent << message.toStdString() << eol;
        }
    }

    void DisableDsePage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshPosture();
    }

    void DisableDsePage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        auto* buttonLayout = new QHBoxLayout();
        buttonLayout->setSpacing(8);

        m_refreshButton = new QPushButton(this);
        m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_refreshButton,
            QStringLiteral("misc.disable_dse.action.refresh"),
            QStringLiteral("刷新状态"));
        buttonLayout->addWidget(m_refreshButton);

        m_locateButton = new QPushButton(this);
        m_locateButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_locateButton,
            QStringLiteral("misc.disable_dse.action.locate"),
            QStringLiteral("定位"));
        buttonLayout->addWidget(m_locateButton);

        m_disableButton = new QPushButton(this);
        m_disableButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_disableButton,
            QStringLiteral("misc.disable_dse.action.disable"),
            QStringLiteral("disable dse"));
        buttonLayout->addWidget(m_disableButton);

        m_restoreButton = new QPushButton(this);
        m_restoreButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_restoreButton,
            QStringLiteral("misc.disable_dse.action.restore"),
            QStringLiteral("恢复"));
        buttonLayout->addWidget(m_restoreButton);

        buttonLayout->addStretch(1);
        rootLayout->addLayout(buttonLayout);

        m_statusEdit = new CodeEditorWidget(this);
        m_statusEdit->setReadOnly(true);
        rootLayout->addWidget(m_statusEdit, 1);
    }

    void DisableDsePage::initializeConnections()
    {
        connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
            refreshPosture();
        });
        connect(m_locateButton, &QPushButton::clicked, this, [this]() {
            runLocate();
        });
        connect(m_disableButton, &QPushButton::clicked, this, [this]() {
            const QString message = ks::i18n::text(
                QStringLiteral("misc.disable_dse.confirm.disable"),
                QStringLiteral("即将把 g_CiOptions 改成 0，系统将不再校验驱动签名。\n\n该变量在 PatchGuard 的巡检范围内，保持关闭状态会导致蓝屏，请在加载完驱动后立即恢复。\n\n确定继续吗？"));
            if (!askConfirmation(
                    this,
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.confirm.title"),
                        QStringLiteral("关闭驱动签名强制")),
                    message))
            {
                return;
            }
            runApply(disable_dse::kDisabledValue, false);
        });
        connect(m_restoreButton, &QPushButton::clicked, this, [this]() {
            runApply(m_savedOriginalValue, true);
        });
    }

    void DisableDsePage::refreshPosture()
    {
        m_posture = disable_dse::queryPosture();
        if (!m_posture.queried)
        {
            setStatusText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.posture_failed"),
                    QStringLiteral("状态查询失败："))
                    + m_posture.failureText);
        }
        else
        {
            setStatusText(QStringLiteral("状态已刷新。"));
        }
        updateButtons();
    }

    void DisableDsePage::runLocate()
    {
        if (m_busy)
        {
            return;
        }
        setBusy(true);
        setStatusText(QStringLiteral("开始定位 g_CiOptions……"));

        const QPointer<DisableDsePage> guardThis(this);
        const disable_dse::CodeIntegrityPosture posture = m_posture;

        std::thread([guardThis, posture]() {
            LocateOutcome outcome;
            outcome.posture = posture;
            outcome.location = disable_dse::locateCiOptions();
            if (outcome.location.ok)
            {
                outcome.readback = disable_dse::readCiOptions(outcome.location);
                // 写入前的护栏：g_CiOptions 用的是 CI.dll 内部编码，与系统自报的
                // CODEINTEGRITY_OPTION_* 不是一套，两个数值本来就不相等，
                // 因此只比对“强制签名此刻是否生效”这一个语义。地址若定位错了，
                // 落在无关内核数据上几乎不可能恰好满足这个关系。
                outcome.valueMatched = outcome.readback.ok
                    && disable_dse::ciOptionsAgreesWithPosture(
                        outcome.readback.value, outcome.posture);
            }

            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(qApp, [guardThis, outcome]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->applyLocateOutcome(outcome);
            });
        }).detach();
    }

    void DisableDsePage::runApply(const std::uint32_t desiredValue, const bool isRestore)
    {
        if (m_busy || !m_location.ok)
        {
            return;
        }
        setBusy(true);

        const QPointer<DisableDsePage> guardThis(this);
        const disable_dse::TargetLocation location = m_location;

        std::thread([guardThis, location, desiredValue, isRestore]() {
            ApplyResult result;
            // 写之前再读一次，把 expected-before 对齐到此刻的真实值：
            // 期间可能有别的工具动过 g_CiOptions。
            const disable_dse::ReadbackResult readback =
                disable_dse::readCiOptions(location);
            if (!readback.ok)
            {
                result.detailText = readback.failureText;
            }
            else
            {
                result = disable_dse::writeCiOptions(
                    location, readback.value, desiredValue);
            }

            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(qApp, [guardThis, result, isRestore]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->applyApplyOutcome(result, isRestore);
            });
        }).detach();
    }

    void DisableDsePage::applyLocateOutcome(const LocateOutcome& outcome)
    {
        setBusy(false);
        m_location = outcome.location;
        m_valueMatched = outcome.valueMatched;

        if (!outcome.location.ok)
        {
            m_hasCurrentValue = false;
            setStatusText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.locate_failed"),
                    QStringLiteral("定位失败："))
                    + outcome.location.failureText);
            updateButtons();
            return;
        }

        if (!outcome.readback.ok)
        {
            m_hasCurrentValue = false;
            setStatusText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.read_failed"),
                    QStringLiteral("读回失败："))
                    + outcome.readback.failureText);
            updateButtons();
            return;
        }

        m_currentValue = outcome.readback.value;
        m_hasCurrentValue = true;

        if (!outcome.valueMatched)
        {
            setStatusText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.mismatch"),
                    QStringLiteral("读回值的强制签名位与系统自报状态矛盾，地址存疑，已禁止写入。")));
            updateButtons();
            return;
        }

        setStatusText(
            ks::i18n::text(
                QStringLiteral("misc.disable_dse.result.locate_ok"),
                QStringLiteral("定位并校验通过，可以执行操作。")));
        updateButtons();
    }

    void DisableDsePage::applyApplyOutcome(const ApplyResult& result, const bool isRestore)
    {
        setBusy(false);

        if (!result.ok)
        {
            setStatusText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.apply_failed"),
                    QStringLiteral("操作失败："))
                    + result.detailText);
            updateButtons();
            return;
        }

        m_currentValue = result.writtenValue;
        m_hasCurrentValue = true;

        if (isRestore)
        {
            // 恢复成功后清掉待恢复记账，页面析构时就不会再写一次。
            m_hasSavedOriginal = false;
        }
        else
        {
            // 只在第一次关闭时记录原值：连续两次关闭不能把原值覆盖成 0。
            if (!m_hasSavedOriginal)
            {
                m_savedOriginalValue = result.previousValue;
                m_hasSavedOriginal = true;
            }
        }

        // 写入会改变 CodeIntegrityOptions，重新查一次姿态让展示保持同步。
        m_posture = disable_dse::queryPosture();
        setStatusText(
            isRestore
                ? ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.restore_ok"),
                      QStringLiteral("已恢复原值，驱动签名强制回到原始状态。"))
                : ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.disable_ok"),
                       QStringLiteral("已关闭驱动签名强制。请立即加载目标驱动，然后马上点“恢复原值”。")));
        updateButtons();
    }

    void DisableDsePage::setStatusText(const QString& text)
    {
        m_statusText = text;
        updateStateDisplay();
    }

    void DisableDsePage::setBusy(const bool busy)
    {
        m_busy = busy;
        updateButtons();
    }

    void DisableDsePage::updateButtons()
    {
        const bool allowed = !m_busy && m_blockReason == disable_dse::BlockReason::None;

        if (m_refreshButton != nullptr)
        {
            m_refreshButton->setEnabled(!m_busy);
        }
        if (m_locateButton != nullptr)
        {
            // 定位本身只读，只要不忙就允许；失败时的原因比灰按钮更有用。
            m_locateButton->setEnabled(!m_busy);
        }
        if (m_disableButton != nullptr)
        {
            m_disableButton->setEnabled(
                allowed && m_valueMatched && m_hasCurrentValue
                && m_currentValue != disable_dse::kDisabledValue);
        }
        if (m_restoreButton != nullptr)
        {
            m_restoreButton->setEnabled(
                allowed && m_valueMatched && m_hasSavedOriginal
                && m_hasCurrentValue && m_currentValue != m_savedOriginalValue);
        }
    }

    void DisableDsePage::updateStateDisplay()
    {
        m_blockReason = disable_dse::evaluateBlockReason(m_posture, m_location);
        if (m_blockReason == disable_dse::BlockReason::None
            && m_location.ok && !m_valueMatched && m_hasCurrentValue)
        {
            m_blockReason = disable_dse::BlockReason::ValueMismatch;
        }

        if (m_statusEdit == nullptr)
        {
            return;
        }

        const QString unavailable = QStringLiteral("未获取");
        const QString driverSigning = m_posture.queried
            ? onOffText(m_posture.ciEnabled)
            : unavailable;
        const QString testSigning = m_posture.queried
            ? onOffText(m_posture.testSigningEnabled)
            : unavailable;
        const QString memoryIntegrity = m_posture.queried
            ? onOffText(m_posture.hvciEnabled)
            : unavailable;
        const QString secureBoot = m_posture.queried
            ? onOffText(m_posture.secureBootEnabled)
            : unavailable;
        const QString address = m_location.ok
            ? formatHex64(m_location.kernelAddress)
            : unavailable;
        const QString value = m_hasCurrentValue
            ? formatHex32(m_currentValue)
            : unavailable;
        const QString ciInitializeRva = m_location.ciInitializeRva != 0U
            ? QStringLiteral("0x%1").arg(m_location.ciInitializeRva, 0, 16)
            : unavailable;
        const QString instruction = m_location.matchedInstruction.isEmpty()
            ? unavailable
            : m_location.matchedInstruction;

        QString status = m_statusText;
        if (status.isEmpty())
        {
            status = m_posture.queried
                ? disable_dse::blockReasonText(m_blockReason)
                : ks::i18n::text(
                    QStringLiteral("misc.disable_dse.posture.unknown"),
                    QStringLiteral("尚未取得代码完整性状态。"));
        }
        if (status.isEmpty())
        {
            status = QStringLiteral("状态已刷新。");
        }

        m_statusEdit->setLocalizedText(
            QStringLiteral("驱动签名强制：%1\n"
                           "测试签名：%2\n"
                           "内存完整性：%3\n"
                           "安全启动：%4\n"
                           "g_CiOptions 地址：%5\n"
                           "g_CiOptions 值：%6\n"
                           "CiInitialize RVA：%7\n"
                           "命中指令：%8\n"
                           "状态：%9")
                .arg(driverSigning)
                .arg(testSigning)
                .arg(memoryIntegrity)
                .arg(secureBoot)
                .arg(address)
                .arg(value)
                .arg(ciInitializeRva)
                .arg(instruction)
                .arg(status));
    }
}
