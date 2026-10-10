// DisableDsePage.cpp
// 说明见 DisableDsePage.h。所有内核访问都在 DisableDseBackend 里，本文件只做界面与调度。

#include "DisableDsePage.h"
#include "../../UI/ToolbarMetrics.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../theme.h"

#include <QApplication>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
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
    using ks::misc::disable_dse::PostureSource;

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

    // postureSourceText：
    // - 输入 source：姿态数据来源；
    // - 作用：告诉用户这份状态是谁给出的；
    // - 返回：来源说明文本。
    QString postureSourceText(const PostureSource source)
    {
        switch (source)
        {
        case PostureSource::Driver:
            return QStringLiteral("R0 驱动查询");
        case PostureSource::Win32:
            return QStringLiteral("R3 系统查询");
        case PostureSource::None:
        default:
            break;
        }
        return QStringLiteral("无可用通道");
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

    // showOpaqueMessage：
    // - 作用：弹一个不透明的主题化提示框，避免继承父链的半透明背景；
    // - 返回：无。
    void showOpaqueMessage(
        QWidget* const parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksDisableDseMessageBox"));
        dialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
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

    void DisableDsePage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::LanguageChange)
        {
            // Translate each owned log message directly; never interpret it as fields.
            QStringList translatedLines;
            for (const QString& line : m_traceLines)
                translatedLines.append(ks::i18n::displayText(line));
            if (m_traceEdit) m_traceEdit->replaceRawText(translatedLines.join(QLatin1Char('\n')));
            updateStateDisplay();
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyBannerStyle();
            updateStateDisplay();
        }
    }

    // applyBannerStyle 作用：
    // - 输入：无，读取当前主题的语义色；
    // - 处理：下发风险横幅与待恢复提示的样式，构造期与主题切换走同一条路径；
    // - 返回：无，控件尚未创建时静默跳过。
    void DisableDsePage::applyBannerStyle()
    {
        if (m_warningLabel != nullptr)
        {
            m_warningLabel->setStyleSheet(
                QStringLiteral(
                    "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                    "background:%2;color:%3;}")
                    .arg(KswordTheme::ErrorHex())
                    .arg(KswordTheme::ThemeColorName(KswordTheme::ErrorBackgroundColor()))
                    .arg(KswordTheme::TextPrimaryHex()));
        }
        if (m_pendingLabel != nullptr)
        {
            m_pendingLabel->setStyleSheet(
                QStringLiteral(
                    "QLabel{padding:8px;border:1px solid %1;border-radius:5px;"
                    "background:%2;color:%3;}")
                    .arg(KswordTheme::WarningHex())
                    .arg(KswordTheme::ThemeColorName(KswordTheme::WarningBackgroundColor()))
                    .arg(KswordTheme::TextPrimaryHex()));
        }
    }

    void DisableDsePage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();

        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // ===================== 风险横幅 =====================
        m_warningLabel = new QLabel(this);
        m_warningLabel->setWordWrap(true);
        m_warningLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        language.bindText(
            m_warningLabel,
            QStringLiteral("misc.disable_dse.warning"),
            QStringLiteral("高风险功能：本页直接修改内核里 CI.dll!g_CiOptions 的 4 个字节，关闭后系统将接受未签名驱动。该变量在 PatchGuard 的巡检范围内，长时间保持关闭会触发 CRITICAL_STRUCTURE_CORRUPTION 蓝屏。请在加载完目标驱动后立刻点“恢复”，不要让系统长期停在关闭状态。"));
        rootLayout->addWidget(m_warningLabel);

        // ===================== 当前状态 =====================
        auto* postureGroup = new QGroupBox(this);
        language.bindText(
            postureGroup,
            QStringLiteral("misc.disable_dse.posture.title"),
            QStringLiteral("代码完整性状态"));
        auto* postureLayout = new QVBoxLayout(postureGroup);
        postureLayout->setSpacing(6);

        m_postureLabel = new QLabel(postureGroup);
        m_postureLabel->setWordWrap(true);
        m_postureLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(m_postureLabel);

        m_optionsLabel = new QLabel(postureGroup);
        m_optionsLabel->setWordWrap(true);
        m_optionsLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(m_optionsLabel);

        m_blockLabel = new QLabel(postureGroup);
        m_blockLabel->setWordWrap(true);
        m_blockLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        postureLayout->addWidget(m_blockLabel);

        rootLayout->addWidget(postureGroup);

        // ===================== 目标定位 =====================
        auto* locationGroup = new QGroupBox(this);
        language.bindText(
            locationGroup,
            QStringLiteral("misc.disable_dse.location.title"),
            QStringLiteral("g_CiOptions 定位"));
        auto* locationLayout = new QVBoxLayout(locationGroup);
        locationLayout->setSpacing(6);

        m_locationLabel = new QLabel(locationGroup);
        m_locationLabel->setWordWrap(true);
        m_locationLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        locationLayout->addWidget(m_locationLabel);

        // 定位与事务保留实际时序消息；追加时翻译，语言切换由页面按消息重绘。
        m_traceEdit = new CodeEditorWidget(locationGroup);
        m_traceEdit->setReadOnly(true);
        m_traceEdit->setMaximumHeight(150);
        language.bindToolTip(
            m_traceEdit,
            QStringLiteral("misc.disable_dse.trace.tooltip"),
            QStringLiteral("定位轨迹与事务日志。定位不使用任何硬编码偏移：从导出的 CiInitialize 反汇编找到 CipInitialize，再在其中找写 g_CiOptions 的指令。"));
        locationLayout->addWidget(m_traceEdit);

        rootLayout->addWidget(locationGroup);

        // ===================== 操作 =====================
        auto* actionGroup = new QGroupBox(this);
        language.bindText(
            actionGroup,
            QStringLiteral("misc.disable_dse.action.title"),
            QStringLiteral("操作"));
        auto* actionLayout = new QVBoxLayout(actionGroup);
        actionLayout->setSpacing(8);

        m_pendingLabel = new QLabel(actionGroup);
        m_pendingLabel->setWordWrap(true);
        m_pendingLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_pendingLabel->setVisible(false);
        actionLayout->addWidget(m_pendingLabel);

        auto* buttonLayout = new QHBoxLayout();
        buttonLayout->setSpacing(8);

        m_refreshButton = new QPushButton(actionGroup);
        m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_refreshButton,
            QStringLiteral("misc.disable_dse.action.refresh"),
            QStringLiteral("刷新状态"));
        buttonLayout->addWidget(m_refreshButton);

        m_locateButton = new QPushButton(actionGroup);
        m_locateButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_locateButton,
            QStringLiteral("misc.disable_dse.action.locate"),
            QStringLiteral("定位并校验"));
        buttonLayout->addWidget(m_locateButton);

        m_disableButton = new QPushButton(actionGroup);
        m_disableButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_disableButton,
            QStringLiteral("misc.disable_dse.action.disable"),
            QStringLiteral("关闭签名强制"));
        buttonLayout->addWidget(m_disableButton);

        m_restoreButton = new QPushButton(actionGroup);
        m_restoreButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        language.bindText(
            m_restoreButton,
            QStringLiteral("misc.disable_dse.action.restore"),
            QStringLiteral("恢复原值"));
        buttonLayout->addWidget(m_restoreButton);

        buttonLayout->addStretch(1);
        ks::ui::NormalizeToolbarRow(buttonLayout);
        actionLayout->addLayout(buttonLayout);

        m_resultLabel = new QLabel(actionGroup);
        m_resultLabel->setWordWrap(true);
        m_resultLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        actionLayout->addWidget(m_resultLabel);

        rootLayout->addWidget(actionGroup);
        rootLayout->addStretch(1);

        applyBannerStyle();
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
        updateStateDisplay();
        updateButtons();

        if (!m_posture.queried)
        {
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.posture_failed"),
                    QStringLiteral("状态查询失败："))
                    + m_posture.failureText,
                true);
        }
    }

    void DisableDsePage::runLocate()
    {
        if (m_busy)
        {
            return;
        }
        setBusy(true);
        appendTrace(QStringLiteral("开始定位 g_CiOptions……"));

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

        for (const QString& line : outcome.location.traceLines)
        {
            appendTrace(line);
        }

        if (!outcome.location.ok)
        {
            m_hasCurrentValue = false;
            appendTrace(QStringLiteral("定位失败：%1").arg(outcome.location.failureText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.locate_failed"),
                    QStringLiteral("定位失败："))
                    + outcome.location.failureText,
                true);
            return;
        }

        if (!outcome.readback.ok)
        {
            m_hasCurrentValue = false;
            appendTrace(QStringLiteral("读回失败：%1").arg(outcome.readback.failureText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.read_failed"),
                    QStringLiteral("读回失败："))
                    + outcome.readback.failureText,
                true);
            return;
        }

        m_currentValue = outcome.readback.value;
        m_hasCurrentValue = true;
        appendTrace(QStringLiteral("读回 g_CiOptions = %1（%2）")
                        .arg(formatHex32(outcome.readback.value))
                        .arg(disable_dse::describeCiOptions(outcome.readback.value)));

        if (!outcome.valueMatched)
        {
            appendTrace(
                QStringLiteral("校验不通过：系统自报驱动签名强制为“%1”，而读回值 %2 的强制位与之矛盾。已拒绝后续写入。")
                    .arg(onOffText(outcome.posture.ciEnabled))
                    .arg(formatHex32(outcome.readback.value)));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.mismatch"),
                    QStringLiteral("读回值的强制签名位与系统自报状态矛盾，地址存疑，已禁止写入。")),
                true);
            return;
        }

        appendTrace(QStringLiteral("校验通过：读回值的强制签名位与系统自报状态一致。"));
        updateStateDisplay();
        updateButtons();
        setResultText(
            ks::i18n::text(
                QStringLiteral("misc.disable_dse.result.locate_ok"),
                QStringLiteral("定位并校验通过，可以执行操作。")),
            false);
    }

    void DisableDsePage::applyApplyOutcome(const ApplyResult& result, const bool isRestore)
    {
        setBusy(false);

        for (const QString& line : result.traceLines)
        {
            appendTrace(line);
        }

        if (!result.ok)
        {
            appendTrace(QStringLiteral("操作失败：%1").arg(result.detailText));
            updateStateDisplay();
            updateButtons();
            setResultText(
                ks::i18n::text(
                    QStringLiteral("misc.disable_dse.result.apply_failed"),
                    QStringLiteral("操作失败："))
                    + result.detailText,
                true);
            return;
        }

        m_currentValue = result.writtenValue;
        m_hasCurrentValue = true;

        if (isRestore)
        {
            // 恢复成功后清掉待恢复记账，页面析构时就不会再写一次。
            m_hasSavedOriginal = false;
            appendTrace(QStringLiteral("已恢复 g_CiOptions = %1")
                            .arg(formatHex32(result.writtenValue)));
        }
        else
        {
            // 只在第一次关闭时记录原值：连续两次关闭不能把原值覆盖成 0。
            if (!m_hasSavedOriginal)
            {
                m_savedOriginalValue = result.previousValue;
                m_hasSavedOriginal = true;
            }
            appendTrace(QStringLiteral("已关闭签名强制，原值 %1 已记录，请尽快恢复。")
                            .arg(formatHex32(m_savedOriginalValue)));
        }

        // 写入会改变 CodeIntegrityOptions，重新查一次姿态让展示保持同步。
        m_posture = disable_dse::queryPosture();
        updateStateDisplay();
        updateButtons();

        setResultText(
            isRestore
                ? ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.restore_ok"),
                      QStringLiteral("已恢复原值，驱动签名强制回到原始状态。"))
                : ks::i18n::text(
                      QStringLiteral("misc.disable_dse.result.disable_ok"),
                      QStringLiteral("已关闭驱动签名强制。请立即加载目标驱动，然后马上点“恢复原值”。")),
            false);
    }

    void DisableDsePage::appendTrace(const QString& line)
    {
        if (m_traceEdit == nullptr)
        {
            return;
        }
        m_traceLines.append(line);
        m_traceEdit->appendRawText(ks::i18n::displayText(line));
    }

    void DisableDsePage::setResultText(const QString& text, const bool isError)
    {
        if (m_resultLabel == nullptr)
        {
            return;
        }
        m_resultLabel->setText(text);
        m_resultLabel->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(isError ? KswordTheme::ErrorHex() : KswordTheme::SuccessHex()));
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

        if (m_postureLabel != nullptr)
        {
            if (!m_posture.queried)
            {
                m_postureLabel->setText(
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.posture.unknown"),
                        QStringLiteral("尚未取得代码完整性状态。")));
            }
            else
            {
                QStringList parts;
                parts << QStringLiteral("驱动签名强制：%1").arg(onOffText(m_posture.ciEnabled));
                parts << QStringLiteral("测试签名：%1").arg(onOffText(m_posture.testSigningEnabled));
                parts << QStringLiteral("内存完整性(HVCI)：%1").arg(onOffText(m_posture.hvciEnabled));
                if (m_posture.source == PostureSource::Driver)
                {
                    parts << QStringLiteral("安全启动：%1").arg(onOffText(m_posture.secureBootEnabled));
                }
                m_postureLabel->setText(
                    QStringLiteral("%1\n数据来源：%2　系统内部版本：%3")
                        .arg(parts.join(QStringLiteral("　")))
                        .arg(postureSourceText(m_posture.source))
                        .arg(m_posture.buildNumber));
            }
        }

        if (m_optionsLabel != nullptr)
        {
            if (!m_posture.queried)
            {
                m_optionsLabel->clear();
            }
            else
            {
                QString text = QStringLiteral("系统自报 CodeIntegrityOptions = %1（%2）")
                                   .arg(formatHex32(m_posture.options))
                                   .arg(disable_dse::describeOptions(m_posture.options));
                if (m_hasCurrentValue)
                {
                    // 两个值用的不是同一套位编码，不该相互对照数值，因此分行标注各自含义。
                    text += QStringLiteral("\n内核读回 g_CiOptions = %1（%2）")
                                .arg(formatHex32(m_currentValue))
                                .arg(disable_dse::describeCiOptions(m_currentValue));
                }
                m_optionsLabel->setText(text);
            }
            m_optionsLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
        }

        if (m_blockLabel != nullptr)
        {
            const QString reasonText = disable_dse::blockReasonText(m_blockReason);
            m_blockLabel->setText(reasonText);
            m_blockLabel->setVisible(!reasonText.isEmpty());
            m_blockLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        }

        if (m_locationLabel != nullptr)
        {
            if (!m_location.ok)
            {
                m_locationLabel->setText(
                    ks::i18n::text(
                        QStringLiteral("misc.disable_dse.location.none"),
                        QStringLiteral("尚未定位。点“定位并校验”开始。")));
            }
            else
            {
                m_locationLabel->setText(
                    QStringLiteral("%1 基址 %2　RVA 0x%3（节 %4）\ng_CiOptions 内核地址 %5")
                        .arg(m_location.moduleName)
                        .arg(formatHex64(m_location.moduleBase))
                        .arg(m_location.rva, 0, 16)
                        .arg(m_location.sectionName)
                        .arg(formatHex64(m_location.kernelAddress)));
            }
        }

        if (m_pendingLabel != nullptr)
        {
            m_pendingLabel->setVisible(m_hasSavedOriginal);
            if (m_hasSavedOriginal)
            {
                m_pendingLabel->setText(
                    QStringLiteral("驱动签名强制当前处于被本页修改的状态，原值 %1 已记录。请在加载完驱动后立即点“恢复原值”；若直接关闭程序，本页会在退出时尝试自动写回。")
                        .arg(formatHex32(m_savedOriginalValue)));
            }
        }
    }
}
