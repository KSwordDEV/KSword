#include "DiskEditorTab.h"
#include "DiskEditorBackend.h"
#include "DiskEditorFormat.h"
#include "../../UI/MemoryWorkbench/HexView.h"
#include "../../Framework/PrivilegeElevationPrompt.h"
#include "../../SettingsDock/AppearanceSettings.h"
#include "../../../../shared/driver/KswordArkStorageForensicsIoctl.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QSpinBox>
#include <limits>
#include <thread>

namespace ks::misc
{
    void DiskEditorTab::invalidateCapturedRange()
    {
        // 页面来源一旦变化，字节缓存与写入资格一起失效，不仅清掉 dirty 标记。
        ++m_captureGeneration;
        m_capturedRange.reset();
        m_loadedBytes.clear();
        m_loadedBaseOffset = 0;
        if (m_hexEditor) m_hexEditor->clearBuffer();
        updateDirtyState(false);
    }

    bool DiskEditorTab::hasWritableCapture() const
    {
        const auto* selected = currentDisk(); // selected：按钮状态同样必须绑定实际当前来源。
        return selected && m_capturedRange && !m_capturedRange->deviceIdentity.isEmpty() &&
            !m_capturedRange->original.isEmpty() &&
            CapturedDiskMatches(*m_capturedRange, *selected, currentRawBackend(), m_captureGeneration);
    }

    void DiskEditorTab::readCurrentRangeAsync(const QString& reasonText)
    {
        const auto* selected = currentDisk(); // selected：只用于复制，不跨确认/线程保存裸指针。
        if (!selected || m_busy)
        {
            appendLog(selected ? QStringLiteral("读取请求被忽略：当前已有后台任务。")
                : QStringLiteral("读取失败：未选择磁盘。"));
            return;
        }
        std::uint64_t offset = 0; // offset：用户明确指定的字节偏移。
        if (!parseAddressText(m_offsetEdit->text(), offset))
        {
            QMessageBox::warning(this, QStringLiteral("磁盘编辑"),
                QStringLiteral("偏移格式无效，请输入十进制或 0x 十六进制。"));
            return;
        }
        DiskCapturedRange captured; // captured：整个操作使用同一冻结设备与访问层。
        captured.source = *selected;
        captured.backend = currentRawBackend();
        captured.generation = m_captureGeneration;
        captured.offset = offset;
        const auto length = static_cast<std::uint32_t>(m_lengthSpin->value()); // length：冻结读取长度。
        const auto backendName = m_backendCombo->currentText(); // backendName：冻结提示文案。
        const QPointer<DiskEditorTab> alive(this);
        if (captured.backend != KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK &&
            (captured.source.rawCapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK))
        {
            const auto decision = QMessageBox::warning(this, QStringLiteral("确认系统盘绕过读取"),
                QStringLiteral("当前目标是系统盘，所选“%1”会绕过部分上层存储对象。"
                    "本次只读取 %2 字节，不会写盘。是否继续？").arg(backendName).arg(length),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (!alive || decision != QMessageBox::Yes) return;
        }
        const auto* current = currentDisk(); // current：确认后的当前选择必须仍等于冻结来源。
        if (!current || !CapturedDiskMatches(captured, *current, currentRawBackend(), m_captureGeneration) || m_busy)
            return;
        invalidateCapturedRange();
        captured.generation = m_captureGeneration;
        m_readGeneration = captured.generation;
        m_busy = true;
        setControlsEnabledForBusy(true);
        m_statusLabel->setText(QStringLiteral("状态：正在读取 %1 @ %2 ...")
            .arg(DiskEditorBackend::formatBytes(length)).arg(diskeditor_detail::HexOffsetText(offset)));
        appendLog(QStringLiteral("%1：%2 access=%3 offset=%4 length=%5")
            .arg(reasonText, captured.source.devicePath, backendName)
            .arg(diskeditor_detail::HexOffsetText(offset)).arg(length));

        // 工作线程只持值快照；排队到应用对象后才在 UI 线程探活页面，避免裸接收者竞态。
        std::thread([alive, captured = std::move(captured), length]() mutable {
            QString identityError; // identityError：缺失身份不伪造 GUID，保留只读证据资格。
            DiskEditorBackend::queryCaptureIdentity(captured.source, captured.deviceIdentity, identityError);
            QString error; // error：真实读失败/不完整/读取中身份变化的诊断。
            bool readOk = false;
            bool captureUnsupported = false;
            if (!captured.deviceIdentity.isEmpty())
            {
                readOk = DiskEditorBackend::readCapturedBytesWithBackend(captured, length,
                    captured.original, captureUnsupported, error);
            }
            if (captured.deviceIdentity.isEmpty() || captureUnsupported)
            {
                // 旧驱动仅兼容证据展示；清掉 GUID，不能把旧读数据升级成可写捕获。
                captured.deviceIdentity.clear();
                error.clear();
                readOk = DiskEditorBackend::readBytesWithBackend(captured.source.diskIndex, captured.backend,
                    captured.offset, length, captured.original, error);
            }
            if (!readOk && error.isEmpty()) error = QStringLiteral("磁盘读取失败，旧缓冲已失效。");
            if (error.isEmpty() && captured.original.size() != static_cast<qsizetype>(length))
                error = QStringLiteral("磁盘读取不完整，旧缓冲已失效，请重新读取。");
            if (error.isEmpty() && !captured.deviceIdentity.isEmpty())
            {
                QString afterIdentity; // afterIdentity：确保读取期间设备没有被替换。
                if (!DiskEditorBackend::queryCaptureIdentity(captured.source, afterIdentity, identityError) ||
                    afterIdentity != captured.deviceIdentity)
                    error = QStringLiteral("读取期间磁盘身份无法保持一致，请重新读取。");
            }
            QMetaObject::invokeMethod(qApp, [alive, captured = std::move(captured), error]() mutable {
                if (alive) alive->applyReadResult(std::move(captured), error);
            }, Qt::QueuedConnection);
        }).detach();
    }

    void DiskEditorTab::applyReadResult(DiskCapturedRange captured, const QString& error)
    {
        // 旧任务不能清掉新任务的 busy 或覆盖新来源；切源后的旧结果只结束所属读操作。
        if (m_readGeneration != captured.generation) return;
        m_readGeneration = 0;
        m_busy = false;
        const auto* selected = currentDisk();
        if (!selected || !CapturedDiskMatches(captured, *selected, currentRawBackend(), m_captureGeneration))
        {
            setControlsEnabledForBusy(false);
            return;
        }
        if (!error.isEmpty())
        {
            invalidateCapturedRange();
            setControlsEnabledForBusy(false);
            m_statusLabel->setText(QStringLiteral("状态：读取失败：%1").arg(error));
            appendLog(QStringLiteral("读取失败：%1").arg(error));
            const QPointer<DiskEditorTab> alive(this);
            const bool handled = ks::ui::promptForPrivilegeFailure(this, QStringLiteral("读取物理磁盘扇区"), error);
            if (alive && !handled) QMessageBox::warning(this, QStringLiteral("磁盘编辑"), error);
            return;
        }
        m_loadedBaseOffset = captured.offset;
        m_loadedBytes = captured.original;
        m_capturedRange = std::move(captured);
        m_hexEditor->setBuffer(m_loadedBaseOffset, m_loadedBytes);
        m_hexEditor->setEditable(!m_readOnlyCheck->isChecked());
        updateDirtyState(false);
        setControlsEnabledForBusy(false);
        m_statusLabel->setText(m_capturedRange->deviceIdentity.isEmpty()
            ? QStringLiteral("设备身份无法核验，缓冲仅供查看，不能写回。")
            : QStringLiteral("状态：读取完成，%1 字节 @ %2。")
                .arg(m_loadedBytes.size()).arg(diskeditor_detail::HexOffsetText(m_loadedBaseOffset)));
    }

    void DiskEditorTab::writeCurrentBuffer()
    {
        const QPointer<DiskEditorTab> alive(this);
        if (!ks::ui::isCurrentProcessElevated())
        {
            (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("写入物理磁盘扇区"));
            return;
        }
        if (m_busy || m_readOnlyCheck->isChecked() || !m_capturedRange || m_capturedRange->deviceIdentity.isEmpty())
        {
            appendLog(QStringLiteral("写回已拒绝：请先读取当前磁盘并关闭只读保护。"));
            return;
        }
        const DiskCapturedRange captured = *m_capturedRange; // captured：确认全过程不重取设备/偏移。
        const QByteArray replacement = m_hexEditor->buffer(); // replacement：用户确认的精确缓存。
        const QString backendName = m_backendCombo->currentText();
        const auto stillCurrent = [&]() {
            if (!alive || !m_capturedRange || m_busy || m_readOnlyCheck->isChecked()) return false;
            const auto* selected = currentDisk();
            return selected && CapturedDiskMatches(captured, *selected, currentRawBackend(), m_captureGeneration) &&
                m_capturedRange->deviceIdentity == captured.deviceIdentity &&
                m_capturedRange->original == captured.original && m_hexEditor->buffer() == replacement;
        };
        if (!stillCurrent()) return;
        const bool systemDisk = (captured.source.rawCapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0;
        if (!ks::settings::dangerousActionConfirmationsSuppressed())
        {
            const auto risk = QMessageBox::warning(this, QStringLiteral("高风险：即将写入物理磁盘"),
                QStringLiteral("目标：%1\n访问层：%2\n偏移：%3\n长度：%4 字节\n\n"
                    "物理写入可能破坏分区表、文件系统或启动数据。%5\n是否继续？")
                    .arg(captured.source.devicePath, backendName, diskeditor_detail::HexOffsetText(captured.offset))
                    .arg(replacement.size()).arg(systemDisk ? QStringLiteral("该磁盘包含当前启动或系统分区。") : QString()),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (!alive || risk != QMessageBox::Yes) return;
            if (!stillCurrent())
            {
                appendLog(QStringLiteral("目标或缓冲已改变，本次写回已取消，请重新读取。"));
                return;
            }
            const auto confirmed = QMessageBox::warning(this, QStringLiteral("确认写回物理磁盘"),
                QStringLiteral("将通过“%1”写入 %2 @ %3，长度 %4 字节。确认写入？")
                    .arg(backendName, captured.source.devicePath, diskeditor_detail::HexOffsetText(captured.offset))
                    .arg(replacement.size()), QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (!alive || confirmed != QMessageBox::Yes) return;
        }
        if (!stillCurrent())
        {
            appendLog(QStringLiteral("目标或缓冲已改变，本次写回已取消，请重新读取。"));
            return;
        }

        // 已有风险策略仍由宿主提供；共享事务只执行同一冻结来源的验证和写入。
        unsigned long flags = KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE | KSWORD_ARK_RAW_DISK_FLAG_FUA;
        if (systemDisk) flags |= KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE;
        const DiskWritePorts ports{
            [captured](QString& identity, QString& error) {
                return DiskEditorBackend::queryCaptureIdentity(captured.source, identity, error);
            },
            [captured](QByteArray& bytes, QString& error) {
                // 写事务的前后回读同样绑定实际实例，不允许退回未验证读取。
                bool unsupported = false;
                return DiskEditorBackend::readCapturedBytesWithBackend(captured,
                    static_cast<std::uint32_t>(captured.original.size()), bytes, unsupported, error);
            },
            [captured, flags](const QByteArray& bytes, QString& error) {
                return DiskEditorBackend::writeCapturedBytesWithBackend(captured, bytes, flags, error);
            }
        };
        m_busy = true;
        setControlsEnabledForBusy(true);
        const DiskWriteReceipt receipt = ApplyCapturedDiskWrite(captured, replacement, ports);
        if (!alive) return;
        m_busy = false;
        if (!receipt.success || !stillCurrent())
        {
            // 写入失败/身份冲突/回读不符均不接受编辑缓存为新基线。
            invalidateCapturedRange();
            setControlsEnabledForBusy(false);
            const QString error = receipt.error.isEmpty()
                ? QStringLiteral("写回未通过完整验证，请重新读取磁盘。") : receipt.error;
            appendLog(QStringLiteral("写回失败：%1").arg(error));
            QMessageBox::critical(this, QStringLiteral("磁盘编辑"), error);
            return;
        }
        m_capturedRange->original = receipt.observed;
        m_loadedBytes = receipt.observed;
        m_hexEditor->setBuffer(captured.offset, receipt.observed);
        updateDirtyState(false);
        setControlsEnabledForBusy(false);
        appendLog(QStringLiteral("写回完成（已回读验证）：访问层=%1，%2 字节 @ %3。")
            .arg(backendName).arg(receipt.observed.size()).arg(diskeditor_detail::HexOffsetText(captured.offset)));
        refreshStructureReportAsync(QStringLiteral("写回后刷新结构解析"));
    }
}
