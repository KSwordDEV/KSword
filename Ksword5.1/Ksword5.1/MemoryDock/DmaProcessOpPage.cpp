#include "DmaProcessOpPage.h"
#include "../UI/CodeTextEdit.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"
#include "../../../shared/evidence/NumericTextParse.h"

#include <QCheckBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <algorithm>

using namespace Ksword::Evidence;

namespace ksword::memory_dock
{
    namespace
    {
        constexpr std::uint64_t kPageBytes = kDmaOpPageBytes;

        QString hex64(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0'))
                .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"));
        }

        QString hexDump(const std::vector<std::uint8_t>& bytes, const std::size_t limit)
        {
            QStringList parts;
            const std::size_t shown = (std::min)(bytes.size(), limit);
            for (std::size_t i = 0U; i < shown; ++i)
            {
                parts << QStringLiteral("%1").arg(bytes[i], 2, 16, QChar('0')).toUpper();
            }
            QString text = parts.join(QLatin1Char(' '));
            if (bytes.size() > shown)
            {
                text += QStringLiteral(" …（共 %1 字节）").arg(bytes.size());
            }
            return text;
        }

        // parseHexPayload：把 "90 48 31 C0" 这类文本解析成字节。
        //
        // 只接受成对的十六进制数位，分隔符随意。刻意不接受"0x" 前缀混排或十进制：
        // 载荷是机器码，一个被宽容解析成别的值的字节就是一条别的指令，而错在哪
        // 从结果上看不出来。
        bool parseHexPayload(const QString& text, std::vector<std::uint8_t>& out, QString& errorOut)
        {
            out.clear();
            QString compact;
            for (const QChar ch : text)
            {
                if (ch.isSpace() || ch == QLatin1Char(',') || ch == QLatin1Char('-'))
                {
                    continue;
                }
                if (!isxdigit(static_cast<unsigned char>(ch.toLatin1())))
                {
                    errorOut = QStringLiteral("载荷里出现了非十六进制字符：%1").arg(ch);
                    return false;
                }
                compact.append(ch);
            }
            if (compact.isEmpty())
            {
                errorOut = QStringLiteral("载荷为空。");
                return false;
            }
            if ((compact.size() % 2) != 0)
            {
                // 奇数位必然是少写了一位。补零会静默改变最后一个字节的值。
                errorOut = QStringLiteral("载荷的十六进制位数是奇数，缺了一位。");
                return false;
            }
            out.reserve(static_cast<std::size_t>(compact.size() / 2));
            for (int i = 0; i < compact.size(); i += 2)
            {
                bool ok = false;
                out.push_back(static_cast<std::uint8_t>(compact.mid(i, 2).toUInt(&ok, 16)));
                if (!ok)
                {
                    errorOut = QStringLiteral("载荷解析失败。");
                    return false;
                }
            }
            return true;
        }
    }

    DmaProcessOpPage::DmaProcessOpPage(QWidget* const parent)
        : QWidget(parent)
    {
        buildUi();
        wireSignals();
        refreshChannelAvailability();
        updateActionState();
    }

    DmaProcessOpPage::~DmaProcessOpPage() = default;

    void DmaProcessOpPage::buildUi()
    {
        QVBoxLayout* root = new QVBoxLayout(this);
        root->setContentsMargins(8, 8, 8, 8);
        root->setSpacing(8);

        QLabel* intro = new QLabel(this);
        intro->setWordWrap(true);
        intro->setTextInteractionFlags(Qt::TextSelectableByMouse);
        intro->setText(QStringLiteral("通过 DDMA 直接往目标进程的物理页里写字节。与“R-1 注入”不是同一件事：R-1 把载荷放在影子页里、真页从头到尾没被改过，还有一个武装好的触发点；DMA 一样都没有。这里改的是**真页**，任何读取路径都看得见（包括本工具自己的 R3/R0/HVM）；而且**没有触发**，载荷写完就躺在那里等目标自己执行到，写进一个永远不会被执行的位置等于什么都没做。每一次写入都强制先备份、写完立刻读回校验——DDMA 写入没有任何自证，驱动报成功只说明命令被接受，不说明物理页真的变了。"));
        root->addWidget(intro);

        m_targetLabel = new QLabel(QStringLiteral("未附加进程。"), this);
        m_targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        root->addWidget(m_targetLabel);

        QGridLayout* form = new QGridLayout();
        form->setHorizontalSpacing(8);
        form->setVerticalSpacing(6);

        form->addWidget(new QLabel(QStringLiteral("目标虚拟地址"), this), 0, 0);
        m_addressEdit = new QLineEdit(this);
        m_addressEdit->setPlaceholderText(QStringLiteral("目标进程里的地址，默认十六进制"));
        m_addressEdit->setClearButtonEnabled(true);
        m_addressEdit->setToolTip(QStringLiteral("注入时这个地址只用来定位所在的页，载荷会被排进页内的空隙里；写 UD2 时写的就是这个地址本身。"));
        form->addWidget(m_addressEdit, 0, 1, 1, 3);

        form->addWidget(new QLabel(QStringLiteral("载荷（十六进制）"), this), 1, 0);
        m_payloadEdit = new QLineEdit(this);
        m_payloadEdit->setPlaceholderText(QStringLiteral("例如 90 48 31 C0 C3"));
        m_payloadEdit->setClearButtonEnabled(true);
        m_payloadEdit->setToolTip(QStringLiteral("位置无关的机器码。只接受成对的十六进制数位，分隔符随意；位数为奇数会被拒绝而不是补零——补零会静默改变最后一个字节，也就是改变最后一条指令。"));
        form->addWidget(m_payloadEdit, 1, 1, 1, 3);

        root->addLayout(form);

        m_forceCheck = new QCheckBox(QStringLiteral("附加 FORCE 标志（DDMA 写入要求）"), this);
        m_forceCheck->setToolTip(QStringLiteral("驱动对 DDMA 写入要求显式的强制标志，缺了会被拒绝。"));
        m_acknowledgeCheck = new QCheckBox(
            QStringLiteral("我确认这会修改目标进程的真实内存页，并且由我负责还原"), this);
        root->addWidget(m_forceCheck);
        m_unknownSharingCheck = new QCheckBox(
            QStringLiteral("目标页的共享性无法确认时仍然写入（后果可能波及其它进程）"), this);
        m_unknownSharingCheck->setToolTip(QStringLiteral("只在“无法确认”时起作用。已经确认被其它进程共享的页没有任何开关能解锁——往一张共享的映像页写字节会打到每一个映射它的进程。"));
        root->addWidget(m_acknowledgeCheck);
        root->addWidget(m_unknownSharingCheck);

        QHBoxLayout* actions = new QHBoxLayout();
        actions->setContentsMargins(0, 0, 0, 0);
        actions->setSpacing(8);
        m_injectButton = new QPushButton(QStringLiteral("注入载荷到页内空隙"), this);
        m_injectButton->setToolTip(QStringLiteral("在目标地址所在页里找一段至少 64 字节的填充（只认 0x00 与 0xCC），把载荷排进去。找不到足够长的空隙会拒绝，而不是凑合写在一段短的上——那与直接覆盖真代码没有区别。"));
        m_ud2Button = new QPushButton(QStringLiteral("写 UD2（让目标崩掉）"), this);
        m_ud2Button->setToolTip(QStringLiteral("往目标地址写两字节 0F 0B。它不是一个可靠的结束：目标可能带异常处理器把 #UD 吞掉，生效与否还取决于那段代码会不会被执行到，而且会留下崩溃转储。"));
        m_restoreButton = new QPushButton(QStringLiteral("还原上一次写入"), this);
        actions->addWidget(m_injectButton);
        actions->addWidget(m_ud2Button);
        actions->addWidget(m_restoreButton);
        actions->addStretch(1);
        root->addLayout(actions);

        m_channelHintLabel = new QLabel(this);
        m_channelHintLabel->setWordWrap(true);
        root->addWidget(m_channelHintLabel);

        m_statusLabel = new QLabel(QStringLiteral("尚未执行。"), this);
        m_statusLabel->setWordWrap(true);
        m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        root->addWidget(m_statusLabel);

        m_logText = new CodeTextEdit(this);
        static_cast<CodeTextEdit*>(m_logText)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        m_logText->setReadOnly(true);
        m_logText->setPlaceholderText(QStringLiteral("每一次写入的计划、备份与读回校验结果都会记在这里。备份是还原的唯一依据，别清空它。"));
        root->addWidget(m_logText, 1);
    }

    void DmaProcessOpPage::wireSignals()
    {
        connect(m_injectButton, &QPushButton::clicked, this, [this]() { performWrite(true); });
        connect(m_ud2Button, &QPushButton::clicked, this, [this]() { performWrite(false); });
        connect(m_restoreButton, &QPushButton::clicked, this, [this]() { restoreLastWrite(); });
        const auto gate = [this](bool) { updateActionState(); };
        connect(m_forceCheck, &QCheckBox::toggled, this, gate);
        connect(m_acknowledgeCheck, &QCheckBox::toggled, this, gate);
        connect(m_unknownSharingCheck, &QCheckBox::toggled, this, gate);
        connect(m_addressEdit, &QLineEdit::textChanged, this,
            [this](const QString&) { updateActionState(); });
    }

    void DmaProcessOpPage::setAttachedProcess(
        const std::uint32_t processId, const QString& processName)
    {
        m_attachedPid = processId;
        m_attachedProcessName = processName;
        m_targetLabel->setText(processId == 0U
            ? QStringLiteral("未附加进程。")
            : QStringLiteral("目标：%1 [PID:%2]").arg(processName).arg(processId));
        updateActionState();
    }

    void DmaProcessOpPage::refreshChannelAvailability()
    {
        QString reason;
        const bool usable = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        if (usable)
        {
            m_channelHintLabel->setText(QStringLiteral("DDMA 通道就绪。"));
            m_channelHintLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            m_channelHintLabel->setText(
                QStringLiteral("DDMA 暂不可用：%1。本页的每一步都要经这条通道。").arg(reason));
            m_channelHintLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        }
        updateActionState();
    }

    void DmaProcessOpPage::updateActionState()
    {
        QString reason;
        const bool channelReady = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        const bool ready = channelReady
            && m_attachedPid != 0U
            && !m_addressEdit->text().trimmed().isEmpty()
            && m_forceCheck->isChecked()
            && m_acknowledgeCheck->isChecked();
        m_injectButton->setEnabled(ready);
        m_ud2Button->setEnabled(ready);
        m_restoreButton->setEnabled(channelReady && !m_records.empty());
    }

    void DmaProcessOpPage::appendLog(const QString& line)
    {
        m_logText->appendPlainText(line);
    }

    bool DmaProcessOpPage::resolveTargetPage(
        std::uint64_t& virtualAddressOut,
        std::uint64_t& pagePhysicalOut,
        std::vector<std::uint8_t>& pageBytesOut,
        QString& errorOut)
    {
        const auto parsed = ksword::evidence::ParseNumericText(
            m_addressEdit->text().trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::Hexadecimal);
        if (!parsed.ok)
        {
            errorOut = QStringLiteral("目标地址解析失败。无前缀按十六进制解释。");
            return false;
        }
        virtualAddressOut = parsed.value;

        // 按页基址翻译并整页读：计划层要整页内容才能找空隙和备份，而翻译只能
        // 按页做。这里用页基址而不是原地址，避免同一页被翻译两次。
        const std::uint64_t pageBase = virtualAddressOut & ~(kPageBytes - 1ULL);
        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualAddressTranslateResult translation =
            client.translateVirtualAddress(m_attachedPid, pageBase, 0UL);
        if (!translation.io.ok || !translation.resolved)
        {
            errorOut = translation.io.ok
                ? QStringLiteral("该页翻译不出物理地址，可能未驻留。")
                : QStringLiteral("地址翻译失败：%1")
                      .arg(QString::fromStdString(translation.io.message));
            return false;
        }
        pagePhysicalOut = translation.physicalAddress;

        const ksword::memory_backend::AccessOutcome readOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                ksword::memory_backend::currentDdmaSession(),
                pagePhysicalOut,
                kPageBytes);
        if (!readOutcome.ok)
        {
            errorOut = QStringLiteral("读取目标页失败：%1").arg(readOutcome.failureText);
            return false;
        }
        if (static_cast<std::uint64_t>(readOutcome.data.size()) != kPageBytes)
        {
            // 少读一截就没法备份完整的一页，而计划层要整页。这里拒绝而不是
            // 拿短的去算——短的算出来的偏移会指向别处。
            errorOut = QStringLiteral("只读到 %1 / %2 字节，无法据此计划写入。")
                .arg(readOutcome.data.size()).arg(kPageBytes);
            return false;
        }
        pageBytesOut.assign(
            reinterpret_cast<const std::uint8_t*>(readOutcome.data.constData()),
            reinterpret_cast<const std::uint8_t*>(readOutcome.data.constData())
                + readOutcome.data.size());
        return true;
    }

    Ksword::Evidence::DmaTargetSharing DmaProcessOpPage::evaluateSharing(
        const std::uint64_t pageVirtualAddress,
        const std::uint64_t pagePhysical,
        QString& evidenceOut)
    {
        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualMemoryQueryResult self =
            client.queryVirtualMemory(m_attachedPid, pageVirtualAddress,
                KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME);
        if (!self.io.ok)
        {
            // 问不出区域类型时不能默认私有。查询失败与"确认私有"是两件事。
            evidenceOut = QStringLiteral("查询目标区域失败：%1")
                .arg(QString::fromStdString(self.io.message));
            return Ksword::Evidence::EvaluateTargetSharing(false, false, false);
        }

        const bool isPrivate = (self.type == MEM_PRIVATE);
        if (isPrivate)
        {
            evidenceOut = QStringLiteral("区域类型 MEM_PRIVATE，不由节对象支撑。");
            return Ksword::Evidence::EvaluateTargetSharing(true, false, false);
        }

        const QString backingFile = QString::fromStdWString(self.mappedFileName);
        // 跨进程比物理地址：在另一个映射同一文件的进程里翻译同一个虚拟地址，
        // 拿到的物理地址相同就是同一张页。这是唯一一个真读数——区域类型只是推测，
        // 一页 MEM_IMAGE 可能早就因写时复制变成了私有副本。
        const ksword::ark::ProcessEnumResult processes = client.enumerateProcesses(0UL);
        int examined = 0;
        if (processes.io.ok)
        {
            for (const auto& entry : processes.entries)
            {
                const std::uint32_t otherPid = static_cast<std::uint32_t>(entry.processId);
                if (otherPid == m_attachedPid || otherPid == 0U || otherPid == 4U)
                {
                    continue;
                }
                if (examined >= 64)
                {
                    break;
                }
                const ksword::ark::VirtualMemoryQueryResult other =
                    client.queryVirtualMemory(otherPid, pageVirtualAddress,
                        KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME);
                if (!other.io.ok || other.state != MEM_COMMIT)
                {
                    continue;
                }
                if (QString::fromStdWString(other.mappedFileName) != backingFile)
                {
                    continue;
                }
                ++examined;
                const ksword::ark::VirtualAddressTranslateResult otherPa =
                    client.translateVirtualAddress(otherPid, pageVirtualAddress, 0UL);
                if (!otherPa.io.ok || !otherPa.resolved)
                {
                    continue;
                }
                if (otherPa.physicalAddress == pagePhysical)
                {
                    evidenceOut = QStringLiteral(
                        "PID %1 的同一虚拟地址落在同一张物理页 %2 上，支撑文件 %3。")
                        .arg(otherPid).arg(hex64(pagePhysical)).arg(backingFile);
                    return Ksword::Evidence::EvaluateTargetSharing(false, true, true);
                }
                // 物理地址不同说明写时复制已经发生，这个进程拿的是自己的副本。
                evidenceOut = QStringLiteral(
                    "PID %1 映射同一文件但物理页不同（%2 vs %3），写时复制已经发生。")
                    .arg(otherPid).arg(hex64(otherPa.physicalAddress)).arg(hex64(pagePhysical));
                return Ksword::Evidence::EvaluateTargetSharing(false, true, false);
            }
        }

        evidenceOut = QStringLiteral(
            "区域类型不是 MEM_PRIVATE（支撑文件 %1），但在检查过的进程里没找到第二个映射它的，无法比对物理页。")
            .arg(backingFile.isEmpty() ? QStringLiteral("未知") : backingFile);
        return Ksword::Evidence::EvaluateTargetSharing(false, false, false);
    }

    void DmaProcessOpPage::performWrite(const bool injectPayload)
    {
        std::uint64_t virtualAddress = 0ULL;
        std::uint64_t pagePhysical = 0ULL;
        std::vector<std::uint8_t> pageBytes;
        QString error;
        if (!resolveTargetPage(virtualAddress, pagePhysical, pageBytes, error))
        {
            m_statusLabel->setText(error);
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
            return;
        }

        // 共享性检查排在计划之前：一张共享页上算出来的计划再正确也不该执行。
        QString sharingEvidence;
        const DmaTargetSharing sharing = evaluateSharing(
            virtualAddress & ~(kPageBytes - 1ULL), pagePhysical, sharingEvidence);
        appendLog(QStringLiteral("── 共享性检查：%1")
            .arg(QString::fromUtf8(DmaTargetSharingName(sharing))));
        appendLog(QStringLiteral("   依据：%1").arg(sharingEvidence));

        if (sharing == DmaTargetSharing::SharedConfirmed)
        {
            // **没有开关能解锁这一条。** DMA 写的是物理页，而写时复制靠缺页异常
            // 实现、DMA 不触发缺页；往一张已经确认被共享的映像页写字节，会打到
            // 每一个映射它的进程。往 ntdll 的代码页写一条 UD2 等于让全机器的进程
            // 在跑到那里时一起崩。这不是一个用户勾一下就该承担的后果。
            m_statusLabel->setText(QStringLiteral(
                "已拒绝：目标页确认被其它进程共享。%1 DMA 不触发写时复制，写入会波及每一个映射这张页的进程。请改用 R-1 注入（它把载荷放在影子页里，作用域限定在单个进程），或选一张进程私有的页。")
                .arg(sharingEvidence));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ErrorHex()));
            return;
        }
        if (sharing == DmaTargetSharing::SharingUnknown
            && !m_unknownSharingCheck->isChecked())
        {
            m_statusLabel->setText(QStringLiteral(
                "已拒绝：无法确认目标页是否被其它进程共享。%1 没找到第二个映射它的进程不等于没有。要继续，请勾选下面那一项并自行承担波及其它进程的可能。")
                .arg(sharingEvidence));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::WarningHex()));
            return;
        }

        DmaWritePlan plan;
        QString description;
        if (injectPayload)
        {
            std::vector<std::uint8_t> payload;
            QString payloadError;
            if (!parseHexPayload(m_payloadEdit->text(), payload, payloadError))
            {
                m_statusLabel->setText(payloadError);
                m_statusLabel->setStyleSheet(
                    QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
                return;
            }
            plan = PlanPayloadIntoCave(pageBytes, payload, kDmaOpMinCaveBytes);
            description = QStringLiteral("注入载荷 %1 字节").arg(payload.size());
        }
        else
        {
            const std::size_t offsetInPage =
                static_cast<std::size_t>(virtualAddress & (kPageBytes - 1ULL));
            plan = PlanBytesAtOffset(pageBytes, offsetInPage, UndefinedInstructionBytes());
            description = QStringLiteral("写 UD2");
        }

        if (plan.status != DmaOpPlanStatus::Ok)
        {
            m_statusLabel->setText(QStringLiteral("计划被拒绝：%1")
                .arg(QString::fromUtf8(DmaOpPlanStatusName(plan.status))));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
            return;
        }

        const std::uint64_t writePhysicalAddress =
            pagePhysical + static_cast<std::uint64_t>(plan.offsetInPage);
        appendLog(QStringLiteral("── %1").arg(description));
        appendLog(QStringLiteral("   目标 VA %1，页物理 %2，页内偏移 0x%3")
            .arg(hex64(virtualAddress)).arg(hex64(pagePhysical))
            .arg(QString::number(plan.offsetInPage, 16).toUpper()));
        appendLog(QStringLiteral("   备份（原始字节）：%1").arg(hexDump(plan.originalBytes, 32U)));
        appendLog(QStringLiteral("   将写入：%1").arg(hexDump(plan.bytesToWrite, 32U)));

        const QByteArray payloadBytes(
            reinterpret_cast<const char*>(plan.bytesToWrite.data()),
            static_cast<qsizetype>(plan.bytesToWrite.size()));
        const ksword::memory_backend::AccessOutcome writeOutcome =
            ksword::memory_backend::writePhysical(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                ksword::memory_backend::currentDdmaSession(),
                writePhysicalAddress,
                payloadBytes,
                m_forceCheck->isChecked());
        if (!writeOutcome.ok)
        {
            appendLog(QStringLiteral("   写入失败：%1").arg(writeOutcome.failureText));
            m_statusLabel->setText(QStringLiteral("写入失败：%1").arg(writeOutcome.failureText));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::ErrorHex()));
            return;
        }
        if (writeOutcome.scratchDirty)
        {
            appendLog(QStringLiteral(
                "   严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。"));
        }

        // 读回校验。这一步不是可选的诊断：DDMA 写入没有任何自证，一次静默没落地
        // 的写入与一次成功的写入在界面上完全同形。
        const ksword::memory_backend::AccessOutcome verifyOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                ksword::memory_backend::currentDdmaSession(),
                writePhysicalAddress,
                static_cast<std::uint64_t>(plan.bytesToWrite.size()));
        std::vector<std::uint8_t> readback;
        if (verifyOutcome.ok)
        {
            readback.assign(
                reinterpret_cast<const std::uint8_t*>(verifyOutcome.data.constData()),
                reinterpret_cast<const std::uint8_t*>(verifyOutcome.data.constData())
                    + verifyOutcome.data.size());
        }
        const DmaWriteVerification verification =
            VerifyWriteReadback(plan.bytesToWrite, readback);

        DmaOpRecord record;
        record.virtualAddress = virtualAddress;
        record.physicalAddress = writePhysicalAddress;
        record.offsetInPage = plan.offsetInPage;
        record.writtenBytes = plan.bytesToWrite;
        record.originalBytes = plan.originalBytes;
        record.description = description;
        record.verified = verification.matched;
        m_records.push_back(record);

        if (verification.matched)
        {
            appendLog(QStringLiteral("   读回校验通过（%1 字节一致）。")
                .arg(verification.comparedBytes));
            m_statusLabel->setText(QStringLiteral(
                "%1 完成并通过读回校验。注意：DMA 没有触发点，载荷要等目标自己执行到；真页已被修改，记得用“还原上一次写入”。")
                .arg(description));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            const QString detail = verification.readbackTooShort
                ? QStringLiteral("读回只有 %1 字节").arg(verification.comparedBytes)
                : QStringLiteral("第 %1 字节期望 %2、实际 %3")
                      .arg(verification.firstMismatchOffset)
                      .arg(QStringLiteral("%1").arg(verification.expectedByte, 2, 16, QChar('0')).toUpper())
                      .arg(QStringLiteral("%1").arg(verification.actualByte, 2, 16, QChar('0')).toUpper());
            appendLog(QStringLiteral("   读回校验失败：%1").arg(detail));
            // 校验失败时**不能**说"写入成功"。驱动接受了命令，但物理页现在是什么
            // 状态并不确定——可能没落地，也可能落了一半。备份仍然留着。
            m_statusLabel->setText(QStringLiteral(
                "%1 的写入命令被接受，但读回校验失败（%2）。目标页当前状态不确定，备份已记录，建议立刻还原。")
                .arg(description).arg(detail));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ErrorHex()));
        }
        updateActionState();
    }

    void DmaProcessOpPage::restoreLastWrite()
    {
        if (m_records.empty())
        {
            return;
        }
        const DmaOpRecord record = m_records.back();
        const QByteArray original(
            reinterpret_cast<const char*>(record.originalBytes.data()),
            static_cast<qsizetype>(record.originalBytes.size()));

        appendLog(QStringLiteral("── 还原 %1").arg(record.description));
        const ksword::memory_backend::AccessOutcome writeOutcome =
            ksword::memory_backend::writePhysical(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                ksword::memory_backend::currentDdmaSession(),
                record.physicalAddress,
                original,
                true);
        if (!writeOutcome.ok)
        {
            appendLog(QStringLiteral("   还原失败：%1").arg(writeOutcome.failureText));
            m_statusLabel->setText(QStringLiteral("还原失败：%1。备份仍然保留在日志里。")
                .arg(writeOutcome.failureText));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ErrorHex()));
            return;
        }

        const ksword::memory_backend::AccessOutcome verifyOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                ksword::memory_backend::currentDdmaSession(),
                record.physicalAddress,
                static_cast<std::uint64_t>(record.originalBytes.size()));
        std::vector<std::uint8_t> readback;
        if (verifyOutcome.ok)
        {
            readback.assign(
                reinterpret_cast<const std::uint8_t*>(verifyOutcome.data.constData()),
                reinterpret_cast<const std::uint8_t*>(verifyOutcome.data.constData())
                    + verifyOutcome.data.size());
        }
        const DmaWriteVerification verification =
            VerifyWriteReadback(record.originalBytes, readback);
        if (!verification.matched)
        {
            appendLog(QStringLiteral("   还原后的读回校验失败，目标页仍处于未知状态。"));
            m_statusLabel->setText(QStringLiteral(
                "还原命令被接受，但读回校验失败。目标页仍处于未知状态，备份保留在日志里。"));
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ErrorHex()));
            return;
        }

        // 只有校验通过才把记录摘掉：校验没过就摘，等于把还原的唯一依据丢了。
        m_records.pop_back();
        appendLog(QStringLiteral("   还原完成并通过读回校验。"));
        m_statusLabel->setText(QStringLiteral("已还原并通过读回校验。"));
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        updateActionState();
    }
}
