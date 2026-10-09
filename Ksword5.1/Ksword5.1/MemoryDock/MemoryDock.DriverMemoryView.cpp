#include "MemoryDock.Internal.h"
#include "../UI/KernelDisassemblyDialog.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"

// ============================================================
// MemoryDock.DriverMemoryView.cpp
// 作用：
// - 承载“驱动内存读写”页的多视图呈现：十六进制、反汇编、文本；
// - 提供快照转存到文件与字符串写入编辑缓存两个便捷入口；
// - 只消费 MemoryDock 已缓存的快照字节，自身不发起任何 IOCTL。
// ============================================================

using namespace ksword::memory_dock_internal;

namespace
{
    // 文本转储每行的字节数：保持地址、十六进制与 ASCII 三列对齐。
    constexpr qsizetype kDriverMemoryTextViewLineWidth = 16;

    // 将 bytes 中的可打印 ASCII 原样输出，其余字节替换为点号。
    // 调用方传入单行快照字节，返回用于文本转储的等长字符串。
    QString driverMemoryPrintableText(const QByteArray& bytes)
    {
        // resultText 保存输出文本；预留单行字节数以避免重复分配。
        QString resultText;
        resultText.reserve(bytes.size());
        for (const char rawByte : bytes)
        {
            // byteValue 保留原始无符号字节；printable 标记 ASCII 可打印范围。
            const std::uint8_t byteValue = static_cast<std::uint8_t>(rawByte);
            const bool printable = byteValue >= 0x20U && byteValue <= 0x7EU;
            resultText.append(printable ? QChar(QLatin1Char(static_cast<char>(byteValue)))
                                        : QChar(QLatin1Char('.')));
        }
        return resultText;
    }

    // driverMemoryBytesText 作用：
    // - 把一段原始字节渲染成反汇编表格里的“原始字节”列文本；
    // - 输入 bytes：单条指令的字节序列；
    // - 处理：逐字节转两位大写十六进制并以空格分隔；
    // - 返回：形如 "48 8B 05 A1" 的文本，空输入返回空串。
    QString driverMemoryBytesText(const QByteArray& bytes)
    {
        QStringList byteTextList;
        byteTextList.reserve(static_cast<int>(bytes.size()));
        for (const char rawByte : bytes)
        {
            // 先转成无符号再格式化，避免 char 为负时补出 FFFFFF 前缀。
            const std::uint8_t byteValue = static_cast<std::uint8_t>(rawByte);
            byteTextList.push_back(
                QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper());
        }
        return byteTextList.join(QLatin1Char(' '));
    }

    // driverMemoryHexAddressText 作用：
    // - 统一反汇编表格的地址列文本格式；
    // - 输入 address：指令绝对虚拟地址；
    // - 处理：按 16 位定宽补零并转大写，前缀保持小写 0x 以便与本页其它地址一致；
    // - 返回：形如 "0xFFFFF8034A1B2C00" 的文本。
    QString driverMemoryHexAddressText(const std::uint64_t address)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }
}

ks::ui::DisassemblyArchitecture MemoryDock::currentDriverMemoryArchitecture() const
{
    // 内核虚拟地址与物理内存快照一律按 x64 解码：本工程只支持 64 位内核。
    if (m_driverMemorySnapshotIsPhysical
        || m_driverMemoryBaseAddress >= 0xFFFF000000000000ULL
        || m_driverMemorySnapshotPid == 0U)
    {
        return ks::ui::DisassemblyArchitecture::X64;
    }

    // 用户态快照跟随目标进程位数：WOW64 进程里的代码是 32 位指令。
    const HANDLE processHandle = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        toDwordPid(m_driverMemorySnapshotPid));
    if (processHandle == nullptr)
    {
        // 拿不到句柄时保守按 x64，与本页读取路径的默认假设一致。
        return ks::ui::DisassemblyArchitecture::X64;
    }

    BOOL isWow64Process = FALSE;
    const BOOL queryOk = ::IsWow64Process(processHandle, &isWow64Process);
    ::CloseHandle(processHandle);
    if (queryOk == FALSE)
    {
        return ks::ui::DisassemblyArchitecture::X64;
    }
    return (isWow64Process != FALSE) ? ks::ui::DisassemblyArchitecture::X86
                                     : ks::ui::DisassemblyArchitecture::X64;
}

void MemoryDock::refreshDriverMemoryViewsFromSnapshot()
{
    if (m_driverMemoryEditor == nullptr)
    {
        return;
    }
    if (!m_driverMemoryHasSnapshot)
    {
        m_driverMemoryEditor->clear();
        m_driverMemoryEditor->setEditable(false);
        return;
    }
    if (m_driverMemoryEditor->baseAddress() != m_driverMemoryBaseAddress
        || m_driverMemoryEditor->originalBytes() != m_driverMemoryOriginalBytes)
    {
        m_driverMemoryEditor->setSnapshot(
            m_driverMemoryOriginalBytes,
            m_driverMemoryBaseAddress,
            currentDriverMemoryArchitecture(),
            m_driverMemoryCenterAddress,
            QStringLiteral("driver_memory_%1_%2_%3_%4_%5").arg(static_cast<int>(m_driverMemorySnapshotBackend))
                .arg(m_driverMemorySnapshotPid).arg(m_driverMemorySnapshotIsPhysical ? 1 : 0)
                .arg(m_driverMemorySnapshotDdmaGeneration).arg(m_driverMemorySnapshotProcessCreateTime100ns));
        const bool processVirtual = !m_driverMemorySnapshotIsPhysical
            && m_driverMemorySnapshotBackend != ksword::memory_backend::MemoryAccessBackend::Ddma
            && !ksword::memory_backend::isKernelVirtualAddress(m_driverMemoryBaseAddress);
        // 视图刷新沿用读取时冻结的身份，不因菜单打开或重新绘制再次查询同号进程。
        m_driverMemoryEditor->setProcessContext(
            processVirtual ? toDwordPid(m_driverMemorySnapshotPid) : 0U,
            processVirtual ? m_driverMemorySnapshotProcessCreateTime100ns : 0ULL);
    }
    else
    {
        m_driverMemoryEditor->refreshFromHexEditor();
    }
    m_driverMemoryEditor->setEditable(true);
}

void MemoryDock::loadDriverMemoryEditorSnapshot()
{
    m_driverMemorySnapshotBackend = currentDriverMemoryBackend();
    m_driverMemorySnapshotDdmaGeneration = ksword::memory_backend::ddmaSessionGeneration();
    const bool processVirtual = !m_driverMemorySnapshotIsPhysical
        && m_driverMemorySnapshotBackend != ksword::memory_backend::MemoryAccessBackend::Ddma
        && !ksword::memory_backend::isKernelVirtualAddress(m_driverMemoryBaseAddress);
    if (!processVirtual)
    {
        m_driverMemorySnapshotProcessCreateTime100ns = 0;
    }
    m_driverMemoryEditor->setSnapshot(m_driverMemoryOriginalBytes,
        m_driverMemoryBaseAddress, currentDriverMemoryArchitecture(), m_driverMemoryCenterAddress,
        QStringLiteral("driver_memory_%1_%2_%3_%4_%5").arg(static_cast<int>(m_driverMemorySnapshotBackend))
            .arg(m_driverMemorySnapshotPid).arg(m_driverMemorySnapshotIsPhysical ? 1 : 0)
            .arg(m_driverMemorySnapshotDdmaGeneration).arg(m_driverMemorySnapshotProcessCreateTime100ns));
    m_driverMemoryEditor->setProcessContext(
        processVirtual ? toDwordPid(m_driverMemorySnapshotPid) : 0U,
        m_driverMemorySnapshotProcessCreateTime100ns);
    m_driverMemoryEditor->setEditable(true);
}

void MemoryDock::dumpDriverMemorySnapshotToFile()
{
    // 记录转存日志：这是一条会在磁盘留下目标内存内容的路径，必须可追溯。
    kLogEvent dumpEvent;
    info << dumpEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 请求把当前快照写入文件。"
        << eol;

    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // 默认文件名带上地址与长度，便于多次转存后区分。
    const QString defaultName = QStringLiteral("memory_%1_%2bytes.bin")
        .arg(formatAddress(m_driverMemoryBaseAddress))
        .arg(m_driverMemoryEditedBytes.size());
    const QString selectedPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("把当前内存快照转存到文件"),
        defaultName,
        QStringLiteral("二进制文件 (*.bin);;十六进制文本 (*.txt);;所有文件 (*.*)"));
    if (selectedPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(selectedPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("无法写入文件: %1").arg(outputFile.errorString()));
        return;
    }

    // 按扩展名决定落盘格式：.txt 走可读的十六进制转储，其余一律原始字节。
    const bool asHexText = selectedPath.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive);
    qint64 writtenBytes = 0;
    if (asHexText)
    {
        // 十六进制文本格式与十六进制视图保持一致：地址 + 16 字节 + ASCII。
        QString dumpText;
        const qsizetype totalBytes = m_driverMemoryEditedBytes.size();
        for (qsizetype lineStart = 0; lineStart < totalBytes; lineStart += kDriverMemoryTextViewLineWidth)
        {
            const qsizetype lineBytes =
                std::min<qsizetype>(kDriverMemoryTextViewLineWidth, totalBytes - lineStart);
            const QByteArray lineSlice = m_driverMemoryEditedBytes.mid(lineStart, lineBytes);
            dumpText += QStringLiteral("%1  %2  %3\n")
                .arg(driverMemoryHexAddressText(
                    m_driverMemoryBaseAddress + static_cast<std::uint64_t>(lineStart)))
                .arg(driverMemoryBytesText(lineSlice), -47)
                .arg(driverMemoryPrintableText(lineSlice));
        }
        const QByteArray encodedText = dumpText.toUtf8();
        writtenBytes = outputFile.write(encodedText);
    }
    else
    {
        writtenBytes = outputFile.write(m_driverMemoryEditedBytes);
    }
    outputFile.close();

    if (writtenBytes < 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("转存到文件"),
            QStringLiteral("写入过程中失败: %1").arg(outputFile.errorString()));
        return;
    }

    // 成功后把结果写进状态标签，避免再弹一个模态框打断操作。
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(
            QStringLiteral("已转存 %1 字节到 %2").arg(writtenBytes).arg(selectedPath));
    }

    kLogEvent dumpDoneEvent;
    info << dumpDoneEvent
        << "[MemoryDock] dumpDriverMemorySnapshotToFile: 转存完成。"
        << eol;
}

void MemoryDock::writeStringIntoDriverMemoryBuffer()
{
    // 记录字符串写入日志：它会改动编辑缓存，属于会影响后续写回的操作。
    kLogEvent writeStringEvent;
    info << writeStringEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 打开字符串写入对话框。"
        << eol;

    if (!m_driverMemoryHasSnapshot || m_driverMemoryEditedBytes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("当前没有已读取的内存快照，请先点击“R0 读取”。"));
        return;
    }

    // 对话框结构：目标地址、编码、是否补结尾 0、字符串内容。
    const auto snapshotBase = m_driverMemoryBaseAddress;
    const auto snapshotPid = m_driverMemorySnapshotPid;
    const auto snapshotBackend = m_driverMemorySnapshotBackend;
    const auto snapshotPhysical = m_driverMemorySnapshotIsPhysical;
    const auto snapshotDdmaGeneration = m_driverMemorySnapshotDdmaGeneration;
    const QByteArray snapshotOriginal = m_driverMemoryOriginalBytes;
    const QByteArray snapshotEdited = m_driverMemoryEditor->data();
    QDialog stringDialog(this);
    stringDialog.setWindowTitle(QStringLiteral("字符串写入"));
    stringDialog.setModal(true);
    QVBoxLayout* dialogLayout = new QVBoxLayout(&stringDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);

    // 默认地址取十六进制视图当前光标位置，符合“选中哪里就写哪里”的直觉。
    const std::uint64_t defaultAddress = (m_driverMemoryHexEditor != nullptr)
        ? m_driverMemoryHexEditor->selectedAbsoluteAddress()
        : m_driverMemoryBaseAddress;
    QLineEdit* addressEdit = new QLineEdit(&stringDialog);
    addressEdit->setText(formatAddress(defaultAddress));
    addressEdit->setToolTip(QStringLiteral("字符串写入的起始地址，必须落在当前快照范围内。"));

    QComboBox* encodingCombo = new QComboBox(&stringDialog);
    encodingCombo->addItem(QStringLiteral("ANSI / UTF-8 单字节"));
    encodingCombo->addItem(QStringLiteral("UTF-16LE 宽字符"));
    encodingCombo->setToolTip(QStringLiteral("选择字符串在目标内存里的编码方式。"));

    QCheckBox* nullTerminatedCheck = new QCheckBox(
        QStringLiteral("末尾补写结尾 0"), &stringDialog);
    nullTerminatedCheck->setChecked(true);
    nullTerminatedCheck->setToolTip(
        QStringLiteral("勾选后在字符串末尾补一个结尾 0，符合 C 字符串约定。"));

    QLineEdit* contentEdit = new QLineEdit(&stringDialog);
    contentEdit->setPlaceholderText(QStringLiteral("要写入的字符串内容"));
    contentEdit->setToolTip(QStringLiteral("按上面选定的编码转成字节后填入编辑缓存。"));

    formLayout->addWidget(new QLabel(QStringLiteral("起始地址"), &stringDialog), 0, 0);
    formLayout->addWidget(addressEdit, 0, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("编码"), &stringDialog), 1, 0);
    formLayout->addWidget(encodingCombo, 1, 1);
    formLayout->addWidget(new QLabel(QStringLiteral("内容"), &stringDialog), 2, 0);
    formLayout->addWidget(contentEdit, 2, 1);
    formLayout->addWidget(nullTerminatedCheck, 3, 1);
    dialogLayout->addLayout(formLayout);

    // 明确告知：这一步只改编辑缓存，真正写回仍需点“应用差异”。
    QLabel* hintLabel = new QLabel(
        QStringLiteral("字符串只填入本地编辑缓存，确认无误后再点“应用差异到真实内存”。"),
        &stringDialog);
    hintLabel->setWordWrap(true);
    dialogLayout->addWidget(hintLabel);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &stringDialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("填入缓存"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    dialogLayout->addWidget(buttonBox);
    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &stringDialog, &QDialog::accept);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &stringDialog, &QDialog::reject);

    if (stringDialog.exec() != QDialog::Accepted)
    {
        return;
    }
    if (!m_driverMemoryHasSnapshot || m_driverMemoryBaseAddress != snapshotBase
        || m_driverMemorySnapshotPid != snapshotPid || m_driverMemorySnapshotBackend != snapshotBackend
        || m_driverMemorySnapshotIsPhysical != snapshotPhysical
        || m_driverMemorySnapshotDdmaGeneration != snapshotDdmaGeneration
        || currentDriverMemoryBackend() != snapshotBackend
        || m_driverMemoryOriginalBytes != snapshotOriginal
        || m_driverMemoryEditor->data() != snapshotEdited)
    {
        QMessageBox::warning(this, QStringLiteral("字符串写入"),
            QStringLiteral("目标进程或访问后端已改变，请重新读取后再应用改动。"));
        return;
    }

    // 解析起始地址，越界一律拒绝，绝不静默截断。
    std::uint64_t targetAddress = 0ULL;
    if (!parseAddressText(addressEdit->text(), targetAddress))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址解析失败，请填写十六进制地址。"));
        return;
    }
    if (targetAddress < m_driverMemoryBaseAddress)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("起始地址在当前快照范围之前，请重新填写。"));
        return;
    }

    // 按选定编码把字符串转成字节序列。
    const QString contentText = contentEdit->text();
    QByteArray payloadBytes;
    if (encodingCombo->currentIndex() == 1)
    {
        // UTF-16LE：逐个码元按小端展开，保持与目标内存布局一致。
        for (const QChar contentChar : contentText)
        {
            const std::uint16_t codeUnit = contentChar.unicode();
            payloadBytes.append(static_cast<char>(codeUnit & 0xFFU));
            payloadBytes.append(static_cast<char>((codeUnit >> 8) & 0xFFU));
        }
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
            payloadBytes.append('\0');
        }
    }
    else
    {
        payloadBytes = contentText.toUtf8();
        if (nullTerminatedCheck->isChecked())
        {
            payloadBytes.append('\0');
        }
    }

    if (payloadBytes.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("内容为空，没有可写入的字节。"));
        return;
    }

    // 校验整段字节都落在快照内，越界直接拒绝，避免部分写入造成半截字符串。
    const std::uint64_t writeOffset = targetAddress - m_driverMemoryBaseAddress;
    const std::uint64_t snapshotSize = static_cast<std::uint64_t>(m_driverMemoryEditedBytes.size());
    if (writeOffset >= snapshotSize
        || (snapshotSize - writeOffset) < static_cast<std::uint64_t>(payloadBytes.size()))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("字符串写入"),
            QStringLiteral("字符串长度超出当前快照范围，请扩大读取范围或换一个起始地址。"));
        return;
    }

    // 写入编辑缓存，并同步刷新十六进制视图，让改动立刻可见。
    for (qsizetype byteIndex = 0; byteIndex < payloadBytes.size(); ++byteIndex)
    {
        m_driverMemoryEditedBytes[static_cast<qsizetype>(writeOffset) + byteIndex] =
            payloadBytes.at(byteIndex);
    }
    if (m_driverMemoryHexEditor != nullptr)
    {
        m_driverMemoryHexEditor->setByteArray(m_driverMemoryEditedBytes, m_driverMemoryBaseAddress);
        m_driverMemoryHexEditor->jumpToAbsoluteAddress(targetAddress);
    }
    refreshDriverMemoryViewsFromSnapshot();

    // 重新统计差异块并据此决定“应用差异”按钮是否可用。
    std::vector<DriverDiffBlock> diffBlocks;
    collectDriverMemoryDiffBlocks(diffBlocks);
    if (m_driverMemoryApplyButton != nullptr)
    {
        m_driverMemoryApplyButton->setEnabled(!diffBlocks.empty());
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(
            QStringLiteral("已在 0x%1 填入 %2 字节字符串，当前共 %3 处差异待应用。")
                .arg(formatAddress(targetAddress))
                .arg(payloadBytes.size())
                .arg(diffBlocks.size()));
    }

    kLogEvent writeStringDoneEvent;
    info << writeStringDoneEvent
        << "[MemoryDock] writeStringIntoDriverMemoryBuffer: 字符串已填入编辑缓存。"
        << eol;
}
