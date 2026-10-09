#include "HvmMemoryDialog.h"

#include "HvmControl.h"
#include "MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "UI_All.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../../../shared/evidence/MemoryAddressInput.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <limits>
#include <thread>

namespace
{
    constexpr int kMaxTransferBytes =
        static_cast<int>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);

    ksword::hvm::HvmMemoryResult readTarget(
        const bool virtualMode, const unsigned long long directoryBase,
        const unsigned long processId, const unsigned long long address,
        const unsigned long length)
    {
        return virtualMode
            ? ksword::hvm::readVirtual(directoryBase, address, length, processId)
            : ksword::hvm::readPhysical(address, length);
    }

    struct WriteOutcome
    {
        bool writeAttempted = false;
        bool allVerified = false;
        qsizetype verifiedBytes = 0;
        QString failure;
        ksword::hvm::HvmMemoryResult readback;
    };

    struct WriteMessages
    {
        QString preflightFailed;
        QString originalConflict;
        QString verifyFailed;
        QString readbackFailed;
        QString mismatch;
        QString incomplete;
    };
}

HvmMemoryDialog::HvmMemoryDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("HVM R-1 内存操作")));
    setObjectName(QStringLiteral("HvmMemoryDialog"));
    buildUi();
    updateEnabledState();
    ks::ui::applyResponsiveWindowGeometry(
        this, parent, QSize(1120, 740), QSize(640, 480));

    QPointer<HvmMemoryDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmMemoryResult result =
            ksword::hvm::queryMemoryWindow();
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
                safeThis->m_windowLabel->setText(result.windowReady
                    ? ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：可用（读写均绕开内存管理器导出例程）"))
                    : ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：不可用（读退化为 MmCopyMemory，写不可用）")));
            }, Qt::QueuedConnection);
    }).detach();
}

HvmMemoryDialog::~HvmMemoryDialog()
{
    cancelPendingOperation();
}

void HvmMemoryDialog::done(const int result)
{
    cancelPendingOperation();
    QDialog::done(result);
}

void HvmMemoryDialog::cancelPendingOperation()
{
    ++m_operationSerial;
    if (m_cancelled != nullptr)
    {
        m_cancelled->store(true, std::memory_order_relaxed);
    }
}

unsigned long long HvmMemoryDialog::beginOperation()
{
    cancelPendingOperation();
    m_cancelled = std::make_shared<std::atomic_bool>(false);
    setBusy(true);
    return m_operationSerial;
}

bool HvmMemoryDialog::isVirtualMode() const
{
    return m_modeBox != nullptr && m_modeBox->currentIndex() == 1;
}

void HvmMemoryDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);
    rootLayout->setSizeConstraint(QLayout::SetNoConstraint);

    m_windowLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("私有页表窗口：正在查询...")), this);
    m_windowLabel->setWordWrap(true);
    rootLayout->addWidget(m_windowLabel);

    QFormLayout* const formLayout = new QFormLayout();
    formLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);
    m_modeBox = new QComboBox(this);
    m_modeBox->addItem(ks::i18n::sourceText(QStringLiteral("物理地址")));
    m_modeBox->addItem(ks::i18n::sourceText(QStringLiteral("虚拟地址")));
    m_modeBox->setCurrentIndex(1);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址类型")), m_modeBox);

    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setPlaceholderText(QStringLiteral("0x1000"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址（十六进制）")), m_addressEdit);

    m_processIdEdit = new QLineEdit(
        QString::number(QCoreApplication::applicationPid()), this);
    m_processIdEdit->setToolTip(ks::i18n::sourceText(QStringLiteral(
        "默认使用 KSword 当前进程 PID；可输入其他进程 PID，自动获取其 CR3")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("目标 PID（十进制）")), m_processIdEdit);

    m_directoryBaseEdit = new QLineEdit(this);
    m_directoryBaseEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空自动获取目标进程 CR3")));
    m_directoryBaseEdit->setToolTip(ks::i18n::sourceText(QStringLiteral(
        "留空时按目标 PID 自动获取 CR3；输入非零 CR3 时只使用自定义页表，忽略 PID")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("页目录基址（CR3）")), m_directoryBaseEdit);

    m_lengthBox = new QSpinBox(this);
    m_lengthBox->setRange(1, kMaxTransferBytes);
    m_lengthBox->setValue(256);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("读取长度（字节）")), m_lengthBox);
    rootLayout->addLayout(formLayout);

    m_editor = new ks::ui::SnapshotWorkbenchWidget(this);
    m_editor->setEditable(false);
    m_editor->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    rootLayout->addWidget(m_editor, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_readButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("读取")), this);
    m_writeButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("应用差异到真实内存")), this);
    m_discardButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("丢弃改动")), this);
    m_translateButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("翻译为物理地址")), this);
    buttonLayout->addWidget(m_readButton, 0, 0);
    buttonLayout->addWidget(m_writeButton, 0, 1);
    buttonLayout->addWidget(m_discardButton, 0, 2);
    buttonLayout->addWidget(m_translateButton, 0, 3);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_modeBox, &QComboBox::currentIndexChanged,
        this, [this](int) { invalidateSnapshot(); });
    connect(m_addressEdit, &QLineEdit::textChanged,
        this, [this](const QString&) { invalidateSnapshot(); });
    connect(m_processIdEdit, &QLineEdit::textChanged,
        this, [this](const QString&) { invalidateSnapshot(); });
    connect(m_directoryBaseEdit, &QLineEdit::textChanged,
        this, [this](const QString&) { invalidateSnapshot(); });
    connect(m_lengthBox, &QSpinBox::valueChanged,
        this, [this](int) { invalidateSnapshot(); });
    connect(m_editor, &ks::ui::SnapshotWorkbenchWidget::bytesChanged,
        this, [this]() { updateEnabledState(); });
    connect(m_readButton, &QPushButton::clicked,
        this, [this]() { startRead(); });
    connect(m_writeButton, &QPushButton::clicked,
        this, [this]() { startWrite(); });
    connect(m_discardButton, &QPushButton::clicked, this, [this]() {
        m_editor->discardChanges();
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("已放弃未应用的修改。")));
        updateEnabledState();
    });
    connect(m_translateButton, &QPushButton::clicked,
        this, [this]() { startTranslate(); });
}

void HvmMemoryDialog::invalidateSnapshot()
{
    const bool hadSnapshot = m_hasSnapshot;
    m_hasSnapshot = false;
    m_editor->clear();
    if (hadSnapshot)
    {
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "目标参数已更改，请重新读取后编辑。")));
    }
    updateEnabledState();
}

void HvmMemoryDialog::updateEnabledState()
{
    const bool virtualMode = isVirtualMode();
    const bool writeAllowed = ksword::hvm::isWriteAccessEnabled();
    const bool hasChanges = m_editor->hasChanges();
    // 暂存修改期间锁定读取目标，用户必须先应用或放弃，不能因输入新地址丢失编辑。
    const bool targetEnabled = !m_busy && !hasChanges;
    m_modeBox->setEnabled(targetEnabled);
    m_addressEdit->setEnabled(targetEnabled);
    m_processIdEdit->setEnabled(virtualMode && targetEnabled &&
        m_directoryBaseEdit->text().trimmed().isEmpty());
    m_directoryBaseEdit->setEnabled(virtualMode && targetEnabled);
    m_lengthBox->setEnabled(targetEnabled);
    m_translateButton->setEnabled(virtualMode && !m_busy);
    m_readButton->setEnabled(targetEnabled);
    m_editor->setEnabled(!m_busy);
    m_editor->setEditable(writeAllowed && m_hasSnapshot && !m_busy);
    m_writeButton->setEnabled(
        writeAllowed && m_hasSnapshot && hasChanges && !m_busy);
    m_discardButton->setEnabled(hasChanges && !m_busy);
    m_writeButton->setToolTip(writeAllowed
        ? ks::i18n::sourceText(QStringLiteral(
            "仅将暂存的修改写回已读取的目标，写入前核对原字节并回读验证"))
        : ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 HVM 按钮右键菜单中开启后才能写入")));
}

void HvmMemoryDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

bool HvmMemoryDialog::parseAddress(
    const QLineEdit* const field, unsigned long long* const valueOut,
    const QString& fieldName)
{
    const QByteArray text = field != nullptr
        ? field->text().trimmed().toLatin1() : QByteArray();
    std::uint64_t value = 0;
    if (!Ksword::Evidence::ParseHexAddress(
            std::string_view(text.constData(), static_cast<std::size_t>(text.size())),
            value))
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("%1 不是合法的十六进制数。"))
                .arg(fieldName));
        return false;
    }
    *valueOut = value;
    return true;
}

bool HvmMemoryDialog::parseVirtualContext(
    unsigned long long* const directoryBaseOut, unsigned long* const processIdOut)
{
    *directoryBaseOut = 0;
    *processIdOut = 0;
    if (!m_directoryBaseEdit->text().trimmed().isEmpty())
    {
        if (!parseAddress(m_directoryBaseEdit, directoryBaseOut,
                ks::i18n::sourceText(QStringLiteral("页目录基址"))))
        {
            return false;
        }
        if (*directoryBaseOut == 0)
        {
            m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
                "自定义 CR3 必须非零；自动获取 CR3 请留空。")));
            return false;
        }
        return true;
    }

    const QString text = m_processIdEdit->text().trimmed();
    bool converted = false;
    const qulonglong processId = text.toULongLong(&converted, 10);
    bool decimalDigits = !text.isEmpty();
    for (const QChar character : text)
    {
        if (character < QLatin1Char('0') || character > QLatin1Char('9'))
        {
            decimalDigits = false;
            break;
        }
    }
    if (!converted || !decimalDigits || processId == 0 ||
        processId > (std::numeric_limits<unsigned long>::max)())
    {
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "目标 PID 必须是非零的 32 位十进制整数。")));
        return false;
    }
    *processIdOut = static_cast<unsigned long>(processId);
    return true;
}

void HvmMemoryDialog::startRead()
{
    if (m_busy)
    {
        return;
    }
    if (m_editor->hasChanges())
    {
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "请先应用或放弃暂存修改，再重新读取。")));
        return;
    }
    unsigned long long address = 0;
    if (!parseAddress(m_addressEdit, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    unsigned long processId = 0;
    const bool virtualMode = isVirtualMode();
    if (virtualMode && !parseVirtualContext(&directoryBase, &processId))
    {
        return;
    }
    const unsigned long length = static_cast<unsigned long>(m_lengthBox->value());
    if (address > (std::numeric_limits<unsigned long long>::max)() - (length - 1))
    {
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "读取范围超出地址空间。")));
        return;
    }

    const auto architecture = m_editor->currentArchitecture();
    const unsigned long long serial = beginOperation();
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在读取...")));
    QPointer<HvmMemoryDialog> safeThis(this);
    const auto cancelled = m_cancelled;
    std::thread([safeThis, cancelled, serial, virtualMode, address,
                    directoryBase, processId, length, architecture]() {
        const ksword::hvm::HvmMemoryResult result =
            readTarget(virtualMode, directoryBase, processId, address, length);
        if (cancelled->load(std::memory_order_relaxed) || safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, serial, virtualMode, address, directoryBase,
                processId, length, architecture]() {
                if (safeThis == nullptr || safeThis->m_operationSerial != serial)
                {
                    return;
                }
                if (!result.ok || result.data.size() != static_cast<qsizetype>(length))
                {
                    safeThis->invalidateSnapshot();
                    safeThis->setBusy(false);
                    safeThis->m_statusLabel->setText(result.ok
                        ? ks::i18n::sourceText(QStringLiteral("读取长度不完整，请重新读取。"))
                        : result.message);
                    return;
                }
                safeThis->m_snapshotVirtualMode = virtualMode;
                safeThis->m_snapshotAddress = address;
                safeThis->m_snapshotDirectoryBase = directoryBase;
                safeThis->m_snapshotProcessId = processId;
                safeThis->m_hasSnapshot = true;
                safeThis->m_editor->setSnapshot(result.data, address, architecture, address,
                    QStringLiteral("hvm_memory_%1_%2_%3").arg(virtualMode ? 1 : 0).arg(directoryBase).arg(processId));
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "已读取 %1 字节，物理地址 0x%2，路径：%3"))
                        .arg(result.data.size()).arg(result.physicalAddress, 0, 16)
                        .arg(result.usedDirectWindow
                            ? ks::i18n::sourceText(QStringLiteral("私有页表窗口"))
                            : ks::i18n::sourceText(QStringLiteral("MmCopyMemory 回退"))));
            }, Qt::QueuedConnection);
    }).detach();
}

void HvmMemoryDialog::startWrite()
{
    if (m_busy || !m_hasSnapshot || !m_editor->hasChanges())
    {
        return;
    }
    if (!ksword::hvm::isWriteAccessEnabled())
    {
        m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
            "R-1 写权限未开启：在 HVM 按钮右键菜单中开启后才能写入")));
        updateEnabledState();
        return;
    }
    const auto blocks = m_editor->diffBlocks();
    const QByteArray original = m_editor->originalBytes();
    const auto architecture = m_editor->currentArchitecture();
    const bool virtualMode = m_snapshotVirtualMode;
    const unsigned long long address = m_snapshotAddress;
    const unsigned long long directoryBase = m_snapshotDirectoryBase;
    const unsigned long processId = m_snapshotProcessId;
    qsizetype totalBytes = 0;
    for (const auto& block : blocks)
    {
        totalBytes += block.bytes.size();
    }
    if (blocks.isEmpty() || original.isEmpty() || original.size() > kMaxTransferBytes)
    {
        return;
    }

    const QString target = virtualMode
        ? (directoryBase != 0
            ? ks::i18n::sourceText(QStringLiteral("虚拟地址 0x%1（按页目录 0x%2 解析）"))
                  .arg(address, 0, 16).arg(directoryBase, 0, 16)
            : ks::i18n::sourceText(QStringLiteral("PID %1 的虚拟地址 0x%2（自动获取 CR3）"))
                  .arg(processId).arg(address, 0, 16))
        : ks::i18n::sourceText(QStringLiteral("**物理**地址 0x%1"))
              .arg(address, 0, 16);
    if (!ks::ui::confirmDestructiveAction(
            this, QStringLiteral("HvmMemoryWrite"),
            ks::i18n::sourceText(QStringLiteral("从 R-1 直接写入内存")), target,
            ks::i18n::sourceText(QStringLiteral("将写入 %1 字节，绕过页保护、只读段与内核写保护。写错地址不会有任何提示：受害的可能是内核代码、页表或另一个进程的数据，症状往往在很久之后才以看不出关联的方式出现。物理地址写入没有任何归属检查 —— 这个地址属于谁，只有你知道。"))
                .arg(totalBytes)))
    {
        return;
    }

    // LanguageManager 访问只能发生在 UI 线程；后台仅使用已翻译模板。
    const WriteMessages messages = {
        ks::i18n::sourceText(QStringLiteral("写入前读取失败，未写入任何字节。%1")),
        ks::i18n::sourceText(QStringLiteral("地址 0x%1 的原字节已变化，已停止应用修改。")),
        ks::i18n::sourceText(QStringLiteral("地址 0x%1 写入或回读验证失败。%2")),
        ks::i18n::sourceText(QStringLiteral("回读失败，目标可能已被部分修改，请重新读取。%1")),
        ks::i18n::sourceText(QStringLiteral("回读字节与修改不一致。")),
        ks::i18n::sourceText(QStringLiteral("读取长度不完整，请重新读取。"))
    };
    const unsigned long long serial = beginOperation();
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral(
        "正在核对原字节、应用修改并回读...")));
    QPointer<HvmMemoryDialog> safeThis(this);
    const auto cancelled = m_cancelled;
    std::thread([safeThis, cancelled, serial, virtualMode, address, directoryBase,
                    processId, original, blocks, totalBytes, architecture, messages]() {
        WriteOutcome outcome;
        const unsigned long length = static_cast<unsigned long>(original.size());
        const auto read = [virtualMode, directoryBase, processId](
            const unsigned long long targetAddress, const unsigned long targetLength) {
            return readTarget(virtualMode, directoryBase, processId,
                targetAddress, targetLength);
        };
        outcome.readback = read(address, length);
        if (!outcome.readback.ok || outcome.readback.data.size() != original.size())
        {
            outcome.failure = messages.preflightFailed.arg(outcome.readback.ok
                ? messages.incomplete : outcome.readback.message);
        }
        else
        {
            // 全部修改块先做预检，避免后面的冲突造成可避免的部分写入。
            for (const auto& block : blocks)
            {
                const qsizetype offset = static_cast<qsizetype>(block.address - address);
                if (block.address < address || offset < 0 ||
                    offset > original.size() || block.bytes.isEmpty() ||
                    block.bytes.size() != block.originalBytes.size() ||
                    block.bytes.size() > original.size() - offset ||
                    original.mid(offset, block.bytes.size()) != block.originalBytes ||
                    outcome.readback.data.mid(offset, block.bytes.size()) != block.originalBytes)
                {
                    outcome.failure = messages.originalConflict
                        .arg(block.address, 0, 16);
                    break;
                }
            }
            if (outcome.failure.isEmpty())
            {
                for (const auto& block : blocks)
                {
                    if (cancelled->load(std::memory_order_relaxed))
                    {
                        return;
                    }
                    // 驱动接口不提供原子 compare/write，尽量缩短二者间隔。
                    const auto current = read(block.address,
                        static_cast<unsigned long>(block.bytes.size()));
                    if (!current.ok || current.data != block.originalBytes)
                    {
                        outcome.failure = messages.originalConflict
                            .arg(block.address, 0, 16);
                        if (!current.ok)
                        {
                            outcome.failure += QLatin1Char(' ') + current.message;
                        }
                        break;
                    }
                    if (cancelled->load(std::memory_order_relaxed))
                    {
                        return;
                    }
                    outcome.writeAttempted = true;
                    const auto written = virtualMode
                        ? ksword::hvm::writeVirtual(directoryBase, block.address,
                              block.bytes, processId)
                        : ksword::hvm::writePhysical(block.address, block.bytes);
                    // 驱动报告失败也可能已有部分写入，随后回读实际状态。
                    const auto checked = read(block.address,
                        static_cast<unsigned long>(block.bytes.size()));
                    if (!written.ok || !checked.ok || checked.data != block.bytes)
                    {
                        outcome.failure = messages.verifyFailed
                            .arg(block.address, 0, 16)
                            .arg(!written.ok ? written.message
                                : !checked.ok ? checked.message : messages.mismatch);
                        break;
                    }
                }
            }
        }
        if (cancelled->load(std::memory_order_relaxed) || safeThis == nullptr)
        {
            return;
        }
        // 回读原区域，UI 只把实际读取到的字节作为新的基线。
        // 即便写入前的逐块复核已经发现变化，也刷新最新实际字节，不能展示旧预检数据。
        outcome.readback = read(address, length);
        // 按最终回读计算确认数量，覆盖失败的写调用实际部分完成、或目标随后变化的情况。
        if (outcome.readback.ok && outcome.readback.data.size() == original.size())
        {
            for (const auto& block : blocks)
            {
                if (block.address < address || block.address - address >
                    static_cast<unsigned long long>(original.size()))
                {
                    continue;
                }
                const qsizetype offset = static_cast<qsizetype>(block.address - address);
                if (block.bytes.size() > original.size() - offset)
                {
                    continue;
                }
                for (qsizetype index = 0; index < block.bytes.size(); ++index)
                {
                    if (outcome.readback.data.at(offset + index) == block.bytes.at(index))
                    {
                        ++outcome.verifiedBytes;
                    }
                }
            }
        }
        if (outcome.failure.isEmpty() && outcome.readback.ok &&
            outcome.readback.data.size() == original.size())
        {
            for (const auto& block : blocks)
            {
                const qsizetype offset = static_cast<qsizetype>(block.address - address);
                if (outcome.readback.data.mid(offset, block.bytes.size()) != block.bytes)
                {
                    outcome.failure = messages.verifyFailed
                        .arg(block.address, 0, 16).arg(messages.mismatch);
                    break;
                }
            }
            outcome.allVerified = outcome.failure.isEmpty();
        }
        if (!outcome.readback.ok || outcome.readback.data.size() != original.size())
        {
            if (outcome.writeAttempted)
            {
                outcome.failure += QLatin1Char(' ') + messages.readbackFailed
                    .arg(outcome.readback.ok ? messages.incomplete : outcome.readback.message);
            }
            outcome.allVerified = false;
        }
        if (cancelled->load(std::memory_order_relaxed) || safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, outcome, serial, address, original, totalBytes, architecture,
                virtualMode, directoryBase, processId]() {
                if (safeThis == nullptr || safeThis->m_operationSerial != serial)
                {
                    return;
                }
                if (outcome.readback.ok && outcome.readback.data.size() == original.size())
                {
                    safeThis->m_editor->setSnapshot(outcome.readback.data, address, architecture, address,
                        QStringLiteral("hvm_memory_%1_%2_%3").arg(virtualMode ? 1 : 0).arg(directoryBase).arg(processId));
                }
                else
                {
                    safeThis->invalidateSnapshot();
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(outcome.allVerified
                    ? ks::i18n::sourceText(QStringLiteral("已应用并回读确认 %1 个修改字节。"))
                        .arg(totalBytes)
                    : ks::i18n::sourceText(QStringLiteral(
                        "应用修改已停止，已回读确认 %1/%2 个修改字节。%3"))
                        .arg(outcome.verifiedBytes).arg(totalBytes)
                        .arg(outcome.failure.trimmed()));
            }, Qt::QueuedConnection);
    }).detach();
}

void HvmMemoryDialog::startTranslate()
{
    if (m_busy || !isVirtualMode())
    {
        return;
    }
    unsigned long long address = 0;
    if (!parseAddress(m_addressEdit, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    unsigned long processId = 0;
    if (!parseVirtualContext(&directoryBase, &processId))
    {
        return;
    }

    const unsigned long long serial = beginOperation();
    m_statusLabel->setText(ks::i18n::sourceText(QStringLiteral("正在翻译...")));
    QPointer<HvmMemoryDialog> safeThis(this);
    const auto cancelled = m_cancelled;
    std::thread([safeThis, cancelled, serial, address, directoryBase, processId]() {
        const ksword::hvm::HvmMemoryResult result =
            ksword::hvm::translate(directoryBase, address, processId);
        if (cancelled->load(std::memory_order_relaxed) || safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, serial]() {
                if (safeThis == nullptr || safeThis->m_operationSerial != serial)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.ok
                    ? ks::i18n::sourceText(QStringLiteral("物理地址：0x%1"))
                        .arg(result.physicalAddress, 0, 16)
                    : result.message);
            }, Qt::QueuedConnection);
    }).detach();
}
