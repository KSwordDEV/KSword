#include "KvmMemoryDialog.h"

#include "KvmControl.h"
#include "../Internationalization/LanguageManager.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <thread>

namespace
{
    // 一次传输的字节上限由驱动协议决定，UI 不能给出更大的选项。
    constexpr int kMaxTransferBytes =
        static_cast<int>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);
    // 十六进制视图每行显示的字节数。
    constexpr int kHexBytesPerLine = 16;

    // parseHexBytes：把 "41 42 43" 或 "414243" 解析成字节序列。
    // 返回 false 表示存在非法字符或奇数个十六进制位。
    bool parseHexBytes(const QString& text, QByteArray* bytesOut)
    {
        QString compact;
        compact.reserve(text.size());
        for (const QChar character : text)
        {
            if (character.isSpace())
            {
                continue;
            }
            if (!isxdigit(character.toLatin1()))
            {
                return false;
            }
            compact.append(character);
        }
        if (compact.isEmpty() || (compact.size() % 2) != 0)
        {
            return false;
        }
        bytesOut->clear();
        bytesOut->reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int value =
                compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytesOut->append(static_cast<char>(value & 0xFFu));
        }
        return true;
    }
}

KvmMemoryDialog::KvmMemoryDialog(QWidget* const parent)
    : QDialog(parent)
{
    setWindowTitle(ks::i18n::sourceText(QStringLiteral("KVM R-1 内存操作")));
    setObjectName(QStringLiteral("KvmMemoryDialog"));
    // 对话框外观由 InstallGlobalDialogTheme 安装的全局样式统一接管，
    // 这里不再单独设样式，避免和主题切换脱节。
    buildUi();
    updateEnabledState();

    // 打开时立刻问一次窗口状态：能不能绕开 Mm* 决定了这个面板的全部价值。
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmMemoryResult result =
            ksword::kvm::queryMemoryWindow();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr || safeThis->m_windowLabel == nullptr)
                {
                    return;
                }
                safeThis->m_windowLabel->setText(result.windowReady
                    ? ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：可用（读写均绕开内存管理器导出例程）"))
                    : ks::i18n::sourceText(QStringLiteral(
                        "私有页表窗口：不可用（读退化为 MmCopyMemory，写不可用）")));
            },
            Qt::QueuedConnection);
    }).detach();
}

bool KvmMemoryDialog::isVirtualMode() const
{
    return m_modeBox != nullptr && m_modeBox->currentIndex() == 1;
}

void KvmMemoryDialog::buildUi()
{
    QVBoxLayout* const rootLayout = new QVBoxLayout(this);

    m_windowLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("私有页表窗口：正在查询...")),
        this);
    m_windowLabel->setWordWrap(true);
    rootLayout->addWidget(m_windowLabel);

    QFormLayout* const formLayout = new QFormLayout();
    m_modeBox = new QComboBox(this);
    m_modeBox->addItem(ks::i18n::sourceText(QStringLiteral("物理地址")));
    m_modeBox->addItem(ks::i18n::sourceText(QStringLiteral("虚拟地址")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址类型")),
        m_modeBox);

    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setPlaceholderText(QStringLiteral("0x1000"));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("地址（十六进制）")),
        m_addressEdit);

    m_directoryBaseEdit = new QLineEdit(this);
    m_directoryBaseEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("留空表示当前进程页表")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("页目录基址（CR3）")),
        m_directoryBaseEdit);

    m_lengthBox = new QSpinBox(this);
    m_lengthBox->setRange(1, kMaxTransferBytes);
    m_lengthBox->setValue(64);
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("读取长度（字节）")),
        m_lengthBox);

    m_writeEdit = new QLineEdit(this);
    m_writeEdit->setPlaceholderText(
        ks::i18n::sourceText(QStringLiteral("要写入的十六进制字节，例如 90 90 90")));
    formLayout->addRow(
        ks::i18n::sourceText(QStringLiteral("写入内容")),
        m_writeEdit);
    rootLayout->addLayout(formLayout);

    m_dataView = new QPlainTextEdit(this);
    m_dataView->setReadOnly(true);
    m_dataView->setFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont));
    m_dataView->setMinimumHeight(220);
    rootLayout->addWidget(m_dataView, 1);

    QGridLayout* const buttonLayout = new QGridLayout();
    m_readButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("读取")), this);
    m_writeButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("写入")), this);
    m_translateButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("翻译为物理地址")), this);
    buttonLayout->addWidget(m_readButton, 0, 0);
    buttonLayout->addWidget(m_writeButton, 0, 1);
    buttonLayout->addWidget(m_translateButton, 0, 2);
    rootLayout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(QString(), this);
    m_statusLabel->setWordWrap(true);
    rootLayout->addWidget(m_statusLabel);

    connect(m_modeBox, &QComboBox::currentIndexChanged, this, [this](int) {
        updateEnabledState();
    });
    connect(m_readButton, &QPushButton::clicked, this, [this]() {
        startRead();
    });
    connect(m_writeButton, &QPushButton::clicked, this, [this]() {
        startWrite();
    });
    connect(m_translateButton, &QPushButton::clicked, this, [this]() {
        startTranslate();
    });
    resize(640, 520);
}

void KvmMemoryDialog::updateEnabledState()
{
    const bool virtualMode = isVirtualMode();
    const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
    if (m_directoryBaseEdit != nullptr)
    {
        // 页目录基址只对虚拟地址模式有意义。
        m_directoryBaseEdit->setEnabled(virtualMode && !m_busy);
    }
    if (m_translateButton != nullptr)
    {
        m_translateButton->setEnabled(virtualMode && !m_busy);
    }
    if (m_readButton != nullptr)
    {
        m_readButton->setEnabled(!m_busy);
    }
    if (m_writeButton != nullptr)
    {
        m_writeButton->setEnabled(writeAllowed && !m_busy);
        m_writeButton->setToolTip(writeAllowed
            ? ks::i18n::sourceText(QStringLiteral("按十六进制字节写入目标地址"))
            : ks::i18n::sourceText(QStringLiteral(
                "R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能写入")));
    }
    if (m_writeEdit != nullptr)
    {
        m_writeEdit->setEnabled(writeAllowed && !m_busy);
    }
}

void KvmMemoryDialog::setBusy(const bool busy)
{
    m_busy = busy;
    updateEnabledState();
}

bool KvmMemoryDialog::parseAddress(
    const QLineEdit* const field,
    unsigned long long* const valueOut,
    const QString& fieldName)
{
    QString text = field != nullptr ? field->text().trimmed() : QString();
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
    }
    bool converted = false;
    const unsigned long long value = text.toULongLong(&converted, 16);
    if (!converted)
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("%1 不是合法的十六进制数。"))
                .arg(fieldName));
        return false;
    }
    *valueOut = value;
    return true;
}

void KvmMemoryDialog::showHexDump(
    const unsigned long long baseAddress,
    const QByteArray& data)
{
    QStringList lines;
    for (int offset = 0; offset < data.size(); offset += kHexBytesPerLine)
    {
        const int lineLength =
            qMin(kHexBytesPerLine, data.size() - offset);
        QString hexPart;
        QString asciiPart;
        for (int index = 0; index < lineLength; ++index)
        {
            const unsigned char value =
                static_cast<unsigned char>(data.at(offset + index));
            hexPart += QStringLiteral("%1 ")
                .arg(value, 2, 16, QLatin1Char('0')).toUpper();
            // 不可打印字节统一显示为点，避免控制字符破坏对齐。
            asciiPart += (value >= 0x20 && value < 0x7F)
                ? QChar(static_cast<char>(value))
                : QChar(QLatin1Char('.'));
        }
        lines << QStringLiteral("%1  %2 %3")
            .arg(baseAddress + static_cast<unsigned long long>(offset),
                16, 16, QLatin1Char('0'))
            .arg(hexPart, -(kHexBytesPerLine * 3))
            .arg(asciiPart);
    }
    m_dataView->setPlainText(lines.join(QStringLiteral("\n")));
}

void KvmMemoryDialog::startRead()
{
    unsigned long long address = 0;
    if (!parseAddress(m_addressEdit, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    const bool virtualMode = isVirtualMode();
    if (virtualMode && !m_directoryBaseEdit->text().trimmed().isEmpty() &&
        !parseAddress(m_directoryBaseEdit, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }
    const unsigned long length =
        static_cast<unsigned long>(m_lengthBox->value());

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在读取...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, virtualMode, address, directoryBase, length]() {
        const ksword::kvm::KvmMemoryResult result = virtualMode
            ? ksword::kvm::readVirtual(directoryBase, address, length)
            : ksword::kvm::readPhysical(address, length);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, address]() {
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
                safeThis->showHexDump(address, result.data);
                // 走没走私有窗口，是这次读取可信度的一部分，必须写在状态里。
                safeThis->m_statusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "已读取 %1 字节，物理地址 0x%2，路径：%3"))
                        .arg(result.data.size())
                        .arg(result.physicalAddress, 0, 16)
                        .arg(result.usedDirectWindow
                            ? ks::i18n::sourceText(QStringLiteral("私有页表窗口"))
                            : ks::i18n::sourceText(QStringLiteral("MmCopyMemory 回退"))));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMemoryDialog::startWrite()
{
    unsigned long long address = 0;
    if (!parseAddress(m_addressEdit, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    const bool virtualMode = isVirtualMode();
    if (virtualMode && !m_directoryBaseEdit->text().trimmed().isEmpty() &&
        !parseAddress(m_directoryBaseEdit, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }
    QByteArray payload;
    if (!parseHexBytes(m_writeEdit->text(), &payload))
    {
        m_statusLabel->setText(ks::i18n::sourceText(
            QStringLiteral("写入内容必须是成对的十六进制字节。")));
        return;
    }
    if (payload.size() > kMaxTransferBytes)
    {
        m_statusLabel->setText(
            ks::i18n::sourceText(QStringLiteral("单次写入最多 %1 字节。"))
                .arg(kMaxTransferBytes));
        return;
    }

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在写入...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, virtualMode, address, directoryBase, payload]() {
        const ksword::kvm::KvmMemoryResult result = virtualMode
            ? ksword::kvm::writeVirtual(directoryBase, address, payload)
            : ksword::kvm::writePhysical(address, payload);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result, size = payload.size()]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->m_statusLabel->setText(result.ok
                    ? ks::i18n::sourceText(
                        QStringLiteral("已写入 %1 字节，物理地址 0x%2。"))
                        .arg(size)
                        .arg(result.physicalAddress, 0, 16)
                    : result.message);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmMemoryDialog::startTranslate()
{
    unsigned long long address = 0;
    if (!parseAddress(m_addressEdit, &address,
            ks::i18n::sourceText(QStringLiteral("地址"))))
    {
        return;
    }
    unsigned long long directoryBase = 0;
    if (!m_directoryBaseEdit->text().trimmed().isEmpty() &&
        !parseAddress(m_directoryBaseEdit, &directoryBase,
            ks::i18n::sourceText(QStringLiteral("页目录基址"))))
    {
        return;
    }

    setBusy(true);
    m_statusLabel->setText(
        ks::i18n::sourceText(QStringLiteral("正在翻译...")));
    QPointer<KvmMemoryDialog> safeThis(this);
    std::thread([safeThis, address, directoryBase]() {
        const ksword::kvm::KvmMemoryResult result =
            ksword::kvm::translate(directoryBase, address);
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
                safeThis->m_statusLabel->setText(result.ok
                    ? ks::i18n::sourceText(QStringLiteral("物理地址：0x%1"))
                        .arg(result.physicalAddress, 0, 16)
                    : result.message);
            },
            Qt::QueuedConnection);
    }).detach();
}
