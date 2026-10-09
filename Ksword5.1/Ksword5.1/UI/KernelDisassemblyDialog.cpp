#include "KernelDisassemblyDialog.h"
#include "MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "MemoryWorkbench/WorkbenchDisasmView.h"
#include "UI_All.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"
/* 统一入口：这一页不需要知道 GPA、EPT 叶或 ruleId。 */
#include "HvmWatchDialog.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#if __has_include(<Zydis.h>)
#define KSWORD_HAS_ZYDIS 1
#include <Zydis.h>
#elif __has_include(<Zydis/Zydis.h>)
#define KSWORD_HAS_ZYDIS 1
#include <Zydis/Zydis.h>
#else
#define KSWORD_HAS_ZYDIS 0
#endif

namespace
{
    QMessageBox::StandardButton ownedMessageBox(QWidget* owner, QMessageBox::Icon icon,
        const QString& title, const QString& text,
        QMessageBox::StandardButtons buttons = QMessageBox::Ok,
        QMessageBox::StandardButton defaultButton = QMessageBox::NoButton)
    {
        // Modal event loops can retire an evidence window. QObject must never
        // delete a dialog on the caller's stack as part of parent destruction.
        QPointer<QMessageBox> box = new QMessageBox(icon, title, text, buttons, owner);
        if (defaultButton != QMessageBox::NoButton) box->setDefaultButton(defaultButton);
        const auto result = static_cast<QMessageBox::StandardButton>(box->exec());
        if (box) delete box.data();
        return result;
    }

    QString bytesText(const QByteArray& bytes)
    {
        QStringList parts;
        parts.reserve(bytes.size());
        for (const char value : bytes)
        {
            parts.push_back(
                QStringLiteral("%1")
                    .arg(
                        static_cast<unsigned char>(value),
                        2,
                        16,
                        QChar('0'))
                    .toUpper());
        }
        return parts.join(QChar(' '));
    }

    QString addressText(const std::uint64_t address)
    {
        return QStringLiteral("0x%1")
            .arg(
                static_cast<qulonglong>(address),
                16,
                16,
                QChar('0'))
            .toUpper();
    }

    std::vector<std::uint8_t> byteVector(
        const QByteArray& bytes)
    {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(
            bytes.constData());
        return std::vector<std::uint8_t>(
            begin,
            begin + static_cast<std::size_t>(bytes.size()));
    }

    bool bytePrefixMatches(
        const std::vector<std::uint8_t>& bytes,
        const QByteArray& expected)
    {
        if (bytes.size()
            < static_cast<std::size_t>(expected.size()))
        {
            return false;
        }
        return std::equal(
            expected.cbegin(),
            expected.cend(),
            bytes.cbegin(),
            [](const char left, const std::uint8_t right)
            {
                return static_cast<std::uint8_t>(
                    static_cast<unsigned char>(left)) == right;
            });
    }

    QString mutationResponseText(
        const QString& stage,
        const ksword::ark::MutationResponseResult& response)
    {
        return QStringLiteral(
            "%1：tx=%2，status=%3，risk=0x%4，"
            "NTSTATUS=0x%5，后端=%6")
            .arg(stage)
            .arg(
                static_cast<qulonglong>(
                    response.transactionId))
            .arg(response.status)
            .arg(response.riskFlags, 8, 16, QChar('0'))
            .arg(
                static_cast<unsigned long>(
                    response.lastStatus),
                8,
                16,
                QChar('0'))
            .arg(QString::fromStdString(response.io.message));
    }

    ks::ui::DisassemblyRow fallbackDecodeOne(
        const QByteArray& bytes,
        std::uint32_t offset,
        std::uint64_t baseAddress,
        ks::ui::DisassemblyArchitecture architecture);

    bool tryZydis(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const ks::ui::DisassemblyArchitecture architecture,
        const std::uint32_t maximumInstructions,
        ks::ui::DisassemblyResult& resultOut)
    {
#if KSWORD_HAS_ZYDIS
        ks::ui::DisassemblyResult result;
        result.backendName = QStringLiteral(
            "Zydis v4（编译期固定依赖）");
        std::uint32_t offset = 0U;
        while (offset < static_cast<std::uint32_t>(bytes.size())
            && result.rows.size()
                < static_cast<qsizetype>(maximumInstructions))
        {
            ZydisDisassembledInstruction instruction{};
            const ZydisMachineMode mode =
                architecture
                    == ks::ui::DisassemblyArchitecture::X64
                ? ZYDIS_MACHINE_MODE_LONG_64
                : ZYDIS_MACHINE_MODE_LEGACY_32;
            const ZyanStatus status = ZydisDisassembleIntel(
                mode,
                baseAddress + offset,
                bytes.constData() + static_cast<qsizetype>(offset),
                static_cast<ZyanUSize>(
                    bytes.size() - static_cast<qsizetype>(offset)),
                &instruction);
            if (!ZYAN_SUCCESS(status)
                || instruction.info.length == 0U)
            {
                break;
            }
            const std::uint32_t length =
                instruction.info.length;
            if (length
                > static_cast<std::uint32_t>(bytes.size()) - offset)
            {
                break;
            }
            const QString text =
                QString::fromLatin1(instruction.text).trimmed();
            const qsizetype separator =
                text.indexOf(QChar(' '));
            ks::ui::DisassemblyRow row;
            row.address = baseAddress + offset;
            row.byteOffset = offset;
            row.bytes = bytes.mid(
                static_cast<qsizetype>(offset),
                static_cast<qsizetype>(length));
            if (separator < 0)
            {
                row.mnemonic = text;
            }
            else
            {
                row.mnemonic = text.left(separator);
                row.operands = text.mid(separator + 1).trimmed();
            }
            row.decoded = true;
            result.rows.push_back(std::move(row));
            offset += length;
        }
        result.complete =
            offset >= static_cast<std::uint32_t>(bytes.size());
        if (!result.rows.isEmpty())
        {
            if (!result.complete)
            {
                result.diagnosticText = QStringLiteral(
                    "Zydis 在快照尾部遇到截断或无效指令；"
                    "剩余字节将由有界降级解码器保留。");
                while (offset
                        < static_cast<std::uint32_t>(bytes.size())
                    && result.rows.size()
                        < static_cast<qsizetype>(
                            maximumInstructions))
                {
                    ks::ui::DisassemblyRow row =
                        fallbackDecodeOne(
                            bytes,
                            offset,
                            baseAddress,
                            architecture);
                    const std::uint32_t consumed = std::max(
                        1U,
                        static_cast<std::uint32_t>(
                            row.bytes.size()));
                    result.rows.push_back(std::move(row));
                    offset += consumed;
                }
                result.complete =
                    offset
                    >= static_cast<std::uint32_t>(bytes.size());
            }
            resultOut = std::move(result);
            return true;
        }
#else
        Q_UNUSED(bytes);
        Q_UNUSED(baseAddress);
        Q_UNUSED(architecture);
        Q_UNUSED(maximumInstructions);
        Q_UNUSED(resultOut);
#endif
        return false;
    }

    QString registerName(
        const unsigned int registerIndex,
        const bool wide)
    {
        static constexpr std::array<const char*, 16> kRegisters64{
            "rax", "rcx", "rdx", "rbx",
            "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15"
        };
        static constexpr std::array<const char*, 16> kRegisters32{
            "eax", "ecx", "edx", "ebx",
            "esp", "ebp", "esi", "edi",
            "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d"
        };
        const unsigned int bounded = registerIndex & 0x0FU;
        return QString::fromLatin1(
            wide ? kRegisters64[bounded] : kRegisters32[bounded]);
    }

    std::uint32_t modRmLength(
        const QByteArray& bytes,
        const std::uint32_t offset,
        const bool address64)
    {
        if (offset >= static_cast<std::uint32_t>(bytes.size()))
        {
            return 0U;
        }
        const unsigned char modRm =
            static_cast<unsigned char>(bytes.at(offset));
        const unsigned int mod = modRm >> 6U;
        const unsigned int rm = modRm & 7U;
        std::uint32_t length = 1U;
        if (mod != 3U && rm == 4U)
        {
            if (offset + length
                >= static_cast<std::uint32_t>(bytes.size()))
            {
                return 0U;
            }
            const unsigned char sib =
                static_cast<unsigned char>(
                    bytes.at(offset + length));
            ++length;
            if (mod == 0U && (sib & 7U) == 5U)
            {
                length += 4U;
            }
        }
        if (mod == 0U && rm == 5U)
        {
            length += address64 ? 4U : 4U;
        }
        else if (mod == 1U)
        {
            ++length;
        }
        else if (mod == 2U)
        {
            length += 4U;
        }
        return offset + length
                <= static_cast<std::uint32_t>(bytes.size())
            ? length
            : 0U;
    }

    ks::ui::DisassemblyRow fallbackDecodeOne(
        const QByteArray& bytes,
        const std::uint32_t offset,
        const std::uint64_t baseAddress,
        const ks::ui::DisassemblyArchitecture architecture)
    {
        ks::ui::DisassemblyRow row;
        row.address = baseAddress + offset;
        row.byteOffset = offset;
        const std::uint32_t remaining =
            static_cast<std::uint32_t>(bytes.size()) - offset;
        const unsigned char first =
            static_cast<unsigned char>(bytes.at(offset));
        std::uint32_t cursor = offset;
        bool rexWide = false;
        unsigned int rexBits = 0U;
        if (architecture == ks::ui::DisassemblyArchitecture::X64
            && first >= 0x40U && first <= 0x4FU)
        {
            rexBits = first & 0x0FU;
            rexWide = (rexBits & 0x08U) != 0U;
            ++cursor;
            if (cursor >= static_cast<std::uint32_t>(bytes.size()))
            {
                row.bytes = bytes.mid(offset, 1);
                row.mnemonic = QStringLiteral("db");
                row.operands = QStringLiteral("0x%1")
                    .arg(first, 2, 16, QChar('0'))
                    .toUpper();
                return row;
            }
        }
        const unsigned char opcode =
            static_cast<unsigned char>(bytes.at(cursor));
        const std::uint32_t prefixBytes = cursor - offset;
        auto finish = [&row, &bytes, offset](
            const std::uint32_t length,
            const QString& mnemonic,
            const QString& operands = QString())
        {
            row.bytes = bytes.mid(
                static_cast<qsizetype>(offset),
                static_cast<qsizetype>(length));
            row.mnemonic = mnemonic;
            row.operands = operands;
            row.decoded = true;
        };
        if (opcode == 0x90U)
        {
            finish(prefixBytes + 1U, QStringLiteral("nop"));
            return row;
        }
        if (opcode == 0xCCU)
        {
            finish(prefixBytes + 1U, QStringLiteral("int3"));
            return row;
        }
        if (opcode == 0xC3U)
        {
            finish(prefixBytes + 1U, QStringLiteral("ret"));
            return row;
        }
        if (opcode == 0xF4U)
        {
            finish(prefixBytes + 1U, QStringLiteral("hlt"));
            return row;
        }
        if (opcode == 0xFAU || opcode == 0xFBU)
        {
            finish(
                prefixBytes + 1U,
                opcode == 0xFAU
                    ? QStringLiteral("cli")
                    : QStringLiteral("sti"));
            return row;
        }
        if (opcode >= 0x50U && opcode <= 0x5FU)
        {
            const bool pop = opcode >= 0x58U;
            const unsigned int index =
                (opcode & 7U)
                + ((rexBits & 1U) != 0U ? 8U : 0U);
            finish(
                prefixBytes + 1U,
                pop ? QStringLiteral("pop") : QStringLiteral("push"),
                registerName(
                    index,
                    architecture
                        == ks::ui::DisassemblyArchitecture::X64));
            return row;
        }
        if ((opcode == 0xE8U || opcode == 0xE9U)
            && remaining >= prefixBytes + 5U)
        {
            std::int32_t displacement = 0;
            std::memcpy(
                &displacement,
                bytes.constData()
                    + static_cast<qsizetype>(cursor + 1U),
                sizeof(displacement));
            const std::uint32_t length = prefixBytes + 5U;
            finish(
                length,
                opcode == 0xE8U
                    ? QStringLiteral("call")
                    : QStringLiteral("jmp"),
                addressText(
                    row.address + length + displacement));
            return row;
        }
        if (opcode == 0xEBU
            && remaining >= prefixBytes + 2U)
        {
            const auto displacement = static_cast<std::int8_t>(
                bytes.at(static_cast<qsizetype>(cursor + 1U)));
            const std::uint32_t length = prefixBytes + 2U;
            finish(
                length,
                QStringLiteral("jmp"),
                addressText(
                    row.address + length + displacement));
            return row;
        }
        static constexpr std::array<const char*, 16> kConditions{
            "jo", "jno", "jb", "jae",
            "je", "jne", "jbe", "ja",
            "js", "jns", "jp", "jnp",
            "jl", "jge", "jle", "jg"
        };
        if (opcode >= 0x70U
            && opcode <= 0x7FU
            && remaining >= prefixBytes + 2U)
        {
            const auto displacement = static_cast<std::int8_t>(
                bytes.at(static_cast<qsizetype>(cursor + 1U)));
            const std::uint32_t length = prefixBytes + 2U;
            finish(
                length,
                QString::fromLatin1(
                    kConditions[opcode - 0x70U]),
                addressText(
                    row.address + length + displacement));
            return row;
        }
        if (opcode == 0x0FU
            && remaining >= prefixBytes + 2U)
        {
            const unsigned char second =
                static_cast<unsigned char>(
                    bytes.at(static_cast<qsizetype>(cursor + 1U)));
            if (second == 0x05U
                || second == 0x07U
                || second == 0x0BU)
            {
                finish(
                    prefixBytes + 2U,
                    second == 0x05U
                        ? QStringLiteral("syscall")
                        : second == 0x07U
                            ? QStringLiteral("sysret")
                            : QStringLiteral("ud2"));
                return row;
            }
            if (second >= 0x80U
                && second <= 0x8FU
                && remaining >= prefixBytes + 6U)
            {
                std::int32_t displacement = 0;
                std::memcpy(
                    &displacement,
                    bytes.constData()
                        + static_cast<qsizetype>(cursor + 2U),
                    sizeof(displacement));
                const std::uint32_t length = prefixBytes + 6U;
                finish(
                    length,
                    QString::fromLatin1(
                        kConditions[second - 0x80U]),
                    addressText(
                        row.address + length + displacement));
                return row;
            }
        }
        if (opcode >= 0xB8U
            && opcode <= 0xBFU)
        {
            const std::uint32_t immediateBytes =
                rexWide ? 8U : 4U;
            if (remaining >= prefixBytes + 1U + immediateBytes)
            {
                std::uint64_t immediate = 0U;
                std::memcpy(
                    &immediate,
                    bytes.constData()
                        + static_cast<qsizetype>(cursor + 1U),
                    immediateBytes);
                const unsigned int index =
                    (opcode & 7U)
                    + ((rexBits & 1U) != 0U ? 8U : 0U);
                finish(
                    prefixBytes + 1U + immediateBytes,
                    QStringLiteral("mov"),
                    QStringLiteral("%1, 0x%2")
                        .arg(registerName(index, rexWide))
                        .arg(
                            static_cast<qulonglong>(immediate),
                            0,
                            16)
                        .toUpper());
                return row;
            }
        }
        const bool hasModRm =
            opcode == 0x89U || opcode == 0x8BU
            || opcode == 0x8DU || opcode == 0x31U
            || opcode == 0x33U || opcode == 0x85U
            || opcode == 0x81U || opcode == 0x83U
            || opcode == 0xFFU;
        if (hasModRm)
        {
            const std::uint32_t modRmBytes =
                modRmLength(
                    bytes,
                    cursor + 1U,
                    architecture
                        == ks::ui::DisassemblyArchitecture::X64);
            std::uint32_t immediateBytes = 0U;
            if (opcode == 0x81U)
            {
                immediateBytes = 4U;
            }
            else if (opcode == 0x83U)
            {
                immediateBytes = 1U;
            }
            const std::uint32_t length =
                prefixBytes + 1U + modRmBytes + immediateBytes;
            if (modRmBytes != 0U && remaining >= length)
            {
                const unsigned char modRm =
                    static_cast<unsigned char>(
                        bytes.at(static_cast<qsizetype>(
                            cursor + 1U)));
                const unsigned int extension =
                    (modRm >> 3U) & 7U;
                QString mnemonic;
                if (opcode == 0x89U || opcode == 0x8BU)
                {
                    mnemonic = QStringLiteral("mov");
                }
                else if (opcode == 0x8DU)
                {
                    mnemonic = QStringLiteral("lea");
                }
                else if (opcode == 0x31U || opcode == 0x33U)
                {
                    mnemonic = QStringLiteral("xor");
                }
                else if (opcode == 0x85U)
                {
                    mnemonic = QStringLiteral("test");
                }
                else if (opcode == 0xFFU)
                {
                    mnemonic = extension == 2U
                        ? QStringLiteral("call")
                        : extension == 4U
                            ? QStringLiteral("jmp")
                            : extension == 6U
                                ? QStringLiteral("push")
                                : QStringLiteral("ff-group");
                }
                else
                {
                    static constexpr std::array<
                        const char*, 8> kGroupOne{
                        "add", "or", "adc", "sbb",
                        "and", "sub", "xor", "cmp"
                    };
                    mnemonic = QString::fromLatin1(
                        kGroupOne[extension]);
                }
                finish(
                    length,
                    mnemonic,
                    QStringLiteral("<ModR/M %1>")
                        .arg(
                            modRm,
                            2,
                            16,
                            QChar('0'))
                        .toUpper());
                return row;
            }
        }
        row.bytes = bytes.mid(
            static_cast<qsizetype>(offset),
            1);
        row.mnemonic = QStringLiteral("db");
        row.operands = QStringLiteral("0x%1")
            .arg(first, 2, 16, QChar('0'))
            .toUpper();
        row.decoded = false;
        return row;
    }
}

namespace ks::ui
{
    DisassemblyResult InstructionDecoder::decode(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const DisassemblyArchitecture architecture,
        const std::uint32_t maximumInstructions)
    {
        DisassemblyResult result;
        if (bytes.isEmpty())
        {
            result.backendName = QStringLiteral("无输入");
            result.diagnosticText =
                QStringLiteral("没有可解码的字节。");
            return result;
        }
        if (baseAddress
            > std::numeric_limits<std::uint64_t>::max()
                - static_cast<std::uint64_t>(
                    bytes.size() - 1))
        {
            result.backendName =
                QStringLiteral("输入校验");
            result.diagnosticText =
                QStringLiteral("指令快照地址范围发生 64 位溢出。");
            return result;
        }
        const std::uint32_t boundedMaximum =
            std::clamp(maximumInstructions, 1U, 65536U);
        if (tryZydis(
                bytes,
                baseAddress,
                architecture,
                boundedMaximum,
                result))
        {
            return result;
        }
        result.backendName =
            QStringLiteral("内置 x86/x64 有界解码器");
        result.diagnosticText = QStringLiteral(
            "编译时未启用 Zydis v4.1.1，或输入首条指令无效；"
            "常见控制流、序言、尾声和 ModR/M 指令已解码，"
            "未知指令以 db 保留原始字节，不猜测语义。");
        std::uint32_t offset = 0U;
        while (offset < static_cast<std::uint32_t>(bytes.size())
            && result.rows.size()
                < static_cast<qsizetype>(boundedMaximum))
        {
            DisassemblyRow row = fallbackDecodeOne(
                bytes,
                offset,
                baseAddress,
                architecture);
            const std::uint32_t consumed = std::max(
                1U,
                static_cast<std::uint32_t>(row.bytes.size()));
            result.rows.push_back(std::move(row));
            offset += consumed;
        }
        result.complete =
            offset >= static_cast<std::uint32_t>(bytes.size());
        return result;
    }

    KernelDisassemblyDialog::KernelDisassemblyDialog(
        QWidget* parent)
        : QDialog(parent)
    {
        setWindowTitle(QStringLiteral("指令视图"));
        applyResponsiveWindowGeometry(this, parent, QSize(980, 640), QSize(520, 360));
        auto* layout = new QVBoxLayout(this);
        m_sourceLabel = new QLabel(this);
        m_sourceLabel->setWordWrap(true);
        layout->addWidget(m_sourceLabel);
        m_backendLabel = new QLabel(this);
        m_backendLabel->setWordWrap(true);
        layout->addWidget(m_backendLabel);
        m_mutationRiskLabel = new QLabel(this);
        m_mutationRiskLabel->setWordWrap(true);
        m_mutationRiskLabel->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        // 走语义色 token：写死的 #b3261e 在深色主题下对比度不够，且不跟随自定义强调色。
        m_mutationRiskLabel->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:6px;"
            "padding:8px;color:%1;font-weight:600;}")
            .arg(KswordTheme::ErrorHex()));
        m_mutationRiskLabel->hide();
        layout->addWidget(m_mutationRiskLabel);
        m_mutationStatusLabel = new QLabel(this);
        m_mutationStatusLabel->setWordWrap(true);
        m_mutationStatusLabel->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        m_mutationStatusLabel->hide();
        layout->addWidget(m_mutationStatusLabel);
        m_editor = new SnapshotWorkbenchWidget(this);
        m_editor->setEditable(false);
        layout->addWidget(m_editor, 1);
        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Close,
            this);
        layout->addWidget(buttons);
        connect(
            buttons,
            &QDialogButtonBox::rejected,
            this,
            &QDialog::reject);
        connect(
            this,
            &KernelDisassemblyDialog::requestModifyBytes,
            this,
            [this](
                const std::uint64_t address,
                const QByteArray& originalBytes)
            {
                if (m_kernelMutationEnabled)
                {
                    executeKernelMutation(
                        address,
                        originalBytes);
                }
            });
        connect(m_editor->disassemblyView(), &WorkbenchDisasmView::architectureChanged,
            this, [this](bool x64) {
                ++m_snapshotRevision;
                m_architecture = x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86;
            });
        connect(m_editor, &SnapshotWorkbenchWidget::instructionContextMenuAboutToShow,
            this, [this](QMenu* menu, std::uint64_t, bool valid) {
                const auto selection = valid ? selectedByteRange() : std::nullopt;
                if (!selection) return;
                // All owner actions capture a value snapshot before the menu's
                // nested event loop. No table row index survives a refresh.
                const auto revision = m_snapshotRevision;
                const auto architecture = m_editor->currentArchitecture();
                const auto stillCurrent = [this, selection, revision, architecture]() {
                    if (revision != m_snapshotRevision || architecture != m_editor->currentArchitecture()
                        || selection->address < m_baseAddress) return false;
                    const auto offset = selection->address - m_baseAddress;
                    return offset <= static_cast<std::uint64_t>(m_originalBytes.size())
                        && m_originalBytes.mid(static_cast<qsizetype>(offset), selection->originalBytes.size())
                            == selection->originalBytes;
                };
                menu->addSeparator();
                auto* watchExecute = menu->addAction(QStringLiteral("HVM 监视：下一次执行到这里"));
                watchExecute->setToolTip(QStringLiteral("装一条首次访问监视，等下一次有人执行这一页时记下现场。EPT 是页粒度，所以实际监视的是这条指令所在的整个 4 KiB 页。"));
                connect(watchExecute, &QAction::triggered, this, [this, selection, stillCurrent]() {
                    if (!stillCurrent()) return;
                    HvmWatchRequest request;
                    request.virtualAddress = true;
                    request.address = selection->address;
                    request.length = selection->originalBytes.isEmpty()
                        ? 1U : static_cast<quint64>(selection->originalBytes.size());
                    request.access = KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
                    request.label = QStringLiteral("%1 处的指令").arg(addressText(selection->address));
                    openHvmWatch(this, request);
                });
                if (m_kernelMutationEnabled)
                {
                    menu->addSeparator();
                    auto* mutationMenu = menu->addMenu(QStringLiteral("字节事务"));
                    auto* modify = mutationMenu->addAction(QStringLiteral("修改所选字节…"));
                    connect(modify, &QAction::triggered, this, [this, selection, stillCurrent]() {
                        if (!m_kernelMutationEnabled || !stillCurrent()) return;
                        emit requestModifyBytes(selection->address, selection->originalBytes);
                    });
                }
            });
    }

    void KernelDisassemblyDialog::openKernelAddress(
        QWidget* parent,
        const std::uint64_t address,
        const QString& sourceDescription,
        const std::uint32_t byteCount)
    {
        if (address == 0U || byteCount == 0U)
        {
            ownedMessageBox(
                parent, QMessageBox::Warning,
                QStringLiteral("指令视图"),
                QStringLiteral("目标内核地址或读取长度无效。"));
            return;
        }
        const std::uint32_t boundedBytes = std::min<std::uint32_t>(
            byteCount,
            KSWORD_ARK_MEMORY_READ_MAX_BYTES);
        const ksword::ark::DriverClient client;
        const ksword::ark::VirtualMemoryReadResult read =
            client.readVirtualMemory(
                0U,
                address,
                boundedBytes,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
        if (!read.io.ok
            || read.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK
            || read.copyStatus != 0
            || read.bytesRead != boundedBytes
            || read.data.size() < static_cast<std::size_t>(boundedBytes))
        {
            ownedMessageBox(
                parent, QMessageBox::Warning,
                QStringLiteral("指令视图"),
                QStringLiteral(
                    "R0 内核字节读取失败。\n"
                    "Win32=%1，NTSTATUS=0x%2，读取=%3/%4。\n%5")
                    .arg(read.io.win32Error)
                    .arg(
                        static_cast<unsigned long>(
                            read.copyStatus),
                        8,
                        16,
                        QChar('0'))
                    .arg(read.bytesRead)
                    .arg(boundedBytes)
                    .arg(QString::fromStdString(
                        read.io.message)));
            return;
        }
        const qsizetype snapshotBytes = static_cast<qsizetype>(boundedBytes);
        const QByteArray snapshot(
            reinterpret_cast<const char*>(read.data.data()),
            snapshotBytes);
        QPointer<KernelDisassemblyDialog> dialog = new KernelDisassemblyDialog(parent);
        dialog->setSnapshot(
            snapshot,
            address,
            DisassemblyArchitecture::X64,
            sourceDescription);
        if (!dialog) return;
        dialog->setKernelMutationEnabled(true);
        dialog->exec();
        if (dialog) delete dialog.data();
    }

    void KernelDisassemblyDialog::setSnapshot(
        const QByteArray& bytes,
        const std::uint64_t baseAddress,
        const DisassemblyArchitecture architecture,
        const QString& sourceDescription)
    {
        m_originalBytes = bytes;
        m_sourceDescription = sourceDescription;
        ++m_snapshotRevision;
        m_baseAddress = baseAddress;
        m_architecture = architecture;
        m_sourceLabel->setText(
            QStringLiteral(
                "证据源：%1\n基址：%2；架构：%3；快照：%4 字节。"
                "本窗口只解码传入快照；是否允许事务修改由当前证据源策略决定。")
                .arg(sourceDescription)
                .arg(addressText(baseAddress))
                .arg(
                    architecture == DisassemblyArchitecture::X64
                        ? QStringLiteral("x64")
                        : QStringLiteral("x86"))
                .arg(bytes.size()));
        rebuildRows();
    }

    void KernelDisassemblyDialog::setKernelMutationEnabled(
        const bool enabled)
    {
        if (m_kernelMutationEnabled != enabled) ++m_snapshotRevision;
        m_kernelMutationEnabled = enabled;
        m_mutationRiskLabel->setVisible(enabled);
        m_mutationStatusLabel->setVisible(enabled);
        if (enabled)
        {
            m_mutationRiskLabel->setText(QStringLiteral(
                "风险：此入口可通过 R0 事务修改当前指令对应的内核虚拟字节。"
                "目标可能是正在执行的代码或关键内核数据；错误修改可能立即导致"
                "权限边界失效、数据损坏、系统挂起或蓝屏。"
                "1–64 字节活体内核补丁不是硬件原子操作，其他 CPU 仍可能"
                "在写入过程中并发执行或修改目标。"
                "PREPARE、dry-run、FORCE+UI_CONFIRMED、写后校验、回滚和审计。"
                "在指令行上右键可进入“字节事务”二级菜单。"));
            m_mutationRiskLabel->setToolTip(QStringLiteral(
                "在指令行上右键，进入“字节事务”二级菜单。"));
            m_mutationStatusLabel->setText(
                QStringLiteral(
                    "事务后端：尚未执行；等待选择一条指令。"
                    "每次写入均要求显式危险确认。"));
        }
    }

    QByteArray KernelDisassemblyDialog::originalBytes() const
    {
        return m_originalBytes;
    }

    std::uint64_t KernelDisassemblyDialog::baseAddress() const
    {
        return m_baseAddress;
    }

    std::optional<DisassemblySelection>
    KernelDisassemblyDialog::selectedByteRange() const
    {
        return m_editor == nullptr ? std::nullopt : m_editor->selectedInstruction();
    }

    void KernelDisassemblyDialog::rebuildRows()
    {
        const DisassemblyResult result =
            InstructionDecoder::decode(
                m_originalBytes,
                m_baseAddress,
                m_architecture);
        m_backendLabel->setText(
            QStringLiteral("解码后端：%1%2")
                .arg(result.backendName)
                .arg(
                    result.diagnosticText.isEmpty()
                        ? QString()
                        : QStringLiteral("\n%1")
                            .arg(result.diagnosticText)));
        m_editor->setSnapshot(m_originalBytes, m_baseAddress, m_architecture, m_baseAddress,
            m_sourceDescription);
        m_editor->showDisassemblyAt(m_baseAddress);
    }

    void KernelDisassemblyDialog::executeKernelMutation(
        const std::uint64_t address,
        QByteArray originalBytes)
    {
        if (!m_kernelMutationEnabled
            || originalBytes.isEmpty()
            || originalBytes.size()
                > static_cast<qsizetype>(
                    KSWORD_ARK_MUTATION_MAX_BYTES))
        {
            return;
        }

        const QPointer<KernelDisassemblyDialog> self(this);
        QPointer<QDialog> editor = new QDialog(this);
        editor->setWindowTitle(QStringLiteral("内核字节事务"));
        applyResponsiveWindowGeometry(editor, this, QSize(860, 640), QSize(520, 380));
        auto* layout = new QVBoxLayout(editor);
        auto* risk = new QLabel(
            QStringLiteral(
                "目标：%1；快照长度：%2 字节。\n"
                "修改可能作用于正在执行的内核代码。错误字节可能导致系统崩溃、"
                "安全边界失效或不可恢复的数据损坏。事务会先核对原始字节并"
                "执行 dry-run，只有最终 FORCE+UI_CONFIRMED 阶段才写入；"
                "写后校验失败会立即请求回滚。多字节写入不是硬件原子操作，"
                "其他 CPU 仍可能并发执行或修改目标。")
                .arg(addressText(address))
                .arg(originalBytes.size()),
            editor);
        risk->setWordWrap(true);
        risk->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:6px;"
            "padding:8px;color:%1;font-weight:600;}")
            .arg(KswordTheme::ErrorHex()));
        layout->addWidget(risk);
        auto* inputHint = new QLabel(
            QStringLiteral(
                "在统一编辑器中暂存字节或汇编修改；确认后沿用内核事务的"
                "原始字节核对、dry-run、写后校验与回滚。"),
            editor);
        inputHint->setWordWrap(true);
        layout->addWidget(inputHint);
        const auto evidence = m_originalBytes;
        const auto evidenceBase = m_baseAddress;
        const auto evidenceArchitecture = m_editor->currentArchitecture();
        const auto evidenceRevision = m_snapshotRevision;
        auto* input = new SnapshotWorkbenchWidget(editor);
        input->setSnapshot(originalBytes, address, evidenceArchitecture, address);
        input->setEditable(true);
        input->showDisassemblyAt(address);
        layout->addWidget(input, 1);
        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
            editor);
        layout->addWidget(buttons);
        connect(
            buttons,
            &QDialogButtonBox::accepted,
            editor.data(),
            &QDialog::accept);
        connect(
            buttons,
            &QDialogButtonBox::rejected,
            editor.data(),
            &QDialog::reject);
        const int editResult = editor->exec();
        const QByteArray replacementBytes = self && editor && editResult == QDialog::Accepted
            ? input->data() : QByteArray();
        if (editor) delete editor.data();
        if (!self || editResult != QDialog::Accepted) return;

        if (!m_kernelMutationEnabled || evidence != m_originalBytes
            || evidenceBase != m_baseAddress || evidenceArchitecture != m_editor->currentArchitecture()
            || evidenceRevision != m_snapshotRevision)
        {
            ownedMessageBox(
                this, QMessageBox::Warning,
                QStringLiteral("内核字节事务"),
                QStringLiteral("内核证据快照已变化，请重新选择字节后编辑。"));
            return;
        }
        if (replacementBytes.size() != originalBytes.size())
        {
            ownedMessageBox(
                this, QMessageBox::Warning,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "替换长度必须与所选原始指令一致（%1 字节），"
                    "以便完整执行 expected-before 校验。")
                    .arg(originalBytes.size()));
            return;
        }
        if (replacementBytes == originalBytes)
        {
            m_mutationStatusLabel->setText(QStringLiteral(
                "事务后端：替换字节与快照一致，未创建事务。"));
            return;
        }

        const QMessageBox::StandardButton confirmed =
            ownedMessageBox(
                this, QMessageBox::Warning,
                QStringLiteral("确认内核字节事务"),
                QStringLiteral(
                    "即将修改内核虚拟地址 %1 的 %2 字节。\n"
                    "原始：%3\n替换：%4\n\n"
                    "这可能立即造成系统挂起、蓝屏、数据损坏或"
                    "安全边界失效。是否继续执行 PREPARE 和 dry-run？")
                    .arg(addressText(address))
                    .arg(originalBytes.size())
                    .arg(bytesText(originalBytes))
                    .arg(bytesText(replacementBytes)),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
        if (!self) return;
        if (confirmed != QMessageBox::Yes)
        {
            m_mutationStatusLabel->setText(
                QStringLiteral("事务后端：用户取消。"));
            return;
        }
        if (!m_kernelMutationEnabled || evidenceRevision != m_snapshotRevision
            || evidenceArchitecture != m_editor->currentArchitecture()) return;

        const ksword::ark::DriverClient client;
        const unsigned long finalFlags =
            KSWORD_ARK_MUTATION_FLAG_FORCE
            | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED;
        ksword::ark::MutationPrepareInput prepareInput;
        prepareInput.flags =
            KSWORD_ARK_MUTATION_FLAG_DRY_RUN
            | KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
        prepareInput.targetKind =
            KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
        prepareInput.bytes =
            static_cast<std::uint32_t>(
                replacementBytes.size());
        prepareInput.targetAddress = address;
        prepareInput.afterBytes =
            byteVector(replacementBytes);
        prepareInput.expectedBeforeBytes =
            byteVector(originalBytes);

        m_mutationStatusLabel->setText(QStringLiteral(
            "事务后端：正在 PREPARE 并核对原始快照…"));
        const ksword::ark::MutationResponseResult prepared =
            client.prepareMutation(prepareInput);
        if (!prepared.io.ok
            || prepared.status
                != KSWORD_ARK_MUTATION_STATUS_PREPARED
            || prepared.transactionId == 0U
            || prepared.bytes
                != static_cast<std::uint32_t>(
                    originalBytes.size())
            || !bytePrefixMatches(
                prepared.beforeBytes,
                originalBytes))
        {
            const QString detail = mutationResponseText(
                QStringLiteral("PREPARE 失败"),
                prepared);
            m_mutationStatusLabel->setText(
                QStringLiteral("事务后端：%1").arg(detail));
            ownedMessageBox(
                this, QMessageBox::Critical,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "PREPARE 未通过；没有发出写入。\n%1")
                    .arg(detail));
            return;
        }

        const auto readKernelBytesMatches =
            [&client, address](
                const QByteArray& expected,
                ksword::ark::VirtualMemoryReadResult& readResult)
            {
                readResult = client.readVirtualMemory(
                    0U,
                    address,
                    static_cast<std::uint32_t>(
                        expected.size()),
                    KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                return readResult.io.ok
                    && readResult.readStatus
                        == KSWORD_ARK_MEMORY_READ_STATUS_OK
                    && readResult.bytesRead
                        == static_cast<std::uint32_t>(
                            expected.size())
                    && readResult.data.size()
                        == static_cast<std::size_t>(
                            expected.size())
                    && bytePrefixMatches(
                        readResult.data,
                        expected);
            };

        m_mutationStatusLabel->setText(QStringLiteral(
            "事务后端：PREPARE 完成；正在执行 dry-run…"));
        const ksword::ark::MutationResponseResult dryRun =
            client.commitMutation(
                prepared.transactionId,
                KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
        if (!dryRun.io.ok
            || dryRun.status
                != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
        {
            const QString detail = mutationResponseText(
                QStringLiteral("dry-run 失败"),
                dryRun);
            m_mutationStatusLabel->setText(
                QStringLiteral("事务后端：%1").arg(detail));
            ownedMessageBox(
                this, QMessageBox::Critical,
                QStringLiteral("内核字节事务"),
                QStringLiteral(
                    "dry-run 未通过；没有发出 FORCE 写入。\n%1")
                    .arg(detail));
            return;
        }

        m_mutationStatusLabel->setText(QStringLiteral(
            "事务后端：dry-run 通过；正在提交 "
            "FORCE+UI_CONFIRMED 并由 R0 写后校验…"));
        const ksword::ark::MutationResponseResult committed =
            client.commitMutation(
                prepared.transactionId,
                finalFlags);
        if (!committed.io.ok
            || committed.status
                != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
        {
            const QString detail = mutationResponseText(
                QStringLiteral("FORCE 提交失败"),
                committed);
            ksword::ark::VirtualMemoryReadResult recoveryRead;
            bool restored = readKernelBytesMatches(
                originalBytes,
                recoveryRead);
            QString rollbackDetail;
            if (restored)
            {
                rollbackDetail = QStringLiteral(
                    "R3 复读确认原始快照仍完整，无需发出回滚写入。");
            }
            else
            {
                const ksword::ark::MutationResponseResult rollback =
                    client.rollbackMutation(
                        prepared.transactionId,
                        finalFlags);
                restored = readKernelBytesMatches(
                    originalBytes,
                    recoveryRead);
                rollbackDetail = mutationResponseText(
                    QStringLiteral("自动回滚"),
                    rollback)
                    + QChar('\n')
                    + (restored
                        ? QStringLiteral(
                            "R3 复读已确认原始快照恢复。")
                        : QStringLiteral(
                            "警告：回滚后 R3 复读未确认原始快照，"
                            "目标可能处于部分修改状态。"));
            }
            m_mutationStatusLabel->setText(
                QStringLiteral("事务后端：%1；%2")
                    .arg(detail, rollbackDetail));
            ownedMessageBox(
                this, QMessageBox::Critical,
                QStringLiteral("内核字节事务"),
                (restored
                    ? QStringLiteral(
                        "提交未完成，但已通过 R3 复读确认原始快照。\n"
                        "%1\n%2")
                    : QStringLiteral(
                        "提交未完成，且无法确认原始快照已经恢复。"
                        "请立即停止继续修改并审查事务审计。\n"
                        "%1\n%2"))
                    .arg(detail, rollbackDetail));
            return;
        }

        ksword::ark::VirtualMemoryReadResult verify;
        const bool verified = readKernelBytesMatches(
            replacementBytes,
            verify);
        if (!verified)
        {
            const ksword::ark::MutationResponseResult rollback =
                client.rollbackMutation(
                    prepared.transactionId,
                    finalFlags);
            ksword::ark::VirtualMemoryReadResult rollbackRead;
            const bool rollbackVerified =
                readKernelBytesMatches(
                    originalBytes,
                    rollbackRead);
            const QString commitDetail = mutationResponseText(
                QStringLiteral("FORCE 已返回"),
                committed);
            const QString rollbackDetail = mutationResponseText(
                QStringLiteral("校验失败后回滚"),
                rollback)
                + QChar('\n')
                + (rollbackVerified
                    ? QStringLiteral(
                        "R3 复读已确认原始快照恢复。")
                    : QStringLiteral(
                        "警告：回滚后 R3 复读未确认原始快照，"
                        "目标可能处于部分修改状态。"));
            m_mutationStatusLabel->setText(
                (rollbackVerified
                    ? QStringLiteral(
                        "事务后端：R3 写后复读不一致；%1")
                    : QStringLiteral(
                        "事务后端：R3 写后复读不一致且回滚未验证；%1"))
                    .arg(rollbackDetail));
            ownedMessageBox(
                this, QMessageBox::Critical,
                QStringLiteral("内核字节事务"),
                (rollbackVerified
                    ? QStringLiteral(
                        "R3 写后复读未得到预期字节，回滚后已确认"
                        "原始快照恢复。\n%1\n复读后端：%2\n%3")
                    : QStringLiteral(
                        "R3 写后复读未得到预期字节，且回滚后仍无法"
                        "确认原始快照。请立即停止继续修改并审查事务"
                        "审计。\n%1\n复读后端：%2\n%3"))
                    .arg(commitDetail)
                    .arg(QString::fromStdString(
                        verify.io.message))
                    .arg(rollbackDetail));
            return;
        }

        const QString completedText =
            QStringLiteral(
                "事务后端：完成。%1；R3 复读与替换字节一致。"
                "原始证据快照仍保留在当前表格中。")
                .arg(mutationResponseText(
                    QStringLiteral("COMMIT"),
                    committed));
        m_mutationStatusLabel->setText(completedText);
        ownedMessageBox(
            this, QMessageBox::Information,
            QStringLiteral("内核字节事务"),
            completedText);
    }
}
