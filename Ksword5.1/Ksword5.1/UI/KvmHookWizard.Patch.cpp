#include "KvmHookWizard.h"

#include "HexEditorWidget.h"
#include "KernelDisassemblyDialog.h"
#include "KvmControl.h"
#include "ThemeStatusRole.h"
#include "../Internationalization/LanguageManager.h"

#include <QAbstractItemView>
#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <thread>

// KvmHookWizard 第 2 步：把补丁编排从「手敲 4096 字节」降级成「只改关心的那几个字节」。
//
// 这一整个文件存在的理由只有一句：HOOK 的影子页是**被执行的那一份**（驱动侧翻转态
// secondary 叶 = 影子页 | EXECUTE，hvm_ept_view.c:186-190）。所以影子页的默认状态必须
// 与目标页逐字节相同——用户什么都不做也不能把一段内核代码变成 0x00。为此这里把
// HexEditorWidget 的缓冲区当作唯一真值：打开即装入基线整页，成品页永远是「编辑器现值」，
// 补丁永远是「编辑器现值与基线的现算差异」。
//
// 为什么不维护一份平行的 diff 列表：撤销、整页粘贴、跳转模板回写三条路径都会改缓冲区，
// 平行列表在其中任何一条上都会与缓冲区分叉，而分叉出来的那一份正好会被拿去构造影子页。

namespace
{
    // 第 2 步里有几个控件没有出现在 KvmHookWizard.h 的成员清单里（头文件已被冻结，
    // 三个 .cpp 并行实现，不能各自往里加字段）。它们用 objectName 挂在对话框上，
    // 由本文件内部 findChild 取回——查找范围就是本对话框，不存在跨对话框串扰。
    constexpr const char* kModifiedTableName = "KvmHookWizardPatchModifiedTable";
    constexpr const char* kJumpOffsetEditName = "KvmHookWizardPatchJumpOffsetEdit";
    constexpr const char* kPasteGroupName = "KvmHookWizardPatchPasteGroup";
    constexpr const char* kPasteEditName = "KvmHookWizardPatchPasteEdit";
    constexpr const char* kPasteButtonName = "KvmHookWizardPatchPasteButton";
    constexpr const char* kPasteBodyName = "KvmHookWizardPatchPasteBody";
    constexpr const char* kDisassemblyHeadName = "KvmHookWizardPatchDisassemblyHead";

    // 已修改字节清单的行数上限。整页粘贴之后差异可能是 4096 行，把它们全部塞进表格
    // 只会让界面卡住，而看第 4097 行与看第 200 行得到的是同一个结论。
    constexpr int kModifiedRowLimit = 256;

    // 反汇编面板只渲染补丁附近的一段。解码仍然固定从页首 offset 0 单向线性做，
    // 这里裁的只是**显示**，不是解码起点——从别的偏移起解会得到另一套指令边界。
    constexpr quint64 kDisassemblyContextBytes = 64;
    constexpr int kDisassemblyRowLimit = 200;

    // hexByteText：一个字节的两位十六进制。
    QString hexByteText(const quint8 value)
    {
        return QStringLiteral("%1")
            .arg(static_cast<unsigned int>(value), 2, 16, QLatin1Char('0'))
            .toUpper();
    }

    // parseHexUnsigned：解析一个可带 0x 前缀的十六进制无符号数。
    quint64 parseHexUnsigned(const QString& text, bool* const okOut)
    {
        QString compact = text.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        compact.remove(QLatin1Char('`'));
        compact.remove(QLatin1Char('_'));
        if (compact.isEmpty())
        {
            if (okOut != nullptr)
            {
                *okOut = false;
            }
            return 0;
        }
        bool converted = false;
        const quint64 value = compact.toULongLong(&converted, 16);
        if (okOut != nullptr)
        {
            *okOut = converted;
        }
        return converted ? value : 0;
    }

    // parseHexBytes：把一段十六进制文本解析成字节，**不补零**。
    //
    // 现有的 KvmViewDialog::parseHexPage 会把不足一页的输入右侧补零到整页
    // （KvmViewDialog.cpp:65-66）。对 CLOAK 那还只是把影子读成零，对 HOOK 那是让
    // 处理器去执行半页垃圾。所以这里只负责解析，长度由调用点自己判，判不过就拒绝。
    bool parseHexBytes(const QString& text, QByteArray* const bytesOut)
    {
        QString compact;
        compact.reserve(text.size());
        for (const QChar character : text)
        {
            if (character.isSpace())
            {
                continue;
            }
            if (character == QLatin1Char(',') || character == QLatin1Char('-'))
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
        QByteArray bytes;
        bytes.reserve(compact.size() / 2);
        for (int index = 0; index < compact.size(); index += 2)
        {
            bool converted = false;
            const unsigned int value = compact.mid(index, 2).toUInt(&converted, 16);
            if (!converted)
            {
                return false;
            }
            bytes.append(static_cast<char>(value & 0xFFu));
        }
        if (bytesOut != nullptr)
        {
            *bytesOut = bytes;
        }
        return true;
    }

    // monospaceFont：字节与地址必须等宽对齐，否则一列十六进制根本看不出差异。
    QFont monospaceFont()
    {
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
}

namespace ks::ui
{
    // -----------------------------------------------------------------
    // 一页字节的读取
    // -----------------------------------------------------------------

    QByteArray readTargetPage(const quint64 pageBasePhysical, QString* const failureOut)
    {
        const quint32 pageBytes = Ksword::Evidence::kPatchPageBytes;
        const quint32 chunkBytes =
            static_cast<quint32>(KSWORD_ARK_HVM_MEMORY_MAX_BYTES);

        // 分片是协议决定的，不是性能选择：R-1 通道单次上限就是这么大。
        QByteArray page;
        page.reserve(static_cast<qsizetype>(pageBytes));
        for (quint32 done = 0; done < pageBytes; done += chunkBytes)
        {
            const unsigned long thisChunk = static_cast<unsigned long>(
                std::min<quint32>(chunkBytes, pageBytes - done));
            const ksword::kvm::KvmMemoryResult result =
                ksword::kvm::readPhysical(pageBasePhysical + done, thisChunk);
            if (!result.ok)
            {
                if (failureOut != nullptr)
                {
                    *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：物理地址 0x%1 起的第 %2 片没读回来（%3）。基线不完整就不能拼影子页，因为缺的那一段会在被执行的那一页里留成零字节。"))
                        .arg(pageBasePhysical + done, 0, 16)
                        .arg(done / chunkBytes + 1)
                        .arg(result.message);
                }
                return QByteArray();
            }
            if (result.data.size() != static_cast<qsizetype>(thisChunk))
            {
                if (failureOut != nullptr)
                {
                    *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：物理地址 0x%1 起本该读回 %2 字节，实际只回了 %3 字节。这一页不完整，不能当基线用。"))
                        .arg(pageBasePhysical + done, 0, 16)
                        .arg(thisChunk)
                        .arg(result.data.size());
                }
                return QByteArray();
            }
            page.append(result.data);
        }
        if (page.size() != static_cast<qsizetype>(pageBytes))
        {
            if (failureOut != nullptr)
            {
                *failureOut = ks::i18n::sourceText(QStringLiteral("读取目标页失败：拼出来的不是整整一页，本层拒绝返回一页残缺的字节。"));
            }
            return QByteArray();
        }
        if (failureOut != nullptr)
        {
            failureOut->clear();
        }
        return page;
    }

    // -----------------------------------------------------------------
    // KvmHookPlan 的两个非平凡求值
    // -----------------------------------------------------------------

    QByteArray KvmHookPlan::composedShadowPage(QString* const failureReasonOut) const
    {
        const auto fail = [failureReasonOut](const QString& reason) {
            if (failureReasonOut != nullptr)
            {
                *failureReasonOut = reason;
            }
            return QByteArray();
        };

        if (!baselineIsComplete())
        {
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：基线页不是整整 4096 字节，用它拼出来的那一页里会有一段不属于目标页的字节，而影子页正是被执行的那一份。")));
        }
        if (patchLength() > 0xFFFFFFFFULL)
        {
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁长度超出 32 位表示范围，几何判定无法进行。")));
        }

        const std::uint8_t* const originalBytes =
            reinterpret_cast<const std::uint8_t*>(baselinePage.constData());
        const std::uint8_t* const patchPointer = patchBytes.isEmpty()
            ? nullptr
            : reinterpret_cast<const std::uint8_t*>(patchBytes.constData());

        const Ksword::Evidence::ComposedPage composed = Ksword::Evidence::ComposePage(
            originalBytes,
            static_cast<std::uint32_t>(pageOffset),
            patchPointer,
            static_cast<std::uint32_t>(patchLength()));

        switch (composed.status)
        {
        case Ksword::Evidence::PatchComposeStatus::Ok:
            break;
        case Ksword::Evidence::PatchComposeStatus::OriginalMissing:
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：没有原页字节。请先回到第 2 步重新抓一次基线页。")));
        case Ksword::Evidence::PatchComposeStatus::PatchMissing:
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：声明了补丁长度却没有补丁字节。")));
        case Ksword::Evidence::PatchComposeStatus::CrossesPageBoundary:
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁从页内偏移 0x%1 起共 %2 字节，越过了页尾。一条视图恰好覆盖一页，协议里没有 PageCount，同一条指令的取指跨两张视图页在两种后端下都是 fail-closed，拆成两条视图也救不了。"))
                .arg(composed.patchOffset, 0, 16)
                .arg(composed.patchLength));
        case Ksword::Evidence::PatchComposeStatus::EmptyPatch:
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：补丁为空。空补丁产出的影子页与原页逐位相同，那样一条 HOOK 视图什么都不改变，却会让人以为补丁装上了。")));
        default:
            return fail(ks::i18n::sourceText(QStringLiteral("影子页构造被拒绝：构造层返回了一个本层不认识的状态。")));
        }

        if (failureReasonOut != nullptr)
        {
            failureReasonOut->clear();
        }
        return QByteArray(
            reinterpret_cast<const char*>(composed.bytes.data()),
            static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes));
    }

    Ksword::Evidence::CrossPageClassification KvmHookPlan::classifyPatchGeometry() const
    {
        const quint64 length = patchLength();
        if (length > 0xFFFFFFFFULL)
        {
            // 32 位截断会把一个明显越界的长度算成页内的一个小数，所以这里先挡住。
            return Ksword::Evidence::CrossPageClassification::CrossesPage;
        }
        return Ksword::Evidence::ClassifyCrossPage(
            static_cast<std::uint32_t>(pageOffset),
            static_cast<std::uint32_t>(length));
    }

    // -----------------------------------------------------------------
    // 第 2 步的控件树
    // -----------------------------------------------------------------

    QWidget* KvmHookWizard::buildPatchPage()
    {
        QWidget* const page = new QWidget(this);
        QVBoxLayout* const rootLayout = new QVBoxLayout(page);

        QLabel* const hintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("影子页是被执行的那一份：翻转态下处理器取指走影子页，所以它必须是「目标页原字节 + 你的补丁」完整的一页。下面的编辑器已经装入目标页当前的 4096 字节，默认与目标页逐字节相同——你只改关心的那几个字节即可。")),
            page);
        hintLabel->setWordWrap(true);
        rootLayout->addWidget(hintLabel);

        QLabel* const boundaryLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("HOOK 不是安全边界：失败即放行，一个有权限的对手可以主动拆除它。这一页只保证字节算术正确。")),
            page);
        boundaryLabel->setWordWrap(true);
        rootLayout->addWidget(boundaryLabel);

        QHBoxLayout* const toolLayout = new QHBoxLayout();
        m_recaptureBaselineButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新抓取基线页")),
            page);
        m_recaptureBaselineButton->setToolTip(
            ks::i18n::sourceText(QStringLiteral("重新从目标物理页读回 4096 字节。重抓会丢弃当前所有改动。")));
        toolLayout->addWidget(m_recaptureBaselineButton);

        m_revertPatchButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("还原为基线页")),
            page);
        m_revertPatchButton->setToolTip(
            ks::i18n::sourceText(QStringLiteral("把编辑器恢复成刚抓回来的那一页，补丁清空。")));
        toolLayout->addWidget(m_revertPatchButton);
        toolLayout->addStretch(1);
        rootLayout->addLayout(toolLayout);

        QSplitter* const splitter = new QSplitter(Qt::Horizontal, page);

        // ---- 左：十六进制编辑器（唯一真值）----
        m_shadowEditor = new HexEditorWidget(splitter);
        m_shadowEditor->setObjectName(QStringLiteral("KvmHookWizardShadowEditor"));
        m_shadowEditor->setEditable(true);
        splitter->addWidget(m_shadowEditor);

        // ---- 右：已修改字节 / 跳转模板 / 反汇编 ----
        QWidget* const sideWidget = new QWidget(splitter);
        QVBoxLayout* const sideLayout = new QVBoxLayout(sideWidget);
        sideLayout->setContentsMargins(0, 0, 0, 0);

        QGroupBox* const modifiedGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("已修改字节（编辑器现值与基线页的现算差异）")),
            sideWidget);
        QVBoxLayout* const modifiedLayout = new QVBoxLayout(modifiedGroup);
        QTableWidget* const modifiedTable = new QTableWidget(0, 3, modifiedGroup);
        modifiedTable->setObjectName(QString::fromLatin1(kModifiedTableName));
        modifiedTable->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("页内偏移"))
            << ks::i18n::sourceText(QStringLiteral("原值"))
            << ks::i18n::sourceText(QStringLiteral("新值")));
        modifiedTable->horizontalHeader()->setStretchLastSection(true);
        modifiedTable->verticalHeader()->setVisible(false);
        modifiedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        modifiedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        modifiedTable->setFont(monospaceFont());
        modifiedLayout->addWidget(modifiedTable);
        sideLayout->addWidget(modifiedGroup, 1);

        // ---- 跳转模板 ----
        QGroupBox* const jumpGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("跳转模板")),
            sideWidget);
        QFormLayout* const jumpLayout = new QFormLayout(jumpGroup);

        m_jumpTemplateBox = new QComboBox(jumpGroup);
        m_jumpTemplateBox->addItem(
            ks::i18n::sourceText(QStringLiteral("不使用模板（直接在左边改字节）")),
            static_cast<int>(JumpTemplate::None));
        m_jumpTemplateBox->addItem(
            ks::i18n::sourceText(QStringLiteral("近跳 E9 rel32（5 字节，位移必须装得进 int32）")),
            static_cast<int>(JumpTemplate::Rel32Near));
        m_jumpTemplateBox->addItem(
            ks::i18n::sourceText(QStringLiteral("绝对跳 FF 25（14 字节，无距离限制）")),
            static_cast<int>(JumpTemplate::Absolute14));
        jumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("模板")),
            m_jumpTemplateBox);

        m_jumpTargetEdit = new QLineEdit(jumpGroup);
        m_jumpTargetEdit->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
        m_jumpTargetEdit->setFont(monospaceFont());
        jumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("跳转目标虚拟地址（十六进制）")),
            m_jumpTargetEdit);

        QLineEdit* const jumpOffsetEdit = new QLineEdit(jumpGroup);
        jumpOffsetEdit->setObjectName(QString::fromLatin1(kJumpOffsetEditName));
        jumpOffsetEdit->setPlaceholderText(QStringLiteral("0x0"));
        jumpOffsetEdit->setFont(monospaceFont());
        jumpOffsetEdit->setToolTip(
            ks::i18n::sourceText(QStringLiteral("补丁写进页内的哪个偏移。在左边点选一个字节会自动填这里。")));
        jumpLayout->addRow(
            ks::i18n::sourceText(QStringLiteral("写入页内偏移（十六进制）")),
            jumpOffsetEdit);

        m_applyJumpButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("把编码结果写进编辑器")),
            jumpGroup);
        jumpLayout->addRow(m_applyJumpButton);
        sideLayout->addWidget(jumpGroup);

        splitter->addWidget(sideWidget);
        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        rootLayout->addWidget(splitter, 1);

        // ---- 摘要 ----
        m_patchSummaryLabel = new QLabel(page);
        m_patchSummaryLabel->setWordWrap(true);
        m_patchSummaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        rootLayout->addWidget(m_patchSummaryLabel);

        // ---- 反汇编（参考，不是判据）----
        QGroupBox* const disassemblyGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("反汇编参考（不是判据）")),
            page);
        QVBoxLayout* const disassemblyLayout = new QVBoxLayout(disassemblyGroup);

        // 这一行是诚实性要求，不许删：仓库里的 InstructionDecoder 只有正向线性解码，
        // 没有反向能力，从任意偏移起解只能是启发式自同步。做出来的「指令边界判定」
        // 会是一个假判据，所以这里明确不做，只把这句话摆在面板上方。
        QLabel* const honestyLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("线性反汇编从页首开始，落在数据区或对齐填充上会给出错误的指令边界 —— 请自行确认补丁点是指令边界。")),
            disassemblyGroup);
        honestyLabel->setWordWrap(true);
        disassemblyLayout->addWidget(honestyLabel);

        QLabel* const headLabel = new QLabel(disassemblyGroup);
        headLabel->setObjectName(QString::fromLatin1(kDisassemblyHeadName));
        headLabel->setWordWrap(true);
        disassemblyLayout->addWidget(headLabel);

        m_patchDisassemblyView = new QPlainTextEdit(disassemblyGroup);
        m_patchDisassemblyView->setReadOnly(true);
        m_patchDisassemblyView->setLineWrapMode(QPlainTextEdit::NoWrap);
        m_patchDisassemblyView->setFont(monospaceFont());
        disassemblyLayout->addWidget(m_patchDisassemblyView);
        rootLayout->addWidget(disassemblyGroup, 1);

        // ---- 整页粘贴（专家入口，默认折叠）----
        QGroupBox* const pasteGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("整页粘贴（专家入口）")),
            page);
        pasteGroup->setObjectName(QString::fromLatin1(kPasteGroupName));
        pasteGroup->setCheckable(true);
        pasteGroup->setChecked(false);
        QVBoxLayout* const pasteOuterLayout = new QVBoxLayout(pasteGroup);
        QWidget* const pasteBody = new QWidget(pasteGroup);
        pasteBody->setObjectName(QString::fromLatin1(kPasteBodyName));
        pasteBody->setVisible(false);
        QVBoxLayout* const pasteLayout = new QVBoxLayout(pasteBody);
        pasteLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* const pasteHint = new QLabel(
            ks::i18n::sourceText(QStringLiteral("粘贴的十六进制必须恰好是 4096 字节。不足一页会被直接拒绝，不会右侧补零——补零意味着把半页垃圾装进那一份将要被执行的影子页。")),
            pasteBody);
        pasteHint->setWordWrap(true);
        pasteLayout->addWidget(pasteHint);

        QPlainTextEdit* const pasteEdit = new QPlainTextEdit(pasteBody);
        pasteEdit->setObjectName(QString::fromLatin1(kPasteEditName));
        pasteEdit->setFont(monospaceFont());
        pasteEdit->setPlaceholderText(QStringLiteral("48 89 5C 24 08 ..."));
        pasteLayout->addWidget(pasteEdit);

        QPushButton* const pasteButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("用粘贴的整页覆盖编辑器")),
            pasteBody);
        pasteButton->setObjectName(QString::fromLatin1(kPasteButtonName));
        pasteLayout->addWidget(pasteButton);

        pasteOuterLayout->addWidget(pasteBody);
        rootLayout->addWidget(pasteGroup);

        m_patchStatusLabel = new QLabel(page);
        m_patchStatusLabel->setWordWrap(true);
        rootLayout->addWidget(m_patchStatusLabel);

        // ---- 连线 ----
        connect(
            m_shadowEditor,
            &HexEditorWidget::byteEdited,
            this,
            &KvmHookWizard::onShadowByteEdited);
        connect(
            m_shadowEditor,
            &HexEditorWidget::currentAddressChanged,
            this,
            [this, jumpOffsetEdit](const std::uint64_t absoluteAddress) {
                // 选中的那个字节就是写入点：让用户在编辑器里点一下即可，不必心算偏移。
                if (absoluteAddress < m_plan.pageBasePhysical)
                {
                    return;
                }
                const quint64 offset = absoluteAddress - m_plan.pageBasePhysical;
                if (offset >= Ksword::Evidence::kPatchPageBytes)
                {
                    return;
                }
                jumpOffsetEdit->setText(QStringLiteral("0x%1").arg(offset, 0, 16));
            });
        connect(
            m_recaptureBaselineButton,
            &QPushButton::clicked,
            this,
            [this]() { startBaselineCapture(); });
        connect(
            m_revertPatchButton,
            &QPushButton::clicked,
            this,
            [this]() { revertPatch(); });
        connect(
            m_jumpTemplateBox,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { updatePatchEnabledState(); });
        connect(
            m_applyJumpButton,
            &QPushButton::clicked,
            this,
            [this]() {
                if (m_jumpTemplateBox == nullptr || m_jumpTargetEdit == nullptr)
                {
                    return;
                }
                const JumpTemplate templateKind = static_cast<JumpTemplate>(
                    m_jumpTemplateBox->currentData().toInt());
                bool converted = false;
                const quint64 targetVa =
                    parseHexUnsigned(m_jumpTargetEdit->text(), &converted);
                if (!converted)
                {
                    if (m_patchStatusLabel != nullptr)
                    {
                        m_patchStatusLabel->setText(ks::i18n::sourceText(
                            QStringLiteral("跳转目标不是一个合法的十六进制地址。")));
                        ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
                    }
                    return;
                }
                applyJumpTemplate(templateKind, targetVa);
            });
        connect(
            pasteGroup,
            &QGroupBox::toggled,
            pasteBody,
            &QWidget::setVisible);
        connect(
            pasteButton,
            &QPushButton::clicked,
            this,
            [this, pasteEdit]() {
                if (m_shadowEditor == nullptr || m_patchStatusLabel == nullptr)
                {
                    return;
                }
                if (!m_plan.baselineIsComplete())
                {
                    m_patchStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：还没有基线页，无法判断粘贴进来的这一页改动了什么。")));
                    ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
                    return;
                }
                QByteArray pasted;
                if (!parseHexBytes(pasteEdit->toPlainText(), &pasted))
                {
                    m_patchStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：文本里有非十六进制字符，或者十六进制位数是奇数。")));
                    ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
                    return;
                }
                if (pasted.size()
                    != static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes))
                {
                    // 这里刻意不补零：补零会把半页垃圾装进那一份被执行的影子页。
                    m_patchStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("整页粘贴被拒绝：粘贴进来的是 %1 字节，而影子页必须恰好 4096 字节。这里不会替你右侧补零——补出来的那一半会被处理器当成指令执行。"))
                        .arg(pasted.size()));
                    ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
                    return;
                }
                m_shadowEditor->setByteArray(pasted, m_plan.pageBasePhysical);
                m_shadowEditor->setEditable(!m_busy);
                recomputePatchFromEditor();
                updatePatchSummary();
                refreshPatchDisassembly();
                updatePatchEnabledState();
                m_patchStatusLabel->setText(ks::i18n::sourceText(
                    QStringLiteral("整页已覆盖进编辑器，补丁按与基线页的差异重新算过。")));
                ApplyStatusRole(m_patchStatusLabel, StatusRole::Info);
            });

        updatePatchSummary();
        updatePatchEnabledState();
        return page;
    }

    // -----------------------------------------------------------------
    // 基线页抓取
    // -----------------------------------------------------------------

    void KvmHookWizard::startBaselineCapture()
    {
        if (m_shadowEditor == nullptr)
        {
            return;
        }
        if (!m_plan.resolved)
        {
            if (m_patchStatusLabel != nullptr)
            {
                m_patchStatusLabel->setText(ks::i18n::sourceText(
                    QStringLiteral("目标还没有解析成功，没有可读的物理页。请回到第 1 步。")));
                ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
            }
            return;
        }
        if (m_baselineInFlight)
        {
            // 单飞：同一时刻只允许一条读页线程，重复点按不叠发。
            return;
        }

        m_baselineInFlight = true;
        const quint64 sequence = ++m_baselineSequence;
        const quint64 pageBase = m_plan.pageBasePhysical;
        setBusy(true);
        updatePatchEnabledState();
        if (m_patchStatusLabel != nullptr)
        {
            m_patchStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("正在从 R-1 通道分四片读回目标页的 4096 字节……")));
            ApplyStatusRole(m_patchStatusLabel, StatusRole::Info);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence, pageBase]() {
            QString failure;
            const QByteArray page = readTargetPage(pageBase, &failure);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, page, failure]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyBaselineCapture(sequence, page, failure);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyBaselineCapture(
        const quint64 sequence,
        const QByteArray& page,
        const QString& failure)
    {
        // 先无条件放掉在飞标志与忙碌态：回来的这一条就是那条在飞的任务，
        // 即便它的序号已经作废，它占的那把锁也必须还回去。
        m_baselineInFlight = false;
        setBusy(false);
        if (sequence != m_baselineSequence)
        {
            // 序号不等说明这一份是被后续输入作废掉的旧页，落地它会让编辑器里的
            // 字节与第 1 步的地址对不上。
            return;
        }
        if (m_shadowEditor == nullptr)
        {
            return;
        }

        if (page.size() != static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes))
        {
            m_plan.baselinePage.clear();
            m_plan.patchBytes.clear();
            m_shadowEditor->setByteArray(QByteArray(), m_plan.pageBasePhysical);
            if (m_patchStatusLabel != nullptr)
            {
                m_patchStatusLabel->setText(failure.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("基线页抓取失败：没有读回完整的一页。"))
                    : failure);
                ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
            }
            setStatusText(
                ks::i18n::sourceText(QStringLiteral("基线页抓取失败，第 2 步无法继续。")),
                KvmCheckVerdict::Fail);
            updatePatchSummary();
            refreshPatchDisassembly();
            updatePatchEnabledState();
            return;
        }

        m_plan.baselinePage = page;
        m_plan.patchBytes.clear();
        // 默认状态与目标页逐字节相同：用户什么都不做也不会把内核代码变成 0x00。
        m_shadowEditor->setByteArray(page, m_plan.pageBasePhysical);
        m_shadowEditor->setEditable(true);
        // 用户关心的是那几个字节，不是页首。
        m_shadowEditor->jumpToAbsoluteAddress(
            m_plan.pageBasePhysical + m_plan.pageOffset);

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (m_patchStatusLabel != nullptr)
        {
            m_patchStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("基线页已就位：物理页 0x%1 的 4096 字节，编辑器当前内容与目标页逐字节相同。"))
                .arg(m_plan.pageBasePhysical, 0, 16));
            ApplyStatusRole(m_patchStatusLabel, StatusRole::Success);
        }
        setStatusText(
            ks::i18n::sourceText(QStringLiteral("基线页已抓取，可以开始编排补丁。")),
            KvmCheckVerdict::Pass);
    }

    // -----------------------------------------------------------------
    // 编辑与补丁重算
    // -----------------------------------------------------------------

    void KvmHookWizard::onShadowByteEdited(
        const std::uint64_t absoluteAddress,
        const std::uint8_t oldValue,
        const std::uint8_t newValue)
    {
        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (m_patchStatusLabel != nullptr)
        {
            const quint64 offset = absoluteAddress >= m_plan.pageBasePhysical
                ? absoluteAddress - m_plan.pageBasePhysical
                : 0ULL;
            m_patchStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("已改写页内偏移 0x%1：原值 %2 改成 %3。"))
                .arg(offset, 0, 16)
                .arg(hexByteText(oldValue))
                .arg(hexByteText(newValue)));
            ApplyStatusRole(m_patchStatusLabel, StatusRole::Info);
        }
    }

    void KvmHookWizard::recomputePatchFromEditor()
    {
        if (m_shadowEditor == nullptr)
        {
            return;
        }

        // 补丁永远是「编辑器现值与基线页的现算差异」。不维护平行的 diff 列表：
        // 整页粘贴、模板回写、单字节编辑三条路径都改缓冲区，平行列表必然分叉。
        const QByteArray current = m_shadowEditor->data();
        const QByteArray& baseline = m_plan.baselinePage;

        // 没有差异时把补丁起点退回第 1 步解析出来的那个页内偏移：
        // 那才是「用户指的那个字节」，而不是上一轮改动留下的起点。
        const quint32 resolvedOffset =
            static_cast<quint32>(m_plan.fullPhysicalAddress & 0xFFFULL);

        if (baseline.size() != static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes)
            || current.size() != baseline.size())
        {
            m_plan.patchBytes.clear();
            m_plan.pageOffset = resolvedOffset;
            return;
        }

        qsizetype firstDifference = -1;
        qsizetype lastDifference = -1;
        for (qsizetype index = 0; index < current.size(); ++index)
        {
            if (current.at(index) != baseline.at(index))
            {
                if (firstDifference < 0)
                {
                    firstDifference = index;
                }
                lastDifference = index;
            }
        }

        if (firstDifference < 0)
        {
            m_plan.patchBytes.clear();
            m_plan.pageOffset = resolvedOffset;
            return;
        }

        m_plan.pageOffset = static_cast<quint32>(firstDifference);
        m_plan.patchBytes = current.mid(
            firstDifference,
            lastDifference - firstDifference + 1);
    }

    void KvmHookWizard::updatePatchSummary()
    {
        // ---- 已修改字节清单 ----
        QTableWidget* const modifiedTable =
            findChild<QTableWidget*>(QString::fromLatin1(kModifiedTableName));
        if (modifiedTable != nullptr)
        {
            modifiedTable->setRowCount(0);
            if (m_shadowEditor != nullptr && m_plan.baselineIsComplete())
            {
                const QByteArray current = m_shadowEditor->data();
                if (current.size() == m_plan.baselinePage.size())
                {
                    int row = 0;
                    for (qsizetype index = 0;
                        index < current.size() && row < kModifiedRowLimit;
                        ++index)
                    {
                        if (current.at(index) == m_plan.baselinePage.at(index))
                        {
                            continue;
                        }
                        modifiedTable->insertRow(row);
                        modifiedTable->setItem(row, 0, new QTableWidgetItem(
                            QStringLiteral("0x%1")
                                .arg(static_cast<qulonglong>(index), 3, 16, QLatin1Char('0'))));
                        modifiedTable->setItem(row, 1, new QTableWidgetItem(
                            hexByteText(static_cast<quint8>(
                                m_plan.baselinePage.at(index)))));
                        modifiedTable->setItem(row, 2, new QTableWidgetItem(
                            hexByteText(static_cast<quint8>(current.at(index)))));
                        ++row;
                    }
                }
            }
        }

        if (m_patchSummaryLabel == nullptr)
        {
            return;
        }

        QStringList lines;
        if (!m_plan.baselineIsComplete())
        {
            lines << ks::i18n::sourceText(QStringLiteral("基线页尚未就位：还没有可编排的一页字节。"));
            m_patchSummaryLabel->setText(lines.join(QStringLiteral("\n")));
            return;
        }

        lines << ks::i18n::sourceText(QStringLiteral("目标物理页 0x%1，第 1 步解析出的页内偏移 0x%2。"))
            .arg(m_plan.pageBasePhysical, 0, 16)
            .arg(m_plan.fullPhysicalAddress & 0xFFFULL, 0, 16);

        if (m_plan.patchIsEmpty())
        {
            lines << ks::i18n::sourceText(QStringLiteral("当前补丁为空：编辑器内容与基线页逐字节相同。空补丁产出的影子页与原页一模一样，那样一条 HOOK 视图什么都不改变，所以第 4 步会拒绝安装。"));
        }
        else
        {
            lines << ks::i18n::sourceText(QStringLiteral("补丁起点页内偏移 0x%1，长度 %2 字节，结束偏移 0x%3（不含）。"))
                .arg(m_plan.pageOffset, 0, 16)
                .arg(m_plan.patchLength())
                .arg(m_plan.patchEndOffset(), 0, 16);
        }

        const Ksword::Evidence::CrossPageClassification classification =
            m_plan.classifyPatchGeometry();
        if (classification == Ksword::Evidence::CrossPageClassification::InPage)
        {
            lines << ks::i18n::sourceText(QStringLiteral("几何判定：补丁完全落在这一页里。"));
        }
        else
        {
            lines << ks::i18n::sourceText(QStringLiteral("几何判定：补丁越过了页尾，第 4 步会直接拒绝。一条视图恰好覆盖一页，协议里没有 PageCount，装两条也救不了——同一条指令的取指跨两张视图页在两种后端下都是 fail-closed。"));
        }

        QString composeFailure;
        const QByteArray composed = m_plan.composedShadowPage(&composeFailure);
        if (composed.size() == static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes))
        {
            lines << ks::i18n::sourceText(QStringLiteral("成品影子页可构造：整整 4096 字节，补丁区间以外与基线页逐位相同。"));
        }
        else
        {
            lines << composeFailure;
        }

        m_patchSummaryLabel->setText(lines.join(QStringLiteral("\n")));
    }

    void KvmHookWizard::refreshPatchDisassembly()
    {
        if (m_patchDisassemblyView == nullptr)
        {
            return;
        }
        QLabel* const headLabel =
            findChild<QLabel*>(QString::fromLatin1(kDisassemblyHeadName));

        if (m_shadowEditor == nullptr || !m_plan.baselineIsComplete())
        {
            m_patchDisassemblyView->setPlainText(ks::i18n::sourceText(
                QStringLiteral("基线页尚未就位，没有可解码的字节。")));
            if (headLabel != nullptr)
            {
                headLabel->clear();
            }
            return;
        }

        const QByteArray current = m_shadowEditor->data();
        if (current.isEmpty())
        {
            m_patchDisassemblyView->clear();
            return;
        }

        // 基址固定取页基址，解码固定从页首 offset 0 单向线性做。
        // 有虚拟地址时用虚拟页基址，因为那才是这一页真正被执行时的地址，
        // 相对跳转的目标才对得上；只有物理地址的入口退回物理页基址。
        const bool haveVirtual = m_plan.hasVirtualAddress();
        const quint64 decodeBase = haveVirtual
            ? (m_plan.virtualAddress & ~0xFFFULL)
            : m_plan.pageBasePhysical;

        const DisassemblyResult result = InstructionDecoder::decode(
            current,
            decodeBase,
            DisassemblyArchitecture::X64,
            static_cast<std::uint32_t>(Ksword::Evidence::kPatchPageBytes));

        if (headLabel != nullptr)
        {
            headLabel->setText(haveVirtual
                ? ks::i18n::sourceText(QStringLiteral("解码基址取虚拟页基址 0x%1，后端：%2。带 * 的行与补丁区间有重叠。"))
                    .arg(decodeBase, 0, 16)
                    .arg(result.backendName)
                : ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，解码基址退回物理页基址 0x%1，后端：%2。带 * 的行与补丁区间有重叠。"))
                    .arg(decodeBase, 0, 16)
                    .arg(result.backendName));
        }

        // 显示窗口只裁**渲染**，不改解码起点：整页 1500 行塞进文本框，
        // 每敲一个字节就重排一次，界面会卡；而看窗口外那几百行得不到别的结论。
        const quint64 patchStart = static_cast<quint64>(m_plan.pageOffset);
        const quint64 patchEnd = m_plan.patchIsEmpty()
            ? patchStart + 1
            : m_plan.patchEndOffset();
        const quint64 windowStart = patchStart > kDisassemblyContextBytes
            ? patchStart - kDisassemblyContextBytes
            : 0ULL;
        const quint64 windowEnd = patchEnd + kDisassemblyContextBytes;

        QStringList lines;
        for (const DisassemblyRow& row : result.rows)
        {
            const quint64 rowStart = static_cast<quint64>(row.byteOffset);
            const quint64 rowEnd = rowStart
                + static_cast<quint64>(std::max<qsizetype>(row.bytes.size(), 1));
            if (rowEnd <= windowStart || rowStart >= windowEnd)
            {
                continue;
            }
            if (lines.size() >= kDisassemblyRowLimit)
            {
                lines << ks::i18n::sourceText(QStringLiteral("（后面的行已省略）"));
                break;
            }

            const bool touchesPatch =
                !m_plan.patchIsEmpty() && rowStart < patchEnd && rowEnd > patchStart;
            lines << QStringLiteral("%1 %2  %3  %4 %5")
                .arg(touchesPatch ? QStringLiteral("*") : QStringLiteral(" "))
                .arg(row.address, 16, 16, QLatin1Char('0'))
                .arg(QString::fromLatin1(row.bytes.toHex(' ')).toUpper(), -32)
                .arg(row.mnemonic)
                .arg(row.operands);
        }

        if (lines.isEmpty())
        {
            lines << ks::i18n::sourceText(QStringLiteral("补丁附近没有解码出任何指令。"));
        }
        if (!result.diagnosticText.isEmpty())
        {
            lines << QString();
            lines << result.diagnosticText;
        }
        m_patchDisassemblyView->setPlainText(lines.join(QStringLiteral("\n")));
    }

    // -----------------------------------------------------------------
    // 跳转模板
    // -----------------------------------------------------------------

    void KvmHookWizard::applyJumpTemplate(
        const JumpTemplate templateKind,
        const quint64 targetVa)
    {
        const auto reject = [this](const QString& reason) {
            if (m_patchStatusLabel != nullptr)
            {
                m_patchStatusLabel->setText(reason);
                ApplyStatusRole(m_patchStatusLabel, StatusRole::Error);
            }
        };

        if (m_shadowEditor == nullptr)
        {
            return;
        }
        if (templateKind == JumpTemplate::None)
        {
            reject(ks::i18n::sourceText(QStringLiteral("当前没有选择跳转模板，请直接在左边的十六进制编辑器里改字节。")));
            return;
        }
        if (!m_plan.baselineIsComplete())
        {
            reject(ks::i18n::sourceText(QStringLiteral("基线页还没有就位，没有可写入的一页字节。")));
            return;
        }
        if (!m_plan.hasVirtualAddress())
        {
            // 近跳的位移基准是下一条指令，源地址取 virtualAddress；
            // 直接给物理地址的那条入口拿不到可信的源地址，所以两个模板都停掉。
            reject(ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，跳转模板不可用：近跳的位移要按源虚拟地址算，而直接给物理地址的路径上没有可信的源地址。请改用左边的十六进制编辑器直接写字节。")));
            return;
        }

        QLineEdit* const jumpOffsetEdit =
            findChild<QLineEdit*>(QString::fromLatin1(kJumpOffsetEditName));
        if (jumpOffsetEdit == nullptr)
        {
            return;
        }
        bool converted = false;
        const quint64 writeOffset = parseHexUnsigned(jumpOffsetEdit->text(), &converted);
        if (!converted)
        {
            reject(ks::i18n::sourceText(QStringLiteral("写入页内偏移不是一个合法的十六进制数。在左边的编辑器里点选一个字节可以自动填上它。")));
            return;
        }
        if (writeOffset >= Ksword::Evidence::kPatchPageBytes)
        {
            reject(ks::i18n::sourceText(QStringLiteral("写入页内偏移 0x%1 已经不在这一页里，一条视图恰好覆盖一页。"))
                .arg(writeOffset, 0, 16));
            return;
        }

        QByteArray encoded;
        if (templateKind == JumpTemplate::Rel32Near)
        {
            const quint64 sourceVa = (m_plan.virtualAddress & ~0xFFFULL) + writeOffset;
            const Ksword::Evidence::Rel32Jump jump =
                Ksword::Evidence::EncodeRel32Jump(sourceVa, targetVa);
            if (!jump.ok())
            {
                // 如实拒绝并说明改用绝对跳，不偷偷替用户换编码：换过去的那五个字节
                // 与他在摘要里读到的长度对不上。
                reject(ks::i18n::sourceText(QStringLiteral("近跳编码被拒绝：从 0x%1 跳到 0x%2 的位移是 %3，装不进 int32。请改用 14 字节的绝对跳 FF 25，它没有距离限制。"))
                    .arg(sourceVa, 0, 16)
                    .arg(targetVa, 0, 16)
                    .arg(static_cast<qlonglong>(jump.displacement)));
                return;
            }
            encoded = QByteArray(
                reinterpret_cast<const char*>(jump.bytes.data()),
                static_cast<qsizetype>(Ksword::Evidence::kRel32JumpLength));
        }
        else
        {
            const auto bytes = Ksword::Evidence::EncodeAbsoluteJump(targetVa);
            encoded = QByteArray(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<qsizetype>(Ksword::Evidence::kAbsoluteJumpLength));
        }

        if (writeOffset + static_cast<quint64>(encoded.size())
            > Ksword::Evidence::kPatchPageBytes)
        {
            // 跨页直接拒绝，不提供「自动装两条」：两页的翻转彼此独立，
            // 中间任何一次退出都可能让 guest 执行到半条指令。
            reject(ks::i18n::sourceText(QStringLiteral("模板写入被拒绝：从页内偏移 0x%1 起写 %2 字节会越过页尾。一条视图恰好覆盖一页，协议里没有 PageCount，拆成两条视图在两种后端下都是 fail-closed，所以这里不提供那个选项。"))
                .arg(writeOffset, 0, 16)
                .arg(encoded.size()));
            return;
        }

        for (qsizetype index = 0; index < encoded.size(); ++index)
        {
            const quint64 address =
                m_plan.pageBasePhysical + writeOffset + static_cast<quint64>(index);
            // setByteAtAbsoluteAddress 不发 byteEdited（HexEditorWidget.cpp:377 起），
            // 所以下面必须自己重算一次补丁。
            m_shadowEditor->setByteAtAbsoluteAddress(
                address,
                static_cast<std::uint8_t>(encoded.at(index)),
                index == encoded.size() - 1);
        }

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (m_patchStatusLabel != nullptr)
        {
            m_patchStatusLabel->setText(templateKind == JumpTemplate::Rel32Near
                ? ks::i18n::sourceText(QStringLiteral("近跳已写入：页内偏移 0x%1 起 5 字节，目标 0x%2。"))
                    .arg(writeOffset, 0, 16)
                    .arg(targetVa, 0, 16)
                : ks::i18n::sourceText(QStringLiteral("绝对跳已写入：页内偏移 0x%1 起 14 字节，目标 0x%2。"))
                    .arg(writeOffset, 0, 16)
                    .arg(targetVa, 0, 16));
            ApplyStatusRole(m_patchStatusLabel, StatusRole::Success);
        }
    }

    void KvmHookWizard::revertPatch()
    {
        if (m_shadowEditor == nullptr)
        {
            return;
        }
        if (!m_plan.baselineIsComplete())
        {
            return;
        }

        m_shadowEditor->setByteArray(m_plan.baselinePage, m_plan.pageBasePhysical);
        m_shadowEditor->setEditable(!m_busy);
        m_plan.patchBytes.clear();
        m_plan.pageOffset = static_cast<quint32>(m_plan.fullPhysicalAddress & 0xFFFULL);
        m_shadowEditor->jumpToAbsoluteAddress(
            m_plan.pageBasePhysical + m_plan.pageOffset);

        recomputePatchFromEditor();
        updatePatchSummary();
        refreshPatchDisassembly();
        updatePatchEnabledState();

        if (m_patchStatusLabel != nullptr)
        {
            m_patchStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("已还原为基线页，编辑器内容与目标页逐字节相同。")));
            ApplyStatusRole(m_patchStatusLabel, StatusRole::Info);
        }
    }

    void KvmHookWizard::updatePatchEnabledState()
    {
        const bool baselineReady = m_plan.baselineIsComplete();
        const bool idle = !m_busy;
        const bool haveVirtual = m_plan.hasVirtualAddress();

        if (m_shadowEditor != nullptr)
        {
            m_shadowEditor->setEditable(baselineReady && idle);
        }
        if (m_recaptureBaselineButton != nullptr)
        {
            m_recaptureBaselineButton->setEnabled(m_plan.resolved && idle);
            m_recaptureBaselineButton->setToolTip(m_plan.resolved
                ? ks::i18n::sourceText(QStringLiteral("重新从目标物理页读回 4096 字节。重抓会丢弃当前所有改动。"))
                : ks::i18n::sourceText(QStringLiteral("第 1 步的目标还没有解析成功，没有可读的物理页。")));
        }
        if (m_revertPatchButton != nullptr)
        {
            m_revertPatchButton->setEnabled(
                baselineReady && idle && !m_plan.patchIsEmpty());
        }

        JumpTemplate selected = JumpTemplate::None;
        if (m_jumpTemplateBox != nullptr)
        {
            selected = static_cast<JumpTemplate>(
                m_jumpTemplateBox->currentData().toInt());
            m_jumpTemplateBox->setEnabled(baselineReady && idle && haveVirtual);
            m_jumpTemplateBox->setToolTip(haveVirtual
                ? ks::i18n::sourceText(QStringLiteral("模板会把编码好的字节写进下面指定的页内偏移。"))
                : ks::i18n::sourceText(QStringLiteral("这条入口没有虚拟地址，跳转模板不可用：近跳的位移要按源虚拟地址算，而直接给物理地址的路径上没有可信的源地址。")));
        }
        const bool jumpUsable =
            baselineReady && idle && haveVirtual && selected != JumpTemplate::None;
        if (m_jumpTargetEdit != nullptr)
        {
            m_jumpTargetEdit->setEnabled(jumpUsable);
        }
        if (m_applyJumpButton != nullptr)
        {
            m_applyJumpButton->setEnabled(jumpUsable);
        }
        QLineEdit* const jumpOffsetEdit =
            findChild<QLineEdit*>(QString::fromLatin1(kJumpOffsetEditName));
        if (jumpOffsetEdit != nullptr)
        {
            jumpOffsetEdit->setEnabled(jumpUsable);
        }

        QGroupBox* const pasteGroup =
            findChild<QGroupBox*>(QString::fromLatin1(kPasteGroupName));
        if (pasteGroup != nullptr)
        {
            pasteGroup->setEnabled(baselineReady && idle);
        }
    }
}
