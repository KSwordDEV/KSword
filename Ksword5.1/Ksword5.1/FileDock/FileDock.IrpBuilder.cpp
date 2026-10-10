#include "FileDock.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"

// ============================================================
// FileDock.IrpBuilder.cpp
// 作用：
// - 承载 FileDock "IRP 构造" 页：手工组装并向文件系统栈投递任意 IRP_MJ_*；
// - 参数区按当前 major 自动启停，避免把无关字段的残留值当成有效参数发下去；
// - 写语义与 PnP/电源类请求要求显式勾选确认，R0 侧还会再校验一次令牌；
// - 避免继续膨胀 FileDock.cpp 主文件。
// ============================================================

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"
#include "IrpFileSystemParser.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include "../UI/CodeTextEdit.h"
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <cstdint>
#include <thread>
#include <vector>

namespace
{
    // IrpOperationPresetId：把常见文件动作映射为一组可审阅的 IRP 参数。
    // 预设只填充界面，不直接执行；写语义的确认复选框仍由用户亲自勾选。
    enum IrpOperationPresetId
    {
        IrpPresetCustom = 0,
        IrpPresetQueryAllInformation,
        IrpPresetRead,
        IrpPresetWrite,
        IrpPresetFlush,
        IrpPresetCreateFile,
        IrpPresetCreateDirectory,
        IrpPresetEnumerateDirectory,
        IrpPresetDeleteLegacy,
        IrpPresetDeletePosix,
        IrpPresetTruncateZero,
        IrpPresetSetNormalAttributes,
        IrpPresetQueryVolume,
        IrpPresetQuerySecurity
    };

    // kIrpMajorNames 作用：
    // - 提供全部 28 个 IRP_MJ_* 的规范名称，索引即 major 数值；
    // - 名称与 WDK 定义逐一对应，便于把界面选项直接对照文档。
    const char* const kIrpMajorNames[] = {
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP"
    };

    // majorIsWriteLike 作用：
    // - 与 R0 侧 KswordArkFileIrpMajorIsWriteLike 保持同一判定；
    // - UI 据此强制勾选确认，避免用户在毫无提示的情况下改动磁盘。
    bool majorIsWriteLike(const int majorFunction)
    {
        switch (majorFunction)
        {
        case 0:   // IRP_MJ_CREATE（FILE_CREATE/OPEN_IF 等可能创建或覆盖目标）
        case 1:   // IRP_MJ_CREATE_NAMED_PIPE
        case 4:   // IRP_MJ_WRITE
        case 6:   // IRP_MJ_SET_INFORMATION
        case 8:   // IRP_MJ_SET_EA
        case 11:  // IRP_MJ_SET_VOLUME_INFORMATION
        case 13:  // IRP_MJ_FILE_SYSTEM_CONTROL
        case 14:  // IRP_MJ_DEVICE_CONTROL
        case 15:  // IRP_MJ_INTERNAL_DEVICE_CONTROL
        case 17:  // IRP_MJ_LOCK_CONTROL
        case 19:  // IRP_MJ_CREATE_MAILSLOT
        case 21:  // IRP_MJ_SET_SECURITY
        case 26:  // IRP_MJ_SET_QUOTA
            return true;
        default:
            return false;
        }
    }

    // majorIsDangerous 作用：
    // - 与 R0 侧 KswordArkFileIrpMajorIsDangerous 保持同一判定；
    // - 这些请求由 PnP/电源管理器按状态机下发，手工构造极易让目标驱动进入非法状态。
    bool majorIsDangerous(const int majorFunction)
    {
        switch (majorFunction)
        {
        case 16:  // IRP_MJ_SHUTDOWN
        case 22:  // IRP_MJ_POWER
        case 23:  // IRP_MJ_SYSTEM_CONTROL
        case 24:  // IRP_MJ_DEVICE_CHANGE
        case 27:  // IRP_MJ_PNP
            return true;
        default:
            return false;
        }
    }

    // statusHex 作用：统一把 NTSTATUS 格式化为固定八位十六进制。
    QString statusHex(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(
                static_cast<qulonglong>(static_cast<unsigned long>(statusValue)),
                8,
                16,
                QChar('0'))
            .toUpper();
    }

    // pointerHex 作用：把内核地址格式化为十六位十六进制，0 显示为占位符。
    QString pointerHex(const std::uint64_t addressValue)
    {
        if (addressValue == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar('0'))
            .toUpper();
    }

    // irpProtocolStatusText 作用：把协议级状态码翻译为可读结论。
    QString irpProtocolStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_FILE_IRP_STATUS_OK:
            return QStringLiteral("完成");
        case KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST:
            return QStringLiteral("请求参数被 R0 拒绝");
        case KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED:
            return QStringLiteral("目标打开失败");
        case KSWORD_ARK_FILE_IRP_STATUS_LAYER_UNAVAILABLE:
            return QStringLiteral("目标栈层不可用");
        case KSWORD_ARK_FILE_IRP_STATUS_ALLOC_FAILED:
            return QStringLiteral("内核内存不足");
        case KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED:
            return QStringLiteral("该 major 需要额外确认");
        case KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED:
            return QStringLiteral("缺少写入确认令牌");
        case KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT:
            return QStringLiteral("等待超时，请求已取消");
        case KSWORD_ARK_FILE_IRP_STATUS_IRP_FAILED:
            return QStringLiteral("IRP 构造失败");
        case KSWORD_ARK_FILE_IRP_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("输出缓冲不足");
        case KSWORD_ARK_FILE_IRP_STATUS_DENIED_BY_POLICY:
            return QStringLiteral("被安全策略拒绝");
        default:
            return QStringLiteral("未知状态(%1)").arg(statusValue);
        }
    }

    // irpStageText 作用：把阶段位图展开为可读列表，让"哪些阶段真的执行了"一目了然。
    QString irpStageText(const std::uint32_t stageFlags)
    {
        QStringList parts;
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CREATE) != 0U)
        {
            parts.append(QStringLiteral("CREATE"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OPERATION) != 0U)
        {
            parts.append(QStringLiteral("目标请求"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLEANUP) != 0U)
        {
            parts.append(QStringLiteral("CLEANUP"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLOSE) != 0U)
        {
            parts.append(QStringLiteral("CLOSE"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CANCELLED) != 0U)
        {
            parts.append(QStringLiteral("已取消"));
        }
        if ((stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED) != 0U)
        {
            parts.append(QStringLiteral("输出被截断"));
        }
        return parts.isEmpty() ? QStringLiteral("-") : parts.join(QStringLiteral(" / "));
    }

    // irpBuilderInputStyle / irpBuilderButtonStyle 作用：
    // - 与 FileDock 主文件的输入/按钮样式保持一致的主题化外观。
    QString irpBuilderInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QTextEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{"
            "  border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    QString irpBuilderButtonStyle()
    {
        return ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}");
    }
}

QString FileDock::irpMajorDisplayText(const int majorFunction)
{
    if (majorFunction < 0 ||
        majorFunction >= static_cast<int>(std::size(kIrpMajorNames)))
    {
        return QStringLiteral("0x%1  未知")
            .arg(majorFunction, 2, 16, QChar('0'));
    }
    return QStringLiteral("0x%1  %2")
        .arg(majorFunction, 2, 16, QChar('0'))
        .arg(QString::fromLatin1(kIrpMajorNames[majorFunction]));
}

bool FileDock::parseNumericField(
    const QString& text,
    unsigned long long& valueOut,
    QString& errorTextOut)
{
    valueOut = 0U;
    errorTextOut.clear();

    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty())
    {
        return true;
    }

    bool convertOk = false;
    if (trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        valueOut = trimmed.mid(2).toULongLong(&convertOk, 16);
    }
    else
    {
        valueOut = trimmed.toULongLong(&convertOk, 10);
        if (!convertOk)
        {
            // 没有 0x 前缀但含十六进制字符时，按十六进制再试一次，
            // 用户从 WDK 文档复制常量时经常不带前缀。
            valueOut = trimmed.toULongLong(&convertOk, 16);
        }
    }
    if (!convertOk)
    {
        errorTextOut = QStringLiteral("无法解析数值: %1").arg(trimmed);
        return false;
    }
    return true;
}

bool FileDock::parseHexPayload(
    const QString& text,
    std::vector<std::uint8_t>& bytesOut,
    QString& errorTextOut)
{
    bytesOut.clear();
    errorTextOut.clear();

    QString compact;
    compact.reserve(text.size());
    for (const QChar character : text)
    {
        if (character.isSpace() ||
            character == QChar(',') ||
            character == QChar('-'))
        {
            continue;
        }
        compact.append(character);
    }
    if (compact.isEmpty())
    {
        return true;
    }
    if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        compact = compact.mid(2);
    }
    if ((compact.size() % 2) != 0)
    {
        errorTextOut = QStringLiteral("十六进制输入必须是偶数个字符。");
        return false;
    }

    bytesOut.reserve(static_cast<std::size_t>(compact.size() / 2));
    for (int index = 0; index < compact.size(); index += 2)
    {
        bool convertOk = false;
        const unsigned int byteValue =
            compact.mid(index, 2).toUInt(&convertOk, 16);
        if (!convertOk)
        {
            errorTextOut = QStringLiteral("十六进制输入含非法字符: %1")
                .arg(compact.mid(index, 2));
            bytesOut.clear();
            return false;
        }
        bytesOut.push_back(static_cast<std::uint8_t>(byteValue));
    }
    return true;
}

QString FileDock::formatHexDump(const std::vector<std::uint8_t>& data)
{
    if (data.empty())
    {
        return QStringLiteral("(无输出数据)");
    }

    QString dumpText;
    dumpText.reserve(static_cast<int>(data.size() * 4 + 64));
    for (std::size_t offset = 0U; offset < data.size(); offset += 16U)
    {
        QString hexPart;
        QString asciiPart;
        for (std::size_t column = 0U; column < 16U; ++column)
        {
            if (offset + column >= data.size())
            {
                hexPart += QStringLiteral("   ");
                continue;
            }
            const std::uint8_t byteValue = data[offset + column];
            hexPart += QStringLiteral("%1 ")
                .arg(byteValue, 2, 16, QChar('0')).toUpper();
            asciiPart += (byteValue >= 0x20U && byteValue < 0x7FU)
                ? QChar(static_cast<char>(byteValue))
                : QChar('.');
        }
        dumpText += QStringLiteral("%1  %2 |%3|\n")
            .arg(static_cast<qulonglong>(offset), 8, 16, QChar('0'))
            .arg(hexPart)
            .arg(asciiPart);
    }
    return dumpText;
}

void FileDock::initializeIrpBuilderPage()
{
    m_irpBuilderPage = new QWidget(m_rootTabWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_irpBuilderPage);
    pageLayout->setContentsMargins(6, 6, 6, 6);
    pageLayout->setSpacing(6);

    const QString inputStyle = irpBuilderInputStyle();
    const QString buttonStyle = irpBuilderButtonStyle();

    // ---------- 目标与请求头 ----------
    QGroupBox* targetGroup = new QGroupBox(
        QStringLiteral("目标与请求"),
        m_irpBuilderPage);
    QGridLayout* targetLayout = new QGridLayout(targetGroup);
    targetLayout->setContentsMargins(8, 8, 8, 8);
    targetLayout->setHorizontalSpacing(8);
    targetLayout->setVerticalSpacing(6);

    m_irpPathEdit = new QLineEdit(targetGroup);
    m_irpPathEdit->setPlaceholderText(
        QStringLiteral("目标路径，例如 C:\\Windows 或 \\??\\C:\\Windows\\notepad.exe"));
    m_irpPathEdit->setStyleSheet(inputStyle);
    m_irpPathEdit->setToolTip(QStringLiteral(
        "Win32 路径会自动转换为 \\??\\ 命名空间路径；也可直接填 NT 路径。"));

    m_irpOperationPresetCombo = new QComboBox(targetGroup);
    m_irpOperationPresetCombo->setStyleSheet(inputStyle);
    m_irpOperationPresetCombo->addItem(QStringLiteral("自定义（手工参数）"), IrpPresetCustom);
    m_irpOperationPresetCombo->addItem(QStringLiteral("查询文件全部信息"), IrpPresetQueryAllInformation);
    m_irpOperationPresetCombo->addItem(QStringLiteral("读取文件"), IrpPresetRead);
    m_irpOperationPresetCombo->addItem(QStringLiteral("写入文件（填写下方十六进制数据）"), IrpPresetWrite);
    m_irpOperationPresetCombo->addItem(QStringLiteral("刷新文件缓冲"), IrpPresetFlush);
    m_irpOperationPresetCombo->addItem(QStringLiteral("创建空文件"), IrpPresetCreateFile);
    m_irpOperationPresetCombo->addItem(QStringLiteral("创建目录"), IrpPresetCreateDirectory);
    m_irpOperationPresetCombo->addItem(QStringLiteral("枚举目录"), IrpPresetEnumerateDirectory);
    m_irpOperationPresetCombo->addItem(QStringLiteral("删除（FileDispositionInformation）"), IrpPresetDeleteLegacy);
    m_irpOperationPresetCombo->addItem(QStringLiteral("删除（POSIX / FileDispositionInformationEx）"), IrpPresetDeletePosix);
    m_irpOperationPresetCombo->addItem(QStringLiteral("截断为 0 字节"), IrpPresetTruncateZero);
    m_irpOperationPresetCombo->addItem(QStringLiteral("设置基本属性为 NORMAL"), IrpPresetSetNormalAttributes);
    m_irpOperationPresetCombo->addItem(QStringLiteral("查询卷属性"), IrpPresetQueryVolume);
    m_irpOperationPresetCombo->addItem(QStringLiteral("查询安全描述符"), IrpPresetQuerySecurity);
    m_irpOperationPresetCombo->setToolTip(QStringLiteral(
        "选择常用操作后自动填写 Major、访问权、InformationClass 与输入结构。预设只填参数、不自动发送；写操作仍需显式勾选确认。"));

    QPushButton* browseButton = new QPushButton(
        QStringLiteral("浏览..."),
        targetGroup);
    browseButton->setStyleSheet(buttonStyle);
    ks::ui::NormalizeToolbarControl(browseButton);

    m_irpMajorCombo = new QComboBox(targetGroup);
    m_irpMajorCombo->setStyleSheet(inputStyle);
    for (int majorIndex = 0;
         majorIndex < static_cast<int>(std::size(kIrpMajorNames));
         ++majorIndex)
    {
        m_irpMajorCombo->addItem(irpMajorDisplayText(majorIndex), majorIndex);
    }
    m_irpMajorCombo->setToolTip(QStringLiteral(
        "选择要构造的 IRP 主功能码。参数区会按所选 major 自动启停。"));

    m_irpMinorEdit = new QLineEdit(targetGroup);
    m_irpMinorEdit->setStyleSheet(inputStyle);
    m_irpMinorEdit->setPlaceholderText(QStringLiteral("0"));
    m_irpMinorEdit->setToolTip(QStringLiteral(
        "IRP_MN_* 次功能码，十进制或 0x 前缀十六进制；不适用时填 0。"));

    m_irpLayerCombo = new QComboBox(targetGroup);
    m_irpLayerCombo->setStyleSheet(inputStyle);
    m_irpLayerCombo->addItem(
        QStringLiteral("设备栈顶（等价 Zw* 路径，作为对照基线）"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_RELATED));
    m_irpLayerCombo->addItem(
        QStringLiteral("基础文件系统设备（跳过其上的过滤层）"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_BASE_FS));
    m_irpLayerCombo->addItem(
        QStringLiteral("VPB 挂载文件系统设备"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_VPB_FS));
    m_irpLayerCombo->addItem(
        QStringLiteral("卷设备本身"),
        static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_DEVICE));
    m_irpLayerCombo->setCurrentIndex(1);
    m_irpLayerCombo->setToolTip(QStringLiteral(
        "选择 IRP 投递到设备栈的哪一层。\n"
        "选择非栈顶时，连 IRP_MJ_CREATE 都由 R0 自行构造并直发，不经过过滤层。\n"
        "注意：手工构造的文件对象缺少 I/O 管理器建立的完整关联，NTFS 在后续\n"
        "目录查询等操作上可能回 STATUS_INVALID_PARAMETER，这属于预期现象；\n"
        "只想绕过目录查询请改用文件页的“R0 IRP 解析”读取方式。\n"
        "目标层不可用时 R0 会回退到栈顶，并在结果里如实标出实际生效的层。"));

    m_irpTimeoutEdit = new QLineEdit(targetGroup);
    m_irpTimeoutEdit->setStyleSheet(inputStyle);
    m_irpTimeoutEdit->setPlaceholderText(QStringLiteral("10000"));
    m_irpTimeoutEdit->setToolTip(QStringLiteral(
        "等待完成的毫秒数，上限 60000；超时后 R0 会取消 IRP 并等待其排空。"));

    int targetRow = 0;
    targetLayout->addWidget(new QLabel(QStringLiteral("常用操作:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(m_irpOperationPresetCombo, targetRow, 1, 1, 5);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("目标路径:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(m_irpPathEdit, targetRow, 1, 1, 4);
    targetLayout->addWidget(browseButton, targetRow, 5);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("MajorFunction:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(m_irpMajorCombo, targetRow, 1, 1, 2);
    targetLayout->addWidget(new QLabel(QStringLiteral("MinorFunction:"), targetGroup), targetRow, 3);
    targetLayout->addWidget(m_irpMinorEdit, targetRow, 4, 1, 2);
    ++targetRow;
    targetLayout->addWidget(new QLabel(QStringLiteral("目标栈层:"), targetGroup), targetRow, 0);
    targetLayout->addWidget(m_irpLayerCombo, targetRow, 1, 1, 2);
    targetLayout->addWidget(new QLabel(QStringLiteral("超时(ms):"), targetGroup), targetRow, 3);
    targetLayout->addWidget(m_irpTimeoutEdit, targetRow, 4, 1, 2);
    targetLayout->setColumnStretch(1, 1);
    targetLayout->setColumnStretch(4, 1);
    pageLayout->addWidget(targetGroup, 0);

    // ---------- 参数区 ----------
    QGroupBox* parameterGroup = new QGroupBox(
        QStringLiteral("IO_STACK_LOCATION 参数"),
        m_irpBuilderPage);
    QGridLayout* parameterLayout = new QGridLayout(parameterGroup);
    parameterLayout->setContentsMargins(8, 8, 8, 8);
    parameterLayout->setHorizontalSpacing(8);
    parameterLayout->setVerticalSpacing(6);

    const auto makeParameterEdit =
        [&](const QString& placeholderText, const QString& tipText)
        {
            QLineEdit* edit = new QLineEdit(parameterGroup);
            edit->setStyleSheet(inputStyle);
            edit->setPlaceholderText(placeholderText);
            edit->setToolTip(tipText);
            return edit;
        };

    m_irpDesiredAccessEdit = makeParameterEdit(
        QStringLiteral("0x00000080"),
        QStringLiteral("CREATE 阶段 ACCESS_MASK；留空时按只读属性访问打开。"));
    m_irpShareAccessEdit = makeParameterEdit(
        QStringLiteral("0x00000007"),
        QStringLiteral("CREATE 阶段共享位；留空时按读/写/删除全共享打开。"));
    m_irpCreateDispositionEdit = makeParameterEdit(
        QStringLiteral("1 (FILE_OPEN)"),
        QStringLiteral("CREATE 处置方式：1=FILE_OPEN，2=FILE_CREATE，3=FILE_OPEN_IF 等。"));
    m_irpCreateOptionsEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("CREATE 选项位；R0 会额外补上同步与备份语义。"));
    m_irpFileAttributesEdit = makeParameterEdit(
        QStringLiteral("0x00000080"),
        QStringLiteral("CREATE 文件属性；留空按 FILE_ATTRIBUTE_NORMAL。"));
    m_irpInformationClassEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral(
            "信息类：QUERY/SET_INFORMATION 用 FILE_INFORMATION_CLASS，\n"
            "QUERY/SET_VOLUME_INFORMATION 用 FS_INFORMATION_CLASS，\n"
            "DIRECTORY_CONTROL 用目录信息类，POWER 复用为目标电源状态。"));
    m_irpControlCodeEdit = makeParameterEdit(
        QStringLiteral("0x00090000"),
        QStringLiteral("DEVICE_CONTROL/FILE_SYSTEM_CONTROL 的控制码，低两位决定缓冲方式。"));
    m_irpSecurityInformationEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("QUERY/SET_SECURITY 的 SECURITY_INFORMATION 位。"));
    m_irpByteOffsetEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("READ/WRITE/LOCK_CONTROL 的起始字节偏移。"));
    m_irpLockKeyEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("READ/WRITE 的 Key，或 LOCK_CONTROL 的锁 Key。"));
    m_irpLockLengthEdit = makeParameterEdit(
        QStringLiteral("0"),
        QStringLiteral("LOCK_CONTROL 的加锁字节数。"));
    m_irpOutputBytesEdit = makeParameterEdit(
        QStringLiteral("4096"),
        QStringLiteral("期望的输出缓冲长度，上限 256 KiB。"));
    m_irpPatternEdit = makeParameterEdit(
        QStringLiteral("*"),
        QStringLiteral("DIRECTORY_CONTROL 的文件名通配符，留空表示不限定。"));

    const auto addParameterRow =
        [&](int row, int column, const QString& labelText, QWidget* editWidget)
        {
            parameterLayout->addWidget(
                new QLabel(labelText, parameterGroup), row, column * 2);
            parameterLayout->addWidget(editWidget, row, column * 2 + 1);
        };

    addParameterRow(0, 0, QStringLiteral("DesiredAccess:"), m_irpDesiredAccessEdit);
    addParameterRow(0, 1, QStringLiteral("ShareAccess:"), m_irpShareAccessEdit);
    addParameterRow(0, 2, QStringLiteral("CreateDisposition:"), m_irpCreateDispositionEdit);
    addParameterRow(1, 0, QStringLiteral("CreateOptions:"), m_irpCreateOptionsEdit);
    addParameterRow(1, 1, QStringLiteral("FileAttributes:"), m_irpFileAttributesEdit);
    addParameterRow(1, 2, QStringLiteral("InformationClass:"), m_irpInformationClassEdit);
    addParameterRow(2, 0, QStringLiteral("ControlCode:"), m_irpControlCodeEdit);
    addParameterRow(2, 1, QStringLiteral("SecurityInformation:"), m_irpSecurityInformationEdit);
    addParameterRow(2, 2, QStringLiteral("ByteOffset:"), m_irpByteOffsetEdit);
    addParameterRow(3, 0, QStringLiteral("Key:"), m_irpLockKeyEdit);
    addParameterRow(3, 1, QStringLiteral("LockLength:"), m_irpLockLengthEdit);
    addParameterRow(3, 2, QStringLiteral("OutputBytes:"), m_irpOutputBytesEdit);
    addParameterRow(4, 0, QStringLiteral("FileName 通配符:"), m_irpPatternEdit);
    for (int column = 0; column < 3; ++column)
    {
        parameterLayout->setColumnStretch(column * 2 + 1, 1);
    }
    pageLayout->addWidget(parameterGroup, 0);

    // ---------- 标志与输入数据 ----------
    QGroupBox* optionGroup = new QGroupBox(
        QStringLiteral("标志与输入数据"),
        m_irpBuilderPage);
    QVBoxLayout* optionLayout = new QVBoxLayout(optionGroup);
    optionLayout->setContentsMargins(8, 8, 8, 8);
    optionLayout->setSpacing(6);

    QHBoxLayout* flagLayout = new QHBoxLayout();
    flagLayout->setContentsMargins(0, 0, 0, 0);
    flagLayout->setSpacing(12);

    m_irpConfirmCheck = new QCheckBox(
        QStringLiteral("确认写入语义"),
        optionGroup);
    m_irpConfirmCheck->setToolTip(QStringLiteral(
        "写类 major 必须勾选；勾选后客户端才会附带确认令牌，R0 会二次校验。"));

    m_irpAllowDangerousCheck = new QCheckBox(
        QStringLiteral("允许 PnP/电源类请求"),
        optionGroup);
    m_irpAllowDangerousCheck->setToolTip(QStringLiteral(
        "IRP_MJ_POWER/PNP/SHUTDOWN/SYSTEM_CONTROL/DEVICE_CHANGE 需要额外勾选。\n"
        "这些请求正常由系统按状态机下发，手工构造可能让目标驱动进入非法状态。"));

    m_irpCreateOnlyCheck = new QCheckBox(
        QStringLiteral("只执行 CREATE"),
        optionGroup);
    m_irpCreateOnlyCheck->setToolTip(QStringLiteral(
        "只验证打开阶段，不再下发目标 major，用于单独观察 CREATE 是否被拦截。"));

    m_irpRestartScanCheck = new QCheckBox(
        QStringLiteral("SL_RESTART_SCAN"),
        optionGroup);
    m_irpSingleEntryCheck = new QCheckBox(
        QStringLiteral("SL_RETURN_SINGLE_ENTRY"),
        optionGroup);
    m_irpReparseCheck = new QCheckBox(
        QStringLiteral("FILE_OPEN_REPARSE_POINT"),
        optionGroup);
    m_irpDirectoryIntentCheck = new QCheckBox(
        QStringLiteral("FILE_DIRECTORY_FILE"),
        optionGroup);

    flagLayout->addWidget(m_irpConfirmCheck, 0);
    flagLayout->addWidget(m_irpAllowDangerousCheck, 0);
    flagLayout->addWidget(m_irpCreateOnlyCheck, 0);
    flagLayout->addWidget(m_irpRestartScanCheck, 0);
    flagLayout->addWidget(m_irpSingleEntryCheck, 0);
    flagLayout->addWidget(m_irpReparseCheck, 0);
    flagLayout->addWidget(m_irpDirectoryIntentCheck, 0);
    flagLayout->addStretch(1);
    optionLayout->addLayout(flagLayout, 0);

    auto* inputHexEditor = new CodeTextEdit(optionGroup);
    inputHexEditor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    inputHexEditor->setLineNumbersVisible(false);
    inputHexEditor->setCompactMode(true);
    m_irpInputHexEdit = inputHexEditor;
    m_irpInputHexEdit->setStyleSheet(inputStyle);
    m_irpInputHexEdit->setPlaceholderText(
        QStringLiteral("内联输入数据，十六进制，例如 01 00 00 00；留空表示无输入。"));
    m_irpInputHexEdit->setMaximumHeight(80);
    m_irpInputHexEdit->setToolTip(QStringLiteral(
        "作为 IRP 数据段的输入内容，上限 64 KiB。\n"
        "空白、逗号和短横线会被忽略，方便直接粘贴各种转储格式。"));
    optionLayout->addWidget(m_irpInputHexEdit, 0);
    pageLayout->addWidget(optionGroup, 0);

    // ---------- 发送与结果 ----------
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(8);

    m_irpSendButton = new QPushButton(
        QStringLiteral("构造并发送 IRP"),
        m_irpBuilderPage);
    m_irpSendButton->setStyleSheet(buttonStyle);
    // 原始 IRP 发送维持危险动作提示与原确认流程。
    ks::ui::ApplyFlatButtonTheme(m_irpSendButton, ks::ui::FlatButtonTone::Danger);
    m_irpSendButton->setMinimumHeight(30);

    m_irpStatusLabel = new QLabel(
        QStringLiteral("尚未发送。写类与 PnP/电源类请求需要先勾选对应确认项。"),
        m_irpBuilderPage);
    m_irpStatusLabel->setWordWrap(true);

    actionLayout->addWidget(m_irpSendButton, 0);
    actionLayout->addWidget(m_irpStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(actionLayout);
    pageLayout->addLayout(actionLayout, 0);

    QSplitter* resultSplitter = new QSplitter(Qt::Horizontal, m_irpBuilderPage);
    resultSplitter->setChildrenCollapsible(false);

    m_irpResultTable = new ks::ui::VisibleTableWidget(resultSplitter);
    // 一次 IRP 回执是字段/值报告，原右键复制足够，不显示快照栏。
    ks::ui::SetTableActionBarMode(m_irpResultTable, ks::ui::TableActionBarMode::None);
    m_irpResultTable->setColumnCount(2);
    m_irpResultTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("项目"),
        QStringLiteral("值") });
    m_irpResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_irpResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_irpResultTable->verticalHeader()->setVisible(false);
    m_irpResultTable->horizontalHeader()->setStretchLastSection(true);
    m_irpResultTable->setAlternatingRowColors(true);

    m_irpOutputHexEdit = new CodeTextEdit(resultSplitter);
    static_cast<CodeTextEdit*>(m_irpOutputHexEdit)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    m_irpOutputHexEdit->setStyleSheet(inputStyle);
    m_irpOutputHexEdit->setReadOnly(true);
    m_irpOutputHexEdit->setPlaceholderText(
        QStringLiteral("目标驱动写回的数据将以十六进制转储显示。"));

    resultSplitter->addWidget(m_irpResultTable);
    resultSplitter->addWidget(m_irpOutputHexEdit);
    resultSplitter->setStretchFactor(0, 1);
    resultSplitter->setStretchFactor(1, 1);
    pageLayout->addWidget(resultSplitter, 1);

    connect(browseButton, &QPushButton::clicked, this, [this]() {
        const QString selectedPath = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("选择 IRP 目标文件"),
            m_irpPathEdit->text().trimmed());
        if (!selectedPath.isEmpty())
        {
            m_irpPathEdit->setText(QDir::toNativeSeparators(selectedPath));
        }
    });
    connect(m_irpOperationPresetCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        applyIrpOperationPreset(m_irpOperationPresetCombo->currentData().toInt());
    });
    connect(m_irpMajorCombo, &QComboBox::currentIndexChanged, this, [this](int) {
        applyIrpMajorPreset(m_irpMajorCombo->currentData().toInt());
        if (m_irpOperationPresetCombo != nullptr &&
            m_irpOperationPresetCombo->currentData().toInt() != IrpPresetCustom)
        {
            const QSignalBlocker blocker(m_irpOperationPresetCombo);
            m_irpOperationPresetCombo->setCurrentIndex(0);
        }
    });
    connect(m_irpSendButton, &QPushButton::clicked, this, [this]() {
        submitConstructedIrp();
    });

    applyIrpMajorPreset(0);
}

void FileDock::applyIrpOperationPreset(const int presetId)
{
    // “自定义”只解除预设标记，不清空用户当前正在编辑的参数。
    if (presetId == IrpPresetCustom || m_irpMajorCombo == nullptr)
    {
        return;
    }

    const auto setEditText = [](QLineEdit* edit, const QString& text) {
        if (edit != nullptr)
        {
            edit->setText(text);
        }
    };
    const auto selectMajor = [this](const int majorFunction) {
        const QSignalBlocker blocker(m_irpMajorCombo);
        const int comboIndex = m_irpMajorCombo->findData(majorFunction);
        if (comboIndex >= 0)
        {
            m_irpMajorCombo->setCurrentIndex(comboIndex);
        }
        applyIrpMajorPreset(majorFunction);
    };

    // 先恢复一套保守、可审阅的 CREATE 基线，再按具体动作覆盖。所有预设固定从
    // RELATED 栈顶进入；用户仍可在填参后主动改成 BASE_FS/VPB/DEVICE 做差异实验。
    setEditText(m_irpMinorEdit, QStringLiteral("0"));
    setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100080"));
    setEditText(m_irpShareAccessEdit, QStringLiteral("0x00000007"));
    setEditText(m_irpCreateDispositionEdit, QStringLiteral("1"));
    setEditText(m_irpCreateOptionsEdit, QStringLiteral("0x00000040"));
    setEditText(m_irpFileAttributesEdit, QStringLiteral("0x00000080"));
    setEditText(m_irpInformationClassEdit, QStringLiteral("0"));
    setEditText(m_irpControlCodeEdit, QStringLiteral("0"));
    setEditText(m_irpSecurityInformationEdit, QStringLiteral("0"));
    setEditText(m_irpByteOffsetEdit, QStringLiteral("0"));
    setEditText(m_irpLockKeyEdit, QStringLiteral("0"));
    setEditText(m_irpLockLengthEdit, QStringLiteral("0"));
    setEditText(m_irpOutputBytesEdit, QStringLiteral("0"));
    setEditText(m_irpTimeoutEdit, QStringLiteral("10000"));
    setEditText(m_irpPatternEdit, QString());
    if (m_irpInputHexEdit != nullptr)
    {
        m_irpInputHexEdit->clear();
    }
    if (m_irpLayerCombo != nullptr)
    {
        const int relatedIndex = m_irpLayerCombo->findData(
            static_cast<unsigned int>(KSWORD_ARK_FILE_IRP_LAYER_RELATED));
        if (relatedIndex >= 0)
        {
            m_irpLayerCombo->setCurrentIndex(relatedIndex);
        }
    }
    m_irpConfirmCheck->setChecked(false);
    m_irpAllowDangerousCheck->setChecked(false);
    m_irpCreateOnlyCheck->setChecked(false);
    m_irpRestartScanCheck->setChecked(false);
    m_irpSingleEntryCheck->setChecked(false);
    m_irpReparseCheck->setChecked(true);
    m_irpDirectoryIntentCheck->setChecked(false);

    QString presetHintText;
    switch (presetId)
    {
    case IrpPresetQueryAllInformation:
        selectMajor(5); // IRP_MJ_QUERY_INFORMATION
        setEditText(m_irpInformationClassEdit, QStringLiteral("18")); // FileAllInformation
        setEditText(m_irpOutputBytesEdit, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入查询 FileAllInformation 的安全栈顶预设。");
        break;
    case IrpPresetRead:
        selectMajor(3); // IRP_MJ_READ
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100001"));
        setEditText(m_irpOutputBytesEdit, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入从偏移 0 读取 4096 字节的预设，可修改偏移与长度。");
        break;
    case IrpPresetWrite:
        selectMajor(4); // IRP_MJ_WRITE
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100002"));
        presetHintText = QStringLiteral("已填入写入预设；请在下方填写十六进制数据，并勾选写入确认。");
        break;
    case IrpPresetFlush:
        selectMajor(9); // IRP_MJ_FLUSH_BUFFERS
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100002"));
        presetHintText = QStringLiteral("已填入刷新文件缓冲预设。");
        break;
    case IrpPresetCreateFile:
        selectMajor(0); // IRP_MJ_CREATE
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100182"));
        setEditText(m_irpCreateDispositionEdit, QStringLiteral("2")); // FILE_CREATE
        m_irpReparseCheck->setChecked(false);
        presetHintText = QStringLiteral("已填入 FILE_CREATE 空文件预设；目标必须不存在，并需勾选写入确认。");
        break;
    case IrpPresetCreateDirectory:
        selectMajor(0); // IRP_MJ_CREATE
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100181"));
        setEditText(m_irpCreateDispositionEdit, QStringLiteral("2")); // FILE_CREATE
        setEditText(m_irpCreateOptionsEdit, QStringLiteral("0"));
        m_irpReparseCheck->setChecked(false);
        m_irpDirectoryIntentCheck->setChecked(true);
        presetHintText = QStringLiteral("已填入 FILE_CREATE 目录预设；目标必须不存在，并需勾选写入确认。");
        break;
    case IrpPresetEnumerateDirectory:
        selectMajor(12); // IRP_MJ_DIRECTORY_CONTROL
        setEditText(m_irpMinorEdit, QStringLiteral("1")); // IRP_MN_QUERY_DIRECTORY
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100081"));
        setEditText(m_irpCreateOptionsEdit, QStringLiteral("0"));
        setEditText(m_irpInformationClassEdit, QStringLiteral("37")); // FileIdBothDirectoryInformation
        setEditText(m_irpOutputBytesEdit, QStringLiteral("65536"));
        setEditText(m_irpPatternEdit, QStringLiteral("*"));
        m_irpRestartScanCheck->setChecked(true);
        m_irpDirectoryIntentCheck->setChecked(true);
        presetHintText = QStringLiteral("已填入 FileIdBothDirectoryInformation 目录枚举预设。");
        break;
    case IrpPresetDeleteLegacy:
        selectMajor(6); // IRP_MJ_SET_INFORMATION
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00110000"));
        setEditText(m_irpInformationClassEdit, QStringLiteral("13")); // FileDispositionInformation
        m_irpInputHexEdit->setPlainText(QStringLiteral("01")); // BOOLEAN DeleteFile
        presetHintText = QStringLiteral("已填入传统 IRP 删除预设；目录目标需另勾 FILE_DIRECTORY_FILE，并需写入确认。");
        break;
    case IrpPresetDeletePosix:
        selectMajor(6); // IRP_MJ_SET_INFORMATION
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00110000"));
        setEditText(m_irpInformationClassEdit, QStringLiteral("64")); // FileDispositionInformationEx
        // DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
        m_irpInputHexEdit->setPlainText(QStringLiteral("13 00 00 00"));
        presetHintText = QStringLiteral("已填入 IRP POSIX 删除预设；支持情况取决于系统与文件系统，并需写入确认。");
        break;
    case IrpPresetTruncateZero:
        selectMajor(6); // IRP_MJ_SET_INFORMATION
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100002"));
        setEditText(m_irpInformationClassEdit, QStringLiteral("20")); // FileEndOfFileInformation
        m_irpInputHexEdit->setPlainText(QStringLiteral("00 00 00 00 00 00 00 00"));
        presetHintText = QStringLiteral("已填入 FileEndOfFileInformation 截断到 0 字节预设，并需写入确认。");
        break;
    case IrpPresetSetNormalAttributes:
        selectMajor(6); // IRP_MJ_SET_INFORMATION
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00100100"));
        setEditText(m_irpInformationClassEdit, QStringLiteral("4")); // FileBasicInformation
        // 四个时间戳保持为 0（不修改），FileAttributes=FILE_ATTRIBUTE_NORMAL，末尾为 x64 对齐。
        m_irpInputHexEdit->setPlainText(QStringLiteral(
            "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00\n"
            "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00\n"
            "80 00 00 00 00 00 00 00"));
        presetHintText = QStringLiteral("已填入 FileBasicInformation 的 NORMAL 属性模板，并需写入确认。");
        break;
    case IrpPresetQueryVolume:
        selectMajor(10); // IRP_MJ_QUERY_VOLUME_INFORMATION
        setEditText(m_irpInformationClassEdit, QStringLiteral("5")); // FileFsAttributeInformation
        setEditText(m_irpOutputBytesEdit, QStringLiteral("1024"));
        presetHintText = QStringLiteral("已填入 FileFsAttributeInformation 卷属性查询预设。");
        break;
    case IrpPresetQuerySecurity:
        selectMajor(20); // IRP_MJ_QUERY_SECURITY
        setEditText(m_irpDesiredAccessEdit, QStringLiteral("0x00120080"));
        setEditText(m_irpSecurityInformationEdit, QStringLiteral("0x00000007"));
        setEditText(m_irpOutputBytesEdit, QStringLiteral("4096"));
        presetHintText = QStringLiteral("已填入所有者、组与 DACL 安全描述符查询预设。");
        break;
    default:
        return;
    }

    if (m_irpStatusLabel != nullptr)
    {
        m_irpStatusLabel->setText(presetHintText);
    }
}

void FileDock::applyIrpMajorPreset(const int majorFunction)
{
    if (m_irpMajorCombo == nullptr)
    {
        return;
    }

    // 每个 major 只启用自己定义的字段。禁用而不是清空，用户切回来时仍能看到
    // 上次填的值；提交时只读取启用中的字段，禁用字段的残留值不会被发下去。
    const bool isCreateLike = (majorFunction == 0 || majorFunction == 1 || majorFunction == 19);
    const bool isReadWrite = (majorFunction == 3 || majorFunction == 4);
    const bool isFileInfo = (majorFunction == 5 || majorFunction == 6);
    const bool isEa = (majorFunction == 7 || majorFunction == 8);
    const bool isVolumeInfo = (majorFunction == 10 || majorFunction == 11);
    const bool isDirectory = (majorFunction == 12);
    const bool isControlCode = (majorFunction == 13 || majorFunction == 14 || majorFunction == 15);
    const bool isLock = (majorFunction == 17);
    const bool isSecurity = (majorFunction == 20 || majorFunction == 21);
    const bool isQuota = (majorFunction == 25 || majorFunction == 26);
    const bool isPower = (majorFunction == 22);

    // CREATE 参数对每个 major 都有意义：目标必须先被打开，才谈得上发后续请求。
    m_irpDesiredAccessEdit->setEnabled(true);
    m_irpShareAccessEdit->setEnabled(true);
    m_irpCreateDispositionEdit->setEnabled(true);
    m_irpCreateOptionsEdit->setEnabled(true);
    m_irpFileAttributesEdit->setEnabled(true);
    m_irpReparseCheck->setEnabled(true);
    m_irpDirectoryIntentCheck->setEnabled(true);

    m_irpInformationClassEdit->setEnabled(
        isFileInfo || isVolumeInfo || isDirectory || isPower);
    m_irpControlCodeEdit->setEnabled(isControlCode);
    m_irpSecurityInformationEdit->setEnabled(isSecurity);
    m_irpByteOffsetEdit->setEnabled(isReadWrite || isLock);
    m_irpLockKeyEdit->setEnabled(isReadWrite || isLock);
    m_irpLockLengthEdit->setEnabled(isLock);
    m_irpPatternEdit->setEnabled(isDirectory);
    m_irpRestartScanCheck->setEnabled(isDirectory);
    m_irpSingleEntryCheck->setEnabled(isDirectory);
    m_irpOutputBytesEdit->setEnabled(
        isReadWrite || isFileInfo || isEa || isVolumeInfo || isDirectory ||
        isControlCode || isSecurity || isQuota);
    m_irpInputHexEdit->setEnabled(
        isReadWrite || isFileInfo || isEa || isVolumeInfo || isControlCode ||
        isSecurity || isQuota);
    m_irpCreateOnlyCheck->setEnabled(!isCreateLike);
    m_irpMinorEdit->setEnabled(!isCreateLike);

    // 常用默认值：只在字段当前为空时填，避免覆盖用户已经输入的内容。
    const auto setDefaultIfEmpty =
        [](QLineEdit* edit, const QString& defaultText)
        {
            if (edit != nullptr && edit->text().trimmed().isEmpty())
            {
                edit->setText(defaultText);
            }
        };

    if (isDirectory)
    {
        // 默认 FileIdBothDirectoryInformation(37) + QUERY_DIRECTORY(1)，
        // 与 R0 目录枚举链路使用同一信息类，方便逐行对照。
        setDefaultIfEmpty(m_irpInformationClassEdit, QStringLiteral("37"));
        setDefaultIfEmpty(m_irpMinorEdit, QStringLiteral("1"));
        setDefaultIfEmpty(m_irpOutputBytesEdit, QStringLiteral("65536"));
        m_irpDirectoryIntentCheck->setChecked(true);
    }
    else if (isFileInfo)
    {
        // FileAllInformation(18) 是排查文件对象状态时最常用的信息类。
        setDefaultIfEmpty(m_irpInformationClassEdit, QStringLiteral("18"));
        setDefaultIfEmpty(m_irpOutputBytesEdit, QStringLiteral("4096"));
    }
    else if (isVolumeInfo)
    {
        // FileFsAttributeInformation(5)。
        setDefaultIfEmpty(m_irpInformationClassEdit, QStringLiteral("5"));
        setDefaultIfEmpty(m_irpOutputBytesEdit, QStringLiteral("1024"));
    }
    else if (isReadWrite)
    {
        setDefaultIfEmpty(m_irpOutputBytesEdit, QStringLiteral("4096"));
    }

    // 写语义与危险 major 的勾选要求直接反映到界面提示上。
    const bool writeLike = majorIsWriteLike(majorFunction);
    const bool dangerous = majorIsDangerous(majorFunction);
    // CREATE 阶段的 disposition/options 也可能让“查询类 major”创建或删除目标，
    // 因此确认项始终可操作；真正是否必选由提交前预检与 R0 双重判定。
    m_irpConfirmCheck->setEnabled(true);
    m_irpAllowDangerousCheck->setEnabled(dangerous);
    if (!writeLike && !dangerous)
    {
        m_irpConfirmCheck->setChecked(false);
    }
    if (!dangerous)
    {
        m_irpAllowDangerousCheck->setChecked(false);
    }

    if (m_irpStatusLabel != nullptr)
    {
        if (dangerous)
        {
            m_irpStatusLabel->setText(QStringLiteral(
                "%1 由 PnP/电源管理器按状态机下发，手工构造可能让目标驱动进入非法状态；"
                "需要同时勾选写入确认与 PnP/电源允许项。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
        else if (writeLike)
        {
            m_irpStatusLabel->setText(QStringLiteral(
                "%1 属于写语义，会改变磁盘或设备状态；需要勾选写入确认。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
        else
        {
            m_irpStatusLabel->setText(QStringLiteral(
                "%1 为只读语义，可直接发送。")
                .arg(irpMajorDisplayText(majorFunction)));
        }
    }
}

void FileDock::updateIrpBuilderEnabledState(const bool submitting)
{
    m_irpSubmitInProgress = submitting;
    if (m_irpSendButton != nullptr)
    {
        m_irpSendButton->setEnabled(!submitting);
        m_irpSendButton->setText(submitting
            ? QStringLiteral("正在发送...")
            : QStringLiteral("构造并发送 IRP"));
    }
    if (m_irpMajorCombo != nullptr)
    {
        m_irpMajorCombo->setEnabled(!submitting);
    }
    if (m_irpOperationPresetCombo != nullptr)
    {
        m_irpOperationPresetCombo->setEnabled(!submitting);
    }
    if (m_irpLayerCombo != nullptr)
    {
        m_irpLayerCombo->setEnabled(!submitting);
    }
    if (m_irpPathEdit != nullptr)
    {
        m_irpPathEdit->setEnabled(!submitting);
    }
}

void FileDock::submitConstructedIrp()
{
    if (m_irpSubmitInProgress)
    {
        return;
    }
    if (m_irpPathEdit == nullptr || m_irpMajorCombo == nullptr)
    {
        return;
    }

    const QString rawPath = m_irpPathEdit->text().trimmed();
    if (rawPath.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("请先填写目标路径。"));
        return;
    }

    const int majorFunction = m_irpMajorCombo->currentData().toInt();
    unsigned long long createDispositionPreview = 0U;
    unsigned long long createOptionsPreview = 0U;
    QString previewErrorText;
    if (m_irpCreateDispositionEdit != nullptr)
    {
        (void)parseNumericField(
            m_irpCreateDispositionEdit->text().trimmed().section(QChar(' '), 0, 0),
            createDispositionPreview,
            previewErrorText);
    }
    previewErrorText.clear();
    if (m_irpCreateOptionsEdit != nullptr)
    {
        (void)parseNumericField(
            m_irpCreateOptionsEdit->text().trimmed().section(QChar(' '), 0, 0),
            createOptionsPreview,
            previewErrorText);
    }
    const bool createStageMutates =
        (createDispositionPreview >= 2U && createDispositionPreview <= 5U) ||
        ((createOptionsPreview & 0x00001000ULL) != 0U); // FILE_DELETE_ON_CLOSE
    const bool writeLike = majorIsWriteLike(majorFunction) || createStageMutates;
    const bool dangerous = majorIsDangerous(majorFunction);
    if ((writeLike || dangerous) && !m_irpConfirmCheck->isChecked())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("%1 会改变磁盘或设备状态，请先勾选“确认写入语义”。")
                .arg(irpMajorDisplayText(majorFunction)));
        return;
    }
    if (dangerous && !m_irpAllowDangerousCheck->isChecked())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("%1 需要同时勾选“允许 PnP/电源类请求”。")
                .arg(irpMajorDisplayText(majorFunction)));
        return;
    }
    if (dangerous)
    {
        const auto answer = QMessageBox::question(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral(
                "即将向文件系统栈手工投递 %1。\n\n"
                "这类请求正常只由 PnP/电源管理器按状态机下发，"
                "手工构造可能让目标驱动进入非法状态甚至触发系统崩溃。\n\n"
                "确认继续？")
                .arg(irpMajorDisplayText(majorFunction)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (answer != QMessageBox::Yes)
        {
            return;
        }
    }

    // 逐字段解析。任何一个字段解析失败都直接中止，不做"按 0 兜底"——
    // 把打错的控制码当成 0 发下去比报错危险得多。
    struct FieldSpec
    {
        QLineEdit* edit;
        const char* name;
        unsigned long long* target;
    };
    unsigned long long minorValue = 0U;
    unsigned long long desiredAccess = 0U;
    unsigned long long shareAccess = 0U;
    unsigned long long createDisposition = 0U;
    unsigned long long createOptions = 0U;
    unsigned long long fileAttributes = 0U;
    unsigned long long informationClass = 0U;
    unsigned long long controlCode = 0U;
    unsigned long long securityInformation = 0U;
    unsigned long long byteOffset = 0U;
    unsigned long long lockKey = 0U;
    unsigned long long lockLength = 0U;
    unsigned long long outputBytes = 0U;
    unsigned long long timeoutMs = 0U;

    const FieldSpec fieldSpecs[] = {
        { m_irpMinorEdit, "MinorFunction", &minorValue },
        { m_irpDesiredAccessEdit, "DesiredAccess", &desiredAccess },
        { m_irpShareAccessEdit, "ShareAccess", &shareAccess },
        { m_irpCreateDispositionEdit, "CreateDisposition", &createDisposition },
        { m_irpCreateOptionsEdit, "CreateOptions", &createOptions },
        { m_irpFileAttributesEdit, "FileAttributes", &fileAttributes },
        { m_irpInformationClassEdit, "InformationClass", &informationClass },
        { m_irpControlCodeEdit, "ControlCode", &controlCode },
        { m_irpSecurityInformationEdit, "SecurityInformation", &securityInformation },
        { m_irpByteOffsetEdit, "ByteOffset", &byteOffset },
        { m_irpLockKeyEdit, "Key", &lockKey },
        { m_irpLockLengthEdit, "LockLength", &lockLength },
        { m_irpOutputBytesEdit, "OutputBytes", &outputBytes },
        { m_irpTimeoutEdit, "Timeout", &timeoutMs }
    };
    for (const FieldSpec& spec : fieldSpecs)
    {
        if (spec.edit == nullptr || !spec.edit->isEnabled())
        {
            continue;
        }
        QString parseErrorText;
        // CreateDisposition 的占位文案带有说明后缀，取第一个空白前的数值部分。
        const QString fieldText = spec.edit->text().trimmed().section(QChar(' '), 0, 0);
        if (!parseNumericField(fieldText, *spec.target, parseErrorText))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("IRP 构造"),
                QStringLiteral("字段 %1 解析失败：%2")
                    .arg(QString::fromLatin1(spec.name))
                    .arg(parseErrorText));
            return;
        }
    }

    std::vector<std::uint8_t> inputBytes;
    if (m_irpInputHexEdit != nullptr && m_irpInputHexEdit->isEnabled())
    {
        QString payloadErrorText;
        if (!parseHexPayload(
                m_irpInputHexEdit->toPlainText(),
                inputBytes,
                payloadErrorText))
        {
            QMessageBox::warning(
                this,
                QStringLiteral("IRP 构造"),
                QStringLiteral("输入数据解析失败：%1").arg(payloadErrorText));
            return;
        }
    }
    if (inputBytes.size() > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("输入数据超出上限 %1 字节。")
                .arg(static_cast<qulonglong>(KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES)));
        return;
    }
    if (outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("IRP 构造"),
            QStringLiteral("输出缓冲超出上限 %1 字节。")
                .arg(static_cast<qulonglong>(KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES)));
        return;
    }

    // 路径归一化：与其它 R0 入口保持同一套 Win32 → NT 转换规则。
    QString ntPath = QDir::toNativeSeparators(rawPath);
    if (!ntPath.startsWith(QStringLiteral("\\??\\")) &&
        !ntPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
    {
        if (ntPath.startsWith(QStringLiteral("\\\\?\\UNC\\"), Qt::CaseInsensitive))
        {
            ntPath = QStringLiteral("\\??\\UNC\\") + ntPath.mid(8);
        }
        else if (ntPath.startsWith(QStringLiteral("\\\\?\\")))
        {
            ntPath = QStringLiteral("\\??\\") + ntPath.mid(4);
        }
        else if (ntPath.startsWith(QStringLiteral("\\\\")))
        {
            ntPath = QStringLiteral("\\??\\UNC\\") + ntPath.mid(2);
        }
        else
        {
            ntPath = QStringLiteral("\\??\\") + ntPath;
        }
    }

    ksword::ark::FileIrpSubmitRequestParams params;
    params.ntPath = ntPath.toStdWString();
    params.pattern = (m_irpPatternEdit != nullptr && m_irpPatternEdit->isEnabled())
        ? m_irpPatternEdit->text().trimmed().toStdWString()
        : std::wstring();
    params.majorFunction = static_cast<std::uint32_t>(majorFunction);
    params.minorFunction = static_cast<std::uint32_t>(minorValue);
    params.targetLayer = m_irpLayerCombo->currentData().toUInt();
    params.timeoutMs = static_cast<std::uint32_t>(timeoutMs);
    params.desiredAccess = static_cast<std::uint32_t>(desiredAccess);
    params.shareAccess = static_cast<std::uint32_t>(shareAccess);
    params.createDisposition = static_cast<std::uint32_t>(createDisposition);
    params.createOptions = static_cast<std::uint32_t>(createOptions);
    params.fileAttributes = static_cast<std::uint32_t>(fileAttributes);
    params.informationClass = static_cast<std::uint32_t>(informationClass);
    params.controlCode = static_cast<std::uint32_t>(controlCode);
    params.securityInformation = static_cast<std::uint32_t>(securityInformation);
    params.lockKey = static_cast<std::uint32_t>(lockKey);
    params.outputBytes = static_cast<std::uint32_t>(outputBytes);
    params.byteOffset = byteOffset;
    params.lockLength = lockLength;
    params.inputData = inputBytes;
    params.uiConfirmed = m_irpConfirmCheck->isChecked();
    params.allowDangerous = m_irpAllowDangerousCheck->isChecked();
    if (m_irpCreateOnlyCheck->isEnabled() && m_irpCreateOnlyCheck->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY;
    }
    if (m_irpRestartScanCheck->isEnabled() && m_irpRestartScanCheck->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN;
    }
    if (m_irpSingleEntryCheck->isEnabled() && m_irpSingleEntryCheck->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY;
    }
    if (m_irpReparseCheck->isEnabled() && m_irpReparseCheck->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT;
    }
    if (m_irpDirectoryIntentCheck->isEnabled() && m_irpDirectoryIntentCheck->isChecked())
    {
        params.flags |= KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 提交自建 IRP, major="
            << majorFunction
            << ", minor="
            << static_cast<qulonglong>(minorValue)
            << ", layer="
            << params.targetLayer
            << ", inputBytes="
            << static_cast<qulonglong>(inputBytes.size())
            << ", outputBytes="
            << static_cast<qulonglong>(outputBytes)
            << ", path="
            << ntPath.toStdString()
            << eol;
    }

    updateIrpBuilderEnabledState(true);
    m_irpStatusLabel->setText(QStringLiteral("正在向 R0 提交 %1 ...")
        .arg(irpMajorDisplayText(majorFunction)));

    const int progressPid = kPro.add(this, "文件", "IRP 构造提交");
    kPro.set(progressPid, "提交内核请求", 0, 20.0f);

    QPointer<FileDock> safeThis(this);
    const auto dispatcher = m_uiDispatcher;
    std::thread([safeThis, dispatcher, params, progressPid, majorFunction, ntPath]() {
        const ksword::ark::FileIrpSubmitResult result =
            ksword::ark::DriverClient().submitFileIrp(params);

        kPro.set(progressPid, "整理结果", 0, 80.0f);
        dispatcher->post(
            [safeThis, result, progressPid, majorFunction, ntPath]() {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                safeThis->updateIrpBuilderEnabledState(false);
                QTableWidget* table = safeThis->m_irpResultTable;
                table->setRowCount(0);

                const auto appendRow =
                    [table](const QString& nameText, const QString& valueText)
                    {
                        const int row = table->rowCount();
                        table->insertRow(row);
                        table->setItem(row, 0, new QTableWidgetItem(nameText));
                        table->setItem(row, 1, new QTableWidgetItem(valueText));
                    };

                if (!result.io.ok)
                {
                    const QString failureText = result.unsupported
                        ? QStringLiteral(
                            "当前 KswordARK 驱动不支持自建 IRP 提交，请重新部署本次构建的驱动。")
                        : QStringLiteral("R0 通信失败：Win32=%1；%2")
                            .arg(result.io.win32Error)
                            .arg(QString::fromStdString(result.io.message));
                    safeThis->m_irpStatusLabel->setText(failureText);
                    appendRow(QStringLiteral("通信结果"), QStringLiteral("失败"));
                    appendRow(QStringLiteral("Win32 错误"),
                        QString::number(result.io.win32Error));
                    appendRow(QStringLiteral("诊断"),
                        QString::fromStdString(result.io.message));
                    safeThis->m_irpOutputHexEdit->setPlainText(
                        FileDock::formatHexDump({}));
                    kPro.set(progressPid, "提交失败", 0, 100.0f);
                    return;
                }

                appendRow(QStringLiteral("协议状态"),
                    irpProtocolStatusText(result.status));
                appendRow(QStringLiteral("执行阶段"),
                    irpStageText(result.stageFlags));
                appendRow(QStringLiteral("MajorFunction"),
                    FileDock::irpMajorDisplayText(
                        static_cast<int>(result.majorFunction)));
                appendRow(QStringLiteral("MinorFunction"),
                    QStringLiteral("0x%1").arg(result.minorFunction, 2, 16, QChar('0')));
                appendRow(QStringLiteral("请求栈层"),
                    ks::file::IrpFileSystemParser::layerDisplayText(result.requestedLayer));
                appendRow(QStringLiteral("实际栈层"),
                    ks::file::IrpFileSystemParser::layerDisplayText(result.resolvedLayer));
                if (result.requestedLayer != result.resolvedLayer)
                {
                    appendRow(QStringLiteral("栈层提示"),
                        QStringLiteral("目标层不可用，R0 已回退到栈顶，本次未绕过过滤层"));
                }
                appendRow(QStringLiteral("CREATE 状态"), statusHex(result.createStatus));
                appendRow(QStringLiteral("目标请求状态"), statusHex(result.operationStatus));
                appendRow(QStringLiteral("CLEANUP 状态"), statusHex(result.cleanupStatus));
                appendRow(QStringLiteral("CLOSE 状态"), statusHex(result.closeStatus));
                appendRow(QStringLiteral("Information"),
                    QStringLiteral("%1 (0x%2)")
                        .arg(static_cast<qulonglong>(result.information))
                        .arg(static_cast<qulonglong>(result.information), 0, 16));
                appendRow(QStringLiteral("输出字节数"),
                    QString::number(result.outputData.size()));
                appendRow(QStringLiteral("接收驱动"),
                    result.driverName.empty()
                        ? QStringLiteral("-")
                        : QString::fromStdWString(result.driverName));
                appendRow(QStringLiteral("接收设备"),
                    result.deviceName.empty()
                        ? QStringLiteral("-")
                        : QString::fromStdWString(result.deviceName));
                appendRow(QStringLiteral("FILE_OBJECT"),
                    pointerHex(result.fileObjectAddress));
                appendRow(QStringLiteral("目标 DEVICE_OBJECT"),
                    pointerHex(result.targetDeviceAddress));
                appendRow(QStringLiteral("栈顶 DEVICE_OBJECT"),
                    pointerHex(result.relatedDeviceAddress));
                appendRow(QStringLiteral("基础 FS DEVICE_OBJECT"),
                    pointerHex(result.baseFsDeviceAddress));
                appendRow(QStringLiteral("VPB DEVICE_OBJECT"),
                    pointerHex(result.vpbDeviceAddress));
                appendRow(QStringLiteral("分发入口"),
                    pointerHex(result.dispatchAddress));
                appendRow(QStringLiteral("目标 StackSize"),
                    QString::number(result.targetStackSize));
                appendRow(QStringLiteral("目标 DeviceFlags"),
                    QStringLiteral("0x%1")
                        .arg(result.targetDeviceFlags, 8, 16, QChar('0')).toUpper());

                table->resizeColumnToContents(0);
                safeThis->m_irpOutputHexEdit->setPlainText(
                    FileDock::formatHexDump(result.outputData));

                const bool semanticOk =
                    result.status == KSWORD_ARK_FILE_IRP_STATUS_OK &&
                    result.operationStatus >= 0;
                safeThis->m_irpStatusLabel->setText(
                    QStringLiteral("%1：协议=%2；目标请求=%3；Information=%4；输出 %5 字节")
                        .arg(FileDock::irpMajorDisplayText(
                            static_cast<int>(result.majorFunction)))
                        .arg(irpProtocolStatusText(result.status))
                        .arg(statusHex(result.operationStatus))
                        .arg(static_cast<qulonglong>(result.information))
                        .arg(result.outputData.size()));

                {
                    kLogEvent event;
                    if (semanticOk)
                    {
                        info << event
                            << "[FileDock] 自建 IRP 完成, major="
                            << majorFunction
                            << ", layer="
                            << result.resolvedLayer
                            << ", op=0x"
                            << statusHex(result.operationStatus).toStdString()
                            << ", outputBytes="
                            << result.outputData.size()
                            << ", path="
                            << ntPath.toStdString()
                            << eol;
                    }
                    else
                    {
                        warn << event
                            << "[FileDock] 自建 IRP 未成功, major="
                            << majorFunction
                            << ", protocol="
                            << result.status
                            << ", create="
                            << statusHex(result.createStatus).toStdString()
                            << ", op="
                            << statusHex(result.operationStatus).toStdString()
                            << ", path="
                            << ntPath.toStdString()
                            << eol;
                    }
                }

                kPro.set(progressPid, semanticOk ? "提交完成" : "提交返回失败状态", 0, 100.0f);
            },
            [progressPid]()
            {
                kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            });
    }).detach();
}
