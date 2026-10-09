#include "MemoryDock.Internal.h"
#include "../../../shared/evidence/NumericTextParse.h"

// 统一状态栏、地址解析和扫描值格式化，不再承载旧查看器或旧断点/书签页面。
using namespace ksword::memory_dock_internal;

void MemoryDock::updateStatusBarText()
{
    // 状态栏刷新日志：记录当前 PID 与权限状态。
    kLogEvent statusUpdateEvent;
    dbg << statusUpdateEvent
        << "[MemoryDock] updateStatusBarText: attachedPid="
        << m_attachedPid
        << ", canReadWrite="
        << (m_canReadWriteMemory ? "true" : "false")
        << eol;

    // 状态栏由三段组成：进程名、PID、读写状态，任何状态变化都统一经此函数刷新。
    if (m_attachedPid == 0 || m_attachedProcessHandle == nullptr)
    {
        m_statusProcessLabel->setText("进程: 未附加");
        m_statusPidLabel->setText("PID: -");
        m_statusMemoryIoLabel->setText("内存读写: 未就绪");
        if (m_dockHeaderStatusLabel != nullptr)
        {
            m_dockHeaderStatusLabel->setText("未附加进程，请先选择目标并点击“附加”。");
        }
        // 附加状态变了，语义色要跟着回到“未附加”的次要色。
        applyMemoryDockSemanticStyles();
        return;
    }

    m_statusProcessLabel->setText(QString("进程: %1").arg(m_attachedProcessName));
    m_statusPidLabel->setText(QString("PID: %1").arg(m_attachedPid));
    m_statusMemoryIoLabel->setText(
        QString("内存读写: %1").arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    if (m_dockHeaderStatusLabel != nullptr)
    {
        m_dockHeaderStatusLabel->setText(
            QString("已附加 %1 (PID %2)，内存%3。")
                .arg(m_attachedProcessName)
                .arg(m_attachedPid)
                .arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    }
    applyMemoryDockSemanticStyles();
}

bool MemoryDock::parseAddressText(const QString& text, std::uint64_t& valueOut)
{
    // 地址解析日志：保留输入文本用于定位格式问题。
    kLogEvent parseAddressEvent;
    dbg << parseAddressEvent
        << "[MemoryDock] parseAddressText: text="
        << text.trimmed().toStdString()
        << eol;

    // 地址的无前缀默认进制是**十六进制**，与下面的通用数值解析不是一套规则。
    // 原先两者共用一个"先试十进制、失败再试十六进制"的解析器，而那条十六进制
    // 回退只对含 a–f 的串生效：纯数字串的十进制解析永远成立。于是在这个所有
    // 地址都以 0x 回显的界面里，输入 1233 会跳到十进制 1233（= 0x4D1），
    // 不报错、不提示，只是读到了别处。
    const auto parsed = ksword::evidence::ParseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::Hexadecimal);
    if (!parsed.ok)
    {
        return false;
    }
    valueOut = parsed.value;
    return true;
}

bool MemoryDock::parseUnsignedNumber(const QString& text, std::uint64_t& valueOut)
{
    // 这里是"数量"语义（搜索的字节值、长度等），无前缀按十进制——数量本来就是
    // 按十进制念的，不能跟着地址一起改。0x 前缀仍然恒为十六进制。
    const auto parsed = ksword::evidence::ParseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::Decimal);
    if (!parsed.ok)
    {
        return false;
    }
    valueOut = parsed.value;
    return true;
}

QString MemoryDock::formatAddress(const std::uint64_t address)
{
    // 统一输出 16 位十六进制，便于 32/64 位地址在表格中对齐阅读。
    const QString hexText = QString("%1").arg(
        static_cast<qulonglong>(address),
        16,
        16,
        QChar('0')).toUpper();
    return QString("0x%1").arg(hexText);
}

QString MemoryDock::formatSize(const std::uint64_t sizeBytes)
{
    // 字节数可读化显示：B / KB / MB / GB 自动切换，保留两位小数。
    constexpr double kKB = 1024.0;
    constexpr double kMB = 1024.0 * 1024.0;
    constexpr double kGB = 1024.0 * 1024.0 * 1024.0;

    const double sizeValue = static_cast<double>(sizeBytes);
    if (sizeValue >= kGB)
    {
        return QString("%1 GB").arg(sizeValue / kGB, 0, 'f', 2);
    }
    if (sizeValue >= kMB)
    {
        return QString("%1 MB").arg(sizeValue / kMB, 0, 'f', 2);
    }
    if (sizeValue >= kKB)
    {
        return QString("%1 KB").arg(sizeValue / kKB, 0, 'f', 2);
    }
    return QString("%1 B").arg(sizeBytes);
}

QString MemoryDock::protectToText(const std::uint32_t protect)
{
    // PAGE_* 主值仅保留低 8 位；高位是 PAGE_GUARD/NOCACHE 等修饰位。
    const std::uint32_t baseProtect = protect & 0xFF;
    QString baseText;
    switch (baseProtect)
    {
    case PAGE_NOACCESS:          baseText = "---"; break;
    case PAGE_READONLY:          baseText = "R--"; break;
    case PAGE_READWRITE:         baseText = "RW-"; break;
    case PAGE_WRITECOPY:         baseText = "RC-"; break;
    case PAGE_EXECUTE:           baseText = "--X"; break;
    case PAGE_EXECUTE_READ:      baseText = "R-X"; break;
    case PAGE_EXECUTE_READWRITE: baseText = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: baseText = "RCX"; break;
    default:                     baseText = "UNK"; break;
    }

    // 叠加修饰标记，帮助用户识别 Guard/NoCache/WriteCombine 特性。
    if ((protect & PAGE_GUARD) != 0)
    {
        baseText += "|G";
    }
    if ((protect & PAGE_NOCACHE) != 0)
    {
        baseText += "|NC";
    }
    if ((protect & PAGE_WRITECOMBINE) != 0)
    {
        baseText += "|WC";
    }

    return baseText;
}

QString MemoryDock::stateToText(const std::uint32_t state)
{
    switch (state)
    {
    case MEM_COMMIT:  return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE:    return "MEM_FREE";
    default:          return QString("UNKNOWN(0x%1)").arg(state, 0, 16);
    }
}

QString MemoryDock::typeToText(const std::uint32_t type)
{
    switch (type)
    {
    case MEM_IMAGE:   return "IMAGE";
    case MEM_MAPPED:  return "MAPPED";
    case MEM_PRIVATE: return "PRIVATE";
    case 0:           return "-";
    default:          return QString("UNKNOWN(0x%1)").arg(type, 0, 16);
    }
}

QString MemoryDock::bytesToDisplayString(const QByteArray& bytes, const SearchValueType valueType)
{
    // 空字节统一显示短横线，避免表格出现空白造成歧义。
    if (bytes.isEmpty())
    {
        return "-";
    }

    switch (valueType)
    {
    case SearchValueType::Byte:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::uint8_t))) return "-";
        std::uint8_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString("%1 (0x%2)")
            .arg(value)
            .arg(value, 2, 16, QChar('0')).toUpper();
    }
    case SearchValueType::Int16:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int16_t))) return "-";
        std::int16_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Int32:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int32_t))) return "-";
        std::int32_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Int64:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int64_t))) return "-";
        std::int64_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Float32:
    {
        if (bytes.size() < static_cast<int>(sizeof(float))) return "-";
        float value = 0.0f;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 6);
    }
    case SearchValueType::Float64:
    {
        if (bytes.size() < static_cast<int>(sizeof(double))) return "-";
        double value = 0.0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 8);
    }
    case SearchValueType::StringAscii:
    {
        return QString::fromLatin1(bytes);
    }
    case SearchValueType::StringUnicode:
    {
        // UTF-16 字节长度需为偶数，不足时截断最后 1 字节防止越界。
        const int alignedLength = bytes.size() - (bytes.size() % 2);
        if (alignedLength <= 0)
        {
            return "-";
        }
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(bytes.constData()),
            alignedLength / 2);
    }
    case SearchValueType::ByteArray:
    default:
    {
        // 默认按十六进制字节串展示，兼容未知类型与书签显示。
        QStringList parts;
        parts.reserve(bytes.size());
        for (int index = 0; index < bytes.size(); ++index)
        {
            const auto byteValue = static_cast<unsigned char>(bytes.at(index));
            parts.push_back(QString("%1").arg(byteValue, 2, 16, QChar('0')).toUpper());
        }
        return parts.join(' ');
    }
    }
}
