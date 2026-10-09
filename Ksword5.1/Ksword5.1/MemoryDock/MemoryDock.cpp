#include "MemoryDock.Internal.h"

namespace ksword::memory_dock_internal
{
    // ========================================================
    // 主题样式函数：统一按钮/输入框/下拉框风格。
    // ========================================================

    // 按钮样式统一转调全局主题实现：
    // 页面自己拼 QSS 会和 UI/GlobalUiBaseStyle.cpp 的基线打架，
    // 而且那份基线已经覆盖了 hover/pressed/checked/disabled 全部状态。
    QString buildBlueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString buildBlueComboStyle()
    {
        return KswordTheme::ThemedComboBoxStyle();
    }

    // 输入框不再下发页面私有样式：全局基线已经给 QLineEdit / QTextEdit /
    // QPlainTextEdit 统一了边框、圆角与焦点态，返回空串即为“交还基线”。
    QString buildBlueInputStyle()
    {
        return QString();
    }

    // 模块表头文本：直接对齐进程详细信息模块页体验。
    const QStringList ModuleTreeHeaders{
        "模块路径",
        "大小",
        "数字签名",
        "入口偏移量",
        "运行状态",
        "ThreadID"
    };

    // 枚举列 -> 整数索引转换，避免代码里散落硬编码数字。
    int toModuleTreeColumnIndex(const ModuleTreeColumn column)
    {
        return static_cast<int>(column);
    }

    // PID 转 DWORD 的显式封装，避免隐式转换警告。
    DWORD toDwordPid(const std::uint32_t pid)
    {
        return static_cast<DWORD>(pid);
    }

    // 判断内存保护属性是否可读。
    bool isReadableProtect(const std::uint32_t protectValue)
    {
        if ((protectValue & PAGE_GUARD) != 0 || (protectValue & PAGE_NOACCESS) != 0)
        {
            return false;
        }
        const std::uint32_t baseProtect = protectValue & 0xFF;
        switch (baseProtect)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    // 解析两位十六进制字节文本，例如 "7F"、"ff"。
    bool parseHexByte(const QString& text, std::uint8_t& valueOut)
    {
        bool parseOk = false;
        const int value = text.trimmed().toInt(&parseOk, 16);
        if (!parseOk || value < 0 || value > 0xFF)
        {
            return false;
        }
        valueOut = static_cast<std::uint8_t>(value);
        return true;
    }

    // 统一按路径加载图标并做缓存，减少重复读取系统图标带来的卡顿。
    QIcon resolveIconByPath(const QString& absolutePath, QHash<QString, QIcon>& cache)
    {
        if (absolutePath.trimmed().isEmpty())
        {
            return QIcon(":/Icon/process_main.svg");
        }

        auto foundIt = cache.find(absolutePath);
        if (foundIt != cache.end())
        {
            return foundIt.value();
        }

        QIcon resolvedIcon(absolutePath);
        if (resolvedIcon.isNull())
        {
            QFileIconProvider iconProvider;
            resolvedIcon = iconProvider.icon(QFileInfo(absolutePath));
        }
        if (resolvedIcon.isNull())
        {
            resolvedIcon = QIcon(":/Icon/process_main.svg");
        }

        cache.insert(absolutePath, resolvedIcon);
        return resolvedIcon;
    }
}
