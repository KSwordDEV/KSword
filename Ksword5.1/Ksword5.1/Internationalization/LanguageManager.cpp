#include "LanguageManager.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QChildEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QDoubleSpinBox>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QMutex>
#include <QMutexLocker>
#include <QPlainTextEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QScopedValueRollback>
#include <QSet>
#include <QTabWidget>
#include <QSpinBox>
#include <QTableView>
#include <QTextEdit>
#include <QTimer>
#include <QToolBox>
#include <QTreeView>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace
{
    constexpr auto kLanguagePackSchema = "ksword-language-pack";
    constexpr int kLanguagePackFormatVersion = 1;
    constexpr qint64 kMaximumLanguagePackBytes = 32 * 1024 * 1024;
    constexpr auto kSystemLanguagePreferenceId = "system";
    constexpr auto kEnglishFallbackLanguageId = "en-US";
    constexpr auto kProductFallbackLanguageId = "zh-CN";
    constexpr int kComboKeyRole = Qt::UserRole + 91;
    constexpr int kComboFallbackRole = Qt::UserRole + 92;

    constexpr auto kTextKeyProperty = "ks_i18n_text_key";
    constexpr auto kTextFallbackProperty = "ks_i18n_text_fallback";
    constexpr auto kToolTipKeyProperty = "ks_i18n_tooltip_key";
    constexpr auto kToolTipFallbackProperty = "ks_i18n_tooltip_fallback";
    constexpr auto kPlaceholderKeyProperty = "ks_i18n_placeholder_key";
    constexpr auto kPlaceholderFallbackProperty = "ks_i18n_placeholder_fallback";
    constexpr auto kSuffixKeyProperty = "ks_i18n_suffix_key";
    constexpr auto kSuffixFallbackProperty = "ks_i18n_suffix_fallback";
    constexpr auto kWindowTitleKeyProperty = "ks_i18n_window_title_key";
    constexpr auto kWindowTitleFallbackProperty = "ks_i18n_window_title_fallback";
    constexpr auto kTabKeyProperty = "ks_i18n_tab_key";
    constexpr auto kTabFallbackProperty = "ks_i18n_tab_fallback";
    constexpr auto kTabToolTipKeyProperty = "ks_i18n_tab_tooltip_key";
    constexpr auto kTabToolTipFallbackProperty = "ks_i18n_tab_tooltip_fallback";

    constexpr auto kRuntimeRefreshPendingProperty = "ks_i18n_runtime_refresh_pending";
    constexpr auto kRuntimeWindowTitleSourceProperty = "ks_i18n_runtime_window_title_source";
    constexpr auto kRuntimeWindowTitleAppliedProperty = "ks_i18n_runtime_window_title_applied";
    constexpr auto kRuntimeToolTipSourceProperty = "ks_i18n_runtime_tooltip_source";
    constexpr auto kRuntimeToolTipAppliedProperty = "ks_i18n_runtime_tooltip_applied";
    constexpr auto kRuntimeStatusTipSourceProperty = "ks_i18n_runtime_status_tip_source";
    constexpr auto kRuntimeStatusTipAppliedProperty = "ks_i18n_runtime_status_tip_applied";
    constexpr auto kRuntimeWhatsThisSourceProperty = "ks_i18n_runtime_whats_this_source";
    constexpr auto kRuntimeWhatsThisAppliedProperty = "ks_i18n_runtime_whats_this_applied";
    constexpr auto kRuntimeAccessibleNameSourceProperty = "ks_i18n_runtime_accessible_name_source";
    constexpr auto kRuntimeAccessibleNameAppliedProperty = "ks_i18n_runtime_accessible_name_applied";
    constexpr auto kRuntimeAccessibleDescriptionSourceProperty = "ks_i18n_runtime_accessible_description_source";
    constexpr auto kRuntimeAccessibleDescriptionAppliedProperty = "ks_i18n_runtime_accessible_description_applied";
    constexpr auto kRuntimeTextSourceProperty = "ks_i18n_runtime_text_source";
    constexpr auto kRuntimeTextAppliedProperty = "ks_i18n_runtime_text_applied";
    constexpr auto kRuntimeTitleSourceProperty = "ks_i18n_runtime_title_source";
    constexpr auto kRuntimeTitleAppliedProperty = "ks_i18n_runtime_title_applied";
    constexpr auto kRuntimePlaceholderSourceProperty = "ks_i18n_runtime_placeholder_source";
    constexpr auto kRuntimePlaceholderAppliedProperty = "ks_i18n_runtime_placeholder_applied";
    constexpr auto kRuntimePrefixSourceProperty = "ks_i18n_runtime_prefix_source";
    constexpr auto kRuntimePrefixAppliedProperty = "ks_i18n_runtime_prefix_applied";
    constexpr auto kRuntimeSuffixSourceProperty = "ks_i18n_runtime_suffix_source";
    constexpr auto kRuntimeSuffixAppliedProperty = "ks_i18n_runtime_suffix_applied";
    constexpr auto kRuntimeSpecialValueSourceProperty = "ks_i18n_runtime_special_value_source";
    constexpr auto kRuntimeSpecialValueAppliedProperty = "ks_i18n_runtime_special_value_applied";
    constexpr auto kRuntimeTabSourceProperty = "ks_i18n_runtime_tab_source";
    constexpr auto kRuntimeTabAppliedProperty = "ks_i18n_runtime_tab_applied";
    constexpr auto kRuntimeTabToolTipSourceProperty = "ks_i18n_runtime_tab_tooltip_source";
    constexpr auto kRuntimeTabToolTipAppliedProperty = "ks_i18n_runtime_tab_tooltip_applied";
    constexpr int kRuntimeComboSourceRole = Qt::UserRole + 1517;
    constexpr int kRuntimeComboAppliedRole = Qt::UserRole + 1518;
    constexpr int kRuntimeHeaderSourceRole = Qt::UserRole + 1519;
    constexpr int kRuntimeHeaderAppliedRole = Qt::UserRole + 1520;
    constexpr int kRuntimeModelSourceRole = Qt::UserRole + 1521;
    constexpr int kRuntimeModelAppliedRole = Qt::UserRole + 1522;

    // containsHanCharacters 作用：判断文本是否含汉字（BMP 内的 CJK 统一表意文字及扩展 A）。
    bool containsHanCharacters(const QStringView text)
    {
        for (const QChar unit : text)
        {
            const ushort code = unit.unicode();
            if ((code >= 0x3400 && code <= 0x4DBF) || (code >= 0x4E00 && code <= 0x9FFF))
            {
                return true;
            }
        }
        return false;
    }

    bool isAsciiDigit(const QChar unit)
    {
        return unit.unicode() >= u'0' && unit.unicode() <= u'9';
    }

    // findPlaceholder 作用：
    // - 从 from 起找下一个占位符，语法等价于正则 %(?:L?\d+|n)|\{\d+\}；
    // - 用手写扫描代替正则，省掉每个包数千个已编译正则的常驻内存；
    // - 返回 true 时 startOut/lengthOut 给出占位符位置。
    bool findPlaceholder(
        const QStringView text,
        const qsizetype from,
        qsizetype* startOut,
        qsizetype* lengthOut)
    {
        const qsizetype size = text.size();
        for (qsizetype index = from; index < size; ++index)
        {
            const QChar current = text[index];
            if (current == u'%')
            {
                qsizetype cursor = index + 1;
                if (cursor < size && text[cursor] == u'n')
                {
                    *startOut = index;
                    *lengthOut = 2;
                    return true;
                }
                if (cursor < size && text[cursor] == u'L')
                {
                    ++cursor;
                }
                const qsizetype digitsBegin = cursor;
                while (cursor < size && isAsciiDigit(text[cursor]))
                {
                    ++cursor;
                }
                if (cursor > digitsBegin)
                {
                    *startOut = index;
                    *lengthOut = cursor - index;
                    return true;
                }
            }
            else if (current == u'{')
            {
                qsizetype cursor = index + 1;
                while (cursor < size && isAsciiDigit(text[cursor]))
                {
                    ++cursor;
                }
                if (cursor > index + 1 && cursor < size && text[cursor] == u'}')
                {
                    *startOut = index;
                    *lengthOut = cursor + 1 - index;
                    return true;
                }
            }
        }
        return false;
    }

    struct ManagedTextResult
    {
        QString sourceText;
        QString appliedText;
        bool setText = false;
        bool updateMetadata = false;
        bool clearMetadata = false;
    };

    ManagedTextResult resolveManagedText(
        const ks::i18n::LanguageManager& languageManager,
        const QString& currentText,
        const QVariant& sourceValue,
        const QVariant& appliedValue,
        const bool allowRenderedSource = true)
    {
        ManagedTextResult result;
        const bool hasSource = sourceValue.isValid();
        const bool isLastAppliedValue = appliedValue.isValid()
            && currentText == appliedValue.toString();

        QString sourceText;
        if (!hasSource)
        {
            if (containsHanCharacters(currentText))
            {
                sourceText = currentText;
            }
            else if (allowRenderedSource)
            {
                sourceText = languageManager.sourceForRenderedText(currentText);
                if (sourceText.isEmpty())
                {
                    return result;
                }
            }
            else
            {
                return result;
            }
        }
        else if (isLastAppliedValue)
        {
            sourceText = sourceValue.toString();
        }
        else
        {
            // A caller replaced a previously translated property. Treat a new
            // Chinese value as the next source string; non-Chinese content is
            // user/runtime data and must no longer be managed by this fallback.
            if (!containsHanCharacters(currentText))
            {
                result.clearMetadata = true;
                return result;
            }
            sourceText = currentText;
        }

        result.sourceText = sourceText;
        result.appliedText = languageManager.sourceText(sourceText);
        if (!hasSource && result.appliedText == sourceText)
        {
            // Unknown Chinese text can be user data (for example a path or a
            // file name). Only manage text for which the active language pack
            // supplies an actual translation.
            return ManagedTextResult{};
        }
        result.setText = currentText != result.appliedText;
        result.updateMetadata = result.setText
            || !sourceValue.isValid()
            || sourceValue.toString() != result.sourceText
            || !appliedValue.isValid()
            || appliedValue.toString() != result.appliedText;
        return result;
    }

    template <typename Setter>
    void applyManagedObjectText(
        const ks::i18n::LanguageManager& languageManager,
        QObject* storageObject,
        const char* sourceProperty,
        const char* appliedProperty,
        const QString& currentText,
        Setter&& setter)
    {
        if (storageObject == nullptr)
        {
            return;
        }

        const ManagedTextResult result = resolveManagedText(
            languageManager,
            currentText,
            storageObject->property(sourceProperty),
            storageObject->property(appliedProperty));
        if (result.clearMetadata)
        {
            storageObject->setProperty(sourceProperty, QVariant());
            storageObject->setProperty(appliedProperty, QVariant());
            return;
        }
        if (!result.updateMetadata)
        {
            return;
        }
        if (result.setText)
        {
            setter(result.appliedText);
        }
        storageObject->setProperty(sourceProperty, result.sourceText);
        storageObject->setProperty(appliedProperty, result.appliedText);
    }

    QObject* runtimeTranslationRoot(QObject* object)
    {
        if (QWidget* widget = qobject_cast<QWidget*>(object))
        {
            return widget->window() != nullptr ? widget->window() : widget;
        }

        QObject* currentObject = object;
        while (currentObject != nullptr)
        {
            if (QWidget* parentWidget = qobject_cast<QWidget*>(currentObject))
            {
                return parentWidget->window() != nullptr ? parentWidget->window() : parentWidget;
            }
            currentObject = currentObject->parent();
        }
        return object;
    }

    void appendUniqueDirectory(QStringList* directoryList, const QString& directoryPath)
    {
        if (directoryList == nullptr)
        {
            return;
        }

        const QString normalizedPath = QDir::cleanPath(directoryPath.trimmed());
        if (!normalizedPath.isEmpty() && !directoryList->contains(normalizedPath, Qt::CaseInsensitive))
        {
            directoryList->append(normalizedPath);
        }
    }

    QStringList languageDirectoryCandidates()
    {
        QStringList directoryList;
        const QString applicationDirectory = QCoreApplication::applicationDirPath();
        appendUniqueDirectory(&directoryList, QDir(applicationDirectory).absoluteFilePath(QStringLiteral("languages")));
#ifdef Q_OS_WIN
        constexpr DWORD executablePathCapacity = 32768U;
        std::vector<wchar_t> executablePathBuffer(executablePathCapacity, L'\0');
        const DWORD executablePathLength = ::GetModuleFileNameW(
            nullptr,
            executablePathBuffer.data(),
            executablePathCapacity);
        if (executablePathLength > 0 && executablePathLength < executablePathCapacity)
        {
            const QString executableDirectory = QFileInfo(
                QString::fromWCharArray(executablePathBuffer.data(), static_cast<int>(executablePathLength))).absolutePath();
            appendUniqueDirectory(
                &directoryList,
                QDir(executableDirectory).absoluteFilePath(QStringLiteral("languages")));
        }
#endif

        QString walkingPath = QDir::currentPath();
        for (int depth = 0; depth < 8; ++depth)
        {
            const QDir walkingDirectory(walkingPath);
            appendUniqueDirectory(&directoryList, walkingDirectory.absoluteFilePath(QStringLiteral("languages")));
            appendUniqueDirectory(
                &directoryList,
                walkingDirectory.absoluteFilePath(QStringLiteral("Ksword5.1/Ksword5.1/languages")));

            QDir parentDirectory(walkingPath);
            if (!parentDirectory.cdUp())
            {
                break;
            }
            walkingPath = parentDirectory.absolutePath();
        }
        return directoryList;
    }

    bool isHistoricalChineseLanguage(const QString& languageId)
    {
        // zh-CN is the checked-in source-language baseline. Other zh-* packs
        // remain extensible and must be allowed to provide their own values.
        return languageId.compare(
            QString::fromLatin1(kProductFallbackLanguageId),
            Qt::CaseInsensitive) == 0;
    }
}

namespace
{
    // StringEntry 说明：
    // - 一条翻译在 LoadedPack::text 里的位置；键和值都只记录偏移与长度，不单独分配 QString；
    // - 值与键相同（恒等映射）时 valueOffset 直接指向键，不再存第二份文本。
    struct StringEntry
    {
        quint32 keyOffset = 0;
        quint32 keyLength = 0;
        quint32 valueOffset = 0;
        quint32 valueLength = 0;
    };

    // TemplateRef 说明：带占位符的中文源串（如“状态：%1”）的索引；
    // 匹配时才按源串现拆字面量与占位符，不再为每条常驻一个已编译正则。
    struct TemplateRef
    {
        quint32 entryIndex = 0;    // entryIndex：在 sourceTranslations 中的下标。
        quint32 literalLength = 0; // literalLength：字面量总长，越长越具体，先匹配。
        quint32 prefixLength = 0;  // prefixLength：首个占位符之前的字面量长度，用于快速排除。
        quint32 suffixLength = 0;  // suffixLength：最后一个占位符之后的字面量长度，用于快速排除。
    };

    // LoadedPack 说明：
    // - 一个语言包全部翻译文本合并进一块连续的 text，三张表按键排序后二分查找；
    // - 比 QHash<QString,QString> 少掉每条两次堆分配与哈希节点开销；
    // - renderedIndex 是“译文 -> 源串”的反查索引，第一次需要时才构建。
    struct LoadedPack
    {
        QString text;
        std::vector<StringEntry> translations;
        std::vector<StringEntry> contextTranslations;
        std::vector<StringEntry> sourceTranslations;
        std::vector<TemplateRef> sourceTemplates;
        mutable std::once_flag renderedOnce;
        mutable std::vector<quint32> renderedIndex;

        QStringView keyOf(const StringEntry& entry) const
        {
            return QStringView(text).sliced(entry.keyOffset, entry.keyLength);
        }

        QStringView valueOf(const StringEntry& entry) const
        {
            return QStringView(text).sliced(entry.valueOffset, entry.valueLength);
        }

        const StringEntry* find(const std::vector<StringEntry>& table, const QStringView key) const
        {
            const auto iterator = std::lower_bound(
                table.begin(),
                table.end(),
                key,
                [this](const StringEntry& entry, const QStringView wanted) {
                    return keyOf(entry).compare(wanted) < 0;
                });
            if (iterator == table.end() || keyOf(*iterator) != key)
            {
                return nullptr;
            }
            return &*iterator;
        }

        // renderedSource 作用：由译文反查唯一对应的源串；无结果或译文对应多个源串时返回空视图。
        QStringView renderedSource(const QStringView renderedText) const
        {
            std::call_once(renderedOnce, [this]() { buildRenderedIndex(); });
            const auto iterator = std::lower_bound(
                renderedIndex.begin(),
                renderedIndex.end(),
                renderedText,
                [this](const quint32 entryIndex, const QStringView wanted) {
                    return valueOf(sourceTranslations[entryIndex]).compare(wanted) < 0;
                });
            if (iterator == renderedIndex.end()
                || valueOf(sourceTranslations[*iterator]) != renderedText)
            {
                return {};
            }
            return keyOf(sourceTranslations[*iterator]);
        }

    private:
        // buildRenderedIndex 作用：
        // - 只保留“译文非空且与源串不同”的条目；
        // - 多个源串共用同一译文时无法确定回哪一个，整组丢弃，避免猜错。
        void buildRenderedIndex() const
        {
            std::vector<quint32> candidates;
            candidates.reserve(sourceTranslations.size());
            for (quint32 index = 0; index < sourceTranslations.size(); ++index)
            {
                const StringEntry& entry = sourceTranslations[index];
                const QStringView value = valueOf(entry);
                if (value.isEmpty() || value == keyOf(entry))
                {
                    continue;
                }
                candidates.push_back(index);
            }
            std::sort(
                candidates.begin(),
                candidates.end(),
                [this](const quint32 left, const quint32 right) {
                    const int order = valueOf(sourceTranslations[left]).compare(
                        valueOf(sourceTranslations[right]));
                    return order != 0 ? order < 0 : left < right;
                });
            renderedIndex.reserve(candidates.size());
            for (std::size_t runBegin = 0; runBegin < candidates.size();)
            {
                std::size_t runEnd = runBegin + 1;
                const QStringView runValue = valueOf(sourceTranslations[candidates[runBegin]]);
                while (runEnd < candidates.size()
                    && valueOf(sourceTranslations[candidates[runEnd]]) == runValue)
                {
                    ++runEnd;
                }
                if (runEnd - runBegin == 1)
                {
                    renderedIndex.push_back(candidates[runBegin]);
                }
                runBegin = runEnd;
            }
            renderedIndex.shrink_to_fit();
        }
    };

    // PackMetadata 说明：语言包顶层的标量字段；清单扫描与完整加载共用。
    struct PackMetadata
    {
        QString schema;
        QString id;
        QString name;
        QString nativeName;
        QString author;
        QString textDirection = QStringLiteral("ltr");
        QString fallback;
        int formatVersion = -1;
        bool hasTranslations = false;
    };

    int hexDigitValue(const char digit)
    {
        if (digit >= '0' && digit <= '9')
        {
            return digit - '0';
        }
        if (digit >= 'a' && digit <= 'f')
        {
            return digit - 'a' + 10;
        }
        if (digit >= 'A' && digit <= 'F')
        {
            return digit - 'A' + 10;
        }
        return -1;
    }

    // JsonCursor 说明：
    // - 语言包格式固定（顶层若干标量 + 三张字符串表），不需要通用 DOM；
    // - 流式扫描 UTF-8 JSON，字符串直接解码追加到调用方给的 QString 里，不产生 QJsonDocument；
    // - 传入空 sink 时只校验并跳过，用于清单扫描时越过大表。
    class JsonCursor
    {
    public:
        explicit JsonCursor(const QByteArray& bytes)
            : m_begin(bytes.constData())
            , m_cursor(bytes.constData())
            , m_end(bytes.constData() + bytes.size())
        {
            if (bytes.size() >= 3
                && static_cast<unsigned char>(m_cursor[0]) == 0xEF
                && static_cast<unsigned char>(m_cursor[1]) == 0xBB
                && static_cast<unsigned char>(m_cursor[2]) == 0xBF)
            {
                m_cursor += 3;
            }
        }

        bool failed() const { return !m_error.isEmpty(); }
        const QString& error() const { return m_error; }

        // fail 作用：
        // - reasonCode 是 snake_case 错误码而非句子：它只用于排查损坏的语言包，
        //   做成可翻译 UI 串会让每个新语言都要翻译一遍解析器内部状态；
        // - 与字节偏移一起塞进已登记的“无效的语言包 JSON (%1)：%2”的 %2。
        bool fail(const char* reasonCode)
        {
            if (m_error.isEmpty())
            {
                m_error = QString::fromLatin1(reasonCode)
                    + QLatin1Char('@')
                    + QString::number(m_cursor - m_begin);
            }
            return false;
        }

        void skipWhitespace()
        {
            while (m_cursor < m_end
                && (*m_cursor == ' ' || *m_cursor == '\t' || *m_cursor == '\n' || *m_cursor == '\r'))
            {
                ++m_cursor;
            }
        }

        char peek()
        {
            skipWhitespace();
            return m_cursor < m_end ? *m_cursor : '\0';
        }

        bool atEnd()
        {
            skipWhitespace();
            return m_cursor >= m_end;
        }

        bool consumeIf(const char expected)
        {
            if (peek() == expected && m_cursor < m_end)
            {
                ++m_cursor;
                return true;
            }
            return false;
        }

        bool expect(const char expected)
        {
            if (consumeIf(expected))
            {
                return true;
            }
            // 字节偏移已经指到出错位置，排查时能直接看到期望的分隔符，无需拼进错误码。
            return fail("expected_character");
        }

        // objectHasMembers 作用：不消费输入，判断下一个 { 之后是否至少有一个成员。
        bool objectHasMembers()
        {
            if (peek() != '{')
            {
                return false;
            }
            const char* const saved = m_cursor;
            ++m_cursor;
            skipWhitespace();
            const bool hasMembers = m_cursor < m_end && *m_cursor != '}';
            m_cursor = saved;
            return hasMembers;
        }

        // scanString 作用：
        // - 读取一个 JSON 字符串；sink 非空时把解码结果追加到 sink 末尾，并回填偏移与长度（UTF-16 单元）；
        // - sink 为空时只校验转义并跳过。
        bool scanString(QString* sink, quint32* offsetOut, quint32* lengthOut)
        {
            if (peek() != '"' || m_cursor >= m_end)
            {
                return fail("expected_string");
            }
            const qsizetype startSize = sink != nullptr ? sink->size() : 0;
            ++m_cursor;
            const char* runBegin = m_cursor;
            while (m_cursor < m_end)
            {
                const unsigned char byte = static_cast<unsigned char>(*m_cursor);
                if (byte == '"')
                {
                    flushRun(sink, runBegin);
                    ++m_cursor;
                    if (offsetOut != nullptr)
                    {
                        *offsetOut = static_cast<quint32>(startSize);
                    }
                    if (lengthOut != nullptr)
                    {
                        *lengthOut = sink != nullptr
                            ? static_cast<quint32>(sink->size() - startSize)
                            : 0U;
                    }
                    return true;
                }
                if (byte == '\\')
                {
                    flushRun(sink, runBegin);
                    ++m_cursor;
                    if (m_cursor >= m_end)
                    {
                        break;
                    }
                    char16_t unit = 0;
                    switch (*m_cursor)
                    {
                    case '"': unit = u'"'; break;
                    case '\\': unit = u'\\'; break;
                    case '/': unit = u'/'; break;
                    case 'b': unit = u'\b'; break;
                    case 'f': unit = u'\f'; break;
                    case 'n': unit = u'\n'; break;
                    case 'r': unit = u'\r'; break;
                    case 't': unit = u'\t'; break;
                    case 'u':
                    {
                        if (m_end - m_cursor < 5)
                        {
                            return fail("truncated_unicode_escape");
                        }
                        for (int index = 1; index <= 4; ++index)
                        {
                            const int digit = hexDigitValue(m_cursor[index]);
                            if (digit < 0)
                            {
                                return fail("invalid_unicode_escape");
                            }
                            unit = static_cast<char16_t>((unit << 4) | digit);
                        }
                        m_cursor += 4;
                        break;
                    }
                    default:
                        return fail("invalid_escape");
                    }
                    if (sink != nullptr)
                    {
                        sink->append(QChar(unit));
                    }
                    ++m_cursor;
                    runBegin = m_cursor;
                    continue;
                }
                if (byte < 0x20)
                {
                    return fail("control_character_in_string");
                }
                ++m_cursor;
            }
            return fail("unterminated_string");
        }

        bool readNumber(double* valueOut)
        {
            skipWhitespace();
            const char* const tokenBegin = m_cursor;
            while (m_cursor < m_end
                && (*m_cursor == '-' || *m_cursor == '+' || *m_cursor == '.'
                    || *m_cursor == 'e' || *m_cursor == 'E'
                    || (*m_cursor >= '0' && *m_cursor <= '9')))
            {
                ++m_cursor;
            }
            if (m_cursor == tokenBegin)
            {
                return fail("expected_number");
            }
            bool converted = false;
            const double value = QByteArray::fromRawData(tokenBegin, static_cast<qsizetype>(m_cursor - tokenBegin))
                .toDouble(&converted);
            if (!converted)
            {
                return fail("invalid_number");
            }
            *valueOut = value;
            return true;
        }

        // skipValue 作用：校验并越过任意一个 JSON 值。
        bool skipValue(const int depth = 0)
        {
            if (depth > 64)
            {
                return fail("nesting_too_deep");
            }
            const char lead = peek();
            if (m_cursor >= m_end)
            {
                return fail("unexpected_end_of_data");
            }
            if (lead == '"')
            {
                return scanString(nullptr, nullptr, nullptr);
            }
            if (lead == '{')
            {
                ++m_cursor;
                if (consumeIf('}'))
                {
                    return true;
                }
                for (;;)
                {
                    if (!scanString(nullptr, nullptr, nullptr) || !expect(':') || !skipValue(depth + 1))
                    {
                        return false;
                    }
                    if (consumeIf(','))
                    {
                        continue;
                    }
                    return expect('}');
                }
            }
            if (lead == '[')
            {
                ++m_cursor;
                if (consumeIf(']'))
                {
                    return true;
                }
                for (;;)
                {
                    if (!skipValue(depth + 1))
                    {
                        return false;
                    }
                    if (consumeIf(','))
                    {
                        continue;
                    }
                    return expect(']');
                }
            }
            if (skipLiteral("true") || skipLiteral("false") || skipLiteral("null"))
            {
                return true;
            }
            double ignoredNumber = 0.0;
            return readNumber(&ignoredNumber);
        }

    private:
        void flushRun(QString* sink, const char* runBegin) const
        {
            if (sink != nullptr && m_cursor > runBegin)
            {
                sink->append(QString::fromUtf8(runBegin, static_cast<qsizetype>(m_cursor - runBegin)));
            }
        }

        bool skipLiteral(const char* literal)
        {
            const qsizetype length = static_cast<qsizetype>(std::char_traits<char>::length(literal));
            if (m_end - m_cursor >= length && std::char_traits<char>::compare(m_cursor, literal, length) == 0)
            {
                m_cursor += length;
                return true;
            }
            return false;
        }

        const char* m_begin = nullptr;
        const char* m_cursor = nullptr;
        const char* m_end = nullptr;
        QString m_error;
    };

    // parseStringMap 作用：
    // - 读取一张 {"键":"值"} 表，键值文本追加进 blob，条目只记位置；
    // - 值与键相同时回退刚写入的值，让值直接复用键那段文本；
    // - 任何值不是字符串都判定语言包损坏。
    bool parseStringMap(JsonCursor& cursor, QString& blob, std::vector<StringEntry>& table)
    {
        if (!cursor.expect('{'))
        {
            return false;
        }
        if (cursor.consumeIf('}'))
        {
            return true;
        }
        for (;;)
        {
            StringEntry entry;
            if (!cursor.scanString(&blob, &entry.keyOffset, &entry.keyLength) || !cursor.expect(':'))
            {
                return false;
            }
            if (cursor.peek() != '"')
            {
                return cursor.fail("translation_value_is_not_a_string");
            }
            if (!cursor.scanString(&blob, &entry.valueOffset, &entry.valueLength))
            {
                return false;
            }
            const QStringView blobView(blob);
            if (entry.keyLength == entry.valueLength
                && blobView.sliced(entry.keyOffset, entry.keyLength)
                    == blobView.sliced(entry.valueOffset, entry.valueLength))
            {
                blob.truncate(entry.valueOffset);
                entry.valueOffset = entry.keyOffset;
            }
            table.push_back(entry);
            if (cursor.consumeIf(','))
            {
                continue;
            }
            return cursor.expect('}');
        }
    }

    // finalizeTable 作用：按键排序；同键重复时保留最后一条（与旧 QHash::insert 覆盖行为一致）。
    void finalizeTable(const QString& text, std::vector<StringEntry>& table)
    {
        const QStringView base(text);
        const auto keyOf = [&base](const StringEntry& entry) {
            return base.sliced(entry.keyOffset, entry.keyLength);
        };
        std::stable_sort(
            table.begin(),
            table.end(),
            [&keyOf](const StringEntry& left, const StringEntry& right) {
                return keyOf(left).compare(keyOf(right)) < 0;
            });
        std::size_t written = 0;
        for (std::size_t index = 0; index < table.size(); ++index)
        {
            if (index + 1 < table.size() && keyOf(table[index]) == keyOf(table[index + 1]))
            {
                continue;
            }
            table[written++] = table[index];
        }
        table.resize(written);
        table.shrink_to_fit();
    }

    // buildSourceTemplates 作用：登记含汉字且带占位符的源串，按字面量长度从长到短排列。
    void buildSourceTemplates(LoadedPack* pack)
    {
        for (quint32 index = 0; index < pack->sourceTranslations.size(); ++index)
        {
            const QStringView key = pack->keyOf(pack->sourceTranslations[index]);
            if (!containsHanCharacters(key))
            {
                continue;
            }
            qsizetype start = 0;
            qsizetype length = 0;
            if (!findPlaceholder(key, 0, &start, &length))
            {
                continue;
            }
            const qsizetype firstStart = start;
            qsizetype lastEnd = start + length;
            qsizetype placeholderChars = length;
            while (findPlaceholder(key, lastEnd, &start, &length))
            {
                lastEnd = start + length;
                placeholderChars += length;
            }
            TemplateRef reference;
            reference.entryIndex = index;
            reference.literalLength = static_cast<quint32>(key.size() - placeholderChars);
            reference.prefixLength = static_cast<quint32>(firstStart);
            reference.suffixLength = static_cast<quint32>(key.size() - lastEnd);
            pack->sourceTemplates.push_back(reference);
        }
        std::stable_sort(
            pack->sourceTemplates.begin(),
            pack->sourceTemplates.end(),
            [](const TemplateRef& left, const TemplateRef& right) {
                return left.literalLength > right.literalLength;
            });
        pack->sourceTemplates.shrink_to_fit();
    }

    // ParsedTemplate 说明：一条源串拆成 n+1 段字面量与 n 个占位符；captures[k] 是第 k 个占位符匹配到的文本。
    struct ParsedTemplate
    {
        std::vector<QStringView> literals;
        std::vector<QStringView> placeholders;
        std::vector<QStringView> captures;
    };

    ParsedTemplate parseTemplate(const QStringView pattern)
    {
        ParsedTemplate parsed;
        qsizetype previousEnd = 0;
        qsizetype cursor = 0;
        qsizetype start = 0;
        qsizetype length = 0;
        while (findPlaceholder(pattern, cursor, &start, &length))
        {
            parsed.literals.push_back(pattern.sliced(previousEnd, start - previousEnd));
            parsed.placeholders.push_back(pattern.sliced(start, length));
            previousEnd = start + length;
            cursor = previousEnd;
        }
        parsed.literals.push_back(pattern.sliced(previousEnd));
        parsed.captures.resize(parsed.placeholders.size());
        return parsed;
    }

    // matchTemplateFrom 作用：
    // - 等价于正则 ^L0([\s\S]*?)L1...([\s\S]*?)Ln$ 的回溯匹配，占位符惰性、取最短；
    // - 末段的 $ 既可匹配文本结尾，也可匹配结尾换行之前，与 PCRE 默认行为一致。
    bool matchTemplateFrom(
        const QStringView text,
        ParsedTemplate& parsed,
        const std::size_t index,
        const qsizetype position)
    {
        const QStringView next = parsed.literals[index + 1];
        if (index + 1 == parsed.placeholders.size())
        {
            const qsizetype size = text.size();
            const qsizetype endings[2] = { size - 1, size };
            for (int choice = text.endsWith(QChar(u'\n')) ? 0 : 1; choice < 2; ++choice)
            {
                const qsizetype literalStart = endings[choice] - next.size();
                if (literalStart >= position && text.sliced(literalStart, next.size()) == next)
                {
                    parsed.captures[index] = text.sliced(position, literalStart - position);
                    return true;
                }
            }
            return false;
        }
        for (qsizetype candidate = position; candidate + next.size() <= text.size(); ++candidate)
        {
            if (text.sliced(candidate, next.size()) != next)
            {
                continue;
            }
            parsed.captures[index] = text.sliced(position, candidate - position);
            if (matchTemplateFrom(text, parsed, index + 1, candidate + next.size()))
            {
                return true;
            }
        }
        return false;
    }

    bool matchTemplate(const QStringView text, ParsedTemplate& parsed)
    {
        if (parsed.placeholders.empty() || !text.startsWith(parsed.literals[0]))
        {
            return false;
        }
        return matchTemplateFrom(text, parsed, 0, parsed.literals[0].size());
    }

    // parsePackBytes 作用：
    // - pack 为空：只做清单扫描，越过三张大表，仅取顶层标量；
    // - pack 非空：完整加载，三张表解码进 pack->text 并排好序。
    bool parsePackBytes(
        const QByteArray& bytes,
        LoadedPack* pack,
        PackMetadata* meta,
        QString* errorOut)
    {
        JsonCursor cursor(bytes);
        if (pack != nullptr)
        {
            pack->text.reserve(bytes.size());
        }

        bool seenTranslations = false;
        bool seenContext = false;
        bool seenSource = false;
        const auto readOptionalString = [&cursor](QString* target) -> bool {
            if (cursor.peek() == '"')
            {
                QString value;
                quint32 offset = 0;
                quint32 length = 0;
                if (!cursor.scanString(&value, &offset, &length))
                {
                    return false;
                }
                *target = value;
                return true;
            }
            return cursor.skipValue();
        };

        const auto handleMember = [&](const QString& key) -> bool {
            if (key == QLatin1String("schema")) return readOptionalString(&meta->schema);
            if (key == QLatin1String("id")) return readOptionalString(&meta->id);
            if (key == QLatin1String("name")) return readOptionalString(&meta->name);
            if (key == QLatin1String("native_name")) return readOptionalString(&meta->nativeName);
            if (key == QLatin1String("author")) return readOptionalString(&meta->author);
            if (key == QLatin1String("text_direction")) return readOptionalString(&meta->textDirection);
            if (key == QLatin1String("fallback")) return readOptionalString(&meta->fallback);
            if (key == QLatin1String("format_version"))
            {
                const char lead = cursor.peek();
                if (lead == '-' || (lead >= '0' && lead <= '9'))
                {
                    double value = 0.0;
                    if (!cursor.readNumber(&value))
                    {
                        return false;
                    }
                    meta->formatVersion = value == static_cast<double>(static_cast<int>(value))
                        ? static_cast<int>(value)
                        : -1;
                    return true;
                }
                return cursor.skipValue();
            }
            if (key == QLatin1String("translations"))
            {
                if (seenTranslations)
                {
                    return cursor.fail("duplicate_translations_section");
                }
                seenTranslations = true;
                if (cursor.peek() != '{')
                {
                    return cursor.skipValue();
                }
                if (pack != nullptr)
                {
                    return parseStringMap(cursor, pack->text, pack->translations);
                }
                meta->hasTranslations = cursor.objectHasMembers();
                return cursor.skipValue();
            }
            if (key == QLatin1String("context_translations"))
            {
                if (seenContext)
                {
                    return cursor.fail("duplicate_context_translations_section");
                }
                seenContext = true;
                if (pack != nullptr && cursor.peek() == '{')
                {
                    return parseStringMap(cursor, pack->text, pack->contextTranslations);
                }
                return cursor.skipValue();
            }
            if (key == QLatin1String("source_translations"))
            {
                if (seenSource)
                {
                    return cursor.fail("duplicate_source_translations_section");
                }
                seenSource = true;
                if (cursor.peek() != '{')
                {
                    return cursor.fail("source_translations_must_be_an_object");
                }
                if (pack != nullptr)
                {
                    return parseStringMap(cursor, pack->text, pack->sourceTranslations);
                }
                return cursor.skipValue();
            }
            return cursor.skipValue();
        };

        bool parsed = cursor.expect('{');
        if (parsed && !cursor.consumeIf('}'))
        {
            for (;;)
            {
                QString key;
                quint32 keyOffset = 0;
                quint32 keyLength = 0;
                if (!cursor.scanString(&key, &keyOffset, &keyLength)
                    || !cursor.expect(':')
                    || !handleMember(key))
                {
                    parsed = false;
                    break;
                }
                if (cursor.consumeIf(','))
                {
                    continue;
                }
                parsed = cursor.expect('}');
                break;
            }
        }
        if (parsed && !cursor.atEnd())
        {
            parsed = cursor.fail("unexpected_data_after_the_root_object");
        }
        if (!parsed)
        {
            if (errorOut != nullptr)
            {
                *errorOut = cursor.error();
            }
            return false;
        }

        if (pack != nullptr)
        {
            meta->hasTranslations = !pack->translations.empty();
            finalizeTable(pack->text, pack->translations);
            finalizeTable(pack->text, pack->contextTranslations);
            finalizeTable(pack->text, pack->sourceTranslations);
            const auto keysAreValid = [pack](const std::vector<StringEntry>& table, const bool allowBlank) {
                return std::none_of(table.begin(), table.end(), [&](const StringEntry& entry) {
                    const QStringView key = pack->keyOf(entry);
                    return allowBlank ? key.isEmpty() : key.trimmed().isEmpty();
                });
            };
            if (!keysAreValid(pack->translations, false)
                || !keysAreValid(pack->contextTranslations, false)
                || !keysAreValid(pack->sourceTranslations, true))
            {
                if (errorOut != nullptr)
                {
                    // 与解析器错误码同类：这是排查损坏语言包用的内部原因，不是 UI 文本。
                    *errorOut = QStringLiteral("empty_translation_key");
                }
                return false;
            }
            pack->text.squeeze();
            buildSourceTemplates(pack);
        }
        return true;
    }

    bool isValidLanguageIdText(const QString& languageId)
    {
        static const QRegularExpression languageIdExpression(
            QStringLiteral("^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"));
        return languageIdExpression.match(languageId).hasMatch();
    }

    // loadPackFile 作用：读取并校验一个语言包文件；pack 为空时只做清单扫描。
    bool loadPackFile(
        const QString& filePath,
        LoadedPack* pack,
        PackMetadata* meta,
        QString* errorOut)
    {
        const auto reportError = [errorOut](const QString& message) {
            if (errorOut != nullptr)
            {
                *errorOut = message;
            }
            return false;
        };

        const QFileInfo fileInfo(filePath);
        if (!fileInfo.exists() || !fileInfo.isFile() || fileInfo.size() <= 0 || fileInfo.size() > kMaximumLanguagePackBytes)
        {
            return reportError(QStringLiteral("Invalid language pack size: %1").arg(filePath));
        }
        QFile packFile(filePath);
        if (!packFile.open(QIODevice::ReadOnly))
        {
            return reportError(QStringLiteral("Cannot open language pack: %1").arg(filePath));
        }
        const QByteArray bytes = packFile.readAll();
        packFile.close();

        QString parseError;
        if (!parsePackBytes(bytes, pack, meta, &parseError))
        {
            return reportError(QStringLiteral("Invalid language pack JSON (%1): %2").arg(filePath, parseError));
        }

        meta->schema = meta->schema;
        meta->id = meta->id.trimmed();
        meta->name = meta->name.trimmed();
        meta->nativeName = meta->nativeName.trimmed();
        meta->author = meta->author.trimmed();
        meta->fallback = meta->fallback.trimmed();
        if (meta->schema != QString::fromLatin1(kLanguagePackSchema)
            || meta->formatVersion != kLanguagePackFormatVersion
            || !isValidLanguageIdText(meta->id)
            || meta->name.isEmpty()
            || meta->nativeName.isEmpty()
            || !meta->hasTranslations)
        {
            return reportError(QStringLiteral("Language pack metadata is invalid: %1").arg(filePath));
        }
        if (!meta->fallback.isEmpty() && !isValidLanguageIdText(meta->fallback))
        {
            return reportError(QStringLiteral("Language pack fallback id is invalid: %1").arg(filePath));
        }
        return true;
    }
}

// State 说明：
// - packs 只在启动时登记清单；data 为空表示该语言尚未被使用，不占翻译表内存；
// - mutex 保护清单与按需加载，查询线程拿到的是 shared_ptr 快照，加载后不再变更。
struct ks::i18n::LanguageManager::State
{
    struct PackEntry
    {
        LanguageInfo info;
        QString fallbackLanguageId;
        std::shared_ptr<const LoadedPack> data;
        bool loadAttempted = false;
        QString loadError;
    };

    mutable QMutex mutex;
    std::vector<PackEntry> packs;
};

struct ks::i18n::LanguageManager::PackRef
{
    bool found = false;
    QString languageId;
    QString fallbackLanguageId;
    QString loadError;
    std::shared_ptr<const LoadedPack> data;
};

ks::i18n::LanguageManager::LanguageManager()
    : m_state(std::make_unique<State>())
{
}

ks::i18n::LanguageManager::~LanguageManager() = default;

ks::i18n::LanguageManager& ks::i18n::LanguageManager::instance()
{
    static LanguageManager manager;
    return manager;
}

ks::i18n::LanguageManager::PackRef ks::i18n::LanguageManager::acquirePack(
    const QString& languageId) const
{
    PackRef reference;
    QMutexLocker locker(&m_state->mutex);
    const auto iterator = std::find_if(
        m_state->packs.begin(),
        m_state->packs.end(),
        [&languageId](const State::PackEntry& entry) {
            return entry.info.id.compare(languageId, Qt::CaseInsensitive) == 0;
        });
    if (iterator == m_state->packs.end())
    {
        return reference;
    }

    if (!iterator->data && !iterator->loadAttempted)
    {
        iterator->loadAttempted = true;
        auto loaded = std::make_shared<LoadedPack>();
        PackMetadata metadata;
        if (loadPackFile(iterator->info.filePath, loaded.get(), &metadata, &iterator->loadError))
        {
            iterator->data = std::move(loaded);
        }
    }

    reference.found = true;
    reference.languageId = iterator->info.id;
    reference.fallbackLanguageId = iterator->fallbackLanguageId;
    reference.loadError = iterator->loadError;
    reference.data = iterator->data;
    return reference;
}

bool ks::i18n::LanguageManager::initialize(
    const QString& preferredLanguageId,
    QString* errorTextOut)
{
    QStringList warningList;
    if (!hasAnyPack())
    {
        discoverLanguagePacks(&warningList);
    }

    if (!hasAnyPack())
    {
        m_currentLanguageId = QString::fromLatin1(kProductFallbackLanguageId);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("No valid language packs were found. Built-in text will be used.");
        }
        applyApplicationDirection();
        return false;
    }

    const bool applied = setLanguage(preferredLanguageId, errorTextOut);
    if (errorTextOut != nullptr && !warningList.isEmpty())
    {
        const QString warningText = warningList.join(QStringLiteral("\n"));
        *errorTextOut = errorTextOut->isEmpty()
            ? warningText
            : (*errorTextOut + QStringLiteral("\n") + warningText);
    }
    return applied;
}

bool ks::i18n::LanguageManager::setLanguage(
    const QString& languageId,
    QString* errorTextOut)
{
    const QString resolvedLanguageId = resolvePreferredLanguageId(languageId);
    // 切换语言时才真正加载该包的翻译表，这里是按需加载的主要触发点。
    const PackRef pack = acquirePack(resolvedLanguageId);
    if (!pack.found)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("Language pack not found: %1 (resolved from %2)")
                .arg(resolvedLanguageId, languageId);
        }
        return false;
    }
    if (!pack.data)
    {
        if (errorTextOut != nullptr)
        {
            // loadPackFile 失败时一定写了 loadError（其中已含登记过的 UI 文案）；
            // 这里的兜底只在该不变式被破坏时出现，所以给内部错误码而不是新增 UI 串。
            *errorTextOut = pack.loadError.isEmpty()
                ? QStringLiteral("language_pack_load_failed:") + pack.languageId
                : pack.loadError;
        }
        return false;
    }

    const bool languageWillChange = !m_currentLanguageId.isEmpty()
        && m_currentLanguageId.compare(pack.languageId, Qt::CaseInsensitive) != 0;
    if (languageWillChange)
    {
        // Capture the canonical source for controls that were constructed from
        // an already-rendered English context translation before changing the
        // active pack. Their runtime metadata then makes the switch reversible.
        QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (application != nullptr)
        {
            const QWidgetList topLevelWidgetList = application->topLevelWidgets();
            for (QWidget* widget : topLevelWidgetList)
            {
                applyRuntimeTranslations(widget);
            }
        }
    }

    m_currentLanguageId = pack.languageId;
    ensureApplicationEventFilter();
    applyApplicationDirection();
    retranslateAll();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return true;
}

QString ks::i18n::LanguageManager::resolvePreferredLanguageId(
    const QString& preferredLanguageId) const
{
    QString requestedLanguageId = preferredLanguageId.trimmed();
    if (requestedLanguageId.isEmpty()
        || requestedLanguageId.compare(
            QString::fromLatin1(kSystemLanguagePreferenceId),
            Qt::CaseInsensitive) == 0)
    {
        requestedLanguageId = QLocale::system().name();
    }
    requestedLanguageId.replace('_', '-');

    // 协商只看清单里的语言 id，不会加载任何翻译表。
    QMutexLocker locker(&m_state->mutex);
    const auto findExactLanguage = [this](const QString& candidateLanguageId) {
        return std::find_if(
            m_state->packs.cbegin(),
            m_state->packs.cend(),
            [&candidateLanguageId](const State::PackEntry& entry) {
                return entry.info.id.compare(candidateLanguageId, Qt::CaseInsensitive) == 0;
            });
    };

    // Locale negotiation is deterministic:
    // exact region -> base language -> en-US -> KSword's product fallback.
    auto languageMatch = findExactLanguage(requestedLanguageId);
    if (languageMatch != m_state->packs.cend())
    {
        return languageMatch->info.id;
    }

    const QString baseLanguageId = requestedLanguageId.section('-', 0, 0);
    languageMatch = findExactLanguage(baseLanguageId);
    if (languageMatch == m_state->packs.cend() && !baseLanguageId.isEmpty())
    {
        languageMatch = std::find_if(
            m_state->packs.cbegin(),
            m_state->packs.cend(),
            [&baseLanguageId](const State::PackEntry& entry) {
                return entry.info.id.section('-', 0, 0).compare(
                    baseLanguageId,
                    Qt::CaseInsensitive) == 0;
            });
    }
    if (languageMatch != m_state->packs.cend())
    {
        return languageMatch->info.id;
    }

    languageMatch = findExactLanguage(QString::fromLatin1(kEnglishFallbackLanguageId));
    if (languageMatch != m_state->packs.cend())
    {
        return languageMatch->info.id;
    }

    languageMatch = findExactLanguage(QString::fromLatin1(kProductFallbackLanguageId));
    if (languageMatch != m_state->packs.cend())
    {
        return languageMatch->info.id;
    }

    // A damaged/custom installation may omit both required fallback packs.
    // Keep the UI usable with the first validated pack; normal builds always
    // stop at the product fallback above.
    return m_state->packs.empty()
        ? QString::fromLatin1(kProductFallbackLanguageId)
        : m_state->packs.front().info.id;
}

bool ks::i18n::LanguageManager::hasAnyPack() const
{
    QMutexLocker locker(&m_state->mutex);
    return !m_state->packs.empty();
}

QString ks::i18n::LanguageManager::currentLanguageId() const
{
    return m_currentLanguageId;
}

QList<ks::i18n::LanguageInfo> ks::i18n::LanguageManager::availableLanguages() const
{
    // 语言选择列表只需要清单里的元数据，不触发任何翻译表加载。
    QMutexLocker locker(&m_state->mutex);
    QList<LanguageInfo> languageList;
    languageList.reserve(static_cast<qsizetype>(m_state->packs.size()));
    for (const State::PackEntry& entry : m_state->packs)
    {
        languageList.append(entry.info);
    }
    return languageList;
}

QString ks::i18n::LanguageManager::text(
    const QString& key,
    const QString& fallbackText) const
{
    QStringList visitedLanguageIds;
    return resolveText(m_currentLanguageId, key, fallbackText, &visitedLanguageIds);
}

QString ks::i18n::LanguageManager::contextText(
    const QString& contextKey,
    const QString& sourceText) const
{
    if (contextKey.trimmed().isEmpty() || sourceText.isEmpty())
    {
        return sourceText;
    }

    // Chinese is the historical source language. Returning the call-site
    // fallback makes a language switch incapable of rewriting the old UI.
    if (isHistoricalChineseLanguage(m_currentLanguageId))
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveContextText(m_currentLanguageId, contextKey, sourceText, &visitedLanguageIds);
}

QString ks::i18n::LanguageManager::sourceText(const QString& sourceText) const
{
    if (sourceText.isEmpty() || isHistoricalChineseLanguage(m_currentLanguageId))
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveSourceText(
        m_currentLanguageId,
        sourceText,
        &visitedLanguageIds,
        true);
}

QString ks::i18n::LanguageManager::packedSourceText(const QString& sourceText) const
{
    if (sourceText.isEmpty())
    {
        return sourceText;
    }

    QStringList visitedLanguageIds;
    return resolveSourceText(
        m_currentLanguageId,
        sourceText,
        &visitedLanguageIds,
        false);
}

QString ks::i18n::LanguageManager::sourceForRenderedText(const QString& renderedText) const
{
    if (renderedText.isEmpty() || containsHanCharacters(renderedText))
    {
        return {};
    }

    // 只沿当前语言的 fallback 链反查：界面上呈现的译文只可能来自当前生效的包，
    // 扫描未启用的语言既会把它们全部加载进内存，也不对应任何已显示的文本。
    // 反查索引本身在各包第一次走到这里时才构建。
    QStringList visitedLanguageIds;
    QString languageId = m_currentLanguageId;
    while (!languageId.trimmed().isEmpty())
    {
        const QString normalizedLanguageId = languageId.trimmed().toLower();
        if (visitedLanguageIds.contains(normalizedLanguageId))
        {
            break;
        }
        visitedLanguageIds.append(normalizedLanguageId);

        const PackRef pack = acquirePack(normalizedLanguageId);
        if (!pack.found)
        {
            break;
        }
        if (pack.data)
        {
            const QStringView source = pack.data->renderedSource(renderedText);
            if (!source.isEmpty())
            {
                return source.toString();
            }
        }
        languageId = pack.fallbackLanguageId;
    }
    return {};
}

QString ks::i18n::LanguageManager::displayText(const QString& renderedOrSourceText) const
{
    if (renderedOrSourceText.isEmpty())
    {
        return renderedOrSourceText;
    }
    if (containsHanCharacters(renderedOrSourceText))
    {
        return sourceText(renderedOrSourceText);
    }

    const QString canonicalSource = sourceForRenderedText(renderedOrSourceText);
    return canonicalSource.isEmpty() ? renderedOrSourceText : sourceText(canonicalSource);
}

void ks::i18n::LanguageManager::bindText(
    QObject* object,
    const QString& key,
    const QString& fallbackText)
{
    if (object == nullptr)
    {
        return;
    }
    object->setProperty(kTextKeyProperty, key);
    object->setProperty(kTextFallbackProperty, fallbackText);
    applyBindings(object);
}

void ks::i18n::LanguageManager::bindToolTip(
    QWidget* widget,
    const QString& key,
    const QString& fallbackText)
{
    if (widget == nullptr)
    {
        return;
    }
    widget->setProperty(kToolTipKeyProperty, key);
    widget->setProperty(kToolTipFallbackProperty, fallbackText);
    applyBindings(widget);
}

void ks::i18n::LanguageManager::bindPlaceholder(
    QLineEdit* lineEdit,
    const QString& key,
    const QString& fallbackText)
{
    if (lineEdit == nullptr)
    {
        return;
    }
    lineEdit->setProperty(kPlaceholderKeyProperty, key);
    lineEdit->setProperty(kPlaceholderFallbackProperty, fallbackText);
    applyBindings(lineEdit);
}

void ks::i18n::LanguageManager::bindSuffix(
    QSpinBox* spinBox,
    const QString& key,
    const QString& fallbackText)
{
    if (spinBox == nullptr)
    {
        return;
    }
    spinBox->setProperty(kSuffixKeyProperty, key);
    spinBox->setProperty(kSuffixFallbackProperty, fallbackText);
    applyBindings(spinBox);
}

void ks::i18n::LanguageManager::bindWindowTitle(
    QWidget* widget,
    const QString& key,
    const QString& fallbackText)
{
    if (widget == nullptr)
    {
        return;
    }
    widget->setProperty(kWindowTitleKeyProperty, key);
    widget->setProperty(kWindowTitleFallbackProperty, fallbackText);
    applyBindings(widget);
}

void ks::i18n::LanguageManager::bindTab(
    QTabWidget* tabWidget,
    QWidget* page,
    const QString& key,
    const QString& fallbackText)
{
    if (tabWidget == nullptr || page == nullptr)
    {
        return;
    }
    page->setProperty(kTabKeyProperty, key);
    page->setProperty(kTabFallbackProperty, fallbackText);
    applyBindings(tabWidget);
}

void ks::i18n::LanguageManager::bindTabToolTip(
    QTabWidget* tabWidget,
    QWidget* page,
    const QString& key,
    const QString& fallbackText)
{
    if (tabWidget == nullptr || page == nullptr || tabWidget->indexOf(page) < 0)
    {
        return;
    }
    page->setProperty(kTabToolTipKeyProperty, key);
    page->setProperty(kTabToolTipFallbackProperty, fallbackText);
    applyBindings(tabWidget);
}

void ks::i18n::LanguageManager::bindComboBoxItem(
    QComboBox* comboBox,
    const int itemIndex,
    const QString& key,
    const QString& fallbackText)
{
    if (comboBox == nullptr || itemIndex < 0 || itemIndex >= comboBox->count())
    {
        return;
    }
    comboBox->setItemData(itemIndex, key, kComboKeyRole);
    comboBox->setItemData(itemIndex, fallbackText, kComboFallbackRole);
    applyBindings(comboBox);
}

void ks::i18n::LanguageManager::retranslateAll()
{
    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }

    const QWidgetList topLevelWidgetList = application->topLevelWidgets();
    for (QWidget* widget : topLevelWidgetList)
    {
        if (widget == nullptr)
        {
            continue;
        }
        QList<QPointer<QWidget>> widgetList;
        widgetList.append(QPointer<QWidget>(widget));
        const QList<QWidget*> childWidgetList = widget->findChildren<QWidget*>();
        widgetList.reserve(widgetList.size() + childWidgetList.size());
        for (QWidget* childWidget : childWidgetList)
        {
            widgetList.append(QPointer<QWidget>(childWidget));
        }

        // Qt normally delivers LanguageChange to top-level widgets. KSword
        // contains many nested, independently implemented pages, so deliver the
        // event to every live widget as well. This keeps already-created lazy
        // pages, tables, charts, and dialogs in sync without a restart.
        for (const QPointer<QWidget>& targetWidget : widgetList)
        {
            if (targetWidget.isNull())
            {
                continue;
            }
            QEvent languageChangeEvent(QEvent::LanguageChange);
            QCoreApplication::sendEvent(targetWidget.data(), &languageChangeEvent);
        }
        applyBindings(widget);
        applyRuntimeTranslations(widget);
    }
}

void ks::i18n::LanguageManager::discoverLanguagePacks(QStringList* warningListOut)
{
    // 只扫描清单：每个包只读顶层标量字段，三张翻译表被跳过。
    // 翻译表由 acquirePack 在该语言第一次被查询时才解析，未使用的语言不占翻译表内存。
    QMutexLocker locker(&m_state->mutex);
    m_state->packs.clear();

    const QStringList directoryList = languageDirectoryCandidates();
    for (const QString& directoryPath : directoryList)
    {
        QDir languageDirectory(directoryPath);
        if (!languageDirectory.exists())
        {
            continue;
        }

        const QFileInfoList fileInfoList = languageDirectory.entryInfoList(
            QStringList{ QStringLiteral("*.json") },
            QDir::Files | QDir::Readable,
            QDir::Name | QDir::IgnoreCase);
        for (const QFileInfo& fileInfo : fileInfoList)
        {
            PackMetadata metadata;
            QString loadErrorText;
            if (!loadPackFile(fileInfo.absoluteFilePath(), nullptr, &metadata, &loadErrorText))
            {
                if (warningListOut != nullptr)
                {
                    warningListOut->append(loadErrorText);
                }
                continue;
            }

            const bool alreadyLoaded = std::any_of(
                m_state->packs.cbegin(),
                m_state->packs.cend(),
                [&metadata](const State::PackEntry& entry) {
                    return entry.info.id.compare(metadata.id, Qt::CaseInsensitive) == 0;
                });
            if (alreadyLoaded)
            {
                continue;
            }

            State::PackEntry entry;
            entry.info.id = metadata.id;
            entry.info.name = metadata.name;
            entry.info.nativeName = metadata.nativeName;
            entry.info.author = metadata.author;
            entry.info.filePath = QDir::cleanPath(fileInfo.absoluteFilePath());
            entry.info.rightToLeft = metadata.textDirection.compare(
                QStringLiteral("rtl"),
                Qt::CaseInsensitive) == 0;
            entry.fallbackLanguageId = metadata.fallback;
            m_state->packs.push_back(std::move(entry));
        }
    }

    std::sort(
        m_state->packs.begin(),
        m_state->packs.end(),
        [](const State::PackEntry& left, const State::PackEntry& right) {
            return left.info.nativeName.localeAwareCompare(right.info.nativeName) < 0;
        });
}

QString ks::i18n::LanguageManager::resolveText(
    const QString& languageId,
    const QString& key,
    const QString& fallbackText,
    QStringList* visitedLanguageIds) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty())
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }

    const QString normalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(normalizedLanguageId))
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }
    visitedLanguageIds->append(normalizedLanguageId);

    // zh-CN is the source-language baseline. The fallback at the original
    // call site is authoritative so a generated/edited pack cannot alter it.
    if (isHistoricalChineseLanguage(normalizedLanguageId) && !fallbackText.isEmpty())
    {
        return fallbackText;
    }

    const PackRef pack = acquirePack(normalizedLanguageId);
    if (!pack.found || !pack.data)
    {
        return fallbackText.isEmpty() ? key : fallbackText;
    }

    if (const StringEntry* entry = pack.data->find(pack.data->translations, key))
    {
        return pack.data->valueOf(*entry).toString();
    }
    if (const StringEntry* entry = pack.data->find(pack.data->contextTranslations, key))
    {
        return pack.data->valueOf(*entry).toString();
    }
    if (!pack.fallbackLanguageId.isEmpty())
    {
        return resolveText(
            pack.fallbackLanguageId,
            key,
            fallbackText,
            visitedLanguageIds);
    }
    return fallbackText.isEmpty() ? key : fallbackText;
}

QString ks::i18n::LanguageManager::resolveContextText(
    const QString& languageId,
    const QString& contextKey,
    const QString& sourceText,
    QStringList* visitedLanguageIds) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty())
    {
        return sourceText;
    }

    const QString normalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(normalizedLanguageId))
    {
        return sourceText;
    }
    visitedLanguageIds->append(normalizedLanguageId);

    // Keep the historical Chinese fallback authoritative even when a third
    // language reaches zh-CN through its fallback chain.
    if (isHistoricalChineseLanguage(normalizedLanguageId))
    {
        return sourceText;
    }

    const PackRef pack = acquirePack(normalizedLanguageId);
    if (!pack.found || !pack.data)
    {
        return sourceText;
    }

    if (const StringEntry* entry = pack.data->find(pack.data->contextTranslations, contextKey))
    {
        return pack.data->valueOf(*entry).toString();
    }
    if (!pack.fallbackLanguageId.isEmpty())
    {
        return resolveContextText(
            pack.fallbackLanguageId,
            contextKey,
            sourceText,
            visitedLanguageIds);
    }
    return sourceText;
}

QString ks::i18n::LanguageManager::resolveSourceText(
    const QString& languageId,
    const QString& sourceText,
    QStringList* visitedLanguageIds,
    const bool preserveHistoricalChineseSource) const
{
    if (visitedLanguageIds == nullptr || languageId.trimmed().isEmpty() || sourceText.isEmpty())
    {
        return sourceText;
    }

    const QString normalizedLanguageId = languageId.trimmed().toLower();
    if (visitedLanguageIds->contains(normalizedLanguageId))
    {
        return sourceText;
    }
    visitedLanguageIds->append(normalizedLanguageId);

    if (preserveHistoricalChineseSource
        && isHistoricalChineseLanguage(normalizedLanguageId))
    {
        return sourceText;
    }

    const PackRef pack = acquirePack(normalizedLanguageId);
    if (!pack.found || !pack.data)
    {
        return sourceText;
    }

    if (const StringEntry* entry = pack.data->find(pack.data->sourceTranslations, sourceText))
    {
        return pack.data->valueOf(*entry).toString();
    }

    if (containsHanCharacters(sourceText))
    {
        for (const TemplateRef& reference : pack.data->sourceTemplates)
        {
            const StringEntry& entry = pack.data->sourceTranslations[reference.entryIndex];
            const QStringView patternText = pack.data->keyOf(entry);
            if (reference.prefixLength > 0
                && !sourceText.startsWith(patternText.first(reference.prefixLength)))
            {
                continue;
            }
            if (reference.suffixLength > 0
                && !sourceText.endsWith(patternText.last(reference.suffixLength)))
            {
                continue;
            }

            ParsedTemplate parsedPattern = parseTemplate(patternText);
            if (!matchTemplate(sourceText, parsedPattern))
            {
                continue;
            }

            const QStringView translatedPattern = pack.data->valueOf(entry);
            QString translatedText;
            qsizetype previousEnd = 0;
            qsizetype placeholderStart = 0;
            qsizetype placeholderLength = 0;
            while (findPlaceholder(translatedPattern, previousEnd, &placeholderStart, &placeholderLength))
            {
                translatedText += translatedPattern.sliced(
                    previousEnd,
                    placeholderStart - previousEnd);
                const QStringView placeholder = translatedPattern.sliced(
                    placeholderStart,
                    placeholderLength);
                // 同一占位符在源串里多次出现时取第一次的捕获，与旧实现的登记顺序一致。
                const auto placeholderIterator = std::find(
                    parsedPattern.placeholders.cbegin(),
                    parsedPattern.placeholders.cend(),
                    placeholder);
                if (placeholderIterator == parsedPattern.placeholders.cend())
                {
                    translatedText.clear();
                    break;
                }
                // Placeholder values can themselves be stable UI phrases (for
                // example a translated status template receiving "安全模式").
                // Resolve each captured value independently so an English outer
                // template cannot retain a nested Chinese enum/status string.
                const std::size_t captureIndex = static_cast<std::size_t>(
                    placeholderIterator - parsedPattern.placeholders.cbegin());
                translatedText += this->sourceText(
                    parsedPattern.captures[captureIndex].toString());
                previousEnd = placeholderStart + placeholderLength;
            }
            if (!translatedText.isNull())
            {
                translatedText += translatedPattern.sliced(previousEnd);
                return translatedText;
            }
        }
    }

    if (!pack.fallbackLanguageId.isEmpty())
    {
        return resolveSourceText(
            pack.fallbackLanguageId,
            sourceText,
            visitedLanguageIds,
            preserveHistoricalChineseSource);
    }
    return sourceText;
}

void ks::i18n::LanguageManager::ensureApplicationEventFilter()
{
    if (m_applicationEventFilterInstalled)
    {
        return;
    }

    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }
    application->installEventFilter(this);
    m_applicationEventFilterInstalled = true;
}

void ks::i18n::LanguageManager::scheduleRuntimeTranslation(QObject* object)
{
    if (object == nullptr || m_applyingRuntimeTranslations
        || object->property(kRuntimeRefreshPendingProperty).toBool())
    {
        return;
    }

    object->setProperty(kRuntimeRefreshPendingProperty, true);
    const QPointer<QObject> guardedObject(object);
    QTimer::singleShot(0, this, [this, guardedObject]() {
        if (guardedObject.isNull())
        {
            return;
        }
        guardedObject->setProperty(kRuntimeRefreshPendingProperty, false);
        applyRuntimeTranslations(guardedObject.data());
    });
}

bool ks::i18n::LanguageManager::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == nullptr || event == nullptr || m_applyingRuntimeTranslations
        || isHistoricalChineseLanguage(m_currentLanguageId))
    {
        return QObject::eventFilter(watched, event);
    }

    switch (event->type())
    {
    case QEvent::ChildAdded:
    {
        QChildEvent* childEvent = static_cast<QChildEvent*>(event);
        QObject* targetObject = childEvent->child() != nullptr ? childEvent->child() : watched;
        scheduleRuntimeTranslation(runtimeTranslationRoot(targetObject));
        break;
    }
    case QEvent::Show:
    case QEvent::PolishRequest:
    case QEvent::ActionAdded:
    case QEvent::ActionChanged:
        scheduleRuntimeTranslation(runtimeTranslationRoot(watched));
        break;
    case QEvent::LayoutRequest:
    case QEvent::UpdateRequest:
    {
        QObject* targetObject = watched;
        if (qobject_cast<QHeaderView*>(watched) != nullptr)
        {
            QObject* parentObject = watched->parent();
            while (parentObject != nullptr && qobject_cast<QAbstractItemView*>(parentObject) == nullptr)
            {
                parentObject = parentObject->parent();
            }
            if (parentObject != nullptr)
            {
                targetObject = parentObject;
            }
        }
        scheduleRuntimeTranslation(targetObject);
        break;
    }
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void ks::i18n::LanguageManager::applyRuntimeTranslations(QObject* object)
{
    if (object == nullptr || m_applyingRuntimeTranslations)
    {
        return;
    }

    QScopedValueRollback<bool> translationGuard(m_applyingRuntimeTranslations, true);
    std::function<void(QAbstractItemModel*, const QModelIndex&, int&)> translateModelItems;
    translateModelItems = [this, &translateModelItems](
                              QAbstractItemModel* model,
                              const QModelIndex& parentIndex,
                              int& remainingIndexBudget) {
        if (model == nullptr || remainingIndexBudget <= 0)
        {
            return;
        }

        const int rowCount = model->rowCount(parentIndex);
        const int columnCount = model->columnCount(parentIndex);
        for (int row = 0; row < rowCount && remainingIndexBudget > 0; ++row)
        {
            for (int column = 0; column < columnCount && remainingIndexBudget > 0; ++column)
            {
                const QModelIndex index = model->index(row, column, parentIndex);
                --remainingIndexBudget;
                if (!index.isValid())
                {
                    continue;
                }

                const QVariant sourceValue = model->data(index, kRuntimeModelSourceRole);
                const QVariant appliedValue = model->data(index, kRuntimeModelAppliedRole);
                const ManagedTextResult result = resolveManagedText(
                    *this,
                    model->data(index, Qt::DisplayRole).toString(),
                    sourceValue,
                    appliedValue,
                    false);
                if (result.clearMetadata)
                {
                    model->setData(index, QVariant(), kRuntimeModelSourceRole);
                    model->setData(index, QVariant(), kRuntimeModelAppliedRole);
                    continue;
                }
                if (!result.updateMetadata)
                {
                    continue;
                }

                // Do not mutate read-only/custom models that reject our
                // private roles. This keeps runtime/user data untouched.
                if (!model->setData(index, result.sourceText, kRuntimeModelSourceRole))
                {
                    continue;
                }
                if (!model->setData(index, result.appliedText, kRuntimeModelAppliedRole))
                {
                    model->setData(index, QVariant(), kRuntimeModelSourceRole);
                    continue;
                }
                if (result.setText
                    && !model->setData(index, result.appliedText, Qt::DisplayRole))
                {
                    model->setData(index, QVariant(), kRuntimeModelSourceRole);
                    model->setData(index, QVariant(), kRuntimeModelAppliedRole);
                }
            }

            const QModelIndex childParent = model->index(row, 0, parentIndex);
            if (childParent.isValid() && model->hasChildren(childParent))
            {
                translateModelItems(model, childParent, remainingIndexBudget);
            }
        }
    };

    std::function<void(QObject*)> visitObject;
    visitObject = [this, &translateModelItems, &visitObject](QObject* currentObject) {
        if (currentObject == nullptr)
        {
            return;
        }

        if (QAction* action = qobject_cast<QAction*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                action,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                action->text(),
                [action](const QString& value) { action->setText(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeToolTipSourceProperty,
                kRuntimeToolTipAppliedProperty,
                action->toolTip(),
                [action](const QString& value) { action->setToolTip(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeStatusTipSourceProperty,
                kRuntimeStatusTipAppliedProperty,
                action->statusTip(),
                [action](const QString& value) { action->setStatusTip(value); });
            applyManagedObjectText(
                *this,
                action,
                kRuntimeWhatsThisSourceProperty,
                kRuntimeWhatsThisAppliedProperty,
                action->whatsThis(),
                [action](const QString& value) { action->setWhatsThis(value); });
        }

        if (QWidget* widget = qobject_cast<QWidget*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeWindowTitleSourceProperty,
                kRuntimeWindowTitleAppliedProperty,
                widget->windowTitle(),
                [widget](const QString& value) { widget->setWindowTitle(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeToolTipSourceProperty,
                kRuntimeToolTipAppliedProperty,
                widget->toolTip(),
                [widget](const QString& value) { widget->setToolTip(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeStatusTipSourceProperty,
                kRuntimeStatusTipAppliedProperty,
                widget->statusTip(),
                [widget](const QString& value) { widget->setStatusTip(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeWhatsThisSourceProperty,
                kRuntimeWhatsThisAppliedProperty,
                widget->whatsThis(),
                [widget](const QString& value) { widget->setWhatsThis(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeAccessibleNameSourceProperty,
                kRuntimeAccessibleNameAppliedProperty,
                widget->accessibleName(),
                [widget](const QString& value) { widget->setAccessibleName(value); });
            applyManagedObjectText(
                *this,
                widget,
                kRuntimeAccessibleDescriptionSourceProperty,
                kRuntimeAccessibleDescriptionAppliedProperty,
                widget->accessibleDescription(),
                [widget](const QString& value) { widget->setAccessibleDescription(value); });
        }

        if (QLabel* label = qobject_cast<QLabel*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                label,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                label->text(),
                [label](const QString& value) { label->setText(value); });
        }
        else if (QAbstractButton* button = qobject_cast<QAbstractButton*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                button,
                kRuntimeTextSourceProperty,
                kRuntimeTextAppliedProperty,
                button->text(),
                [button](const QString& value) { button->setText(value); });
        }

        if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                groupBox,
                kRuntimeTitleSourceProperty,
                kRuntimeTitleAppliedProperty,
                groupBox->title(),
                [groupBox](const QString& value) { groupBox->setTitle(value); });
        }
        if (QMenu* menu = qobject_cast<QMenu*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                menu,
                kRuntimeTitleSourceProperty,
                kRuntimeTitleAppliedProperty,
                menu->title(),
                [menu](const QString& value) { menu->setTitle(value); });
        }
        if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                lineEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                lineEdit->placeholderText(),
                [lineEdit](const QString& value) { lineEdit->setPlaceholderText(value); });
        }
        if (QPlainTextEdit* plainTextEdit = qobject_cast<QPlainTextEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                plainTextEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                plainTextEdit->placeholderText(),
                [plainTextEdit](const QString& value) { plainTextEdit->setPlaceholderText(value); });
        }
        if (QTextEdit* textEdit = qobject_cast<QTextEdit*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                textEdit,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                textEdit->placeholderText(),
                [textEdit](const QString& value) { textEdit->setPlaceholderText(value); });
        }

        const auto translateSpinBox = [this](auto* spinBox) {
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimePrefixSourceProperty,
                kRuntimePrefixAppliedProperty,
                spinBox->prefix(),
                [spinBox](const QString& value) { spinBox->setPrefix(value); });
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimeSuffixSourceProperty,
                kRuntimeSuffixAppliedProperty,
                spinBox->suffix(),
                [spinBox](const QString& value) { spinBox->setSuffix(value); });
            applyManagedObjectText(
                *this,
                spinBox,
                kRuntimeSpecialValueSourceProperty,
                kRuntimeSpecialValueAppliedProperty,
                spinBox->specialValueText(),
                [spinBox](const QString& value) { spinBox->setSpecialValueText(value); });
        };
        if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(currentObject))
        {
            translateSpinBox(spinBox);
        }
        else if (QDoubleSpinBox* doubleSpinBox = qobject_cast<QDoubleSpinBox*>(currentObject))
        {
            translateSpinBox(doubleSpinBox);
        }

        if (QComboBox* comboBox = qobject_cast<QComboBox*>(currentObject))
        {
            applyManagedObjectText(
                *this,
                comboBox,
                kRuntimePlaceholderSourceProperty,
                kRuntimePlaceholderAppliedProperty,
                comboBox->placeholderText(),
                [comboBox](const QString& value) { comboBox->setPlaceholderText(value); });
            for (int itemIndex = 0; itemIndex < comboBox->count(); ++itemIndex)
            {
                const ManagedTextResult result = resolveManagedText(
                    *this,
                    comboBox->itemText(itemIndex),
                    comboBox->itemData(itemIndex, kRuntimeComboSourceRole),
                    comboBox->itemData(itemIndex, kRuntimeComboAppliedRole));
                if (result.clearMetadata)
                {
                    comboBox->setItemData(itemIndex, QVariant(), kRuntimeComboSourceRole);
                    comboBox->setItemData(itemIndex, QVariant(), kRuntimeComboAppliedRole);
                    continue;
                }
                if (!result.updateMetadata)
                {
                    continue;
                }
                if (result.setText)
                {
                    comboBox->setItemText(itemIndex, result.appliedText);
                }
                comboBox->setItemData(itemIndex, result.sourceText, kRuntimeComboSourceRole);
                comboBox->setItemData(itemIndex, result.appliedText, kRuntimeComboAppliedRole);
            }
        }

        if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(currentObject))
        {
            for (int tabIndex = 0; tabIndex < tabWidget->count(); ++tabIndex)
            {
                QWidget* page = tabWidget->widget(tabIndex);
                if (page == nullptr)
                {
                    continue;
                }
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabSourceProperty,
                    kRuntimeTabAppliedProperty,
                    tabWidget->tabText(tabIndex),
                    [tabWidget, tabIndex](const QString& value) { tabWidget->setTabText(tabIndex, value); });
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabToolTipSourceProperty,
                    kRuntimeTabToolTipAppliedProperty,
                    tabWidget->tabToolTip(tabIndex),
                    [tabWidget, tabIndex](const QString& value) { tabWidget->setTabToolTip(tabIndex, value); });
            }
        }
        if (QToolBox* toolBox = qobject_cast<QToolBox*>(currentObject))
        {
            for (int itemIndex = 0; itemIndex < toolBox->count(); ++itemIndex)
            {
                QWidget* page = toolBox->widget(itemIndex);
                if (page == nullptr)
                {
                    continue;
                }
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabSourceProperty,
                    kRuntimeTabAppliedProperty,
                    toolBox->itemText(itemIndex),
                    [toolBox, itemIndex](const QString& value) { toolBox->setItemText(itemIndex, value); });
                applyManagedObjectText(
                    *this,
                    page,
                    kRuntimeTabToolTipSourceProperty,
                    kRuntimeTabToolTipAppliedProperty,
                    toolBox->itemToolTip(itemIndex),
                    [toolBox, itemIndex](const QString& value) { toolBox->setItemToolTip(itemIndex, value); });
            }
        }

        if (QTableView* tableView = qobject_cast<QTableView*>(currentObject))
        {
            QAbstractItemModel* model = tableView->model();
            if (model != nullptr)
            {
                const int columnCount = model->columnCount(tableView->rootIndex());
                for (int section = 0; section < columnCount; ++section)
                {
                    const QString currentHeader = model->headerData(
                        section,
                        Qt::Horizontal,
                        Qt::DisplayRole).toString();
                    const ManagedTextResult result = resolveManagedText(
                        *this,
                        currentHeader,
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderSourceRole),
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderAppliedRole));
                    if (result.clearMetadata)
                    {
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderSourceRole);
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderAppliedRole);
                        continue;
                    }
                    if (!result.updateMetadata)
                    {
                        continue;
                    }
                    if (result.setText
                        && !model->setHeaderData(section, Qt::Horizontal, result.appliedText, Qt::DisplayRole))
                    {
                        continue;
                    }
                    model->setHeaderData(section, Qt::Horizontal, result.sourceText, kRuntimeHeaderSourceRole);
                    model->setHeaderData(section, Qt::Horizontal, result.appliedText, kRuntimeHeaderAppliedRole);
                }
                int remainingIndexBudget = 50000;
                translateModelItems(model, tableView->rootIndex(), remainingIndexBudget);
            }
        }
        else if (QTreeView* treeView = qobject_cast<QTreeView*>(currentObject))
        {
            QAbstractItemModel* model = treeView->model();
            if (model != nullptr)
            {
                const int columnCount = model->columnCount(treeView->rootIndex());
                for (int section = 0; section < columnCount; ++section)
                {
                    const QString currentHeader = model->headerData(
                        section,
                        Qt::Horizontal,
                        Qt::DisplayRole).toString();
                    const ManagedTextResult result = resolveManagedText(
                        *this,
                        currentHeader,
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderSourceRole),
                        model->headerData(section, Qt::Horizontal, kRuntimeHeaderAppliedRole));
                    if (result.clearMetadata)
                    {
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderSourceRole);
                        model->setHeaderData(section, Qt::Horizontal, QVariant(), kRuntimeHeaderAppliedRole);
                        continue;
                    }
                    if (!result.updateMetadata)
                    {
                        continue;
                    }
                    if (result.setText
                        && !model->setHeaderData(section, Qt::Horizontal, result.appliedText, Qt::DisplayRole))
                    {
                        continue;
                    }
                    model->setHeaderData(section, Qt::Horizontal, result.sourceText, kRuntimeHeaderSourceRole);
                    model->setHeaderData(section, Qt::Horizontal, result.appliedText, kRuntimeHeaderAppliedRole);
                }
                int remainingIndexBudget = 50000;
                translateModelItems(model, treeView->rootIndex(), remainingIndexBudget);
            }
        }

        const QObjectList childList = currentObject->children();
        for (QObject* childObject : childList)
        {
            visitObject(childObject);
        }
    };

    visitObject(object);
}

void ks::i18n::LanguageManager::applyBindings(QObject* object) const
{
    if (object == nullptr)
    {
        return;
    }

    const QString textKey = object->property(kTextKeyProperty).toString();
    if (!textKey.isEmpty())
    {
        const QString translatedText = text(textKey, object->property(kTextFallbackProperty).toString());
        if (QAbstractButton* button = qobject_cast<QAbstractButton*>(object))
        {
            button->setText(translatedText);
        }
        else if (QLabel* label = qobject_cast<QLabel*>(object))
        {
            label->setText(translatedText);
        }
        else if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(object))
        {
            groupBox->setTitle(translatedText);
        }
        else if (QAction* action = qobject_cast<QAction*>(object))
        {
            action->setText(translatedText);
        }
    }

    if (QWidget* widget = qobject_cast<QWidget*>(object))
    {
        const QString toolTipKey = widget->property(kToolTipKeyProperty).toString();
        if (!toolTipKey.isEmpty())
        {
            widget->setToolTip(text(toolTipKey, widget->property(kToolTipFallbackProperty).toString()));
        }

        const QString windowTitleKey = widget->property(kWindowTitleKeyProperty).toString();
        if (!windowTitleKey.isEmpty())
        {
            widget->setWindowTitle(text(
                windowTitleKey,
                widget->property(kWindowTitleFallbackProperty).toString()));
        }
    }

    if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(object))
    {
        const QString placeholderKey = lineEdit->property(kPlaceholderKeyProperty).toString();
        if (!placeholderKey.isEmpty())
        {
            lineEdit->setPlaceholderText(text(
                placeholderKey,
                lineEdit->property(kPlaceholderFallbackProperty).toString()));
        }
    }

    if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(object))
    {
        const QString suffixKey = spinBox->property(kSuffixKeyProperty).toString();
        if (!suffixKey.isEmpty())
        {
            spinBox->setSuffix(text(
                suffixKey,
                spinBox->property(kSuffixFallbackProperty).toString()));
        }
    }

    if (QComboBox* comboBox = qobject_cast<QComboBox*>(object))
    {
        for (int index = 0; index < comboBox->count(); ++index)
        {
            const QString itemKey = comboBox->itemData(index, kComboKeyRole).toString();
            if (!itemKey.isEmpty())
            {
                comboBox->setItemText(index, text(itemKey, comboBox->itemData(index, kComboFallbackRole).toString()));
            }
        }
    }

    if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(object))
    {
        for (int index = 0; index < tabWidget->count(); ++index)
        {
            QWidget* page = tabWidget->widget(index);
            if (page == nullptr)
            {
                continue;
            }
            const QString tabKey = page->property(kTabKeyProperty).toString();
            if (!tabKey.isEmpty())
            {
                tabWidget->setTabText(index, text(tabKey, page->property(kTabFallbackProperty).toString()));
            }
            const QString tabToolTipKey = page->property(kTabToolTipKeyProperty).toString();
            if (!tabToolTipKey.isEmpty())
            {
                tabWidget->setTabToolTip(
                    index,
                    text(tabToolTipKey, page->property(kTabToolTipFallbackProperty).toString()));
            }
        }
    }

    const QObjectList childList = object->children();
    for (QObject* childObject : childList)
    {
        applyBindings(childObject);
    }
}

void ks::i18n::LanguageManager::applyApplicationDirection() const
{
    QApplication* application = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (application == nullptr)
    {
        return;
    }

    // 书写方向来自清单里的元数据，不需要加载翻译表。
    bool rightToLeft = false;
    {
        QMutexLocker locker(&m_state->mutex);
        const auto packIterator = std::find_if(
            m_state->packs.cbegin(),
            m_state->packs.cend(),
            [this](const State::PackEntry& entry) {
                return entry.info.id.compare(m_currentLanguageId, Qt::CaseInsensitive) == 0;
            });
        rightToLeft = packIterator != m_state->packs.cend() && packIterator->info.rightToLeft;
    }
    application->setLayoutDirection(rightToLeft ? Qt::RightToLeft : Qt::LeftToRight);
}
