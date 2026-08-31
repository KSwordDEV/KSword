#include "ReportStructuredView.h"

// ============================================================
// ReportStructuredView.cpp
// 作用：
// - 实现报告纯文本 → 结构化块模型的解析；
// - 按块形态分别渲染属性表、分组树、数据表格和等宽代码块。
//
// 取舍说明：
// - 这里解析的是本程序自己拼出来的报告文本，格式由上游生成代码保证，不是外部输入；
// - 更彻底的做法是让每个采集页直接产出结构化数据，但那要改动几十处取证逻辑；
//   在展示层解析可以让所有详情页立刻摆脱纯文本框，且不冒改坏取证结果的风险；
// - 判定不成立时一律回退纯文本，宁可不结构化，也不把日志和原始数据硬拆成表格。
// ============================================================

#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QEvent>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QFrame>
#include <QHeaderView>
#include <QLabel>
#include <QLayoutItem>
#include <QMenu>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPoint>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QShowEvent>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

namespace
{
    // kMaxFieldNameLength：字段名最长字符数。
    // 超过这个长度的“冒号前半句”几乎都是叙述句而不是字段名，按说明行处理。
    constexpr int kMaxFieldNameLength = 48;

    // kMinTableRunRows：连续多少行列数一致才认定为对齐表格。
    // 取 3 是为了避免把偶然对齐的两行说明误判成表。
    constexpr int kMinTableRunRows = 3;

    // kMaxCodeBlockHeight：等宽代码块的最大像素高度，超出部分块内自行滚动。
    constexpr int kMaxCodeBlockHeight = 320;

    // scaledBlockFont 作用：转调对外公开的统一放大规则，保证本文件内外只有一处倍数定义。
    QFont scaledBlockFont(const QFont& baseFont)
    {
        return ks::ui::ScaledReportFont(baseFont);
    }

    // ParsedField：一条属性行，或一条跨列说明行。
    struct ParsedField
    {
        QString name;         // name：属性名；说明行时存放整句。
        QString value;        // value：属性值；说明行时为空。
        bool isNote = false;  // isNote：true 表示跨两列显示的说明行。
    };

    // ParsedBlock：报告中的一个连续同形态区块。
    struct ParsedBlock
    {
        enum class Kind
        {
            Fields,  // Fields：属性行集合（可夹带说明行）。
            Table,   // Table：同构多列数据行。
            Code,    // Code：hex dump / 机器码 / 需要保留原始对齐的块。
            Note     // Note：独立成段的说明文字。
        };

        Kind kind = Kind::Fields;
        QList<ParsedField> fields;    // fields：Fields 块内容。
        QList<QStringList> tableRows; // tableRows：Table 块行；含表头时为第一行。
        bool tableHasHeader = false;  // tableHasHeader：首行是否为表头。
        QStringList lines;            // lines：Code / Note 块原始行。
    };

    // ParsedSection：一个报告分组，标题为空表示无名默认分组。
    struct ParsedSection
    {
        QString title;
        QList<ParsedBlock> blocks;
    };

    // ParsedDocument：整份报告的解析结果。
    struct ParsedDocument
    {
        QString title;                 // title：报告首行标题（无标题时为空）。
        QList<ParsedSection> sections; // sections：按出现顺序排列的分组。
        int fieldCount = 0;            // fieldCount：属性行总数。
        int tableRowCount = 0;         // tableRowCount：表格数据行总数。
        int contentLineCount = 0;      // contentLineCount：非空行总数。
        int namedSectionCount = 0;     // namedSectionCount：带标题分组数量。
        bool hasNonFieldBlock = false; // hasNonFieldBlock：是否存在表格或代码块。
        bool structured = false;       // structured：是否值得提供结构视图。
    };

    // sectionTitleFrom 作用：
    // - 输入 trimmedLine：已去首尾空白的报告行；
    // - 处理：识别 “[分组]”“【分组】”“=== 分组 ===”“--- 分组 ---” 四种分组写法；
    // - 返回：命中时返回分组标题，未命中返回空字符串。
    QString sectionTitleFrom(const QString& trimmedLine)
    {
        const qsizetype lineLength = trimmedLine.size();
        if (lineLength < 3 || lineLength > 80)
        {
            return QString();
        }

        // 方括号写法：整行只有一对括号，内部不再嵌套，避免把 “[10:00:01] 日志” 当分组。
        const bool halfWidthBracket =
            trimmedLine.startsWith(QLatin1Char('[')) && trimmedLine.endsWith(QLatin1Char(']'));
        const bool fullWidthBracket =
            trimmedLine.startsWith(QChar(0x3010)) && trimmedLine.endsWith(QChar(0x3011));
        if (halfWidthBracket || fullWidthBracket)
        {
            const QString innerText = trimmedLine.mid(1, lineLength - 2).trimmed();
            if (innerText.isEmpty() ||
                innerText.contains(QLatin1Char('[')) ||
                innerText.contains(QLatin1Char(']')) ||
                innerText.contains(QChar(0x3010)) ||
                innerText.contains(QChar(0x3011)))
            {
                return QString();
            }
            return innerText;
        }

        // 等号/连字号包边写法：两端至少三个相同符号。
        for (const QChar decorationChar : { QLatin1Char('='), QLatin1Char('-') })
        {
            if (!trimmedLine.startsWith(QString(3, decorationChar)) ||
                !trimmedLine.endsWith(QString(3, decorationChar)))
            {
                continue;
            }
            QString innerText = trimmedLine;
            while (innerText.startsWith(decorationChar))
            {
                innerText.remove(0, 1);
            }
            while (innerText.endsWith(decorationChar))
            {
                innerText.chop(1);
            }
            innerText = innerText.trimmed();
            if (!innerText.isEmpty())
            {
                return innerText;
            }
        }
        return QString();
    }

    // splitFieldLine 作用：
    // - 输入 trimmedLine：已去首尾空白的报告行；nameOut/valueOut：解析结果出参；
    // - 处理：只认第一个 “: ”或全角“：”，时间戳、盘符和 NT 路径里的冒号不会被误当分界；
    //   字段名带方括号、竖线、制表符或过长时判为叙述句；
    // - 返回：true 表示这是一条属性行。
    bool splitFieldLine(const QString& trimmedLine, QString* nameOut, QString* valueOut)
    {
        const qsizetype halfWidthIndex = trimmedLine.indexOf(QStringLiteral(": "));
        const qsizetype fullWidthIndex = trimmedLine.indexOf(QChar(0xFF1A));

        qsizetype separatorIndex = -1;
        qsizetype separatorLength = 0;
        if (halfWidthIndex >= 0 && (fullWidthIndex < 0 || halfWidthIndex < fullWidthIndex))
        {
            separatorIndex = halfWidthIndex;
            separatorLength = 2;
        }
        else if (fullWidthIndex >= 0)
        {
            separatorIndex = fullWidthIndex;
            separatorLength = 1;
        }
        else if (trimmedLine.endsWith(QLatin1Char(':')))
        {
            // “名称:” 独占一行：值可能在后续缩进行，先按空值字段收下。
            separatorIndex = trimmedLine.size() - 1;
            separatorLength = 1;
        }

        if (separatorIndex <= 0)
        {
            return false;
        }

        const QString fieldName = trimmedLine.left(separatorIndex).trimmed();
        if (fieldName.isEmpty() || fieldName.size() > kMaxFieldNameLength)
        {
            return false;
        }
        if (fieldName.contains(QLatin1Char('[')) ||
            fieldName.contains(QLatin1Char(']')) ||
            fieldName.contains(QLatin1Char('|')) ||
            fieldName.contains(QLatin1Char('\t')))
        {
            return false;
        }

        if (nameOut != nullptr)
        {
            *nameOut = fieldName;
        }
        if (valueOut != nullptr)
        {
            *valueOut = trimmedLine.mid(separatorIndex + separatorLength).trimmed();
        }
        return true;
    }

    // machineCodeLineRegex 作用：
    // - 返回匹配 hex dump 与机器码行的正则；
    // - 形如 “0000: 41 42 43 44” 或 “FFFFF80542 48 8B C4 48” 的行必须保留原始对齐。
    const QRegularExpression& machineCodeLineRegex()
    {
        static const QRegularExpression pattern(
            QStringLiteral("^[0-9A-Fa-f]{4,16}\\s*[:|h]?\\s+(?:[0-9A-Fa-f]{2}\\s+){3,}"));
        return pattern;
    }

    // splitAlignedColumns 作用：
    // - 输入 trimmedLine：候选表格行；
    // - 处理：优先按竖线切分；没有竖线时按两个以上连续空白切分；
    // - 返回：切分后的列；不足两列时返回空列表。
    QStringList splitAlignedColumns(const QString& trimmedLine)
    {
        QStringList columnTexts;
        if (trimmedLine.count(QLatin1Char('|')) >= 2)
        {
            columnTexts = trimmedLine.split(QLatin1Char('|'), Qt::SkipEmptyParts);
        }
        else
        {
            static const QRegularExpression gapPattern(QStringLiteral("\\s{2,}"));
            columnTexts = trimmedLine.split(gapPattern, Qt::SkipEmptyParts);
        }

        for (QString& columnText : columnTexts)
        {
            columnText = columnText.trimmed();
        }
        columnTexts.removeAll(QString());
        return columnTexts.size() >= 2 ? columnTexts : QStringList();
    }

    // looksLikeTableHeader 作用：
    // - 输入 columnTexts：候选表头列；
    // - 处理：表头列不应含地址、纯数字或冒号赋值；
    // - 返回：true 表示这一行更像表头而不是数据行。
    bool looksLikeTableHeader(const QStringList& columnTexts)
    {
        for (const QString& columnText : columnTexts)
        {
            if (columnText.contains(QLatin1Char(':')))
            {
                return false;
            }
            bool numericConversionOk = false;
            columnText.toLongLong(&numericConversionOk);
            if (numericConversionOk || columnText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                return false;
            }
        }
        return true;
    }

    // appendBlock 作用：把已收集完的块并入当前分组，空块直接丢弃。
    void appendBlock(ParsedSection& section, ParsedBlock& block)
    {
        const bool blockEmpty =
            block.fields.isEmpty() && block.tableRows.isEmpty() && block.lines.isEmpty();
        if (!blockEmpty)
        {
            section.blocks.append(block);
        }
        block = ParsedBlock();
    }

    // parseReport 作用：
    // - 输入 reportText：已本地化的报告纯文本；
    // - 处理：逐行分类为分组标题 / 属性行 / 表格行 / 机器码行 / 说明行，
    //   连续同类行合并成块，最后按字段密度判定是否值得结构化；
    // - 返回：完整块模型。
    ParsedDocument parseReport(const QString& reportText)
    {
        ParsedDocument document;

        // JSON / XML 原文有自己的格式化通道，绝不在这里拆成属性行。
        const QString leadingText = reportText.trimmed();
        if (leadingText.startsWith(QLatin1Char('{')) || leadingText.startsWith(QLatin1Char('<')))
        {
            return document;
        }

        const QStringList reportLines = reportText.split(QLatin1Char('\n'));

        // 预扫描：标记出“连续 kMinTableRunRows 行以上列数一致”的对齐表格行。
        QList<QStringList> lineColumns;
        lineColumns.reserve(reportLines.size());
        for (const QString& reportLine : reportLines)
        {
            const QString trimmedLine = reportLine.trimmed();
            QStringList columnTexts;
            if (!trimmedLine.isEmpty() &&
                sectionTitleFrom(trimmedLine).isEmpty() &&
                !machineCodeLineRegex().match(trimmedLine).hasMatch() &&
                !splitFieldLine(trimmedLine, nullptr, nullptr))
            {
                columnTexts = splitAlignedColumns(trimmedLine);
            }
            lineColumns.append(columnTexts);
        }

        QList<bool> isTableLine;
        isTableLine.fill(false, static_cast<int>(reportLines.size()));
        for (int lineIndex = 0; lineIndex < lineColumns.size();)
        {
            const int columnCount = lineColumns.at(lineIndex).size();
            if (columnCount < 2)
            {
                ++lineIndex;
                continue;
            }

            int runEndIndex = lineIndex;
            while (runEndIndex < lineColumns.size() &&
                lineColumns.at(runEndIndex).size() == columnCount)
            {
                ++runEndIndex;
            }
            if (runEndIndex - lineIndex >= kMinTableRunRows)
            {
                for (int markIndex = lineIndex; markIndex < runEndIndex; ++markIndex)
                {
                    isTableLine[markIndex] = true;
                }
            }
            lineIndex = runEndIndex;
        }

        ParsedSection currentSection;
        ParsedBlock currentBlock;
        bool documentTitleResolved = false;
        QString pendingLeadingNote;

        // flushSection：结束当前分组并写入文档。
        auto flushSection = [&document, &currentSection, &currentBlock]()
            {
                appendBlock(currentSection, currentBlock);
                if (!currentSection.blocks.isEmpty() || !currentSection.title.isEmpty())
                {
                    document.sections.append(currentSection);
                }
                currentSection = ParsedSection();
            };

        // adoptPendingTitle：首行说明后面确实跟着正文内容，说明那一行是报告标题。
        // 四类正文分支都必须调用它，否则挂起的标题会漏到后面，被当成普通说明插错位置。
        auto adoptPendingTitle = [&document, &pendingLeadingNote]()
            {
                if (!pendingLeadingNote.isEmpty() && document.title.isEmpty())
                {
                    document.title = pendingLeadingNote;
                }
                pendingLeadingNote.clear();
            };

        for (int lineIndex = 0; lineIndex < reportLines.size(); ++lineIndex)
        {
            const QString trimmedLine = reportLines.at(lineIndex).trimmed();
            if (trimmedLine.isEmpty())
            {
                // 空行只切块，不切分组：报告里空行主要用于分隔字段簇。
                appendBlock(currentSection, currentBlock);
                continue;
            }
            ++document.contentLineCount;

            const QString sectionTitle = sectionTitleFrom(trimmedLine);
            if (!sectionTitle.isEmpty())
            {
                adoptPendingTitle();
                flushSection();
                currentSection.title = sectionTitle;
                ++document.namedSectionCount;
                documentTitleResolved = true;
                continue;
            }

            if (isTableLine.at(lineIndex))
            {
                adoptPendingTitle();
                // 列数不同的两段对齐块必须拆开：合成一张表会让后一段多出的列被静默丢掉。
                const bool columnCountChanged =
                    currentBlock.kind == ParsedBlock::Kind::Table &&
                    !currentBlock.tableRows.isEmpty() &&
                    currentBlock.tableRows.constLast().size() != lineColumns.at(lineIndex).size();
                if (currentBlock.kind != ParsedBlock::Kind::Table || columnCountChanged)
                {
                    appendBlock(currentSection, currentBlock);
                    currentBlock.kind = ParsedBlock::Kind::Table;
                    currentBlock.tableHasHeader = looksLikeTableHeader(lineColumns.at(lineIndex));
                }
                currentBlock.tableRows.append(lineColumns.at(lineIndex));
                ++document.tableRowCount;
                document.hasNonFieldBlock = true;
                documentTitleResolved = true;
                continue;
            }

            if (machineCodeLineRegex().match(trimmedLine).hasMatch())
            {
                adoptPendingTitle();
                if (currentBlock.kind != ParsedBlock::Kind::Code)
                {
                    appendBlock(currentSection, currentBlock);
                    currentBlock.kind = ParsedBlock::Kind::Code;
                }
                // 代码块保留原始行而不是 trim 结果，缩进本身就是信息。
                currentBlock.lines.append(reportLines.at(lineIndex));
                document.hasNonFieldBlock = true;
                documentTitleResolved = true;
                continue;
            }

            QString fieldName;
            QString fieldValue;
            if (splitFieldLine(trimmedLine, &fieldName, &fieldValue))
            {
                adoptPendingTitle();
                if (currentBlock.kind != ParsedBlock::Kind::Fields)
                {
                    appendBlock(currentSection, currentBlock);
                    currentBlock.kind = ParsedBlock::Kind::Fields;
                }
                currentBlock.fields.append(ParsedField{ fieldName, fieldValue, false });
                ++document.fieldCount;
                documentTitleResolved = true;
                continue;
            }

            if (!documentTitleResolved && document.title.isEmpty() && pendingLeadingNote.isEmpty())
            {
                // 报告首行常是一句标题；先挂起，等下一行确认它后面确实是字段。
                pendingLeadingNote = trimmedLine;
                continue;
            }

            if (!pendingLeadingNote.isEmpty())
            {
                // 首行后面跟的还是说明：那就不是标题，按普通说明收回正文。
                appendBlock(currentSection, currentBlock);
                currentBlock.kind = ParsedBlock::Kind::Note;
                currentBlock.lines.append(pendingLeadingNote);
                pendingLeadingNote.clear();
            }

            if (currentBlock.kind == ParsedBlock::Kind::Fields && !currentBlock.fields.isEmpty())
            {
                // 夹在字段之间的说明：留在同一张属性表里跨列显示，避免把一个字段簇拆成两块。
                currentBlock.fields.append(ParsedField{ trimmedLine, QString(), true });
                continue;
            }

            if (currentBlock.kind != ParsedBlock::Kind::Note)
            {
                appendBlock(currentSection, currentBlock);
                currentBlock.kind = ParsedBlock::Kind::Note;
            }
            currentBlock.lines.append(trimmedLine);
        }

        if (!pendingLeadingNote.isEmpty())
        {
            // 全文只有一行：既没有字段也没有后续内容，按说明处理。
            appendBlock(currentSection, currentBlock);
            currentBlock.kind = ParsedBlock::Kind::Note;
            currentBlock.lines.append(pendingLeadingNote);
        }
        flushSection();

        // 结构化判定：宁可回退纯文本，也不要把日志或散文硬塞进属性表。
        const bool fieldDense =
            document.fieldCount >= 3 &&
            document.fieldCount * 2 >= document.contentLineCount;
        const bool groupedFields =
            document.namedSectionCount >= 2 && document.fieldCount >= 2;
        const bool tableRich = document.tableRowCount >= kMinTableRunRows;
        document.structured = fieldDense || groupedFields || tableRich;
        return document;
    }

    // fixedFont 作用：返回等宽字体，用于地址、哈希和机器码。
    // 同样按 kBlockFontScale 放大：只放大正文会让同一行里的地址显得比标签矮一截。
    QFont fixedFont()
    {
        return scaledBlockFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    }

    // valueLooksMonospace 作用：
    // - 输入 valueText：属性值；
    // - 返回：true 表示该值是地址、哈希或纯十六进制，适合等宽显示。
    bool valueLooksMonospace(const QString& valueText)
    {
        if (valueText.size() < 6)
        {
            return false;
        }
        if (valueText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            return true;
        }
        for (const QChar valueChar : valueText)
        {
            const bool hexDigit =
                (valueChar >= QLatin1Char('0') && valueChar <= QLatin1Char('9')) ||
                (valueChar >= QLatin1Char('a') && valueChar <= QLatin1Char('f')) ||
                (valueChar >= QLatin1Char('A') && valueChar <= QLatin1Char('F'));
            if (!hexDigit && valueChar != QLatin1Char(' '))
            {
                return false;
            }
        }
        return true;
    }

    // valueStatusColor 作用：
    // - 输入 valueText：属性值；colorOut：命中的语义色出参；
    // - 处理：按中英双语关键词判定“正常 / 警示 / 风险”，只认整体语义明确的词；
    // - 返回：true 表示该值有语义色。
    bool valueStatusColor(const QString& valueText, QColor* colorOut)
    {
        if (valueText.isEmpty() || valueText.size() > 64)
        {
            return false;
        }

        static const QStringList errorKeywords = {
            QStringLiteral("失败"), QStringLiteral("无效"), QStringLiteral("异常"),
            QStringLiteral("篡改"), QStringLiteral("风险"), QStringLiteral("错误"),
            QStringLiteral("拒绝"), QStringLiteral("命中"), QStringLiteral("未签名"),
            QStringLiteral("failed"), QStringLiteral("invalid"), QStringLiteral("error"),
            QStringLiteral("denied"), QStringLiteral("tampered"), QStringLiteral("unsigned")
        };
        static const QStringList warningKeywords = {
            QStringLiteral("未知"), QStringLiteral("不可用"), QStringLiteral("降级"),
            QStringLiteral("未验证"), QStringLiteral("警告"), QStringLiteral("跳过"),
            QStringLiteral("unknown"), QStringLiteral("unavailable"), QStringLiteral("degraded"),
            QStringLiteral("warning"), QStringLiteral("skipped"), QStringLiteral("false")
        };
        static const QStringList successKeywords = {
            QStringLiteral("有效"), QStringLiteral("正常"), QStringLiteral("通过"),
            QStringLiteral("成功"), QStringLiteral("已验证"), QStringLiteral("已启用"),
            QStringLiteral("valid"), QStringLiteral("normal"), QStringLiteral("passed"),
            QStringLiteral("success"), QStringLiteral("verified"), QStringLiteral("enabled"),
            QStringLiteral("true")
        };

        // 先判风险再判警示，最后判正常：同一句里同时出现时以更高风险等级为准。
        for (const QString& keyword : errorKeywords)
        {
            if (valueText.contains(keyword, Qt::CaseInsensitive))
            {
                *colorOut = KswordTheme::ErrorColor();
                return true;
            }
        }
        for (const QString& keyword : warningKeywords)
        {
            if (valueText.contains(keyword, Qt::CaseInsensitive))
            {
                *colorOut = KswordTheme::WarningColor();
                return true;
            }
        }
        for (const QString& keyword : successKeywords)
        {
            if (valueText.contains(keyword, Qt::CaseInsensitive))
            {
                *colorOut = KswordTheme::SuccessColor();
                return true;
            }
        }
        return false;
    }

    // installCopyMenu 作用：
    // - 为属性表/数据表装上右键复制菜单：复制单元格、复制整行、复制全部；
    // - 结构视图不能比纯文本更难取证，复制能力必须补齐。
    void installCopyMenu(QAbstractItemView* itemView)
    {
        if (itemView == nullptr)
        {
            return;
        }

        itemView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            itemView,
            &QAbstractItemView::customContextMenuRequested,
            itemView,
            [itemView](const QPoint& menuPosition)
            {
                QAbstractItemModel* itemModel = itemView->model();
                if (itemModel == nullptr)
                {
                    return;
                }

                const QModelIndex clickedIndex = itemView->indexAt(menuPosition);
                QMenu contextMenu(itemView);
                QAction* copyCellAction = contextMenu.addAction(
                    ks::i18n::displayText(QStringLiteral("复制该值")));
                QAction* copyRowAction = contextMenu.addAction(
                    ks::i18n::displayText(QStringLiteral("复制该行")));
                QAction* copyAllAction = contextMenu.addAction(
                    ks::i18n::displayText(QStringLiteral("复制全部")));
                copyCellAction->setEnabled(clickedIndex.isValid());
                copyRowAction->setEnabled(clickedIndex.isValid());

                // rowTextAt：把一行所有非空列拼成 “A: B” 或制表符分隔文本。
                auto rowTextAt = [itemModel](const QModelIndex& rowIndex) -> QString
                    {
                        QStringList columnTexts;
                        const int columnCount = itemModel->columnCount(rowIndex.parent());
                        for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
                        {
                            const QString cellText =
                                itemModel->index(rowIndex.row(), columnIndex, rowIndex.parent())
                                    .data(Qt::DisplayRole).toString();
                            if (!cellText.isEmpty())
                            {
                                columnTexts << cellText;
                            }
                        }
                        return columnCount == 2 && columnTexts.size() == 2
                            ? QStringLiteral("%1: %2").arg(columnTexts.at(0), columnTexts.at(1))
                            : columnTexts.join(QLatin1Char('\t'));
                    };

                const QAction* selectedAction =
                    contextMenu.exec(itemView->viewport()->mapToGlobal(menuPosition));
                if (selectedAction == nullptr)
                {
                    return;
                }

                QString clipboardText;
                if (selectedAction == copyCellAction && clickedIndex.isValid())
                {
                    clipboardText = clickedIndex.data(Qt::DisplayRole).toString();
                }
                else if (selectedAction == copyRowAction && clickedIndex.isValid())
                {
                    clipboardText = rowTextAt(clickedIndex);
                }
                else if (selectedAction == copyAllAction)
                {
                    QStringList allRowTexts;
                    // 属性表最多两层，逐层取文本即可覆盖分组树与平表两种形态。
                    for (int rowIndex = 0; rowIndex < itemModel->rowCount(); ++rowIndex)
                    {
                        const QModelIndex topIndex = itemModel->index(rowIndex, 0);
                        allRowTexts << rowTextAt(topIndex);
                        for (int childIndex = 0; childIndex < itemModel->rowCount(topIndex); ++childIndex)
                        {
                            allRowTexts << rowTextAt(itemModel->index(childIndex, 0, topIndex));
                        }
                    }
                    clipboardText = allRowTexts.join(QLatin1Char('\n'));
                }

                QClipboard* clipboardObject = QApplication::clipboard();
                if (clipboardObject != nullptr && !clipboardText.isEmpty())
                {
                    clipboardObject->setText(clipboardText);
                }
            });
    }

    // kPreserveCustomFontProperty：标记本控件字体由自己维护。
    // MainWindow 在外观设置变更后会遍历所有 QAbstractItemView 强制刷成应用字体，
    // 不打这个标记的话，用户一改字体设置，报告视图的放大字号就被刷回默认档。
    constexpr const char* kPreserveCustomFontProperty = "ksword_preserve_custom_font";

    // applyNameColumnWidth 作用：
    // - 按真实属性名算名称列宽度，并夹到可用区间；
    // - 不能用 resizeColumnToContents：它会把跨列说明行的整句长度也算进第 0 列，
    //   一条长说明就能把名称列撑到上千像素，值列被挤出屏幕（GPU 页的 WMI 段就是这样）。
    void applyNameColumnWidth(QTreeWidget* treeWidget)
    {
        constexpr int kMinNameColumnWidth = 140;
        constexpr int kMaxNameColumnWidth = 360;

        const QFontMetrics nameMetrics(treeWidget->font());
        int widestNameWidth = 0;

        // 报告树最多两层（分组 + 属性行），逐层遍历即可覆盖平表与分组树两种形态。
        for (int topIndex = 0; topIndex < treeWidget->topLevelItemCount(); ++topIndex)
        {
            QTreeWidgetItem* topItem = treeWidget->topLevelItem(topIndex);
            if (!topItem->isFirstColumnSpanned())
            {
                widestNameWidth = std::max(widestNameWidth, nameMetrics.horizontalAdvance(topItem->text(0)));
            }
            for (int childIndex = 0; childIndex < topItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = topItem->child(childIndex);
                if (childItem->isFirstColumnSpanned())
                {
                    continue;
                }
                widestNameWidth = std::max(
                    widestNameWidth,
                    nameMetrics.horizontalAdvance(childItem->text(0)) + treeWidget->indentation());
            }
        }

        // 额外留出展开箭头和左右内边距；超长字段名交给 ToolTip。
        const int paddedWidth = widestNameWidth + treeWidget->indentation() + 16;
        treeWidget->setColumnWidth(
            0, std::clamp(paddedWidth, kMinNameColumnWidth, kMaxNameColumnWidth));
    }

    // configurePropertyView 作用：
    // - 统一属性视图外观：两列、不可编辑、不排序、带复制菜单；
    // - 报告行的先后顺序本身有含义（按采集顺序写的），因此一律不开排序。
    void configurePropertyView(QTreeWidget* treeWidget, const bool showTreeBranches)
    {
        treeWidget->setProperty(kPreserveCustomFontProperty, true);
        treeWidget->setColumnCount(2);
        treeWidget->setHeaderLabels(QStringList{
            ks::i18n::displayText(QStringLiteral("属性")),
            ks::i18n::displayText(QStringLiteral("值"))
            });
        treeWidget->setRootIsDecorated(showTreeBranches);
        treeWidget->setAlternatingRowColors(true);
        treeWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        treeWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        treeWidget->setUniformRowHeights(true);
        treeWidget->setSortingEnabled(false);
        treeWidget->setFrameShape(QFrame::NoFrame);
        if (treeWidget->header() != nullptr)
        {
            treeWidget->header()->setStretchLastSection(true);
        }
        installCopyMenu(treeWidget);
    }

    // applyFieldItemStyle 作用：
    // - 说明行跨两列并使用次要文字色；
    // - 属性值按语义着色，地址/哈希改等宽字体；
    // - 值同时写入 ToolTip，列宽截断时悬停仍可看全。
    void applyFieldItemStyle(QTreeWidgetItem* rowItem, const ParsedField& field)
    {
        if (field.isNote)
        {
            rowItem->setFirstColumnSpanned(true);
            rowItem->setForeground(0, KswordTheme::TextSecondaryColor());
            rowItem->setToolTip(0, field.name);
            return;
        }

        rowItem->setToolTip(1, field.value);
        QColor statusColor;
        if (valueStatusColor(field.value, &statusColor))
        {
            rowItem->setForeground(1, statusColor);
        }
        if (valueLooksMonospace(field.value))
        {
            rowItem->setFont(1, fixedFont());
        }
    }

    // appendFieldRows 作用：把一个 Fields 块的所有行追加到属性视图指定父节点下。
    void appendFieldRows(
        QTreeWidget* treeWidget,
        QTreeWidgetItem* parentItem,
        const QList<ParsedField>& fields)
    {
        for (const ParsedField& field : fields)
        {
            QTreeWidgetItem* rowItem = parentItem != nullptr
                ? new QTreeWidgetItem(parentItem)
                : new QTreeWidgetItem(treeWidget);
            rowItem->setText(0, field.name);
            if (!field.isNote)
            {
                rowItem->setText(1, field.value);
            }
            applyFieldItemStyle(rowItem, field);
        }
    }

    // propertyViewHeightFor 作用：
    // - 输入 treeWidget 与可见行数；
    // - 返回：刚好容纳全部行的高度，让外层滚动条统一负责滚动。
    int propertyViewHeightFor(const QTreeWidget* treeWidget, const int visibleRowCount)
    {
        const int rowHeight = treeWidget->fontMetrics().height() + 10;
        const int headerHeight =
            treeWidget->header() != nullptr ? treeWidget->header()->sizeHint().height() : 0;
        return headerHeight + std::max(visibleRowCount, 1) * rowHeight + 6;
    }
}

namespace ks::ui
{
    QFont ScaledReportFont(const QFont& baseFont)
    {
        // kReportFontScale：结构化报告相对界面默认字号的放大倍数。
        // 报告是要逐条读地址、哈希和路径的，沿用工具栏那一档小字号看着太吃力。
        // 全项目只有这一处定义：页面自建的属性树也走这里，字号才不会两套。
        constexpr double kReportFontScale = 1.6;

        QFont scaledFont = baseFont;
        if (scaledFont.pointSizeF() > 0.0)
        {
            scaledFont.setPointSizeF(scaledFont.pointSizeF() * kReportFontScale);
            return scaledFont;
        }
        if (scaledFont.pixelSize() > 0)
        {
            scaledFont.setPixelSize(static_cast<int>(scaledFont.pixelSize() * kReportFontScale));
        }
        return scaledFont;
    }

    ReportStructuredView::ReportStructuredView(QWidget* parent)
        : QWidget(parent)
    {
        QVBoxLayout* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(0, 0, 0, 0);
        rootLayout->setSpacing(0);

        m_scrollArea = new QScrollArea(this);
        m_scrollArea->setWidgetResizable(true);
        m_scrollArea->setFrameShape(QFrame::NoFrame);
        // 背景一律交给全局样式表：这里若自设 styleSheet，会压过祖先 Dock 的主题规则。
        m_scrollArea->viewport()->setAutoFillBackground(false);

        m_blockHost = new QWidget(m_scrollArea);
        m_blockHost->setAutoFillBackground(false);
        // 字号只在这一处放大：块控件全部是 m_blockHost 的后代，Qt 字体沿父子链继承，
        // 逐个控件 setFont 反而容易漏掉新加的块类型。
        m_blockHost->setFont(scaledBlockFont(font()));
        m_blockLayout = new QVBoxLayout(m_blockHost);
        m_blockLayout->setContentsMargins(0, 0, 0, 0);
        m_blockLayout->setSpacing(8);
        m_scrollArea->setWidget(m_blockHost);

        rootLayout->addWidget(m_scrollArea, 1);
    }

    ReportStructuredView::~ReportStructuredView() = default;

    bool ReportStructuredView::setReportText(const QString& localizedReportText)
    {
        m_reportText = localizedReportText;
        m_hasStructure = parseReport(localizedReportText).structured;
        m_blocksDirty = true;
        if (isVisible())
        {
            rebuildBlocks();
        }
        return m_hasStructure;
    }

    bool ReportStructuredView::canStructure(const QString& localizedReportText)
    {
        return parseReport(localizedReportText).structured;
    }

    bool ReportStructuredView::hasStructure() const
    {
        return m_hasStructure;
    }

    int ReportStructuredView::verticalScrollBarWidth() const
    {
        if (m_scrollArea == nullptr || m_scrollArea->verticalScrollBar() == nullptr)
        {
            return 0;
        }
        if (!m_scrollArea->verticalScrollBar()->isVisible())
        {
            return 0;
        }
        return m_scrollArea->verticalScrollBar()->width();
    }

    void ReportStructuredView::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() != QEvent::PaletteChange &&
            event->type() != QEvent::ApplicationPaletteChange &&
            event->type() != QEvent::FontChange)
        {
            return;
        }

        // 语义色和放大字号都是按当前主题/字体算出来写进块控件的，两者一变必须整块重算。
        m_blocksDirty = true;
        if (isVisible())
        {
            rebuildBlocks();
        }
    }

    void ReportStructuredView::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        if (m_blocksDirty)
        {
            rebuildBlocks();
        }
    }

    void ReportStructuredView::clearBlocks()
    {
        while (QLayoutItem* layoutItem = m_blockLayout->takeAt(0))
        {
            if (QWidget* blockWidget = layoutItem->widget())
            {
                blockWidget->setParent(nullptr);
                blockWidget->deleteLater();
            }
            delete layoutItem;
        }
    }

    void ReportStructuredView::rebuildBlocks()
    {
        m_blocksDirty = false;
        clearBlocks();

        // 每次重建都按当前继承字体重算：构造时全局样式可能还没落到控件上，
        // 而 m_blockHost 一旦显式 setFont 就不再跟随父链，只能在这里刷新。
        m_blockHost->setFont(scaledBlockFont(font()));

        const ParsedDocument document = parseReport(m_reportText);
        if (!document.structured)
        {
            return;
        }

        if (!document.title.isEmpty())
        {
            QLabel* titleLabel = new QLabel(document.title, m_blockHost);
            titleLabel->setWordWrap(true);
            QFont titleFont = titleLabel->font();
            titleFont.setBold(true);
            titleLabel->setFont(titleFont);
            m_blockLayout->addWidget(titleLabel);
        }

        // 形态一：全篇只有属性字段。
        // 这时用一棵树填满整个视图最省控件也最好用：
        // 有分组就把分组做成可折叠顶层节点，没有分组就退化成不带箭头的两列平表。
        if (!document.hasNonFieldBlock)
        {
            QTreeWidget* propertyView = new QTreeWidget(m_blockHost);
            configurePropertyView(propertyView, document.namedSectionCount > 0);

            for (const ParsedSection& section : document.sections)
            {
                QTreeWidgetItem* groupItem = nullptr;
                if (!section.title.isEmpty())
                {
                    groupItem = new QTreeWidgetItem(propertyView);
                    groupItem->setText(0, section.title);
                    QFont groupFont = groupItem->font(0);
                    groupFont.setBold(true);
                    groupItem->setFont(0, groupFont);
                    // 分组行不可选中：避免被当成一条属性复制走。
                    groupItem->setFlags(groupItem->flags() & ~Qt::ItemIsSelectable);
                    groupItem->setExpanded(true);
                }

                for (const ParsedBlock& block : section.blocks)
                {
                    if (block.kind == ParsedBlock::Kind::Fields)
                    {
                        appendFieldRows(propertyView, groupItem, block.fields);
                        continue;
                    }
                    // 说明块在纯字段文档里同样跨列显示，保证正文一行不丢。
                    QList<ParsedField> noteFields;
                    noteFields.reserve(block.lines.size());
                    for (const QString& noteLine : block.lines)
                    {
                        noteFields.append(ParsedField{ noteLine, QString(), true });
                    }
                    appendFieldRows(propertyView, groupItem, noteFields);
                }
            }

            propertyView->expandAll();
            applyNameColumnWidth(propertyView);
            m_blockLayout->addWidget(propertyView, 1);
            return;
        }

        // 形态二：报告里混有表格或机器码块。
        // 这时不能强行塞进一棵树——按块各用各的控件，纵向堆叠后统一滚动。
        for (const ParsedSection& section : document.sections)
        {
            if (!section.title.isEmpty())
            {
                QLabel* sectionLabel = new QLabel(section.title, m_blockHost);
                QFont sectionFont = sectionLabel->font();
                sectionFont.setBold(true);
                sectionLabel->setFont(sectionFont);
                sectionLabel->setContentsMargins(0, 6, 0, 0);
                m_blockLayout->addWidget(sectionLabel);
            }

            for (const ParsedBlock& block : section.blocks)
            {
                switch (block.kind)
                {
                case ParsedBlock::Kind::Fields:
                {
                    QTreeWidget* propertyView = new QTreeWidget(m_blockHost);
                    configurePropertyView(propertyView, false);
                    appendFieldRows(propertyView, nullptr, block.fields);
                    applyNameColumnWidth(propertyView);
                    propertyView->setFixedHeight(
                        propertyViewHeightFor(propertyView, static_cast<int>(block.fields.size())));
                    m_blockLayout->addWidget(propertyView);
                    break;
                }
                case ParsedBlock::Kind::Table:
                {
                    const bool useHeaderRow = block.tableHasHeader && block.tableRows.size() > 1;
                    const int dataRowOffset = useHeaderRow ? 1 : 0;
                    const int dataRowCount = static_cast<int>(block.tableRows.size()) - dataRowOffset;
                    const int columnCount = static_cast<int>(block.tableRows.at(0).size());

                    QTableWidget* tableView = new QTableWidget(dataRowCount, columnCount, m_blockHost);
                    tableView->setProperty(kPreserveCustomFontProperty, true);
                    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
                    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
                    tableView->setAlternatingRowColors(true);
                    tableView->setFrameShape(QFrame::NoFrame);
                    tableView->verticalHeader()->setVisible(false);
                    if (useHeaderRow)
                    {
                        tableView->setHorizontalHeaderLabels(block.tableRows.at(0));
                    }
                    else
                    {
                        tableView->horizontalHeader()->setVisible(false);
                    }

                    for (int dataRowIndex = 0; dataRowIndex < dataRowCount; ++dataRowIndex)
                    {
                        const QStringList& rowColumns = block.tableRows.at(dataRowIndex + dataRowOffset);
                        for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
                        {
                            const QString cellText = rowColumns.value(columnIndex);
                            QTableWidgetItem* cellItem = new QTableWidgetItem(cellText);
                            cellItem->setToolTip(cellText);
                            QColor statusColor;
                            if (valueStatusColor(cellText, &statusColor))
                            {
                                cellItem->setForeground(statusColor);
                            }
                            if (valueLooksMonospace(cellText))
                            {
                                cellItem->setFont(fixedFont());
                            }
                            tableView->setItem(dataRowIndex, columnIndex, cellItem);
                        }
                    }

                    tableView->resizeColumnsToContents();
                    tableView->horizontalHeader()->setStretchLastSection(true);
                    const int tableRowHeight = tableView->fontMetrics().height() + 10;
                    const int tableHeaderHeight = useHeaderRow
                        ? tableView->horizontalHeader()->sizeHint().height()
                        : 0;
                    tableView->setFixedHeight(
                        tableHeaderHeight + std::max(dataRowCount, 1) * tableRowHeight + 6);
                    installCopyMenu(tableView);
                    m_blockLayout->addWidget(tableView);
                    break;
                }
                case ParsedBlock::Kind::Code:
                {
                    QPlainTextEdit* codeView = new QPlainTextEdit(
                        block.lines.join(QLatin1Char('\n')), m_blockHost);
                    codeView->setReadOnly(true);
                    codeView->setFont(fixedFont());
                    codeView->setLineWrapMode(QPlainTextEdit::NoWrap);
                    codeView->setFrameShape(QFrame::NoFrame);
                    const int codeLineHeight = codeView->fontMetrics().height() + 2;
                    codeView->setFixedHeight(std::min(
                        static_cast<int>(block.lines.size()) * codeLineHeight + 12,
                        kMaxCodeBlockHeight));
                    m_blockLayout->addWidget(codeView);
                    break;
                }
                case ParsedBlock::Kind::Note:
                {
                    QLabel* noteLabel = new QLabel(
                        block.lines.join(QLatin1Char('\n')), m_blockHost);
                    noteLabel->setWordWrap(true);
                    noteLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                    noteLabel->setForegroundRole(QPalette::PlaceholderText);
                    m_blockLayout->addWidget(noteLabel);
                    break;
                }
                }
            }
        }
        m_blockLayout->addStretch(1);
    }
}
