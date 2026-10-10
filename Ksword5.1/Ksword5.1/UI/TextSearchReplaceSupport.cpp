#include "TextSearchReplaceSupport.h"
#include "./PageControlStyle.h"
#include "./ToolbarMetrics.h"

// ============================================================
// TextSearchReplaceSupport.cpp
// 说明：
// 1) 面板以文本框自身为父控件浮动定位，不参与宿主布局，
//    因此不会打乱各页面千差万别的既有布局；
// 2) 查找统一走 QTextDocument::find，正则与纯文本只是入参差异；
// 3) 替换全部时用一个编辑块包裹，保证一次撤销即可回退。
// ============================================================

#include <QAbstractScrollArea>
#include <QApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QString>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextEdit>
#include <QToolButton>
#include <QWidget>

namespace
{
    // kSearchBarProperty 作用：在文本框上标记已创建的查找面板，避免重复创建。
    constexpr const char* kSearchBarProperty = "kswordTextSearchBar";

    // kMaxCountedMatches 作用：
    // - 匹配计数需要全文扫描，超大文本会明显卡顿；
    // - 超过该上限就停止精确计数，改为显示带“+”的近似值。
    constexpr int kMaxCountedMatches = 5000;

    // EditorAccess 作用：
    // - QPlainTextEdit 与 QTextEdit 没有共同的文本操作基类，
    //   这里做一层薄适配，让查找替换逻辑只写一份。
    struct EditorAccess
    {
        QPlainTextEdit* plainEditor = nullptr;
        QTextEdit* richEditor = nullptr;

        bool isValid() const
        {
            return plainEditor != nullptr || richEditor != nullptr;
        }

        QWidget* widget() const
        {
            return plainEditor != nullptr
                ? static_cast<QWidget*>(plainEditor)
                : static_cast<QWidget*>(richEditor);
        }

        QTextDocument* document() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->document();
            }
            return richEditor != nullptr ? richEditor->document() : nullptr;
        }

        QTextCursor textCursor() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->textCursor();
            }
            return richEditor != nullptr ? richEditor->textCursor() : QTextCursor();
        }

        void setTextCursor(const QTextCursor& cursorValue) const
        {
            if (plainEditor != nullptr)
            {
                plainEditor->setTextCursor(cursorValue);
                plainEditor->ensureCursorVisible();
                return;
            }
            if (richEditor != nullptr)
            {
                richEditor->setTextCursor(cursorValue);
                richEditor->ensureCursorVisible();
            }
        }

        bool isReadOnly() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->isReadOnly();
            }
            return richEditor != nullptr ? richEditor->isReadOnly() : true;
        }

        QWidget* viewport() const
        {
            if (plainEditor != nullptr)
            {
                return plainEditor->viewport();
            }
            return richEditor != nullptr ? richEditor->viewport() : nullptr;
        }
    };

    // resolveEditor 作用：把任意控件解析为可查找的文本框视图。
    EditorAccess resolveEditor(QWidget* widgetValue)
    {
        EditorAccess accessValue{};
        if (widgetValue == nullptr)
        {
            return accessValue;
        }
        // 焦点常落在 viewport 上，这里顺带向上找一层真正的编辑器。
        QWidget* candidate = widgetValue;
        if (QWidget* parentWidget = widgetValue->parentWidget();
            parentWidget != nullptr
            && qobject_cast<QAbstractScrollArea*>(parentWidget) != nullptr
            && qobject_cast<QAbstractScrollArea*>(parentWidget)->viewport() == widgetValue)
        {
            candidate = parentWidget;
        }

        accessValue.plainEditor = qobject_cast<QPlainTextEdit*>(candidate);
        if (accessValue.plainEditor == nullptr)
        {
            accessValue.richEditor = qobject_cast<QTextEdit*>(candidate);
        }
        return accessValue;
    }

    // hasOwnFindPanel 作用：
    // - 代码编辑器与十六进制编辑器自带查找栏，全局面板必须让位；
    // - 通过类名向上匹配，避免把这两个模块的头文件拖进本文件。
    bool hasOwnFindPanel(const QWidget* editorWidget)
    {
        const QObject* currentObject = editorWidget;
        while (currentObject != nullptr)
        {
            const QString className =
                QString::fromLatin1(currentObject->metaObject()->className());
            if (className.contains(QStringLiteral("CodeEditorWidget"))
                || className.contains(QStringLiteral("HexView"))
                || className.contains(QStringLiteral("CodeTextEdit")))
            {
                return true;
            }
            currentObject = currentObject->parent();
        }
        return false;
    }

    // expandBackreferences 作用：
    // - 正则替换时把 \1..\9 展开为对应捕获组，\\ 还原为单个反斜杠；
    // - 非正则模式下替换文本按字面使用，不走这里。
    QString expandBackreferences(
        const QString& replacementText,
        const QRegularExpressionMatch& matchValue)
    {
        QString resultText;
        resultText.reserve(replacementText.size());
        for (qsizetype i = 0; i < replacementText.size(); ++i)
        {
            const QChar currentChar = replacementText.at(i);
            if (currentChar != QLatin1Char('\\') || i + 1 >= replacementText.size())
            {
                resultText.append(currentChar);
                continue;
            }

            const QChar nextChar = replacementText.at(i + 1);
            if (nextChar == QLatin1Char('\\'))
            {
                resultText.append(QLatin1Char('\\'));
                ++i;
                continue;
            }
            if (nextChar.isDigit())
            {
                const int groupIndex = nextChar.digitValue();
                if (groupIndex <= matchValue.lastCapturedIndex())
                {
                    resultText.append(matchValue.captured(groupIndex));
                }
                ++i;
                continue;
            }
            resultText.append(currentChar);
        }
        return resultText;
    }

    // TextSearchBar 作用：
    // - 浮在文本框内上方的查找替换条；
    // - 不使用 Q_OBJECT，全部走 lambda 连接，因此无需 moc 参与构建。
    class TextSearchBar final : public QWidget
    {
    public:
        explicit TextSearchBar(const EditorAccess& accessValue)
            : QWidget(accessValue.widget())
            , m_access(accessValue)
        {
            setObjectName(QStringLiteral("KswordTextSearchBar"));
            setAutoFillBackground(true);

            QHBoxLayout* rootLayout = new QHBoxLayout(this);
            rootLayout->setContentsMargins(6, 4, 6, 4);
            rootLayout->setSpacing(4);

            m_findEdit = new QLineEdit(this);
            m_findEdit->setPlaceholderText(QStringLiteral("查找"));
            ks::ui::StyleSearchField(m_findEdit);
            m_findEdit->setClearButtonEnabled(true);
            m_findEdit->setMinimumWidth(160);

            m_prevButton = new QToolButton(this);
            m_prevButton->setText(QStringLiteral("↑"));
            m_prevButton->setToolTip(QStringLiteral("查找上一个匹配项 (Shift+Enter)"));

            m_nextButton = new QToolButton(this);
            m_nextButton->setText(QStringLiteral("↓"));
            m_nextButton->setToolTip(QStringLiteral("查找下一个匹配项 (Enter)"));

            m_regexButton = new QToolButton(this);
            m_regexButton->setText(QStringLiteral(".*"));
            m_regexButton->setCheckable(true);
            m_regexButton->setToolTip(
                QStringLiteral("按正则表达式匹配；替换文本中可用 \\1..\\9 引用捕获组"));

            m_caseButton = new QToolButton(this);
            m_caseButton->setText(QStringLiteral("Aa"));
            m_caseButton->setCheckable(true);
            m_caseButton->setToolTip(QStringLiteral("区分大小写"));

            m_statusLabel = new QLabel(this);
            m_statusLabel->setMinimumWidth(72);
            m_statusLabel->setAlignment(Qt::AlignCenter);

            m_replaceEdit = new QLineEdit(this);
            m_replaceEdit->setPlaceholderText(QStringLiteral("替换为"));
            ks::ui::StyleSearchField(m_replaceEdit);
            m_replaceEdit->setClearButtonEnabled(true);
            m_replaceEdit->setMinimumWidth(140);

            m_replaceOneButton = new QToolButton(this);
            m_replaceOneButton->setText(QStringLiteral("替换"));
            m_replaceOneButton->setToolTip(QStringLiteral("替换当前匹配项并跳到下一处"));

            m_replaceAllButton = new QToolButton(this);
            m_replaceAllButton->setText(QStringLiteral("全部替换"));
            m_replaceAllButton->setToolTip(QStringLiteral("替换文本中全部匹配项，可一次撤销"));

            m_closeButton = new QToolButton(this);
            m_closeButton->setText(QStringLiteral("×"));
            m_closeButton->setToolTip(QStringLiteral("关闭查找栏 (Esc)"));

            rootLayout->addWidget(m_findEdit, 1);
            rootLayout->addWidget(m_prevButton, 0);
            rootLayout->addWidget(m_nextButton, 0);
            rootLayout->addWidget(m_regexButton, 0);
            rootLayout->addWidget(m_caseButton, 0);
            rootLayout->addWidget(m_statusLabel, 0);
            rootLayout->addWidget(m_replaceEdit, 1);
            rootLayout->addWidget(m_replaceOneButton, 0);
            rootLayout->addWidget(m_replaceAllButton, 0);
            rootLayout->addWidget(m_closeButton, 0);
            ks::ui::NormalizeToolbarRow(rootLayout);

            // 只读文本框没有替换的意义，直接隐藏这一组控件。
            const bool readOnly = m_access.isReadOnly();
            m_replaceEdit->setVisible(!readOnly);
            m_replaceOneButton->setVisible(!readOnly);
            m_replaceAllButton->setVisible(!readOnly);

            connect(m_findEdit, &QLineEdit::textChanged, this, [this]() {
                refreshMatchStatus();
            });
            connect(m_findEdit, &QLineEdit::returnPressed, this, [this]() {
                findStep(true, true);
            });
            connect(m_replaceEdit, &QLineEdit::returnPressed, this, [this]() {
                replaceCurrent();
            });
            connect(m_nextButton, &QToolButton::clicked, this, [this]() {
                findStep(true, true);
            });
            connect(m_prevButton, &QToolButton::clicked, this, [this]() {
                findStep(false, true);
            });
            connect(m_regexButton, &QToolButton::toggled, this, [this](bool) {
                refreshMatchStatus();
            });
            connect(m_caseButton, &QToolButton::toggled, this, [this](bool) {
                refreshMatchStatus();
            });
            connect(m_replaceOneButton, &QToolButton::clicked, this, [this]() {
                replaceCurrent();
            });
            connect(m_replaceAllButton, &QToolButton::clicked, this, [this]() {
                replaceAll();
            });
            connect(m_closeButton, &QToolButton::clicked, this, [this]() {
                closeBar();
            });

            m_findEdit->installEventFilter(this);
            m_replaceEdit->installEventFilter(this);
            if (QWidget* hostWidget = m_access.widget(); hostWidget != nullptr)
            {
                hostWidget->installEventFilter(this);
            }

            updateGeometryToHost();
        }

        // activate 作用：显示查找栏并把焦点交给对应输入框。
        void activate(const bool focusReplaceField)
        {
            // 选中文本时直接作为查找词，省去手工复制。
            const QTextCursor cursorValue = m_access.textCursor();
            if (cursorValue.hasSelection())
            {
                const QString selectedText = cursorValue.selectedText();
                if (!selectedText.isEmpty() && !selectedText.contains(QChar(0x2029)))
                {
                    m_findEdit->setText(selectedText);
                }
            }

            show();
            raise();
            updateGeometryToHost();
            refreshMatchStatus();

            if (focusReplaceField && !m_access.isReadOnly())
            {
                m_replaceEdit->setFocus(Qt::ShortcutFocusReason);
                m_replaceEdit->selectAll();
                return;
            }
            m_findEdit->setFocus(Qt::ShortcutFocusReason);
            m_findEdit->selectAll();
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            if (eventValue->type() == QEvent::Resize
                && watchedObject == m_access.widget())
            {
                updateGeometryToHost();
                return false;
            }
            if (eventValue->type() != QEvent::KeyPress)
            {
                return QWidget::eventFilter(watchedObject, eventValue);
            }

            QKeyEvent* keyEvent = static_cast<QKeyEvent*>(eventValue);
            if (keyEvent->key() == Qt::Key_Escape)
            {
                closeBar();
                return true;
            }
            if ((keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
                && watchedObject == m_findEdit)
            {
                findStep(!keyEvent->modifiers().testFlag(Qt::ShiftModifier), true);
                return true;
            }
            return QWidget::eventFilter(watchedObject, eventValue);
        }

        void keyPressEvent(QKeyEvent* keyEvent) override
        {
            if (keyEvent->key() == Qt::Key_Escape)
            {
                closeBar();
                return;
            }
            QWidget::keyPressEvent(keyEvent);
        }

    private:
        // closeBar 作用：隐藏查找栏并把焦点还给文本框。
        void closeBar()
        {
            hide();
            if (QWidget* hostWidget = m_access.widget(); hostWidget != nullptr)
            {
                hostWidget->setFocus(Qt::OtherFocusReason);
            }
        }

        // updateGeometryToHost 作用：
        // - 贴住文本框视口右上角浮动，宽度受视口宽度限制；
        // - 右上角比整条横幅更少遮挡正文。
        void updateGeometryToHost()
        {
            QWidget* viewportWidget = m_access.viewport();
            if (viewportWidget == nullptr)
            {
                return;
            }
            const int availableWidth = viewportWidget->width();
            const int desiredWidth = std::min(availableWidth, sizeHint().width());
            const int barHeight = sizeHint().height();
            const QPoint topLeftInHost =
                viewportWidget->mapTo(m_access.widget(), QPoint(0, 0));
            setGeometry(
                topLeftInHost.x() + std::max(0, availableWidth - desiredWidth),
                topLeftInHost.y(),
                desiredWidth,
                barHeight);
        }

        // buildRegex 作用：按当前开关组装正则；非正则模式下把查找词转义为字面量。
        QRegularExpression buildRegex(bool& validOut) const
        {
            validOut = false;
            const QString patternText = m_regexButton->isChecked()
                ? m_findEdit->text()
                : QRegularExpression::escape(m_findEdit->text());
            QRegularExpression::PatternOptions options =
                QRegularExpression::NoPatternOption;
            if (!m_caseButton->isChecked())
            {
                options |= QRegularExpression::CaseInsensitiveOption;
            }
            QRegularExpression regexValue(patternText, options);
            validOut = regexValue.isValid();
            return regexValue;
        }

        // findStep 作用：
        // - 从当前光标向指定方向查找下一处匹配；
        // - 到头后回绕一次，仍找不到则保持原位。
        bool findStep(const bool forward, const bool reportStatus)
        {
            QTextDocument* documentValue = m_access.document();
            if (documentValue == nullptr || m_findEdit->text().isEmpty())
            {
                if (reportStatus)
                {
                    refreshMatchStatus();
                }
                return false;
            }

            bool regexValid = false;
            const QRegularExpression regexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                m_statusLabel->setText(QStringLiteral("正则无效"));
                return false;
            }

            QTextDocument::FindFlags findFlags;
            if (!forward)
            {
                findFlags |= QTextDocument::FindBackward;
            }
            if (m_caseButton->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            QTextCursor foundCursor =
                documentValue->find(regexValue, m_access.textCursor(), findFlags);
            if (foundCursor.isNull())
            {
                // 回绕：向下从文首重来，向上从文末重来。
                QTextCursor wrapCursor(documentValue);
                if (!forward)
                {
                    wrapCursor.movePosition(QTextCursor::End);
                }
                foundCursor = documentValue->find(regexValue, wrapCursor, findFlags);
            }
            if (foundCursor.isNull())
            {
                if (reportStatus)
                {
                    m_statusLabel->setText(QStringLiteral("无匹配"));
                }
                return false;
            }

            m_access.setTextCursor(foundCursor);
            if (reportStatus)
            {
                refreshMatchStatus();
            }
            return true;
        }

        // refreshMatchStatus 作用：统计匹配总数并回显，超过上限只给近似值。
        void refreshMatchStatus()
        {
            QTextDocument* documentValue = m_access.document();
            if (documentValue == nullptr || m_findEdit->text().isEmpty())
            {
                m_statusLabel->clear();
                return;
            }

            bool regexValid = false;
            const QRegularExpression regexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                m_statusLabel->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextDocument::FindFlags findFlags;
            if (m_caseButton->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            int matchCount = 0;
            QTextCursor scanCursor(documentValue);
            while (matchCount < kMaxCountedMatches)
            {
                scanCursor = documentValue->find(regexValue, scanCursor, findFlags);
                if (scanCursor.isNull())
                {
                    break;
                }
                ++matchCount;
                // 空匹配（如 a*）不会推进光标，必须手动前进一格，否则死循环。
                if (scanCursor.selectionStart() == scanCursor.selectionEnd())
                {
                    if (scanCursor.atEnd())
                    {
                        break;
                    }
                    scanCursor.movePosition(QTextCursor::NextCharacter);
                }
            }

            m_statusLabel->setText(
                matchCount >= kMaxCountedMatches
                ? QStringLiteral("%1+ 项").arg(kMaxCountedMatches)
                : QStringLiteral("%1 项").arg(matchCount));
        }

        // replaceCurrent 作用：
        // - 当前选区正好命中查找条件时替换它，否则先跳到下一处；
        // - 替换后自动前进，便于连续点击。
        void replaceCurrent()
        {
            if (m_access.isReadOnly() || m_findEdit->text().isEmpty())
            {
                return;
            }
            bool regexValid = false;
            const QRegularExpression regexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                m_statusLabel->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextCursor cursorValue = m_access.textCursor();
            if (cursorValue.hasSelection())
            {
                const QRegularExpressionMatch matchValue =
                    regexValue.match(cursorValue.selectedText());
                const bool wholeSelectionMatched =
                    matchValue.hasMatch()
                    && matchValue.capturedStart() == 0
                    && matchValue.capturedLength() == cursorValue.selectedText().size();
                if (wholeSelectionMatched)
                {
                    cursorValue.insertText(
                        m_regexButton->isChecked()
                        ? expandBackreferences(m_replaceEdit->text(), matchValue)
                        : m_replaceEdit->text());
                    m_access.setTextCursor(cursorValue);
                }
            }
            findStep(true, true);
        }

        // replaceAll 作用：整篇替换，全部改动合并成一个撤销步骤。
        void replaceAll()
        {
            QTextDocument* documentValue = m_access.document();
            if (documentValue == nullptr
                || m_access.isReadOnly()
                || m_findEdit->text().isEmpty())
            {
                return;
            }
            bool regexValid = false;
            const QRegularExpression regexValue = buildRegex(regexValid);
            if (!regexValid)
            {
                m_statusLabel->setText(QStringLiteral("正则无效"));
                return;
            }

            QTextDocument::FindFlags findFlags;
            if (m_caseButton->isChecked())
            {
                findFlags |= QTextDocument::FindCaseSensitively;
            }

            int replacedCount = 0;
            QTextCursor editCursor(documentValue);
            editCursor.beginEditBlock();
            QTextCursor scanCursor(documentValue);
            while (true)
            {
                scanCursor = documentValue->find(regexValue, scanCursor, findFlags);
                if (scanCursor.isNull())
                {
                    break;
                }

                const QString matchedText = scanCursor.selectedText();
                QString replacementText = m_replaceEdit->text();
                if (m_regexButton->isChecked())
                {
                    const QRegularExpressionMatch matchValue = regexValue.match(matchedText);
                    if (matchValue.hasMatch())
                    {
                        replacementText = expandBackreferences(replacementText, matchValue);
                    }
                }

                if (matchedText.isEmpty())
                {
                    // 空匹配不消耗字符，直接插入会原地死循环，这里跳过一格。
                    if (scanCursor.atEnd())
                    {
                        break;
                    }
                    scanCursor.movePosition(QTextCursor::NextCharacter);
                    continue;
                }

                scanCursor.insertText(replacementText);
                ++replacedCount;
            }
            editCursor.endEditBlock();

            m_statusLabel->setText(QStringLiteral("已替换 %1 处").arg(replacedCount));
        }

        EditorAccess m_access{};              // 目标文本框适配器。
        QLineEdit* m_findEdit = nullptr;      // 查找输入框。
        QLineEdit* m_replaceEdit = nullptr;   // 替换输入框。
        QToolButton* m_prevButton = nullptr;  // 上一个匹配。
        QToolButton* m_nextButton = nullptr;  // 下一个匹配。
        QToolButton* m_regexButton = nullptr; // 正则开关。
        QToolButton* m_caseButton = nullptr;  // 大小写开关。
        QToolButton* m_replaceOneButton = nullptr; // 替换当前。
        QToolButton* m_replaceAllButton = nullptr; // 全部替换。
        QToolButton* m_closeButton = nullptr; // 关闭查找栏。
        QLabel* m_statusLabel = nullptr;      // 匹配数量/错误提示。
    };

    // ensureSearchBar 作用：取回文本框上已有的查找栏，没有则创建一个。
    TextSearchBar* ensureSearchBar(const EditorAccess& accessValue)
    {
        QWidget* hostWidget = accessValue.widget();
        if (hostWidget == nullptr)
        {
            return nullptr;
        }

        // TextSearchBar 刻意不带 Q_OBJECT（省掉 moc 参与构建），因此不能用 qobject_cast。
        // 该属性只由本文件写入，且面板是文本框的子控件、随其一同销毁，
        // 所以这里的向下转型是安全的。
        const QVariant storedBar = hostWidget->property(kSearchBarProperty);
        if (storedBar.isValid())
        {
            if (QObject* storedObject = storedBar.value<QObject*>();
                storedObject != nullptr)
            {
                return static_cast<TextSearchBar*>(storedObject);
            }
        }

        TextSearchBar* barWidget = new TextSearchBar(accessValue);
        hostWidget->setProperty(
            kSearchBarProperty,
            QVariant::fromValue(static_cast<QObject*>(barWidget)));
        return barWidget;
    }

    // GlobalTextSearchFilter 作用：
    // - 监听全应用按键，把 Ctrl+F / Ctrl+H 转成查找面板；
    // - 只在焦点确实落在多行文本框上时才拦截，其它场景一律放行。
    class GlobalTextSearchFilter final : public QObject
    {
    public:
        explicit GlobalTextSearchFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            const QEvent::Type eventType = eventValue->type();
            if (eventType != QEvent::KeyPress && eventType != QEvent::ShortcutOverride)
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }

            QKeyEvent* keyEvent = static_cast<QKeyEvent*>(eventValue);
            if (!keyEvent->modifiers().testFlag(Qt::ControlModifier))
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }
            const bool wantFind = keyEvent->key() == Qt::Key_F;
            const bool wantReplace = keyEvent->key() == Qt::Key_H;
            if (!wantFind && !wantReplace)
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }

            QWidget* focusWidget = QApplication::focusWidget();
            if (!ks::ui::OpenTextSearchPanelFor(focusWidget, wantReplace))
            {
                return QObject::eventFilter(watchedObject, eventValue);
            }
            eventValue->accept();
            return true;
        }
    };

    QPointer<GlobalTextSearchFilter> g_globalFilter; // 全局过滤器实例，仅安装一次。
}

bool ks::ui::OpenTextSearchPanelFor(QWidget* editorWidget, const bool focusReplaceField)
{
    const EditorAccess accessValue = resolveEditor(editorWidget);
    if (!accessValue.isValid())
    {
        return false;
    }
    if (hasOwnFindPanel(accessValue.widget()))
    {
        return false;
    }

    TextSearchBar* barWidget = ensureSearchBar(accessValue);
    if (barWidget == nullptr)
    {
        return false;
    }
    barWidget->activate(focusReplaceField);
    return true;
}

void ks::ui::InstallGlobalTextSearchReplaceSupport(QApplication* appInstance)
{
    if (appInstance == nullptr || !g_globalFilter.isNull())
    {
        return;
    }
    g_globalFilter = new GlobalTextSearchFilter(appInstance);
    appInstance->installEventFilter(g_globalFilter);
}
