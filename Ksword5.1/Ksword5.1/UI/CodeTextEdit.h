#pragma once

// ============================================================
// CodeTextEdit.h
// 作用：
// - 提供 CodeEditorWidget 的核心文本控件；
// - 集成行号、词法语法色、当前行与括号匹配，并合并宿主查找高亮；
// - 所有格式更新都保留原文；文件编码与保存事务由宿主负责；
// - 对外暴露行跳转与外部高亮注入接口。
// ============================================================

#include <QList>
#include <QFont>
#include <QPlainTextEdit>
#include <QTextEdit>

class QPaintEvent;
class QKeyEvent;
class QResizeEvent;
class QSyntaxHighlighter;
class QTimer;
class QWidget;

// CodeTextEdit：
// - 统一代码文本编辑器实现；
// - 供 CodeEditorWidget 组合复用。
class CodeTextEdit final : public QPlainTextEdit
{
public:
    enum class SyntaxLanguage { Auto, PlainText, Json, Xml, Cpp, Ini, Shell };

    // Auto only inspects a bounded prefix. Logs can explicitly choose PlainText
    // so appending a line never scans the beginning of their retained document.
    void setSyntaxLanguage(SyntaxLanguage language);
    SyntaxLanguage syntaxLanguage() const { return m_syntaxLanguage; }
    SyntaxLanguage effectiveSyntaxLanguage() const;
    // Repaints formats without semantic text/modified notifications or undo edits.
    void refreshThemeColors();
    void setWhitespaceVisible(bool visible);
    bool whitespaceVisible() const { return m_whitespaceVisible; }
    void setLineNumbersVisible(bool visible);
    bool lineNumbersVisible() const { return m_lineNumbersVisible; }
    void setCompactMode(bool compact);
    bool compactMode() const { return m_compactMode; }
    static QFont editorFont();

    // 构造函数：
    // - parent：父控件，可为空。
    explicit CodeTextEdit(QWidget* parent = nullptr);

    // 析构函数：
    // - 释放内部括号着色器对象。
    ~CodeTextEdit() override;

    // lineNumberAreaWidth：
    // - 按当前行数动态计算行号区域宽度。
    int lineNumberAreaWidth() const;

    // paintLineNumberArea：
    // - 绘制行号区域内容。
    // 入参 event：行号区绘制事件。
    void paintLineNumberArea(QPaintEvent* event);

    // gotoLine：
    // - 跳转到指定 1 基行号并居中显示。
    // 入参 oneBasedLine：目标行号（从 1 开始）。
    // 返回：true=跳转成功；false=越界或无效。
    bool gotoLine(int oneBasedLine);

    // setExternalExtraSelections：
    // - 注入外层命中高亮（例如查找全部命中）；
    // - 会与当前行/括号高亮合并显示。
    // 入参 selections：额外高亮集合。
    void setExternalExtraSelections(const QList<QTextEdit::ExtraSelection>& selections);

protected:
    // changeEvent：排队重算语法色和选择区，不修改正文与编辑会话。
    void changeEvent(QEvent* event) override;

    // resizeEvent：
    // - 编辑区尺寸变化时同步行号区几何。
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private:
    // scheduleRefreshExtraSelections：
    // - 节流触发高亮刷新。
    void scheduleRefreshExtraSelections();

    void updateGutterGeometry();
    void scheduleSyntaxRefresh();
    void refreshSyntaxLanguage();
    void indentSelection(bool backwards);
    int findBracketPair(int bracketPos, QChar bracketCh) const;
    bool isCodeBracket(int position) const;

    // refreshExtraSelections：
    // - 刷新当前行高亮、括号高亮与外部命中高亮。
    void refreshExtraSelections();

private:
    // m_lineNumberArea：行号区域控件。
    QWidget* m_lineNumberArea = nullptr;

    // m_syntaxHighlighter：词法着色与有界括号 token 元数据。
    QSyntaxHighlighter* m_syntaxHighlighter = nullptr;

    bool m_themeRefreshPending = false; // 合并多个palette通知，避免重复重高亮。
    bool m_syntaxRefreshPending = false;
    SyntaxLanguage m_syntaxLanguage = SyntaxLanguage::Auto;
    SyntaxLanguage m_effectiveSyntaxLanguage = SyntaxLanguage::PlainText;
    bool m_whitespaceVisible = false;
    bool m_lineNumbersVisible = true;
    bool m_compactMode = false;

    // m_extraSelectionTimer：高亮刷新节流计时器。
    QTimer* m_extraSelectionTimer = nullptr;

    // m_externalExtraSelections：外层注入的额外高亮集合。
    QList<QTextEdit::ExtraSelection> m_externalExtraSelections;

};

