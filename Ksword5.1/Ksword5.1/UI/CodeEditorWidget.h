#pragma once

// ============================================================
// CodeEditorWidget.h
// 作用：
// - 提供可复用的“即时窗口代码编辑器”组件；
// - 集成行号、查找替换、跳转行、文件读写、括号高亮与匹配；
// - 后续所有需要“类似记事本/代码编辑器输入框”的场景可直接复用。
// ============================================================

#include <QString>
#include <QStringConverter>
#include <QPointer>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QEvent;
class QToolButton;
class QVBoxLayout;
class QHBoxLayout;
class QWidget;

class CodeTextEdit;
class QMenu;
class QAction;

// CodeEditorWidget：
// - 统一的文本编辑器外壳；
// - 对外提供基础文本读写、当前文件路径与文件编码会话访问。
class CodeEditorWidget final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - parent：Qt 父控件，可为空。
    explicit CodeEditorWidget(QWidget* parent = nullptr);

    // 析构函数：
    // - 资源由 Qt 父子机制自动回收。
    ~CodeEditorWidget() override;

    // text：
    // - 未编辑的原文保留完整字符与 CRLF；编辑后返回当前文档。
    QString text() const;

    // setText：
    // - 覆盖设置编辑器文本内容；
    // - 与 setRawText 相同，始终保留原文，不根据只读状态猜测报告语义。
    // 入参 plainText：目标文本。
    void setText(const QString& plainText);

    // setRawText：
    // - 无条件按原文覆盖内容，不翻译，也不在 LanguageChange 时重绘；
    // - 用于用户文件、原始日志、API JSON 与字节 ASCII 视图。
    void setRawText(const QString& plainText);

    // 提示文字在外壳维护，报告页无需访问内部文本核心。
    void setPlaceholderText(const QString& placeholder);

    // 原文流式追加：语义与 appendPlainText 相同，不翻译且不进入结构模式。
    // autoScroll=true 仅在原来位于尾部时继续跟随；否则保留阅读位置。
    // false 始终保留当前滚动位置，容量裁剪时钳制到有效区间。
    // contentChanged 仍合并到下一轮事件循环；文档保留 Qt 本身的撤销策略。
    void appendRawText(const QString& rawText, bool autoScroll = true);
    // 完整原文日志重建：保持原有水平/垂直阅读位置及最大块数；原来位于尾部时可继续跟随。
    // followTailIfAtBottom=false 时始终恢复旧位置；追加循环应使用 appendRawText。
    void replaceRawText(const QString& rawText, bool followTailIfAtBottom = true);
    // 设置日志最多保留的文本块；0 为不限。正数按 Qt 文档规则禁用撤销。
    // 用于原文日志流；容量裁剪后复制仅包含实际保留的正文。
    void setMaximumBlockCount(int count);
    int maximumBlockCount() const;
    // 清空内容；保留容量限制和只读状态。
    void clear();

    // currentFilePath：
    // - 返回当前文件路径（未保存时为空）。
    QString currentFilePath() const;

    // setCurrentFilePath：
    // - 外部设置当前文件路径标签。
    // 入参 filePath：文件路径。
    void setCurrentFilePath(const QString& filePath);

    // setReadOnly：
    // - 设置编辑器是否只读；
    // - 只读模式下会禁用写入类按钮与替换功能。
    // 入参 readOnly：true=只读，false=可编辑。
    void setReadOnly(bool readOnly);

    // isReadOnly：
    // - 返回当前是否只读。
    bool isReadOnly() const;
    QString copyTextForCurrentView() const;
    void setWordWrapEnabled(bool enabled);
    bool wordWrapEnabled() const;

    // currentEncodingDisplayText：
    // - 返回当前文件编码展示文本（如 "UTF-8 BOM"）；
    // - 若当前内容不是来自文件加载，则返回 "未知"。
    QString currentEncodingDisplayText() const;

    // openLocalFile：
    // - 通过程序接口打开本地文本文件（自动识别编码）；
    // - 不依赖 UI 按钮，适合业务代码直接调用。
    // 返回：true=成功，false=失败。
    bool openLocalFile(const QString& filePath);

    // openLocalFileWithEncoding：
    // - 通过程序接口按指定编码打开本地文本文件；
    // - 用于“以其他编码重新打开”场景。
    // 返回：true=成功，false=失败。
    bool openLocalFileWithEncoding(const QString& filePath, QStringConverter::Encoding encoding);

    // reopenCurrentFileWithEncoding：
    // - 使用当前文件路径按指定编码重新加载；
    // - 当前文件路径为空时会直接失败。
    // 返回：true=成功，false=失败。
    bool reopenCurrentFileWithEncoding(QStringConverter::Encoding encoding);

signals:
    // contentChanged：统一通知外部详情布局当前可见文本已经变化。
    // 调用方式：程序写入、用户编辑或语言切换后在下一轮事件循环合并通知最新正文；
    // 避免观察者关闭窗口时，在 Qt 原生文档更新栈内销毁编辑器。
    // 入参 text：编辑器当前完整纯文本；返回：Qt 信号无返回值。
    void contentChanged(const QString& text);

protected:
    // changeEvent：更新界面主题与状态文字，正文始终保持原文。
    void changeEvent(QEvent* event) override;

    // eventFilter：同步工具图标状态及窄窗口工具栏布局。
    bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

private:
    // initializeUi：
    // - 创建工具栏、查找替换面板、跳转面板、编辑区与状态栏。
    void initializeUi();

    // initializeConnections：
    // - 连接按钮、快捷键与编辑器状态回调。
    void initializeConnections();

    // applyThemeStyle：
    // - 统一应用工具按钮/输入框样式。
    void applyThemeStyle();

    // openFindReplacePanel：
    // - 显示查找替换面板；
    // - replaceEnabled=true 时同时激活替换输入框。
    void openFindReplacePanel(bool replaceEnabled);

    // openGotoPanel：
    // - 显示跳转行面板并聚焦输入。
    void openGotoPanel();

    // closeInlinePanels：
    // - 隐藏查找替换与跳转行面板。
    void closeInlinePanels();

    // updateStatusText：
    // - 刷新底部状态栏文本（行号、列号、长度、路径）。
    void updateStatusText();

    // findByDirection：
    // - 执行向前/向后查找（非阻塞）。
    // 入参 forward：true=向后查找，false=向前查找。
    // 返回：true=命中，false=未命中。
    bool findByDirection(bool forward);

    // replaceCurrentSelection：
    // - 若当前命中查找文本，则替换为目标文本。
    void replaceCurrentSelection();

    // replaceAllMatches：
    // - 执行全文替换并返回替换次数。
    int replaceAllMatches();

    // jumpToInputLine：
    // - 按跳转面板输入定位到指定行。
    void jumpToInputLine();

    // openTextFile：
    // - 通过文件选择框打开文本文件到编辑器（自动识别编码）。
    void openTextFile();

    // loadLocalFile：
    // - 文件加载内部实现；
    // - 支持自动识别编码或按指定编码强制解码。
    bool loadLocalFile(const QString& filePath, bool forceEncoding, QStringConverter::Encoding forcedEncoding);

    // saveTextFile：
    // - 保存文本到文件。
    // 入参 forceSaveAs：true=强制另存为，false=优先覆盖当前路径。
    void saveTextFile(bool forceSaveAs);

    // refreshReadOnlyUiState：
    // - 根据只读状态更新按钮可用性和面板可见性。
    void refreshReadOnlyUiState();

    // 同步撤销/重做、选区、剪贴板与换行状态，避免图标可点但动作无效。
    void refreshActionButtonState();
    void updateToolbarLayout();
    void formatDocument();
    void updateFindHighlights();

    void copyCurrentView();

    // resetFileSessionMetadata：
    // - 重置当前文件会话元数据（编码/BOM/换行）。
    void resetFileSessionMetadata();

    // applyStructuredAutoFormatIfNeeded：
    // - 若文本识别为 JSON/XML，则自动格式化；
    // - 返回格式化后的文本，无法识别或解析失败时原样返回。
    QString applyStructuredAutoFormatIfNeeded(const QString& inputText, QString* detectedKindOut = nullptr) const;


private:
    // m_rootLayout：根布局。
    QVBoxLayout* m_rootLayout = nullptr;

    // m_toolbarLayout：顶部快捷操作按钮布局。
    QHBoxLayout* m_toolbarLayout = nullptr;

    // m_toolbarWidget：顶部工具栏容器。
    QWidget* m_toolbarWidget = nullptr;

    // m_newButton：新建文本按钮。
    QToolButton* m_newButton = nullptr;

    // m_openButton：打开文本按钮。
    QToolButton* m_openButton = nullptr;

    // m_saveButton：保存文本按钮。
    QToolButton* m_saveButton = nullptr;

    // m_saveAsButton：另存为按钮。
    QToolButton* m_saveAsButton = nullptr;

    // m_undoButton：撤销按钮。
    QToolButton* m_undoButton = nullptr;

    // m_redoButton：重做按钮。
    QToolButton* m_redoButton = nullptr;

    // m_cutButton：剪切按钮。
    QToolButton* m_cutButton = nullptr;

    // m_copyButton：复制按钮。
    QToolButton* m_copyButton = nullptr;

    // m_pasteButton：粘贴按钮。
    QToolButton* m_pasteButton = nullptr;

    // m_findButton：打开查找面板按钮。
    QToolButton* m_findButton = nullptr;

    // m_replaceButton：打开替换面板按钮。
    QToolButton* m_replaceButton = nullptr;

    // m_gotoButton：打开跳转面板按钮。
    QToolButton* m_gotoButton = nullptr;

    // m_wrapButton：切换自动换行按钮。
    QToolButton* m_wrapButton = nullptr;

    // m_findPanel：查找替换面板。
    QWidget* m_findPanel = nullptr;

    // m_findLayout：查找替换面板布局。
    QHBoxLayout* m_findLayout = nullptr;

    // m_findEdit：查找输入框。
    QLineEdit* m_findEdit = nullptr;

    // m_replaceEdit：替换输入框。
    QLineEdit* m_replaceEdit = nullptr;

    // m_findPrevButton：查找上一个按钮。
    QToolButton* m_findPrevButton = nullptr;

    // m_findNextButton：查找下一个按钮。
    QToolButton* m_findNextButton = nullptr;

    // m_replaceOneButton：替换当前命中按钮。
    QToolButton* m_replaceOneButton = nullptr;

    // m_replaceAllButton：全部替换按钮。
    QToolButton* m_replaceAllButton = nullptr;

    // m_findCloseButton：关闭查找面板按钮。
    QToolButton* m_findCloseButton = nullptr;

    // m_gotoPanel：跳转行面板。
    QWidget* m_gotoPanel = nullptr;

    // m_gotoLayout：跳转行面板布局。
    QHBoxLayout* m_gotoLayout = nullptr;

    // m_gotoLineEdit：跳转行输入框。
    QLineEdit* m_gotoLineEdit = nullptr;

    // m_gotoApplyButton：执行跳转按钮。
    QToolButton* m_gotoApplyButton = nullptr;

    // m_gotoCloseButton：关闭跳转面板按钮。
    QToolButton* m_gotoCloseButton = nullptr;

    // m_editor：核心代码编辑器（行号 + 括号高亮）。
    CodeTextEdit* m_editor = nullptr;
    QToolButton* m_moreButton = nullptr;
    QToolButton* m_matchCaseButton = nullptr;
    QToolButton* m_wholeWordButton = nullptr;
    QWidget* m_replaceRow = nullptr;
    QLabel* m_findResultLabel = nullptr;
    QComboBox* m_languageCombo = nullptr;
    QWidget* m_statusWidget = nullptr;
    QLabel* m_fileLabel = nullptr;
    QLabel* m_positionLabel = nullptr;
    QLabel* m_documentLabel = nullptr;
    QLabel* m_modeLabel = nullptr;
    QLabel* m_encodingLabel = nullptr;
    QAction* m_whitespaceAction = nullptr;
    QAction* m_formatAction = nullptr;

    // m_statusLabel：底部状态信息标签。
    QLabel* m_statusLabel = nullptr;

    // m_currentFilePath：当前文件路径（用于保存覆盖）。
    QString m_currentFilePath;

    // Cache only an untouched raw input to preserve CRLF when copied. Editing invalidates it.
    QString m_originalRawText;
    bool m_originalRawTextActive = false;
    bool m_settingRawText = false;

    // m_fileEncoding：当前文件编码（仅在文件加载后有效）。
    QStringConverter::Encoding m_fileEncoding = QStringConverter::Utf8;

    // m_fileHasBom：当前文件是否带 BOM。
    bool m_fileHasBom = false;

    // m_fileLineEnding：当前文件主导换行风格（"\r\n" / "\n" / "\r"）。
    QString m_fileLineEnding = QStringLiteral("\n");

    // m_fileSessionAvailable：当前编码元数据是否有效可展示。
    bool m_fileSessionAvailable = false;

    // m_replaceEnabled：标记查找面板当前是否显示替换控件。
    bool m_replaceEnabled = false;

    // m_readOnlyMode：标记当前是否只读模式。
    bool m_readOnlyMode = false;

    // m_destroying：标记组件正在析构。
    // - 输入/处理：析构函数置 true，所有延迟信号回调在刷新 UI 前检查；
    // - 返回行为：无返回值，用于避免 MainWindow 退出销毁链中访问已释放子控件。
    bool m_destroying = false;

    // m_themeRefreshPending：合并排队的样式更新，避免setStyleSheet引发palette事件递归。
    bool m_themeRefreshPending = false;
    bool m_contentNotificationPending = false;
};
