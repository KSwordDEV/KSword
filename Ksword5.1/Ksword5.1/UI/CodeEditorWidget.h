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
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QEvent;
class QStackedWidget;
class QToolButton;
class QVBoxLayout;
class QHBoxLayout;
class QWidget;

class CodeTextEdit;

namespace ks::ui
{
    class ReportStructuredView;

    // LocalizeGeneratedReport 作用：
    // - 按行翻译“本程序自己生成的审计报告文本”，规则与 CodeEditorWidget 只读页完全一致：
    //   整行命中语言包时直接替换，未命中时再尝试翻译“标签: 值”里冒号后的状态值；
    // - 路径、哈希、地址等动态内容不会被改写。
    // 用途：报告除了塞进只读文本框，也可能被解析成属性树等结构化视图；
    //       两条路径必须共用同一套翻译逻辑，否则同一份数据换个视图就变回英文。
    // 入参 sourceText：未翻译的报告原文。
    // 返回：逐行翻译后的报告文本。
    QString LocalizeGeneratedReport(const QString& sourceText);
}

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
    // - 返回当前编辑器文本内容。
    QString text() const;

    // setText：
    // - 覆盖设置编辑器文本内容；
    // - 只读模式默认视为应用生成报告并支持即时语言切换；
    // - 原始日志、JSON、文件/字节内容必须显式调用 setRawText。
    // 入参 plainText：目标文本。
    void setText(const QString& plainText);

    // setRawText：
    // - 无条件按原文覆盖内容，不翻译，也不在 LanguageChange 时重绘；
    // - 用于用户文件、原始日志、API JSON 与字节 ASCII 视图。
    void setRawText(const QString& plainText);

    // setLocalizedText：
    // - 用于应用生成的只读报告，而不是用户文件原文；
    // - 保存中文规范源文本，并在 LanguageChange 时按当前语言重新渲染；
    // - 普通 setText 会退出该模式，避免误翻译用户打开的源码或日志原文。
    void setLocalizedText(const QString& sourceText);

    // setLocalizedTextWithRawSuffix：
    // - sourceText 为应用生成、需要随语言切换重绘的报告前缀；
    // - rawSuffix 为文件或系统返回的原始内容，始终逐字保留，不参与翻译；
    // - 适用于“程序提示 + 原始字符串/日志”混合展示。
    void setLocalizedTextWithRawSuffix(const QString& sourceText, const QString& rawSuffix);

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

    // setStructuredReportViewEnabled：
    // - 关闭内置的“结构视图 / 原始文本”切换入口；
    // - 只用于页面已经自备结构化视图的场合（例如从 R0 结构体逐字段搭出来的属性树），
    //   否则同一页会出现两套结构视图，用户还得分辨哪套更准；
    // - 默认开启，普通只读报告框不需要调用。
    void setStructuredReportViewEnabled(bool enabled);

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
    // 调用方式：程序写入、用户编辑或语言切换重绘后自动发出。
    // 入参 text：编辑器当前完整纯文本；返回：Qt 信号无返回值。
    void contentChanged(const QString& text);

protected:
    // changeEvent：语言切换时重新渲染 setLocalizedText 保存的生成报告。
    void changeEvent(QEvent* event) override;

    // eventFilter：内容区换页或改尺寸时，把右上角悬浮切换按钮重新贴到角上。
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

    // resetFileSessionMetadata：
    // - 重置当前文件会话元数据（编码/BOM/换行）。
    void resetFileSessionMetadata();

    // applyStructuredAutoFormatIfNeeded：
    // - 若文本识别为 JSON/XML，则自动格式化；
    // - 返回格式化后的文本，无法识别或解析失败时原样返回。
    QString applyStructuredAutoFormatIfNeeded(const QString& inputText, QString* detectedKindOut = nullptr) const;

    // positionStructuredSwitch：
    // - 把悬浮切换下拉框贴到内容区右上角；
    // - 控件不进任何布局，尺寸取自身 sizeHint，右边距额外避开当前页可见的垂直滚动条。
    void positionStructuredSwitch();

    // updateStructuredReportView：
    // - 当前内容为只读报告且能解析出结构时，显示结构视图切换按钮并按用户上次选择切页；
    // - 内容没有结构（日志、原始数据、用户文件）时隐藏入口并强制回到纯文本；
    // - 由文本变化统一驱动，覆盖 setText / setRawText / setLocalizedText 与语言切换重绘。
    void updateStructuredReportView();

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

    // m_structuredCombo：结构视图 / 原始文本切换下拉框（仅只读报告可解析时可见）。
    QComboBox* m_structuredCombo = nullptr;

    // m_viewStack：纯文本编辑器与结构视图的切换容器。
    QStackedWidget* m_viewStack = nullptr;

    // m_structuredView：当前内容的结构化呈现。
    ks::ui::ReportStructuredView* m_structuredView = nullptr;

    // m_editor：核心代码编辑器（行号 + 括号高亮）。
    CodeTextEdit* m_editor = nullptr;

    // m_statusLabel：底部状态信息标签。
    QLabel* m_statusLabel = nullptr;

    // m_currentFilePath：当前文件路径（用于保存覆盖）。
    QString m_currentFilePath;

    // m_localizedSourceText：setLocalizedText 保存的中文规范源报告。
    QString m_localizedSourceText;

    // m_localizedRawSuffix：混合报告中必须逐字保留、不得翻译的原始后缀。
    QString m_localizedRawSuffix;

    // m_localizedTextActive：true 时 LanguageChange 会重新渲染生成报告正文。
    bool m_localizedTextActive = false;

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

    // m_structuredViewEnabled：是否允许出现内置结构视图切换入口。
    bool m_structuredViewEnabled = true;

    // m_destroying：标记组件正在析构。
    // - 输入/处理：析构函数置 true，所有延迟信号回调在刷新 UI 前检查；
    // - 返回行为：无返回值，用于避免 MainWindow 退出销毁链中访问已释放子控件。
    bool m_destroying = false;
};
