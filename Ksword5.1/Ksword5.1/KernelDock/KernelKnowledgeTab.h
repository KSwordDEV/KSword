#pragma once

#include <QString>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <vector>

class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class QTextBrowser;
class QToolButton;
class QTreeWidget;

// KernelKnowledgeTab 作用：
// - 把《第二规划》的 71 个专题组织成可检索、可筛选的只读知识中心；
// - 每篇正文都由语言包提供关系图与八项完成字段；
// - 可选地把用户送到当前 KernelDock 内已经存在的只读观察页。
class KernelKnowledgeTab final : public QWidget
{
public:
    // RouteHandler 输入稳定 routeId；由 KernelDock 决定如何切换实际页签。
    using RouteHandler = std::function<void(const QString& routeId)>;

    explicit KernelKnowledgeTab(QWidget* parent = nullptr);
    ~KernelKnowledgeTab() override = default;

    // setRouteHandler：设置站内观察入口回调。
    // 输入 handler；无返回。空回调会自动禁用“打开相关功能”按钮。
    void setRouteHandler(RouteHandler handler);

protected:
    // changeEvent：响应语言包与应用调色板变化。
    // 输入 Qt change event；无返回，始终继续交给 QWidget 基类处理。
    void changeEvent(QEvent* event) override;

private:
    // initializeUi：构建目录、工具栏、文章阅读器和所有连接。
    // 无输入无返回，仅在构造函数调用一次。
    void initializeUi();

    // retranslateUi：重载全部控件文本并保持当前专题和覆盖筛选。
    // 无输入无返回；语言切换时调用。
    void retranslateUi();

    // applyTheme：应用不含布局几何的主题颜色，并刷新富文本 CSS。
    // 无输入无返回；构造和调色板变化时调用。
    void applyTheme();

    // rebuildTree：按当前关键词与覆盖度重建左侧目录。
    // preferredTopicId 是重建后希望保留的专题；无返回。
    void rebuildTree(const QString& preferredTopicId = QString());

    // showTopic：把目录索引对应的专题渲染到右侧。
    // 输入全目录索引；无返回，非法索引时显示空状态。
    void showTopic(int topicIndex);

    // selectTopic：在树中选择指定目录索引并滚动到可见区域。
    // 输入全目录索引；命中返回 true，否则返回 false。
    bool selectTopic(int topicIndex);

    // findTopicIndex：按稳定 topic id 查找全目录索引。
    // 输入 id；命中返回非负索引，否则返回 -1。
    int findTopicIndex(const QString& topicId) const;

    // navigateRelative：在当前筛选后的专题列表中前后移动。
    // delta 为 -1 或 +1；无返回，到达边界时保持当前项。
    void navigateRelative(int delta);

    // copyCurrentTopic：复制当前标题、摘要、正文和官方参考链接。
    // 无输入无返回；没有当前项时静默跳过。
    void copyCurrentTopic() const;

    // openCurrentRoute：调用 KernelDock 提供的只读站内导航回调。
    // 无输入无返回；当前专题没有 routeId 时静默跳过。
    void openCurrentRoute() const;

    // openCurrentReference：用系统浏览器打开当前分类的微软官方参考。
    // 无输入无返回；没有有效 URL 时静默跳过。
    void openCurrentReference() const;

    // collectCurrentEvidence：异步调用版本化 R0 专题协议并展示原始证据行。
    // 无输入无返回；对话框只读，不会自动触发各业务扫描。
    void collectCurrentEvidence();

    QLineEdit* m_searchEdit = nullptr;             // m_searchEdit：跨标题、摘要和正文检索。
    QComboBox* m_coverageCombo = nullptr;          // m_coverageCombo：按底层能力覆盖度筛选。
    QLabel* m_resultCountLabel = nullptr;          // m_resultCountLabel：当前筛选命中数量。
    QTreeWidget* m_topicTree = nullptr;            // m_topicTree：分类与专题两级目录。
    QLabel* m_titleLabel = nullptr;                // m_titleLabel：当前专题标题。
    QLabel* m_summaryLabel = nullptr;              // m_summaryLabel：当前专题一句话摘要。
    QLabel* m_coverageBadge = nullptr;             // m_coverageBadge：底层能力覆盖标签。
    QLabel* m_knowledgeBadge = nullptr;            // m_knowledgeBadge：知识文章完整性标签。
    QToolButton* m_previousButton = nullptr;        // m_previousButton：上一篇图标按钮。
    QToolButton* m_nextButton = nullptr;            // m_nextButton：下一篇图标按钮。
    QToolButton* m_copyButton = nullptr;            // m_copyButton：复制完整文章图标按钮。
    QToolButton* m_evidenceButton = nullptr;        // m_evidenceButton：采集当前专题 R0 现场证据。
    QToolButton* m_routeButton = nullptr;           // m_routeButton：打开 Ksword 相关观察页。
    QToolButton* m_referenceButton = nullptr;       // m_referenceButton：打开微软官方参考。
    QTextBrowser* m_articleView = nullptr;          // m_articleView：适合 Markdown 标题/关系图/链接的只读富文本视图。

    std::vector<int> m_visibleTopicIndexes;         // m_visibleTopicIndexes：当前筛选后仍可导航的全目录索引。
    int m_currentTopicIndex = -1;                   // m_currentTopicIndex：当前文章在完整目录中的索引。
    QString m_currentRouteId;                       // m_currentRouteId：当前文章可选站内观察路由。
    QString m_currentReferenceUrl;                  // m_currentReferenceUrl：当前分类的官方文档 URL。
    RouteHandler m_routeHandler;                    // m_routeHandler：由父 KernelDock 注入的安全导航函数。
    std::uint64_t m_evidenceGeneration = 0;         // m_evidenceGeneration：屏蔽切换专题后返回的过期异步结果。
};
