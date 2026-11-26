#pragma once

#include "ArchivedSampleAnalysis.h"
#include "BehaviorRulesPage.h"
#include "OfflineProjectReader.h"
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QTabWidget;
class QTableView;
namespace ks::ui
{
    class AsyncOperation;
    class ResultTableHost;
    class StructuredFieldView;
}

namespace ks::action_analyze
{
    class SampleCatalogModel;
    class OfflineSegmentOverview;
    class ActionAnalyzeBreakpointPage;
    struct ToolbarActionEligibility;

    // Qt 行为追踪页。页面持有只读项目投影，不持有任何活动采样会话。
    class ActionAnalyzeWorkspace final : public QWidget
    {
    public:
        // 使用监控 Tab 的宿主作为 parent，创建页面但不开始文件读取。
        explicit ActionAnalyzeWorkspace(QWidget* parent);
        // 关闭异步回投门禁后由 Qt 释放子控件。
        ~ActionAnalyzeWorkspace() override;
        // 返回供监控目录导航使用的真实子页签，所有权仍属于工作台。
        QTabWidget* navigationTabs() const
        {
            return m_tabs;
        }

    protected:
        // 语言改变时重新呈现固定标签和状态，保留目录与当前采样身份。
        void changeEvent(QEvent* event) override;

    private:
        // 构造项目目录页，返回页签直接持有的页面。
        QWidget* createProjectBrowser();
        // 选择新项目目录，或选择现有清单。写入与目录回读共用项目任务。
        void chooseNewProject();
        void chooseProject();
        void openProject(const QString& path, bool create = false);
        void applyProject(const ProjectSnapshot& snapshot);
        // 根据当前目录行发起单个后台读；没有目录行时清空详情。
        void readSelectedSample();
        // 向同一结构化字段文档发布已验证的选中采样内容。
        void updateSampleDocument();
        // 用当前采样线索更新选择菜单，保留同一条已选原始记录。
        void updateSampleClues();
        // 根据当前加载阶段、已发布项目和采样刷新工具与状态文字。
        void updateStatus();
        // 重算规则入口启用状态；由目录选择和规则页在途状态共同驱动。
        void updateSampleReplayAction();
        // 返回目录当前选中归档的资格，点击和界面刷新使用同一判断。
        ToolbarActionEligibility sampleArchiveEligibility() const;

        QTabWidget* m_tabs = nullptr; // 概览和项目采样目录的子导航。
        QPushButton* m_create = nullptr; // 新建独立项目目录并打开。
        QPushButton* m_open = nullptr; // 显式选择项目清单。
        QPushButton* m_newScan = nullptr; // 跳到当前项目的新一轮扫描参数。
        QPushButton* m_retry = nullptr; // 重读最近一次所选的项目清单。
        QPushButton* m_cancel = nullptr; // 取消当前项目读取并保留原目录。
        QPushButton* m_sampleRetry = nullptr; // 重读当前目录行，不依赖项目打开历史。
        QPushButton* m_sampleArchive = nullptr; // 打开所选采样的原始归档。
        QPushButton* m_sampleReplay = nullptr; // 对选中采样显式运行五类规则预置。
        QComboBox* m_sampleClue = nullptr; // 此采样内明确选定的原始记录锚点。
        QList<SampleSensitiveClue> m_displayedClues; // 当前选项与归档坐标的对应关系。
        QLabel* m_status = nullptr; // 当前读取进度、空结果或失败。
        QLabel* m_source = nullptr; // 已发布目录实际对应的项目与代次。
        QLabel* m_manifestPath = nullptr; // 只显示已发布清单路径。
        OfflineSegmentOverview* m_overview = nullptr; // 独立归档投影与当前项目身份对照。
        QWidget* m_rulesPage = nullptr; // 已挂在同一子导航中的规则页。
        ReplaySamplePresets m_replaySamplePresets; // 将冻结请求交给规则页的唯一控制器。
        ActionAnalyzeBreakpointPage* m_breakpoints = nullptr; // 同一工作台内保存项目定义的页面。
        QLabel* m_sessionStatus = nullptr; // 当前页面的真实会话状态。
        QTableView* m_samples = nullptr; // 项目已提交采样目录。
        SampleCatalogModel* m_catalog = nullptr; // 稳定样本身份的按需表模型。
        ks::ui::ResultTableHost* m_catalogHost = nullptr; // 共享操作条和模型提交屏障。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 唯一的所选样本详情文档。
        ks::ui::AsyncOperation* m_projectRead = nullptr; // 单个在途项目读取。
        ks::ui::AsyncOperation* m_sampleRead = nullptr; // 单个在途采样读取。
        QString m_requestedPath; // 最后一次读取的路径，失败也可重试。
        ProjectSnapshot m_project; // 当前有效目录，失败不会覆盖。
        ReadProblem m_projectProblem; // 最近一次项目读取的独立回执。
        SampleSummary m_selected; // 详情请求冻结的采样目录行。
        SampleDetails m_sampleDetails; // 同一目录行最后一次验证成功的配置。
        std::optional<ArchivedSampleAnalysis> m_sampleAnalysis; // 当前样本最后一次发布的只读分类。
        std::optional<ArchivedSampleAnalysis> m_sampleAnalysisIssue; // 保留原分类时用于显示新读回的异常。
        std::optional<SampleRequest> m_verifiedSample; // 最后一次成功读取使用的冻结目录身份。
        ReadProblem m_sampleProblem; // 当前采样最近一次读取的独立回执。
        bool m_hasVerifiedSample = false; // 目前保留的配置是否已通过读取验证。
        bool m_readingProject = false; // 项目请求尚未结束。
        bool m_creatingProject = false; // 后台可能正在提交清单，此阶段不可取消写入。
        bool m_projectCanceled = false; // 用户取消了最近一次项目读取。
        bool m_readingSample = false; // 详情请求尚未结束。
        bool m_rulesBusy = false; // 规则页有已受理的请求时，目录入口暂停提交。
    };
}
