#pragma once

#include "OfflineProjectReader.h"
#include <QWidget>

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
        // 打开用户所选清单，或使用相同入口重试最近一次读取。
        void chooseProject();
        void openProject(const QString& path);
        void applyProject(const ProjectSnapshot& snapshot);
        // 根据当前目录行发起单个后台读；没有目录行时清空详情。
        void readSelectedSample();
        // 向同一结构化字段文档发布已验证的选中采样内容。
        void updateSampleDocument();
        // 根据当前加载阶段、已发布项目和采样刷新工具与状态文字。
        void updateStatus();

        QTabWidget* m_tabs = nullptr; // 概览和项目采样目录的子导航。
        QPushButton* m_open = nullptr; // 显式选择项目清单。
        QPushButton* m_retry = nullptr; // 重读最近一次所选的项目清单。
        QPushButton* m_cancel = nullptr; // 取消当前项目读取并保留原目录。
        QPushButton* m_sampleRetry = nullptr; // 重读当前目录行，不依赖项目打开历史。
        QLabel* m_status = nullptr; // 当前读取进度、空结果或失败。
        QLabel* m_source = nullptr; // 已发布目录实际对应的项目与代次。
        QLabel* m_manifestPath = nullptr; // 只显示已发布清单路径。
        OfflineSegmentOverview* m_overview = nullptr; // 独立归档投影与当前项目身份对照。
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
        ReadProblem m_sampleProblem; // 当前采样最近一次读取的独立回执。
        bool m_hasVerifiedSample = false; // 目前保留的配置是否已通过读取验证。
        bool m_readingProject = false; // 项目请求尚未结束。
        bool m_projectCanceled = false; // 用户取消了最近一次项目读取。
        bool m_readingSample = false; // 详情请求尚未结束。
    };
}
