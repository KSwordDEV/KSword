#pragma once

#include "PassiveApiCaptureOwner.h"

#include <QWidget>
#include <functional>

class QLabel;
class QGroupBox;
class QLineEdit;
class QPushButton;
class QTabBar;
class QTimer;
class QSpinBox;
class QCheckBox;
class QComboBox;
class QTabWidget;

namespace ks::ui
{
    class AsyncOperation;
    class StructuredFieldView;
}

namespace ks::action_analyze
{
    // 嵌在总览的现有采集区域，只协调用户草稿和本端后台所有者。
    class PassiveApiCapturePane final : public QWidget
    {
    public:
        // 不读取文件；在共享参数工作区中建立表单、回执及固定动作。
        explicit PassiveApiCapturePane(QWidget* parent);
        // 提前阻断跨线程回投并请求读端完成收尾。
        ~PassiveApiCapturePane() override;
        // 切换待提交项目或更新相邻动作门禁，不改变正在采样的已冻结归属。
        void setContext(const QString& manifest, const QString& projectId, const QString& revisionId,
            bool etwBusy, bool readingArchive);
        // 禁止在本端创建两个并行采集所有者（包括打开和收尾阶段）。
        bool busy() const noexcept { return m_busy; }
        // 借用已发布的档案水位，实际读包仍由总览后台读侧核验。
        const PassiveApiCaptureReceipt& archiveReceipt() const noexcept { return m_receipt; }
        // 提供给工作台底栏的可读摘要；详细字段仅在本区域投影。
        QString summary() const;

        std::function<void()> statusChanged; // 让总览同步工具提示和底栏。
        std::function<void(const SampleRequest&)> registered; // 刷新现有项目目录，不切换用户当前页。
        std::function<void(const SampleRequest&)> openArchive; // 调用现有归档入口，不另建结果页。

    protected:
        // 语言改变后重译控件与值回执，不改输入草稿。
        void changeEvent(QEvent* event) override;

    private:
        // 从单文件选择器挑选授权范围；取消保持旧草稿。
        void chooseFile();
        // 点击时校验并冻结请求；发现非法身份或未开项目不提交任务。
        void start();
        // 向当前所有者发出一次停止请求，等待同一所有者真实收尾。
        void stop();
        // 从共享值读取后台进度；只在有变化时重绘文档。
        void readProgress();
        // 接收工作线程终态或异常回执，释放下一次显式启动资格。
        void finish(const PassiveApiCaptureReceipt& receipt, bool abnormal = false);
        // 固定文案、字段标签和悬停释义由当前语言决定。
        void retranslate();
        // 本次按钮资格及禁用原因与点击守卫共用。
        void updateControls();
        QString startDisabledReason() const;
        bool canOpenArchive() const;
        // 发布结果的单一结构化文档，独立于仍可编辑的草稿。
        void renderReceipt();

        ks::ui::AsyncOperation* m_operation = nullptr; // 单次启动对应单个后台任务。
        QTimer* m_preview = nullptr; // 只刷新值回执，不执行 I/O。
        QGroupBox* m_sourceGroup = nullptr; // 来源参数标题。
        QLabel* m_projectLabel = nullptr; // 下次采样归属，精确清单路径放在释义。
        QTabBar* m_sourceMode = nullptr; // 共享分段控件，区分文件、合作已装载与显式附加。
        QLabel* m_sourceHint = nullptr; // 按草稿来源解释文件/session 与活管道的互斥关系。
        QLabel* m_durationLabel = nullptr; // 两种活采时限的可见标签。
        QSpinBox* m_duration = nullptr; // 秒数草稿，零表示持续，有限区间从 Ready 起算。
        QCheckBox* m_autoTransfer = nullptr; // 启动冻结，文件回放模式不提交。
        QLabel* m_networkTrafficLabel = nullptr; // 同采样网络来源的可见标签。
        QComboBox* m_networkTraffic = nullptr; // 网络草稿，JSONL禁用但保留选择，默认不采集。
        QCheckBox* m_captureAgentEtw = nullptr; // 原参数正文的配套ETW草稿，运行冻结，JSONL禁用但不清除。
        QLabel* m_pathLabel = nullptr; // 已授权文件的可见标签。
        QLabel* m_sessionLabel = nullptr; // 来源会话的可见标签。
        QLabel* m_pidLabel = nullptr; // 来源 PID 的可见标签。
        QLabel* m_creationLabel = nullptr; // 来源创建时间的可见标签。
        QLineEdit* m_path = nullptr; // 仅显示用户选中的本地来源。
        QLabel* m_executableLabel = nullptr; // 第四来源独立EXE标签。
        QLineEdit* m_executable = nullptr; // 只读EXE路径，切换来源保留草稿。
        QPushButton* m_executableBrowse = nullptr; // 普通EXE原生选择器，图标及tooltip沿原动作带。
        QLineEdit* m_session = nullptr; // 来源会话 ID 草稿。
        QLineEdit* m_pid = nullptr; // 来源 PID 草稿。
        QLineEdit* m_creation = nullptr; // 来源实例的 FILETIME 草稿。
        QPushButton* m_browse = nullptr; // 原生 JSONL 文件选择入口。
        QPushButton* m_start = nullptr; // 显式开始跟随。
        QPushButton* m_stop = nullptr; // 停止读端并收尾。
        QPushButton* m_archive = nullptr; // 查看已提交且读回的独立采样。
        QLabel* m_status = nullptr; // 生命周期摘要，独立于存量字段。
        ks::ui::StructuredFieldView* m_fields = nullptr; // 正规回执的唯一可复制字段源。
        QTabWidget* m_resultTabs = nullptr; // 采集回执和接管树分工明确，切换不改变当前采样或草稿。
        ks::ui::StructuredFieldView* m_handoffFields = nullptr; // 同一冻结接管JSON的可搜索、可复制树状投影。
        PassiveApiCaptureRequest m_context; // 下一次开始时冻结的项目身份。
        std::shared_ptr<PassiveApiCaptureOwner> m_owner; // 当前或最近一次本端请求。
        std::shared_ptr<PassiveApiCaptureOwner> m_resultOwner; // 已提交回执实际所属的请求。
        PassiveApiCaptureReceipt m_receipt; // 上次发布到 UI 的值。
        PassiveApiCaptureReceipt m_currentReceipt; // 当前请求的启动与失败回执，不冒用旧归档身份。
        quint64 m_liveCoverageRevision = 0; // 当前请求的启动回执，不替换上次已归档结果。
        QString m_announced; // 已通知现有目录的本次采样 ID。
        QString m_startError; // 未登记采样时的独立失败详情。
        bool m_registered = false; // 两个真实后台登记都已取得。
        bool m_busy = false; // 有已受理的开始或收尾。
        bool m_stopping = false; // 本端已经请求收尾。
        bool m_failed = false; // 后台异常或启动失败；不覆盖已提交证据。
        bool m_invalid = false; // 参数未通过校验；保留上次回执。
        bool m_etwBusy = false; // ETW 的真实占用及待恢复责任。
        bool m_readingArchive = false; // 档案查看入口正处理另一请求。
        bool m_confirming = false; // 确认框打开期间阻断重入启动，确认不跨请求复用。
    };
}
