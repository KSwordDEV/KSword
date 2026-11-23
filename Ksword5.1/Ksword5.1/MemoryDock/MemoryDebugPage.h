#pragma once

#include "MemoryDebugProcessCatalog.h"
#include "../UI/MemoryWorkbench/WorkbenchContinuation.h"
#include <QWidget>
#include <memory>

class QComboBox;
class QLabel;
class QShowEvent;
class QToolButton;
class QTimer;
class QVBoxLayout;

namespace ks::ui
{
    class AsyncUiDispatcher;
    class MemoryWorkbenchView;
    class MemoryDebugExecutionPanel;

    // MemoryDebugPage：独立内存与运行控制页面；完全不建立 Windows 调试附加。
    // 首次显示才创建工作台/枚举，构造不会访问目标；关闭只走内存改动离开守卫。
    class MemoryDebugPage final : public QWidget
    {
    public:
        explicit MemoryDebugPage(QWidget* parent = nullptr);
        ~MemoryDebugPage() override;

        // confirmQuit：只确认暂存许可，不提前归还运行控制；全部宿主同意后再统一释放。
        LeaveEntryStatus confirmQuit(LeaveCompletion completion = {});
        bool releaseExecutionForQuit(); // 退出第二阶段，不重复询问暂存许可。
        void cancelQuitPreparation();
        bool quitPreparationCurrent();

        // prepareForNavigation：搜索/目录建立前只创建工作台控件树，不刷新目标进程或改变会话。
        void prepareForNavigation();

    protected:
        // showEvent：惰性装配并刷新候选，不自动选择或改变任何目标。
        void showEvent(QShowEvent* event) override;

    private:
        // ensureView：幂等装配正式生产服务；refreshProcesses 异步获取轻量进程列表。
        void ensureView();
        void refreshProcesses();
        int candidateIndex(const QString& draft) const;
        // selectProcess：只接受列表中已核验的 PID+创建时间，选择前让目标层再次复核身份。
        void selectProcess();
        // closeSession：用户主动关闭会话；取消离开守卫时保持全部当前状态。
        void closeSession();
        void resumeSelectProcess(MemoryDebugProcessCandidate candidate, std::uint64_t source);
        void finishSelectProcess(const MemoryDebugProcessCandidate& candidate);
        void resumeCloseSession(std::uint64_t source);
        void finishClosedSession();
        bool finishQuitPreparation();
        bool transitionPending_ = false;
        bool releaseExecutionControl(); // 后台释放期间冻结工作台输入，防止新增未询问的暂存修改。
        // refreshModules/openModule：使用目标层已核对所有者的模块快照导航到基址。
        void refreshModules();
        void openModule();

        QVBoxLayout* layout_ = nullptr;            // 页面的根布局。
        QComboBox* processCombo_ = nullptr;        // 名称/PID 可筛选选择器，编辑文字不直接当身份。
        QComboBox* moduleCombo_ = nullptr;         // 当前会话的模块基址导航。
        QWidget* moduleField_ = nullptr;
        QToolButton* refreshButton_ = nullptr;     // 刷新候选列表。
        QToolButton* selectButton_ = nullptr;      // 建立内存会话。
        QToolButton* closeButton_ = nullptr;       // 关闭当前内存会话。
        QLabel* status_ = nullptr;                 // 候选/身份失败和退出反馈。
        MemoryWorkbenchView* view_ = nullptr;      // 只属于本页的工作台会话。
        MemoryDebugExecutionPanel* execution_ = nullptr; // 明确区分线程检查与真实协作单步。
        QTimer* livenessTimer_ = nullptr;          // 查询锚点存活，不暂停目标。
        std::shared_ptr<AsyncUiDispatcher> dispatcher_; // 页面销毁时关闭的回投门禁。
        MemoryDebugProcessCatalog catalog_;       // 当前选择器的不可变身份快照。
        QString processName_;                     // 成功选择的目标名称，不随列表刷新改变。
        MemoryDebugProcessCandidate selectedProcess_; // 名称缓存所属身份，不能套到另一个会话。
        bool refreshing_ = false;                 // 防止并发刷新造成选择器错配。
        bool initialCatalogRequested_ = false;    // 导航可先构造视图，第一次显示仍要载入候选。
        bool initialModulePending_ = false;       // 仅首次模块加载自动导航，刷新不抢用户地址。
        bool quitPrepared_ = false;              // 已批准退出，整页冻结到释放完成或全局取消。
        bool enabledBeforeQuit_ = true;          // 取消退出时恢复原启用状态，不停止后台租约查询。
    };
}
