#pragma once

#include "MemoryDebugProcessCatalog.h"
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

    // MemoryDebugPage：独立进程内存会话页面；目标持续运行，完全不建立 Windows 调试附加。
    // 首次显示才创建工作台/枚举，构造不会访问目标；关闭只走内存改动离开守卫。
    class MemoryDebugPage final : public QWidget
    {
    public:
        explicit MemoryDebugPage(QWidget* parent = nullptr);
        ~MemoryDebugPage() override;

        // confirmQuit/cancelQuitPreparation：宿主窗口关闭前调用，与既有暂存离开守卫一致。
        bool confirmQuit();
        void cancelQuitPreparation();

    protected:
        // showEvent：惰性装配并刷新候选，不自动选择或改变任何目标。
        void showEvent(QShowEvent* event) override;

    private:
        // ensureView：幂等装配正式生产服务；refreshProcesses 异步获取轻量进程列表。
        void ensureView();
        void refreshProcesses();
        // selectProcess：只接受列表中已核验的 PID+创建时间，选择前让目标层再次复核身份。
        void selectProcess();
        // closeSession：用户主动关闭会话；取消离开守卫时保持全部当前状态。
        void closeSession();
        // refreshModules/openModule：使用目标层已核对所有者的模块快照导航到基址。
        void refreshModules();
        void openModule();

        QVBoxLayout* layout_ = nullptr;            // 页面的根布局。
        QComboBox* processCombo_ = nullptr;        // 名称/PID 可筛选选择器，编辑文字不直接当身份。
        QComboBox* moduleCombo_ = nullptr;         // 当前会话的模块基址导航。
        QToolButton* refreshButton_ = nullptr;     // 刷新候选列表。
        QToolButton* selectButton_ = nullptr;      // 建立内存会话。
        QToolButton* closeButton_ = nullptr;       // 关闭当前内存会话。
        QLabel* status_ = nullptr;                 // 候选/身份失败和退出反馈。
        MemoryWorkbenchView* view_ = nullptr;      // 只属于本页的工作台会话。
        QTimer* livenessTimer_ = nullptr;          // 查询锚点存活，不暂停目标。
        std::shared_ptr<AsyncUiDispatcher> dispatcher_; // 页面销毁时关闭的回投门禁。
        MemoryDebugProcessCatalog catalog_;       // 当前选择器的不可变身份快照。
        QString processName_;                     // 成功选择的目标名称，不随列表刷新改变。
        MemoryDebugProcessCandidate selectedProcess_; // 名称缓存所属身份，不能套到另一个会话。
        bool refreshing_ = false;                 // 防止并发刷新造成选择器错配。
        bool initialModulePending_ = false;       // 仅首次模块加载自动导航，刷新不抢用户地址。
    };
}
