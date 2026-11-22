#pragma once

#include "MemoryDebugThreadSession.h"
#include "../UI/StructuredFieldView.h"
#include "../ArkDriverClient/ArkHvmNoAttachClient.h"
#include <QWidget>
#include <QPointer>
#include <array>
#include <functional>
#include <memory>

class QComboBox;
class QLabel;
class QToolButton;
class QTimer;
class QDialog;
class QLineEdit;
class QTableWidget;
class QPushButton;
namespace ksword::cooperative { class Session; struct Result; }

namespace ks::ui
{
    class AsyncUiDispatcher;

    // 专业内存页的运行控制工具带；不接管工作台布局，不调用 Windows 调试附加。
    class MemoryDebugExecutionPanel final : public QWidget
    {
    public:
        explicit MemoryDebugExecutionPanel(QWidget* parent);
        ~MemoryDebugExecutionPanel() override;
        // setTarget 只登记强身份；用户操作前不暂停、连接或修改目标。
        void setTarget(std::uint32_t pid, std::uint64_t creation);
        // 离开前配平自有暂停；忙碌或恢复失败时拒绝关闭，以保留重试入口。
        bool prepareClose();
        // 仅真实暂停的当前现场可请求反汇编定位；快照检查不会抢占工作台地址。
        std::function<void(std::uint64_t)> onStoppedAddress;

    private:
        void execute(int operation); // 在工作线程串行执行一次明确操作。
        void applyNative(const MemoryDebugThreadResult& result, int operation);
        void applyCooperative(const ksword::cooperative::Result& result);
        void applyHvm(const ksword::ark::HvmNoAttachResult& result);
        bool closeHvm(); // 后台释放全核资源；嵌套事件循环只保持 UI 响应，不在 UI 运行 IOCTL。
        void updateActions(); // 以实际状态更新控件，不从历史寄存器推断暂停。
        void showRegisters(); // 用同一规范文档打开共享字段详情。
        void showHvmControls(); // 参数工作区承载断点草稿，当前配置使用独立结果表。
        void updateHvmControls(); // 根据实际停点更新编辑资格，保留未提交草稿。
        void submitHvm(KSWORD_ARK_HVM_NOATTACH_REQUEST request); // 冻结身份后后台执行扩展操作。

        QComboBox* backend_ = nullptr; // 原生检查、协作 VEH 与虚拟化能力边界。
        QComboBox* thread_ = nullptr; // 原生检查绑定创建时间的线程选择。
        QWidget* threadField_ = nullptr;
        QWidget* actions_ = nullptr;
        QToolButton* refresh_ = nullptr; // 原生刷新线程或主动连接协作组件。
        QToolButton* capture_ = nullptr; // 原生临时暂停读取现场。
        QToolButton* pause_ = nullptr; // 原生单线程暂停或请求协作检查点暂停。
        QToolButton* resume_ = nullptr; // 归还本会话暂停或继续当前协作停点。
        QToolButton* step_ = nullptr; // 仅支持真实单步后端的当前停点可用。
        QToolButton* registers_ = nullptr; // 显示不可变现场及其来源。
        QToolButton* openHvm_ = nullptr; // 仅显式确认后开启独占的实验 HVM 后端。
        QToolButton* configureHvm_ = nullptr; // 打开独立的断点/整数寄存器工具页。
        QToolButton* closeHvm_ = nullptr; // 显式关闭虚拟化，保留当前内存会话。
        QLabel* status_ = nullptr; // 操作、权限、恢复及能力限制的可换行说明。
        QTimer* poll_ = nullptr; // 协作停点/租约查询；隐藏页面仍保持生命周期。
        std::shared_ptr<AsyncUiDispatcher> dispatcher_; // 控件销毁后的回投门禁。
        std::shared_ptr<MemoryDebugThreadSession> native_; // 唯一自有暂停的持有者。
        std::shared_ptr<ksword::cooperative::Session> cooperative_; // 目标主动开启的控制连接。
        std::shared_ptr<ksword::ark::DriverHandle> hvmHandle_; // 同一会话始终复用此设备句柄。
        std::vector<MemoryDebugThreadRecord> threads_; // 与选择器索引一一对应的强身份。
        FieldDocument document_; // 寄存器显示、搜索、复制和导出的唯一来源。
        std::array<std::uint64_t, 28> documentKey_{}; // 后端、身份及全部显示数值；不比较协议填充。
        QString documentLanguage_; // 语言变化仍重新生成当前规范文档。
        bool documentKeyValid_ = false; // 只跳过相同现场文档，生命周期查询和状态回执仍应用。
        std::uint32_t pid_ = 0; // 当前工作台目标。
        std::uint64_t creation_ = 0; // 当前目标进程创建时间。
        std::uint64_t stopId_ = 0; // 协作后端当前一次性停点身份。
        std::uint64_t epoch_ = 0; // 目标或后端变化后拒绝旧回投。
        std::uint64_t hvmSessionId_ = 0; // 驱动返回的独占生命周期身份，失败时不得遗忘。
        std::uint64_t ownerCreation_ = 0; // 控制进程创建时间，与驱动请求者对象复核。
        unsigned long hvmState_ = KSWORD_ARK_HVM_NOATTACH_CLOSED; // 最后确认的当前执行状态。
        int mode_ = 0; // 当前已生效的后端索引。
        bool busy_ = false; // 禁止同一面板发出重叠控制请求。
        bool ownsPause_ = false; // 原生会话仍需归还的一次暂停。
        bool connected_ = false; // 协作握手成功，不能由端点存在推断。
        bool stopped_ = false; // 协作后端最新响应证实当前停止。
        bool hvmAvailable_ = false; // 驱动只读查询证实具备实验执行能力。
        bool hvmOwnershipUncertain_ = false; // OPEN 回执丢失时先恢复身份，不能放弃潜在自有常驻。
        int fastPollBudget_ = 0; // 新暂停/单步短时加快回执查询，长期等待恢复低频，避免常驻忙轮询。
        KSWORD_ARK_HVM_NOATTACH_RESPONSE hvmResponse_{}; // 最近经协议核验的会话文档。
        QPointer<QDialog> hvmDialog_; // 工具窗关闭不执行继续或结束调试。
        QLineEdit* hvmAddress_ = nullptr;
        QLineEdit* hvmValue_ = nullptr;
        QComboBox* hvmRegister_ = nullptr;
        QTableWidget* hvmBreakpoints_ = nullptr;
        QLabel* hvmDetailStatus_ = nullptr;
        QPushButton* hvmAdd_ = nullptr;
        QPushButton* hvmRemove_ = nullptr;
        QPushButton* hvmRunTo_ = nullptr;
        QPushButton* hvmWrite_ = nullptr;
        std::uint64_t hvmDialogSession_ = 0; // 同一窗口不会把旧目标草稿用于另一个会话。
        std::array<KSWORD_ARK_HVM_NOATTACH_BREAKPOINT, KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS> hvmDisplayedRows_{};
        unsigned long hvmDisplayedCount_ = ~0UL;
    };
}
