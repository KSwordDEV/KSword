#pragma once

// ============================================================
// DisableDsePage.h
// 作用：
// 1) 在“杂项”里提供驱动签名强制（DSE）开关，用于临时加载未签名驱动；
// 2) 展示 CI / HVCI / 安全启动姿态，并把不满足条件的情况直接挡在按钮之前；
// 3) 定位 CI.dll!g_CiOptions 并展示完整定位轨迹，供用户核对地址是否可信；
// 4) 关闭前记录原值，提供一键恢复；页面析构时若仍处于关闭状态会自动写回。
//
// 风险说明：g_CiOptions 属于 PatchGuard 的巡检范围，长时间保持修改会触发
// CRITICAL_STRUCTURE_CORRUPTION 蓝屏。本页的定位是运行时反汇编得出的，
// 并在写入前校验读回值的强制签名位与系统自报状态自洽，
// 但仍要求用户加载完驱动后立刻恢复。
// ============================================================

#include "DisableDseBackend.h"

#include "../../Framework.h"

#include <QWidget>

#include <cstdint>

class QPushButton;
class QShowEvent;
class CodeEditorWidget;

namespace ks::misc
{
    // DisableDsePage：
    // - 作用：DSE 开关页；唯一的系统修改是 CI.dll!g_CiOptions 的 4 个字节；
    // - 说明：页面不加载任何第三方漏洞驱动，全部内核访问都走 KswordARK 自有 R0 事务通道。
    class DisableDsePage final : public QWidget
    {
    public:
        // 构造函数：只建界面，不访问驱动，避免打开“杂项”就触发一次内核查询。
        explicit DisableDsePage(QWidget* parent = nullptr);
        // 析构函数：若本页关闭过 DSE 且尚未恢复，在这里做最后一次写回，
        // 避免用户忘记恢复后被 PatchGuard 判定为内核数据被篡改。
        ~DisableDsePage() override;

    protected:
        // 页面第一次真正可见时才读一次系统姿态。
        void showEvent(QShowEvent* event) override;
    private:
        // initializeUi：建出状态编辑器和操作按钮。
        void initializeUi();
        // initializeConnections：把四个按钮接到各自的处理函数。
        void initializeConnections();

        // refreshPosture：同步查询 CI / HVCI 姿态并刷新到界面。
        void refreshPosture();
        // runLocate：在后台线程定位 g_CiOptions，并在定位成功后立即读回校验。
        void runLocate();
        // runApply：在后台线程把 g_CiOptions 写成 desiredValue；
        //   isRestore 只影响文案与状态记账，写入路径完全相同。
        void runApply(std::uint32_t desiredValue, bool isRestore);

        // LocateOutcome：一次定位 + 读回校验的综合结果，只在线程间传值。
        struct LocateOutcome
        {
            disable_dse::TargetLocation location;      // location：定位结果。
            disable_dse::ReadbackResult readback;      // readback：定位成功后的读回结果。
            disable_dse::CodeIntegrityPosture posture; // posture：做一致性判定时依据的系统姿态。
            bool valueMatched = false;                 // valueMatched：读回值是否与系统姿态自洽。
        };

        // applyLocateOutcome：在 UI 线程收拢定位结果。
        void applyLocateOutcome(const LocateOutcome& outcome);
        // applyApplyOutcome：在 UI 线程收拢写入结果。
        void applyApplyOutcome(const disable_dse::ApplyResult& result, bool isRestore);

        // setStatusText：记录最近一次操作结论并刷新状态编辑器。
        void setStatusText(const QString& text);
        // setBusy：一次操作没结束时禁用按钮，防止重复点击。
        void setBusy(bool busy);
        // updateButtons：按忙碌状态、姿态与定位结果刷新按钮可用性。
        void updateButtons();
        // updateStateDisplay：刷新状态编辑器的固定字段。
        void updateStateDisplay();

    private:
        CodeEditorWidget* m_statusEdit = nullptr; // m_statusEdit：全部状态与定位信息。
        QPushButton* m_refreshButton = nullptr; // m_refreshButton：重新查询系统姿态。
        QPushButton* m_locateButton = nullptr;  // m_locateButton：定位 g_CiOptions 并读回校验。
        QPushButton* m_disableButton = nullptr; // m_disableButton：关闭驱动签名强制。
        QPushButton* m_restoreButton = nullptr; // m_restoreButton：把 g_CiOptions 写回原值。

        disable_dse::CodeIntegrityPosture m_posture; // m_posture：最近一次查询到的姿态。
        disable_dse::TargetLocation m_location;      // m_location：最近一次定位结果。

        std::uint32_t m_currentValue = 0;      // m_currentValue：最近一次读回的 g_CiOptions。
        bool m_hasCurrentValue = false;        // m_hasCurrentValue：m_currentValue 是否有效。
        std::uint32_t m_savedOriginalValue = 0;// m_savedOriginalValue：本页关闭 DSE 前的原值。
        bool m_hasSavedOriginal = false;       // m_hasSavedOriginal：是否记录了待恢复的原值。
        bool m_valueMatched = false;           // m_valueMatched：读回值是否与系统自报值一致，false 时禁止写入。
        bool m_busy = false;                   // m_busy：后台操作进行中。
        QString m_statusText;                  // m_statusText：最近一次操作或校验状态。

        // m_blockReason：
        // - 最近一次算出的准入判定，updateStateDisplay 里刷新、updateButtons 里消费；
        // - 缓存下来是为了避免每次刷新按钮都去开一次驱动设备句柄。
        disable_dse::BlockReason m_blockReason = disable_dse::BlockReason::DriverUnavailable;
    };
}
