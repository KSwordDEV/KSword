#pragma once

#include <QDialog>
#include <QString>

#include <array>
#include <cstdint>

namespace ks::ui { class StructuredFieldView; }
class QLabel;
class QPushButton;
class QCheckBox;
class QTableWidget;

namespace ksword::ark
{
    struct DriverImageControlResult;
    struct DriverImageValues;
}

// DriverObject/KLDR 镜像元数据与 PsLoadedModuleList 高级事务编辑器。
// UI 只告知风险并获取显式确认，不按目标类别、产品身份或请求值施加限制。
class KernelDriverImageEditorDialog final : public QDialog
{
public:
    explicit KernelDriverImageEditorDialog(
        const QString& driverObjectName,
        QWidget* parent = nullptr);

private:
    // initializeUi：构建不透明对话框、五字段表格、详情编辑器和高风险动作栏。
    void initializeUi();
    // refreshSnapshot：先确定 DriverObject 身份，再查询 R0 事务/加载链同锁快照。
    void refreshSnapshot();
    // queryTransaction：按已建立身份刷新事务，并可选择是否覆盖用户目标值。
    bool queryTransaction(
        ksword::ark::DriverImageControlResult& resultOut,
        bool resetDesiredValues);
    // applySelectedFields：解析勾选行目标值并提交五字段原子 CAS 请求。
    void applySelectedFields();
    // hideFromLoadedModuleList：按最新 Flink/Blink 快照执行资源锁内摘链。
    void hideFromLoadedModuleList();
    // restoreManagedState：恢复勾选字段，并按复选框决定是否重新插入加载链。
    void restoreManagedState();
    // abandonRecoveryRecord：保持当前危险状态并永久丢弃 R0 恢复记录。
    void abandonRecoveryRecord();

    // applyResultToView：把完整响应投影到表格、详情和动作可用状态。
    void applyResultToView(
        const ksword::ark::DriverImageControlResult& result,
        bool resetDesiredValues);
    // updateDetails：使用原生字段模型展示地址、链、掩码、代次和状态位。
    void updateDetails(
        const ksword::ark::DriverImageControlResult& result);
    // setActionsEnabled：统一控制事务按钮，避免身份尚未建立时发请求。
    void setActionsEnabled(bool querySucceeded, bool recordPresent);
    // setStatus：更新可复制状态文本和语义颜色。
    void setStatus(const QString& text, const QString& colorHex);

    // selectedFieldMask：读取表格复选框并生成共享协议 fieldMask。
    std::uint32_t selectedFieldMask() const;
    // parseDesiredValues：解析表格目标列；仅自然 ULONG 字段检查 32 位宽度。
    bool parseDesiredValues(
        ksword::ark::DriverImageValues& valuesOut,
        QString& errorOut) const;
    // confirmDanger：警告后要求输入动作短语，确认但不改变目标/值。
    bool confirmDanger(
        const QString& warningText,
        const QString& phrase) const;

    // fieldValue / setFieldValue：按固定行号访问五字段模型。
    static std::uint64_t fieldValue(
        const ksword::ark::DriverImageValues& values,
        int row);
    static void setFieldValue(
        ksword::ark::DriverImageValues& values,
        int row,
        std::uint64_t value);
    static QString pointerText(std::uint64_t address);
    static QString ntStatusText(long status);
    static bool parseUnsigned64(
        const QString& text,
        std::uint64_t& valueOut);

    QString m_requestedDriverName;              // 用户从对象目录选择的原始名称。
    QString m_canonicalDriverName;              // R0 返回的 canonical DriverObject 名称。
    QLabel* m_riskLabel = nullptr;              // 永久可见的高风险说明。
    QLabel* m_identityLabel = nullptr;          // DriverObject/模块身份摘要。
    QLabel* m_statusLabel = nullptr;            // 当前动作与 NTSTATUS。
    QTableWidget* m_table = nullptr;            // 五字段当前/目标/事务明细表。
    ks::ui::StructuredFieldView* m_detailEditor = nullptr; // 完整链和事务证据，只读。
    QCheckBox* m_restoreLinkCheckBox = nullptr; // 恢复时是否同时重插加载链。
    QPushButton* m_refreshButton = nullptr;     // 刷新身份和事务快照。
    QPushButton* m_applyButton = nullptr;       // 原子应用勾选字段。
    QPushButton* m_hideButton = nullptr;        // 从 PsLoadedModuleList 摘链。
    QPushButton* m_restoreButton = nullptr;     // 恢复字段/加载链。
    QPushButton* m_abandonButton = nullptr;     // 放弃恢复记录。

    std::uint64_t m_moduleBase = 0;             // 首次身份模块基址。
    std::uint64_t m_driverObjectAddress = 0;    // 精确 DriverObject 地址。
    std::uint64_t m_currentLinkFlink = 0;       // 最近查询到的加载链 Flink。
    std::uint64_t m_currentLinkBlink = 0;       // 最近查询到的加载链 Blink。
    std::array<std::uint64_t, 5> m_currentValues{}; // 最近五字段原子快照。
    std::uint32_t m_generation = 0;             // 当前事务代次。
    std::uint32_t m_responseFlags = 0;          // 链和记录状态位。
    std::uint32_t m_managedFieldMask = 0;       // 当前受管字段掩码。
};
