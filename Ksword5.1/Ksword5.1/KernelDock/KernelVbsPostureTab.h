#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
#include "../UI/StructuredFieldView.h"

// VBS/HVCI 真实姿态页。
//
// 这一页解决的是「以为 HVCI 开着、其实没在跑」这个具体问题：策略位
// （SystemCodeIntegrityInformation 的 HVCI_KMCI_ENABLED）只说明配置意图，
// 真正生效还需要 VBS 在位、hypervisor 存在、securekernel/skci 已加载。
// 页面把这两类证据并排放，任何一侧缺失都会给出明确结论，并单独列出
// 审计模式、测试签名、CI 调试模式、内核调试器这些会削弱 CI 的降级项。
class KernelVbsPostureTab final : public QWidget
{
public:
    explicit KernelVbsPostureTab(QWidget* parent = nullptr);
    ~KernelVbsPostureTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    // 单项判定的严重度，决定表格着色与是否计入降级清单。
    enum class Severity : int
    {
        Good = 0,
        Neutral,
        Warning,
        Bad
    };

    struct PostureRow
    {
        QString item;
        QString observed;
        QString verdict;
        QString source;
        Severity severity = Severity::Neutral;
        bool downgrade = false;
    };

    struct Snapshot
    {
        ksword::ark::SecurityStatusAuditResult security;
        ksword::ark::HyperVSummaryAuditResult hyperV;
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTable(const QList<PostureRow>& rows);
    void applyVerdictBanner(const Snapshot& snapshot, const QList<PostureRow>& rows);

    static QList<PostureRow> buildRows(const Snapshot& snapshot);
    static ks::ui::FieldDocument buildDetail(const Snapshot& snapshot);
    static QString codeIntegrityOptionText(std::uint32_t options);
    static QString moduleStateText(std::uint32_t state);
    static QString boolText(std::uint32_t value);
    static QString ntStatusText(long status);
    static QString fixedWide(const wchar_t* text, std::size_t capacity);

    QLabel* m_verdictLabel = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_downgradeLabel = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QTableWidget* m_table = nullptr;
    ks::ui::StructuredFieldView* m_detailEdit = nullptr;
    bool m_firstRefreshStarted = false;
    bool m_queryRunning = false;
};
