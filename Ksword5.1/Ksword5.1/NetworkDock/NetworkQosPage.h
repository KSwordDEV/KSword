#pragma once
#include "../../../shared/usermode/backend/network/NetworkPolicy.h"
#include <QPointer>
#include <QWidget>
#include <functional>
class QLineEdit;
class QComboBox;
class QDoubleSpinBox;
class QSpinBox;
class QCheckBox;
class QLabel;
class QPushButton;
class QTableView;
namespace ks::ui
{
class AsyncOperation;
class MetricAreaWindow;
} // namespace ks::ui
class NetworkQosPage final : public QWidget
{
  public:
    explicit NetworkQosPage(QWidget *parent = nullptr);
    ~NetworkQosPage() override;

  protected:
    void changeEvent(QEvent *) override;

  private:
    void refresh();
    void save();
    void remove();
    void toggle();
    void selected();
    void reset();
    void updateButtons();
    void refreshArea();
    void exportPolicies();
    void importPolicy();
    ks::r3::network::QosPolicy form() const;
    void setForm(const ks::r3::network::QosPolicy &policy);
    void publishPolicies(std::vector<ks::r3::network::QosPolicy> policies, const QString &selectedId);
    void mutate(std::function<ks::r3::network::NetworkPolicyResult()> operation);
    ks::ui::AsyncOperation *m_operation = nullptr;
    QLineEdit *m_path = nullptr, *m_source = nullptr, *m_destination = nullptr;
    QComboBox *m_scope = nullptr, *m_protocol = nullptr;
    QDoubleSpinBox *m_rate = nullptr;
    QSpinBox *m_dscp = nullptr, *m_priority = nullptr, *m_precedence = nullptr;
    QSpinBox *m_sourceStart = nullptr, *m_sourceEnd = nullptr, *m_destStart = nullptr, *m_destEnd = nullptr;
    QCheckBox *m_enabled = nullptr;
    QLabel *m_status = nullptr, *m_identity = nullptr;
    QPushButton *m_save = nullptr, *m_remove = nullptr, *m_toggle = nullptr, *m_refresh = nullptr, *m_new = nullptr;
    QTableView *m_table = nullptr;
    class Model;
    Model *m_model = nullptr;
    std::vector<ks::r3::network::QosPolicy> m_policies;
    QString m_editingId;
    bool m_managed = true;
    std::uint64_t m_originalRateBytes = 0;
    double m_originalRateDisplay = 0;
    QPointer<ks::ui::MetricAreaWindow> m_area;
};
