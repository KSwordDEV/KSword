#pragma once

#include <QWidget>
#include <atomic>
#include <memory>

class QLabel;
class QLineEdit;
class QComboBox;
class QSpinBox;
class QPushButton;
class QGroupBox;
class QFormLayout;
class QTabWidget;
class CodeEditorWidget;
namespace ks::ui { class AsyncOperation; class StructuredFieldView; }

namespace ks::action_analyze {

// 监控→行为分析→网络流量；已有项目与sample的显式采集/只读回放参数页。
class NetworkTrafficPane final : public QWidget {
public:
    explicit NetworkTrafficPane(QWidget* parent);
    ~NetworkTrafficPane() override;

protected:
    // 语言事件只更新展示文字；不重做采集、不改参数草稿或已发布结果。
    void changeEvent(QEvent* event) override;

private:
    // 在UI线程按当前语言重译固定文字、页签及保存的状态源文案。
    void retranslate();
    // 接收稳定中文源文案并更新状态，供后续语言切换重复翻译。
    void setStatus(const QString& source);
    // 点击时校验并冻结草稿，提交本端单个后台事务；read不要求当前目标仍存在。
    void execute(bool capture);
    // 选择已有正式manifest，仅修改草稿，不启动采集。
    void chooseProject();
    // 按真实单任务状态控制执行资格，参数草稿在结果发布期间保持独立。
    void updateActions();

    QGroupBox* m_section = nullptr; // 参数分区标题的原控件。
    QFormLayout* m_form = nullptr; // 按输入控件找到原标签，不重建表单。
    QLabel* m_hint = nullptr; // 面向用户的操作说明。
    QPushButton* m_browse = nullptr; // 项目选择按钮及提示。
    QTabWidget* m_tabs = nullptr; // 已有回执和字节页签的稳定宿主。
    QString m_statusSource; // 当前状态源文案，独立于已发布回执。
    QLineEdit* m_project = nullptr; // 已有项目manifest草稿。
    QLineEdit* m_sample = nullptr; // 已登记sample UUID。
    QLineEdit* m_pid = nullptr; // 下一次采集的目标PID。
    QLineEdit* m_creation = nullptr; // 精确创建FILETIME。
    QComboBox* m_source = nullptr; // 显式R3/既有WFP来源。
    QSpinBox* m_duration = nullptr; // 100..60000ms采集时长。
    QLineEdit* m_ordinal = nullptr; // 网络段号，0为最新。
    QLineEdit* m_sequence = nullptr; // 可选精确记录序号。
    QPushButton* m_capture = nullptr; // 显式启动采集。
    QPushButton* m_read = nullptr; // 只读原网络段。
    QPushButton* m_cancel = nullptr; // 置位本次采集取消，不撤销已提交内容。
    QLabel* m_status = nullptr; // 独立错误/忙/完成状态，不清空旧结果。
    ks::ui::StructuredFieldView* m_fields = nullptr; // 唯一字段文档与搜索复制导出。
    CodeEditorWidget* m_bytes = nullptr; // 真实字节正文，复用共享编辑器。
    ks::ui::AsyncOperation* m_worker = nullptr; // 单事务后台执行/投递门禁。
    std::shared_ptr<std::atomic_bool> m_cancelled; // worker独立拥有取消位。
};

} // namespace ks::action_analyze
