#pragma once

#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/CooperativeApiCapture.h"
#include <QWidget>

class QLineEdit;
class QSpinBox;
class QLabel;
namespace ks::ui { struct FieldDocument; }

namespace ks::action_analyze {

// 挂载：行为分析→写入停点/执行断点集合→原ParameterWorkspace参数区；不创建页、动作栏或worker。
class NativeSessionApiPane final : public QWidget {
public:
    // parent为原参数正文；仅创建自然高度分区，动作由原页面固定栏负责。
    explicit NativeSessionApiPane(QWidget* parent);
    // 输入原worker公布的native目标纯值，输出冻结来源草稿；失败保持out不变。
    // 本方法仅解析参数，不确认、不读项目、不查询进程；成功时confirmed仍为false。
    bool Prepare(const Ksword::ActionAnalyze::NativeBoundApiTarget& nativeTarget,
        Ksword::ActionAnalyze::NativeBoundApiRequest& out);
    // 输入Prepare冻结请求，显示精确来源和有限区间；确认后仅将本请求confirmed设true。
    // 返回false时不得派发；模态期间页面/会话变化由调用页在派发前再次核对。
    bool Confirm(Ksword::ActionAnalyze::NativeBoundApiRequest& request);
    // 将原worker纯值追加到现有规范文档，搜索/复制/导出仍使用原同一文档。
    static void AppendFields(ks::ui::FieldDocument& document,
        const Ksword::ActionAnalyze::NativeBoundApiResult& result);
    // 输入在途启动快照，追加本次来源、采样和真实阶段；不把它当成最终采集回执。
    static void AppendProgress(ks::ui::FieldDocument& document,
        const Ksword::ActionAnalyze::NativeBoundApiProgress& progress);
    // 输入同一writer发布的已提交水位和规则快照，追加原值字段；不重新匹配或推断规则。
    static void AppendCheckpoint(ks::ui::FieldDocument& document,
        const Ksword::ActionAnalyze::ProjectApiCheckpoint& checkpoint,
        const Ksword::ActionAnalyze::CooperativeApiRuleReceipt& rules);

private:
    QLineEdit* m_pid = nullptr; // 显式API来源PID草稿，不自动填native目标。
    QLineEdit* m_creation = nullptr; // 来源创建FILETIME十进制草稿。
    QSpinBox* m_duration = nullptr; // 有限采集区间毫秒值。
    QLabel* m_error = nullptr; // 参数错误，不覆盖旧结果规范文档。
};

} // namespace ks::action_analyze
