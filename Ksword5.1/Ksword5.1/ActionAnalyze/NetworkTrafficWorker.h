#pragma once

#include "../../../KswordCLI/ActionAnalyze/Project/NetworkTrafficRead.h"
#include "../UI/StructuredFieldView.h"

namespace ks::action_analyze {

struct NetworkTrafficView {
    Ksword::ActionAnalyze::NetworkTrafficResult result; // 原请求、writer与读端结果。
    ks::ui::FieldDocument fields; // 同一结果的完整规范字段文档。
    QString bytes; // 已核验记录的十六进制预览或精确记录全部保留字节。
};

// Qt后台事务调用，输入冻结值和独立取消位，输出可直接发布的同源字段与正文。
// worker独占正式ProjectDocument写租约，返回前释放；不访问任何窗口。
NetworkTrafficView RunNetworkTraffic(Ksword::ActionAnalyze::NetworkTrafficRequest request,
    const std::atomic_bool& cancelled);

} // namespace ks::action_analyze
