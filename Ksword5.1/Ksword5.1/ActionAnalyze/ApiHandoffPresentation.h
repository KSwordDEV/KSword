#pragma once

#include <QString>

namespace ks::ui
{
    struct FieldDocument;
}

namespace ks::action_analyze
{
    // 输入本次采样的冻结JSON；返回共享字段文档供接管树搜索/复制/导出，不访问目标或控制后端。
    ks::ui::FieldDocument ApiHandoffDocument(const QString& receipt);
}
