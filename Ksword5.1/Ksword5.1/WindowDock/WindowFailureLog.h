#pragma once

#include "../Framework.h"
#include <exception>

namespace ks::window
{
    // 调用方为一次操作创建 trace 并复用；传入模块、阶段和原始诊断，写入错误日志，无返回值。
    void LogWindowFailure(kLogEvent& trace, const char* module, const char* stage, const QString& detail);

    // 异步失败回调传入 exception_ptr；解出异常原因后复用同一 trace 写日志，无返回值。
    void LogWindowException(kLogEvent& trace, const char* module, std::exception_ptr failure);
}
