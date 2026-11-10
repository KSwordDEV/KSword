#include "WindowFailureLog.h"

namespace ks::window
{
    void LogWindowFailure(kLogEvent& trace, const char* module, const char* stage, const QString& detail)
    {
        // 使用固定诊断字段名保留来源，业务详情不经翻译，便于比对不同语言的现场。
        err << trace << "WINDOW_FAIL|" << module << '|' << stage << '|' << detail << eol;
    }

    void LogWindowException(kLogEvent& trace, const char* module, std::exception_ptr failure)
    {
        QString detail = QStringLiteral("unknown exception"); // 没有异常对象时仍保留明确诊断。
        try
        {
            if (failure)
            {
                std::rethrow_exception(failure);
            }
        }
        catch (const std::exception& exception)
        {
            // exception 由当前异常持有；立即复制 what()，不向异步边界外借用指针。
            detail = QString::fromUtf8(exception.what());
        }
        catch (...)
        {
            detail = QStringLiteral("non-standard exception");
        }
        LogWindowFailure(trace, module, "ASYNC_EXCEPTION", detail);
    }
}
