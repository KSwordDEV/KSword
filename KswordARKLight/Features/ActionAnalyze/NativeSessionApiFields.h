#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include <string>

namespace Ksword::Features::ActionAnalyze {

// 供原页面字段调用的纯值准备：输入十进制草稿与worker公布的原目标，不访问进程/项目。
// 成功输出confirmed=false请求，失败保留out；reason返回用户可读错误。
bool PrepareLightNativeSessionApi(const std::wstring& pid, const std::wstring& creation,
    const std::wstring& duration, const Ksword::ActionAnalyze::NativeBoundApiTarget& nativeTarget,
    Ksword::ActionAnalyze::NativeBoundApiRequest& out, std::wstring& reason);

// 输入原页三个EDIT和原native目标，读取草稿并对冻结的来源实例显示本次确认。
// 返回true才允许原worker派发CaptureApi；不会创建控件、sample、writer或native owner。
bool CollectLightNativeSessionApi(HWND parent, HWND pid, HWND creation, HWND duration,
    const Ksword::ActionAnalyze::NativeBoundApiTarget& nativeTarget,
    Ksword::ActionAnalyze::NativeBoundApiRequest& out, std::wstring& reason);

// 输入原worker不可变回执，返回原详情文档追加文本；不读取归档文件或当前UI条件。
std::wstring FormatLightNativeSessionApi(const Ksword::ActionAnalyze::NativeBoundApiResult& result);

// 输入原worker当前在途启动值，返回原详情正文；完整回执继续使用上面的独立格式化入口。
std::wstring FormatLightNativeSessionApiProgress(const Ksword::ActionAnalyze::NativeBoundApiProgress& progress);

} // namespace Ksword::Features::ActionAnalyze
