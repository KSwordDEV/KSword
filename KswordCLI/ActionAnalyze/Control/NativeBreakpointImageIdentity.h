#pragma once

#include "NativeDebugAdmission.h"

#include <map>
#include <string>

namespace ks::cli::action_analyze::control
{
    // 输入SHA256文本，返回是否为项目约定的64位小写十六进制；不接受有损归一化。
    bool ValidNativeImageSha256(std::string_view value);

    // 只在有固定散列约束时持有调试事件的真实映像文件，不按路径重开另一份文件替代。
    class NativeBreakpointImageIdentity final
    {
    public:
        // 输入原owner收到的装载/卸载事件，登记按实际模块基址定位的文件句柄；不访问目标线程。
        native_owner_detail::NativeDebugError Observe(const DEBUG_EVENT& event);
        // 输入已解析的实际模块基址和冻结散列，成功输出实测SHA256；失败不武装断点。
        native_owner_detail::NativeDebugError Verify(std::uintptr_t moduleBase,
            std::string_view expected, std::string& observed);
        // 原绑定确认退出或脱离后调用，释放装载文件；历史快照保留实测散列而不再占用文件。
        void Reset() noexcept;

    private:
        std::map<std::uintptr_t, native_owner_detail::NativeDebugHandle> files_; // 装载事件文件，以映像基址区分同名模块。
    };
}
