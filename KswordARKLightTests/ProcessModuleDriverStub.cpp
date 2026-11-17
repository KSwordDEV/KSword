#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

namespace ksword::ark
{
    // 离线测试不访问驱动：参数与生产接口一致，始终返回不可用的枚举结果。
    ProcessModuleEnumResult DriverClient::enumerateProcessModules(
        std::uint32_t,
        std::uint64_t,
        std::uint64_t,
        unsigned long,
        unsigned long) const
    {
        // 返回失败状态，避免离线测试把空结果误认为驱动枚举成功。
        ProcessModuleEnumResult result{};
        result.io.win32Error = ERROR_NOT_SUPPORTED;
        result.io.message = "Driver module enumeration is unavailable in offline tests";
        return result;
    }
}
