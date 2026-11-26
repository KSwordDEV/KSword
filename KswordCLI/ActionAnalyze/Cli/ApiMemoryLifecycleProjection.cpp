#include "ApiMemoryLifecycleProjection.h"

namespace ks::cli::action_analyze {
// 唯一JSON投影：各有效位独立决定值，Free从不生成实际释放范围。
Ksword::Evidence::JsonValue ApiMemoryLifecycleJson(const Ksword::Evidence::ApiMemoryLifecycleFieldsV1& f,
    std::uint64_t session)
{
    using namespace Ksword::Evidence;
    using V = JsonValue;
    // value为原64位数值，返回规范十进制字符串，与现有归档详情保持一致。
    const auto number = [](std::uint64_t value)
    {
        return V::makeString(std::to_string(value));
    };
    // flag为当前字段有效位，value为已解码原值；缺位返回null，不能补零或输入值。
    const auto optional = [&](std::uint64_t flag, std::uint64_t value) {
        return f.flags & flag ? number(value) : V::makeNull();
    };
    const auto type = ApiMemoryLifecycleEventType(f); // 共享解析给出的稳定事件类型。
    const auto operation = f.operation == ApiMemoryOperation::Allocate ? "allocate" :
        f.operation == ApiMemoryOperation::Protect ? "protect" : "free-request"; // Free保持请求语义。
    return V::makeObject({{"schema", V::makeString("api-memory-lifecycle-v1")},
        {"kind", V::makeString(operation)}, {"eventType", V::makeString(std::string(type))},
        {"flags", number(f.flags)}, {"pointerBits", V::makeUInt(f.pointerBits)},
        // 来源会话与进程强实例各自保留；字段自述不提升为认证图角色。
        {"sourceSessionIdentity", number(session)},
        {"actorCreationFileTime", optional(ApiMemoryActorIdentity, f.actorCreationFileTime)},
        {"targetPid", optional(ApiMemoryTargetIdentity, f.targetPid)},
        {"targetCreationFileTime", optional(ApiMemoryTargetIdentity, f.targetCreationFileTime)},
        {"targetStable", f.flags & ApiMemoryTargetIdentity ? V::makeBool((f.flags & ApiMemoryTargetStable) != 0) : V::makeNull()},
        // 输入、成功输出及操作专属参数分列，保留有效零值。
        {"requestedBase", optional(ApiMemoryRequestedBase, f.requestedBase)},
        {"requestedBytes", optional(ApiMemoryRequestedBytes, f.requestedBytes)},
        {"outputBase", optional(ApiMemoryOutputBase, f.outputBase)},
        {"outputBytes", optional(ApiMemoryOutputBytes, f.outputBytes)},
        {"allocationType", f.operation == ApiMemoryOperation::Allocate ? number(f.allocationType) : V::makeNull()},
        {"newProtection", f.operation != ApiMemoryOperation::Free ? number(f.newProtection) : V::makeNull()},
        {"freeType", f.operation == ApiMemoryOperation::Free ? number(f.freeType) : V::makeNull()},
        // oldProtection独立判有效，不以成功或保护请求值代替原输出。
        {"oldProtectionValid", V::makeBool((f.flags & ApiMemoryOldProtection) != 0)},
        {"oldProtection", optional(ApiMemoryOldProtection, f.oldProtection)},
        {"status", f.returnValid ? V::makeInt(f.status) : V::makeNull()},
        {"returnValid", V::makeBool(f.returnValid)}, {"inputProcessHandle", number(f.inputProcessHandle)},
        {"enterQpc", f.enterQpc ? number(f.enterQpc) : V::makeNull()},
        {"returnQpc", f.returnQpc ? number(f.returnQpc) : V::makeNull()},
        // 本投影不生成实际释放全区、分配代次或执行与因果结论。
        {"actualReleasedRange", V::makeNull()}, {"allocationGeneration", V::makeNull()},
        {"execution", V::makeNull()}, {"causality", V::makeNull()}});
}

// 已知结构生成JSON后才转Unicode；不把原详情文本当作JSON或命令执行。
Json ApiMemoryLifecycleCliJson(const ks::winapi_monitor::ApiMonitorEventPacket& packet)
{
    const auto fields = Ksword::Evidence::ReadApiMemoryLifecycleFields(packet); // 同一完整包的严格解码。
    if (!fields) {
        return {};
    }
    const auto serialized = Ksword::Evidence::WriteJson(ApiMemoryLifecycleJson(*fields, packet.sessionIdentity)); // 仅ASCII键与数值。
    return {std::wstring(serialized.begin(), serialized.end()), L"AAIM1"};
}
} // namespace ks::cli::action_analyze
