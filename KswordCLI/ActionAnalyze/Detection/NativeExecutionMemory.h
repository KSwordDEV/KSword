#pragma once

#include "../Project/MemorySnapshotReader.h"
#include "../Project/ProjectNativeExecution.h"

namespace Ksword::ActionAnalyze::Detection {

// 同一历史停点的执行观察与稍后读取的字节；不把内容读取当作CPU取指记录。
struct NativeExecutionMemoryMatch {
    std::string observation; // 保留进入尝试或Into完成的原始执行阶段。
    std::uint64_t instructionAddress = 0; // 使用原执行观察的指令起点，不使用下一RIP。
    std::string bytes; // 核验后所选范围的真实归档字节，最多15字节。
    std::vector<std::uint64_t> memoryRecordSequences; // 覆盖所选字节的raw-memory原页序号。
    bool heldAtBothChecks = false; // 仅成功匹配相同读前/读后停点时置真。
    bool bytesAtExecutionVerified = false; // 停点后的读取不能确认CPU当时取到的内容。
    bool allocationGenerationVerified = false; // 同址重新分配代次尚无证明。
    bool sourceAuthenticated = false; // 文件散列不认证历史生产者。
};

// 输入必须来自对应项目Reader的完整核验结果；不接受活进程或历史控制令牌接管。
// byteCount为指令起点后1..15字节的显式范围，不承诺已解码完整指令。
// 成功输出同停点字节与双方原始序号；失败清空out并返回具体阶段，不访问目标。
ProjectResult AssociateNativeExecutionMemory(std::string_view projectId, std::string_view sampleId,
    const ArchivedNativeExecution& execution, const ArchivedMemorySnapshot& memory,
    std::uint64_t byteCount, NativeExecutionMemoryMatch& out);

} // namespace Ksword::ActionAnalyze::Detection
