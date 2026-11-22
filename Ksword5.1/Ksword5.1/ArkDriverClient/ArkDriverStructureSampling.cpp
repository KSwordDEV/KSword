#include "ArkDriverClient.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        // 输入原始 Windows GUID 字节和 Age；输出与精确分片相同的大写符号键，不查找邻版。
        std::string PdbKey(const KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID& kernel)
        {
            GUID guid{}; // 只在本地格式化已收到的 GUID，不将结构字段当作地址。
            std::memcpy(&guid, kernel.pdbGuid, sizeof(guid));
            std::ostringstream text; // 固定宽度的 GUID 段和不补零的十六进制 Age。
            text << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << guid.Data1
                << std::setw(4) << guid.Data2 << std::setw(4) << guid.Data3;
            for (const auto byte : guid.Data4) // 后八字节不改变 GUID 文本顺序。
            {
                text << std::setw(2) << static_cast<unsigned int>(byte);
            }
            text << kernel.pdbAge;
            return text.str();
        }

        // 输入回执有效位；输出所有根内有效字节的数量，拒绝根外位图或非零未读字节。
        bool ValidateBitmap(const KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE& packet)
        {
            unsigned long count = 0; // 独立计数后与回执 bytesCopied 比较，不能只信状态文字。
            for (unsigned long index = 0; index < KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES; ++index)
            {
                const bool valid = (packet.valid[index >> 3] & (1U << (index & 7))) != 0; // 单字节有效位。
                if ((valid && index >= packet.rootSize) || (!valid && packet.bytes[index] != 0))
                {
                    return false;
                }
                count += valid ? 1UL : 0UL;
            }
            return count == packet.bytesCopied;
        }
    }

    // 调用：传入精确 PDB 布局及 PID/TID/创建时间请求；返回同次快照的逐行值或明确失败。
    // 该接口是 GUI/CLI 唯一的对象体采样入口，不接受调用方地址、字段偏移或读取长度。
    StructureSampleResult DriverClient::queryStructureSample(const ks::threadlayout::Profile& profile,
        const KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST& request) const
    {
        StructureSampleResult result; // 设备回执和投影由当前调用独立持有。
        auto captured = request; // 旧底层传输签名接收可写指针，独立副本不会暴露调用者的只读请求。
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_STRUCTURE_SAMPLE, &captured,
            static_cast<unsigned long>(sizeof(captured)), &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (!result.io.ok)
        {
            result.unsupported = result.io.win32Error == ERROR_INVALID_FUNCTION ||
                result.io.win32Error == ERROR_NOT_SUPPORTED;
            return result;
        }
        const auto& packet = result.response; // 以下所有校验均只处理当前同步设备回执。
        result.io.ntStatus = packet.lastStatus;
        result.unsupported = packet.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED;
        if (result.io.bytesReturned != sizeof(packet) || packet.version != KSWORD_ARK_STRUCTURE_SAMPLE_VERSION ||
            packet.size != sizeof(packet) || packet.atomic != 0 ||
            packet.kernel.reserved != 0 ||
            packet.sampleStatus < KSWORD_ARK_STRUCTURE_SAMPLE_OK ||
            packet.sampleStatus > KSWORD_ARK_STRUCTURE_SAMPLE_READ_FAILED ||
            packet.objectType != request.objectType || packet.rootSize > KSWORD_ARK_STRUCTURE_SAMPLE_MAX_BYTES ||
            packet.bytesCopied > packet.rootSize || !ValidateBitmap(packet))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "Invalid bounded structure-sample response";
            return result;
        }
        if (packet.sampleStatus != KSWORD_ARK_STRUCTURE_SAMPLE_OK &&
            packet.sampleStatus != KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL)
        {
            result.io.message = "Structure sampling rejected, status=" + std::to_string(packet.sampleStatus);
            return result;
        }
        // 对象引用核验、采样区间和精确内核身份缺一不可；旧缓存和仅磁盘符号都不能替代。
        constexpr unsigned long required = KSWORD_ARK_STRUCTURE_SAMPLE_NONATOMIC |
            KSWORD_ARK_STRUCTURE_SAMPLE_BODY_ONLY | KSWORD_ARK_STRUCTURE_SAMPLE_POINTER_VALUES |
            KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID_VALID; // 四个独立协议保证必须同时存在。
        if (packet.flags != required || !packet.profileId || !packet.objectAddress ||
            !(packet.objectAddress >> 63) || !packet.sampleStartTime100ns || !packet.sampleEndTime100ns ||
            packet.sampleEndTime100ns < packet.sampleStartTime100ns ||
            packet.processId != request.processId || packet.threadId != request.threadId ||
            packet.processCreationTime100ns != request.processCreationTime100ns ||
            packet.threadCreationTime100ns != request.threadCreationTime100ns ||
            (packet.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_OK && packet.bytesCopied != packet.rootSize) ||
            (packet.sampleStatus == KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL &&
                (!packet.bytesCopied || packet.bytesCopied >= packet.rootSize)))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "Structure sampling did not verify the requested identity and read interval";
            return result;
        }
        const ks::threadlayout::Identity identity{packet.kernel.machine, packet.kernel.timeDateStamp,
            packet.kernel.sizeOfImage, PdbKey(packet.kernel)}; // 使用加载中内核的完整 RSDS，不使用查询前磁盘缓存。
        result.projection = ks::structure_sample::Project(profile, identity, packet.rootSize,
            packet.bytes, packet.rootSize, packet.valid, sizeof(packet.valid));
        result.identityVerified = result.projection.identityMatched; // 还必须通过布局和根大小的精确一致性校验。
        result.io.message = result.identityVerified ? "Identity-verified non-atomic object-body sample" :
            "Running kernel identity or exact root size does not match the supplied symbol profile";
        return result;
    }
}
