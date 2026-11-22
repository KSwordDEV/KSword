#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <cstring>
#include <iostream>

namespace
{
    KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE receipt{}; // 内存中的合成传输回执，绝不打开宿主机驱动。
    unsigned long returned = sizeof(receipt); // 可独立模拟截断的设备输出长度。
    int failures = 0; // 所有生产客户端断言的失败总数。

    // 输入断言及标签；输出单行测试结果并累计失败，不修改任何系统对象。
    void Check(const bool pass, const char* name)
    {
        std::cout << (pass ? "PASS " : "FAIL ") << name << '\n';
        failures += !pass;
    }

    // 无参数；构造拥有完整有效位的固定合成包，只用于校验客户端拒绝与解码逻辑。
    KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE GoodReceipt()
    {
        KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE result{}; // 不能把该测试包记入虚拟机现场覆盖率。
        result.version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION;
        result.size = sizeof(result);
        result.sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_OK;
        result.objectType = KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS;
        result.profileId = 1;
        result.flags = KSWORD_ARK_STRUCTURE_SAMPLE_NONATOMIC | KSWORD_ARK_STRUCTURE_SAMPLE_BODY_ONLY |
            KSWORD_ARK_STRUCTURE_SAMPLE_POINTER_VALUES | KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_ID_VALID;
        result.processId = 123;
        result.processCreationTime100ns = 100;
        result.rootSize = 64;
        result.bytesCopied = 64;
        result.objectAddress = 0xffff800000001000ULL;
        result.sampleStartTime100ns = 1000;
        result.sampleEndTime100ns = 1100;
        result.kernel.machine = 0x8664;
        result.kernel.timeDateStamp = 123;
        result.kernel.sizeOfImage = 456;
        result.kernel.pdbAge = 1;
        const unsigned char guid[16] = {0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}; // 检查 Windows GUID 字节序，不使用对称字节蒙混。
        std::memcpy(result.kernel.pdbGuid, guid, sizeof(guid));
        std::memset(result.valid, 0xff, 8);
        result.bytes[0] = 0x42;
        return result;
    }
}

namespace ksword::ark
{
    // 替换的唯一边界是传输：生产 DriverClient::queryStructureSample 与投影实现保持原样。
    IoResult DriverClient::deviceIoControl(const unsigned long code, void* input, const unsigned long inputBytes,
        void* output, const unsigned long outputBytes, DriverHandle*) const
    {
        Check(code == IOCTL_KSWORD_ARK_QUERY_STRUCTURE_SAMPLE && input &&
            inputBytes == sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST) && outputBytes == sizeof(receipt),
            "production transport uses the fixed identity-only ABI");
        std::memcpy(output, &receipt, sizeof(receipt));
        IoResult result; // 仅说明合成传输成功，语义和身份仍必须由生产客户端校验。
        result.ok = true;
        result.bytesReturned = returned;
        return result;
    }
}

// 无参数；测试完整/稀疏回执、身份错误、协议错误以及未知内核的拒绝路径。
int main()
{
    ks::threadlayout::Profile profile; // 精确符号键按真实分片相同格式构造。
    profile.identity = {0x8664, 123, 456, "00112233445566778899AABBCCDDEEFF1"};
    profile.rootSize = 64;
    profile.fields = {{0, 0, "Value", "0x0022 (unsigned long)", -1, -1, false},
        {0, 60, "Zero", "0x0022 (unsigned long)", -1, -1, false}};
    KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST request{}; // 只传冻结的进程身份，不传对象地址或大小。
    request.version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION;
    request.objectType = KSWORD_ARK_STRUCTURE_SAMPLE_EPROCESS;
    request.processId = 123;
    request.processCreationTime100ns = 100;
    const ksword::ark::DriverClient client; // 每次仍调用生产的固定协议客户端包装。
    const auto run = [&]() // 当前合成包 → 生产校验/投影结果；没有设备访问。
    {
        return client.queryStructureSample(profile, request);
    };
    receipt = GoodReceipt();
    const auto good = run(); // 验证精确 GUID 字节序和有效零值都能正确解码。
    Check(good.io.ok && good.identityVerified && good.projection.coverageRows == 2 &&
        good.projection.fields[0].value == 0x42 && good.projection.fields[1].value == 0,
        "verified synthetic bytes including real zero values decode");
    receipt.kernel.pdbGuid[0] ^= 1;
    Check(!run().identityVerified && run().projection.fields.empty(), "wrong loaded-kernel RSDS publishes no fields");
    receipt = GoodReceipt();
    ++receipt.processCreationTime100ns;
    Check(!run().io.ok && !run().identityVerified, "wrong process incarnation rejected");
    receipt = GoodReceipt();
    receipt.flags &= ~KSWORD_ARK_STRUCTURE_SAMPLE_BODY_ONLY;
    Check(!run().io.ok, "missing body-only guarantee rejected");
    receipt = GoodReceipt();
    --receipt.bytesCopied;
    Check(!run().io.ok, "validity population must equal copied byte count");
    receipt = GoodReceipt();
    receipt.bytes[65] = 1;
    Check(!run().io.ok, "invalid-byte tail cannot contain exposed data");
    receipt = GoodReceipt();
    receipt.valid[8] = 1;
    ++receipt.bytesCopied;
    Check(!run().io.ok, "root-external validity bit rejected");
    receipt = GoodReceipt();
    ++receipt.version;
    Check(!run().io.ok, "incompatible protocol version rejected");
    receipt = GoodReceipt();
    receipt.flags |= 0x80000000UL;
    Check(!run().io.ok, "unknown version-one guarantee flag rejected");
    receipt = GoodReceipt();
    receipt.kernel.reserved = 1;
    Check(!run().io.ok, "nonzero kernel identity reserved field rejected");
    receipt = GoodReceipt();
    receipt.sampleStatus = 0x80000000UL;
    Check(!run().io.ok, "unknown sample status rejected");
    receipt = GoodReceipt();
    receipt.sampleEndTime100ns = receipt.sampleStartTime100ns - 1;
    Check(!run().io.ok, "reversed sampling interval rejected");
    receipt = GoodReceipt();
    returned = sizeof(receipt) - 1;
    Check(!run().io.ok, "truncated response rejected");
    returned = sizeof(receipt);
    receipt = GoodReceipt();
    receipt.sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_PARTIAL;
    receipt.valid[7] &= 0x0f;
    receipt.bytesCopied = 60;
    const auto partial = run(); // 最后四字节不完整，其余字段仍允许分别显示。
    Check(partial.io.ok && partial.identityVerified && partial.projection.sampledRows == 1 &&
        partial.projection.fields[1].status == ks::structure_sample::FieldStatus::OutsideSnapshot,
        "sparse valid prefix does not fabricate a zero-valued final field");
    receipt = {};
    receipt.version = KSWORD_ARK_STRUCTURE_SAMPLE_VERSION;
    receipt.size = sizeof(receipt);
    receipt.objectType = request.objectType;
    receipt.sampleStatus = KSWORD_ARK_STRUCTURE_SAMPLE_KERNEL_UNSUPPORTED;
    const auto unsupported = run(); // 旧版或未知内核只能保留拒绝状态，不能推测邻版结构。
    Check(unsupported.io.ok && unsupported.unsupported && !unsupported.identityVerified &&
        unsupported.projection.fields.empty(), "unknown kernel returns explicit unsupported without fields");
    return failures ? 1 : 0;
}
