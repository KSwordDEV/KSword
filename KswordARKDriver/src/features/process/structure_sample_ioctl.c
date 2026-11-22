// 为有界进程或线程根快照提供 KMDF 传输适配。
#include "structure_sample.h" // 后端及处理函数声明独立于分发注册表。
#include "../../dispatch/ioctl_validation.h" // 复用共享的必需缓冲区校验辅助函数。

// 功能：先捕获重叠缓冲请求再调用后端；输入为框架请求，输出为固定回执长度和传输状态。
NTSTATUS // 现有分发层仍是请求完成的唯一所有者。
KswordARKProcessIoctlQueryStructureSample( // METHOD_BUFFERED 输入输出重叠，必须先保存完整输入。
    WDFDEVICE Device, // 框架拥有的设备上下文。
    WDFREQUEST Request, // 框架拥有的当前请求对象。
    size_t InputBufferLength, // 分发层提供的输入长度，后续还会核对实际长度。
    size_t OutputBufferLength, // 分发层提供的输出容量，必须容纳固定响应。
    size_t* BytesReturned // 后端生成有效回执后才返回完整响应字节数。
    ) // 不在栈上分配巨大响应，也无需额外池分配。
{ // 适配层只负责当前请求的传输和输入快照。
    KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST captured; // 四十八字节请求副本可安全保存在内核栈上。
    PVOID input = NULL; // 仅由共享 WDF 缓冲区辅助函数取得的输入地址。
    PVOID output = NULL; // 指向完整的调用方可见响应缓冲区。
    size_t inputBytes = 0U; // WDF 实际返回的输入缓冲区长度。
    size_t outputBytes = 0U; // WDF 实际返回的输出缓冲区长度。
    NTSTATUS status; // 区分传输错误与正常返回的采样回执。
    UNREFERENCED_PARAMETER(Device); // 设备访问安全仍由现有分发及权限层管理。
    if (BytesReturned == NULL) // 分发层必须提供完成字节数的存储地址。
    { // 内部调用不合法时不访问框架请求。
        return STATUS_INVALID_PARAMETER; // 无法安全返回响应长度。
    } // 完成字节数现在可以安全初始化。
    *BytesReturned = 0U; // 传输失败时不能暴露旧输出字节。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) // 映像发现和对象查找之前先拒绝较高执行级别。
    { // 此处不尝试绕过队列策略或改变 IRQL。
        return STATUS_INVALID_DEVICE_STATE; // 明确报告执行环境不符合要求。
    } // 正常被动级分发策略由调用方负责。
    if (InputBufferLength != sizeof(captured) || // 第一版请求长度固定且必须精确一致。
        OutputBufferLength < sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE)) // 输出必须容纳完整固定响应。
    { // 截断或扩展请求不能被静默接受。
        return STATUS_INFO_LENGTH_MISMATCH; // 在取得缓冲区之前拒绝错误的长度声明。
    } // 后续仍需核对框架返回的实际缓冲区长度。
    status = KswordARKRetrieveRequiredInputBuffer( // 使用共享辅助函数取得 METHOD_BUFFERED 输入。
        Request, // 当前框架请求。
        sizeof(captured), // 固定请求的最低必需大小。
        &input, // 保存已验证的内核输入缓冲区地址。
        &inputBytes); // 保存框架返回的实际输入长度。
    if (!NT_SUCCESS(status)) // 保留框架给出的精确输入缓冲区错误。
    { // 此时尚未写入任何输出。
        return status; // 由现有分发层统一完成失败请求。
    } // 输入缓冲区至少包含完整请求。
    if (inputBytes != sizeof(captured)) // 未知尾随字节不是第一版协议的一部分。
    { // 不把额外输入解释为可选成员偏移或读取大小。
        return STATUS_INFO_LENGTH_MISMATCH; // 明确拒绝超长或不明确的请求。
    } // 整个通信请求的范围现在唯一确定。
    RtlCopyMemory(&captured, input, sizeof(captured)); // 必须先捕获输入，再取得或清零可能重叠的输出。
    status = KswordARKRetrieveRequiredOutputBuffer( // 要求框架提供完整固定响应缓冲区。
        Request, // 当前框架请求保持不变。
        sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE), // 不通过截断响应返回部分根正文。
        &output, // 保存已验证的响应缓冲区地址。
        &outputBytes); // 保存框架返回的实际输出容量。
    if (!NT_SUCCESS(status)) // 输出过小仍属于传输失败，而非采样成功。
    { // 不能让后端写入不完整的响应空间。
        return status; // 保留原始框架输出缓冲区错误。
    } // 后端现在可以安全初始化完整固定响应。
    status = KswordARKQueryStructureSample( // 仅把已捕获的身份数值传入 R0 采样后端。
        &captured, // 输入是独立栈副本，不受输出清零影响。
        (KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE*)output); // 输出指向完整的框架响应缓冲区。
    if (NT_SUCCESS(status)) // 对象或内核拒绝原因由响应的 sampleStatus 字段表达。
    { // 只返回固定响应长度，不包含多余输出容量。
        *BytesReturned = sizeof(KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE); // 明确供分发层完成请求的字节数。
    } // 现有分发层会且只会完成一次请求。
    return status; // 此适配函数不能调用 WdfRequestComplete。
} // 不跨请求保留输入输出缓冲区或对象引用。
