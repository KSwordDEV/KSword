#include "thread_stack.h" // 导入模块入口与唯一共享协议。
#include "thread_stack_snapshot.h" // 新来源独立端点与完整快照回执。
#include "../../dispatch/ioctl_validation.h" // 复用现有 WDF 缓冲区校验。

NTSTATUS KswordARKThreadIoctlCaptureStack( // 同步处理固定包，所有目标回调都必须在返回前完成取消或退休。
    _In_ WDFDEVICE Device, // 保留统一处理器签名，不改变设备状态。
    _In_ WDFREQUEST Request, // 请求缓冲区仅用于同步处理。
    _In_ size_t InputBufferLength, // 实际输入容量由共享校验器查询。
    _In_ size_t OutputBufferLength, // 实际输出容量由共享校验器查询。
    _Out_ size_t* BytesReturned // 成功时返回固定回执字节数。
    ) // 通信结构只能来自共享协议头。
{ // 开始固定缓冲区处理。
    KSWORD_ARK_THREAD_STACK_REQUEST input; // METHOD_BUFFERED 输入输出可能共享底层存储，必须先复制。
    PVOID inputBuffer = NULL; // 保存已校验输入地址。
    PVOID outputBuffer = NULL; // 保存已校验输出地址。
    size_t actualInput = 0U; // 保存真实输入容量。
    size_t actualOutput = 0U; // 保存真实输出容量。
    NTSTATUS status; // 保存运输或业务处理状态。
    UNREFERENCED_PARAMETER(Device); // 本模块不修改设备或目标状态。
    UNREFERENCED_PARAMETER(InputBufferLength); // 以 WDF 返回的实际容量为准。
    UNREFERENCED_PARAMETER(OutputBufferLength); // 以 WDF 返回的实际容量为准。
    if (BytesReturned == NULL) // 不接受缺失完成长度的调用。
    { // 开始缺失返回长度的拒绝分支。
        return STATUS_INVALID_PARAMETER; // 不写入无效长度指针。
    } // 结束返回长度检查。
    *BytesReturned = 0U; // 验证完成前绝不宣称存在输出。
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(input), &inputBuffer, &actualInput); // 验证固定输入最小长度。
    if (!NT_SUCCESS(status)) // 不读取短输入。
    { // 开始输入校验失败分支。
        return status; // 原样返回运输失败。
    } // 结束输入校验检查。
    RtlCopyMemory(&input, inputBuffer, sizeof(input)); // 在清零共享输出前冻结输入。
    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(KSWORD_ARK_THREAD_STACK_RESPONSE), &outputBuffer, &actualOutput); // 要求完整固定回执空间。
    if (!NT_SUCCESS(status)) // 无法容纳回执时不进行业务查询。
    { // 开始输出校验失败分支。
        return status; // 不执行部分回执。
    } // 结束输出校验检查。
    UNREFERENCED_PARAMETER(actualInput); // 输入包内 size 仍由业务层精确核对。
    UNREFERENCED_PARAMETER(actualOutput); // 输出最小容量已经验证。
    status = KswordARKThreadStackCapture(&input, (KSWORD_ARK_THREAD_STACK_RESPONSE*)outputBuffer); // 业务状态写入固定回执。
    if (!NT_SUCCESS(status)) // 参数指针或调用环境失败没有可消费回执。
    { // 开始业务入口环境失败分支。
        return status; // 不能用固定长度掩盖运输失败。
    } // 结束业务入口状态检查。
    *BytesReturned = sizeof(KSWORD_ARK_THREAD_STACK_RESPONSE); // 标记真实返回的固定字节数。
    return STATUS_SUCCESS; // 运输成功不等于已采到目标调用帧。
} // 结束固定缓冲区处理。

NTSTATUS KswordARKThreadIoctlSnapshotStack(WDFDEVICE Device, WDFREQUEST Request, size_t InputBufferLength, size_t OutputBufferLength, size_t* BytesReturned) // 只读同步保存上下文端点。
{ // 输入输出可能共用 METHOD_BUFFERED 存储，先冻结输入。
    KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST input; // 唯一共享固定身份输入。
    PVOID inputBuffer = NULL; // WDF 校验后的输入指针。
    PVOID outputBuffer = NULL; // WDF 校验后的完整输出指针。
    size_t actualInput = 0U; // WDF 实际输入容量。
    size_t actualOutput = 0U; // WDF 实际输出容量。
    NTSTATUS status; // 仅此变量决定运输层失败。
    UNREFERENCED_PARAMETER(Device); // 不修改控制设备状态。
    UNREFERENCED_PARAMETER(InputBufferLength); // 信任 WDF 返回的实际容量而非转发参数。
    UNREFERENCED_PARAMETER(OutputBufferLength); // 容量仍在下面独立核验。
    if (BytesReturned == NULL) return STATUS_INVALID_PARAMETER; // 不写入缺失的完成长度。
    *BytesReturned = 0U; // 校验失败没有输出。
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(input), &inputBuffer, &actualInput); // 输入不足时不读取。
    if (!NT_SUCCESS(status)) return status; // 保留实际 WDF 运输错误。
    RtlCopyMemory(&input, inputBuffer, sizeof(input)); // 输出清零前完整冻结身份包。
    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE), &outputBuffer, &actualOutput); // 必须容纳独立完整响应。
    if (!NT_SUCCESS(status)) return status; // 不执行只能返回一半的快照。
    UNREFERENCED_PARAMETER(actualInput); // 包内 size 仍由后端精确检查。
    UNREFERENCED_PARAMETER(actualOutput); // 此处已确保最小完整容量。
    status = KswSavedStackCapture(&input, (KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE*)outputBuffer); // 业务结果写入源明确的响应。
    if (!NT_SUCCESS(status)) return status; // 不能用固定长度掩盖入口环境错误。
    *BytesReturned = sizeof(KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE); // 返回实际完整 wire 大小。
    return STATUS_SUCCESS; // 调用者必须另查业务状态、来源和帧数。
} // 所有目标内存读取与 DPC 返回均在本次同步请求内结束。
