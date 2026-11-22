#pragma once // 声明有界只读根对象采样的驱动私有入口。
#include "ark/ark_driver.h" // 使用工程现有的 NT 和 KMDF 类型声明。
#include "driver/KswordArkStructureSampleIoctl.h" // 引入唯一的共享通信协议。

// 后端接收内核拥有的输入输出缓冲区，负责返回固定回执，不完成 WDF 请求。
NTSTATUS // 返回调用状态，对象级拒绝原因写入响应。
KswordARKQueryStructureSample( // 调用方提供已捕获的请求和完整的固定响应空间。
    _In_ const KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST* Request, // 已捕获的身份请求，不包含外部地址。
    _Out_ KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE* Response // 调用方拥有的完整固定输出缓冲区。
    ); // 声明只读采样后端，不转移任何缓冲区所有权。

// 注册表在完成现有设备和访问权限校验后调用此传输适配入口。
NTSTATUS // 传输失败返回错误，对象采样结果通过固定响应返回。
KswordARKProcessIoctlQueryStructureSample( // 必须先保存 METHOD_BUFFERED 输入，再写入可能重叠的输出。
    _In_ WDFDEVICE Device, // 设备身份仍由现有分发层管理。
    _In_ WDFREQUEST Request, // 适配层既不完成请求，也不保留请求对象。
    _In_ size_t InputBufferLength, // 第一版协议输入长度固定。
    _In_ size_t OutputBufferLength, // 输出必须能够容纳完整的固定响应。
    _Out_ size_t* BytesReturned // 传输失败时为零，有效回执返回固定响应大小。
    ); // 声明处理入口，请求完成仍由现有分发层负责。
