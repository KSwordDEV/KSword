#pragma once

#include "WorkbenchDisasmView.h"
#include <QString>

namespace ks::ui
{
    // AssemblyPreviewInput：宿主冻结的旧字节和预览政策；本模块不读写目标或管理提交事务。
    struct AssemblyPreviewInput
    {
        std::uint64_t address = 0; // 指令起点，使用宿主正式坐标域。
        bool x64 = true; // 编辑开始时的架构，不随模态期间宿主变化。
        QByteArray snapshot; // 起点之后捕获的旧字节，用于完整指令边界校验。
        QString initialSource; // 初始 Intel 汇编文本。
        int initialSpan = 1; // 初始覆盖长度，通常是原指令长度。
        int maximumSpan = 256; // 宿主明确限额：实时 256，快照 65536。
        QString dialogName; // 已有自动化入口名称，由宿主传入以保持契约。
        QString sourceName; // 源码核心对象名，供键盘测试定位。
        QString previewName; // 只读预览核心对象名。
        QString stageCaption; // 宿主提交动作文字，缓存和事务暂存保持原意。
        QString hint; // 宿主说明提交行为与权限边界。
        QString completion; // 成功状态模板，保留宿主的最终应用方式。
    };

    // AssemblyPreviewResult：纯计算结果，失败没有可提交载荷。
    struct AssemblyPreviewResult
    {
        QByteArray payload; // 成功时覆盖指定长度的机器码，按政策补 NOP。
        QString text; // 原始/替换字节及逐条反汇编预览。
        QString error; // 失败原因；空字符串表示成功。
    };

    // BuildAssemblyPreview：共享边界扫描、NOP 和预览逻辑；不使用 UI 或真实目标。
    // 传入冻结字节、覆盖长度、已编译结果及解码器，返回完整载荷或明确错误。
    AssemblyPreviewResult BuildAssemblyPreview(const AssemblyPreviewInput& input, int span,
        bool padWithNop, const WorkbenchAssembleResult& assembled, const DecodeOneFn& decode);

    // RunAssemblyPreviewDialog：共享可取消预览外壳；返回确认载荷，取消/销毁返回空。
    // 宿主收到结果后仍必须复核身份、权限和旧字节，并通过自己的正式事务提交。
    QByteArray RunAssemblyPreviewDialog(QWidget* parent, const AssemblyPreviewInput& input,
        const AssembleOneFn& assemble, const DecodeOneFn& decode);
}
