#include "ApiTransferPresentation.h"
#include "OfflineSegmentReader.h"
#include "../UI/StructuredFieldView.h"
#include "../../../KswordCLI/ActionAnalyze/Detection/ApiTransferChain.h"

namespace ks::action_analyze
{
namespace
{
    // 输入有效位、所需位、原数值及进制，返回字段文本；缺位统一未知，有效零值原样保留。
    QString OptionalApiValue(std::uint64_t flags, std::uint64_t required, std::uint64_t value, int radix = 10)
    {
        // flags 为原包有效位，required 为当前字段所需位，value 为原值，radix 为显示进制。
        if ((flags & required) != required)
        {
            return QStringLiteral("未知");
        }
        return QString::number(value, radix);
    }

    // 将共享结果枚举转换为可翻译源文本；未知结果保留未知，不按 API 名称推断成功。
    QString OutcomeText(Ksword::Evidence::ApiInjectionOutcome outcome)
    {
        using Outcome = Ksword::Evidence::ApiInjectionOutcome;
        switch (outcome)
        {
        case Outcome::Succeeded:
            return QStringLiteral("成功");
        case Outcome::Failed:
            return QStringLiteral("失败");
        case Outcome::Partial:
            return QStringLiteral("部分成功");
        default:
            return QStringLiteral("未知");
        }
    }
}

    // 只投影当前行的版本化源字段；缺有效位的值不显示零，原始输入句柄不授予对象操作资格。
    void AppendApiTransferFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue)
    {
        if (!clue.apiTransfer)
        {
            return;
        }
        const auto& fields = *clue.apiTransfer; // 当前原包中已完成格式核验的字段。
        using namespace Ksword::Evidence;
        document.section(QStringLiteral("API 转移参数"))
            .field(QStringLiteral("调用结果"), OutcomeText(clue.apiTransferOutcome), true)
            .field(QStringLiteral("API 输入句柄"), QString::number(fields.inputHandle, 16))
            .field(QStringLiteral("调用进入 QPC"), QString::number(fields.enterQpc))
            .field(QStringLiteral("调用返回 QPC"), QString::number(fields.returnQpc));

        // 身份来自同次调用窗口的查询，单独显示前后是否稳定，不替代采样的规范对象引用。
        if (fields.flags & ApiInjectionActorIdentity)
        {
            document.field(QStringLiteral("源进程创建 FILETIME"), QString::number(fields.actorCreationFileTime));
        }
        if (fields.flags & ApiInjectionTargetIdentity)
        {
            document.field(QStringLiteral("API 目标 PID"), QString::number(fields.targetPid))
                .field(QStringLiteral("目标进程创建 FILETIME"), QString::number(fields.targetCreationFileTime))
                .field(QStringLiteral("目标身份前后稳定"),
                    fields.flags & ApiInjectionTargetStable ? QStringLiteral("是") : QStringLiteral("否"), true);
        }
        if (fields.flags & ApiInjectionThreadIdentity)
        {
            document.field(QStringLiteral("API 返回线程 TID"), QString::number(fields.targetTid))
                .field(QStringLiteral("返回线程创建 FILETIME"), QString::number(fields.targetThreadCreationFileTime));
        }

        // 写入请求与实际完成量分别保留；线程入口是请求值，不能作为已经执行的结论。
        if (fields.operation == ApiInjectionOperation::MemoryWrite)
        {
            document.field(QStringLiteral("请求写入字节数"), QString::number(fields.requestedBytes));
        }
        if (fields.flags & ApiInjectionAddress)
        {
            document.field(QStringLiteral("API 写入起始地址"), QString::number(fields.address, 16));
        }
        if (fields.flags & ApiInjectionCompletedLength)
        {
            document.field(QStringLiteral("实际完成写入字节数"), QString::number(fields.completedBytes));
        }
        if (fields.flags & ApiInjectionStartAddress)
        {
            document.field(QStringLiteral("请求线程入口地址"), QString::number(fields.startAddress, 16));
        }
        document.note(QStringLiteral("字段来自本次 API 调用；请求线程入口不代表实际执行。"));
    }

    // 输入为归档行已解码的 AAAP1，输出共享字段文档；不创建对象或控制资格。
    void AppendApiApcFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue)
    {
        if (!clue.apiApc)
        {
            return;
        }
        const auto& fields = *clue.apiApc; // AAAP1字段值均来自同一完整原包，旧档扩展字段为零。
        using namespace Ksword::Evidence;
        const auto outcome = clue.apcOutcome == ApiApcQueueOutcome::Accepted ? QStringLiteral("接受入队")
            : clue.apcOutcome == ApiApcQueueOutcome::Failed ? QStringLiteral("失败") : QStringLiteral("未知"); // 只说明返回语义。
        document.section(QStringLiteral("APC 入队参数"))
            .field(QStringLiteral("APC 入队结果"), outcome, true)
            .field(QStringLiteral("APC 操作类型"), QString::number(static_cast<std::uint64_t>(fields.operation)))
            .field(QStringLiteral("APC 字段有效位"), QString::number(fields.flags, 16))
            .field(QStringLiteral("API 输入线程句柄"), QString::number(fields.inputThreadHandle, 16))
            .field(QStringLiteral("调用进入 QPC"), QString::number(fields.enterQpc))
            .field(QStringLiteral("调用返回 QPC"), QString::number(fields.returnQpc));

        // 缺有效位的身份显示未知；合法零请求地址和参数仍按原值展示。
        const auto identity = [&](std::uint64_t flag, std::uint64_t value) {
            return fields.flags & flag ? QString::number(value) : QStringLiteral("未知");
        }; // 输入有效位及原值，输出规范字段值；未知值由共享文档本地化。
        document.field(QStringLiteral("源进程创建 FILETIME"), identity(ApiApcActorIdentity, fields.actorCreationFileTime), true)
            .field(QStringLiteral("API 目标 PID"), identity(ApiApcTargetIdentity, fields.targetPid), true)
            .field(QStringLiteral("目标进程创建 FILETIME"), identity(ApiApcTargetIdentity, fields.targetCreationFileTime), true)
            .field(QStringLiteral("APC 目标线程 TID"), identity(ApiApcThreadIdentity, fields.targetTid), true)
            .field(QStringLiteral("目标线程创建 FILETIME"), identity(ApiApcThreadIdentity, fields.targetThreadCreationFileTime), true)
            .field(QStringLiteral("请求 APC 例程地址"), fields.flags & ApiApcRoutineAddress
                ? QString::number(fields.routineAddress, 16) : QStringLiteral("未知"), true)
            .field(QStringLiteral("目标身份前后稳定"), fields.flags & ApiApcTargetStable
                ? QStringLiteral("是") : QStringLiteral("否"), true);

        // QueueUserAPC 只有 data；NT 的额外参数不凭协议中的保留零伪造成 Win32 参数。
        const bool native = clue.api == QLatin1String("NtQueueApcThread") ||
            clue.api == QLatin1String("NtQueueApcThreadEx") ||
            clue.api == QLatin1String("NtQueueApcThreadEx2"); // 原生入口都有参数2/3。
        document.field(QStringLiteral("APC 参数 1"), QString::number(fields.argument1, 16));
        if (clue.api == QLatin1String("QueueUserAPC2") || clue.api == QLatin1String("NtQueueApcThreadEx2"))
        {
            // 有效位区分原始零flags与旧Agent未采集；不从接受入队推断投递方式已生效。
            document.field(QStringLiteral("APC 调度标志"), identity(ApiApcQueueFlags, fields.queueFlags), true);
        }
        if (clue.api == QLatin1String("NtQueueApcThreadEx") || clue.api == QLatin1String("NtQueueApcThreadEx2"))
        {
            document.field(QStringLiteral("APC Reserve 句柄"), QString::number(fields.reserveHandle, 16), true);
        }
        document
            .field(QStringLiteral("APC 参数 2"), native ? QString::number(fields.argument2, 16) : QStringLiteral("不适用"), true)
            .field(QStringLiteral("APC 参数 3"), native ? QString::number(fields.argument3, 16) : QStringLiteral("不适用"), true)
            .note(QStringLiteral("接受入队不证明 APC 已投递或执行；请求例程地址不是实际执行地址。"));
    }

    // 调用方传入唯一文档 document 和已核验行 clue；追加十五个 AACT1 字段及结果，无返回值。
    void AppendApiContextFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue)
    {
        if (!clue.apiContext)
        {
            return;
        }
        const auto& fields = *clue.apiContext; // 同一原包中的请求参数，不是线程当前寄存器。
        using namespace Ksword::Evidence;
        const auto outcome = clue.contextOutcome == ApiContextOutcome::Accepted ? QStringLiteral("接受请求")
            : clue.contextOutcome == ApiContextOutcome::Failed ? QStringLiteral("失败") : QStringLiteral("未知"); // 仅原 API 返回。

        // 句柄和 CONTEXT 指针仅作为原输入显示，不解引用、不注册对象角色。
        document.section(QStringLiteral("线程上下文请求参数"))
            .field(QStringLiteral("上下文请求结果"), outcome, true)
            .field(QStringLiteral("上下文操作类型"), QString::number(static_cast<std::uint64_t>(fields.operation)))
            .field(QStringLiteral("上下文字段有效位"), QString::number(fields.flags, 16))
            .field(QStringLiteral("API 输入线程句柄"), QString::number(fields.inputThreadHandle, 16))
            .field(QStringLiteral("输入 CONTEXT 地址"), QString::number(fields.inputContextAddress, 16))
            .field(QStringLiteral("调用进入 QPC"), QString::number(fields.enterQpc))
            .field(QStringLiteral("调用返回 QPC"), QString::number(fields.returnQpc));

        // 身份缺位即未知；稳定标记只有在进程和线程身份均存在时才解释。
        const bool identitiesKnown = (fields.flags & (ApiContextTargetIdentity | ApiContextThreadIdentity)) ==
            (ApiContextTargetIdentity | ApiContextThreadIdentity); // 是否具备稳定性复核的完整身份。
        const auto stable = !identitiesKnown ? QStringLiteral("未知") : fields.flags & ApiContextTargetStable
            ? QStringLiteral("是") : QStringLiteral("否"); // 前后复核状态，不是长期身份保证。
        document.field(QStringLiteral("源进程创建 FILETIME"), OptionalApiValue(fields.flags, ApiContextActorIdentity, fields.actorCreationFileTime), true)
            .field(QStringLiteral("API 目标 PID"), OptionalApiValue(fields.flags, ApiContextTargetIdentity, fields.targetPid), true)
            .field(QStringLiteral("目标进程创建 FILETIME"), OptionalApiValue(fields.flags, ApiContextTargetIdentity, fields.targetCreationFileTime), true)
            .field(QStringLiteral("上下文目标线程 TID"), OptionalApiValue(fields.flags, ApiContextThreadIdentity, fields.targetTid), true)
            .field(QStringLiteral("目标线程创建 FILETIME"), OptionalApiValue(fields.flags, ApiContextThreadIdentity, fields.targetThreadCreationFileTime), true)
            .field(QStringLiteral("目标身份前后稳定"), stable, true);

        // ABI 是源端固定的请求布局；Flags 和控制寄存器分别按自己的有效位显示。
        document.field(QStringLiteral("请求 CONTEXT ABI（位）"), QString::number(fields.contextArchitecture))
            .field(QStringLiteral("请求 ContextFlags"), OptionalApiValue(fields.flags, ApiContextFlags, fields.contextFlags, 16), true)
            .field(QStringLiteral("请求指令指针 IP"), OptionalApiValue(fields.flags, ApiContextControlRegisters, fields.requestedIp, 16), true)
            .field(QStringLiteral("请求栈指针 SP"), OptionalApiValue(fields.flags, ApiContextControlRegisters, fields.requestedSp, 16), true)
            .field(QStringLiteral("上下文已生效"), QStringLiteral("未知"), true)
            .field(QStringLiteral("上下文请求后的执行"), QStringLiteral("未知"), true)
            .note(QStringLiteral("IP、SP、ContextFlags 和 ABI 仅描述请求；接受请求不证明上下文已生效或发生执行。输入句柄和 CONTEXT 地址不授予对象身份。"));
    }

    // 调用方传入唯一文档 document 和已核验行 clue；追加十五个 AASM1 字段及结果，无返回值。
    void AppendApiSectionMapFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue)
    {
        if (!clue.apiSectionMap)
        {
            return;
        }
        const auto& fields = *clue.apiSectionMap; // 单次映射调用的原始请求和返回值。
        using namespace Ksword::Evidence;
        const auto outcome = clue.sectionMapOutcome == ApiSectionMapOutcome::Accepted ? QStringLiteral("接受请求")
            : clue.sectionMapOutcome == ApiSectionMapOutcome::Failed ? QStringLiteral("失败") : QStringLiteral("未知"); // 不表示内容已写入。

        // 原节句柄与进程句柄保留位模式，但不成为节对象、别名或可控制目标。
        document.section(QStringLiteral("节映射参数"))
            .field(QStringLiteral("节映射调用结果"), outcome, true)
            .field(QStringLiteral("节映射操作类型"), QString::number(static_cast<std::uint64_t>(fields.operation)))
            .field(QStringLiteral("节映射字段有效位"), QString::number(fields.flags, 16))
            .field(QStringLiteral("API 输入节句柄"), QString::number(fields.inputSectionHandle, 16))
            .field(QStringLiteral("API 输入进程句柄"), QString::number(fields.inputProcessHandle, 16))
            .field(QStringLiteral("调用进入 QPC"), QString::number(fields.enterQpc))
            .field(QStringLiteral("调用返回 QPC"), QString::number(fields.returnQpc));

        // 目标身份与调用返回独立；缺少身份有效位时不能把零显示成已知身份。
        const auto stable = !(fields.flags & ApiSectionMapTargetIdentity) ? QStringLiteral("未知")
            : fields.flags & ApiSectionMapTargetStable ? QStringLiteral("是") : QStringLiteral("否"); // 已知身份的前后复核状态。
        document.field(QStringLiteral("源进程创建 FILETIME"), OptionalApiValue(fields.flags, ApiSectionMapActorIdentity, fields.actorCreationFileTime), true)
            .field(QStringLiteral("API 目标 PID"), OptionalApiValue(fields.flags, ApiSectionMapTargetIdentity, fields.targetPid), true)
            .field(QStringLiteral("目标进程创建 FILETIME"), OptionalApiValue(fields.flags, ApiSectionMapTargetIdentity, fields.targetCreationFileTime), true)
            .field(QStringLiteral("目标身份前后稳定"), stable, true);

        // 请求和实际返回范围分别保留，缺输出位不回填请求值；偏移始终是输入位模式。
        document.field(QStringLiteral("请求映射基址"), OptionalApiValue(fields.flags, ApiSectionMapRequestedBase, fields.requestedBase, 16), true)
            .field(QStringLiteral("请求映射字节数"), OptionalApiValue(fields.flags, ApiSectionMapRequestedBytes, fields.requestedBytes), true)
            .field(QStringLiteral("实际映射基址（返回）"), OptionalApiValue(fields.flags, ApiSectionMapMappedBase, fields.mappedBase, 16), true)
            .field(QStringLiteral("实际映射字节数（返回）"), OptionalApiValue(fields.flags, ApiSectionMapMappedBytes, fields.mappedBytes), true)
            .field(QStringLiteral("节内偏移（原输入位模式）"), OptionalApiValue(fields.flags, ApiSectionMapSectionOffset, fields.sectionOffset, 16), true)
            .field(QStringLiteral("请求映射保护"), QString::number(fields.requestedProtection, 16))
            .note(QStringLiteral("节内偏移为原输入，不是系统调整后的输出；输入节句柄不代表节对象或别名身份，输入进程句柄不授予目标身份。映射返回不证明内容写入、别名传播、归因或执行。"));
    }

    // AAIM1只追加到现有详情规范源，不改变布局、对象菜单、设断或跟随策略。
    void AppendApiMemoryLifecycleFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue)
    {
        if (!clue.apiMemoryLifecycle)
        {
            return;
        }
        using namespace Ksword::Evidence;
        const auto& f = *clue.apiMemoryLifecycle; // 同一完整原包的字段和独立有效位。
        const auto eventType = ApiMemoryLifecycleEventType(f); // 稳定机器类型，不提升成执行证据。
        const bool unmap = f.operation == ApiMemoryOperation::Unmap; // 解除映射只有原输入基址，没有字节范围或保护输入输出。
        const auto kind = f.operation == ApiMemoryOperation::Allocate ? QStringLiteral("分配") :
            f.operation == ApiMemoryOperation::Protect ? QStringLiteral("保护变更") :
            f.operation == ApiMemoryOperation::Free ? QStringLiteral("释放请求") :
            unmap ? QStringLiteral("解除映射请求") : QStringLiteral("未知"); // 原API种类，不把新操作默认归为Free。
        document.section(QStringLiteral("API 内存生命周期"))
            .field(QStringLiteral("内存操作类型"), kind, true)
            .field(QStringLiteral("生命周期事件类型"), QString::fromLatin1(eventType.data(), eventType.size()))
            .field(QStringLiteral("内存字段有效位"), QString::number(f.flags, 16))
            .field(QStringLiteral("源调用 ABI（位）"), QString::number(f.pointerBits))
            .field(QStringLiteral("来源会话 ID"), QString::number(clue.memorySourceSession))
            .field(QStringLiteral("API 输入进程句柄"), QString::number(f.inputProcessHandle, 16));

        // 身份只用原查询有效位；当前进程和远程进程均按同一强实例链显示。
        const auto stable = !(f.flags & ApiMemoryTargetIdentity) ? QStringLiteral("未知") :
            f.flags & ApiMemoryTargetStable ? QStringLiteral("是") : QStringLiteral("否"); // 调用前后复核状态。
        document.field(QStringLiteral("源进程创建 FILETIME"), OptionalApiValue(f.flags, ApiMemoryActorIdentity, f.actorCreationFileTime), true)
            .field(QStringLiteral("API 目标 PID"), OptionalApiValue(f.flags, ApiMemoryTargetIdentity, f.targetPid), true)
            .field(QStringLiteral("目标进程创建 FILETIME"), OptionalApiValue(f.flags, ApiMemoryTargetIdentity, f.targetCreationFileTime), true)
            .field(QStringLiteral("目标身份前后稳定"), stable, true)
            .field(unmap ? QStringLiteral("解除映射输入基址") : QStringLiteral("请求内存基址"),
                OptionalApiValue(f.flags, ApiMemoryRequestedBase, f.requestedBase, 16), true);
        if (!unmap)
        {
            // NtUnmapViewOfSection没有长度参数或输出范围，不能把保留零展示成解除映射字节数。
            document.field(QStringLiteral("请求内存字节数"), OptionalApiValue(f.flags, ApiMemoryRequestedBytes, f.requestedBytes), true)
                .field(QStringLiteral("实际输出内存基址"), OptionalApiValue(f.flags, ApiMemoryOutputBase, f.outputBase, 16), true)
                .field(QStringLiteral("实际输出内存字节数"), OptionalApiValue(f.flags, ApiMemoryOutputBytes, f.outputBytes), true);
        }

        // 操作专属参数不借零值伪造成其它API输入；oldProtection有效性与值分列。
        if (f.operation == ApiMemoryOperation::Allocate)
        {
            document.field(QStringLiteral("分配类型 AllocationType"), QString::number(f.allocationType, 16));
        }
        if (f.operation == ApiMemoryOperation::Allocate || f.operation == ApiMemoryOperation::Protect)
        {
            document.field(QStringLiteral("请求内存保护"), QString::number(f.newProtection, 16));
        }
        else if (f.operation == ApiMemoryOperation::Free)
        {
            document.field(QStringLiteral("释放类型 FreeType"), QString::number(f.freeType, 16));
        }
        if (!unmap)
        {
            document.field(QStringLiteral("旧保护有效"), f.flags & ApiMemoryOldProtection ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("原内存保护"), OptionalApiValue(f.flags, ApiMemoryOldProtection, f.oldProtection, 16), true);
        }
        // Unmap与其它操作共用原返回文档；成功状态也不补造已解除映射的实际范围。
        document.field(QStringLiteral("原返回有效"), f.returnValid ? QStringLiteral("是") : QStringLiteral("否"), true)
            .field(QStringLiteral("原 NTSTATUS"), QString::number(static_cast<std::uint32_t>(f.status), 16))
            .field(QStringLiteral("调用进入 QPC"), f.enterQpc ? QString::number(f.enterQpc) : QStringLiteral("未知"), true)
            .field(QStringLiteral("调用返回 QPC"), f.returnQpc ? QString::number(f.returnQpc) : QStringLiteral("未知"), true)
            .field(QStringLiteral("分配代次"), QStringLiteral("未知"), true)
            .field(unmap ? QStringLiteral("实际解除映射范围") : QStringLiteral("实际释放范围"), QStringLiteral("未知"), true)
            .note(unmap ? QStringLiteral("解除映射仅记录原输入基址及返回；实际解除映射范围、分配代次、后续执行与因果未知，不提供私有 NX 范围草稿。") :
                QStringLiteral("内存生命周期仅记录原请求及返回；释放全区、分配代次、后续执行与因果未知。"));
    }

    // 输入 document 为原文档、candidates 为累计数、latest 为可空最近 APC 回执；追加正文，无返回值。
    void AppendApiApcProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        const Ksword::ActionAnalyze::Detection::ApiApcTransferLink* latest)
    {
        document.section(QStringLiteral("APC 转移候选"))
            .field(QStringLiteral("累计候选数"), QString::number(candidates));
        if (latest)
        {
            // 输入 evidence 为回执原坐标，输出定位文本；不从当前选择或活动段补造坐标。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence)
            {
                if (!evidence.raw)
                {
                    return QStringLiteral("未知");
                }
                return QStringLiteral("raw/%1 #%2").arg(evidence.raw->segmentOrdinal).arg(evidence.raw->sequence);
            };
            document.field(QStringLiteral("写入原包"), coordinate(latest->write), true)
                .field(QStringLiteral("APC 入队原包"), coordinate(latest->queue), true)
                .field(QStringLiteral("来源 PID"), QString::number(latest->actorPid))
                .field(QStringLiteral("源进程创建 FILETIME"), QString::number(latest->actorCreationFileTime))
                .field(QStringLiteral("API 目标 PID"), QString::number(latest->targetPid))
                .field(QStringLiteral("目标进程创建 FILETIME"), QString::number(latest->targetCreationFileTime));

            // 线程、写入范围和例程均来自同一不可变候选，不触发现场查询或提升角色。
            document.field(QStringLiteral("APC 目标线程 TID"), QString::number(latest->targetTid))
                .field(QStringLiteral("目标线程创建 FILETIME"), QString::number(latest->targetThreadCreationFileTime))
                .field(QStringLiteral("API 写入起始地址"), QString::number(latest->writtenAddress, 16))
                .field(QStringLiteral("实际完成写入字节数"), QString::number(latest->writtenBytes))
                .field(QStringLiteral("请求 APC 例程地址"), QString::number(latest->requestedRoutineAddress, 16));
        }
        document.note(QStringLiteral("接受入队不证明 APC 已投递或执行；请求例程地址不是实际执行地址。"));
    }

    // document 为唯一正文，candidates 为累计数，latest 为可空最近回执；仅投影请求，无返回值。
    void AppendApiContextProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        const Ksword::ActionAnalyze::Detection::ApiContextTransferLink* latest)
    {
        document.section(QStringLiteral("上下文转移候选"))
            .field(QStringLiteral("累计候选数"), QString::number(candidates));
        if (latest)
        {
            // 输入 evidence 为原回执坐标，返回定位文本；不从当前活动段推断缺失坐标。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence)
            {
                if (!evidence.raw)
                {
                    return QStringLiteral("未知");
                }
                return QStringLiteral("raw/%1 #%2").arg(evidence.raw->segmentOrdinal).arg(evidence.raw->sequence);
            };
            document.field(QStringLiteral("写入原包"), coordinate(latest->write), true)
                .field(QStringLiteral("上下文请求原包"), coordinate(latest->context), true)
                .field(QStringLiteral("来源 PID"), QString::number(latest->actorPid))
                .field(QStringLiteral("源进程创建 FILETIME"), QString::number(latest->actorCreationFileTime))
                .field(QStringLiteral("API 目标 PID"), QString::number(latest->targetPid))
                .field(QStringLiteral("目标进程创建 FILETIME"), QString::number(latest->targetCreationFileTime));

            // 请求 IP/SP/ABI 保持请求语义，不能据此设置 contextApplied 或升级强图角色。
            document.field(QStringLiteral("上下文目标线程 TID"), QString::number(latest->targetTid))
                .field(QStringLiteral("目标线程创建 FILETIME"), QString::number(latest->targetThreadCreationFileTime))
                .field(QStringLiteral("API 写入起始地址"), QString::number(latest->writtenAddress, 16))
                .field(QStringLiteral("实际完成写入字节数"), QString::number(latest->writtenBytes))
                .field(QStringLiteral("请求指令指针 IP"), QString::number(latest->requestedIp, 16))
                .field(QStringLiteral("请求栈指针 SP"), QString::number(latest->requestedSp, 16))
                .field(QStringLiteral("请求 CONTEXT ABI（位）"), QString::number(latest->contextArchitecture));
        }
        document.field(QStringLiteral("上下文已生效"), QStringLiteral("未知"), true)
            .field(QStringLiteral("上下文请求后的执行"), QStringLiteral("未知"), true)
            .note(QStringLiteral("IP、SP、ContextFlags 和 ABI 仅描述请求；接受请求不证明上下文已生效或发生执行。输入句柄和 CONTEXT 地址不授予对象身份。"));
    }

    // 活采工作线程已完成串链，UI 仅从不可变回执格式化最后一对同采样原包。
    void AppendApiTransferProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        std::uint64_t evictedWrites, const Ksword::ActionAnalyze::Detection::ApiTransferLink* latest)
    {
        document.section(QStringLiteral("API 转移候选"))
            .field(QStringLiteral("累计候选数"), QString::number(candidates))
            .field(QStringLiteral("已淘汰写入数"), QString::number(evictedWrites));
        if (latest)
        {
            // 双方定位始终来自最近候选，不使用当前列表选择或当前活动段替换。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence)
            {
                return QStringLiteral("raw/%1 #%2").arg(evidence.raw->segmentOrdinal).arg(evidence.raw->sequence);
            };
            document.field(QStringLiteral("写入原包"), coordinate(latest->write))
                .field(QStringLiteral("线程创建原包"), coordinate(latest->threadCreate))
                .field(QStringLiteral("来源 PID"), QString::number(latest->actorPid))
                .field(QStringLiteral("源进程创建 FILETIME"), QString::number(latest->actorCreationFileTime))
                .field(QStringLiteral("API 目标 PID"), QString::number(latest->targetPid))
                .field(QStringLiteral("目标进程创建 FILETIME"), QString::number(latest->targetCreationFileTime))
                .field(QStringLiteral("API 写入起始地址"), QString::number(latest->writtenAddress, 16))
                .field(QStringLiteral("实际完成写入字节数"), QString::number(latest->writtenBytes))
                .field(QStringLiteral("请求线程入口地址"), QString::number(latest->requestedStartAddress, 16));
        }
        document.note(QStringLiteral("候选仅关联实际写入与后续创建请求，不证明实际执行。"));
    }
}
