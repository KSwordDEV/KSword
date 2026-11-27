#include "ApiTransferPresentation.h"
#include "StoredEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/CooperativeApiCapture.h"
#include "../../../shared/evidence/ApiHandoffReceiptView.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"

namespace Ksword::Features::ActionAnalyze
{
    // 输入本轮接管回执，输出同一详情正文的字段分组；原JSON仍保留，不以摘要替代取证原文。
    std::wstring ApiHandoffDetails(const Ksword::Evidence::JsonValue& receipt)
    {
        std::wstring text; // 由原生详情宿主统一提供搜索、复制及导出。
        if (receipt.type() == Ksword::Evidence::JsonType::Null)
        {
            return {};
        }
        const auto groups = Ksword::Evidence::BuildHandoffReceiptView(receipt); // 与Qt使用同一字段定义和缺值规则。
        if (groups.empty())
        {
            return L"\r\n\r\n自动接管\r\n接管回执状态：接管回执格式不可用";
        }
        for (const auto& group : groups)
        {
            text += L"\r\n\r\n";
            text += group.name;
            for (const auto& field : group.fields)
            {
                text += L"\r\n";
                text += field.name;
                text += L"：";
                text += ks::r3::process::Utf8ToWide(field.value);
            }
        }
        return text;
    }

namespace
{
    // 调用时传入 text 输出正文、label 字段名、value 原数值和 known 有效性；原位追加，无返回值。
    void AppendApiNumber(std::wstring& text, const wchar_t* label, std::uint64_t value, bool known = true)
    {
        // 缺位不显示协议保留零；有效的零地址、长度、偏移和寄存器值仍然保留。
        text += L"\r\n";
        text += label;
        text += L"：";
        text += known ? std::to_wstring(value) : L"未知";
    }
}

    // 输入为已核验原包的行快照，输出供现有详情文本外壳读取，不查询现场或创建对象句柄。
    std::wstring ApiTransferDetails(const EvidenceRecord& record)
    {
        if (record.apiMemoryLifecycle)
        {
            // 不新建详情宿主；本分支使用同一行源值供搜索、复制和导出。
            const auto& f = *record.apiMemoryLifecycle; // AAIM1核验通过的不可变字段。
            using namespace Ksword::Evidence;
            const auto eventType = ApiMemoryLifecycleEventType(f); // 稳定事件类型，不作跨事件归因。
            const bool unmap = f.operation == ApiMemoryOperation::Unmap; // 解除映射只有原输入基址和返回状态，不含长度或保护。
            std::wstring text = L"API 内存生命周期\r\n内存操作类型："; // 复用现有详情正文。
            text += f.operation == ApiMemoryOperation::Allocate ? L"分配" :
                f.operation == ApiMemoryOperation::Protect ? L"保护变更" :
                f.operation == ApiMemoryOperation::Free ? L"释放请求" : unmap ? L"解除映射请求" : L"未知";
            text += L"\r\n生命周期事件类型：" + std::wstring(eventType.begin(), eventType.end());
            AppendApiNumber(text, L"内存字段有效位", f.flags);
            AppendApiNumber(text, L"源调用 ABI（位）", f.pointerBits);
            AppendApiNumber(text, L"来源会话 ID", record.memorySourceSession);
            AppendApiNumber(text, L"API 输入进程句柄", f.inputProcessHandle);

            // 身份缺位保留未知；远程和当前进程不从包头PID互相回填。
            AppendApiNumber(text, L"源进程创建 FILETIME", f.actorCreationFileTime, (f.flags & ApiMemoryActorIdentity) != 0);
            AppendApiNumber(text, L"API 目标 PID", f.targetPid, (f.flags & ApiMemoryTargetIdentity) != 0);
            AppendApiNumber(text, L"目标进程创建 FILETIME", f.targetCreationFileTime, (f.flags & ApiMemoryTargetIdentity) != 0);
            text += L"\r\n目标身份前后稳定：";
            text += !(f.flags & ApiMemoryTargetIdentity) ? L"未知" : f.flags & ApiMemoryTargetStable ? L"是" : L"否";
            AppendApiNumber(text, unmap ? L"解除映射输入基址" : L"请求内存基址", f.requestedBase, (f.flags & ApiMemoryRequestedBase) != 0);
            if (!unmap)
            {
                // Unmap没有长度参数或输出范围，保留零不构成已解除映射的字节范围。
                AppendApiNumber(text, L"请求内存字节数", f.requestedBytes, (f.flags & ApiMemoryRequestedBytes) != 0);
                AppendApiNumber(text, L"实际输出内存基址", f.outputBase, (f.flags & ApiMemoryOutputBase) != 0);
                AppendApiNumber(text, L"实际输出内存字节数", f.outputBytes, (f.flags & ApiMemoryOutputBytes) != 0);
            }

            // 各操作只显示自身参数；Unmap既不是Free，也没有新保护或旧保护输出。
            if (f.operation == ApiMemoryOperation::Allocate)
            {
                AppendApiNumber(text, L"分配类型 AllocationType", f.allocationType);
            }
            if (f.operation == ApiMemoryOperation::Allocate || f.operation == ApiMemoryOperation::Protect)
            {
                AppendApiNumber(text, L"请求内存保护", f.newProtection);
            }
            else if (f.operation == ApiMemoryOperation::Free)
            {
                AppendApiNumber(text, L"释放类型 FreeType", f.freeType);
            }
            if (!unmap)
            {
                text += f.flags & ApiMemoryOldProtection ? L"\r\n旧保护有效：是" : L"\r\n旧保护有效：否";
                AppendApiNumber(text, L"原内存保护", f.oldProtection, (f.flags & ApiMemoryOldProtection) != 0);
            }
            text += f.returnValid ? L"\r\n原返回有效：是" : L"\r\n原返回有效：否";
            text += L"\r\n原 NTSTATUS：" + std::to_wstring(f.status);
            AppendApiNumber(text, L"调用进入 QPC", f.enterQpc, f.enterQpc != 0);
            AppendApiNumber(text, L"调用返回 QPC", f.returnQpc, f.returnQpc != 0);
            if (unmap)
            {
                return text + L"\r\n分配代次：未知\r\n实际解除映射范围：未知\r\n"
                    L"解除映射仅记录原输入基址及返回；实际解除映射范围、分配代次、后续执行与因果未知，不提供私有 NX 范围草稿。\r\n";
            }
            return text + L"\r\n分配代次：未知\r\n实际释放范围：未知\r\n"
                L"内存生命周期仅记录原请求及返回；释放全区、分配代次、后续执行与因果未知。\r\n";
        }
        // 保留原详情唯一调用点，新增协议不创建第二份文本或控件。
        if (record.apiContext)
        {
            return ApiContextDetails(record);
        }
        if (record.apiSectionMap)
        {
            return ApiSectionMapDetails(record);
        }
        if (record.apiApc)
        {
            return ApiApcDetails(record); // 沿用全部既有归档详情调用点，不另建文本宿主。
        }
        if (!record.apiTransfer)
        {
            return {};
        }
        const auto& fields = *record.apiTransfer; // 同一行已核验的参数及有效位。
        using namespace Ksword::Evidence;
        const auto outcome = record.apiTransferOutcome; // 按 Win32/NT 返回约定解释的结果。
        std::wstring text = L"API 转移参数\r\n调用结果："; // 写入现有详情，不新建第二个文档模型。
        text += outcome == ApiInjectionOutcome::Succeeded ? L"成功" :
            outcome == ApiInjectionOutcome::Failed ? L"失败" :
            outcome == ApiInjectionOutcome::Partial ? L"部分成功" : L"未知";

        // 按有效位添加数值；有效的零值仍显示，未知字段不伪造为零。
        const auto append = [&](const wchar_t* label, std::uint64_t value)
        {
            text += L"\r\n";
            text += label;
            text += L"：" + std::to_wstring(value);
        };
        append(L"API 输入句柄", fields.inputHandle);
        append(L"调用进入 QPC", fields.enterQpc);
        append(L"调用返回 QPC", fields.returnQpc);
        if (fields.flags & ApiInjectionActorIdentity)
        {
            append(L"源进程创建 FILETIME", fields.actorCreationFileTime);
        }
        if (fields.flags & ApiInjectionTargetIdentity)
        {
            append(L"API 目标 PID", fields.targetPid);
            append(L"目标进程创建 FILETIME", fields.targetCreationFileTime);
            text += fields.flags & ApiInjectionTargetStable ? L"\r\n目标身份前后稳定：是" : L"\r\n目标身份前后稳定：否";
        }
        if (fields.flags & ApiInjectionThreadIdentity)
        {
            append(L"API 返回线程 TID", fields.targetTid);
            append(L"返回线程创建 FILETIME", fields.targetThreadCreationFileTime);
        }

        // 请求范围、实际字节与线程请求入口分列，避免把成功创建请求显示成执行证明。
        if (fields.operation == ApiInjectionOperation::MemoryWrite)
        {
            append(L"请求写入字节数", fields.requestedBytes);
        }
        if (fields.flags & ApiInjectionAddress)
        {
            append(L"API 写入起始地址", fields.address);
        }
        if (fields.flags & ApiInjectionCompletedLength)
        {
            append(L"实际完成写入字节数", fields.completedBytes);
        }
        if (fields.flags & ApiInjectionStartAddress)
        {
            append(L"请求线程入口地址", fields.startAddress);
        }
        return text + L"\r\n字段来自本次 API 调用；请求线程入口不代表实际执行。\r\n";
    }

    // 输入已解码 AAAP1 行，输出原生只读文本；旧档案的 Reserve 字段保持零值。
    std::wstring ApiApcDetails(const EvidenceRecord& record)
    {
        if (!record.apiApc)
        {
            return {};
        }
        const auto& fields = *record.apiApc; // 同一原包参数及有效位。
        using namespace Ksword::Evidence;
        std::wstring text = L"APC 入队参数\r\nAPC 入队结果："; // 与原列表详情合并的唯一文本。
        text += record.apcOutcome == ApiApcQueueOutcome::Accepted ? L"接受入队" :
            record.apcOutcome == ApiApcQueueOutcome::Failed ? L"失败" : L"未知";
        const auto append = [&](const wchar_t* label, std::uint64_t value) {
            text += L"\r\n" + std::wstring(label) + L"：" + std::to_wstring(value);
        }; // 输入字段名及原数值，追加到同一文本，无返回值。
        append(L"APC 操作类型", static_cast<std::uint64_t>(fields.operation));
        append(L"APC 字段有效位", fields.flags);
        append(L"API 输入线程句柄", fields.inputThreadHandle);
        if (record.apiClue == L"NtQueueApcThreadEx" || record.apiClue == L"NtQueueApcThreadEx2")
        {
            append(L"APC Reserve 句柄", fields.reserveHandle);
        }
        append(L"调用进入 QPC", fields.enterQpc);
        append(L"调用返回 QPC", fields.returnQpc);

        // 缺有效位时保留未知，原输入句柄不独立作为目标身份。
        const auto identity = [&](const wchar_t* label, std::uint64_t flag, std::uint64_t value) {
            text += L"\r\n" + std::wstring(label) + L"：";
            text += fields.flags & flag ? std::to_wstring(value) : L"未知";
        }; // 输入有效位与原值，追加身份或请求值，不授予对象角色。
        identity(L"源进程创建 FILETIME", ApiApcActorIdentity, fields.actorCreationFileTime);
        identity(L"API 目标 PID", ApiApcTargetIdentity, fields.targetPid);
        identity(L"目标进程创建 FILETIME", ApiApcTargetIdentity, fields.targetCreationFileTime);
        identity(L"APC 目标线程 TID", ApiApcThreadIdentity, fields.targetTid);
        identity(L"目标线程创建 FILETIME", ApiApcThreadIdentity, fields.targetThreadCreationFileTime);
        identity(L"请求 APC 例程地址", ApiApcRoutineAddress, fields.routineAddress);
        if (record.apiClue == L"QueueUserAPC2" || record.apiClue == L"NtQueueApcThreadEx2")
        {
            identity(L"APC 调度标志", ApiApcQueueFlags, fields.queueFlags); // 旧包缺有效位显示未知，零仍可知。
        }
        text += fields.flags & ApiApcTargetStable ? L"\r\n目标身份前后稳定：是" : L"\r\n目标身份前后稳定：否";

        // Win32 没有第二、第三参数，不能把保留零显示成真实 API 输入。
        append(L"APC 参数 1", fields.argument1);
        if (record.apiClue == L"NtQueueApcThread" || record.apiClue == L"NtQueueApcThreadEx" ||
            record.apiClue == L"NtQueueApcThreadEx2")
        {
            append(L"APC 参数 2", fields.argument2);
            append(L"APC 参数 3", fields.argument3);
        }
        else
        {
            text += L"\r\nAPC 参数 2：不适用\r\nAPC 参数 3：不适用";
        }
        return text + L"\r\n接受入队不证明 APC 已投递或执行；请求例程地址不是实际执行地址。\r\n";
    }

    // 输入 record 为已核验行，返回 AACT1 十五字段与原返回文本，供 ApiTransferDetails 调用，无现场查询。
    std::wstring ApiContextDetails(const EvidenceRecord& record)
    {
        if (!record.apiContext)
        {
            return {};
        }
        const auto& fields = *record.apiContext; // 当前调用的请求参数，不是当前线程上下文。
        using namespace Ksword::Evidence;
        std::wstring text = L"线程上下文请求参数\r\n上下文请求结果："; // 追加到现有原包详情的唯一正文。
        text += record.contextOutcome == ApiContextOutcome::Accepted ? L"接受请求"
            : record.contextOutcome == ApiContextOutcome::Failed ? L"失败" : L"未知";

        // 原线程句柄与输入指针仅用于显示，不解引用或构造对象引用。
        AppendApiNumber(text, L"上下文操作类型", static_cast<std::uint64_t>(fields.operation));
        AppendApiNumber(text, L"上下文字段有效位", fields.flags);
        AppendApiNumber(text, L"API 输入线程句柄", fields.inputThreadHandle);
        AppendApiNumber(text, L"输入 CONTEXT 地址", fields.inputContextAddress);
        AppendApiNumber(text, L"调用进入 QPC", fields.enterQpc);
        AppendApiNumber(text, L"调用返回 QPC", fields.returnQpc);

        // 各身份只由自己的有效位决定，缺位不显示零或从报头反推目标。
        AppendApiNumber(text, L"源进程创建 FILETIME", fields.actorCreationFileTime, (fields.flags & ApiContextActorIdentity) != 0);
        AppendApiNumber(text, L"API 目标 PID", fields.targetPid, (fields.flags & ApiContextTargetIdentity) != 0);
        AppendApiNumber(text, L"目标进程创建 FILETIME", fields.targetCreationFileTime, (fields.flags & ApiContextTargetIdentity) != 0);
        AppendApiNumber(text, L"上下文目标线程 TID", fields.targetTid, (fields.flags & ApiContextThreadIdentity) != 0);
        AppendApiNumber(text, L"目标线程创建 FILETIME", fields.targetThreadCreationFileTime, (fields.flags & ApiContextThreadIdentity) != 0);
        const bool identitiesKnown = (fields.flags & (ApiContextTargetIdentity | ApiContextThreadIdentity)) ==
            (ApiContextTargetIdentity | ApiContextThreadIdentity); // 稳定性复核是否具备完整目标身份。
        text += L"\r\n目标身份前后稳定：";
        text += !identitiesKnown ? L"未知" : fields.flags & ApiContextTargetStable ? L"是" : L"否";

        // ABI 总是来自固定协议；Flags 与 IP/SP 有各自有效位，不能互相填补。
        AppendApiNumber(text, L"请求 CONTEXT ABI（位）", fields.contextArchitecture);
        AppendApiNumber(text, L"请求 ContextFlags", fields.contextFlags, (fields.flags & ApiContextFlags) != 0);
        AppendApiNumber(text, L"请求指令指针 IP", fields.requestedIp, (fields.flags & ApiContextControlRegisters) != 0);
        AppendApiNumber(text, L"请求栈指针 SP", fields.requestedSp, (fields.flags & ApiContextControlRegisters) != 0);
        // 原请求结果不是 contextApplied 或执行证据，这两个结论始终保持未知。
        text += L"\r\n上下文已生效：未知\r\n上下文请求后的执行：未知";
        return text + L"\r\nIP、SP、ContextFlags 和 ABI 仅描述请求；接受请求不证明上下文已生效或发生执行。输入句柄和 CONTEXT 地址不授予对象身份。\r\n";
    }

    // 输入 record 为已核验行，返回 AASM1 十五字段与原返回文本，供 ApiTransferDetails 调用，不建立别名关系。
    std::wstring ApiSectionMapDetails(const EvidenceRecord& record)
    {
        if (!record.apiSectionMap)
        {
            return {};
        }
        const auto& fields = *record.apiSectionMap; // 单次调用的原请求和实际返回字段。
        using namespace Ksword::Evidence;
        std::wstring text = L"节映射参数\r\n节映射调用结果："; // 复用原生详情宿主，不新建文档副本。
        text += record.sectionMapOutcome == ApiSectionMapOutcome::Accepted ? L"接受请求"
            : record.sectionMapOutcome == ApiSectionMapOutcome::Failed ? L"失败" : L"未知";

        // 两个输入句柄均为位模式，不能按数值相等认定节别名或目标身份。
        AppendApiNumber(text, L"节映射操作类型", static_cast<std::uint64_t>(fields.operation));
        AppendApiNumber(text, L"节映射字段有效位", fields.flags);
        AppendApiNumber(text, L"API 输入节句柄", fields.inputSectionHandle);
        AppendApiNumber(text, L"API 输入进程句柄", fields.inputProcessHandle);
        AppendApiNumber(text, L"调用进入 QPC", fields.enterQpc);
        AppendApiNumber(text, L"调用返回 QPC", fields.returnQpc);

        // 只显示协议中明确有效的身份，不能将缺位的稳定状态误报为否。
        AppendApiNumber(text, L"源进程创建 FILETIME", fields.actorCreationFileTime, (fields.flags & ApiSectionMapActorIdentity) != 0);
        AppendApiNumber(text, L"API 目标 PID", fields.targetPid, (fields.flags & ApiSectionMapTargetIdentity) != 0);
        AppendApiNumber(text, L"目标进程创建 FILETIME", fields.targetCreationFileTime, (fields.flags & ApiSectionMapTargetIdentity) != 0);
        text += L"\r\n目标身份前后稳定：";
        text += !(fields.flags & ApiSectionMapTargetIdentity) ? L"未知" : fields.flags & ApiSectionMapTargetStable ? L"是" : L"否";

        // 请求与输出分别按有效位显示；缺 mappedBase/Bytes 时不使用请求值代替。
        AppendApiNumber(text, L"请求映射基址", fields.requestedBase, (fields.flags & ApiSectionMapRequestedBase) != 0);
        AppendApiNumber(text, L"请求映射字节数", fields.requestedBytes, (fields.flags & ApiSectionMapRequestedBytes) != 0);
        AppendApiNumber(text, L"实际映射基址（返回）", fields.mappedBase, (fields.flags & ApiSectionMapMappedBase) != 0);
        AppendApiNumber(text, L"实际映射字节数（返回）", fields.mappedBytes, (fields.flags & ApiSectionMapMappedBytes) != 0);
        AppendApiNumber(text, L"节内偏移（原输入位模式）", fields.sectionOffset, (fields.flags & ApiSectionMapSectionOffset) != 0);
        AppendApiNumber(text, L"请求映射保护", fields.requestedProtection);
        return text + L"\r\n节内偏移为原输入，不是系统调整后的输出；输入节句柄不代表节对象或别名身份，输入进程句柄不授予目标身份。映射返回不证明内容写入、别名传播、归因或执行。\r\n";
    }

    // 复用现有原生详情文本，不在 UI 线程查询目标或重新扫描归档。
    std::wstring ApiTransferProgress(const Ksword::ActionAnalyze::CooperativeApiTransferReceipt& receipt)
    {
        std::wstring text = L"\r\nAPI 转移候选 · 累计候选数：" + std::to_wstring(receipt.candidateCount) +
            L" · 已淘汰写入数：" + std::to_wstring(receipt.evictedWrites);
        if (!receipt.recent.empty())
        {
            const auto& latest = receipt.recent.back(); // 同一已提交前缀最近形成的一对原始包。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence)
            {
                return L"raw/" + std::to_wstring(evidence.raw->segmentOrdinal) + L" #" +
                    std::to_wstring(evidence.raw->sequence);
            };
            text += L"\r\n写入原包：" + coordinate(latest.write) + L" · 线程创建原包：" + coordinate(latest.threadCreate);
            text += L"\r\n来源 PID：" + std::to_wstring(latest.actorPid) + L" / " +
                std::to_wstring(latest.actorCreationFileTime) + L" · API 目标 PID：" +
                std::to_wstring(latest.targetPid) + L" / " + std::to_wstring(latest.targetCreationFileTime);
            text += L"\r\nAPI 写入起始地址：" + std::to_wstring(latest.writtenAddress) +
                L" · 实际完成写入字节数：" + std::to_wstring(latest.writtenBytes) +
                L" · 请求线程入口地址：" + std::to_wstring(latest.requestedStartAddress);
        }
        text += L"\r\n候选仅关联实际写入与后续创建请求，不证明实际执行。";

        // 同一现有回执正文追加 APC 分组；数量和坐标不依赖当前列表选择或活动段。
        text += L"\r\nAPC 转移候选 · 累计候选数：" + std::to_wstring(receipt.apcCandidateCount);
        if (!receipt.recentApc.empty())
        {
            const auto& latest = receipt.recentApc.back(); // 同采样已提交前缀最近的 APC 来源候选。
            // 输入 evidence 为候选原坐标，返回原生定位文本，缺少坐标时保持未知。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence) -> std::wstring
            {
                if (!evidence.raw)
                {
                    return L"未知";
                }
                return L"raw/" + std::to_wstring(evidence.raw->segmentOrdinal) + L" #" +
                    std::to_wstring(evidence.raw->sequence);
            };
            text += L"\r\n写入原包：" + coordinate(latest.write);
            text += L" · APC 入队原包：" + coordinate(latest.queue);
            AppendApiNumber(text, L"来源 PID", latest.actorPid);
            AppendApiNumber(text, L"源进程创建 FILETIME", latest.actorCreationFileTime);
            AppendApiNumber(text, L"API 目标 PID", latest.targetPid);
            AppendApiNumber(text, L"目标进程创建 FILETIME", latest.targetCreationFileTime);

            // 完整显示原候选线程代次及范围，但不把请求例程视作实际执行地址。
            AppendApiNumber(text, L"APC 目标线程 TID", latest.targetTid);
            AppendApiNumber(text, L"目标线程创建 FILETIME", latest.targetThreadCreationFileTime);
            AppendApiNumber(text, L"API 写入起始地址", latest.writtenAddress);
            AppendApiNumber(text, L"实际完成写入字节数", latest.writtenBytes);
            AppendApiNumber(text, L"请求 APC 例程地址", latest.requestedRoutineAddress);
        }
        text += L"\r\n接受入队不证明 APC 已投递或执行；请求例程地址不是实际执行地址。";

        // 原 receipt 的独立上下文累计数和最近双方复用本次正文，不增加采集或轮询。
        text += L"\r\n上下文转移候选 · 累计候选数：" + std::to_wstring(receipt.contextCandidateCount);
        if (!receipt.recentContext.empty())
        {
            const auto& latest = receipt.recentContext.back(); // 同一已提交前缀最近的 write/context 原回执。
            // 输入 evidence 为原包坐标，返回原生定位文本，缺失时保持未知。
            const auto coordinate = [](const Ksword::ActionAnalyze::Detection::EvidenceRef& evidence) -> std::wstring
            {
                if (!evidence.raw)
                {
                    return L"未知";
                }
                return L"raw/" + std::to_wstring(evidence.raw->segmentOrdinal) + L" #" +
                    std::to_wstring(evidence.raw->sequence);
            };
            text += L"\r\n写入原包：" + coordinate(latest.write);
            text += L" · 上下文请求原包：" + coordinate(latest.context);
            AppendApiNumber(text, L"来源 PID", latest.actorPid);
            AppendApiNumber(text, L"源进程创建 FILETIME", latest.actorCreationFileTime);
            AppendApiNumber(text, L"API 目标 PID", latest.targetPid);
            AppendApiNumber(text, L"目标进程创建 FILETIME", latest.targetCreationFileTime);

            // 只投影请求寄存器和 ABI，既不查询线程也不表示已采用请求 IP。
            AppendApiNumber(text, L"上下文目标线程 TID", latest.targetTid);
            AppendApiNumber(text, L"目标线程创建 FILETIME", latest.targetThreadCreationFileTime);
            AppendApiNumber(text, L"API 写入起始地址", latest.writtenAddress);
            AppendApiNumber(text, L"实际完成写入字节数", latest.writtenBytes);
            AppendApiNumber(text, L"请求指令指针 IP", latest.requestedIp);
            AppendApiNumber(text, L"请求栈指针 SP", latest.requestedSp);
            AppendApiNumber(text, L"请求 CONTEXT ABI（位）", latest.contextArchitecture);
        }
        text += L"\r\n上下文已生效：未知\r\n上下文请求后的执行：未知";
        return text + L"\r\nIP、SP、ContextFlags 和 ABI 仅描述请求；接受请求不证明上下文已生效或发生执行。输入句柄和 CONTEXT 地址不授予对象身份。";
    }
}
