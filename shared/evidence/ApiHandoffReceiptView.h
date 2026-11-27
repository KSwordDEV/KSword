#pragma once

#include "EvidenceJson.h"
#include <utility>

namespace Ksword::Evidence
{
    // 桌面两端共用的只读字段；name为规范中文标签，value保留回执原值，translate仅标记状态词。
    struct HandoffReceiptField
    {
        const wchar_t* name = L""; // 搜索、复制和导出使用的同一字段名。
        std::string value; // UTF-8文本；64位身份和地址不经过浮点转换。
        bool translate = false; // 只有固定状态词参与界面本地化。
    };

    // 每个分组对应集合、一个来源或一次准入；tone只表达该分组自身的故障事实。
    struct HandoffReceiptSection
    {
        const wchar_t* name = L""; // 稳定分组名，界面可追加PID作为导航摘要。
        std::vector<HandoffReceiptField> fields; // 原序字段，不读取当前进程或其它样本。
        bool failed = false; // 明确错误才置位，不能从历史Ready或资源clean推导成功。
    };

    namespace HandoffReceiptView
    {
        // 输入回执对象和键；返回无损标量文本，缺失、null或错误类型均保留未知。
        inline std::string Scalar(const JsonValue& object, const char* key)
        {
            const auto* value = object.find(key); // 仅借用本次冻结的JSON，不创建键。
            if (!value || value->isNull())
            {
                return "未知";
            }
            if (value->type() == JsonType::String)
            {
                std::string text; // 接收原始UTF-8字符串，地址和散列不作格式猜测。
                value->tryGetString(text);
                return text;
            }
            if (value->type() == JsonType::Bool)
            {
                bool flag = false; // 只有真实bool才能显示是/否，缺失不补false。
                value->tryGetBool(flag);
                return flag ? "是" : "否";
            }
            if (value->type() == JsonType::UInt || value->type() == JsonType::Int)
            {
                return WriteJson(*value);
            }
            return "未知";
        }

        // 输入冻结对象及字段定义；追加一个可读字段，无现场查询与控制副作用。
        inline void Field(HandoffReceiptSection& section, const JsonValue& object,
            const wchar_t* label, const char* key)
        {
            const auto* value = object.find(key); // 用类型而非内容决定布尔值是否本地化。
            auto text = Scalar(object, key); // 无损投影唯一的原值。
            const bool translate = !value || value->isNull() ||
                value->type() == JsonType::Bool || text == "未知";
            section.fields.push_back({label, std::move(text), translate});
        }

        // 输入回执及键，只有明确非零错误或true失败位才返回true；未知不冒充失败或成功。
        inline bool Failed(const JsonValue& object, const char* key)
        {
            const auto* value = object.find(key); // 支持错误码及失败开关两种后端原类型。
            bool flag = false; // 存放真实失败位。
            std::uint64_t code = 0; // 存放真实非零错误码。
            return value && ((value->tryGetBool(flag) && flag) ||
                (value->tryGetU64(code) && code != 0));
        }
    }

    // 输入api-transfer-handoff-v1原回执；输出集合、来源和目标准入分组，不推导API因果或当前保护。
    // Qt映射为共享FieldDocument，Win32映射为同一详情正文；原JSON仍由调用者保存用于完整导出。
    inline std::vector<HandoffReceiptSection> BuildHandoffReceiptView(const JsonValue& receipt)
    {
        using namespace HandoffReceiptView;
        std::vector<HandoffReceiptSection> sections; // 每次只从同一冻结回执生成纯值分组。
        if (Scalar(receipt, "kind") != "api-transfer-handoff-v1")
        {
            return sections;
        }

        HandoffReceiptSection summary{L"自动接管概览"}; // 集合事实与各目标的执行、采集状态分开。
        Field(summary, receipt, L"集合 ID", "collectionId");
        Field(summary, receipt, L"来源 PID", "sourcePid");
        Field(summary, receipt, L"继续接收目标", "acceptingTargets");
        Field(summary, receipt, L"成员资源已归还", "clean");
        Field(summary, receipt, L"请求次数", "requests");
        Field(summary, receipt, L"已设防准入数", "armed");
        Field(summary, receipt, L"拒绝次数", "rejected");
        Field(summary, receipt, L"已保存执行观察", "savedExecutionStops");
        Field(summary, receipt, L"当前递归来源均就绪", "recursiveAgentReady");
        Field(summary, receipt, L"归档错误码", "archiveError");
        Field(summary, receipt, L"管道失败次数", "pipeFailures");
        Field(summary, receipt, L"首次管道错误码", "firstPipeError");
        Field(summary, receipt, L"接管初始化错误码", "setupError");
        Field(summary, receipt, L"最近接管错误码", "lastError");
        summary.failed = Failed(receipt, "setupError") || Failed(receipt, "archiveError") ||
            Failed(receipt, "pipeFailures") || Failed(receipt, "callbackFailed") || Failed(receipt, "rejected");
        sections.push_back(std::move(summary));

        const auto* sources = receipt.find("sources"); // 原控制器持有的来源目录，不按界面选择替换。
        if (sources && sources->asArray())
        {
            for (const auto& source : *sources->asArray())
            {
                HandoffReceiptSection group{L"采集来源"}; // Ready是历史事实，Stop/Ended及Failed独立显示。
                Field(group, source, L"来源 PID", "pid");
                Field(group, source, L"进程创建 FILETIME", "creationFileTime");
                Field(group, source, L"曾达到 Ready", "ready");
                Field(group, source, L"已请求停止", "stopRequested");
                Field(group, source, L"来源已结束", "ended");
                Field(group, source, L"采集失败", "failed");
                Field(group, source, L"来源错误码", "error");
                Field(group, source, L"清退完成", "cleanupComplete");
                Field(group, source, L"来源会话 ID", "session");
                group.failed = Failed(source, "failed");

                // 同一来源可能含多个进程回执，逐项保留EOF和覆盖状态，不用资源clean掩盖错误。
                const auto* processes = source.find("processes"); // 对应原采集器的实际读管道事实。
                if (processes && processes->asArray())
                {
                    for (const auto& process : *processes->asArray())
                    {
                        Field(group, process, L"管道错误码", "pipeError");
                        Field(group, process, L"管道正常读完", "cleanPipeEof");
                        Field(group, process, L"覆盖快照过期", "coverageStale");
                        Field(group, process, L"目标已退出", "exited");
                        group.failed = group.failed || Failed(process, "pipeError") || Failed(process, "coverageStale");
                    }
                }
                sections.push_back(std::move(group));
            }
        }

        const auto* admissions = receipt.find("admissions"); // 请求窗口只代表回执保留的准入，不冒充全量历史。
        if (admissions && admissions->asArray())
        {
            for (const auto& admission : *admissions->asArray())
            {
                HandoffReceiptSection group{L"接管目标"}; // 每次准入独立保留入口和精确对象身份。
                Field(group, admission, L"API 目标 PID", "targetPid");
                Field(group, admission, L"目标进程创建 FILETIME", "targetCreationFileTime");
                Field(group, admission, L"来源 PID", "sourcePid");
                Field(group, admission, L"源进程创建 FILETIME", "sourceCreationFileTime");
                Field(group, admission, L"准入处理结束", "completed");
                Field(group, admission, L"准入错误码", "error");
                Field(group, admission, L"请求入口地址", "address");
                Field(group, admission, L"私有范围基址", "rangeBase");
                Field(group, admission, L"私有范围字节数", "rangeBytes");
                Field(group, admission, L"原生所有者阶段", "nativeOwnerStage");
                Field(group, admission, L"已请求失败目标恢复", "failedTargetRecoveryRequested");
                Field(group, admission, L"目标退出码", "nativeExitCode");
                Field(group, admission, L"恢复失败阶段", "nativeRecoveryFailureStage");
                Field(group, admission, L"恢复失败错误码", "nativeRecoveryFailureError");
                group.failed = Failed(admission, "error") || Failed(admission, "nativeRecoveryFailureError");

                const auto* entry = admission.find("entryObservation"); // 仅后端归档确认的精确入口观察。
                if (entry && entry->asObject())
                {
                    Field(group, *entry, L"实际指令地址", "instructionAddress");
                    Field(group, *entry, L"入口观察类型", "observation");
                    Field(group, *entry, L"观察线程 TID", "tid");
                    Field(group, *entry, L"线程创建 FILETIME", "threadCreationFileTime");
                    Field(group, *entry, L"原生归档段号", "segmentOrdinal");
                    Field(group, *entry, L"原生记录序号", "recordSequence");
                    Field(group, *entry, L"原生段 SHA-256", "sha256");
                }
                else
                {
                    group.fields.push_back({L"入口观察类型", "尚无已归档入口观察", true});
                }

                // 页推进回执只描述同一owner最近一步，不能解释为当前准入入口已经完成执行。
                const auto* step = admission.find("nativePageAdvance"); // 原后端明确给出的target-owner-latest投影。
                if (step && step->asObject())
                {
                    Field(group, admission, L"页推进回执范围", "nativePageAdvanceScope");
                    Field(group, *step, L"最近页推进阶段", "stage");
                    Field(group, *step, L"步进资源已归还", "resourcesRestored");
                }
                sections.push_back(std::move(group));
            }
        }
        return sections;
    }
}
