#pragma once

#include "NativeDebugOwner.h"
#include "../Rules/RuleExpression.h"

#include <algorithm>
#include <array>

namespace ks::cli::action_analyze::control {

// 输入两类原生会话的求值阶段，输出排序后的字段目录；保持各端既有阶段语义。
inline constexpr auto NativeStopConditionFields(Ksword::ActionAnalyze::Rules::Phase phase)
{
    namespace rules = Ksword::ActionAnalyze::Rules;
    std::array<rules::FieldBinding, 9 + NativeStopRegisterFields.size()> fields{}; // 通用事件字段及完整寄存器目录。
    fields[0] = {"stop.address", rules::FieldType::U64, phase};
    fields[1] = {"stop.data.changedByteMask", rules::FieldType::U64, phase};
    fields[2] = {"stop.data.enrolledAfterStop", rules::FieldType::U64, phase};
    fields[3] = {"stop.data.watchedBytes", rules::FieldType::U64, phase};
    fields[4] = {"stop.exceptionCode", rules::FieldType::U64, phase};
    fields[5] = {"stop.firstChance", rules::FieldType::Bool, phase};
    fields[6] = {"stop.pid", rules::FieldType::U64, phase};
    fields[7] = {"stop.thread.creationFileTime", rules::FieldType::U64, phase};
    // 依共用寄存器顺序接在创建时间后面，保持类型化编译器需要的字段排序。
    for (std::size_t index = 0; index < NativeStopRegisterFields.size(); ++index)
    {
        fields[8 + index] = {NativeStopRegisterFields[index].conditionField, rules::FieldType::U64, phase};
    }
    fields.back() = {"stop.tid", rules::FieldType::U64, phase};
    return fields;
}

// 原生条件只绑定原生停点目录；普通 API 文本规则不能通过此入口取得额外字段。
// 新草稿使用 v3，读取冻结条件时由调用方明确传入保存的 v1/v2/v3 profile。
[[nodiscard]] inline Ksword::ActionAnalyze::Rules::ExpressionPreparation PrepareNativeStopCondition(
    std::string_view source, Ksword::ActionAnalyze::Rules::Phase phase,
    std::string_view profile = Ksword::ActionAnalyze::Rules::PredicateExpressionProfile)
{
    const auto fields = NativeStopConditionFields(phase);
    return Ksword::ActionAnalyze::Rules::PreparePredicateExpression(source, phase, fields, profile);
}

// 输入原生冻结快照，输出拥有固定字段名的值数组。调用者负责控制资格；不查询线程或执行Continue。
inline auto NativeStopConditionSamples(const NativeControlResult& state)
{
    namespace rules = Ksword::ActionAnalyze::Rules;
    constexpr auto fields = NativeStopConditionFields(rules::Phase::Observation); // 只取字段名，求值阶段由调用者提供。
    std::array<rules::FieldSample, fields.size()> samples{}; // 未取得的值统一保持NotCollected。
    for (std::size_t index = 0; index < fields.size(); ++index)
    {
        samples[index] = {fields[index].id, rules::Quality::NotCollected, std::monostate{}};
    }
    // 将已采集的原始值与Known一起发布；零、false不表示缺失。
    const auto known = [&](std::size_t index, auto value)
    {
        samples[index].quality = rules::Quality::Known;
        samples[index].value = value;
    };
    if (state.breakpointHit)
    {
        known(0, state.breakpointHit->address);
        if (const auto& data = state.breakpointHit->dataChange)
        {
            known(1, std::uint64_t{data->changedByteMask});
            known(2, data->enrolledAfterStop);
            known(3, std::uint64_t{data->watchedBytes});
        }
    }
    if (!state.pending)
    {
        return samples;
    }
    const auto& event = *state.pending; // 精确原生事件，不从最近一次命中推断本轮异常。
    if (event.exceptionCode)
    {
        known(4, std::uint64_t{*event.exceptionCode});
    }
    if (event.exceptionFirstChance)
    {
        known(5, *event.exceptionFirstChance);
    }
    known(6, std::uint64_t{event.pid});
    known(samples.size() - 1, std::uint64_t{event.tid});
    if (!state.responsibility || state.responsibility->event != event.event)
    {
        return samples;
    }
    // 只有同一事件线程的强身份匹配，才发布创建时间和寄存器。
    const auto thread = std::find_if(state.frozenThreads.begin(), state.frozenThreads.end(), [&](const auto& member) {
        return member.identity == state.responsibility->actualEventThread && member.tid == event.tid && member.creationTime;
    });
    if (thread == state.frozenThreads.end())
    {
        return samples;
    }
    known(7, thread->creationTime);
    if (state.registers && state.registers->thread == thread->identity)
    {
        for (std::size_t index = 0; index < NativeStopRegisterFields.size(); ++index)
        {
            known(8 + index, (*state.registers).*(NativeStopRegisterFields[index].value));
        }
    }
    return samples;
}

// 仅消费调用方已取得的冻结快照；条件分支沿用已准备 AST 的三值和短路语义。
// 这不是停点资格检查，不查询目标、不读指针，也不提交继续或其它原生控制请求。
[[nodiscard]] inline Ksword::ActionAnalyze::Rules::Evaluation EvaluateNativeStopCondition(
    const Ksword::ActionAnalyze::Rules::PreparedPredicate& predicate,
    Ksword::ActionAnalyze::Rules::Phase phase, const NativeControlResult& state,
    std::size_t workLimit = Ksword::ActionAnalyze::Rules::MaxPredicateWork)
{
    const auto samples = NativeStopConditionSamples(state);
    return Ksword::ActionAnalyze::Rules::EvaluatePredicate(predicate, phase, samples, workLimit);
}

} // namespace ks::cli::action_analyze::control
