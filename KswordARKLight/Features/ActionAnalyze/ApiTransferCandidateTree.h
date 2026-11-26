#pragma once

#include "StoredEvidence.h"

namespace Ksword::Features::ActionAnalyze {

// 原生底部候选树只消费已核验快照；不读取归档，不访问目标进程。
class ApiTransferCandidateTree final {
public:
    // parent 为现有工作台宿主，id 是 WM_NOTIFY 固定身份；无返回值，调用方用 hwnd 检查创建结果。
    void Create(HWND parent, int id);
    // 输入后台已提交的证据及范围是否相同；同步复制有界双方并更新树，无返回值。
    void Publish(const SegmentEvidence* evidence, bool sameScope);
    // 双击或 Enter 时读取当前叶项并返回只读原包；非叶项返回空，由调用方展开或折叠。
    const EvidenceRecord* Activate() const;
    // 无输入，返回当前原生执行叶的规范来源；API 叶及分类根返回空。
    const Ksword::Evidence::ApiNativeExecutionCandidate<EvidenceRecord>* Execution() const;
    // 无输入；仅独立历史叶返回原观察，API候选和状态根返回空。
    const Ksword::Evidence::NativeExecutionHistoryEntry* History() const;
    // 返回父页面拥有的控件句柄，供布局及 WM_NOTIFY 处理使用；调用方不单独销毁。
    HWND hwnd() const noexcept { return hwnd_; }

private:
    struct Candidate {
        EvidenceRecord write; // 当前候选的真实写入原行。
        EvidenceRecord request; // 线程创建、APC 或上下文请求返回原行。
        int kind = 0; // 0..2为创建/APC/上下文来源，3..6为对应执行及节映射候选。
        std::wstring title; // 后台已提交的候选身份摘要，只用于展示。
        std::optional<Ksword::Evidence::ApiNativeExecutionCandidate<EvidenceRecord>> execution; // 执行分支的独立来源及原生坐标。
    };
    HWND hwnd_ = nullptr; // 页面拥有的原生 TreeView，随父窗口销毁。
    std::vector<Candidate> candidates_; // 最多512对API来源候选和512个执行候选，自持有来源防止快照更换悬空。
    std::vector<Ksword::Evidence::NativeExecutionHistoryEntry> history_; // 最近512条独立历史，按原来源恢复选择。
};

} // namespace Ksword::Features::ActionAnalyze
