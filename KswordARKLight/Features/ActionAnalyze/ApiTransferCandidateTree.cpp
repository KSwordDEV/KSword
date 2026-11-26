#include "ApiTransferCandidateTree.h"

#include "../../Ui/Controls.h"
#include "../../Ui/Theme.h"

#include <array>
#include <algorithm>
#include <commctrl.h>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

using Key = std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>; // 实际raw段号、序号和记录头偏移。
using CandidateKey = std::tuple<int, Key, Key, Key, std::string>; // 类型、双方、原生物理坐标和段摘要共同区分来源。
constexpr LPARAM kHistoryLeaf = 1000000; // 独立历史节点值，与三角色候选编码分开。

// 输入原行，输出真实坐标，不使用当前表格下标。
Key Coordinate(const EvidenceRecord& row)
{
    return {row.segmentOrdinal, row.sequence, row.offset};
}

// 输入双方原行与角色，输出同一 TreeView 中可定位的叶项标题。
std::wstring LeafText(const EvidenceRecord& row, bool write, int kind)
{
    const wchar_t* role = write ? L"写入：raw/" : kind == 3 ? L"范围请求：raw/" : kind == 2 ? L"上下文请求：raw/"
        : kind == 1 ? L"APC 入队：raw/" : L"线程创建：raw/"; // kind 是候选类型，请求不冒充执行。
    return std::wstring(role) + std::to_wstring(row.segmentOrdinal) + L" #" +
        std::to_wstring(row.sequence) + L" · " + row.apiClue;
}

// 输入树、父项、文字与值，输出新节点；正值是双方下标，负值是独立分类根。
HTREEITEM Insert(HWND tree, HTREEITEM parent, const std::wstring& text, LPARAM data)
{
    TVINSERTSTRUCTW item{}; // TreeView 同步复制值和文字，不借用源快照指针。
    item.hParent = parent;
    item.hInsertAfter = TVI_LAST;
    item.item.mask = TVIF_TEXT | TVIF_PARAM;
    item.item.pszText = const_cast<wchar_t*>(text.c_str());
    item.item.lParam = data;
    return TreeView_InsertItem(tree, &item);
}

// 输入控件及节点，输出已保存的值；空节点返回零，不借用旧模型地址。
LPARAM NodeValue(HWND tree, HTREEITEM node)
{
    TVITEMW item{}; // 只读取同步保存的节点身份。
    item.mask = TVIF_PARAM;
    item.hItem = node;
    return node && TreeView_GetItem(tree, &item) ? item.lParam : 0;
}

} // namespace

// 输入现有工作台宿主与通知 ID，创建原生树；调用方用 hwnd 检查结果。
void ApiTransferCandidateTree::Create(HWND parent, int id)
{
    hwnd_ = ::CreateWindowExW(0, WC_TREEVIEWW, L"写入与请求候选", WS_CHILD | WS_TABSTOP |
        TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_INFOTIP,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    ::SendMessageW(hwnd_, WM_SETFONT, reinterpret_cast<WPARAM>(Ui::SystemUIFont()), FALSE);
    const auto& theme = Ui::AppTheme(); // 复用原生主题实底、文字与连接线颜色。
    TreeView_SetBkColor(hwnd_, theme.panelColor);
    TreeView_SetTextColor(hwnd_, theme.textColor);
    TreeView_SetLineColor(hwnd_, theme.mutedTextColor);
}

// 输入已发布快照及范围是否相同，同步更新三类API来源、四类执行候选及读取状态；不执行I/O。
void ApiTransferCandidateTree::Publish(const SegmentEvidence* evidence, bool sameScope)
{
    std::optional<Key> selected; // 当前叶项坐标。
    std::optional<CandidateKey> selectedPair; // 当前候选类型与双方身份。
    std::optional<int> selectedRoot; // 当前分类根，不以旧节点句柄恢复。
    std::array<bool, 8> rootExpanded{}; // 第八根同时承载历史状态和独立观察。
    std::optional<Ksword::Evidence::NativeExecutionHistoryEntry> selectedHistory; // 原历史选择按散列与坐标恢复。
    std::optional<int> selectedSide; // 原生叶与同序号 API 叶不可互换。
    std::set<CandidateKey> expanded; // 三类重叠候选分别恢复展开。
    const auto current = TreeView_GetSelection(hwnd_); // 旧树当前节点。

    // 从旧树值恢复身份，整个过程使用树自有行，不借用即将替换的快照。
    const auto keyOf = [&](std::size_t index) {
        const auto& pair = candidates_[index]; // 已验证范围中的旧候选。
        return CandidateKey{pair.kind, Coordinate(pair.write), Coordinate(pair.request), pair.execution
            ? Key{pair.execution->nativeOrdinal, pair.execution->nativeSequence, pair.execution->nativeRecordOffset} : Key{},
            pair.execution ? pair.execution->nativeSha256 : std::string{}};
    }; // 输入候选下标，输出类型和双方坐标。
    if (sameScope)
    {
        const auto value = NodeValue(hwnd_, current); // 根为负值，叶为正值，候选父项为零。
        if (const auto* entry = History())
        {
            selectedHistory = *entry;
        }
        else if (value < 0)
        {
            selectedRoot = static_cast<int>(-value - 1);
        }
        else
        {
            const auto leafValue = value > 0 ? value : NodeValue(hwnd_, TreeView_GetChild(hwnd_, current)); // 父项由首叶解析。
            const auto index = leafValue > 0 ? static_cast<std::size_t>((leafValue - 1) / 3) : candidates_.size(); // 越界哨兵。
            if (index < candidates_.size())
            {
                selectedPair = keyOf(index);
                if (value > 0)
                {
                    selectedSide = static_cast<int>((value - 1) % 3);
                    selected = Coordinate(*selectedSide == 0 ? candidates_[index].write : candidates_[index].request);
                }
            }
        }
        for (auto root = TreeView_GetRoot(hwnd_); root; root = TreeView_GetNextSibling(hwnd_, root))
        {
            const auto groupValue = NodeValue(hwnd_, root); // -1 创建，-2 APC，-3 上下文。
            const auto group = static_cast<int>(-groupValue - 1); // 独立根类型。
            if (group < 0 || group >= 8)
            {
                continue;
            }
            rootExpanded[group] = (TreeView_GetItemState(hwnd_, root, TVIS_EXPANDED) & TVIS_EXPANDED) != 0;
            for (auto node = TreeView_GetChild(hwnd_, root); node; node = TreeView_GetNextSibling(hwnd_, node))
            {
                const auto leafValue = NodeValue(hwnd_, TreeView_GetChild(hwnd_, node)); // 候选首叶。
                const auto index = leafValue > 0 ? static_cast<std::size_t>((leafValue - 1) / 3) : candidates_.size(); // 旧候选下标。
                if (index < candidates_.size() && (TreeView_GetItemState(hwnd_, node, TVIS_EXPANDED) & TVIS_EXPANDED))
                {
                    expanded.insert(keyOf(index));
                }
            }
        }
    }

    // 最多512对API来源及512个执行候选自持原行，窗口外定位不借用旧快照地址。
    ::SendMessageW(hwnd_, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(hwnd_);
    candidates_.clear();
    history_.clear();
    if (evidence)
    {
        history_.assign(evidence->nativeExecution.observations.begin(), evidence->nativeExecution.observations.end());
        for (const auto& pair : evidence->transferCandidates)
        {
            candidates_.push_back({pair.write, pair.threadCreate, 0,
                L"来源声明候选 · PID " + std::to_wstring(pair.link.actorPid) + L" → " + std::to_wstring(pair.link.targetPid)});
        }
        for (const auto& pair : evidence->apcTransferCandidates)
        {
            candidates_.push_back({pair.write, pair.queue, 1,
                L"APC 来源声明候选 · PID " + std::to_wstring(pair.link.actorPid) + L" → " +
                std::to_wstring(pair.link.targetPid) + L" / TID " + std::to_wstring(pair.link.targetTid) +
                L" · 请求例程 " + std::to_wstring(pair.link.requestedRoutineAddress)});
        }
        // 每个 pair 为已提交上下文候选，保留原请求 IP/SP/ABI，不标记 contextApplied。
        for (const auto& pair : evidence->contextTransferCandidates)
        {
            candidates_.push_back({pair.write, pair.context, 2,
                L"上下文来源声明候选 · PID " + std::to_wstring(pair.link.actorPid) + L" → " +
                std::to_wstring(pair.link.targetPid) + L" / TID " + std::to_wstring(pair.link.targetTid) +
                L" · 请求 IP " + std::to_wstring(pair.link.requestedIp) + L" / SP " + std::to_wstring(pair.link.requestedSp) +
                L" / ABI " + std::to_wstring(pair.link.contextArchitecture)});
        }
        for (const auto& candidate : evidence->nativeExecution.candidates) // 仅消费共享匹配核心返回的只读候选。
        {
            Candidate row; // API 双方和 native 文档共同归属于一个稳定分支。
            row.write = candidate.write.value_or(EvidenceRecord{});
            row.request = candidate.request;
            row.kind = candidate.kind + 3;
            row.title = L"一致性候选 · " + candidate.request.apiClue + L" → raw-native/" +
                std::to_wstring(candidate.nativeOrdinal) + L" #" + std::to_wstring(candidate.nativeSequence);
            row.execution = candidate;
            candidates_.push_back(std::move(row));
        }
    }
    for (int kind = 0; evidence && kind < 7; ++kind) // 稳定分类不因空组重新编号。
    {
        const auto retained = kind >= 3 ? static_cast<std::size_t>(std::count_if(candidates_.begin(), candidates_.end(),
            [&](const auto& candidate) { return candidate.kind == kind; })) : kind == 2 ? evidence->contextTransferCandidates.size() : kind == 1
            ? evidence->apcTransferCandidates.size() : evidence->transferCandidates.size(); // 当前类型保留数量。
        const auto total = kind >= 3 ? retained : kind == 2 ? evidence->contextTransferCandidateCount : kind == 1
            ? evidence->apcTransferCandidateCount : evidence->transferCandidateCount; // 当前类型累计数，含裁剪部分。
        if (!retained && !total && !evidence->evictedTransferWrites)
        {
            continue;
        }
        auto title = std::wstring(kind == 2 ? L"来源声明：写入 → 上下文请求" : kind == 1
            ? L"来源声明：写入 → APC 入队" : L"来源声明：写入 → 线程创建") +
            L" · 保留 " + std::to_wstring(retained) + L" / 总计 " + std::to_wstring(total) + L" · 写入淘汰 " +
            std::to_wstring(evidence->evictedTransferWrites) + (kind == 2 ? L"（生效和执行未知）" : kind == 1
                ? L"（不证明投递或执行）" : L"（不证明实际执行或强归因）"); // 根摘要只报告来源候选。
        if (kind >= 3)
        {
            const wchar_t* names[]{L"线程创建", L"APC 入队", L"上下文请求", L"内存范围（映射／分配／保护）"}; // 保留稳定根编号。
            title = std::wstring(names[kind - 3]) + L" → 原生执行一致性候选（" + std::to_wstring(retained) + L"）";
        }
        const auto group = Insert(hwnd_, TVI_ROOT, title, -kind - 1); // 分类根身份不依赖创建顺序。
        for (std::size_t index = 0; index < candidates_.size(); ++index)
        {
            const auto& pair = candidates_[index]; // 当前类型的候选双方。
            if (pair.kind != kind)
            {
                continue;
            }
            const auto key = keyOf(index); // 新快照中的完整分支身份。
            const auto node = Insert(hwnd_, group, pair.title, 0); // 父项仅控制展开。
            const EvidenceRecord* rows[]{&pair.write, &pair.request}; // 固定双方顺序。
            for (std::size_t side = 0; side < (pair.execution ? 3u : 2u); ++side)
            {
                auto text = side < 2 ? LeafText(*rows[side], side == 0, kind >= 3 ? kind - 3 : kind)
                    : L"raw-native/" + std::to_wstring(pair.execution->nativeOrdinal) + L" #" + std::to_wstring(pair.execution->nativeSequence);
                if (pair.execution && side == 2)
                {
                    const auto* native = pair.execution->sourceDocument.find("native"); // 原观察类型不与请求混合。
                    const auto* observation = native ? native->find("observation") : nullptr;
                    std::string observationKind; // execution-enter-attempt 或 instruction-completed 原值。
                    if (observation && observation->tryGetString(observationKind))
                    {
                        text += L" · " + std::wstring(observationKind.begin(), observationKind.end());
                    }
                    const auto number = [](const auto* object, std::string_view field) { // 原文无损数值，不从 API 请求补值。
                        const auto* value = object ? object->find(field) : nullptr;
                        std::uint64_t decoded = 0; // 当前真实字段值。
                        return value && value->tryGetU64(decoded) ? std::to_wstring(decoded) : std::wstring(L"?");
                    };
                    const auto* target = native ? native->find("target") : nullptr; // 执行事件所属进程。
                    const auto* thread = native ? native->find("thread") : nullptr; // 实际执行线程。
                    text += L" @" + number(&pair.execution->sourceDocument, "nativeRecordOffset") +
                        L" · PID " + number(target, "pid") + L"/" + number(target, "creationFileTime") +
                        L" · TID " + number(thread, "tid") + L"/" + number(thread, "creationFileTime") +
                        L" · IP " + number(native, "instructionAddress");
                }
                if (pair.execution && side == 1 && pair.execution->kind == 3)
                {
                    text = L"API 请求：raw/" + std::to_wstring(pair.request.segmentOrdinal) + L" #" +
                        std::to_wstring(pair.request.sequence) + L" · " + pair.request.apiClue;
                }
                if (pair.execution && side == 0 && !pair.execution->write)
                {
                    text = L"本关联未绑定前置写入；不表示没有发生写入。";
                }
                const auto leaf = Insert(hwnd_, node, text,
                    static_cast<LPARAM>(index * 3 + side + 1)); // 三种角色分开编码，不保存行指针。
                if (selectedSide == static_cast<int>(side) && selectedPair == key)
                {
                    TreeView_SelectItem(hwnd_, leaf);
                }
            }
            if (expanded.contains(key))
            {
                TreeView_Expand(hwnd_, node, TVE_EXPAND);
            }
            if (!selected && selectedPair == key)
            {
                TreeView_SelectItem(hwnd_, node);
            }
        }
        if (!sameScope || rootExpanded[kind])
        {
            TreeView_Expand(hwnd_, group, TVE_EXPAND);
        }
        if (selectedRoot == kind)
        {
            TreeView_SelectItem(hwnd_, group);
        }
    }
    if (evidence && evidence->nativeExecution.state != Ksword::Evidence::NativeHistoryState::NotRequested)
    {
        const auto& native = evidence->nativeExecution; // 独立读取状态，候选为空也不隐藏。
        auto status = L"原生历史：已核验 " + std::to_wstring(native.verifiedNativeCount) +
            L" 条；执行候选保留 " + std::to_wstring(native.candidates.size()) + L" / 匹配 " +
            std::to_wstring(native.candidateCount) + L"；请求输入淘汰 " + std::to_wstring(native.evictedMaps);
        if (native.state == Ksword::Evidence::NativeHistoryState::Failed)
        {
            const auto detail = std::string_view(native.problem.detail); // 项目错误阶段是静态 ASCII 文本。
            status = L"原生历史读取失败：段 " + std::to_wstring(native.failedOrdinal) + L"；" +
                std::wstring(detail.begin(), detail.end()) + L"；Win32 " +
                std::to_wstring(native.problem.nativeError) + L"。已发布的其他来源结果仍保留。";
        }
        else if (native.state == Ksword::Evidence::NativeHistoryState::Limited)
        {
            status += L"；已达到原生历史 4096 段读取上限。";
        }
        else if (native.state == Ksword::Evidence::NativeHistoryState::Canceled)
        {
            status = L"原生历史读取已取消。";
        }
        const auto statusNode = Insert(hwnd_, TVI_ROOT, status, -8); // 成功空历史与失败均有稳定状态节点。
        for (std::size_t index = 0; index < history_.size(); ++index)
        {
            const auto& entry = history_[index]; // 原生流段号及实际记录坐标不借用API原行。
            const auto* document = entry.sourceDocument.find("native"); // 完整历史来自原后台核验。
            const auto* observation = document ? document->find("observation") : nullptr;
            std::string kind; // 真实阶段，保留进入尝试和指令完成原值。
            if (observation)
            {
                observation->tryGetString(kind);
            }
            const auto text = L"raw-native/" + std::to_wstring(entry.nativeOrdinal) + L" #" +
                std::to_wstring(entry.nativeSequence) + L" @" + std::to_wstring(entry.nativeRecordOffset) +
                L" · " + std::wstring(kind.begin(), kind.end()); // 详情通过同一sourceDocument展开全部身份和寄存器。
            const auto leaf = Insert(hwnd_, statusNode, text, kHistoryLeaf + static_cast<LPARAM>(index));
            if (selectedHistory && Ksword::Evidence::SameNativeExecutionHistory(*selectedHistory, entry))
            {
                TreeView_SelectItem(hwnd_, leaf);
            }
        }
        if (!sameScope || rootExpanded[7])
        {
            TreeView_Expand(hwnd_, statusNode, TVE_EXPAND);
        }
        if (selectedRoot == 7)
        {
            TreeView_SelectItem(hwnd_, statusNode);
        }
    }
    ::SendMessageW(hwnd_, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

// 无参数；双击／Enter 时返回自有只读叶行，父项和分类根返回空。
const EvidenceRecord* ApiTransferCandidateTree::Activate() const
{
    const auto value = NodeValue(hwnd_, TreeView_GetSelection(hwnd_)); // 正值才有原包定位资格。
    if (value <= 0 || value >= kHistoryLeaf)
    {
        return nullptr;
    }
    const auto index = static_cast<std::size_t>((value - 1) / 3); // 当前分支的有界缓存下标。
    if (index >= candidates_.size())
    {
        return nullptr;
    }
    const auto& pair = candidates_[index]; // 返回树拥有的行，不产生强对象引用。
    const auto side = (value - 1) % 3; // 原生叶只能由 Execution 返回规范文档。
    if (side == 2 || (side == 0 && pair.execution && !pair.execution->write))
    {
        return nullptr;
    }
    return side == 0 ? &pair.write : &pair.request;
}

// 仅原生观察叶返回当前只读来源；调用方可用于选择详情、Enter 与双击。
const Ksword::Evidence::ApiNativeExecutionCandidate<EvidenceRecord>* ApiTransferCandidateTree::Execution() const
{
    const auto value = NodeValue(hwnd_, TreeView_GetSelection(hwnd_)); // 控件自持有的稳定角色编号。
    if (value <= 0 || value >= kHistoryLeaf || (value - 1) % 3 != 2)
    {
        return nullptr;
    }
    const auto index = static_cast<std::size_t>((value - 1) / 3); // 当前只读分支下标。
    return index < candidates_.size() && candidates_[index].execution ? &*candidates_[index].execution : nullptr;
}

// 输入为当前树选择；只返回本树自有的独立历史，调用方复制值后才能跨快照保留。
const Ksword::Evidence::NativeExecutionHistoryEntry* ApiTransferCandidateTree::History() const
{
    const auto value = NodeValue(hwnd_, TreeView_GetSelection(hwnd_)); // 独立编码只用于历史叶。
    if (value < kHistoryLeaf)
    {
        return nullptr;
    }
    const auto index = static_cast<std::size_t>(value - kHistoryLeaf); // 本轮有界历史窗口下标。
    return index < history_.size() ? &history_[index] : nullptr;
}

} // namespace Ksword::Features::ActionAnalyze
