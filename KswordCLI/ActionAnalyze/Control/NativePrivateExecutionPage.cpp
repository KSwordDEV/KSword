#include "NativePrivateExecutionPage.h"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace ks::cli::action_analyze::control {
namespace {
constexpr std::uint64_t kPageBytes = 4096;
DWORD LastError() { const auto error = GetLastError(); return error ? error : ERROR_GEN_FAILURE; }
}

DWORD NativePrivateExecutionPage::ParseRange(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes,
    std::vector<Page>& resolved) const
{
    if (!address || address % kPageBytes || !bytes || bytes % kPageBytes ||
        bytes > (std::numeric_limits<std::uintptr_t>::max)() ||
        address > (std::numeric_limits<std::uintptr_t>::max)() - bytes) return ERROR_INVALID_PARAMETER;
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    if (system.dwPageSize != kPageBytes) return ERROR_NOT_SUPPORTED;
    // 只按容器可表示容量拒绝；实际分配失败转换成原所有者可发布的Win32错误。
    const auto pageCount = bytes / kPageBytes; // 整页数量保持64位，不截断成控件整数。
    if (pageCount > resolved.max_size()) return ERROR_NOT_ENOUGH_MEMORY;
    try
    {
        resolved.reserve(static_cast<std::size_t>(pageCount));
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY; // 分配失败发生在任何页保护改动之前。
    }
    for (std::uint64_t offset = 0; offset < bytes; offset += kPageBytes) {
        Page page;
        if (const auto error = ResolveNativeExplicitMemorySite(process, pid, address + offset, 0, page.site)) return error;
        const auto& selected = page.site.site;
        if (selected.address < selected.regionBase || selected.regionBytes < kPageBytes ||
            selected.address - selected.regionBase > selected.regionBytes - kPageBytes) return ERROR_INVALID_ADDRESS;
        if (!resolved.empty() && (selected.allocationBase != resolved.front().site.site.allocationBase ||
            page.site.allocationProtection != resolved.front().site.allocationProtection)) return ERROR_INVALID_ADDRESS;
        // 不提升读写权限；首版拒绝GUARD、WRITECOPY及所有保护修饰位。
        switch (selected.regionProtection) {
        case PAGE_EXECUTE: page.nonExecutable = PAGE_NOACCESS; break;
        case PAGE_EXECUTE_READ: page.nonExecutable = PAGE_READONLY; break;
        case PAGE_EXECUTE_READWRITE: page.nonExecutable = PAGE_READWRITE; break;
        default: return ERROR_NOT_SUPPORTED;
        }
        page.original = page.expected = selected.regionProtection;
        resolved.push_back(page);
    }
    return ERROR_SUCCESS;
}

DWORD NativePrivateExecutionPage::Resolve(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes)
{
    if (OwnsProtection()) return ERROR_INVALID_STATE;
    std::vector<Page> resolved;
    if (const auto error = ParseRange(process, pid, address, bytes, resolved)) return error;
    std::vector<NativeExecutionRange> ranges; // 在取得任何保护责任之前准备完整初始目录。
    try
    {
        ranges.push_back({address, bytes, resolved.front().site.site.allocationBase});
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    site_ = resolved.front().site; // 绑定元数据保留起始页的原区域，rangeBytes另外描述整个关注范围。
    pages_ = std::move(resolved);
    ranges_ = std::move(ranges);
    return ERROR_SUCCESS;
}

DWORD NativePrivateExecutionPage::AddRange(HANDLE process, DWORD pid, std::uint64_t address, std::uint64_t bytes,
    bool& rollbackComplete)
{
    rollbackComplete = true;
    if (const auto error = Verify(process)) return error;
    if (!address || address % kPageBytes || !bytes || bytes % kPageBytes ||
        bytes > (std::numeric_limits<std::uintptr_t>::max)() ||
        address > (std::numeric_limits<std::uintptr_t>::max)() - bytes) return ERROR_INVALID_PARAMETER;
    for (const auto& page : pages_) {
        if (!page.active || !page.owned || page.expected != page.nonExecutable) return ERROR_INVALID_STATE;
        if (page.site.site.address >= address && page.site.site.address - address < bytes) return ERROR_ALREADY_EXISTS;
    }
    // 用剩余容器容量比较，避免累计页数先相加后溢出；不设固定页数额度。
    if (bytes / kPageBytes > pages_.max_size() - pages_.size() || ranges_.size() == ranges_.max_size())
        return ERROR_NOT_ENOUGH_MEMORY;
    std::vector<Page> resolved;
    if (const auto error = ParseRange(process, pid, address, bytes, resolved)) return error;
    const auto originalCount = pages_.size();
    try
    {
        pages_.reserve(originalCount + resolved.size());
        ranges_.reserve(ranges_.size() + 1); // 所有存储先取得，再开始保护事务。
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY; // 原范围和保护保持原样，交原回执发布真实失败。
    }
    const NativeExecutionRange range{address, bytes, resolved.front().site.site.allocationBase};
    pages_.insert(pages_.end(), resolved.begin(), resolved.end()); // 先登记原Protect及责任位置再Set。
    DWORD failure = ERROR_SUCCESS;
    for (std::size_t i = originalCount; i < pages_.size(); ++i) {
        failure = Change(process, pages_[i], pages_[i].nonExecutable);
        if (failure) break;
    }
    if (!failure) failure = Verify(process); // Set后再次核对原页与本次新增页。
    if (!failure) {
        ranges_.push_back(range);
        return ERROR_SUCCESS;
    }
    for (std::size_t i = originalCount; i < pages_.size(); ++i) {
        pages_[i].active = false;
        if (RestorePage(process, pages_[i])) rollbackComplete = false;
    }
    // 只移除本批确已恢复的页；未知/冲突页仍在原owner，Close逐页继续恢复。
    const auto firstAdded = pages_.begin() + static_cast<std::ptrdiff_t>(originalCount);
    pages_.erase(std::remove_if(firstAdded, pages_.end(), [](const auto& page) { return !page.owned; }), pages_.end());
    return failure;
}

DWORD NativePrivateExecutionPage::RearmExecutablePages(HANDLE process)
{
    if (pages_.empty()) return ERROR_INVALID_STATE;
    // 输入一页的实际可执行保护，输出同等读写权限的NX保护；不接受未知修饰位。
    const auto nonExecutableFor = [](DWORD executable, DWORD& nonExecutable) {
        switch (executable) {
        case PAGE_EXECUTE: nonExecutable = PAGE_NOACCESS; return true;
        case PAGE_EXECUTE_READ: nonExecutable = PAGE_READONLY; return true;
        case PAGE_EXECUTE_READWRITE: nonExecutable = PAGE_READWRITE; return true;
        default: return false; // 保留保护修饰位/WRITECOPY 的恢复语义，不猜测可替换值。
        }
    };

    // 先验证全目录身份和每页可接受的当前态，再改任一页，避免把未知修改半途当作合法重布防。
    for (const auto& page : pages_)
    {
        if (!page.active || !page.owned || page.indeterminate || page.conflict) return ERROR_INVALID_STATE;
        DWORD actual = 0; // 真实当前页保护，由原目标句柄的VirtualQueryEx读取。
        if (const auto error = ReadProtection(process, page, actual)) return error;
        DWORD ignored = 0; // 仅用于确认可执行保护可安全映射，不写入owner状态。
        if (actual != page.nonExecutable && !nonExecutableFor(actual, ignored)) return ERROR_INVALID_DATA;
    }

    for (auto& page : pages_)
    {
        DWORD actual = 0; // 该页修改前实际保护，用于保留API最终请求语义。
        if (const auto error = ReadProtection(process, page, actual)) return error;
        if (actual == page.nonExecutable)
        {
            page.expected = page.nonExecutable;
            continue;
        }
        DWORD nonExecutable = 0; // 当前可执行保护对应的NX形式。
        if (!nonExecutableFor(actual, nonExecutable)) return ERROR_INVALID_DATA;

        page.original = actual;
        page.nonExecutable = nonExecutable;
        page.indeterminate = true; // 首次写保护前登记最新保护与NX恢复责任。
        DWORD previous = 0; // VirtualProtectEx回读的先前保护，用于检测并发外部修改。
        const BOOL changed = VirtualProtectEx(process, reinterpret_cast<void*>(page.site.site.address),
            static_cast<SIZE_T>(kPageBytes), nonExecutable, &previous);
        const DWORD changeError = changed ? ERROR_SUCCESS : LastError(); // API失败保留原生错误码。
        if (!changed) return changeError;
        if (previous != actual)
        {
            page.conflict = true;
            return ERROR_INVALID_DATA;
        }
        DWORD observed = 0; // 写保护后的实际回读值。
        if (const auto error = ReadProtection(process, page, observed)) return error;
        if (observed != nonExecutable) return ERROR_INVALID_DATA;

        // 更新此页最后一次由调用者请求的可执行保护；Close仍恢复该API的有效最终语义。
        page.expected = nonExecutable;
        page.indeterminate = false;
    }
    return Verify(process);
}

DWORD NativePrivateExecutionPage::ReadProtection(HANDLE process, const Page& page, DWORD& protection) const
{
    MEMORY_BASIC_INFORMATION region{};
    const auto address = page.site.site.address;
    if (VirtualQueryEx(process, reinterpret_cast<const void*>(address), &region, sizeof(region)) != sizeof(region))
        return LastError();
    const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    // 自有NX拆分/合并允许RegionSize变化，每页仍须属于冻结的同一MEM_PRIVATE分配。
    if (region.State != MEM_COMMIT || region.Type != MEM_PRIVATE ||
        reinterpret_cast<std::uintptr_t>(region.AllocationBase) != page.site.site.allocationBase ||
        region.AllocationProtect != page.site.allocationProtection || address < base ||
        region.RegionSize < kPageBytes || address - base > region.RegionSize - kPageBytes) return ERROR_INVALID_ADDRESS;
    protection = region.Protect;
    return ERROR_SUCCESS;
}

DWORD NativePrivateExecutionPage::VerifyPage(HANDLE process, const Page& page) const
{
    DWORD actual = 0;
    if (const auto error = ReadProtection(process, page, actual)) return error;
    if (page.indeterminate || page.conflict) return ERROR_INVALID_STATE;
    return actual == page.expected ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD NativePrivateExecutionPage::Verify(HANDLE process) const
{
    if (pages_.empty()) return ERROR_INVALID_STATE;
    for (const auto& page : pages_) {
        if (!page.active) return ERROR_INVALID_STATE; // 失败批次残留仅准Close，不能重新作为可执行业务使用。
        if (const auto error = VerifyPage(process, page)) return error;
    }
    return ERROR_SUCCESS;
}

DWORD NativePrivateExecutionPage::Change(HANDLE process, Page& page, DWORD desired)
{
    if (const auto error = VerifyPage(process, page)) return error;
    if (page.expected == desired) return ERROR_SUCCESS;
    page.owned = true;
    page.indeterminate = true;
    const auto before = page.expected;
    DWORD previous = 0;
    const auto changed = VirtualProtectEx(process, reinterpret_cast<void*>(page.site.site.address),
        static_cast<SIZE_T>(kPageBytes), desired, &previous);
    const auto failure = changed ? ERROR_SUCCESS : LastError();
    if (changed && previous != before) page.conflict = true;
    DWORD actual = 0;
    const auto read = ReadProtection(process, page, actual);
    if (!read && !page.conflict && (actual == page.original || actual == page.nonExecutable)) {
        page.expected = actual;
        page.indeterminate = false;
    }
    if (failure) return failure;
    return read ? read : actual == desired && !page.indeterminate ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD NativePrivateExecutionPage::SetExecutable(HANDLE process, bool executable, std::uint64_t address, std::size_t instructionBytes)
{
    if (executable) {
        if (const auto error = Verify(process)) return error;
        if (!instruction_ || instruction_->address != address || instructionBytes != (instruction_->length ? instruction_->length : 1))
            return ERROR_INVALID_DATA; // 只有同一冻结指令能授权第二页，不接受调用方猜测长度。
        if (!instructionBytes || instructionBytes > 15 || address > (std::numeric_limits<std::uintptr_t>::max)() - (instructionBytes - 1))
            return ERROR_INVALID_PARAMETER;
        const auto first = address & ~std::uint64_t{4095};
        const auto last = (address + instructionBytes - 1) & ~std::uint64_t{4095};
        if (!FindPage(address) && !FindPage(address + instructionBytes - 1)) return ERROR_INVALID_ADDRESS;
        for (const auto& page : pages_) {
            if (page.expected != page.nonExecutable) return ERROR_BUSY; // 每条指令开始前原窗口必须已完全关回NX。
        }
        for (auto& page : pages_) {
            const auto base = page.site.site.address;
            if (base != first && base != last) continue;
            if (const auto error = Change(process, page, page.original)) {
                (void)SetExecutable(process, false); // 逐页回NX，失败责任仍在pages_内，原owner保持事件。
                return error;
            }
        }
        return ERROR_SUCCESS;
    }
    const bool initial = !OwnsProtection();
    DWORD firstError = ERROR_SUCCESS;
    for (auto& page : pages_) {
        const auto error = page.active ? Change(process, page, page.nonExecutable) : ERROR_INVALID_STATE;
        if (!firstError && error) firstError = error; // 一页冲突不跳过其它临时开放页。
    }
    if (firstError && initial) (void)Restore(process);
    if (!firstError) { instruction_.reset(); externalFetchPage_.reset(); }
    return firstError;
}

DWORD NativePrivateExecutionPage::OpenInstruction(HANDLE process, HANDLE thread, bool& opened)
{
    opened = std::any_of(pages_.begin(), pages_.end(), [](const auto& page) {
        return page.expected != page.nonExecutable || page.indeterminate || page.conflict;
    }); // 重试不能用false覆盖前一轮尚未确认关回的窗口责任。
    if (const auto error = Verify(process)) return error;
    if (opened) return ERROR_BUSY;
    if (GetProcessIdOfThread(thread) != GetProcessId(process)) return ERROR_INVALID_DATA;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) return LastError();
#if defined(_M_X64)
    const auto rip = context.Rip;
#else
    const auto rip = context.Eip;
#endif
    NativeInstructionFetch fetch;
    fetch.address = rip;
    const auto room = 4096 - (rip & std::uint64_t{4095});
    instruction_.reset(); externalFetchPage_.reset();
    if (!Contains(rip) && (room >= 15 || !Contains((rip & ~std::uint64_t{4095}) + 4096))) return ERROR_SUCCESS;
    // 只有页尾14字节可能涉及第二页；其它位置继续保留原TF-only普通指令入口。
    if (room < 15) {
        if (const auto error = NativeStepRuntime::DecodeInstructionFetch(process, rip, fetch); error) return error.code;
    }
    const auto length = fetch.length ? fetch.length : std::size_t{1};
    const auto end = rip + length - 1;
    if (!Contains(rip) && !Contains(end)) return ERROR_SUCCESS;
    instruction_ = fetch;
    externalFetchPage_.reset();
    const auto firstBase = rip & ~std::uint64_t{4095}, lastBase = end & ~std::uint64_t{4095};
    for (const auto base : {firstBase, lastBase}) {
        if (FindPage(base)) continue;
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQueryEx(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(base)), &region, sizeof(region)) != sizeof(region))
            return LastError();
        const auto protect = region.Protect & 0xff;
        if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) ||
            (protect != PAGE_EXECUTE && protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE && protect != PAGE_EXECUTE_WRITECOPY))
            return ERROR_INVALID_ADDRESS;
        externalFetchPage_ = ExternalFetchPage{base, region}; // 最多一张未登记页；不取得其保护责任。
    }
    if (const auto error = VerifyInstruction(process, rip)) return error;
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) return LastError();
#if defined(_M_X64)
    if (context.Rip != rip) return ERROR_INVALID_DATA;
#else
    if (context.Eip != rip) return ERROR_INVALID_DATA;
#endif
    opened = true; // 首次Set前登记窗口责任，部分失败也必须由原owner先回NX再归还peer。
    const auto error = SetExecutable(process, true, rip, length);
    if (error) return error;
    return VerifyInstruction(process, rip);
}

DWORD NativePrivateExecutionPage::VerifyInstruction(HANDLE process, std::uint64_t rip) const
{
    if (!instruction_ || instruction_->address != rip) return ERROR_INVALID_DATA;
    if (const auto error = Verify(process)) return error;
    if (externalFetchPage_) {
        MEMORY_BASIC_INFORMATION actual{};
        const auto address = externalFetchPage_->address;
        if (VirtualQueryEx(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)), &actual, sizeof(actual)) != sizeof(actual)) return LastError();
        const auto& frozen = externalFetchPage_->mapping;
        const auto base = reinterpret_cast<std::uintptr_t>(actual.BaseAddress);
        // 相邻登记页撤X/还X可能拆合区域，未登记页本身的分配、整页覆盖和保护必须不变。
        if (address < base || actual.RegionSize < 4096 || address - base > actual.RegionSize - 4096 || actual.AllocationBase != frozen.AllocationBase ||
            actual.AllocationProtect != frozen.AllocationProtect || actual.State != frozen.State || actual.Type != frozen.Type || actual.Protect != frozen.Protect)
            return ERROR_INVALID_DATA;
    }
    if (!instruction_->length) return ERROR_SUCCESS;
    std::array<std::uint8_t, 15> bytes{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(rip)), bytes.data(), instruction_->length, &read)) return LastError();
    return read == instruction_->length && std::equal(bytes.begin(), bytes.begin() + instruction_->length, instruction_->bytes.begin())
        ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD NativePrivateExecutionPage::RestorePage(HANDLE process, Page& page)
{
    if (!page.owned) return ERROR_SUCCESS;
    if (page.conflict) return ERROR_INVALID_DATA;
    DWORD actual = 0;
    if (const auto error = ReadProtection(process, page, actual)) return error;
    if (actual != page.original && actual != page.nonExecutable) return ERROR_INVALID_DATA;
    if (actual != page.original) {
        page.indeterminate = true;
        DWORD previous = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<void*>(page.site.site.address),
            static_cast<SIZE_T>(kPageBytes), page.original, &previous)) return LastError();
        if (previous != page.nonExecutable) { page.conflict = true; return ERROR_INVALID_DATA; }
    }
    if (const auto error = ReadProtection(process, page, actual)) return error;
    if (actual != page.original) return ERROR_INVALID_DATA;
    page.expected = page.original;
    page.owned = page.indeterminate = false;
    return ERROR_SUCCESS;
}

DWORD NativePrivateExecutionPage::Restore(HANDLE process)
{
    DWORD first = ERROR_SUCCESS;
    for (auto& page : pages_) {
        const auto error = RestorePage(process, page); // 一页失败不能跳过其它页，不能把失败页清账。
        if (!first && error) first = error;
    }
    if (!first) { instruction_.reset(); externalFetchPage_.reset(); }
    return first;
}

bool NativePrivateExecutionPage::OwnsProtection() const noexcept
{
    return std::any_of(pages_.begin(), pages_.end(), [](const auto& page) { return page.owned; });
}

void NativePrivateExecutionPage::ProcessExited() noexcept
{
    for (auto& page : pages_) page.owned = page.indeterminate = false;
    instruction_.reset(); externalFetchPage_.reset();
}

bool NativePrivateExecutionPage::Contains(std::uint64_t address) const noexcept
{
    return FindPage(address) != nullptr;
}

const NativePrivateExecutionPage::Page* NativePrivateExecutionPage::FindPage(std::uint64_t address) const noexcept
{
    for (const auto& page : pages_) {
        if (page.active && address >= page.site.site.address && address - page.site.site.address < kPageBytes) return &page;
    }
    return nullptr;
}

bool NativePrivateExecutionPage::IsExecuteFault(const DEBUG_EVENT& event, std::uint64_t rip) const noexcept
{
    if (event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT || !event.u.Exception.dwFirstChance) return false;
    const auto& exception = event.u.Exception.ExceptionRecord;
    if (exception.ExceptionCode != EXCEPTION_ACCESS_VIOLATION || exception.NumberParameters < 2 ||
        exception.ExceptionInformation[0] != 8 || !Contains(exception.ExceptionInformation[1]) ||
        reinterpret_cast<std::uintptr_t>(exception.ExceptionAddress) != rip) return false;
    const auto* page = FindPage(exception.ExceptionInformation[1]); // 不依赖初始范围的连续偏移。
    const auto fault = exception.ExceptionInformation[1];
    if (!Contains(rip) && (fault <= rip || fault - rip >= 15 ||
        (fault & ~std::uint64_t{4095}) != (rip & ~std::uint64_t{4095}) + 4096)) return false;
    return page && page->owned && !page->indeterminate && !page->conflict && page->expected == page->nonExecutable;
}

DWORD NativePrivateExecutionPage::VerifyFaultSpan(HANDLE process, const DEBUG_EVENT& event, std::uint64_t rip) const
{
    if (!IsExecuteFault(event, rip)) return ERROR_INVALID_DATA;
    if (const auto error = Verify(process)) return error;
    const auto fault = event.u.Exception.ExceptionRecord.ExceptionInformation[1];
    if ((rip & ~std::uint64_t{4095}) == (fault & ~std::uint64_t{4095})) return ERROR_SUCCESS;
    NativeInstructionFetch fetch;
    if (const auto error = NativeStepRuntime::DecodeInstructionFetch(process, rip, fetch); error) return error.code;
    if (fault < rip || fault - rip >= fetch.length) return ERROR_INVALID_DATA;
    if (!Contains(rip)) {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQueryEx(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(rip)), &region, sizeof(region)) != sizeof(region)) return LastError();
        const auto protection = region.Protect & 0xff;
        if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD) || (protection != PAGE_EXECUTE &&
            protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)) return ERROR_INVALID_ADDRESS;
    }
    return ERROR_SUCCESS;
}

} // namespace ks::cli::action_analyze::control
