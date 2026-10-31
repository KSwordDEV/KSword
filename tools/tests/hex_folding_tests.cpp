#include "../../shared/evidence/memory_workbench/HexViewport.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <vector>

using View = ksword::memwb::HexViewport;
int RunMemwbViewportTests();
static int checks=0, failures=0;
#define CHECK(...) do { ++checks; if(!(__VA_ARGS__)) { ++failures; std::cerr<<"FAIL "<<__LINE__<<'\n'; } } while(false)
int main() {
    View empty(0,0x2FFF);
    CHECK(empty.RowCount()==768);
    empty.SetFoldUnknown(true);
    CHECK(empty.RowCount()==2 && empty.RowStartAddress(1)==0x2FF0);
    CHECK(empty.PeekByte(0x1000).state==View::ByteState::NotLoaded);
    empty.MarkInFlight({0x1000,1,0});
    CHECK(empty.RowCount()==2 && empty.PeekByte(0x1000).state==View::ByteState::Pending);
    empty.MarkUnreadable({0,1,0},empty.SourceRevision());
    CHECK(empty.RowCount()==2 && empty.PeekByte(0).state==View::ByteState::Unreadable);
    empty.SetCaret(0x1000,false);
    CHECK(empty.RowCount()==3 && empty.RowStartAddress(*empty.RowOfAddress(0x1000))==0x1000);
    empty.RevealAddress(0x2000);
    CHECK(empty.RowCount()==4 && empty.RowStartAddress(*empty.RowOfAddress(0x2000))==0x2000);
    empty.SetFoldUnknown(false);
    CHECK(empty.RowCount()==768 && empty.GetSelection().caret==0x1000);
    empty.SetFoldUnknown(true);
    CHECK(empty.RowCount()==3);
    const auto old=empty.SourceRevision();
    empty.InvalidateAll(old+1);
    CHECK(empty.RowCount()==3 && !empty.IsKnownUnreadable(0));
    CHECK(empty.MarkUnreadable({0,1,0},old)==View::PageResult::RejectedStaleRevision);

    // Independent byte-bitmap oracle: preserve all value rows and the endpoints
    // of each maximal unknown byte run, regardless of the cache's byte state.
    const unsigned widths[]={8,16,32,48,64};
    for(unsigned seed=0;seed<25;++seed) for(const auto width:widths) {
        const std::uint64_t first=seed%11, last=0x7FFF-seed%13;
        View view(first,last,width);
        view.SetFoldUnknown(true);
        std::vector<std::uint8_t> valid(0x8000,0), bytes(4096,0x42), mask(4096,0);
        for(std::uint64_t page=0;page<8;++page) {
            const auto kind=(page+seed)%5;
            if(kind==0) continue; // NotLoaded.
            if(kind==1) { view.MarkInFlight({page*4096,1,0}); continue; } // Pending.
            if(kind==2) { view.MarkUnreadable({page*4096,1,0},view.SourceRevision()); continue; }
            for(std::size_t i=0;i<4096;++i) {
                mask[i]=static_cast<std::uint8_t>(kind==3 || ((i+seed*7)/37)%11==0);
                valid[page*4096+i]=mask[i];
            }
            view.InsertPage(page*4096,bytes,mask,view.SourceRevision());
        }
        const auto caret=first+1234, reveal=first+6578, pending=last-251;
        view.SetCaret(caret,false); view.RevealAddress(reveal);
        view.SetFoldProtection([pending](auto low,auto high) -> std::optional<View::AddressRange> {
            return low<=pending && high>=pending ? std::optional<View::AddressRange>({pending,pending}) : std::nullopt;
        });
        const auto verify=[&] {
            const auto w=view.BytesPerRow();
            const auto base=first-first%w;
            std::vector<bool> keep(static_cast<std::size_t>((last-base)/w+1),false);
            std::uint64_t address=first;
            while(address<=last) {
                if(valid[address]) { keep[(address-base)/w]=true; ++address; continue; }
                const auto begin=address;
                while(address<=last && !valid[address]) ++address;
                keep[(begin-base)/w]=true; keep[(address-1-base)/w]=true;
            }
            keep[(caret-base)/w]=true; keep[(reveal-base)/w]=true; keep[(pending-base)/w]=true;
            std::uint64_t visual=0;
            for(std::size_t raw=0;raw<keep.size();++raw) if(keep[raw]) {
                const auto expected=base+raw*w;
                CHECK(view.RowStartAddress(visual)==expected);
                CHECK(view.RowOfAddress(std::max(expected,first))==visual);
                ++visual;
            }
            CHECK(view.RowCount()==visual);
        };
        verify();
        // Changing width must rebuild per-page summaries, including 48-byte rows
        // spanning two pages; it cannot reuse stale row summaries.
        if(width!=48) { view.SetBytesPerRow(48); verify(); }
    }
    View eviction(0,0x2FFF,16,1);
    eviction.SetFoldUnknown(true);
    std::vector<std::uint8_t> data(4096,0), full(4096,1);
    eviction.InsertPage(0,data,full,eviction.SourceRevision());
    CHECK(eviction.RowCount()==258);
    eviction.InsertPage(0x1000,data,full,eviction.SourceRevision());
    CHECK(eviction.RowCount()==260 && eviction.PeekByte(0).state==View::ByteState::NotLoaded);
    eviction.MarkUnreadable({0x1000,1,0},eviction.SourceRevision());
    CHECK(eviction.RowCount()==2);
    View arrows(0,0x2FFF);
    arrows.SetFoldUnknown(true); arrows.SetCaret(15,false);
    CHECK(arrows.MoveCaretByBytes(1,false) && arrows.GetSelection().caret==0x2FF0);
    CHECK(arrows.MoveCaretByBytes(-1,false) && arrows.GetSelection().caret==15);

    View sparse(0,std::numeric_limits<std::uint64_t>::max());
    sparse.SetFoldUnknown(true);
    CHECK(sparse.RowCount()==2 && sparse.RowStartAddress(1)==0xFFFFFFFFFFFFFFF0);
    unsigned protectionCalls=0;
    sparse.SetFoldProtection([&](auto low,auto high) -> std::optional<View::AddressRange> {
        ++protectionCalls;
        return low<=0x8000000000000000 && high>=0x8000000000000000
            ? std::optional<View::AddressRange>({0x8000000000000000,0x8000000000000000}) : std::nullopt;
    });
    CHECK(sparse.RowCount()==3 && protectionCalls<8);
    sparse.RevealAddress(0x10000);
    CHECK(sparse.RowCount()==4);
    View largePatch(0,UINT64_MAX);
    largePatch.SetFoldUnknown(true);
    unsigned rangeQueries=0;
    constexpr std::uint64_t patchFirst=0x100000000, patchLast=patchFirst+64*1024*1024-1;
    largePatch.SetFoldProtection([&](auto low,auto high) -> std::optional<View::AddressRange> {
        ++rangeQueries;
        return low<=patchLast && high>=patchFirst ? std::optional<View::AddressRange>({patchFirst,patchLast}) : std::nullopt;
    });
    CHECK(rangeQueries<4 && largePatch.RowCount()==64*1024*1024/16+2);
    auto plan=sparse.PlanFetch(0,4,2,true);
    std::uint64_t pages=0;
    for(const auto& range:plan) pages+=range.pageCount;
    CHECK(pages<=16);
    auto explicitPlan=sparse.PlanAddressFetch(0x8000,0x8FFF,0,true);
    CHECK(!explicitPlan.empty() && explicitPlan.front().firstPageStart==0x8000);
    const auto start=std::chrono::steady_clock::now();
    std::uint64_t checksum=0;
    for(int n=0;n<1000000;++n) checksum+=sparse.RowStartAddress(static_cast<std::uint64_t>(n)%sparse.RowCount()).value_or(0);
    const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
    std::cout<<"fold mapping: 1000000 queries, "<<ms<<" ms, checksum="<<checksum<<'\n';
    std::cout<<"Hex folding: "<<checks<<" checks, "<<failures<<" failures\n";
    failures += RunMemwbViewportTests();
    return failures ? 1 : 0;
}
