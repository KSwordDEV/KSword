#include "../../shared/evidence/memory_workbench/HexViewport.h"
#include <chrono>
#include <iostream>
#include <limits>

using View = ksword::memwb::HexViewport;
int RunMemwbViewportTests();
static int checks=0, failures=0;
#define CHECK(...) do { ++checks; if(!(__VA_ARGS__)) { ++failures; std::cerr<<"FAIL "<<__LINE__<<'\n'; } } while(false)
int main() {
    View view(0,0x2FFF);
    CHECK(view.RowCount()==768);
    view.SetFoldUnknown(true);
    CHECK(view.RowCount()==768);
    CHECK(view.MarkUnreadable({0,1,0},view.SourceRevision())==View::PageResult::Accepted);
    CHECK(view.RowCount()==514 && view.RowStartAddress(0)==0 && view.RowStartAddress(1)==0xFF0);
    CHECK(view.RowStartAddress(2)==0x1000);
    CHECK(view.MarkUnreadable({0x1000,1,0},view.SourceRevision())==View::PageResult::Accepted);
    CHECK(view.RowCount()==258 && view.RowStartAddress(1)==0x1FF0 && view.RowStartAddress(2)==0x2000);
    CHECK(view.MoveCaretByRows(1,false) && view.GetSelection().caret==0x1FF0);
    CHECK(view.MoveCaretByRows(-1,false) && view.GetSelection().caret==0);
    view.SetCaret(0x1000,false);
    CHECK(view.RowCount()==259);
    CHECK(view.RowStartAddress(*view.RowOfAddress(0x1000))==0x1000);
    CHECK(view.SelectedRange()->first==0x1000);
    view.SetFoldUnknown(false);
    CHECK(view.RowCount()==768 && view.GetSelection().caret==0x1000);
    view.SetFoldUnknown(true);
    CHECK(view.RowCount()==259);
    std::vector<std::uint8_t> data(4096,0), mask(4096,1);
    CHECK(view.InsertPage(0x1000,data,mask,view.SourceRevision())==View::PageResult::Accepted);
    CHECK(view.RowCount()==514 && view.PeekByte(0x1000).state==View::ByteState::Valid);
    CHECK(view.RowStartAddress(*view.RowOfAddress(0x1000))==0x1000);
    const auto old=view.SourceRevision();
    view.InvalidateAll(old+1);
    CHECK(view.RowCount()==768 && !view.IsKnownUnreadable(0));
    CHECK(view.MarkUnreadable({0,1,0},old)==View::PageResult::RejectedStaleRevision);
    CHECK(view.RowCount()==768);

    View sparse(0,std::numeric_limits<std::uint64_t>::max());
    sparse.SetFoldUnknown(true);
    sparse.NoteUnreadableRange(0x1000,0xFFFFFFFFFFFFEFFF);
    CHECK(sparse.RowStartAddress(257)==0xFFFFFFFFFFFFEFF0);
    auto plan=sparse.PlanFetch(255,8,2,true);
    std::uint64_t pages=0;
    for(const auto& range:plan) {
        pages+=range.pageCount;
        CHECK(range.firstPageStart < 0x1000 || range.firstPageStart > 0xFFFFFFFFFFFFEFFF);
    }
    CHECK(pages<=12);
    auto explicitPlan=sparse.PlanAddressFetch(0x8000,0x8FFF,0,true);
    CHECK(!explicitPlan.empty() && explicitPlan.front().firstPageStart==0x8000);
    sparse.SetBytesPerRow(48);
    for(std::uint64_t row=0;row<sparse.RowCount();++row) {
        const auto address=sparse.RowStartAddress(row);
        CHECK(address.has_value());
        if(address) CHECK(sparse.RowOfAddress(std::max(*address,sparse.FirstAddress()))==row);
    }
    View partial(7,0x1007,48);
    partial.SetFoldUnknown(true);
    partial.NoteUnreadableRange(7,0x1007);
    CHECK(partial.RowCount()==2 && partial.RowStartAddress(1)==4080);
    partial.SetCaret(1500,false);
    CHECK(partial.RowCount()==3 && partial.RowStartAddress(*partial.RowOfAddress(1500))==1488);
    partial.SetFoldUnknown(false);
    CHECK(partial.RowCount()==86);

    View protectedView(0,0x4FFF);
    protectedView.SetFoldUnknown(true);
    protectedView.NoteUnreadableRange(0x1000,0x3FFF);
    const auto foldedCount=protectedView.RowCount();
    protectedView.RevealAddress(0x2100);
    CHECK(protectedView.RowCount()==foldedCount+1);
    CHECK(protectedView.RowStartAddress(*protectedView.RowOfAddress(0x2100))==0x2100);
    protectedView.RevealAddress(0x2200);
    CHECK(protectedView.RowCount()==foldedCount+1);
    CHECK(protectedView.RowStartAddress(*protectedView.RowOfAddress(0x2100))!=0x2100);
    bool pending=true;
    protectedView.SetFoldProtection([&](auto first,auto last){return pending && first<=0x2000 && last>=0x2000;});
    CHECK(protectedView.RowCount()==1280);
    pending=false;
    protectedView.RefreshFoldProtection();
    CHECK(protectedView.RowCount()==foldedCount+1);
    protectedView.InsertPage(0x2000,data,mask,protectedView.SourceRevision());
    protectedView.MarkInFlight({0x3000,1,0});
    protectedView.NoteUnreadableRange(0x1000,0x3FFF);
    CHECK(!protectedView.IsKnownUnreadable(0x2000));
    CHECK(!protectedView.IsKnownUnreadable(0x3000));
    CHECK(protectedView.PeekByte(0x2000).state==View::ByteState::Valid);
    CHECK(protectedView.PeekByte(0x3000).state==View::ByteState::Pending);
    View arrows(0,0x2FFF);
    arrows.SetFoldUnknown(true);
    arrows.NoteUnreadableRange(0x1000,0x1FFF);
    arrows.SetCaret(0x100F,false);
    CHECK(arrows.MoveCaretByBytes(1,false) && arrows.GetSelection().caret==0x1FF0);
    CHECK(arrows.MoveCaretByBytes(-1,false) && arrows.GetSelection().caret==0x100F);

    // Mapping across a multi-exabyte hole must depend on index size, never address count.
    const auto start=std::chrono::steady_clock::now();
    std::uint64_t checksum=0;
    for(int n=0;n<1000000;++n) checksum+=sparse.RowStartAddress(static_cast<std::uint64_t>(n)%sparse.RowCount()).value_or(0);
    const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
    std::cout<<"fold mapping: 1000000 queries, "<<ms<<" ms, checksum="<<checksum<<'\n';
    std::cout<<"Hex folding: "<<checks<<" checks, "<<failures<<" failures\n";
    failures += RunMemwbViewportTests();
    return failures ? 1 : 0;
}
