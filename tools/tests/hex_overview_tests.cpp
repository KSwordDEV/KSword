#include "../../shared/evidence/memory_workbench/HexViewport.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <vector>

using View = ksword::memwb::HexViewport;
static int checks = 0, failures = 0;
#define CHECK(...) do { ++checks; if (!(__VA_ARGS__)) { ++failures; std::cerr << "FAIL " << __LINE__ << '\n'; } } while (false)
int main() {
    View view(0,8191);
    CHECK(!view.OverviewEnabled());
    std::vector<std::uint8_t> bytes(4096,0xFF), mask(4096,0);
    std::fill(mask.begin(),mask.begin()+128,std::uint8_t{1});
    std::fill(bytes.begin(),bytes.begin()+64,std::uint8_t{0});
    view.InsertPage(0,bytes,mask,view.SourceRevision());
    view.SetOverviewEnabled(true); // Lazy initialization from existing cache.
    auto bins=view.OverviewBins(2);
    CHECK(bins.size()==2 && bins[0].totalBytes==4096 && bins[0].readBytes==128 && bins[0].nonZeroBytes==64);
    CHECK(bins[1].readBytes==0 && bins[1].nonZeroBytes==0 && bins[1].totalBytes==4096);
    auto revision=view.OverviewRevision();
    CHECK(view.InsertPage(0,bytes,{1},view.SourceRevision())==View::PageResult::RejectedBadSize);
    CHECK(view.OverviewRevision()==revision);
    CHECK(view.InsertPage(0,bytes,mask,view.SourceRevision()+1)==View::PageResult::RejectedStaleRevision);
    CHECK(view.OverviewRevision()==revision);
    std::vector<std::uint8_t> all(4096,1), zero(4096,0);
    view.InsertPage(0,zero,all,view.SourceRevision());
    bins=view.OverviewBins(1);
    CHECK(bins[0].readBytes==4096 && bins[0].nonZeroBytes==0 && bins[0].totalBytes==8192);
    view.InsertPage(4096,bytes,all,view.SourceRevision());
    bins=view.OverviewBins(1);
    CHECK(bins[0].readBytes==8192 && bins[0].nonZeroBytes==4096-64);
    view.MarkUnreadable({4096,1,0},view.SourceRevision());
    bins=view.OverviewBins(1);
    CHECK(bins[0].readBytes==4096 && bins[0].nonZeroBytes==0);
    revision=view.OverviewRevision();
    view.MarkInFlight({4096,1,0});
    CHECK(view.OverviewRevision()==revision); // Pending is not accepted read data.
    view.InvalidateAll(view.SourceRevision()+1);
    CHECK(view.OverviewRevision()!=revision && view.OverviewBins(1)[0].readBytes==0);

    View evicted(0,8191,16,1);
    evicted.SetOverviewEnabled(true);
    evicted.InsertPage(0,bytes,all,evicted.SourceRevision());
    CHECK(evicted.OverviewBins(2)[0].readBytes==4096);
    evicted.InsertPage(4096,zero,all,evicted.SourceRevision());
    bins=evicted.OverviewBins(2);
    CHECK(bins[0].readBytes==0 && bins[1].readBytes==4096 && bins[1].nonZeroBytes==0);
    CHECK(evicted.PeekByte(0).state==View::ByteState::NotLoaded);

    // Independent per-byte oracle, including partial first/last rows, 48-byte
    // rows crossing pages, mixed validity and all histogram bin boundaries.
    const unsigned widths[]={8,16,32,48,64};
    for(const auto width:widths) for(unsigned seed=0;seed<12;++seed) {
        const std::uint64_t first=seed%11,last=8191-seed%13;
        View sample(first,last,width);
        sample.SetOverviewEnabled(true);
        std::vector<std::uint8_t> source(8192,0), valid(8192,0);
        for(std::uint64_t page=0;page<2;++page) {
            for(std::size_t at=0;at<4096;++at) {
                const auto index=page*4096+at;
                source[index]=bytes[at]=static_cast<std::uint8_t>((index+seed)%5 ? 0xA5 : 0);
                valid[index]=mask[at]=static_cast<std::uint8_t>(((index+seed*7)/29)%7==0);
            }
            sample.InsertPage(page*4096,bytes,mask,sample.SourceRevision());
        }
        for(const bool fold:{false,true}) {
            sample.SetFoldUnknown(fold);
            for(const auto requested:{1U,3U,17U,401U,4096U}) {
                const auto results=sample.OverviewBins(requested);
                for(const auto& bin:results) {
                    std::uint64_t total=0,read=0,nonzero=0;
                    for(auto row=bin.firstRow;row<bin.firstRow+bin.rowCount;++row) {
                        const auto span=sample.RowValidSpan(row).value();
                        for(auto address=span.first;address<=span.last;++address) {
                            ++total;
                            if(valid[address]) { ++read; if(source[address]) ++nonzero; }
                        }
                    }
                    CHECK(bin.totalBytes==static_cast<double>(total));
                    CHECK(bin.readBytes==read && bin.nonZeroBytes==nonzero);
                }
            }
        }
    }
    constexpr std::uint64_t far=1ULL<<48;
    View sparse(0,far+4095);
    sparse.SetOverviewEnabled(true); sparse.SetFoldUnknown(true);
    sparse.InsertPage(0,zero,all,sparse.SourceRevision());
    sparse.InsertPage(far,zero,all,sparse.SourceRevision());
    bins=sparse.OverviewBins(1);
    CHECK(sparse.RowCount()==514 && bins[0].totalBytes==8224 && bins[0].readBytes==8192 && bins[0].nonZeroBytes==0);
    CHECK(sparse.RowStartAddress(257)==far-16 && sparse.RowStartAddress(258)==far);
    for(std::uint32_t extent:{1U,7U,511U,4096U}) {
        CHECK(sparse.OverviewRowAt(0,extent)==0 && sparse.OverviewRowAt(extent,extent)==sparse.RowCount());
        std::uint64_t previous=0;
        for(std::uint32_t at=0;at<=extent;++at) {
            const auto row=sparse.OverviewRowAt(at,extent);
            CHECK(row>=previous && row<=sparse.RowCount()); previous=row;
        }
    }
    View fullSpace(0,std::numeric_limits<std::uint64_t>::max());
    fullSpace.SetOverviewEnabled(true);
    CHECK(fullSpace.OverviewBins(1)[0].totalBytes==18446744073709551616.0);
    fullSpace.SetFoldUnknown(true);
    CHECK(fullSpace.OverviewBins(1)[0].totalBytes==32);
    const auto start=std::chrono::steady_clock::now();
    for(int n=0;n<100;++n) CHECK(sparse.OverviewBins(1000).size()==514);
    std::cout << "SPARSE_OVERVIEW_100_REBUILDS_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count() << '\n';
    std::cout << "Overview: "<<checks<<" checks, "<<failures<<" failures\n";
    return failures ? 1 : 0;
}
