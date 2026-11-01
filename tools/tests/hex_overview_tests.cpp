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
                source[index]=bytes[at]=static_cast<std::uint8_t>((index+seed)%5 ? ((index+seed)%3 ? 0xA5 : 0x41) : 0);
                valid[index]=mask[at]=static_cast<std::uint8_t>(((index+seed*7)/29)%7==0);
            }
            sample.InsertPage(page*4096,bytes,mask,sample.SourceRevision());
        }
        for(const bool fold:{false,true}) {
            sample.SetFoldUnknown(fold);
            const View raw(first,last,width);
            std::vector<View::AddressRange> known;
            if(fold) for(std::uint64_t row=0;row<raw.RowCount();++row) {
                const auto span=raw.RowValidSpan(row).value();
                bool read=false;
                for(auto address=span.first;address<=span.last;++address) if(valid[address]) read=true;
                if(read) known.push_back(span);
            }
            CHECK(sample.KnownRowCount()==known.size());
            for(std::uint64_t row=0;row<known.size();++row) {
                CHECK(sample.KnownRowSpan(row)==known[row]);
                CHECK(sample.KnownRowOfAddress(known[row].first)==row);
            }
            for(std::uint64_t address=first;address<=last;address+=13) {
                const auto rawRow=raw.UnfoldedRowOfAddress(address).value();
                const auto it=std::lower_bound(known.begin(),known.end(),rawRow,[&](const auto& span,auto index) {
                    return raw.UnfoldedRowOfAddress(span.first).value()<index;
                });
                const auto index=static_cast<std::uint64_t>(it-known.begin());
                CHECK(sample.KnownRowAtOrAfter(address)==index);
                CHECK(sample.KnownRowOfAddress(address)==(it!=known.end() && address>=it->first && address<=it->last
                    ? std::optional<std::uint64_t>(index) : std::nullopt));
            }
            for(const int scale:{0,1,2}) for(const auto requested:{1U,3U,17U,401U,4096U}) {
                const bool fixed=scale==1,knownOnly=scale==2;
                const View unfolded(first,last,width);
                const auto& geometry=fixed ? unfolded : sample;
                const auto results=sample.OverviewBins(requested,fixed,knownOnly);
                CHECK(!knownOnly || results.size()==std::min<std::size_t>(requested,known.size()));
                for(const auto& bin:results) {
                    std::uint64_t total=0,read=0,nonzero=0,ascii=0;
                    for(auto row=bin.firstRow;row<bin.firstRow+bin.rowCount;++row) {
                        const auto span=knownOnly ? known[row] : geometry.RowValidSpan(row).value();
                        for(auto address=span.first;address<=span.last;++address) {
                            ++total;
                            if(valid[address]) { ++read; if(source[address]) ++nonzero; if(source[address]>=32 && source[address]<127) ++ascii; }
                        }
                    }
                    CHECK(bin.totalBytes==static_cast<double>(total));
                    CHECK(bin.readBytes==read && bin.nonZeroBytes==nonzero && bin.asciiBytes==ascii);
                }
            }
        }
    }
    View asciiSample(0,7);
    asciiSample.SetOverviewEnabled(true);
    bytes.assign(4096,0x42);mask.assign(4096,0);
    const std::uint8_t asciiEdges[]={0x1F,0x20,0x7E,0x7F,0,0xFF,0x41,9};
    std::copy(std::begin(asciiEdges),std::end(asciiEdges),bytes.begin());
    std::fill(mask.begin(),mask.begin()+8,std::uint8_t{1});mask[6]=0;
    asciiSample.InsertPage(0,bytes,mask,asciiSample.SourceRevision());
    auto asciiBin=asciiSample.OverviewBins(1)[0];
    CHECK(asciiBin.readBytes==7 && asciiBin.nonZeroBytes==6 && asciiBin.asciiBytes==2);
    asciiSample.MarkUnreadable({0,1,0},asciiSample.SourceRevision());
    CHECK(asciiSample.OverviewBins(1)[0].asciiBytes==0);
    constexpr std::uint64_t far=1ULL<<48;
    View sparse(0,far+4095);
    sparse.SetOverviewEnabled(true); sparse.SetFoldUnknown(true);
    sparse.InsertPage(0,zero,all,sparse.SourceRevision());
    sparse.InsertPage(far,zero,all,sparse.SourceRevision());
    CHECK(sparse.KnownRowCount()==512 && sparse.KnownRowSpan(256)->first==far);
    auto knownBins=sparse.OverviewBins(1,true,true);
    CHECK(knownBins.size()==1 && knownBins[0].totalBytes==8192 && knownBins[0].readBytes==8192);
    sparse.RevealAddress(far/2);sparse.SetCaret(far/3,false);
    CHECK(sparse.KnownRowCount()==512 && !sparse.KnownRowOfAddress(far/2));
    sparse.SetCaret(0,false);sparse.SetFoldUnknown(false);sparse.SetFoldUnknown(true);
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
    fullSpace.RevealAddress(1ULL<<48);
    CHECK(fullSpace.KnownRowCount()==0 && fullSpace.OverviewBins(512,true,true).empty());
    CHECK(fullSpace.OverviewRowAt(11,51,true,true)==0);
    // Remove the temporary explicit row for the legacy projected assertion.
    fullSpace.SetFoldUnknown(false);fullSpace.SetFoldUnknown(true);
    CHECK(fullSpace.OverviewBins(1)[0].totalBytes==32);
    CHECK(fullSpace.OverviewBins(1,true)[0].totalBytes==18446744073709551616.0);
    evicted.SetFoldUnknown(true);
    CHECK(evicted.KnownRowCount()==256 && evicted.KnownRowSpan(0)->first==4096);
    evicted.MarkUnreadable({4096,1,0},evicted.SourceRevision());
    CHECK(!evicted.KnownRowCount() && evicted.OverviewBins(1,true,true).empty());
    evicted.InsertPage(0,zero,all,evicted.SourceRevision());
    evicted.InvalidateAll(evicted.SourceRevision()+1);
    CHECK(!evicted.KnownRowCount() && evicted.OverviewBins(1,true,true).empty());
    const auto start=std::chrono::steady_clock::now();
    for(int n=0;n<100;++n) CHECK(sparse.OverviewBins(1000).size()==514);
    std::cout << "SPARSE_OVERVIEW_100_REBUILDS_MS=" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count() << '\n';
    std::cout << "Overview: "<<checks<<" checks, "<<failures<<" failures\n";
    return failures ? 1 : 0;
}
