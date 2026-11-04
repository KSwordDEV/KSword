"""Exercise production R0 event-page rendering without touching a driver."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
text = (ROOT / "KswordCLI/ArkDriverExtended.cpp").read_text(encoding="utf-8-sig")
utf8 = text[text.index("    std::wstring utf8ToWide"):text.index("    template <typename T, typename = void>")]
state = text[text.index("    template <typename T, typename = void>"):text.index("    void printBytes")]
helpers = text[text.index("    // Incremental ring responses are pages:"):text.index("\n}\n\n// commandArkDriverExtended")]
source = r'''
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include "TYPES_HEADER"
#include "REGISTRY_HEADER"
namespace fixture {
using ks::cli::Json;
using JsonFields = std::vector<std::pair<std::wstring, Json>>;
HELPERS
}
int main() {
    using namespace ksword::ark;
    NetworkTrafficPacketResult packet{}; packet.io.ok=true; packet.status=KSWORD_ARK_NETWORK_STATUS_APPLIED;
    packet.totalCount=2; packet.returnedCount=1; packet.capacity=4; packet.nextSequence=7;
    packet.flags=KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED;
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW row{}; row.sequence=7; row.addressFamily=4;
    row.flags=KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4; row.localAddress[0]=127; row.localAddress[3]=1;
    row.capturedLength=2; row.capturedBytes[0]=0xab; row.capturedBytes[1]=0xcd; packet.entries.push_back(row);
    assert(fixture::emitNetworkRing(L"traffic",packet,3,true)==0);
    packet.cursorGapCount=2; packet.flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP;
    assert(fixture::emitNetworkRing(L"traffic",packet,3,true)==6);
    NetworkWfpEventResult wfp{}; wfp.io.ok=true; wfp.status=KSWORD_ARK_NETWORK_STATUS_DISABLED;
    assert(fixture::emitNetworkRing(L"wfp-events",wfp,0,true)==6);
    PiDdbQueryResult pid{}; pid.io.ok=true; pid.queryStatus=KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING;
    assert(fixture::emitPiDdb(pid,true)==5);
    HvmEventResult hvm{}; hvm.io.ok=true; hvm.io.bytesReturned=sizeof(hvm.response);
    hvm.response.version=KSWORD_ARK_HVM_PROTOCOL_VERSION; hvm.response.size=sizeof(hvm.response);
    hvm.response.returnedRows=1; hvm.response.availableRows=1; hvm.response.rows[0].sequence=99;
    assert(fixture::emitHvmEvents(hvm,true)==0);
    hvm.response.returnedRows=KSWORD_ARK_HVM_MAX_EVENT_ROWS+1;
    assert(fixture::emitHvmEvents(hvm,true)==4);
    NetworkTrafficCaptureControlResult control{}; control.io.ok=true;
    control.response.status=KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
    assert(fixture::emitTrafficControl(L"traffic-start",control,true,true)==5);
}
'''

with tempfile.TemporaryDirectory(prefix="ksword-r0-event-rows-") as directory:
    directory = Path(directory)
    cpp = directory / "fixture.cpp"
    cpp.write_text(source.replace("TYPES_HEADER", (ROOT / "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h").as_posix())
                   .replace("REGISTRY_HEADER", (ROOT / "KswordCLI/CommandRegistry.h").as_posix())
                   .replace("HELPERS", utf8 + state + helpers), encoding="utf-8")
    exe = directory / "fixture.exe"
    subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", str(cpp),
                    *[str(ROOT / ("KswordCLI/" + n)) for n in ("CommandRegistry.cpp", "CliArgs.cpp", "CliText.cpp")],
                    "/Fe:" + str(exe), "/link", "Ole32.lib"], cwd=directory, check=True)
    result = subprocess.run([str(exe)], capture_output=True, text=True, check=True)
    docs = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(docs) == 7
    assert docs[0]["data"]["entries"][0]["localAddress"] == "127.0.0.1"
    assert docs[0]["data"]["entries"][0]["capturedHex"] == "abcd"
    assert docs[0]["data"]["pageTruncated"] and docs[0]["status"] == "success"
    assert docs[1]["status"] == "partial" and docs[1]["data"]["cursorGapCount"] == "2"
    assert docs[4]["data"]["entries"][0]["sequence"] == "99"
    assert docs[5]["status"] == "failed" and docs[5]["data"]["entries"] == []
    assert docs[6]["status"] == "unsupported"
    print("R0_EVENT_ROWS_PASS page, gap, disabled, unsupported, HVM bounds, packet prefix")
