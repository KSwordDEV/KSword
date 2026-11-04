"""Validate the production PiDDB client against malformed transport replies."""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <cassert>
#include <cstring>
#include <iostream>
#include "SOURCE"
static int scenario=0;
ksword::ark::IoResult ksword::ark::DriverClient::deviceIoControl(unsigned long code,void* input,unsigned long inputBytes,
    void* output,unsigned long outputBytes,DriverHandle*) const {
    IoResult r{};r.ok=true;
    if(code==IOCTL_KSWORD_ARK_QUERY_PIDDB) {
        assert(inputBytes==sizeof(KSWORD_ARK_QUERY_PIDDB_REQUEST));
        auto* q=static_cast<KSWORD_ARK_QUERY_PIDDB_RESPONSE*>(output);
        q->version=KSWORD_ARK_PIDDB_PROTOCOL_VERSION;q->rowSize=sizeof(KSWORD_ARK_PIDDB_ROW);
        q->size=KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE+sizeof(KSWORD_ARK_PIDDB_ROW);
        q->totalRows=1;q->returnedRows=1;q->rows[0].entryAddress=0x12345;wcscpy_s(q->rows[0].driverName,L"fixture.sys");
        r.bytesReturned=q->size;
        if(scenario==1)q->version++;
        if(scenario==2)q->rowSize++;
        if(scenario==3)q->returnedRows=2;
        if(scenario==4)q->size=KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE;
        if(scenario==5)r.bytesReturned=outputBytes+1;
        if(scenario==6)r.bytesReturned=1;
    } else {
        assert(code==IOCTL_KSWORD_ARK_DELETE_PIDDB && inputBytes==sizeof(KSWORD_ARK_DELETE_PIDDB_REQUEST));
        auto* request=static_cast<KSWORD_ARK_DELETE_PIDDB_REQUEST*>(input);
        assert(request->expectedEntryAddress==0x12345 && request->flags==(KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE|KSWORD_ARK_PIDDB_DELETE_FLAG_UI_CONFIRMED));
        auto* p=static_cast<KSWORD_ARK_DELETE_PIDDB_RESPONSE*>(output);p->version=KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
        p->size=sizeof(*p);p->status=KSWORD_ARK_PIDDB_DELETE_STATUS_OK;p->matchedEntryAddress=0x12345;
        r.bytesReturned=sizeof(*p);
        if(scenario==7)p->version++;
        if(scenario==8)p->size--;
        if(scenario==9)r.bytesReturned--;
    }
    return r;
}
int main() {
    ksword::ark::DriverClient client;
    scenario=0;auto q=client.queryPiDdb(10);assert(q.io.ok && q.entries.size()==1 && q.entries[0].entryAddress==0x12345);
    for(int i=1;i<=6;i++){scenario=i;q=client.queryPiDdb(10);assert(!q.io.ok&&q.io.win32Error==ERROR_INVALID_DATA&&q.entries.empty());}
    ksword::ark::PiDdbEntry entry{};entry.entryAddress=0x12345;entry.driverName=L"fixture.sys";
    scenario=0;auto d=client.deletePiDdbEntry(entry,true,true);assert(d.io.ok && d.status==KSWORD_ARK_PIDDB_DELETE_STATUS_OK);
    for(int i=7;i<=9;i++){scenario=i;d=client.deletePiDdbEntry(entry,true,true);assert(!d.io.ok&&d.io.win32Error==ERROR_INVALID_DATA);}
    std::cout<<"PIDDB_CLIENT_RESPONSE_PASS\n";
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-piddb-client-") as directory:
        directory=Path(directory);source=directory/"fixture.cpp"
        source.write_text(HARNESS.replace("SOURCE",(ROOT/"Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverPiDdb.cpp").as_posix()),encoding="utf-8")
        subprocess.run(["cl","/nologo","/std:c++20","/EHsc","/utf-8","/W4","/WX",str(source),"/Fe:"+str(directory/"fixture.exe")],cwd=directory,check=True)
        subprocess.run([str(directory/"fixture.exe")],cwd=directory,check=True)

if __name__=="__main__":
    main()
