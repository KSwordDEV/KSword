"""Exercise the production v4 observer admission and lookup with a simulated loaded-image witness."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "KswordARKDriver/src/features/dyndata"
OUT = ROOT / "tools/tests/x64/Release"
OBJ = OUT / "ProcessObserverDriver/obj"

PRELUDE = r'''
#include <windows.h>
#include <winternl.h>
#include <strsafe.h>
#include <cassert>
#include <cstring>
#include <vector>
#include "WIRE_HEADER"
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((s)>=0)
#endif
#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003eUL)
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xc0000059UL)
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000dUL)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif
#define RtlStringCbPrintfA StringCbPrintfA
#define RtlStringCbLengthA StringCbLengthA
#define KSWORD_BUGCHECK_ID_RSDS 2
#define KSWORD_BUGCHECK_ID_PE 1
struct KSWORD_BUGCHECK_IMAGE_ID {
    ULONG Flags, ImageSize, TimeDateStamp, PdbAge; NTSTATUS Status;
    UCHAR PdbGuid[16]; CHAR PdbName[64];
} actual;
void KswordARKBugcheckIdentityRead(ULONG_PTR,ULONG,void*,KSWORD_BUGCHECK_IMAGE_ID* value) { *value=actual; }
struct KSW_DYN_V4_MODULE_STATE {
    bool Occupied; ULONG StoredItemCount;
    KSW_DYN_V4_MODULE_STATUS_ENTRY PublicEntry;
    struct { KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY PublicEntry; } Groups[1];
    KSW_DYN_V4_ITEM_PACKET Items[10];
};
struct { KSW_DYN_V4_MODULE_STATE Modules[1]; } g_KswordDynDataV4State;
int g_KswordDynDataV4Lock = 0;
void KswordARKAcquirePushLockShared(int* value) { assert(*value == 0); ++*value; }
void KswordARKReleasePushLockShared(int* value) { assert(*value == 1); --*value; }
'''

TESTS = r'''
int main() {
    static constexpr ULONG ids[] = {57,58,59,62,63,64,66,122,123,166};
    std::vector<unsigned long long> words((KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE + 10*sizeof(KSW_DYN_V4_ITEM_PACKET) + 7)/8);
    auto& request=*reinterpret_cast<KSW_APPLY_DYN_PROFILE_V4_REQUEST*>(words.data());
    auto& group=request.capabilityGroups[0];
    group.groupId=KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY; group.requiredItemCount=10;
    request.capabilityGroupCount=1; request.itemCount=10;
    auto& pe=request.module.image; pe.machine=IMAGE_FILE_MACHINE_AMD64; pe.classId=KSW_DYN_PROFILE_CLASS_NTOSKRNL;
    pe.sizeOfImage=0x1000000; pe.timeDateStamp=0x12345678;
    request.module.pdb.pdbAge=1;
    strcpy_s(request.module.pdb.pdbGuid,"123456789ABCDEF01234567890ABCDEF");
    strcpy_s(request.module.pdb.pdbName,"ntkrnlmp.pdb");
    GUID id={0x12345678,0x9abc,0xdef0,{0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef}};
    memcpy(actual.PdbGuid,&id,sizeof(id)); actual.Flags=3; actual.PdbAge=1;
    actual.ImageSize=pe.sizeOfImage; actual.TimeDateStamp=pe.timeDateStamp; strcpy_s(actual.PdbName,"NTKRNLMP.PDB");
    auto check=[&]{return KswordARKDynDataV4VerifyProcessObserverProfile(&request,&pe);};
    for (ULONG i=0;i<10;++i) { auto& item=request.items[i]; item.itemId=ids[i];
        item.capabilityGroupId=group.groupId; item.flags=KSW_DYN_V4_ITEM_FLAG_REQUIRED;
        item.itemKind=KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET; item.valueLow=0x20+8*i; }
    assert(check()==STATUS_SUCCESS);
    ++actual.PdbAge; assert(check()==STATUS_REVISION_MISMATCH); --actual.PdbAge;
    actual.PdbGuid[15]^=1; assert(check()==STATUS_REVISION_MISMATCH); actual.PdbGuid[15]^=1;
    actual.PdbName[6]='x'; assert(check()==STATUS_REVISION_MISMATCH); strcpy_s(actual.PdbName,"NTKRNLMP.PDB");
    for(ULONG i=0;i<10;++i) {
        auto& v=request.items[i]; const auto saved=v;
        v.itemKind=KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA; assert(check()==STATUS_INVALID_PARAMETER); v=saved;
        v.valueLow++; assert(check()==STATUS_INVALID_PARAMETER); v=saved;
        v.aux0=1; assert(check()==STATUS_INVALID_PARAMETER); v=saved;
        v.capabilityGroupId=5; assert(check()==STATUS_INVALID_PARAMETER); v=saved;
        v.itemId=ids[(i+1)%10]; assert(check()==STATUS_INVALID_PARAMETER); v=saved;
    }
    request.itemCount=9; assert(check()==STATUS_INVALID_PARAMETER); request.itemCount=10;
    auto& slot=g_KswordDynDataV4State.Modules[0]; KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT layout;
    assert(!KswordARKDynDataV4SnapshotProcessObserver(&layout) && !layout.VadRoot);
    slot.Occupied=true; slot.StoredItemCount=10; slot.PublicEntry.module.image=pe;
    slot.PublicEntry.capabilityGroupCount=1; slot.PublicEntry.statusFlags=KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED;
    slot.Groups[0].PublicEntry.groupId=group.groupId; memcpy(slot.Items,request.items,sizeof(slot.Items));
    assert(KswordARKDynDataV4SnapshotProcessObserver(&layout) && layout.VadCount==0x68 && layout.Pid==0x20);
    slot.Items[8].valueHigh=1; assert(!KswordARKDynDataV4SnapshotProcessObserver(&layout) && !layout.Pid);
    assert(g_KswordDynDataV4Lock==0);
}
'''


def main():
    OBJ.mkdir(parents=True, exist_ok=True)
    wire = (ROOT / "shared/driver/KswordArkDynDataIoctl.h").as_posix()
    layout = (DRIVER / "dyndata_v4_internal.h").read_text("utf-8-sig").split(
        "typedef struct _KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT", 1)[1].split("} KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT;", 1)[0]
    code = "\n".join(s for s in (DRIVER / "dyndata_v4_process_observer.c").read_text("utf-8-sig").splitlines()
                     if not s.startswith("#include"))
    src = OBJ / "observer_driver_fixture.cpp"
    src.write_text(PRELUDE.replace("WIRE_HEADER", wire) + "\ntypedef struct _KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT"
                   + layout + "} KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT;\n" + code + TESTS, encoding="utf-8")
    binary = OUT / "process_observer_driver_tests.exe"
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++20", "/utf-8", "/W4", "/WX", str(src),
                    "/Fe:" + str(binary)], cwd=OBJ, check=True)
    subprocess.run([str(binary)], cwd=OBJ, check=True)
    print("PROCESS_OBSERVER_DRIVER_PASS")


if __name__ == "__main__":
    main()
