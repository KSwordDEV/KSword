/* Exercise production nested-MMU code without executing SVM instructions. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_mmu.h"
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_shadow.h"
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_state.h"
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_msr.h"

static unsigned checks;
static int check(int condition, unsigned line, const char* expression)
{
    ++checks;
    if (!condition) { printf("FAIL line %u: %s\n", line, expression); }
    return condition;
}
#define CHECK(x) do { if (!check((x), __LINE__, #x)) { return 1; } } while (0)
#define PAT 0x0007010600070106ULL
typedef struct _MEMORY {
    KSW_SVM_U64 page[64][512];
    KSW_SVM_U64 failRead, mutateCas;
    unsigned reads, writes, mutation;
} MEMORY;
static MEMORY memory;
static int read_word(void* context, KSW_SVM_U64 address, KSW_SVM_U64* value)
{
    MEMORY* m = (MEMORY*)context;
    if ((address & 7) || address >= sizeof(m->page) || address == m->failRead) { return 0; }
    ++m->reads;
    *value = m->page[address >> 12][(address & 4095) >> 3];
    return 1;
}
static int compare_or(void* context, KSW_SVM_U64 address, KSW_SVM_U64 expected, KSW_SVM_U64 bits)
{
    MEMORY* m = (MEMORY*)context;
    KSW_SVM_U64* slot;
    if ((address & 7) || address >= sizeof(m->page)) { return 0; }
    slot = &m->page[address >> 12][(address & 4095) >> 3];
    if (address == m->mutateCas && !m->mutation++) { *slot ^= 0x1000ULL; }
    if (*slot != expected) { return 0; }
    *slot |= bits;
    ++m->writes;
    return 1;
}
static void reset_memory(void)
{
    memset(&memory, 0, sizeof(memory));
    memory.failRead = memory.mutateCas = ~0ULL;
    memory.page[1][0] = 0x2007;
    memory.page[2][0] = 0x3007;
    memory.page[3][0] = 0x4007;
    memory.page[4][2] = 0x200007;
}
static unsigned walk(KSW_SVM_U64 gpa, unsigned access, KSW_NNPT_WALK* result)
{
    return KswSvmNestedNptWalk(0x1000, gpa, 45, 1, 1, access, read_word, &memory, result);
}
static int test_walk(void)
{
    KSW_NNPT_WALK w;
    unsigned level, pat;
    reset_memory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    CHECK(w.Address == 0x200123 && w.InputAddress == 0x2123 && w.Root == 0x1000);
    CHECK(w.Count == 4 && w.LeafShift == 12 && w.Permissions == 7 && w.Fault == 0);
    CHECK(w.EntryAddress[3] == 0x4010 && memory.writes == 0);
    CHECK(walk(0x3123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 4 && !w.Complete);
    CHECK(KswSvmNestedNptCommitAd(&w, 0, read_word, compare_or, &memory) == KSW_NNPT_UNSUPPORTED);
    for (level = 1; level <= 4; ++level) {
        unsigned slot = level == 4 ? 2 : 0;
        reset_memory();
        memory.page[level][slot] &= ~2ULL;
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_FAULT && w.Fault == 7);
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK && !(w.Permissions & 2));
        memory.page[level][slot] &= ~4ULL;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 5);
        reset_memory();
        memory.page[level][slot] |= KSW_NNPT_NX;
        CHECK(walk(0x2123, KSW_NNPT_EXECUTE, &w) == KSW_NNPT_FAULT && w.Fault == 21);
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK && (w.Permissions & KSW_NNPT_NX));
        CHECK(KswSvmNestedNptWalk(0x1000, 0x2123, 45, 1, 0, 0, read_word, &memory, &w) == KSW_NNPT_FAULT);
        CHECK(w.Fault == 13);
        reset_memory();
        memory.page[level][slot] |= 1ULL << 45;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 13);
        memory.page[level][slot] &= ~1ULL;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 4);
    }
    reset_memory();
    memory.page[1][0] |= 128;
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 13);
    for (pat = 0; pat < 8; ++pat) {
        reset_memory();
        memory.page[4][2] = 0x200000 | KswNptLeafFlags(1, pat);
        CHECK(walk(0x2fff, 0, &w) == KSW_NNPT_OK && w.Address == 0x200fff && w.PatIndex == pat);
        memory.page[3][0] = 0x600000 | KswNptLeafFlags(2, pat);
        CHECK(walk(0x1fffff, 0, &w) == KSW_NNPT_OK && w.Address == 0x7fffff && w.PatIndex == pat);
        CHECK(w.LeafShift == 21 && w.Count == 3);
        memory.page[3][0] |= 1ULL << 13;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 13);
        memory.page[2][0] = 0x40000000 | KswNptLeafFlags(3, pat);
        CHECK(walk(0x3fffffff, 0, &w) == KSW_NNPT_OK && w.Address == 0x7fffffff && w.PatIndex == pat);
        CHECK(w.LeafShift == 30 && w.Count == 2);
        CHECK(KswSvmNestedNptWalk(0x1000, 0x2123, 45, 0, 1, 0, read_word, &memory, &w) == KSW_NNPT_FAULT);
        memory.page[2][0] |= 1ULL << 29;
        CHECK(walk(0x2123, 0, &w) == KSW_NNPT_FAULT && w.Fault == 13);
    }
    reset_memory();
    memory.failRead = 0x3000;
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_UNREADABLE && w.Count == 2 && !w.Complete);
    CHECK(walk(1ULL << 45, 0, &w) == KSW_NNPT_UNSUPPORTED && !w.Complete);
    CHECK(walk(0x2123, 8, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedNptWalk(0x1008, 0, 45, 1, 1, 0, read_word, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedNptWalk(0x1000, 0, 49, 1, 1, 0, read_word, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedNptWalk(0x1000, 0, 45, 1, 1, 0, NULL, &memory, &w) == KSW_NNPT_UNSUPPORTED);
    return 0;
}
static int test_ad(void)
{
    KSW_NNPT_WALK w;
    unsigned level;
    reset_memory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    CHECK(KswSvmNestedNptCommitAd(&w, 1, read_word, compare_or, &memory) == KSW_NNPT_UNSUPPORTED);
    CHECK(memory.writes == 0);
    CHECK(KswSvmNestedNptCommitAd(&w, 0, read_word, compare_or, &memory) == KSW_NNPT_OK);
    CHECK((memory.page[4][2] & 0x60) == 0x20 && w.Complete);
    CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
    CHECK(KswSvmNestedNptCommitAd(&w, 1, read_word, compare_or, &memory) == KSW_NNPT_OK);
    CHECK((memory.page[4][2] & 0x60) == 0x60);
    CHECK((memory.page[1][0] & 0x60) == 0x20);
    for (level = 0; level < 4; ++level) {
        KSW_SVM_U64 old;
        reset_memory();
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
        old = w.EntryValue[level];
        memory.page[level + 1][level == 3 ? 2 : 0] ^= 0x1000;
        CHECK(KswSvmNestedNptCommitAd(&w, 1, read_word, compare_or, &memory) == KSW_NNPT_RETRY);
        CHECK(memory.writes == 0 && !w.Complete);
        CHECK(memory.page[level + 1][level == 3 ? 2 : 0] == (old ^ 0x1000));
        reset_memory();
        CHECK(walk(0x2123, KSW_NNPT_WRITE, &w) == KSW_NNPT_OK);
        old = w.EntryValue[level];
        memory.mutateCas = w.EntryAddress[level];
        CHECK(KswSvmNestedNptCommitAd(&w, 1, read_word, compare_or, &memory) == KSW_NNPT_RETRY);
        CHECK(memory.writes == level && !w.Complete);
        CHECK(memory.page[level + 1][level == 3 ? 2 : 0] == (old ^ 0x1000));
    }
    reset_memory();
    CHECK(walk(0x2123, 0, &w) == KSW_NNPT_OK);
    memory.failRead = 0x4010;
    CHECK(KswSvmNestedNptCommitAd(&w, 0, read_word, compare_or, &memory) == KSW_NNPT_UNREADABLE);
    CHECK(memory.writes == 0 && !w.Complete);
    return 0;
}
static void setup_mmu(KSW_NMMU_CONFIG* config, KSW_NMMU_IO* io)
{
    unsigned i;
    reset_memory();
    for (i = 0; i < 64; ++i) { memory.page[4][i] = (KSW_SVM_U64)i * 4096 | 7; }
    /* NPT12's tables deliberately have different guest and host physical addresses. */
    for (i = 0; i < 4; ++i) { memory.page[4][8 + i] = (KSW_SVM_U64)(16 + i) * 4096 | 7; }
    memory.page[16][0] = 0x9007;
    memory.page[17][0] = 0xa007;
    memory.page[18][0] = 0xb007;
    memory.page[19][2] = 0x18007;
    memory.page[4][24] = 0x28007;
    memset(config, 0, sizeof(*config));
    config->InnerRoot = 0x8000;
    config->OuterRoot = 0x1000;
    config->InnerPat = config->OuterPat = config->HardwarePat = PAT;
    config->InnerBits = config->OuterBits = 45;
    config->InnerPage1Gb = config->OuterPage1Gb = 1;
    config->InnerNx = config->OuterNx = 1;
    config->Epoch = 42;
    io->Read = read_word;
    io->CompareOr = compare_or;
    io->Context = &memory;
}
static int test_mmu(void)
{
    KSW_NMMU_CONFIG config;
    KSW_NMMU_IO io;
    KSW_NMMU_RESULT r;
    KSW_SVM_U64 leaf;
    unsigned pat, access;
    for (access = 0; access <= 2; access += 2) {
        setup_mmu(&config, &io);
        CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, access, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
        CHECK(r.Gpa == 0x2123 && r.Epoch == 42 && r.FaultOwner == 0);
        CHECK(r.Inner.Address == 0x18123 && r.Outer.Address == 0x28123);
        CHECK((r.Leaf & KSW_NNPT_FRAME) == 0x28000 && (r.Leaf & 2) == access);
        CHECK((memory.page[19][2] & 0x60) == (access ? 0x60ULL : 0x20ULL));
        CHECK((memory.page[4][24] & 0x60) == (access ? 0x60ULL : 0x20ULL));
        CHECK((memory.page[4][8] & 0x60) == 0x60 && r.Reads < 256);
        CHECK(KswSvmNestedNptCompose4k(&r.Inner, &r.Outer, PAT, PAT, PAT, &leaf) == KSW_NNPT_OK);
        r.Outer.InputAddress += 4096;
        CHECK(KswSvmNestedNptCompose4k(&r.Inner, &r.Outer, PAT, PAT, PAT, &leaf) == KSW_NNPT_UNSUPPORTED && leaf == 0);
    }
    setup_mmu(&config, &io);
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, KSW_NNPT_EXECUTE, KSW_NMMU_TABLE, &r) == KSW_NNPT_OK);
    CHECK((r.Leaf & 0x62) == 0x62 && r.Inner.Access == KSW_NNPT_WRITE);
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK((r.Leaf & 0x62) == 0x62); /* Already dirty source paths need no second write fault. */
    memory.page[19][2] &= ~0x40ULL;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(!(r.Leaf & 0x42)); /* Clearing either D bit re-arms first-write tracking. */
    memory.page[19][2] |= 0x40;
    memory.page[4][24] &= ~0x40ULL;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(!(r.Leaf & 0x42));
    memory.page[4][24] |= 0x40;
    memory.page[19][2] &= ~2ULL;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(!(r.Leaf & 2)); /* Dirty does not grant write permission. */
    for (pat = 0; pat < 8; ++pat) {
        unsigned type = (unsigned)((PAT >> (pat * 8)) & 255);
        setup_mmu(&config, &io);
        memory.page[19][2] = 0x18000 | KswNptLeafFlags(1, pat);
        if (type == 0 || type == 6) {
            CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
            CHECK((r.Leaf & 0x98) == (type == 0 ? 0x18ULL : 0ULL));
        } else {
            CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED);
            CHECK(!r.Leaf && !(memory.page[19][2] & 0x60));
        }
    }
    setup_mmu(&config, &io);
    memory.page[19][2] |= 0x18;
    config.HardwarePat = 0x0606060606060606ULL;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED && !r.Leaf);
    setup_mmu(&config, &io);
    memory.page[19][2] = 0;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.Leaf && r.FaultOwner == KSW_NMMU_INNER && r.FaultAddress == 0x2123 && r.FaultInfo == (KSW_NMMU_FINAL | 4));
    setup_mmu(&config, &io);
    memory.page[4][8] &= ~2ULL;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.Leaf && r.FaultOwner == KSW_NMMU_OUTER_TABLE && r.FaultAddress == 0x8000 && r.FaultInfo == (KSW_NMMU_TABLE | 7));
    setup_mmu(&config, &io);
    memory.page[4][24] = 0;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_FAULT);
    CHECK(!r.Leaf && r.FaultOwner == KSW_NMMU_OUTER_DATA && r.FaultAddress == 0x18123 && r.FaultInfo == (KSW_NMMU_FINAL | 4));
    setup_mmu(&config, &io);
    memory.failRead = 0x10000;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNREADABLE);
    CHECK(!r.Leaf && r.FaultOwner == KSW_NMMU_PHYSICAL && r.FaultAddress == 0x10000);
    setup_mmu(&config, &io);
    memory.mutateCas = 0x13010;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, KSW_NNPT_WRITE, KSW_NMMU_FINAL, &r) == KSW_NNPT_RETRY);
    CHECK(!r.Leaf && (memory.page[19][2] & KSW_NNPT_FRAME) == 0x19000 && !(memory.page[19][2] & 0x40));
    setup_mmu(&config, &io);
    config.Epoch = 0;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_UNSUPPORTED && !r.Leaf && !memory.reads);
    return 0;
}
__declspec(align(4096)) static KSW_SVM_U64 shadow_words[8][512];
static int test_large_span(void)
{
    KSW_NSHADOW_PAGE pages[4];
    KSW_NSHADOW shadow = {0};
    KSW_NMMU_CONFIG config;
    KSW_NMMU_IO io;
    KSW_NMMU_RESULT r;
    unsigned i;
    setup_mmu(&config, &io);
    memory.page[3][0] = 0x87; /* Outer identity mapping for inner page tables. */
    memory.page[3][1] = 0x400087;
    memory.page[8][0] = 0x9007;
    memory.page[9][0] = 0xa007;
    memory.page[10][0] = 0x20009f | KSW_NNPT_NX; /* UC/NX large inner leaf. */
    for (i = 0; i < 4; ++i) {
        pages[i].Words = shadow_words[i];
        pages[i].Physical = 0x100000 + 4096ULL * i;
    }
    CHECK(KswSvmNestedShadowInitialize(&shadow, pages, 4, 45) == KSW_NSHADOW_OK);
    config.Epoch = shadow.Epoch;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(r.Inner.LeafShift == 21 && r.Outer.LeafShift == 21);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.Used == 4);
    for (i = 0; i < 512; ++i) {
        CHECK(shadow_words[3][i] == ((0x400000 + 4096ULL * i) | 0x3d | KSW_NNPT_NX));
    }
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 2, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK);
    CHECK((shadow_words[3][2] & 0x42) == 0x42 && !(shadow_words[3][1] & 2));
    CHECK(KswSvmNestedShadowReset(&shadow) == KSW_NSHADOW_OK);
    config.Epoch = shadow.Epoch;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x1ff123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK);
    CHECK(shadow_words[3][0] == (0x40007f | KSW_NNPT_NX));
    CHECK(shadow_words[3][511] == (0x5ff07f | KSW_NNPT_NX));
    CHECK(shadow_words[2][1] == 0); /* No prefill outside either validated source span. */
    return 0;
}
static int test_shadow(void)
{
    KSW_NSHADOW_PAGE pages[8];
    KSW_NSHADOW shadow = {0}, bad = {0};
    KSW_NMMU_CONFIG config;
    KSW_NMMU_IO io;
    KSW_NMMU_RESULT r;
    unsigned i;
    for (i = 0; i < 8; ++i) {
        pages[i].Words = shadow_words[i];
        pages[i].Physical = 0x100000 + 4096ULL * i;
    }
    memset(shadow_words, 0xa5, sizeof(shadow_words));
    CHECK(KswSvmNestedShadowInitialize(&shadow, pages, 3, 45) == KSW_NSHADOW_OK);
    CHECK(shadow.Used == 1 && shadow.Epoch == 1 && shadow.FlushPending == 1);
    CHECK(shadow_words[0][0] == 0 && shadow_words[1][0] == 0xa5a5a5a5a5a5a5a5ULL);
    setup_mmu(&config, &io);
    config.Epoch = shadow.Epoch;
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 2, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_FULL);
    CHECK(shadow.Used == 1 && shadow_words[0][0] == 0 && shadow_words[1][0] == 0xa5a5a5a5a5a5a5a5ULL);
    memset(&shadow, 0, sizeof(shadow));
    CHECK(KswSvmNestedShadowInitialize(&shadow, pages, 8, 45) == KSW_NSHADOW_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK);
    CHECK(shadow.Used == 4 && shadow_words[0][0] == 0x101007 && shadow_words[1][0] == 0x102007);
    CHECK(shadow_words[2][0] == 0x103007 && shadow_words[3][2] == r.Leaf);
    CHECK(shadow_words[3][1] == 0 && shadow_words[3][3] == 0);
    shadow.FlushPending = 0; /* Simulate the owning entry loop having consumed the flush request. */
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.Used == 4 && shadow.FlushPending);
    /* Hardware may set Accessed on any intermediate table. */
    shadow_words[1][0] |= 0x20;
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.Used == 4);
    shadow_words[1][0] = 0x101007; /* A forged cycle must not be followed. */
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    CHECK(KswSvmNestedShadowReset(&shadow) == KSW_NSHADOW_OK && shadow.Epoch == 2 && shadow.Used == 1);
    CHECK(shadow_words[0][0] == 0);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_STALE);
    config.Epoch = shadow.Epoch;
    memory.page[19][2] &= ~0x40ULL; /* Guest invalidation cleared D: writes must fault again. */
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow_words[1][0] == 0x102007);
    CHECK(!(shadow_words[3][2] & 2)); /* Read resolutions cannot bypass dirty logging. */
    r.Gpa += 4096;
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    memory.page[16][1] = memory.page[16][0];
    CHECK(KswSvmNestedMmuResolve(&config, &io, (1ULL << 39) | 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_OK && shadow.Used == 7);
    CHECK(shadow_words[0][1] == 0x104007 && shadow_words[6][2] == r.Leaf);
    memory.page[16][2] = memory.page[16][0];
    CHECK(KswSvmNestedMmuResolve(&config, &io, (2ULL << 39) | 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_FULL && shadow.Used == 7 && shadow_words[0][2] == 0);
    CHECK(KswSvmNestedMmuResolve(&config, &io, 0x2123, 0, KSW_NMMU_FINAL, &r) == KSW_NNPT_OK);
    r.Leaf |= 1ULL << 45;
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    r.Leaf &= ~(1ULL << 45);
    r.Leaf |= 2; /* A writable leaf cannot skip source dirty accounting. */
    CHECK(KswSvmNestedShadowInstall(&shadow, &r) == KSW_NSHADOW_INVALID);
    shadow.Epoch = ~0ULL;
    CHECK(KswSvmNestedShadowReset(&shadow) == KSW_NSHADOW_INVALID && shadow.Used == 7);
    pages[1].Physical = pages[0].Physical;
    CHECK(KswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.Pages);
    pages[1].Physical = 0x101008;
    CHECK(KswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.Pages);
    pages[1].Physical = 0x101000;
    pages[1].Words = pages[0].Words;
    CHECK(KswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.Pages);
    pages[1].Words = shadow_words[1] + 1;
    CHECK(KswSvmNestedShadowInitialize(&bad, pages, 8, 45) == KSW_NSHADOW_INVALID && !bad.Pages);
    return 0;
}
static int test_state(void)
{
    KSW_SVM_VMCB source, destination;
    unsigned i;
    unsigned char* bytes = (unsigned char*)&destination;
    memset(&source, 0x33, sizeof(source));
    memset(&destination, 0xaa, sizeof(destination));
    KswSvmNestedCopyVmload(&destination, &source);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_FS) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_TR) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_SYSENTER_EIP) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_CR2) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_RAX) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_GDTR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    /* VMLOAD must not copy the VMRUN-managed CET core state. */
    CHECK(KswSvmRead64(&destination, KSW_VMCB_S_CET) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_ISST) == 0xaaaaaaaaaaaaaaaaULL);
    memset(&destination, 0xaa, sizeof(destination));
    KswSvmNestedCopyVmrun(&destination, &source, 0);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_S_CET) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_SSP) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_ISST) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_CR4) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_RIP) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_RAX) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_CR2) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_GS) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_PAT) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_LDTR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_STAR) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(bytes[KSW_VMCB_CPL] == 0x33 && bytes[KSW_VMCB_CPL + 1] == 0xaa);
    KswSvmNestedCopyVmrun(&destination, &source, 1);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_PAT) == 0x3333333333333333ULL);
    KswSvmWrite64(&source, KSW_VMCB_INTCTL, 0xdeadbeef00000305ULL);
    KswSvmWrite64(&source, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_NPF);
    KswSvmWrite64(&source, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 7);
    KswSvmWrite64(&source, KSW_VMCB_EXITINFO2, 0x12345000);
    KswSvmWrite64(&source, KSW_VMCB_NCR3, 0x2468000);
    KswSvmWrite64(&source, 0x68, 1);
    memset(&destination, 0xaa, sizeof(destination));
    KswSvmNestedReflectExit(&destination, &source, 1);
    /* Never copy a stale software EVENTINJ even if the source image was synthesized. */
    CHECK(KswSvmRead64(&destination, KSW_VMCB_EVENT) == 0);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_S_CET) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_SSP) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_ISST) == 0x3333333333333333ULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_NPF);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_EXITINFO1) == (KSW_NMMU_FINAL | 7));
    CHECK(KswSvmRead64(&destination, KSW_VMCB_EXITINFO2) == 0x12345000);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_NCR3) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_MSRPM) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_GS) == 0xaaaaaaaaaaaaaaaaULL);
    CHECK(KswSvmRead64(&destination, KSW_VMCB_INTCTL) == ((0xaaaaaaaaaaaaaaaaULL & ~0x10fULL) | 0x105ULL));
    CHECK(KswSvmRead64(&destination, 0x68) == 0xaaaaaaaaaaaaaaabULL);
    memset(&destination, 0, sizeof(destination));
    bytes[0] = 8; /* CR3 read. */
    bytes[2] = 16; /* CR4 write. */
    bytes[4] = 64; /* DR6 read. */
    bytes[6] = 128; /* DR7 write. */
    bytes[9] = 32; /* #GP vector 13. */
    bytes[14] = 4; /* CPUID at misc1 bit 18. */
    bytes[16] = 1; /* VMRUN at misc2 bit 0. */
    for (i = 0; i < 160; ++i) {
        unsigned expected = i == 3 || i == 0x14 || i == 0x26 || i == 0x37 || i == 0x4d || i == 0x72 || i == 0x80;
        CHECK(KswSvmNestedInterceptRequested(&destination, i) == expected);
    }
    CHECK(KswSvmNestedInterceptRequested(&destination, KSW_SVM_EXIT_NPF) == KSW_NSVM_INTERCEPT_UNKNOWN);
    CHECK(KswSvmNestedInterceptRequested(&destination, KSW_SVM_EXIT_INVALID) == KSW_NSVM_INTERCEPT_UNKNOWN);
    return 0;
}
static int test_resume_event(void)
{
    KSW_SVM_VMCB image, saved;
    unsigned type, vector;
    memset(&image, 0, sizeof(image));
    KswSvmWrite64(&image, KSW_VMCB_EVENT, 0x8000030d);
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x7fffffff);
    CHECK(KswSvmNestedResumeEvent(&image) == KSW_NSVM_EVENT_OK);
    CHECK(KswSvmRead64(&image, KSW_VMCB_EVENT) == 0);
    for (type = 0; type < 8; ++type) {
        for (vector = 0; vector < 256; ++vector) {
            KSW_SVM_U64 event = 0x1080000000ULL | (type << 8) | vector;
            unsigned expected = ((type != 0 && type != 2 && type != 3 && type != 4) ||
                (type == 3 && (vector == 2 || vector > 31))) ? KSW_NSVM_EVENT_INVALID : KSW_NSVM_EVENT_OK;
            KswSvmWrite64(&image, KSW_VMCB_RIP, 0x8000);
            KswSvmWrite64(&image, KSW_VMCB_NRIP, 0x8002);
            KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, event);
            KswSvmWrite64(&image, KSW_VMCB_EVENT, 0x1234);
            saved = image;
            CHECK(KswSvmNestedResumeEvent(&image) == expected);
            /* EV=0 leaves the high error-code word undefined; preserve raw evidence only. */
            if (expected == KSW_NSVM_EVENT_OK) { KswSvmWrite64(&saved, KSW_VMCB_EVENT, event & 0xffffffffULL); }
            CHECK(!memcmp(&image, &saved, sizeof(image)));
        }
    }
    /* EV=1 preserves the architectural error code while leaving EXITINTINFO unchanged. */
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x1080000b0dULL);
    saved = image;
    KswSvmWrite64(&saved, KSW_VMCB_EVENT, 0x1080000b0dULL);
    CHECK(KswSvmNestedResumeEvent(&image) == KSW_NSVM_EVENT_OK);
    CHECK(!memcmp(&image, &saved, sizeof(image)));
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x80000480);
    KswSvmWrite64(&image, KSW_VMCB_NRIP, 0);
    saved = image;
    CHECK(KswSvmNestedResumeEvent(&image) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    CHECK(!memcmp(&image, &saved, sizeof(image)));
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x80001020);
    CHECK(KswSvmNestedResumeEvent(&image) == KSW_NSVM_EVENT_INVALID);
    CHECK(KswSvmNestedResumeEvent(NULL) == KSW_NSVM_EVENT_INVALID);
    return 0;
}

static int test_npf_software_event(void)
{
    KSW_SVM_VMCB image, saved, reflected;
    KSW_NSVM_EVENT_ENTRY entry, other;
    unsigned i;
    const KSW_SVM_U64 rip = 0xfffff806305fd103ULL;
    memset(&image, 0, sizeof(image));
    KswSvmWrite64(&image, KSW_VMCB_RIP, rip - 3);
    KswSvmWrite64(&image, KSW_VMCB_RSP, 0xfffff80633aa0de8ULL);
    KswSvmWrite64(&image, KSW_VMCB_RFLAGS, 0x10202);
    KswSvmWrite64(&image, KSW_VMCB_CR2, 0x12340000);
    KswSvmWrite64(&image, 0x68, 1);
    KswSvmNestedCaptureEventEntry(&image, &entry, 0x871d8);
    KswSvmWrite64(&image, KSW_VMCB_RIP, rip);
    KswSvmWrite64(&image, KSW_VMCB_EXITCODE, 0x400);
    KswSvmWrite64(&image, KSW_VMCB_EXITINFO1, 0x100000004ULL);
    KswSvmWrite64(&image, KSW_VMCB_EXITINFO2, 0x60932d0);
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x8000042d);
    saved = image;
    CHECK(KswSvmNestedResumeEvent(&image) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d8) == KSW_NSVM_EVENT_OK);
    CHECK(!memcmp(&image, &saved, sizeof(image)));
    CHECK(KswSvmNestedResumeNpfEvent(&image, NULL, 0x871d8) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d9) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    other = entry; other.Valid = 0;
    CHECK(KswSvmNestedResumeNpfEvent(&image, &other, 0x871d8) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    CHECK(!memcmp(&image, &saved, sizeof(image)));
    KswSvmWrite64(&image, KSW_VMCB_EXITCODE, 0x61);
    CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d8) == KSW_NSVM_EVENT_NRIP_REQUIRED);
    image = saved;
    KswSvmWrite64(&image, KSW_VMCB_EVENT, 0x8000042d);
    KswSvmWrite64(&image, KSW_VMCB_NRIP, rip + 7);
    KswSvmNestedCaptureEventEntry(&image, &entry, 0x871d8);
    for (i = 0; i < 4; ++i) {
        KswSvmWrite64(&image, KSW_VMCB_NRIP, 0);
        KswSvmWrite64(&image, KSW_VMCB_EVENT, 0);
        CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d8) == KSW_NSVM_EVENT_OK);
        CHECK(KswSvmRead64(&image, KSW_VMCB_EVENT) == 0x8000042d);
        CHECK(KswSvmRead64(&image, KSW_VMCB_NRIP) == rip + 7);
        CHECK(KswSvmRead64(&image, KSW_VMCB_RIP) == rip);
        KswSvmNestedCaptureEventEntry(&image, &entry, 0x871d8);
    }
    KswSvmWrite64(&image, KSW_VMCB_NRIP, 0);
    saved = image;
    for (i = 0; i < 6; ++i) {
        other = entry;
        if (i == 0) { ++other.Rip; }
        if (i == 1) { ++other.CsBase; }
        if (i == 2) { ++other.Cs; }
        if (i == 3) { other.Event ^= 1; }
        if (i == 4) { other.NextRip = other.Rip; }
        if (i == 5) { other.NextRip = other.Rip + 16; }
        CHECK(KswSvmNestedResumeNpfEvent(&image, &other, 0x871d8) == KSW_NSVM_EVENT_NRIP_REQUIRED);
        CHECK(!memcmp(&image, &saved, sizeof(image)));
    }
    memset(&reflected, 0, sizeof(reflected));
    KswSvmNestedReflectExit(&reflected, &image, 1);
    CHECK(KswSvmRead64(&reflected, KSW_VMCB_EXITINTINFO) == 0x8000042d);
    CHECK(KswSvmRead64(&reflected, KSW_VMCB_NRIP) == 0);
    CHECK(KswSvmRead64(&reflected, KSW_VMCB_EVENT) == 0);
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0);
    CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d8) == KSW_NSVM_EVENT_OK);
    CHECK(KswSvmRead64(&image, KSW_VMCB_EVENT) == 0);
    KswSvmNestedCaptureEventEntry(&image, &entry, 0x871d9);
    CHECK(entry.Event == 0 && entry.Owner == 0x871d9 && entry.NextRip == 0);
    KswSvmWrite64(&image, KSW_VMCB_EXITINTINFO, 0x80001020);
    CHECK(KswSvmNestedResumeNpfEvent(&image, &entry, 0x871d9) == KSW_NSVM_EVENT_INVALID);
    CHECK(KswSvmNestedResumeNpfEvent(NULL, &entry, 0x871d9) == KSW_NSVM_EVENT_INVALID);
    return 0;
}

int main(void)
{
    KSW_NSVM_MSRS msrs = {0xd01, 0, 8, 0};
    KSW_SVM_U64 value;
    if (test_walk() || test_ad() || test_mmu() || test_shadow() || test_large_span() || test_state() || test_resume_event() || test_npf_software_event()) { return 1; }
    msrs.AddressMask = KswNptAddressMask(45);
    value = 0x1d01;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_OK);
    value = 0;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 0, &value) == KSW_NSVM_MSR_OK && value == 0x1d01);
    value = 0x1d00;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_GP && msrs.Efer == 0x1d01);
    value = 0x1000;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_OK && msrs.Hsave == 0x1000);
    value = 0x1001;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_GP && msrs.Hsave == 0x1000);
    value = 1ULL << 45;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_GP);
    value = 0;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 0, &value) == KSW_NSVM_MSR_OK && value == 0x1000);
    value = 0;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_HSAVE, 1, &value) == KSW_NSVM_MSR_OK && !msrs.Hsave);
    value = 0x10;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 1, &value) == KSW_NSVM_MSR_GP && msrs.VmCr == 8);
    value = 0;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 0, &value) == KSW_NSVM_MSR_OK && value == 8);
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_VM_CR, 1, &value) == KSW_NSVM_MSR_OK);
    value = 0xd01;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_OK);
    msrs.VmCr |= 0x10;
    value = 0x1d01;
    CHECK(KswSvmNestedMsrAccess(&msrs, KSW_SVM_MSR_EFER, 1, &value) == KSW_NSVM_MSR_GP && msrs.Efer == 0xd01);
    CHECK(KswSvmNestedMsrAccess(&msrs, 0x1234, 0, &value) == KSW_NSVM_MSR_OTHER);
    printf("SVM_NESTED_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
