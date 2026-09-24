/* Execute the production map engine, without MSRs, I/O instructions or SVM. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_permissions.h"

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned char aMsr[8192], bMsr[8192], outMsr[8192];
static unsigned char aIo[12288], bIo[12288], outIo[12288];
static KSW_NSVM_PERMISSION_VIEW a, b;
static KSW_NSVM_PERMISSION_IMAGE image;
static unsigned char source[5][4096];
static unsigned reads, failPage;

static void clear_maps(void)
{
    memset(aMsr, 0, sizeof(aMsr)); memset(bMsr, 0, sizeof(bMsr));
    memset(aIo, 0, sizeof(aIo)); memset(bIo, 0, sizeof(bIo));
    a.Flags = b.Flags = KSW_NSVM_PERMISSION_FLAGS;
    a.Msr = aMsr; a.Io = aIo; b.Msr = bMsr; b.Io = bIo;
}
static void set_bit(unsigned char* map, unsigned bit)
{
    map[bit / 8] |= (unsigned char)(1U << (bit % 8));
}
static int test_msr_owners(void)
{
    /* Expected offsets are from the APM table, not the function under test. */
    static const unsigned msrs[] = {0, 0x1fff, 0xc0000000, 0xc0001fff, 0xc0010000, 0xc0011fff};
    static const unsigned bits[] = {0, 16382, 16384, 32766, 32768, 49150};
    static const unsigned outside[] = {0x2000, 0xbfffffff, 0xc0002000, 0xc000ffff, 0xc0012000, 0xffffffff};
    unsigned i, write, owner;
    for (i = 0; i < sizeof(msrs) / sizeof(msrs[0]); ++i) {
        for (write = 0; write < 2; ++write) {
            for (owner = 0; owner < 4; ++owner) {
                clear_maps();
                if (owner & 1) { set_bit(aMsr, bits[i] + write); }
                if (owner & 2) { set_bit(bMsr, bits[i] + write); }
                CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, write, msrs[i]) == owner);
                CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, write ^ 1, msrs[i]) == 0);
            }
        }
    }
    for (i = 0; i < sizeof(outside) / sizeof(outside[0]); ++i) {
        for (owner = 0; owner < 4; ++owner) {
            clear_maps();
            a.Flags = owner & 1 ? KSW_NSVM_MSR_PROT : 0;
            b.Flags = owner & 2 ? KSW_NSVM_MSR_PROT : 0;
            CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, outside[i]) == owner);
            CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 1, outside[i]) == owner);
        }
    }
    clear_maps();
    a.Msr = NULL;
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, 0) == KSW_NSVM_OWNER_INVALID);
    a.Flags = 0;
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 0, 0) == 0);
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 2, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7c, 1ULL << 32, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x72, 0, 0) == KSW_NSVM_OWNER_INVALID);
    return 0;
}
static int test_io_owners(void)
{
    unsigned port, width, owner;
    KSW_SVM_U64 info;
    clear_maps();
    for (port = 0; port < 65536; ++port) {
        for (width = 1; width <= 4; width *= 2) {
            /* Last accessed byte forces the entire operation to exit, including the tail page. */
            set_bit(bIo, port + width - 1);
            info = ((KSW_SVM_U64)port << 16) | (width << 4);
            CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, info, 0) == 2);
            CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, info | 0xd, 0) == 2); /* IN+STR+REP */
            bIo[(port + width - 1) / 8] = 0;
            CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, info, 0) == 0);
        }
    }
    for (owner = 0; owner < 4; ++owner) {
        clear_maps();
        if (owner & 1) { set_bit(aIo, 0x3f8); }
        if (owner & 2) { set_bit(bIo, 0x3f9); }
        CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x3f80020, 0) == owner);
    }
    clear_maps(); set_bit(bIo, 0); /* A wrap to port zero would falsely request this exit. */
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, 0xffff0040, 0) == 0);
    for (width = 0; width < 8; ++width) {
        if (width == 1 || width == 2 || width == 4) { continue; }
        CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, width << 4, 0) == KSW_NSVM_OWNER_INVALID);
    }
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x12, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, 0x2010, 0) == KSW_NSVM_OWNER_INVALID);
    CHECK(KswSvmNestedPermissionOwners(&a, &b, 0x7b, (1ULL << 32) | 0x10, 0) == KSW_NSVM_OWNER_INVALID);
    return 0;
}
static int test_merge(void)
{
    unsigned i, enabled;
    clear_maps();
    for (i = 0; i < sizeof(aMsr); ++i) { aMsr[i] = (unsigned char)(i * 17); bMsr[i] = (unsigned char)(i * 31 + 1); }
    for (i = 0; i < sizeof(aIo); ++i) { aIo[i] = (unsigned char)(i * 13); bIo[i] = (unsigned char)(i * 7 + 3); }
    for (enabled = 0; enabled < 16; ++enabled) {
        a.Flags = ((enabled & 1) ? KSW_NSVM_MSR_PROT : 0) | ((enabled & 2) ? KSW_NSVM_IOIO_PROT : 0);
        b.Flags = ((enabled & 4) ? KSW_NSVM_MSR_PROT : 0) | ((enabled & 8) ? KSW_NSVM_IOIO_PROT : 0);
        CHECK(KswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
        for (i = 0; i < sizeof(aMsr); ++i) {
            CHECK(outMsr[i] == (((enabled & 1) ? aMsr[i] : 0) | ((enabled & 4) ? bMsr[i] : 0)));
        }
        for (i = 0; i < sizeof(aIo); ++i) {
            CHECK(outIo[i] == (((enabled & 2) ? aIo[i] : 0) | ((enabled & 8) ? bIo[i] : 0)));
        }
    }
    memset(outMsr, 0xaa, sizeof(outMsr)); memset(outIo, 0x55, sizeof(outIo));
    a.Msr = NULL;
    CHECK(!KswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
    CHECK(outMsr[0] == 0xaa && outMsr[8191] == 0xaa && outIo[0] == 0x55 && outIo[12287] == 0x55);
    a.Flags = b.Flags = 0; a.Io = b.Io = NULL; b.Msr = NULL;
    CHECK(KswSvmNestedMergePermissions(&a, &b, outMsr, outIo));
    CHECK(outMsr[0] == 0 && outIo[12287] == 0);
    return 0;
}
static int read_page(void* context, KSW_SVM_U64 address, unsigned char* page)
{
    unsigned index;
    (void)context;
    ++reads;
    /* Guest addresses deliberately differ from the source's actual user-mode address. */
    if (address < 0x100000 || address >= 0x105000 || (address & 4095)) { return 0; }
    index = (unsigned)((address - 0x100000) >> 12);
    if (index == failPage) { return 0; }
    memcpy(page, source[index], 4096);
    return 1;
}
static int test_capture(void)
{
    unsigned bits, i;
    KSW_SVM_U64 base, limit;
    KSW_NSVM_PERMISSION_VIEW view;
    for (bits = 32; bits <= 48; ++bits) {
        limit = 1ULL << bits;
        CHECK(KswSvmNestedMapAddress(limit - 8192 + 123, 8192, bits, &base) && base == limit - 8192);
        CHECK(!KswSvmNestedMapAddress(limit - 4096, 8192, bits, &base) && base == 0);
        CHECK(KswSvmNestedMapAddress(limit - 12288, 12288, bits, &base));
        CHECK(!KswSvmNestedMapAddress(limit - 8192, 12288, bits, &base));
        CHECK(!KswSvmNestedMapAddress(limit, 8192, bits, &base));
    }
    CHECK(!KswSvmNestedMapAddress(~0ULL, 8192, 48, &base));
    CHECK(!KswSvmNestedMapAddress(0, 4096, 48, &base));
    CHECK(!KswSvmNestedMapAddress(0, 8192, 64, &base));
    CHECK(KswSvmNestedMapAddress(0, 8192, 48, &base) && base == 0);
    for (i = 0; i < 5; ++i) { memset(source[i], (int)i + 1, 4096); }
    failPage = ~0U; reads = 0;
    CHECK(KswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100abc, 0x102def, 48, read_page, NULL));
    CHECK(reads == 5 && image.Ready == 1);
    CHECK(KswSvmNestedPermissionView(&image, &view));
    CHECK(!memcmp(view.Msr, source, 8192) && !memcmp(view.Io, source[2], 12288));
    for (failPage = 0; failPage < 5; ++failPage) {
        reads = 0;
        CHECK(!KswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100000, 0x102000, 48, read_page, NULL));
        CHECK(!image.Ready && reads == failPage + 1);
        CHECK(!KswSvmNestedPermissionView(&image, &view) && !view.Msr && !view.Io);
    }
    reads = 0;
    CHECK(!KswSvmNestedCapturePermissions(&image, KSW_NSVM_PERMISSION_FLAGS, 0x100000, ~0ULL, 48, read_page, NULL));
    CHECK(!reads && !image.Ready);
    CHECK(KswSvmNestedCapturePermissions(&image, 0, ~0ULL, ~0ULL, 48, NULL, NULL));
    CHECK(KswSvmNestedPermissionView(&image, &view) && !view.Flags);
    CHECK(!image.Msr[8191] && !image.Io[12287]);
    failPage = ~0U; reads = 0;
    CHECK(KswSvmNestedCapturePermissions(&image, KSW_NSVM_IOIO_PROT, ~0ULL, 0x102000, 48, read_page, NULL));
    CHECK(reads == 3);
    reads = 0;
    CHECK(KswSvmNestedCapturePermissions(&image, KSW_NSVM_MSR_PROT, 0x100000, ~0ULL, 48, read_page, NULL));
    CHECK(reads == 2);
    return 0;
}
int main(void)
{
    if (test_msr_owners() || test_io_owners() || test_merge() || test_capture()) { return 1; }
    printf("SVM_PERMISSION_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
