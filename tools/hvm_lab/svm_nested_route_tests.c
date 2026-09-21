/* Verify inner reflection precedes outer emulation for shared intercept ownership. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_route.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSW_SVM_VMCB outer, inner, savedOuter, savedInner;
static unsigned char outerMsr[8192], innerMsr[8192], outerIo[12288], innerIo[12288];
static KSW_NSVM_PERMISSION_VIEW outerMaps, innerMaps;
static KSW_NSVM_EXIT_ROUTE result;
static void intercept(KSW_SVM_VMCB* image, unsigned code)
{
    unsigned byte, bit;
    if (code < 64) { byte = (code / 16) * 2; bit = code % 16; }
    else if (code < 96) { byte = 8; bit = code - 64; }
    else { byte = code < 128 ? 12 : 16; bit = code % 32; }
    image->control[byte + bit / 8] |= (unsigned char)(1U << (bit % 8));
}
static void reset(void)
{
    memset(&outer, 0, sizeof(outer)); memset(&inner, 0, sizeof(inner));
    memset(outerMsr, 0, sizeof(outerMsr)); memset(innerMsr, 0, sizeof(innerMsr));
    memset(outerIo, 0, sizeof(outerIo)); memset(innerIo, 0, sizeof(innerIo));
    outerMaps.Flags = innerMaps.Flags = 0;
    outerMaps.Msr = outerMsr; outerMaps.Io = outerIo;
    innerMaps.Msr = innerMsr; innerMaps.Io = innerIo;
}
static unsigned route(KSW_SVM_U64 code, KSW_SVM_U64 info, unsigned msr)
{
    return KswSvmNestedRouteExit(&outer, &inner, &outerMaps, &innerMaps, code, info, msr, &result);
}
int main(void)
{
    unsigned code, owners;
    for (code = 0; code < 160; ++code) {
        if (code == 0x7b || code == 0x7c) { continue; }
        for (owners = 0; owners < 4; ++owners) {
            unsigned expected = !owners ? KSW_NSVM_ROUTE_FAULT :
                ((code >= 0x60 && code <= 0x63) ? KSW_NSVM_ROUTE_ASYNC :
                ((owners & 2) ? KSW_NSVM_ROUTE_REFLECT : KSW_NSVM_ROUTE_EMULATE));
            reset();
            if (owners & 1) { intercept(&outer, code); }
            if (owners & 2) { intercept(&inner, code); }
            savedOuter = outer; savedInner = inner;
            CHECK(route(code, 0xdeadbeef, 0) == expected);
            CHECK(result.Owners == owners && result.Code == code && result.Info1 == 0xdeadbeef);
            CHECK(!memcmp(&outer, &savedOuter, 4096) && !memcmp(&inner, &savedInner, 4096));
        }
    }
    for (owners = 0; owners < 4; ++owners) {
        unsigned expected = !owners ? 0 : (owners & 2 ? 1 : 2);
        reset();
        outerMaps.Flags = innerMaps.Flags = KSW_NSVM_MSR_PROT | KSW_NSVM_IOIO_PROT;
        KswSvmWrite32(&outer, KSW_VMCB_MISC1, outerMaps.Flags);
        KswSvmWrite32(&inner, KSW_VMCB_MISC1, innerMaps.Flags);
        /* The coarse MSR intercept is set in both VMCBs; only the fine-grained bit owns EFER. */
        outerMsr[0x820] = (owners & 1) ? 3 : 0;
        innerMsr[0x820] = (owners & 2) ? 3 : 0;
        CHECK(route(0x7c, 0, 0xc0000080) == expected && result.Owners == owners);
        CHECK(route(0x7c, 1, 0xc0000080) == expected && result.Owners == owners);
        CHECK(route(0x7c, 2, 0xc0000080) == 0 && result.Owners == KSW_NSVM_OWNER_INVALID);
        /* A dword at port 0xffff includes the IOPM tail; it does not wrap around to port zero. */
        outerIo[8192] = (owners & 1) ? 4 : 0;
        innerIo[8192] = (owners & 2) ? 4 : 0;
        CHECK(route(0x7b, (0xffffULL << 16) | (4U << 4), 0) == expected && result.Owners == owners);
        CHECK(route(0x7c, 0, 0xdeadbeef) == KSW_NSVM_ROUTE_REFLECT && result.Owners == 3);
        innerMaps.Flags = 0;
        CHECK(route(0x7c, 0, 0xc0000080) == 0 && result.Owners == KSW_NSVM_OWNER_INVALID);
    }
    reset();
    CHECK(route(0x400, 0, 0) == KSW_NSVM_ROUTE_NPF);
    CHECK(route(~0ULL, 0, 0) == KSW_NSVM_ROUTE_FAULT);
    CHECK(route(0x100000000ULL, 0, 0) == KSW_NSVM_ROUTE_FAULT);
    CHECK(route(0xa0, 0, 0) == KSW_NSVM_ROUTE_FAULT);
    CHECK(KswSvmNestedRouteExit(NULL, &inner, &outerMaps, &innerMaps, 0x72, 0, 0, &result) == 0);
    printf("SVM_ROUTE_CHECKS=%u RESULT=PASS (no hardware)\n", checks);
    return 0;
}
