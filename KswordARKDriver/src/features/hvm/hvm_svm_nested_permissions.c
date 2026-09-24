/* Fine-grained ownership must follow the original L1 map, never the merged map. */
#include "hvm_svm_nested_permissions.h"

/* Reject incomplete enabled maps before touching output or making a routing decision. */
static unsigned int KswNsvmPermissionValid(const KSW_NSVM_PERMISSION_VIEW* View)
{
    /* A disabled map's address has no bearing on whether L1 requested an exit. */
    return View && (!(View->Flags & KSW_NSVM_MSR_PROT) || View->Msr) &&
        (!(View->Flags & KSW_NSVM_IOIO_PROT) || View->Io);
}

/* These reads are safe to execute natively and are high-frequency on Windows. */
static unsigned int KswNsvmNativeReadMsr(unsigned int Msr)
{
    return Msr == 0x10U || Msr == 0xe7U || Msr == 0xe8U ||
        (Msr >= 0xc0010062U && Msr <= 0xc001006bU) ||
        Msr == 0xc0010293U || Msr == 0xc001029aU;
}

/* Remove only the L1 read bit when L0 does not own that MSR. */
static void KswNsvmClearNativeRead(unsigned char* MsrMap, unsigned int Msr)
{
    unsigned int bit = KswSvmMsrpmBit(Msr, 0);
    if (bit != 0xffffffffU) { MsrMap[bit / 8U] &= (unsigned char)~(1U << (bit & 7U)); }
}

/* Normalize architectural bases without truncating unsupported high address bits. */
unsigned int KswSvmNestedMapAddress(KSW_SVM_U64 Address, unsigned int Bytes,
    unsigned int PhysicalBits, KSW_SVM_U64* Base)
{
    /* The shared four-level implementation currently supports at most 48 bits. */
    KSW_SVM_U64 mask = KswNptAddressMask(PhysicalBits);
    /* Never leave a stale address in a failed result. */
    if (!Base) { return 0; }
    /* Clear before testing either size or address. */
    *Base = 0;
    /* Only the two architectural permission-map allocation sizes are admitted. */
    if (!mask || (Bytes != KSW_NSVM_MSRPM_BYTES && Bytes != KSW_NSVM_IOPM_BYTES) ||
        (Address & ~(mask | 0xfffULL))) { return 0; }
    /* VMRUN ignores the low twelve bits, unlike the VMCB operand's alignment check. */
    Address &= ~0xfffULL;
    /* Subtraction prevents both wraparound and a final page beyond MAXPHYADDR. */
    if (Address > (mask | 0xfffULL) - (Bytes - 1U)) { return 0; }
    /* Zero is a representable base; RAM ownership belongs to the read callback. */
    *Base = Address;
    /* Address validity alone never proves that the memory is readable RAM. */
    return 1;
}

/* Build a private image without publishing partially read maps. */
unsigned int KswSvmNestedCapturePermissions(KSW_NSVM_PERMISSION_IMAGE* Image,
    unsigned int Flags, KSW_SVM_U64 MsrPa, KSW_SVM_U64 IoPa,
    unsigned int PhysicalBits, KSW_NSVM_PERMISSION_READ Read, void* Context)
{
    /* Decode both complete ranges before making the first memory access. */
    KSW_SVM_U64 msr = 0, io = 0;
    /* Five bounded page reads are enough for both maps. */
    unsigned int offset;
    /* A missing destination cannot acquire ownership. */
    if (!Image) { return 0; }
    /* Any previous snapshot becomes unusable, including on a failed recapture. */
    Image->Ready = 0;
    /* Preserve only the relevant intercept controls from this VMRUN. */
    Image->Flags = Flags & KSW_NSVM_PERMISSION_FLAGS;
    /* Disabled maps are not read or range-checked by this software snapshotter. */
    if (((Image->Flags & KSW_NSVM_MSR_PROT) &&
            !KswSvmNestedMapAddress(MsrPa, KSW_NSVM_MSRPM_BYTES, PhysicalBits, &msr)) ||
        ((Image->Flags & KSW_NSVM_IOIO_PROT) &&
            !KswSvmNestedMapAddress(IoPa, KSW_NSVM_IOPM_BYTES, PhysicalBits, &io)) ||
        (Image->Flags && !Read)) { return 0; }
    /* No disabled/previous map bytes may leak into a subsequent combined image. */
    for (offset = 0; offset < KSW_NSVM_MSRPM_BYTES; ++offset) { Image->Msr[offset] = 0; }
    /* Clear the full hardware IOPM allocation, including its tail page. */
    for (offset = 0; offset < KSW_NSVM_IOPM_BYTES; ++offset) { Image->Io[offset] = 0; }
    /* Each callback must translate L1 physical memory rather than using it as host PA. */
    if (Image->Flags & KSW_NSVM_MSR_PROT) {
        /* Copy a page into owned memory, never retain the callback's transient mapping. */
        for (offset = 0; offset < KSW_NSVM_MSRPM_BYTES; offset += 4096U) {
            /* A failure invalidates the whole image, including earlier successful pages. */
            if (!Read(Context, msr + offset, Image->Msr + offset)) { return 0; }
        }
    }
    /* I/O width can consume the first three bits of the third page at port 0xffff. */
    if (Image->Flags & KSW_NSVM_IOIO_PROT) {
        /* Keep all three hardware pages under the same lifetime as the MSR snapshot. */
        for (offset = 0; offset < KSW_NSVM_IOPM_BYTES; offset += 4096U) {
            /* The caller must refuse VMRUN if any source page cannot be captured. */
            if (!Read(Context, io + offset, Image->Io + offset)) { return 0; }
        }
    }
    /* Only the fully captured CPU-private image is eligible for merge and routing. */
    Image->Ready = 1;
    /* No hardware or TLB state was changed by this capture. */
    return 1;
}

/* Produce a view only after complete capture, including the all-disabled case. */
unsigned int KswSvmNestedPermissionView(const KSW_NSVM_PERMISSION_IMAGE* Image,
    KSW_NSVM_PERMISSION_VIEW* View)
{
    /* No stale view is returned on failure; the caller must check the result. */
    if (!View) { return 0; }
    /* Start with an inert descriptor, not a pointer to a previous generation's image. */
    View->Flags = 0; View->Msr = 0; View->Io = 0;
    /* A partial read is not a valid empty permissions map. */
    if (!Image || Image->Ready != 1U) { return 0; }
    /* Controls and buffers are bound to the same completed snapshot. */
    View->Flags = Image->Flags; View->Msr = Image->Msr; View->Io = Image->Io;
    /* Lifetimes remain the caller's responsibility throughout inner execution. */
    return 1;
}

/* OR only enabled source maps: disabling an intercept must ignore stale map bits. */
unsigned int KswSvmNestedMergePermissions(const KSW_NSVM_PERMISSION_VIEW* Outer,
    const KSW_NSVM_PERMISSION_VIEW* Inner, unsigned char* Msr, unsigned char* Io)
{
    /* All inputs are owned snapshots; no guest read takes place in the merge. */
    unsigned int index;
    /* Reject missing active maps before touching either hardware output. */
    if (!Msr || !Io || !KswNsvmPermissionValid(Outer) || !KswNsvmPermissionValid(Inner)) { return 0; }
    /* Preserve every L0 protection even if L1 leaves its permission map clear. */
    for (index = 0; index < KSW_NSVM_MSRPM_BYTES; ++index) {
        /* Bits outside the three MSR ranges remain opaque, not routed as extra MSRs. */
        Msr[index] = (unsigned char)(((Outer->Flags & KSW_NSVM_MSR_PROT) ? Outer->Msr[index] : 0) |
            ((Inner->Flags & KSW_NSVM_MSR_PROT) ? Inner->Msr[index] : 0));
    }
    if (Outer->Flags & KSW_NSVM_MSR_PROT) {
        static const unsigned int nativeReads[] = {
            0x10U, 0xe7U, 0xe8U,
            0xc0010062U, 0xc0010063U, 0xc0010064U, 0xc0010065U, 0xc0010066U,
            0xc0010067U, 0xc0010068U, 0xc0010069U, 0xc001006aU,
            0xc001006bU, 0xc0010293U, 0xc001029aU
        };
        for (index = 0; index < sizeof(nativeReads) / sizeof(nativeReads[0]); ++index) {
            unsigned int bit = KswSvmMsrpmBit(nativeReads[index], 0);
            if (bit != 0xffffffffU && !((Outer->Msr[bit / 8U] >> (bit & 7U)) & 1U)) {
                KswNsvmClearNativeRead(Msr, nativeReads[index]);
            }
        }
    }
    /* The tail bits are significant for multibyte I/O at the last port. */
    for (index = 0; index < KSW_NSVM_IOPM_BYTES; ++index) {
        /* Hardware control bits must separately be the OR of both owners' intercepts. */
        Io[index] = (unsigned char)(((Outer->Flags & KSW_NSVM_IOIO_PROT) ? Outer->Io[index] : 0) |
            ((Inner->Flags & KSW_NSVM_IOIO_PROT) ? Inner->Io[index] : 0));
    }
    /* Caller may now publish these pre-resolved physical pointers into VMCB02. */
    return 1;
}

/* Query one owner independently; never derive ownership from the combined maps. */
static unsigned int KswNsvmPermissionRequested(const KSW_NSVM_PERMISSION_VIEW* View,
    KSW_SVM_U64 Code, unsigned int Bit, unsigned int Width)
{
    /* IOIO can span four permission bits, with no 16-bit wrap at the last port. */
    unsigned int index;
    /* A clear MSR_PROT disables even the implicit out-of-range MSR intercept. */
    if (Code == KSW_SVM_EXIT_MSR) {
        /* A missing map was rejected before this helper. */
        if (!(View->Flags & KSW_NSVM_MSR_PROT)) { return 0; }
        /* The architecture intercepts all MSRs absent from its three bitmap ranges. */
        return Bit == 0xffffffffU || ((View->Msr[Bit / 8U] >> (Bit & 7U)) & 1U);
    }
    /* Disabled I/O interception ignores every IOPM bit, including the tail. */
    if (!(View->Flags & KSW_NSVM_IOIO_PROT)) { return 0; }
    /* Port plus byte offset fits within the architectural 65539 meaningful bits. */
    for (index = 0; index < Width; ++index) {
        /* Any covered byte forces the entire IN/OUT/INS/OUTS operation to intercept. */
        if ((View->Io[(Bit + index) / 8U] >> ((Bit + index) & 7U)) & 1U) { return 1; }
    }
    /* Neither direction nor REP changes which port bytes are checked. */
    return 0;
}

/* Return ownership evidence; the dispatcher still implements reflection/emulation. */
unsigned int KswSvmNestedPermissionOwners(const KSW_NSVM_PERMISSION_VIEW* Outer,
    const KSW_NSVM_PERMISSION_VIEW* Inner, KSW_SVM_U64 ExitCode,
    KSW_SVM_U64 ExitInfo1, unsigned int MsrNumber)
{
    /* Normalize both exit formats before looking at either owner's map. */
    unsigned int bit, width = 1;
    /* Invalid views cannot silently become a local/native passthrough decision. */
    if (!KswNsvmPermissionValid(Outer) || !KswNsvmPermissionValid(Inner)) { return KSW_NSVM_OWNER_INVALID; }
    /* MSR EXITINFO1 is exactly zero for read or one for write. */
    if (ExitCode == KSW_SVM_EXIT_MSR) {
        /* Ignore neither malformed high bits nor an invalid direction. */
        if (ExitInfo1 > 1ULL) { return KSW_NSVM_OWNER_INVALID; }
        /* Keep the architectural out-of-map sentinel for implicit interception. */
        bit = KswSvmMsrpmBit(MsrNumber, (unsigned int)ExitInfo1);
    } else if (ExitCode == 0x7bULL) {
        /* Size is a one-hot 8/16/32-bit operand encoding. */
        width = (unsigned int)((ExitInfo1 >> 4) & 7ULL);
        /* Reserved bits must not turn an unknown exit into a guessed port access. */
        if ((ExitInfo1 & ~0xffff1ffdULL) || (width != 1U && width != 2U && width != 4U)) {
            /* Caller preserves the raw failure instead of executing I/O on a guessed port. */
            return KSW_NSVM_OWNER_INVALID;
        }
        /* Do not cast port plus width to ushort: trailing permission bits do not wrap. */
        bit = (unsigned int)(ExitInfo1 >> 16);
    } else {
        /* Other exit classes require their own intercept/exception ownership rules. */
        return KSW_NSVM_OWNER_INVALID;
    }
    /* Native-read policy mirrors the devirtz/KVM fast path without allowing writes through. */
    {
        unsigned int owners = KswNsvmPermissionRequested(Outer, ExitCode, bit, width) ? KSW_NSVM_OWNER_L0 : 0U;
        if (!(ExitCode == KSW_SVM_EXIT_MSR && ExitInfo1 == 0 && KswNsvmNativeReadMsr(MsrNumber))) {
            if (KswNsvmPermissionRequested(Inner, ExitCode, bit, width)) { owners |= KSW_NSVM_OWNER_L1; }
        }
        return owners;
    }
}
