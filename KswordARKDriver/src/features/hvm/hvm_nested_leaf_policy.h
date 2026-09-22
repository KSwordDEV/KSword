/* Shared admission/publication invariants; no Windows or hardware dependencies. */
#pragma once

static __inline int KswordHvmLeafPolicyValidShift(unsigned int Shift)
{
    return Shift == 12U || Shift == 21U || Shift == 30U;
}

/* A scan is not an address-contiguity or lifetime proof. */
static __inline int KswordHvmLeafPolicySourceCovers(unsigned int Shift,
    unsigned int SourceEntryCount)
{
    unsigned int sourceShift = SourceEntryCount == 4U ? 12U :
        SourceEntryCount == 3U ? 21U : SourceEntryCount == 2U ? 30U : 0U;
    return KswordHvmLeafPolicyValidShift(Shift) && sourceShift >= Shift;
}

/* Backing may remain a region while hardware maps it with 4-KiB leaves. */
static __inline int KswordHvmLeafPolicyUseLarge(unsigned int Shift,
    unsigned int SourceEntryCount, int ScanAdmitted,
    unsigned int OuterShift, int ViewsActive)
{
    return Shift > 12U && !ScanAdmitted && !ViewsActive &&
        KswordHvmLeafPolicySourceCovers(Shift, SourceEntryCount) &&
        KswordHvmLeafPolicyValidShift(OuterShift) && OuterShift >= Shift;
}
