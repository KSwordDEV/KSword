#pragma once

#define KSW_HVM_NPT_CACHE_DISABLED 0U
#define KSW_HVM_NPT_CACHE_COLD 1U
#define KSW_HVM_NPT_CACHE_EPOCH 2U
#define KSW_HVM_NPT_CACHE_OWNER 3U
#define KSW_HVM_NPT_CACHE_TLB 4U
#define KSW_HVM_NPT_CACHE_KEY_BASE 5U
#define KSW_HVM_NPT_CACHE_KEYS 13U
#define KSW_HVM_NPT_CACHE_REASONS 18U

/* Reasons may overlap. Validity is inherited from the enclosing general snapshot. */
typedef struct _KSWORD_HVM_NPT_CACHE_STATS {
    unsigned long long lookups, hits, resets, resetFailures;
    unsigned long long reasons[KSW_HVM_NPT_CACHE_REASONS];
    unsigned long lastMissMask, saturated;
} KSWORD_HVM_NPT_CACHE_STATS;

static __inline void KswHvmNptCacheCount(KSWORD_HVM_NPT_CACHE_STATS* Stats,
    unsigned long long* Counter)
{
    if (*Counter == ~0ULL) { Stats->saturated = 1; }
    else { ++*Counter; }
}
