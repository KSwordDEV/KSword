#pragma once
// Minimal x64 native ABI adapted from System Informer PHNT ntpfapi.h/ntmmapi.h.
// Copyright (c) 2022 Winsider Seminars & Solutions, Inc. MIT: LICENSE.txt.
// https://github.com/winsiderss/phnt/blob/master/ntpfapi.h
// No private _MMPFN offsets are assumed. Keep R0/R3 packet definitions separate.

typedef struct _KSW_PF_SUPERFETCH {
    ULONG Version;
    ULONG Magic;
    ULONG InfoClass;
    PVOID Buffer;
    ULONG Length;
} KSW_PF_SUPERFETCH;

typedef struct _KSW_PF_IDENTITY {
    ULONGLONG Frame;
    ULONG_PTR Pfn;
    ULONG_PTR Backing;
} KSW_PF_IDENTITY;

typedef struct _KSW_PF_QUERY {
    ULONG Version;
    ULONG Flags;
    SIZE_T Count;
    // SYSTEM_MEMORY_LIST_INFORMATION: five lists, 8 standby, 8 repurposed,
    // and ModifiedPageCountPageFile; sizeof == 176 on x64.
    SIZE_T MemoryLists[22];
    KSW_PF_IDENTITY Pages[1];
} KSW_PF_QUERY;

typedef struct _KSW_PF_RANGE {
    ULONG_PTR Base;
    ULONG_PTR Count;
} KSW_PF_RANGE;

typedef struct _KSW_PF_RANGES_V2 {
    ULONG Version;
    ULONG Flags;
    ULONG Count;
    ULONG Reserved;
    KSW_PF_RANGE Ranges[1];
} KSW_PF_RANGES_V2;

typedef struct _KSW_PF_SOURCE {
    ULONG Type;
    ULONG ProcessId;
    ULONG ImagePathHash;
    ULONG_PTR UniqueProcessHash;
} KSW_PF_SOURCE;

typedef struct _KSW_PF_PRIVATE_INFO {
    KSW_PF_SOURCE Source;
    PVOID EProcess;
    SIZE_T WsPrivatePages;
    SIZE_T TotalPrivatePages;
    ULONG SessionId;
    UCHAR ImageName[16];
    SIZE_T WsSwapPages;
    SIZE_T WsTotalPages;
    ULONG DeepFreezeTimeMs;
    ULONG Flags;
} KSW_PF_PRIVATE_INFO;

typedef struct _KSW_PF_PRIVATE_QUERY {
    ULONG Version;
    ULONG Flags;
    ULONG Count;
    KSW_PF_PRIVATE_INFO Sources[1];
} KSW_PF_PRIVATE_QUERY;
