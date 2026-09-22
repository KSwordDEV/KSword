#pragma once

#include <ntddk.h>

EXTERN_C_START

#define KSW_OBJECT_HEADER_FALLBACK_FIELD_POINTER_COUNT 0x00000001UL
#define KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT  0x00000002UL

typedef struct _KSW_OBJECT_HEADER_FALLBACK_RESULT
{
    ULONG ValidFields;
    ULONG BodyOffset;
    ULONG PointerCountOffset;
    ULONG HandleCountOffset;
    ULONG PointerCount;
    ULONG HandleCount;
} KSW_OBJECT_HEADER_FALLBACK_RESULT, *PKSW_OBJECT_HEADER_FALLBACK_RESULT;

NTSTATUS
KswordARKObjectHeaderResolveBodyOffsetFallback(
    _Out_ ULONG* BodyOffsetOut
    );

NTSTATUS
KswordARKObjectHeaderQueryFallback(
    _In_ PVOID Object,
    _Out_ KSW_OBJECT_HEADER_FALLBACK_RESULT* Result
    );

/* Obtain a documented ID-based reference, then require exact pointer identity.
   Object is only an observed address until lookup succeeds. No object-header
   layout or direct reference-count write is used. A successful call owns one
   reference; the caller releases it with ObDereferenceObject. Lookup failure
   or identity drift must remain unconfirmed, read-only evidence. APC_LEVEL max. */
NTSTATUS
KswordARKObjectHeaderReferenceObjectSafe(
    _In_ PVOID Object,
    _In_ HANDLE ObjectId,
    _In_ POBJECT_TYPE ExpectedObjectType
    );

EXTERN_C_END
