#pragma once

#include "KswordArkNetworkIoctl.h"

#define KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_CONTROL_MANAGED_POLICY 0x933UL
#define KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_MANAGED_POLICIES 0x934UL
#define IOCTL_KSWORD_ARK_NETWORK_CONTROL_MANAGED_POLICY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_NETWORK_CONTROL_MANAGED_POLICY, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_NETWORK_QUERY_MANAGED_POLICIES \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_NETWORK_QUERY_MANAGED_POLICIES, METHOD_BUFFERED, FILE_READ_ACCESS)

#define KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES 64UL
#define KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES 32UL
#define KSWORD_ARK_NETWORK_MANAGED_UPSERT 1UL
#define KSWORD_ARK_NETWORK_MANAGED_REMOVE 2UL
#define KSWORD_ARK_NETWORK_MANAGED_ENABLE 3UL
#define KSWORD_ARK_NETWORK_MANAGED_DISABLE 4UL
#define KSWORD_ARK_NETWORK_MANAGED_ENABLED 0x00000001UL
#define KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED 0x00000002UL
#define KSWORD_ARK_NETWORK_MANAGED_CAP_IPV4 0x00000001UL
#define KSWORD_ARK_NETWORK_MANAGED_CAP_IPV6 0x00000002UL
#define KSWORD_ARK_NETWORK_MANAGED_CAP_CIDR 0x00000004UL
#define KSWORD_ARK_NETWORK_MANAGED_CAP_PROCESS_INSTANCE 0x00000008UL

typedef struct _KSWORD_ARK_NETWORK_MANAGED_PREFIX {
    unsigned long family;
    unsigned long prefixLength;
    unsigned char address[16];
} KSWORD_ARK_NETWORK_MANAGED_PREFIX;

typedef struct _KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY {
    unsigned char policyId[16];
    unsigned long processId;
    unsigned long directionMask;
    unsigned long flags;
    unsigned long reserved0;
    unsigned long long creationTime100ns;
    unsigned long prefixCount;
    unsigned long reserved1;
    KSWORD_ARK_NETWORK_MANAGED_PREFIX prefixes[KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES];
} KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY;

typedef struct _KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST {
    unsigned long version;
    unsigned long size;
    unsigned long action;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY policy;
} KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST;

typedef struct _KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE {
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long policyCount;
    unsigned long generation;
    unsigned long capabilities;
    long lastStatus;
    unsigned long reserved;
} KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE;

typedef struct _KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE {
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long policyCount;
    unsigned long generation;
    unsigned long capabilities;
    long lastStatus;
    unsigned long reserved;
    KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY policies[KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES];
} KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE;
