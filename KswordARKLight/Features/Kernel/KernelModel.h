#pragma once
#include "../../../shared/usermode/backend/kernel/KernelTypes.h"
namespace Ksword::Features::Kernel {
using enum ks::r3::kernel::KernelRequestFlag;
using ks::r3::kernel::KernelFeatureId;
using ks::r3::kernel::KernelFeatureBackend;
using ks::r3::kernel::KernelFeatureDescriptor;
using ks::r3::kernel::KernelRequest;
using ks::r3::kernel::KernelRequestFlag;
using ks::r3::kernel::KernelResultRow;
using ks::r3::kernel::KernelObjectNamespaceEntry;
using ks::r3::kernel::KernelOperationResult;
using ks::r3::kernel::KernelActionId;
using ks::r3::kernel::KernelActionRequest;
using ks::r3::kernel::ToDisplayName;
using ks::r3::kernel::BackendToDisplayName;
}
