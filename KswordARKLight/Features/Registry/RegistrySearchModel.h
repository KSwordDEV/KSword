#pragma once
#include "../../../shared/usermode/backend/registry/RegistrySearchModel.h"
namespace Ksword::Features::Registry {
using ks::r3::registry::ValidateRegistrySearchRequest;
using ks::r3::registry::ProjectRegistrySearchHit;
using ks::r3::registry::RegistrySearchHitMatches;
using ks::r3::registry::BuildRegistrySearchStatusText;
using ks::r3::registry::SanitizeRegistrySearchTsvCell;
using ks::r3::registry::BuildRegistrySearchTsv;
using ks::r3::registry::BuildVisibleRegistrySearchTsv;
using ks::r3::registry::RegistrySearchRequest;
using ks::r3::registry::RegistrySearchEntryKind;
using ks::r3::registry::RegistrySearchCandidate;
using ks::r3::registry::RegistrySearchHit;
using ks::r3::registry::RegistrySearchCounters;
using ks::r3::registry::RegistrySearchStopReason;
using ks::r3::registry::RegistrySearchValidation;
using ks::r3::registry::RegistrySearchSnapshot;
using ks::r3::registry::kRegistrySearchMaxKeys;
using ks::r3::registry::kRegistrySearchMaxValues;
using ks::r3::registry::kRegistrySearchMaxResults;
using ks::r3::registry::kRegistrySearchMaxDepth;
using ks::r3::registry::kRegistrySearchMaxValuePreviewBytes;
}
