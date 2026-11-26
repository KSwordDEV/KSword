#pragma once

#include "ProjectRawEvidence.h"
#include "../Memory/PassiveDirtyMemory.h"
#include "../../../shared/evidence/EvidenceJson.h"

namespace Ksword::ActionAnalyze {

struct ArchivedMemoryPage {
    Evidence::JsonValue metadata;
    ks::cli::action_analyze::memory::Range range;
    std::string bytes; // Only verified successful bytes; unavailable pages remain empty.
    std::uint64_t sequence = 0;
    std::uint64_t offset = 0;
};

struct ArchivedMemorySnapshot {
    Evidence::JsonValue plan, end;
    std::vector<ArchivedMemoryPage> pages;
    ks::cli::action_analyze::memory::Range range;
    ks::cli::action_analyze::archive::RawEvidenceBoundary boundary;
    std::string sha256;
    std::uint64_t capturedBytes = 0;
    std::uint64_t unavailablePages = 0;
    bool completeRange = false;
};

// Uses the project's pinned, safe raw-memory path and one verified read handle.
// Publishes no bytes on a bad segment, missing end record or semantic/hash mismatch.
// CRC/SHA validate stored content and read consistency, not the historical producer.
// The archived plan is descriptive evidence only; it never grants live process/stop control.
// Optional readContext remains part of plan, with live/held tokens validated independently
// from completeRange. A changed historical held stop is never reclassified as live.
ProjectResult ReadMemorySnapshot(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence, ArchivedMemorySnapshot& out);

// Concatenates only a fully covered subrange of one verified snapshot, never fills gaps.
ProjectResult SelectMemorySnapshotBytes(const ArchivedMemorySnapshot& snapshot,
    ks::cli::action_analyze::memory::Range range, std::string& out);

} // namespace Ksword::ActionAnalyze
