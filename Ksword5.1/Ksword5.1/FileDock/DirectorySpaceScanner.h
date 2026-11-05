#pragma once

#include "NtfsFastIndex.h"

namespace ks::files {

// Ordinary directory enumeration; no volume handle, MFT or USN access.
class DirectorySpaceScanner final {
public:
    struct Result {
        NtfsFastIndex::Snapshot snapshot;
        quint64 skippedDirectories = 0;
        quint64 skippedReparsePoints = 0;
        quint64 duplicateFiles = 0;
        QString error;
    };

    // Blocking, metadata-only scan of the selected subtree. Run on a worker.
    // complete marks enumeration completion, not complete access: callers must
    // display the skipped counts and unknownSizeCount beside measured totals.
    // Canceled/fatal scans never publish a partially enumerated snapshot.
    static Result scan(const QString& root,
        const NtfsFastIndex::Cancel& cancel = {},
        const NtfsFastIndex::Progress& progress = {});
};

} // namespace ks::files
