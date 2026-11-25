#pragma once

#include "ProjectStorage.h"

namespace Ksword::ActionAnalyze {

class ProjectLock final {
public:
    ProjectResult AcquireWriter(const ProjectStorage::Directory& root, bool create);
    ProjectResult AcquireReader(const ProjectStorage::Directory& root);

private:
    ProjectStorage::Handle writer_;
    ProjectStorage::Handle reader_;
};

} // namespace Ksword::ActionAnalyze
