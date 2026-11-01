// The production callback uses its outcome only with perf tracing enabled.
// Keep that existing release-only unused-parameter warning local to this test
// translation unit while retaining /W4 /WX for the remaining test sources.
#pragma warning(push)
#pragma warning(disable: 4100)
#include "../../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp"
#pragma warning(pop)
