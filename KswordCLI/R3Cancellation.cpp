#include "CommandRegistry.h"
#include <Windows.h>
namespace ks::cli {
namespace {
std::atomic_bool cancelled{false};
BOOL WINAPI control(DWORD kind) {
    if(kind!=CTRL_C_EVENT && kind!=CTRL_BREAK_EVENT) return FALSE;
    cancelled.store(true,std::memory_order_relaxed); return TRUE;
}
}
Cancellation::Cancellation() {
    cancelled.store(false,std::memory_order_relaxed);
    token=std::shared_ptr<std::atomic_bool>(&cancelled,[](std::atomic_bool*){});
    registered=SetConsoleCtrlHandler(control,TRUE)!=FALSE;
}
Cancellation::~Cancellation() {if(registered)SetConsoleCtrlHandler(control,FALSE);}
}
