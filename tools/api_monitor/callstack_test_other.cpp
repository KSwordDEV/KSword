#include "APIMonitor_x64/hook/HookCallStack.h"
void storeFromOtherTranslationUnit(ks::winapi_monitor::ApiMonitorEventPacket& packet)
{ apimon::StoreHookCallStack(packet); }
