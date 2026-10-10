#pragma once
#include "../Common.h"
#include "Clipboard.h"
namespace ks::r3::window_tools {
DWORD CurrentClipboardOwnerProcessId();
DWORD CurrentClipboardOpenProcessId();
struct ClipboardWindowIdentity {HWND window=nullptr,windowAfter=nullptr;bool stable=false,identityKnown=false;DWORD processId=0,threadId=0,error=0;};
ClipboardWindowIdentity QueryClipboardWindowIdentity(bool opener=false);
struct ClipboardClearResult {
    bool emptied=false;DWORD error=0;
    bool opened=false,attempted=false,sequenceMatched=true,beforeCountKnown=false,afterCountKnown=false,malformed=false,closeAttempted=false,closed=false;
    DWORD sequenceBefore=0,sequenceAfter=0,countBeforeError=0,countAfterError=0,closeError=0;int countBefore=0,countAfter=0;
};
ClipboardClearResult ClearClipboard(HWND owner,DWORD expectedSequence=0);
}
