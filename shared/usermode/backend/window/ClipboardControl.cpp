#include "ClipboardControl.h"

namespace ks::r3::window_tools {
ClipboardWindowIdentity QueryClipboardWindowIdentity(bool opener){ClipboardWindowIdentity e;
    const auto get=[&]{::SetLastError(0);return opener?::GetOpenClipboardWindow(): ::GetClipboardOwner();};e.window=get();e.error=e.window?0: ::GetLastError();
    if(!e.window){e.windowAfter=get();if(!e.windowAfter&&!e.error)e.error=::GetLastError();e.stable=e.windowAfter==nullptr;e.identityKnown=e.stable&&!e.error;return e;}
    if(::IsWindow(e.window)){::SetLastError(0);e.threadId=::GetWindowThreadProcessId(e.window,&e.processId);e.error=e.threadId&&e.processId?0: ::GetLastError();}
    e.windowAfter=get();if(!e.windowAfter&&!e.error)e.error=::GetLastError();e.stable=e.windowAfter==e.window;e.identityKnown=e.stable&&e.threadId&&e.processId;return e;
}
DWORD CurrentClipboardOwnerProcessId() {
    const auto evidence=QueryClipboardWindowIdentity();return evidence.identityKnown?evidence.processId:0U;
}
DWORD CurrentClipboardOpenProcessId() {
    const auto evidence=QueryClipboardWindowIdentity(true);return evidence.identityKnown?evidence.processId:0U;
}
ClipboardClearResult ClearClipboard(HWND owner,DWORD expectedSequence) {
    ClipboardClearResult e;ScopedClipboard clipboard(owner);e.opened=clipboard.opened();
    if(e.opened){e.sequenceBefore=::GetClipboardSequenceNumber();e.sequenceMatched=!expectedSequence||(e.sequenceBefore&&e.sequenceBefore==expectedSequence);
        if(e.sequenceMatched){::SetLastError(0);e.countBefore=::CountClipboardFormats();e.countBeforeError=::GetLastError();e.beforeCountKnown=e.countBefore>=0&&(!e.countBeforeError||e.countBefore>0);e.malformed=e.countBefore<0;
            e.attempted=true;::SetLastError(0);e.emptied=::EmptyClipboard()!=FALSE;e.error=e.emptied?0: ::GetLastError();
            if(e.emptied){::SetLastError(0);e.countAfter=::CountClipboardFormats();e.countAfterError=::GetLastError();e.afterCountKnown=e.countAfter>=0&&(!e.countAfterError||e.countAfter>0);e.malformed=e.malformed||e.countAfter<0;e.sequenceAfter=::GetClipboardSequenceNumber();}
        }else e.error=ERROR_INVALID_DATA;
    }else e.error=clipboard.lastError();
    e.closed=clipboard.close();e.closeAttempted=clipboard.closeAttempted();e.closeError=clipboard.closeError();return e;
}
}
