#pragma once

#include "../../../shared/usermode/backend/network/Connections.h"

#include "NetToolsModel.h"

namespace Ksword::Features::NetTools {
using ks::r3::network::NetToolsActionResult;


// NetToolsActionResult is the value-only outcome of one mutation. Inputs come
// from the action functions below; the message is already user-facing text and
// the view never needs to interpret the result any further.


// CloseTcpConnection deletes the TCB of one IPv4 TCP connection through
// SetTcpEntry. Input is the selected row; processing rebuilds the exact tuple the
// IP Helper table reported and issues one SetTcpEntry; output reports the Win32
// status as readable text.
//
// This is the destructive operation on this page. The peer sees the connection
// vanish without a FIN, whatever was in flight is lost, and nothing puts it back
// -- the view asks for confirmation before calling this, and it needs the
// process to be running elevated to succeed at all.
using ks::r3::network::CloseTcpConnection;

} // namespace Ksword::Features::NetTools
