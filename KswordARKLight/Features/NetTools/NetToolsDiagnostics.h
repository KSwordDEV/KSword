#pragma once

#include "../../../shared/usermode/backend/network/Diagnostics.h"

#include "NetToolsModel.h"

#include <cstdint>
#include <string>

namespace Ksword::Features::NetTools {
using ks::r3::network::DiagnosticKind;
using ks::r3::network::DiagnosticRequest;
using ks::r3::network::DiagnosticResult;


// DiagnosticKind selects which probe the diagnostics tab runs. The three share
// one request/result pair because they all produce the same thing from the
// user's point of view: a block of text about one target.


// DiagnosticRequest is one probe description. The bounds are part of the request
// rather than constants inside the worker because every one of them multiplies
// into wall-clock time: a 30-hop trace at a 3-second timeout is a minute and a
// half of a thread doing nothing but waiting.


// DiagnosticResult carries one completed probe. The text is already broken into
// CRLF lines for a multi-line EDIT, and the summary is the single line the page
// footer shows.


// RunDiagnostic executes one probe to completion. Input is the request;
// processing blocks for up to (probe count x timeout) and therefore only ever
// runs on a worker thread; output is the formatted report.
//
// Ping and traceroute are IPv4-only here: IcmpSendEcho2 needs a bound source
// address for IPv6 and picking one silently would report a path the caller never
// asked about. A target that resolves only to IPv6 is reported as such instead.
DiagnosticResult RunDiagnostic(const DiagnosticRequest& request);

// DnsRecordTypeChoiceCount / DnsRecordTypeChoiceLabel / DnsRecordTypeChoiceValue
// expose the record types the tab offers, indexed by combo position. They live
// here so the view never has to include windns.h just to fill a drop-down, and
// so the labels and the DNS_TYPE_* values can never drift apart.
int DnsRecordTypeChoiceCount();
const wchar_t* DnsRecordTypeChoiceLabel(int index);
std::uint16_t DnsRecordTypeChoiceValue(int index);

} // namespace Ksword::Features::NetTools
