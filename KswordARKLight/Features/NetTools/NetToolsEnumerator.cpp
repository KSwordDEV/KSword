#include "NetToolsEnumerator.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

namespace Ksword::Features::NetTools {


ConnectionEnumerationResult EnumerateConnections() {
    return ks::r3::network::EnumerateConnections();
}




FirewallEnumerationResult EnumerateFirewallRules() {
    return ks::r3::network::EnumerateFirewallRules();
}

} // namespace Ksword::Features::NetTools
