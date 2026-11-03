"""Validate the build-time API catalog and emit deterministic C++ (stdlib only).

The distributed JSON is documentation, never executable runtime configuration.
Handlers are compiled C++ registered separately; catalog values cannot inject code.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid

SUPPORTED_TYPES = set(['ACCESS_MASK', 'ALG_ID', 'BCRYPT_ALG_HANDLE', 'BCRYPT_ALG_HANDLE*', 'BCRYPT_HASH_HANDLE', 'BCRYPT_HASH_HANDLE*', 'BCRYPT_KEY_HANDLE', 'BCRYPT_KEY_HANDLE*', 'BOOL', 'BOOLEAN', 'BYTE*', 'COSERVERINFO*', 'CRYPTPROTECT_PROMPTSTRUCT*', 'DATA_BLOB*', 'DLL_DIRECTORY_COOKIE', 'DNS_STATUS', 'DWORD', 'DWORD*', 'DWORD_PTR', 'FARPROC', 'FILE_INFO_BY_HANDLE_CLASS', 'FINDEX_INFO_LEVELS', 'FINDEX_SEARCH_OPS', 'GET_FILEEX_INFO_LEVELS', 'GROUP', 'GUID*', 'HANDLE', 'HANDLE*', 'HBITMAP', 'HCERTCHAINENGINE', 'HCERTSTORE', 'HCERTSTORE*', 'HCRYPTHASH', 'HCRYPTHASH*', 'HCRYPTKEY', 'HCRYPTKEY*', 'HCRYPTMSG*', 'HCRYPTPROV', 'HCRYPTPROV*', 'HCRYPTPROV_LEGACY', 'HDC', 'HGDIOBJ', 'HHOOK', 'HINSTANCE', 'HINTERNET', 'HKEY', 'HMODULE', 'HMODULE*', 'HOOKPROC', 'HRESULT', 'HWND', 'HostEntPtr', 'IDataObject*', 'IDataObject**', 'INT', 'INTERNET_PORT', 'IUnknown*', 'JOBOBJECTINFOCLASS', 'KS_FILE_INFORMATION_CLASS', 'KS_KEY_INFORMATION_CLASS', 'KS_KEY_VALUE_INFORMATION_CLASS', 'KsIoApcRoutine', 'LARGE_INTEGER', 'LONG', 'LPARAM', 'LPBINDSTATUSCALLBACK', 'LPBOOL', 'LPBYTE', 'LPBYTE*', 'LPCGUID', 'LPCONTEXT', 'LPCREATEFILE2_EXTENDED_PARAMETERS', 'LPCSTR', 'LPCSTR*', 'LPCVOID', 'LPCWSTR', 'LPCWSTR*', 'LPDWORD', 'LPFILETIME', 'LPHANDLE', 'LPHEAPENTRY32', 'LPHEAPLIST32', 'LPINT', 'LPLONG', 'LPMODULEENTRY32W', 'LPOVERLAPPED', 'LPPROCESS_INFORMATION', 'LPPROC_THREAD_ATTRIBUTE_LIST', 'LPPROGRESS_ROUTINE', 'LPQOS', 'LPQUERY_SERVICE_CONFIGA', 'LPQUERY_SERVICE_CONFIGW', 'LPSECURITY_ATTRIBUTES', 'LPSERVICE_STATUS', 'LPSTARTUPINFOA', 'LPSTARTUPINFOW', 'LPSTR', 'LPSTR*', 'LPTHREADENTRY32', 'LPTHREAD_START_ROUTINE', 'LPUNKNOWN', 'LPURL_COMPONENTS', 'LPURL_COMPONENTSA', 'LPURL_COMPONENTSW', 'LPVOID', 'LPVOID*', 'LPWSABUF', 'LPWSADATA', 'LPWSAOVERLAPPED', 'LPWSAOVERLAPPED_COMPLETION_ROUTINE', 'LPWSAPROTOCOL_INFOA', 'LPWSAPROTOCOL_INFOW', 'LPWSTR', 'LPWSTR*', 'LSTATUS', 'MULTI_QI*', 'NCRYPT_HANDLE', 'NCRYPT_KEY_HANDLE', 'NCRYPT_KEY_HANDLE*', 'NCRYPT_PROV_HANDLE', 'NCRYPT_PROV_HANDLE*', 'NTSTATUS', 'PADDRINFOA*', 'PADDRINFOW*', 'PANSI_STRING', 'PAPCFUNC', 'PBOOL', 'PBYTE', 'PCCERT_CHAIN_CONTEXT', 'PCCERT_CHAIN_CONTEXT*', 'PCCERT_CONTEXT', 'PCERT_CHAIN_PARA', 'PCERT_CHAIN_POLICY_PARA', 'PCERT_CHAIN_POLICY_STATUS', 'PCEVENT_DESCRIPTOR', 'PCHAR', 'PCONTEXT', 'PCSTR', 'PCWSTR', 'PDNS_RECORDA*', 'PDNS_RECORDW*', 'PDWORD', 'PDWORD_PTR', 'PENABLECALLBACK', 'PEVENT_DATA_DESCRIPTOR', 'PEVENT_TRACE_LOGFILEA', 'PEVENT_TRACE_LOGFILEW', 'PEVENT_TRACE_PROPERTIES', 'PFILETIME', 'PHANDLE', 'PHKEY', 'PIO_STATUS_BLOCK', 'PKS_CLIENT_ID', 'PLARGE_INTEGER', 'PLONG', 'PLUID', 'PLUID_AND_ATTRIBUTES', 'POBJECT_ATTRIBUTES', 'PREGHANDLE', 'PROCESSENTRY32W*', 'PSECURITY_DESCRIPTOR', 'PSID', 'PSID_AND_ATTRIBUTES', 'PSIZE_T', 'PTOKEN_PRIVILEGES', 'PTRACEHANDLE', 'PUCHAR', 'PULONG', 'PUNICODE_STRING', 'PVOID', 'PVOID*', 'PWCHAR', 'PWSTR', 'REFCLSID', 'REFIID', 'REGHANDLE', 'REGSAM', 'RPC_BINDING_HANDLE', 'RPC_BINDING_HANDLE*', 'RPC_CSTR', 'RPC_CSTR*', 'RPC_EP_INQ_HANDLE', 'RPC_EP_INQ_HANDLE*', 'RPC_IF_ID*', 'RPC_STATUS', 'RPC_WSTR', 'RPC_WSTR*', 'SC_ENUM_TYPE', 'SC_HANDLE', 'SC_STATUS_TYPE', 'SECURITY_IMPERSONATION_LEVEL', 'SECURITY_STATUS', 'SHELLEXECUTEINFOA*', 'SHELLEXECUTEINFOW*', 'SIZE_T', 'SIZE_T*', 'SOCKET', 'SOLE_AUTHENTICATION_SERVICE*', 'TOKEN_INFORMATION_CLASS', 'TOKEN_TYPE', 'TRACEHANDLE', 'UCHAR', 'UINT', 'UINT*', 'ULONG', 'ULONG*', 'ULONG64', 'ULONGLONG', 'ULONG_PTR', 'USHORT', 'USHORT*', 'UUID*', 'VOID', 'VOID*', 'WNDENUMPROC', 'WORD', 'WSAEVENT', 'char*', 'const ADDRINFOA*', 'const ADDRINFOW*', 'const BYTE*', 'const CONTEXT*', 'const HANDLE*', 'const LPSECURITY_ATTRIBUTES', 'const char*', 'const sockaddr*', 'const timeval*', 'const void*', 'const void**', 'fd_set*', 'int', 'int*', 'long', 'sockaddr*', 'tagMODULEENTRY32*', 'tagPROCESSENTRY32*', 'u_long*', 'unsigned int', 'unsigned long', 'void', 'void*'])
SUPPORTED_TYPES.update(['BIND_OPTS*', 'KS_ALPC_MESSAGE_ATTRIBUTES*', 'KS_ALPC_PORT_ATTRIBUTES*', 'KS_PORT_MESSAGE*', 'MEM_EXTENDED_PARAMETER*', 'QUEUE_USER_APC_FLAGS', 'THREADINFOCLASS', 'const UNICODE_STRING*', 'void**'])
SUPPORTED_TYPES.update(["LPOVERLAPPED_COMPLETION_ROUTINE", "PULONG_PTR", "LPOVERLAPPED*", "LPOVERLAPPED_ENTRY"])
SUPPORTED_TYPES.update(["LPWSAMSG", "LPTRANSMIT_FILE_BUFFERS", "LPTRANSMIT_PACKETS_ELEMENT", "sockaddr**"])
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")
POLICIES = {"bool", "handle", "dword_nonzero", "uint_nonzero", "int_positive",
            "ulong_status", "long_status", "security_status", "rpc_status",
            "void", "lstatus", "ntstatus", "wsa_int", "hresult"}
SIZE_TYPES = {"DWORD", "ULONG", "SIZE_T", "UINT", "int", "ULONG_PTR", "ULONGLONG", "ULONG64",
              "INT", "LONG", "WORD", "USHORT", "long", "unsigned int", "unsigned long", "DWORD_PTR"}
SIZE_POINTER_TYPES = {"LPDWORD", "PULONG", "PSIZE_T", "int*", "DWORD*", "ULONG*", "UINT*", "LPINT", "LPLONG"}

# Success-defined fixed-size output values only. Explicit names prevent generic
# direction annotations from causing reads of async buffers or secrets.
OUTPUT_SNAPSHOTS = {
    'VirtualProtect': [('oldProtectPointer', 'PDWORD')],
    'DuplicateHandle': [('targetHandlePointer', 'LPHANDLE')],
    'OpenProcessToken': [('tokenHandlePointer', 'PHANDLE')],
    'OpenThreadToken': [('tokenHandlePointer', 'PHANDLE')],
    'DuplicateToken': [('newTokenHandlePointer', 'PHANDLE')],
    'DuplicateTokenEx': [('newTokenHandlePointer', 'PHANDLE')],
    'LogonUserA': [('tokenHandlePointer', 'PHANDLE')],
    'LogonUserW': [('tokenHandlePointer', 'PHANDLE')],
    'CreateRestrictedToken': [('newTokenHandlePointer', 'PHANDLE')],
    'CreatePipe': [('readPipePointer', 'PHANDLE'), ('writePipePointer', 'PHANDLE')],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(catalog, handlers):
    require(catalog.get("schema_version") == 1, "unsupported schema_version")
    ids, exports, symbols, extension_guids = set(), set(), set(), set()
    for api in catalog["apis"]:
        name = api["export"]
        require(IDENTIFIER.fullmatch(name), f"invalid export: {name}")
        require(isinstance(api["id"], int) and 0 < api["id"] < 0x80000000
                and api["id"] not in ids, f"duplicate/invalid ID: {name}")
        ids.add(api["id"])
        module = api["module"]
        require(re.fullmatch(r"[A-Za-z0-9_]+\.dll", module), f"invalid module: {name}")
        key = (module.lower(), name)
        require(key not in exports, f"duplicate export: {key}")
        exports.add(key)
        require(isinstance(api["architectures"], list) and bool(api["architectures"])
                and set(api["architectures"]) <= {"x86", "x64"}
                and len(set(api["architectures"])) == len(api["architectures"]), f"unsupported architecture: {name}")
        require(api["category"] in {"File", "Registry", "Network", "Process", "Loader", "Clipboard"}, f"bad category: {name}")
        require(api["calling_convention"] in {"WINAPI", "NTAPI", "WSAAPI", "RPC_ENTRY"}, f"bad convention: {name}")
        require(api["return_type"] in SUPPORTED_TYPES, f"invalid return type: {name}")
        binding = api["binding"]
        require(binding["scope"] in {"targets", "clipboard", "extension"}, f"invalid scope: {name}")
        if binding["scope"] == "extension":
            guid = api.get("extension_guid")
            require(isinstance(guid, str) and str(uuid.UUID(guid)) == guid and guid not in extension_guids,
                    f"invalid/duplicate extension GUID: {name}")
            extension_guids.add(guid)
            require(api["wrapper"]["kind"] == "special", f"extensions require a named handler: {name}")
        for field in ("type_alias", "record", "original", "hook"):
            symbol = binding[field]
            require(IDENTIFIER.fullmatch(symbol) and symbol not in symbols, f"duplicate/invalid symbol: {symbol}")
            symbols.add(symbol)
        names = set()
        for param in api["parameters"]:
            require(IDENTIFIER.fullmatch(param["name"]) and param["name"] not in names, f"bad parameter: {name}")
            names.add(param["name"])
            require(param["type"] in SUPPORTED_TYPES and param["type"] != "void", f"invalid parameter type: {name}.{param['name']}")
            require(param["direction"] in {"in", "out", "inout"}, f"bad direction: {name}")
            require(param["capture"] in {"handler", "formatter", "address", "value", "utf16", "ansi"}, f"bad capture: {name}")
            require(param["encoding"] in {"none", "utf16", "ansi", "bytes"}, f"bad encoding: {name}")
        for param in api["parameters"]:
            length = param["length"]
            if length is not None:
                require("*" in param["type"] or param["type"].startswith(("P", "LP")), f"length on non-buffer parameter: {name}")
                require(isinstance(length, dict) and length.get("parameter") in names
                        and length["parameter"] != param["name"]
                        and length.get("unit") in {"bytes", "elements"}
                        and isinstance(length.get("indirect", False), bool), f"bad length reference: {name}")
                source = next(p for p in api["parameters"] if p["name"] == length["parameter"])
                require(source["encoding"] == "none" and source["type"] in SIZE_TYPES | SIZE_POINTER_TYPES,
                        f"non-size length source: {name}")
                require(length.get("indirect", False) == (source["type"] in SIZE_POINTER_TYPES),
                        f"length indirection/type mismatch: {name}")
        edges = {p["name"]: p["length"]["parameter"] for p in api["parameters"] if p["length"]}
        for origin in edges:
            seen, cursor = set(), origin
            while cursor in edges:
                require(cursor not in seen, f"cyclic length relationships: {name}")
                seen.add(cursor)
                cursor = edges[cursor]
        wrapper = api["wrapper"]
        require(wrapper["kind"] in {"special", "generated"}, f"bad wrapper: {name}")
        handler = wrapper.get("handler") if wrapper["kind"] == "special" else wrapper.get("capture_handler")
        require(handler in handlers, f"unknown C++ handler: {name}: {handler}")
        if wrapper["kind"] == "generated":
            require(wrapper["policy"] in POLICIES, f"unknown return policy: {name}")
            if wrapper["policy"] == "handle":
                require(api["return"]["success"] in {"handle", "not_invalid_handle"}, f"bad handle success condition: {name}")
            if wrapper["policy"] == "wsa_int":
                require(wrapper["success"] in {"zero", "not_socket_error"}, f"bad WSA success rule: {name}")
        else:
            require(handler == binding["hook"], f"special handler/binding mismatch: {name}")
        require(api["return"]["error_source"] in {"handler", "wsa_last_error", "return_status", "win32_last_error"}, f"bad error source: {name}")
        require(api["return"]["success"] in POLICIES | {"handler", "zero", "not_socket_error", "not_invalid_handle", "nonnegative"}, f"bad success rule: {name}")


def signature(api):
    return ", ".join(p["type"] + " " + p["name"] for p in api["parameters"])


def declaration(api, external=False):
    b = api["binding"]
    types = ", ".join(p["type"] for p in api["parameters"])
    result = f"using {b['type_alias']} = {api['return_type']}({api['calling_convention']}*)({types});\n"
    result += f"{'extern ' if external else ''}InlineHookRecord {b['record']}{';' if external else '{};'}\n"
    result += f"{'extern ' if external else ''}{b['type_alias']} {b['original']}{';' if external else ' = nullptr;'}\n"
    if external:
        result += f"{api['return_type']} {api['calling_convention']} {b['hook']}({signature(api)});\n"
    return result


def wrapper(api):
    b, w = api["binding"], api["wrapper"]
    params, ret = signature(api), api["return_type"]
    args = ", ".join(p["name"] for p in api["parameters"])
    policy = w["policy"]
    uses_wsa_error = policy == "wsa_int" or api["return"]["error_source"] == "wsa_last_error"
    result = "resultHandle" if policy == "handle" else "statusValue" if policy in {
        "ulong_status", "long_status", "security_status", "rpc_status", "lstatus", "ntstatus", "hresult"} else "resultValue"
    capture_args = "detailBuffer" + (", " + args if args else "") + (", " + result if ret != "void" else "")
    capture_params = "wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars]" + (", " + params if params else "") + (f", {ret} {result}" if ret != "void" else "")
    outputs = OUTPUT_SNAPSHOTS.get(api['export'], [])
    if outputs:
        require(ret == 'BOOL' and policy == 'bool', f"output policy changed: {api['export']}")
        for name, type_name in outputs:
            require(any(p['name'] == name and p['type'] == type_name and p['direction'] == 'out'
                        for p in api['parameters']), f"output signature changed: {api['export']}.{name}")
    # SEH boundary contains no C++ objects/destructors. Invalid output pointers cannot crash the target.
    code = f"void {w['capture_handler']}Checked({capture_params})\n{{\n"
    code += f"    __try {{ {w['capture_handler']}({capture_args}); }}\n"
    code += "    __except (EXCEPTION_EXECUTE_HANDLER) { wcscpy_s(detailBuffer, ks::winapi_monitor::kMaxDetailChars, L\"capture=unreadable\"); }\n}\n"
    if outputs:
        output_params = ', '.join(f'{type_name} {name}' for name, type_name in outputs)
        code += f"void {w['capture_handler']}OutputChecked(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BOOL success, {output_params})\n{{\n"
        for name, _ in outputs:
            code += f'    AppendWideText(detailBuffer, L" out_after.{name}=");\n'
            code += f'    if (!success || !{name}) AppendWideText(detailBuffer, L"<unavailable>");\n'
            code += f'    else {{ __try {{ AppendHexText(detailBuffer, ApiReturnBits(*{name})); }}\n'
            code += '        __except (EXCEPTION_EXECUTE_HANDLER) { AppendWideText(detailBuffer, L"<unreadable>"); } }\n'
        code += '}\n'
    code += f"{ret} {api['calling_convention']} {b['hook']}({params})\n{{\n    ScopedHookGuard guardValue;\n"
    call = f"{b['original']}({args})"
    code += f"    if (guardValue.bypass()) {{ {'return ' if ret != 'void' else ''}{call};{' return;' if ret == 'void' else ''} }}\n"
    # These formatters already publish this path after the call. Snapshot it
    # beforehand as well: the callee is allowed to modify/free caller memory.
    # Do not infer permission to read arbitrary input strings from annotations:
    # other APIs can carry secrets, non-NUL buffers, or opaque string-like data.
    before_path = api['export'] in {'DeleteFileA', 'DeleteFileW', 'RemoveDirectoryA', 'RemoveDirectoryW'}
    if before_path:
        append = 'AppendWideText' if api['export'].endswith('W') else 'AppendAnsiText'
        code += '    const DWORD entryError = ::GetLastError();\n'
        code += '    wchar_t inputBefore[96] = {};\n'
        code += '    AppendWideText(inputBefore, L" input_before.path=");\n'
        code += f'    {append}(inputBefore, pathPointer, 72);\n'
        code += '    ::SetLastError(entryError);\n'
    # Snapshot argument *values*, never pointees. Even out parameters have an
    # input address that remains useful; it is not an output value. REFIID and
    # REFCLSID are C++ references and cannot safely be copied as ABI words.
    # The packet has a bounded detail field, so preserve at most eight values;
    # formatting below may truncate if a named formatter uses the whole field.
    entry_values = [(i, p) for i, p in enumerate(api['parameters'][:8], 1)
                    if p['type'] not in {'REFIID', 'REFCLSID'}]
    for position, param in entry_values:
        code += f"    const auto entryArg{position} = ApiReturnBits({param['name']});\n"
    code += "    const auto callClock = BeginApiCallClock();\n"
    code += f"    {'' if ret == 'void' else f'const {ret} {result} = '}{call};\n"
    code += "    const DWORD savedError = ::GetLastError();\n"
    if uses_wsa_error:
        code += "    const int savedWsaError = ::WSAGetLastError();\n"
    code += "    const auto duration = EndApiCallClock(callClock);\n"
    code += "    wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};\n"
    code += f"    {w['capture_handler']}Checked({capture_args});\n"
    if outputs:
        code += f"    {w['capture_handler']}OutputChecked(detailBuffer, {result}, " + ', '.join(name for name, _ in outputs) + ");\n"
    if before_path:
        code += '    AppendWideText(detailBuffer, inputBefore);\n'
    for position, _ in entry_values:
        code += f'    AppendWideText(detailBuffer, L" arg{position}=");\n'
        code += f'    AppendHexText(detailBuffer, entryArg{position});\n'
    # Append helpers cap writes; if full, reserve a marker so a clipped record
    # cannot look like a complete set of captured parameters.
    code += '    if (detailBuffer[ks::winapi_monitor::kMaxDetailChars - 2] != 0) {\n'
    code += '        constexpr wchar_t marker[] = L"<possibly-truncated>";\n'
    code += '        std::memcpy(detailBuffer + ks::winapi_monitor::kMaxDetailChars - (sizeof(marker) / sizeof(marker[0])), marker, sizeof(marker));\n'
    code += '    }\n'
    success = {"bool": f"{result} != FALSE", "handle": f"{result} != nullptr",
               "dword_nonzero": f"{result} != 0", "uint_nonzero": f"{result} != 0",
               "int_positive": f"{result} > 0"}.get(policy)
    if policy == "handle" and api["return"]["success"] == "not_invalid_handle":
        success = f"{result} != nullptr && {result} != INVALID_HANDLE_VALUE"
    if policy == "wsa_int":
        success = f"{result} == 0" if w["success"] == "zero" else f"{result} != SOCKET_ERROR"
    status = "0" if ret == "void" else f"({success}) ? 0 : {'savedWsaError' if uses_wsa_error else 'savedError'}" if success else f"static_cast<std::int32_t>({result})"
    module = api["module"][:-4]
    return_bits = '0' if ret == 'void' else f'ApiReturnBits({result})'
    has_return = 'false' if ret == 'void' else 'true'
    code += f"    SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::{api['category']}, L\"{module}\", L\"{api['export']}\", {status}, detailBuffer, {has_return}, {return_bits}, duration);\n"
    if uses_wsa_error:
        code += "    ::WSASetLastError(savedWsaError);\n"
    code += "    ::SetLastError(savedError);\n"
    if ret != "void":
        code += f"    return {result};\n"
    return code + "}\n"


def write_changed(path, content):
    encoded = content.encode("utf-8")
    if not path.exists() or path.read_bytes() != encoded:
        path.write_bytes(encoded)


def generate(source, output, architecture="x64"):
    raw = source.read_bytes()
    catalog = json.loads(raw)
    registered = set(json.loads((source.parent / "hook/ApiHandlers.json").read_text(encoding="utf-8")))
    # A registered name must also exist as a C++ definition/declaration.
    cpp = "\n".join(p.read_text(encoding="utf-8-sig") for p in (source.parent / "hook").glob("*.*") if p.suffix in {".cpp", ".h", ".inc"})
    handlers = {h for h in registered if re.search(r"\b" + re.escape(h) + r"\s*\(", cpp)}
    validate(catalog, handlers)
    output.mkdir(parents=True, exist_ok=True)
    header = "// Generated from api_monitor_definitions.json. Do not edit.\n"
    require(architecture in {"x86", "x64"}, "unsupported generation architecture")
    apis = [a for a in catalog["apis"] if architecture in a["architectures"]]
    declarations = header + "\n".join(declaration(a) for a in apis if a["binding"]["scope"] == "targets")
    extensions = [a for a in apis if a["binding"]["scope"] == "extension"]
    extension_declarations = header
    for a in extensions:
        types = ", ".join(p["type"] for p in a["parameters"])
        extension_declarations += f"\nusing {a['binding']['type_alias']} = {a['return_type']}({a['calling_convention']}*)({types});\n"
        extension_declarations += f"{a['return_type']} {a['calling_convention']} {a['wrapper']['handler']}(ExtensionContext* context, {signature(a)});\n"
    declarations += '\n#include "ApiMonitorExtensionDeclarations.inc"\n'
    abi = header + '#pragma once\nstruct ApiStackAbi { const wchar_t* module; const wchar_t* name; unsigned stackBytes; unsigned returnBytes; };\n'
    abi += 'const ApiStackAbi kApiStackAbi[] = {\n'
    for a in apis:
        sizes = ' + '.join(f'((sizeof({p["type"]}) + 3) & ~3u)' for p in a['parameters']) or '0'
        return_bytes = '0' if a['return_type'] in {'void', 'VOID'} else f'sizeof({a["return_type"]})'
        abi += f'{{ L"{a["module"]}", L"{a["export"]}", {sizes}, {return_bytes} }},\n'
    write_changed(output / 'ApiMonitorStackAbi.inc', abi + '};\n')
    write_changed(output / "ApiMonitorExtensionDeclarations.inc", extension_declarations)
    write_changed(output / "ApiMonitorDeclarations.inc", declarations)
    clip = [a for a in apis if a["binding"]["scope"] == "clipboard"]
    write_changed(output / "ApiMonitorClipboardDeclarations.inc", header + "\n".join(declaration(a, True) for a in clip))
    write_changed(output / "ApiMonitorClipboardDefinitions.inc", header + "\n".join(f"InlineHookRecord {a['binding']['record']}{{}};\n{a['binding']['type_alias']} {a['binding']['original']} = nullptr;" for a in clip))
    write_changed(output / "ApiMonitorWrappers.inc", header + "\n".join(wrapper(a) for a in apis if a["wrapper"]["kind"] == "generated"))
    table = "HookBinding g_bindings[] = {\n"
    for a in apis:
        if a["binding"]["scope"] == "extension":
            continue
        b = a["binding"]
        table += f"    {{ L\"{a['module']}\", \"{a['export']}\", ks::winapi_monitor::EventCategory::{a['category']}, &{b['record']}, reinterpret_cast<void*>(&{b['hook']}), reinterpret_cast<void**>(&{b['original']}) }},\n"
    table += "};\n"
    write_changed(output / "ApiMonitorBindings.inc", header + table)
    extension_table = header + "const ExtensionDefinition kExtensionDefinitions[] = {\n"
    for a in extensions:
        guid = uuid.UUID(a["extension_guid"])
        tail = ", ".join(f"0x{x:02X}" for x in guid.bytes[8:])
        literal = f"{{0x{guid.time_low:08X}, 0x{guid.time_mid:04X}, 0x{guid.time_hi_version:04X}, {{{tail}}}}}"
        extension_table += f"{{ {a['id']}, L\"{a['export']}\", {literal}, reinterpret_cast<void*>(&{a['wrapper']['handler']}), {len(a['parameters'])} }},\n"
    write_changed(output / "ApiMonitorExtensions.inc", extension_table + "};\n")
    digest = hashlib.sha256(raw).hexdigest()
    write_changed(output / "ApiMonitorDefinitionIdentity.h", header + f'#pragma once\nnamespace apimon {{ inline constexpr char kDefinitionSha256[] = "{digest}"; inline constexpr unsigned kDefinitionCount = {len(apis)}; }}\n')
    metadata = header + '#pragma once\n#include "ApiMonitorDefinitionIdentity.h"\nnamespace apimon {\n'
    metadata += 'struct ApiDefinitionIdentity { const wchar_t* name; const wchar_t* module; unsigned id; };\ninline constexpr ApiDefinitionIdentity kApiDefinitionIdentities[] = {\n'
    for a in sorted(apis, key=lambda a: (a["export"], a["module"].lower())):
        metadata += f'{{ L"{a["export"]}", L"{a["module"][:-4].lower()}", {a["id"]} }},\n'
    metadata += '''};
inline unsigned FindApiDefinitionId(const wchar_t* module, const wchar_t* name)
{
    if (!module || !name) return 0;
    std::size_t first = 0, last = std::size(kApiDefinitionIdentities);
    while (first < last)
    {
        const auto middle = first + (last - first) / 2;
        const int order = wcscmp(kApiDefinitionIdentities[middle].name, name);
        if (order < 0) first = middle + 1; else last = middle;
    }
    for (; first < std::size(kApiDefinitionIdentities) && wcscmp(kApiDefinitionIdentities[first].name, name) == 0; ++first)
    {
        const auto& entry = kApiDefinitionIdentities[first];
        const auto length = wcslen(entry.module);
        if (_wcsnicmp(module, entry.module, length) == 0
            && (module[length] == 0 || _wcsicmp(module + length, L".dll") == 0)) return entry.id;
    }
    return 0;
}
}\n'''
    write_changed(output / "ApiMonitorMetadata.h", metadata)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definitions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=("x86", "x64"), default="x64")
    args = parser.parse_args()
    try:
        digest = generate(args.definitions, args.output, args.architecture)
    except (ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"API definitions validation failed: {error}\n")
    print(f"API definitions validated/generated: SHA256={digest}")


if __name__ == "__main__":
    main()
