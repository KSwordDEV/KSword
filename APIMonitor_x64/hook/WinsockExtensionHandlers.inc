        struct ExtensionDefinition
        {
            std::uint32_t id;
            const wchar_t* name;
            GUID guid;
            void* dispatcher;
            unsigned arguments;
        };
        struct ExtensionContext
        {
            const ExtensionDefinition* definition = nullptr;
            void* address = nullptr;
            void* original = nullptr;
            void* detour = nullptr;
            std::uint64_t session = 0;
            InlineHookRecord record;
            bool retired = false;
        };
        struct ExtensionErrors
        {
            DWORD win32 = ::GetLastError();
            int wsa = ::WSAGetLastError();
            void Restore() const { ::WSASetLastError(wsa); ::SetLastError(win32); }
        };
        void RecordExtensionCall(ExtensionContext* context, DWORD error, SOCKET socket, LPOVERLAPPED ov,
            DWORD bytes, const wchar_t* parameters, bool hasReturn, std::uint64_t returnBits,
            const ApiCallDuration& duration, bool bytesKnown = true)
        {
            wchar_t detail[ks::winapi_monitor::kMaxDetailChars]{};
            wchar_t bytesText[32]{};
            if (bytesKnown) _snwprintf_s(bytesText, _TRUNCATE, L"%lu", bytes);
            else wcscpy_s(bytesText, L"unknown");
            _snwprintf_s(detail, _TRUNCATE, L"socket=0x%llX overlapped=%p bytes=%s %s",
                static_cast<unsigned long long>(socket), ov, bytesText, parameters);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Mswsock", context->definition->name,
                error, detail, hasReturn, returnBits, duration, context->definition->id);
        }
        BOOL WSAAPI DispatchAcceptEx(ExtensionContext* context, SOCKET listener, SOCKET accepted, PVOID buffer,
            DWORD receiveLength, DWORD localLength, DWORD remoteLength, LPDWORD bytes, LPOVERLAPPED ov)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<AcceptExFn>(context->original);
            if (guard.bypass()) return original(listener, accepted, buffer, receiveLength, localLength, remoteLength, bytes, ov);
            const ExtensionErrors incoming;
            auto op = BeginIo(listener, ov, L"Mswsock", L"AcceptEx", ks::winapi_monitor::EventCategory::Network, receiveLength);
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const BOOL result = original(listener, accepted, buffer, receiveLength, localLength, remoteLength, bytes, ov);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock);
            const DWORD error = result ? 0 : saved.wsa;
            DWORD transferred = 0;
            const bool bytesKnown = result != FALSE && TrySafeIoValue(bytes, &transferred);
            FinishIo(op, result || error == WSA_IO_PENDING, !result && error == WSA_IO_PENDING, error, transferred, bytesKnown);
            wchar_t parameters[160]{};
            _snwprintf_s(parameters, _TRUNCATE, L"accepted=0x%llX buffer=%p receive=%lu local=%lu remote=%lu",
                static_cast<unsigned long long>(accepted), buffer, receiveLength, localLength, remoteLength);
            RecordExtensionCall(context, error, listener, ov, transferred, parameters, true, ApiReturnBits(result), duration, bytesKnown);
            saved.Restore(); return result;
        }
        BOOL WSAAPI DispatchConnectEx(ExtensionContext* context, SOCKET socket, const sockaddr* address,
            int addressLength, PVOID buffer, DWORD length, LPDWORD bytes, LPOVERLAPPED ov)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<ConnectExFn>(context->original);
            if (guard.bypass()) return original(socket, address, addressLength, buffer, length, bytes, ov);
            const ExtensionErrors incoming;
            auto op = BeginIo(socket, ov, L"Mswsock", L"ConnectEx", ks::winapi_monitor::EventCategory::Network, length);
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const BOOL result = original(socket, address, addressLength, buffer, length, bytes, ov);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock); const DWORD error = result ? 0 : saved.wsa;
            DWORD transferred = 0;
            const bool bytesKnown = result != FALSE && TrySafeIoValue(bytes, &transferred);
            FinishIo(op, result || error == WSA_IO_PENDING, !result && error == WSA_IO_PENDING, error, transferred, bytesKnown);
            wchar_t parameters[160]{};
            _snwprintf_s(parameters, _TRUNCATE, L"address=%p addressLength=%d buffer=%p length=%lu", address, addressLength, buffer, length);
            RecordExtensionCall(context, error, socket, ov, transferred, parameters, true, ApiReturnBits(result), duration, bytesKnown);
            saved.Restore(); return result;
        }
        int WSAAPI DispatchWSARecvMsg(ExtensionContext* context, SOCKET socket, LPWSAMSG message,
            LPDWORD bytes, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<WSARecvMsgFn>(context->original);
            if (guard.bypass()) return original(socket, message, bytes, ov, callback);
            const ExtensionErrors incoming;
            const auto description = SafeIoValue(message);
            auto op = BeginIo(socket, ov, L"Mswsock", L"WSARecvMsg", ks::winapi_monitor::EventCategory::Network,
                SumWsaBufferLength(description.lpBuffers, description.dwBufferCount), callback != nullptr);
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(op, nullptr, callback));
            if (callback && !replacement) op.reset();
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const int result = original(socket, message, bytes, ov, replacement ? replacement : callback);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock); const DWORD error = result == 0 ? 0 : saved.wsa;
            DWORD transferred = 0;
            const bool bytesKnown = result == 0 && !ov && TrySafeIoValue(bytes, &transferred);
            FinishIo(op, result == 0 || error == WSA_IO_PENDING, result != 0 && error == WSA_IO_PENDING, error, transferred, bytesKnown);
            wchar_t parameters[160]{};
            WSAMSG output{};
            const bool flagsKnown = result == 0 && !ov && TrySafeIoValue(message, &output);
            if (flagsKnown) _snwprintf_s(parameters, _TRUNCATE, L"message=%p flags=0x%lX callback=%p", message, output.dwFlags, callback);
            else _snwprintf_s(parameters, _TRUNCATE, L"message=%p flags=unknown callback=%p", message, callback);
            RecordExtensionCall(context, error, socket, ov, transferred, parameters, true, ApiReturnBits(result), duration, bytesKnown);
            saved.Restore(); return result;
        }
        int WSAAPI DispatchWSASendMsg(ExtensionContext* context, SOCKET socket, LPWSAMSG message, DWORD flags,
            LPDWORD bytes, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<WSASendMsgFn>(context->original);
            if (guard.bypass()) return original(socket, message, flags, bytes, ov, callback);
            const ExtensionErrors incoming;
            const auto description = SafeIoValue(message);
            auto op = BeginIo(socket, ov, L"Mswsock", L"WSASendMsg", ks::winapi_monitor::EventCategory::Network,
                SumWsaBufferLength(description.lpBuffers, description.dwBufferCount), callback != nullptr);
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(op, nullptr, callback));
            if (callback && !replacement) op.reset();
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const int result = original(socket, message, flags, bytes, ov, replacement ? replacement : callback);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock); const DWORD error = result == 0 ? 0 : saved.wsa;
            DWORD transferred = 0;
            const bool bytesKnown = result == 0 && !ov && TrySafeIoValue(bytes, &transferred);
            FinishIo(op, result == 0 || error == WSA_IO_PENDING, result != 0 && error == WSA_IO_PENDING, error, transferred, bytesKnown);
            wchar_t parameters[160]{};
            _snwprintf_s(parameters, _TRUNCATE, L"message=%p flags=0x%lX callback=%p", message, flags, callback);
            RecordExtensionCall(context, error, socket, ov, transferred, parameters, true, ApiReturnBits(result), duration, bytesKnown);
            saved.Restore(); return result;
        }
        BOOL WSAAPI DispatchTransmitFile(ExtensionContext* context, SOCKET socket, HANDLE file, DWORD length,
            DWORD perSend, LPOVERLAPPED ov, LPTRANSMIT_FILE_BUFFERS buffers, DWORD flags)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<TransmitFileFn>(context->original);
            if (guard.bypass()) return original(socket, file, length, perSend, ov, buffers, flags);
            const ExtensionErrors incoming;
            auto op = BeginIo(socket, ov, L"Mswsock", L"TransmitFile", ks::winapi_monitor::EventCategory::Network, length);
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const BOOL result = original(socket, file, length, perSend, ov, buffers, flags);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock); const DWORD error = result ? 0 : saved.wsa;
            const DWORD transferred = 0; // No reliable byte count is exposed by this entry point.
            FinishIo(op, result || error == WSA_IO_PENDING, !result && error == WSA_IO_PENDING, error, transferred, false);
            wchar_t parameters[160]{};
            _snwprintf_s(parameters, _TRUNCATE, L"file=%p length=%lu perSend=%lu buffers=%p flags=0x%lX", file, length, perSend, buffers, flags);
            RecordExtensionCall(context, error, socket, ov, transferred, parameters, true, ApiReturnBits(result), duration, false);
            saved.Restore(); return result;
        }
        std::uint64_t TransmitPacketLength(LPTRANSMIT_PACKETS_ELEMENT packets, DWORD count)
        {
            std::uint64_t total = 0;
            for (DWORD index = 0; packets && index < (std::min)(count, 1024UL); ++index) total += SafeIoValue(packets + index).cLength;
            return total;
        }
        BOOL WSAAPI DispatchTransmitPackets(ExtensionContext* context, SOCKET socket, LPTRANSMIT_PACKETS_ELEMENT packets,
            DWORD count, DWORD sendSize, LPOVERLAPPED ov, DWORD flags)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<TransmitPacketsFn>(context->original);
            if (guard.bypass()) return original(socket, packets, count, sendSize, ov, flags);
            const ExtensionErrors incoming;
            const auto length = TransmitPacketLength(packets, count);
            auto op = BeginIo(socket, ov, L"Mswsock", L"TransmitPackets", ks::winapi_monitor::EventCategory::Network, length);
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const BOOL result = original(socket, packets, count, sendSize, ov, flags);
            const ExtensionErrors saved; const auto duration = EndApiCallClock(callClock); const DWORD error = result ? 0 : saved.wsa;
            const DWORD transferred = 0; // No reliable byte count is exposed by this entry point.
            FinishIo(op, result || error == WSA_IO_PENDING, !result && error == WSA_IO_PENDING, error, transferred, false);
            wchar_t parameters[160]{};
            _snwprintf_s(parameters, _TRUNCATE, L"packets=%p count=%lu sendSize=%lu flags=0x%lX", packets, count, sendSize, flags);
            RecordExtensionCall(context, error, socket, ov, transferred, parameters, true, ApiReturnBits(result), duration, false);
            saved.Restore(); return result;
        }
        VOID WSAAPI DispatchGetAcceptExSockaddrs(ExtensionContext* context, PVOID buffer, DWORD receiveLength,
            DWORD localLength, DWORD remoteLength, sockaddr** local, LPINT localSize, sockaddr** remote, LPINT remoteSize)
        {
            ScopedHookGuard guard;
            const auto original = reinterpret_cast<GetAcceptExSockaddrsFn>(context->original);
            if (guard.bypass()) { original(buffer, receiveLength, localLength, remoteLength, local, localSize, remote, remoteSize); return; }
            const auto callClock = BeginApiCallClock();
            original(buffer, receiveLength, localLength, remoteLength, local, localSize, remote, remoteSize);
            const ExtensionErrors saved;
            const auto duration = EndApiCallClock(callClock);
            wchar_t parameters[200]{};
            _snwprintf_s(parameters, _TRUNCATE, L"buffer=%p receive=%lu localLength=%lu remoteLength=%lu local=%p localSize=%d remote=%p remoteSize=%d",
                buffer, receiveLength, localLength, remoteLength, SafeIoValue(local), SafeIoValue(localSize), SafeIoValue(remote), SafeIoValue(remoteSize));
            RecordExtensionCall(context, 0, 0, nullptr, 0, parameters, false, 0, duration, false); saved.Restore();
        }

        #include "ApiMonitorExtensions.inc"
        auto& g_extensionMutex = *new std::mutex;
        auto& g_extensions = *new std::vector<ExtensionContext*>;
        void TryInstallExtension(ExtensionContext* context)
        {
            if (context->retired || context->record.installed || context->record.permanentlyDisabled
                || StopRequested() || !CategoryEnabled(ks::winapi_monitor::EventCategory::Network)) return;
            if (!context->detour) context->detour = BuildContextThunk(context, context->definition->dispatcher, context->definition->arguments);
            if (!context->detour) { context->record.lastFailure = L"extension context thunk allocation failed"; return; }
            (void)InstallInlineHookAtAddress(context->address, context->detour, &context->record, &context->original, nullptr);
        }
        void DiscoverExtension(const GUID& guid, void* address) noexcept
        {
            try
            {
                if (!address || StopRequested()) return;
                ScopedInlineHookInternalBypass bypass;
                std::lock_guard lock(g_extensionMutex);
                const auto session = CurrentMonitorSessionIdentity();
                if (!session) return;
                for (const auto& definition : kExtensionDefinitions)
                {
                    if (std::memcmp(&guid, &definition.guid, sizeof(guid))) continue;
                    for (auto* context : g_extensions)
                        if (context->definition == &definition && context->address == address && context->session == session)
                        { TryInstallExtension(context); return; }
                    auto* context = new ExtensionContext;
                    context->definition = &definition; context->address = address; context->session = session;
                    g_extensions.push_back(context);
                    TryInstallExtension(context); return;
                }
            }
            catch (...) {}
        }
        void RetryExtensionHooks()
        {
            std::lock_guard lock(g_extensionMutex);
            for (auto* context : g_extensions) if (context->session == CurrentMonitorSessionIdentity()) TryInstallExtension(context);
        }
        bool UninstallExtensionHooks()
        {
            std::lock_guard lock(g_extensionMutex);
            bool removed = true;
            for (auto* context : g_extensions) {
                if (UninstallInlineHook(&context->record)) context->retired = true;
                else removed = false;
            }
            return removed;
        }
        void AppendExtensionCoverage(std::vector<ks::winapi_monitor::ApiMonitorEventPacket>& rows)
        {
            using namespace ks::winapi_monitor;
            std::lock_guard lock(g_extensionMutex);
            for (const auto& definition : kExtensionDefinitions)
            {
                bool discovered = false;
                for (const auto* context : g_extensions)
                {
                    if (context->definition != &definition || context->session != CurrentMonitorSessionIdentity()) continue;
                    discovered = true;
                    ApiMonitorEventPacket row{};
                    row.apiId = definition.id; row.hookKind = static_cast<std::uint32_t>(HookKind::DynamicExtension);
                    row.hookAddress = reinterpret_cast<std::uintptr_t>(context->record.targetAddress ? context->record.targetAddress : context->address);
                    const auto state = context->record.installed ? (context->record.sharedEntry ? CoverageState::SharedEntry : CoverageState::Installed)
                        : context->retired ? CoverageState::Removed
                        : !CategoryEnabled(EventCategory::Network) ? CoverageState::CategoryDisabled
                        : context->record.permanentlyDisabled ? CoverageState::Unsupported : CoverageState::RetryableFailure;
                    row.coverageState = static_cast<std::uint32_t>(state);
                    wcscpy_s(row.moduleName, L"Mswsock.dll"); wcscpy_s(row.apiName, definition.name);
                    wcsncpy_s(row.detailText, context->record.lastFailure.c_str(), _TRUNCATE);
                    rows.push_back(row);
                }
                if (!discovered) {
                    ApiMonitorEventPacket row{}; row.apiId = definition.id;
                    row.hookKind = static_cast<std::uint32_t>(HookKind::DynamicExtension);
                    row.coverageState = static_cast<std::uint32_t>(CategoryEnabled(EventCategory::Network)
                        ? CoverageState::WaitingModule : CoverageState::CategoryDisabled);
                    wcscpy_s(row.moduleName, L"Mswsock.dll"); wcscpy_s(row.apiName, definition.name);
                    wcscpy_s(row.detailText, L"extension address not yet discovered via WSAIoctl"); rows.push_back(row);
                }
            }
        }
        struct ExtensionDiscovery
        {
            GUID guid{};
            LPVOID output = nullptr;
            DWORD capacity = 0;
            LPDWORD returned = nullptr;
        };
        void DiscoverCompletedIoctl(const IoToken& op, DWORD error)
        {
            const auto* discovery = static_cast<const ExtensionDiscovery*>(op->observerContext);
            if (!error && discovery && op->completionBytesKnown && discovery->capacity >= sizeof(void*) && op->completionBytes >= sizeof(void*))
                DiscoverExtension(discovery->guid, SafeIoValue(static_cast<void**>(discovery->output)));
        }
        int WSAAPI HookedWSAIoctl(SOCKET socketValue, DWORD ioControlCode, LPVOID inBufferPointer, DWORD inBufferSize,
            LPVOID outBufferPointer, DWORD outBufferSize, LPDWORD bytesReturnedPointer,
            LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guard;
            if (guard.bypass()) return g_wsaIoctlOriginal(socketValue, ioControlCode, inBufferPointer, inBufferSize,
                outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer, completionRoutinePointer);
            const ExtensionErrors incoming;
            const bool discover = ioControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && inBufferSize >= sizeof(GUID);
            const GUID guid = discover ? SafeIoValue(static_cast<GUID*>(inBufferPointer)) : GUID{};
            auto op = BeginIo(socketValue, overlappedPointer, L"Ws2_32", L"WSAIoctl", ks::winapi_monitor::EventCategory::Network,
                outBufferSize, completionRoutinePointer != nullptr);
            if (discover && op) {
                auto* discovery = new(std::nothrow) ExtensionDiscovery{guid, outBufferPointer, outBufferSize, bytesReturnedPointer};
                if (discovery) { op->observerContext = discovery; op->completionObserver = &DiscoverCompletedIoctl; }
            }
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(op, nullptr, completionRoutinePointer));
            if (completionRoutinePointer && !replacement) op.reset();
            incoming.Restore();
            const auto callClock = BeginApiCallClock();
            const int result = g_wsaIoctlOriginal(socketValue, ioControlCode, inBufferPointer, inBufferSize,
                outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer, replacement ? replacement : completionRoutinePointer);
            const auto duration = EndApiCallClock(callClock);
            const ExtensionErrors saved; const DWORD error = result == 0 ? 0 : saved.wsa;
            DWORD returned = 0;
            // WSAIoctl documents a valid byte count on immediate success even with OVERLAPPED.
            const bool returnedKnown = result == 0 && TrySafeIoValue(bytesReturnedPointer, &returned);
            FinishIo(op, result == 0 || error == WSA_IO_PENDING, result != 0 && error == WSA_IO_PENDING, error, returned, returnedKnown);
            if (returnedKnown && discover && outBufferSize >= sizeof(void*) && returned >= sizeof(void*))
                DiscoverExtension(guid, SafeIoValue(static_cast<void**>(outBufferPointer)));
            wchar_t detail[ks::winapi_monitor::kMaxDetailChars]{};
            wchar_t returnedText[32]{};
            if (returnedKnown) _snwprintf_s(returnedText, _TRUNCATE, L"%lu", returned);
            else wcscpy_s(returnedText, L"unknown");
            _snwprintf_s(detail, _TRUNCATE, L"socket=0x%llX code=0x%lX in=%p inLength=%lu out=%p outLength=%lu returned=%s overlapped=%p callback=%p",
                static_cast<unsigned long long>(socketValue), ioControlCode, inBufferPointer, inBufferSize, outBufferPointer,
                outBufferSize, returnedText, overlappedPointer, completionRoutinePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"WSAIoctl", error, detail, true, ApiReturnBits(result), duration);
            saved.Restore(); return result;
        }
