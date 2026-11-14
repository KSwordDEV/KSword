-- Adapter-independent binary backend API exposed to CE's Lua engine.
-- All requests use the exact shared/driver structures, negotiated from the DLL.
return function(appendLog, bridgePath)
    assert(cheatEngineIs64Bit(), "KSword debugger integration requires 64-bit CE")
    local getModule = assert(getAddressSafe("kernel32.GetModuleHandleW", true), "GetModuleHandleW is missing")
    local getProc = assert(getAddressSafe("kernel32.GetProcAddress", true), "GetProcAddress is missing")
    local function resolve()
        local module = executeCodeLocalEx(getModule, {type = 4, value = bridgePath})
        if module == nil or module == 0 then
            module = executeCodeLocalEx(getModule, {type = 4, value = "KswordCheatEnginePlugin.dll"})
        end
        if module == nil or module == 0 then return nil end
        local address = executeCodeLocalEx(getProc, module, {type = 3, value = "KSwordDebuggerCall"})
        return address ~= 0 and address or nil
    end
    assert(resolve() ~= nil, "KSword debugger backend API export is missing")
    local api = {version = 1, hvm = {}}
    local commands = {status = 16, control = 17, memory = 18, eptRule = 19,
        events = 20, view = 21, crPolicy = 22, msrPolicy = 23, domain = 24,
        process = 25, inject = 26, platform = 27, metrics = 28,
        nestedProbe = 29, nestedPage = 30, breakpoint = 31, native = 32, noAttach = 33, kernelNoAttach = 34}

    local function buffer(size)
        local stream = createMemoryStream()
        stream.Size = size
        if size > 0 then
            writeBytesLocal(stream.Memory, stringToByteTable(string.rep("\0", size)))
        end
        return stream
    end

    local function invoke(command, input, outputBytes)
        local call, output = buffer(48), buffer(outputBytes)
        -- Re-resolve on CE's UI thread so disabling/unloading the plugin leaves no cached code pointer.
        local address = resolve()
        if address == nil then call.destroy(); return output, 126, 0 end
        local p = call.Memory
        writeIntegerLocal(p, 1)
        writeIntegerLocal(p + 4, 48)
        writeIntegerLocal(p + 8, command)
        writeQwordLocal(p + 16, input and input.Memory or 0)
        writeQwordLocal(p + 24, output.Memory)
        writeIntegerLocal(p + 32, input and input.Size or 0)
        writeIntegerLocal(p + 36, outputBytes)
        local ok, errorCode = pcall(executeCodeLocalEx, address, p)
        if not ok then call.destroy(); output.destroy(); error(errorCode) end
        local returned = readIntegerLocal(p + 44)
        call.destroy()
        if returned < 0 or returned > outputBytes then output.destroy(); error("Invalid KSword response length") end
        return output, errorCode, returned
    end

    function api.status()
        local output, errorCode, returned = invoke(1, nil, 40)
        if errorCode ~= 0 then output.destroy(); return nil, errorCode end
        if returned ~= 40 or readIntegerLocal(output.Memory) ~= 1 or
            readIntegerLocal(output.Memory + 4) ~= 40 then output.destroy(); return nil, 13 end
        local p = output.Memory
        local status = {driverReady = readIntegerLocal(p + 8) ~= 0,
            useHvm = readIntegerLocal(p + 12) ~= 0,
            directMemoryWindow = readIntegerLocal(p + 16) ~= 0,
            residentActive = readIntegerLocal(p + 20) ~= 0,
            ownsResident = readIntegerLocal(p + 24) ~= 0,
            attachedProcessId = readIntegerLocal(p + 28),
            eptBreakpointProtocol = readIntegerLocal(p + 32),
            lastError = readIntegerLocal(p + 36)}
        output.destroy()
        return status, 0
    end

    function api.useHvm(enabled)
        local input = buffer(4)
        writeIntegerLocal(input.Memory, enabled and 1 or 0)
        local output, errorCode = invoke(2, input, 40)
        input.destroy(); output.destroy()
        return errorCode == 0, errorCode
    end

    local optionFields = {"mode", "shadowMemoryWrites", "allowFallback", "logFallback",
        "nativeContextFallback", "nativeSuspendFallback", "maxShadowPages"}
    local booleanFields = {shadowMemoryWrites = true, allowFallback = true, logFallback = true,
        nativeContextFallback = true, nativeSuspendFallback = true}
    local function decodeOptions(output, returned, expectedSize)
        if returned ~= expectedSize or readIntegerLocal(output.Memory) ~= 1 or
            readIntegerLocal(output.Memory + 4) ~= 48 then return nil end
        local options = {version = 1, size = 48}
        for index, name in ipairs(optionFields) do
            local value = readIntegerLocal(output.Memory + 4 + index * 4)
            if booleanFields[name] then
                if value > 1 then return nil end
                options[name] = value ~= 0
            else options[name] = value end
        end
        if options.mode > 1 or options.maxShadowPages < 1 or options.maxShadowPages > 32 or not options.logFallback or
            readIntegerLocal(output.Memory + 36) ~= 0 or readIntegerLocal(output.Memory + 40) ~= 0 or
            readIntegerLocal(output.Memory + 44) ~= 0 then return nil end
        return options
    end
    function api.options()
        local output, errorCode, returned = invoke(4, nil, 48)
        local options = decodeOptions(output, returned, 48)
        output.destroy()
        if options == nil and errorCode == 0 then errorCode = 13 end
        return options, errorCode
    end
    api.getOptions = api.options
    function api.setOptions(changes)
        assert(type(changes) == "table", "Options must be a table")
        local current, errorCode = api.options()
        if current == nil or errorCode ~= 0 then return nil, errorCode end
        for name, value in pairs(changes) do
            assert(booleanFields[name] or name == "mode" or name == "maxShadowPages", "Unknown backend option: " .. name)
            if booleanFields[name] then assert(type(value) == "boolean", name .. " must be boolean") end
            if name == "mode" then assert(value == 0 or value == 1, "mode must be 0 (normal) or 1 (stealth)") end
            if name == "maxShadowPages" then
                assert(type(value) == "number" and value == math.floor(value) and value >= 1 and value <= 32,
                    "maxShadowPages must be an integer from 1 to 32")
            end
            current[name] = value
        end
        -- Every fallback must remain observable, including calls made from user Lua.
        assert(current.logFallback, "Fallback logging cannot be disabled")
        local input = buffer(48)
        writeIntegerLocal(input.Memory, 1); writeIntegerLocal(input.Memory + 4, 48)
        for index, name in ipairs(optionFields) do
            local value = current[name]
            if booleanFields[name] then value = value and 1 or 0 end
            writeIntegerLocal(input.Memory + 4 + index * 4, value)
        end
        local output, result, returned = invoke(5, input, 48)
        input.destroy()
        local actual = decodeOptions(output, returned, 48)
        output.destroy()
        if actual == nil and result == 0 then result = 13 end
        if result ~= 0 then appendLog("Backend options rejected, error " .. result) end
        return actual, result
    end
    function api.policy()
        local output, errorCode, returned = invoke(6, nil, 72)
        local policy = decodeOptions(output, returned, 72)
        if policy ~= nil then
            local fields = {"activePath", "shadowWritePages", "activeBreakpoints", "canChangeOptions",
                "fallbackCount", "lastFallbackError"}
            for index, name in ipairs(fields) do policy[name] = readIntegerLocal(output.Memory + 44 + index * 4) end
            if policy.activePath > 2 or policy.canChangeOptions > 1 then policy = nil
            else policy.canChangeOptions = policy.canChangeOptions ~= 0 end
        elseif errorCode == 0 then errorCode = 13 end
        if policy == nil and errorCode == 0 then errorCode = 13 end
        output.destroy()
        return policy, errorCode
    end
    function api.restoreShadowWrites(address, bytes)
        address, bytes = address or 0, bytes or 0
        assert(type(address) == "number" and type(bytes) == "number" and address >= 0 and bytes >= 0 and
            address == math.floor(address) and bytes == math.floor(bytes) and
            ((address == 0 and bytes == 0) or (address > 0 and bytes > 0)),
            "Use 0/0 for all Shadow writes, or a nonzero address and byte count")
        local input = buffer(24)
        writeIntegerLocal(input.Memory, 1); writeIntegerLocal(input.Memory + 4, 24)
        writeQwordLocal(input.Memory + 8, address); writeQwordLocal(input.Memory + 16, bytes)
        local output, errorCode, returned = invoke(7, input, 40)
        if errorCode == 0 and (returned ~= 40 or readIntegerLocal(output.Memory) ~= 1 or
            readIntegerLocal(output.Memory + 4) ~= 40) then errorCode = 13 end
        input.destroy(); output.destroy()
        appendLog(errorCode == 0 and "Shadow execution-view writes restored" or
            ("Shadow write restore rejected, error " .. errorCode))
        return errorCode == 0, errorCode
    end

    -- packet.write32/write64 use byte offsets from the shared protocol headers.
    -- send returns the raw response and transport error; inspect protocol status too.
    function api.hvm.packet(name)
        local command = assert(commands[name], "Unknown KSword HVM operation")
        local query = buffer(4)
        writeIntegerLocal(query.Memory, command)
        local layout, errorCode, returned = invoke(3, query, 24)
        query.destroy()
        if errorCode ~= 0 then layout.destroy(); error("KSword schema error " .. errorCode) end
        if returned ~= 24 or readIntegerLocal(layout.Memory) ~= 1 or
            readIntegerLocal(layout.Memory + 4) ~= command then
            layout.destroy(); error("Invalid KSword schema identity")
        end
        local inputBytes = readIntegerLocal(layout.Memory + 8)
        local outputBytes = readIntegerLocal(layout.Memory + 12)
        local protocol = readIntegerLocal(layout.Memory + 16)
        layout.destroy()
        assert(inputBytes >= 8 and inputBytes <= 4 * 1024 * 1024 and
            outputBytes >= 8 and outputBytes <= 8 * 1024 * 1024 and protocol > 0,
            "Invalid KSword schema size/version")
        local input = buffer(inputBytes)
        writeIntegerLocal(input.Memory, protocol)
        writeIntegerLocal(input.Memory + 4, inputBytes)
        local packet = {command = command, input = input, outputBytes = outputBytes}
        function packet.write32(offset, value)
            assert(offset >= 0 and offset + 4 <= input.Size, "Field outside request")
            writeIntegerLocal(input.Memory + offset, value)
            return packet
        end
        function packet.write64(offset, value)
            assert(offset >= 0 and offset + 8 <= input.Size, "Field outside request")
            writeQwordLocal(input.Memory + offset, value)
            return packet
        end
        function packet.writeBytes(offset, bytes)
            assert(offset >= 0 and offset + #bytes <= input.Size, "Payload outside request")
            writeBytesLocal(input.Memory + offset, bytes)
            return packet
        end
        function packet.send()
            local output, transportError, returned = invoke(command, input, outputBytes)
            local bytes = returned > 0 and readBytesLocal(output.Memory, returned, true) or {}
            output.destroy()
            if transportError ~= 0 then appendLog("HVM " .. name .. " failed: " .. transportError) end
            return bytes, transportError
        end
        function packet.destroy()
            if input ~= nil then input.destroy(); input = nil; packet.input = nil end
        end
        return packet
    end
    api.hvm.commands = commands
    -- Independent execution channel. These calls never invoke CE's debugProcess,
    -- debug_continueFromBreakpoint, VEH debugger, TF stepping or DR breakpoint API.
    local noAttach = {sessionId = 0, stopId = 0, backend = "hvm", uncertain = false}
    api.noAttach = noAttach
    local function noAttachCall(operation, options)
        options = options or {}
        local request = buffer(232)
        local kernel = noAttach.backend == "kernel"
        local protocol = kernel and 1 or 2
        writeIntegerLocal(request.Memory, protocol)
        writeIntegerLocal(request.Memory + 4, 232)
        writeIntegerLocal(request.Memory + 8, operation)
        writeIntegerLocal(request.Memory + 12, options.flags or 0)
        writeIntegerLocal(request.Memory + 16, options.pid or 0)
        writeIntegerLocal(request.Memory + 20, options.tid or 0)
        writeQwordLocal(request.Memory + 48, noAttach.sessionId)
        writeQwordLocal(request.Memory + 56, noAttach.stopId)
        writeQwordLocal(request.Memory + 64, options.address or 0)
        writeIntegerLocal(request.Memory + 72, options.breakpointId or 0)
        writeIntegerLocal(request.Memory + 76, options.breakpointFlags or 0)
        writeQwordLocal(request.Memory + 80, options.minimumRsp or 0)
        if options.registerIndex ~= nil then
            writeQwordLocal(request.Memory + 88, 1 << options.registerIndex)
            writeQwordLocal(request.Memory + 96 + options.registerIndex * 8, options.value)
        end
        if operation == 1 then noAttach.uncertain = true end
        local output, transport, returned = invoke(kernel and 34 or 33, request, 480)
        request.destroy()
        if transport ~= 0 then output.destroy(); return nil, transport end
        if returned ~= 480 or readIntegerLocal(output.Memory) ~= protocol or readIntegerLocal(output.Memory + 4) ~= 480 then
            output.destroy(); return nil, 13
        end
        local status = readIntegerLocal(output.Memory + 8)
        if status >= 0x80000000 then status = status - 0x100000000 end
        local result = {status = status, state = readIntegerLocal(output.Memory + 12),
            capabilities = readIntegerLocal(output.Memory + 16), reason = readIntegerLocal(output.Memory + 20),
            pid = readIntegerLocal(output.Memory + 24), tid = readIntegerLocal(output.Memory + 28),
            sessionId = readQwordLocal(output.Memory + 32), stopId = readQwordLocal(output.Memory + 40),
            breakpointId = readIntegerLocal(output.Memory + 216), breakpoints = {}}
        if result.state < 0 or result.state > 11 then output.destroy(); return nil, 13 end
        -- Historical registers are never exposed as a current stop.
        local currentStop = status >= 0 and result.state == 3 and result.stopId or 0
        if status >= 0 and result.state == 3 and
            (result.sessionId == 0 or currentStop == 0 or result.reason < 1 or result.reason > 4) then
            output.destroy(); return nil, 13
        end
        if currentStop ~= 0 then
            result.rip = readQwordLocal(output.Memory + 64)
            result.rsp = readQwordLocal(output.Memory + 72)
            result.rflags = readQwordLocal(output.Memory + 80)
            result.registers = {}
            local names = {"rax","rcx","rdx","rbx","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"}
            for index, name in ipairs(names) do result.registers[name] = readQwordLocal(output.Memory + 88 + index * 8) end
        end
        local count = readIntegerLocal(output.Memory + 220)
        if count < 0 or count > (kernel and 4 or 8) then output.destroy(); return nil, 13 end
        for index = 0, count - 1 do
            local at = output.Memory + 224 + index * 32
            result.breakpoints[#result.breakpoints + 1] = {id = readIntegerLocal(at), flags = readIntegerLocal(at + 4),
                address = readQwordLocal(at + 8), physicalPage = readQwordLocal(at + 16), minimumRsp = readQwordLocal(at + 24)}
        end
        output.destroy()
        -- Commit cached command authority only after validating the whole response.
        if result.sessionId ~= 0 then noAttach.sessionId = result.sessionId; noAttach.uncertain = false end
        if status >= 0 and (result.state == 0 or result.state == 9) and result.sessionId == 0 then
            noAttach.sessionId = 0; noAttach.uncertain = false
        end
        noAttach.stopId = currentStop
        noAttach.last = result
        if status < 0 then appendLog("No-attach request rejected: NTSTATUS=" .. string.format("%08X", status & 0xffffffff)) end
        return result, 0
    end
    function noAttach.useBackend(backend)
        assert(backend == "hvm" or backend == "kernel", "Choose hvm or kernel")
        assert(noAttach.sessionId == 0 and not noAttach.uncertain, "QUERY/CLOSE the current transport first")
        noAttach.backend, noAttach.stopId, noAttach.last = backend, 0, nil
        if backend == "kernel" then appendLog("Kernel no-attach: version-bound exception hook, TF/DR; driver bridge remains resident until reboot") end
    end
    function noAttach.query() return noAttachCall(0) end
    function noAttach.open(pid, tid, confirmed, allowNested)
        assert(confirmed == true, "Explicit no-attach HVM startup confirmation is required")
        assert(noAttach.sessionId == 0 and not noAttach.uncertain, "Close or recover the existing no-attach session first")
        assert(type(pid) == "number" and pid > 4 and type(tid) == "number" and tid > 0, "Select a process and thread")
        assert(noAttach.backend ~= "kernel" or not allowNested, "Nested virtualization applies only to the HVM transport")
        return noAttachCall(1, {pid = pid, tid = tid, flags = noAttach.backend == "kernel" and 5 or (allowNested and 3 or 1)})
    end
    function noAttach.pause() return noAttachCall(2) end
    function noAttach.step() assert(noAttach.stopId ~= 0, "Query the current stop first"); return noAttachCall(3) end
    function noAttach.continue() assert(noAttach.stopId ~= 0, "Query the current stop first"); return noAttachCall(4) end
    function noAttach.close() return noAttachCall(5) end
    function noAttach.addBreakpoint(address, once)
        assert(noAttach.stopId ~= 0, "Query the current stop first")
        return noAttachCall(6, {address = address, breakpointFlags = once and 1 or 0})
    end
    function noAttach.removeBreakpoint(id)
        assert(noAttach.stopId ~= 0, "Query the current stop first")
        return noAttachCall(7, {breakpointId = id})
    end
    function noAttach.runTo(address, minimumRsp)
        assert(noAttach.stopId ~= 0, "Query the current stop first")
        return noAttachCall(8, {address = address, minimumRsp = minimumRsp, breakpointFlags = minimumRsp and 3 or 1})
    end
    function noAttach.setRegister(index, value)
        assert(noAttach.stopId ~= 0 and index >= 0 and index < 17 and index == math.floor(index), "Select a current integer register")
        return noAttachCall(9, {registerIndex = index, value = value})
    end
    return api
end
