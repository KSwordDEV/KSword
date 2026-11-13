local allocations, nextAddress = {}, 0x10000
local function memory(address, count)
    for base, stream in pairs(allocations) do
        if address >= base and address + count <= base + stream.Size then return stream, address - base end
    end
    error("Invalid local buffer " .. address)
end
function createMemoryStream()
    local stream = {Size = 0, Memory = nextAddress, data = {}}
    nextAddress = nextAddress + 0x100000
    allocations[stream.Memory] = stream
    function stream.destroy() allocations[stream.Memory] = nil end
    return stream
end
function stringToByteTable(value)
    local bytes = {}; for i = 1, #value do bytes[i] = value:byte(i) end; return bytes
end
function writeBytesLocal(address, bytes)
    local stream, offset = memory(address, #bytes)
    for i, value in ipairs(bytes) do stream.data[offset + i] = value end
end
function readBytesLocal(address, count)
    local stream, offset = memory(address, count)
    local bytes = {}; for i = 1, count do bytes[i] = stream.data[offset + i] or 0 end; return bytes
end
local function writeNumber(address, value, count)
    local bytes = {}; for i = 1, count do bytes[i] = (value >> ((i - 1) * 8)) & 255 end
    writeBytesLocal(address, bytes)
end
local function readNumber(address, count)
    local value = 0; for i, byte in ipairs(readBytesLocal(address, count)) do value = value | (byte << ((i - 1) * 8)) end
    return value
end
function writeIntegerLocal(address, value) writeNumber(address, value, 4) end
function writeQwordLocal(address, value) writeNumber(address, value, 8) end
function readIntegerLocal(address) return readNumber(address, 4) end
function readQwordLocal(address) return readNumber(address, 8) end
function cheatEngineIs64Bit() return true end
function getAddressSafe(name)
    if name:find("MoveFileExW", 1, true) then return 3 end
    return name:find("GetModuleHandleW", 1, true) and 1 or 2
end
local loaded, selected, selectionError, driverReady = true, false, 0, true
local files, timers = {}, {}
local optionValues = {0, 0, 1, 1, 1, 1, 32}
local optionError, restoreError, shadowPages, fallbackCount, lastFallbackError = 0, 0, 0, 0, 0
local optionFields = {"mode", "shadowMemoryWrites", "allowFallback", "logFallback",
    "nativeContextFallback", "nativeSuspendFallback", "maxShadowPages"}
local versions = {[16] = 6, [17] = 6, [18] = 2, [19] = 6, [20] = 6,
    [21] = 1, [22] = 1, [23] = 1, [24] = 1, [25] = 2, [26] = 1,
    [27] = 1, [28] = 9, [29] = 1, [30] = 4, [31] = 1, [32] = 1, [33] = 2}
local noAttachMock = {state = 0, session = 0, stop = 0, status = 0, reason = 0}
local noAttachRequest, noAttachBadResponse = {}, false
function executeCodeLocalEx(address, parameter, destination, flags)
    if address == 3 then
        assert(flags == 9 and parameter.type == 4 and destination.type == 4)
        files[destination.value] = files[parameter.value]; files[parameter.value] = nil; return 1
    end
    if address == 1 then return loaded and 100 or 0 end
    if address == 2 then return 200 end
    assert(address == 200)
    assert(readIntegerLocal(parameter) == 1 and readIntegerLocal(parameter + 4) == 48)
    local command = readIntegerLocal(parameter + 8)
    local input, output = readQwordLocal(parameter + 16), readQwordLocal(parameter + 24)
    local returned, errorCode = 0, 0
    if command == 1 or command == 2 then
        if command == 2 then
            errorCode = selectionError
            if errorCode == 0 then selected = readIntegerLocal(input) == 1 end
        end
        writeIntegerLocal(output, 1); writeIntegerLocal(output + 4, 40)
        writeIntegerLocal(output + 8, driverReady and 1 or 0); writeIntegerLocal(output + 12, selected and 1 or 0)
        writeIntegerLocal(output + 16, 1); writeIntegerLocal(output + 32, 1)
        returned = 40
    elseif command == 4 or command == 5 or command == 6 then
        if command == 5 then
            assert(readIntegerLocal(parameter + 32) == 48 and readIntegerLocal(input) == 1 and readIntegerLocal(input + 4) == 48)
            assert(readIntegerLocal(input + 36) == 0 and readIntegerLocal(input + 40) == 0 and readIntegerLocal(input + 44) == 0)
            errorCode = optionError
            if errorCode == 0 then for index = 1, 7 do optionValues[index] = readIntegerLocal(input + 4 + index * 4) end end
        end
        writeIntegerLocal(output, 1); writeIntegerLocal(output + 4, 48)
        for index = 1, 7 do writeIntegerLocal(output + 4 + index * 4, optionValues[index]) end
        returned = 48
        if command == 6 then
            writeIntegerLocal(output + 48, selected and 2 or 0); writeIntegerLocal(output + 52, shadowPages)
            writeIntegerLocal(output + 56, 0); writeIntegerLocal(output + 60, shadowPages == 0 and 1 or 0)
            writeIntegerLocal(output + 64, fallbackCount); writeIntegerLocal(output + 68, lastFallbackError)
            returned = 72
        end
    elseif command == 7 then
        assert(readIntegerLocal(parameter + 32) == 24 and readIntegerLocal(input) == 1 and readIntegerLocal(input + 4) == 24)
        errorCode = restoreError
        if errorCode == 0 then shadowPages = 0 end
        writeIntegerLocal(output, 1); writeIntegerLocal(output + 4, 40); returned = 40
    elseif command == 3 then
        local requested = readIntegerLocal(input)
        assert(versions[requested] ~= nil)
        writeIntegerLocal(output, 1); writeIntegerLocal(output + 4, requested)
        writeIntegerLocal(output + 8, requested == 33 and 232 or 64)
        writeIntegerLocal(output + 12, requested == 33 and 480 or 64)
        writeIntegerLocal(output + 16, versions[requested]); returned = 24
    elseif command == 33 then
        assert(readIntegerLocal(input) == 2 and readIntegerLocal(input + 4) == 232)
        assert(readIntegerLocal(parameter + 32) == 232 and readIntegerLocal(parameter + 36) == 480)
        noAttachRequest = {operation = readIntegerLocal(input + 8), flags = readIntegerLocal(input + 12),
            pid = readIntegerLocal(input + 16), tid = readIntegerLocal(input + 20),
            session = readQwordLocal(input + 48), stop = readQwordLocal(input + 56),
            address = readQwordLocal(input + 64), id = readIntegerLocal(input + 72),
            bpFlags = readIntegerLocal(input + 76), minimumRsp = readQwordLocal(input + 80),
            mask = readQwordLocal(input + 88), rax = readQwordLocal(input + 96)}
        writeIntegerLocal(output, 2); writeIntegerLocal(output + 4, 480)
        writeIntegerLocal(output + 8, noAttachMock.status)
        writeIntegerLocal(output + 12, noAttachBadResponse and 99 or noAttachMock.state)
        writeIntegerLocal(output + 16, 31); writeIntegerLocal(output + 20, noAttachMock.reason)
        writeIntegerLocal(output + 24, 800); writeIntegerLocal(output + 28, 801)
        writeQwordLocal(output + 32, noAttachMock.session); writeQwordLocal(output + 40, noAttachMock.stop)
        writeQwordLocal(output + 64, 0x12340000); writeQwordLocal(output + 72, 0x70000000)
        writeQwordLocal(output + 80, 0x202); writeQwordLocal(output + 96, 0x12345678)
        writeIntegerLocal(output + 220, 1); writeIntegerLocal(output + 224, 42)
        writeIntegerLocal(output + 228, 1); writeQwordLocal(output + 232, 0x12345678)
        returned = 480
    else
        assert(readIntegerLocal(input) == versions[command] and readIntegerLocal(input + 4) == 64)
        writeIntegerLocal(output, versions[command]); writeIntegerLocal(output + 4, 64); returned = 64
    end
    writeIntegerLocal(parameter + 40, errorCode); writeIntegerLocal(parameter + 44, returned)
    return errorCode
end
local messages = {}
local function log(message) messages[#messages + 1] = message end
local factory = assert(loadfile(backend_factory_file))()
local api = factory(log, "virtual/KswordCheatEnginePlugin.dll")
local status = assert(api.status()); assert(status.driverReady and not status.useHvm)
assert(api.useHvm(true)); assert(api.status().useHvm)
selectionError = 170; assert(not api.useHvm(false)); assert(api.status().useHvm)
selectionError = 0; assert(api.useHvm(false))
local options = assert(api.options())
assert(options.shadowMemoryWrites == false and options.allowFallback == true and options.mode == 0)
local changed, changedError = api.setOptions({shadowMemoryWrites = true, allowFallback = false, nativeContextFallback = false,
    nativeSuspendFallback = false, mode = 1, maxShadowPages = 4})
assert(changedError == 0 and changed.shadowMemoryWrites and not changed.allowFallback and changed.mode == 1)
optionError = 170
local rejected, rejectedError = api.setOptions({allowFallback = true})
assert(rejectedError == 170 and rejected.allowFallback == false and api.options().allowFallback == false)
optionError = 0
assert(not pcall(api.setOptions, {maxShadowPages = 0}))
assert(not pcall(api.setOptions, {mode = 2}))
assert(not pcall(api.setOptions, {logFallback = false}))
assert(not pcall(api.setOptions, {unknown = true}))
assert(not pcall(api.restoreShadowWrites, 0, 4096))
shadowPages, fallbackCount, lastFallbackError = 2, 1, 50
local policy = assert(api.policy()); assert(policy.shadowWritePages == 2 and not policy.canChangeOptions and policy.lastFallbackError == 50)
restoreError = 50; assert(not api.restoreShadowWrites()); assert(shadowPages == 2)
assert(messages[#messages]:find("rejected, error 50", 1, true))
restoreError = 0; assert(api.restoreShadowWrites()); assert(api.policy().shadowWritePages == 0)
local commandCount = 0
for name in pairs(api.hvm.commands) do
    local packet = api.hvm.packet(name)
    packet.write32(8, 0).write64(16, 0x1234)
    assert(not pcall(packet.write64, packet.input.Size - 4, 1))
    local bytes, errorCode = packet.send(); assert(errorCode == 0 and #bytes == (name == "noAttach" and 480 or 64))
    packet.destroy(); packet.destroy(); commandCount = commandCount + 1
end
assert(commandCount == 18 and next(allocations) == nil)

-- Exercise the independent channel's actual Lua serializer and stop semantics.
local na = api.noAttach
assert(not pcall(na.open, 800, 801, false))
noAttachMock.state, noAttachMock.session = 1, 99
local opened = assert(na.open(800, 801, true, true))
assert(noAttachRequest.flags == 3 and noAttachRequest.pid == 800 and noAttachRequest.tid == 801)
assert(opened.state == 1 and opened.rip == nil and na.sessionId == 99 and na.stopId == 0)
assert(not pcall(na.step) and not pcall(na.open, 800, 801, true))
noAttachMock.state, noAttachMock.stop, noAttachMock.reason = 3, 123, 3
local stopped = assert(na.query())
assert(stopped.rip == 0x12340000 and stopped.registers.rax == 0x12345678 and stopped.breakpoints[1].id == 42)
na.addBreakpoint(0x12345678, true)
assert(noAttachRequest.operation == 6 and noAttachRequest.address == 0x12345678 and noAttachRequest.bpFlags == 1 and noAttachRequest.stop == 123)
na.setRegister(0, 0x11223344)
assert(noAttachRequest.operation == 9 and noAttachRequest.mask == 1 and noAttachRequest.rax == 0x11223344)
assert(not pcall(na.setRegister, 17, 1))
na.removeBreakpoint(42); assert(noAttachRequest.operation == 7 and noAttachRequest.id == 42)
na.runTo(0x12345678, 0x70000000)
assert(noAttachRequest.operation == 8 and noAttachRequest.bpFlags == 3 and noAttachRequest.minimumRsp == 0x70000000)
noAttachMock.state, noAttachMock.stop, noAttachMock.reason = 4, 0, 0
local pending = assert(na.step())
assert(pending.state == 4 and pending.rip == nil and pending.registers == nil and na.stopId == 0)
assert(not pcall(na.continue))
noAttachMock.status = 0xC0000059
local rejectedNa = assert(na.query()); assert(rejectedNa.status < 0 and na.sessionId == 99 and na.stopId == 0)
noAttachBadResponse = true
local invalidNa, invalidError = na.query(); assert(invalidNa == nil and invalidError == 13)
noAttachBadResponse = false
noAttachMock.state, noAttachMock.session, noAttachMock.stop, noAttachMock.status = 0, 0, 0, 0
assert(na.close().state == 0 and na.sessionId == 0 and na.stopId == 0)
assert(next(allocations) == nil)

-- Exercise the actual autorun timer and session files entirely in memory.
local environment = {KSWORD_CE_BRIDGE_STATUS_FILE = "status", KSWORD_CE_LOG_FILE = "log",
    KSWORD_CE_BRIDGE_DLL = "virtual/KswordCheatEnginePlugin.dll",
    KSWORD_CE_CONTROL_FILE = "control", KSWORD_CE_BACKEND_STATE_FILE = "state",
    KSWORD_CE_SETTINGS_FILE = "settings", KSWORD_CE_SETTINGS_TEMP_FILE = "settings.pending"}
local realDofile, realIo = dofile, io
io = {}
function io.open(path, mode)
    if mode == "r" and files[path] == nil then return nil end
    if mode == "w" then files[path] = "" end
    local handle = {}
    function handle.read() return files[path] end
    function handle.write(self, ...) for _, value in ipairs({...}) do files[path] = (files[path] or "") .. tostring(value) end; return self end
    function handle.close() return true end
    return handle
end
local ticks = 0
os.getenv = function(name) return environment[name] end
os.time = function() ticks = ticks + 1; return ticks end
os.remove = function(path) files[path] = nil; return true end
os.rename = function(from, to) files[to] = files[from]; files[from] = nil; return true end
local form = {Caption = "Cheat Engine", Color = 42, Font = {Name = "Tahoma"}}
function getMainForm() return form end
function getCheatEngineDir() return "virtual/" end
function loadPlugin() return 0 end
function createTimer()
    local timer = {}; function timer.destroy() end; timers[#timers + 1] = timer; return timer
end
dofile = function(path)
    assert(path == "virtual/autorun\\ksword_hvm.lua")
    return realDofile(backend_factory_file)
end
assert(loadfile(backend_bootstrap_file))()
local timer = assert(KSwordBackendTimer)
timer.OnTimer(); assert(form.Caption == "Cheat Engine [KSword R0]" and files.status == "ready")
assert(files.settings == "CE2 0 0 0 1 1 1 32\n")
assert(not api.options().shadowMemoryWrites and api.options().allowFallback and api.options().logFallback)
files.control = "1 1\n"; timer.OnTimer()
assert(form.Caption == "Cheat Engine [KSword HVM]" and files.state:match("^1 0 1 1 0 1"))
selectionError = 170; files.control = "2 0\n"; timer.OnTimer()
assert(files.state:match("^2 170 1 1 0 1") and form.Caption == "Cheat Engine [KSword HVM]")
optionError = 0
files.control = "CE2 3 1 1 1 1 0 0 0 4\n"; timer.OnTimer()
assert(files.state:match("^3 0 1 1 0 1 CE2 1 1 1 1 0 0 0 4"))
assert(files.settings == "CE2 1 1 1 0 0 0 4\n")
optionError = 170
files.control = "CE2 4 1 1 0 0 1 1 1 32\n"; timer.OnTimer()
assert(files.state:match("^4 170 1 1 0 1 CE2 1 1 1 1 0 0 0 4"))
assert(files.settings == "CE2 1 1 1 0 0 0 4\n")
optionError = 0; restoreError = 50; shadowPages = 2
files.control = "CE2 5 2 1 1 1 0 0 0 4\n"; timer.OnTimer()
assert(files.state:match("^5 50") and files.log:find("Shadow write restore rejected, error 50", 1, true))
restoreError = 0; files.control = "CE2 6 2 1 1 1 0 0 0 4\n"; timer.OnTimer()
assert(files.state:match("^6 0") and shadowPages == 0)
assert(form.Color == 42 and form.Font.Name == "Tahoma")
driverReady = false; timer.OnTimer()
assert(form.Caption == "Cheat Engine [KSword Connected]")
driverReady = true; timer.OnTimer()
assert(form.Caption == "Cheat Engine [KSword HVM]")
loaded = false; timer.OnTimer()
assert(timer.Enabled == true and form.Caption == "Cheat Engine" and files.state:match("^6 126 0 0 0 0"))
loaded = true; timer.OnTimer()
assert(form.Caption == "Cheat Engine [KSword HVM]" and files.state:match("^6 0 1 1 0 1"))
-- Reload the actual startup script from the acknowledged persistent settings.
selected = false; selectionError = 0; optionValues = {0, 0, 1, 1, 1, 1, 32}
assert(loadfile(backend_bootstrap_file))(); KSwordBackendTimer.OnTimer()
assert(selected and api.options().mode == 1 and not api.options().allowFallback and api.options().maxShadowPages == 4)
assert(next(allocations) == nil)
io = realIo
print("PASS: Lua policy ABI, freeze/Shadow policy, ACK rollback, persistence, and independent no-attach v2 serialization/current-stop gating")
