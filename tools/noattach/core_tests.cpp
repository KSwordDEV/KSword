// Included after the unmodified production function bodies by the generator.
KSW_HVM_NOATTACH g_KswordNoAttach{};
static KSW_HVM_RUNTIME runtime;
static std::array<std::array<SIZE_T, 0x7000>, 2> vmcs{};
static std::array<KSW_HVM_RESIDENT_VCPU, 2> cpus{};
static unsigned int cpu = 0, checks = 0, probes = 0, unlocks = 0, invepts = 0, rendezvous = 0;
static unsigned int devirtualizations = 0;
static bool targetThread = true;
static bool tfAvailable = false;
static std::array<unsigned char, 4096> tfCode{};
static unsigned long long mockDr6 = 0xFFFF0FF0, mockCr2 = 0;
static DWORD mockProtection = PAGE_EXECUTE_READ;
static std::unordered_map<unsigned long long, unsigned long long> mappings;

static void check(bool valid, const char* description)
{
    if (!valid) throw std::runtime_error(description);
    ++checks;
}
KSW_HVM_RUNTIME* KswordARKHvmGetRuntime() { return &runtime; }
void* KswordARKHvmAllocateEptPageLocked(KSW_HVM_RUNTIME* state, PHYSICAL_ADDRESS* physical)
{
    if (state->EptPageCount >= 512) return nullptr;
    auto* page = VirtualAlloc(nullptr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    physical->QuadPart = 0x100000LL + state->EptPageCount * PAGE_SIZE;
    state->EptPages[state->EptPageCount++] = {page, *physical};
    return page;
}
NTSTATUS KswordARKHvmResidentInvalidateEpt(unsigned long long)
{
    ++rendezvous;
    // Real rendezvous visits every CPU. State remains reserved, so it cannot
    // execute target instructions while the new bank is being published.
    const auto saved = cpu;
    for (cpu = 0; cpu < 2; ++cpu)
    {
        KSW_HVM_GPR_FRAME frame{}; ULONG action = 0;
        (void)KswordARKHvmNoAttachHandleExit(&cpus[cpu], &frame, 18, 0, &action);
    }
    cpu = saved;
    return STATUS_SUCCESS;
}
unsigned char KswordARKHvmAsmInveptSingle(unsigned long long) { ++invepts; return 0; }
unsigned char KswordARKHvmVmcsFieldLoad(unsigned long field, SIZE_T* value) { *value = vmcs[cpu].at(field); return 0; }
unsigned char KswordARKHvmVmcsFieldStore(unsigned long field, SIZE_T value) { vmcs[cpu].at(field) = value; return 0; }
BOOLEAN KswordARKHvmResidentDeactivateCurrent(KSW_HVM_RESIDENT_VCPU*, unsigned long, BOOLEAN) { ++devirtualizations; return TRUE; }
void* KeGetCurrentThread() { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(targetThread ? 1 : 2)); }
unsigned long long fixtureReadMsr(unsigned long number)
{
    if (number == 0x480) return 1ULL << 55;
    if (number == 0x48D || number == 0x481) return tfAvailable ? 9ULL << 32 : 0;
    if (number == 0x48F || number == 0x483) return 0;
    return static_cast<unsigned long long>(KSW_NOATTACH_MBEC_CONTROL) << 32;
}
unsigned long long fixtureReadDr(int) { return mockDr6; }
void fixtureWriteDr(int, unsigned long long value) { mockDr6 = value; }
void fixtureWriteCr2(unsigned long long value) { mockCr2 = value; }
void* MmGetSystemAddressForMdlSafe(PMDL, unsigned long) { return tfCode.data(); }
NTSTATUS ZwQueryVirtualMemory(HANDLE, void*, int, MEMORY_BASIC_INFORMATION* result, SIZE_T, SIZE_T* returned)
{ *result = {}; result->State = MEM_COMMIT; result->Protect = mockProtection; *returned = sizeof(*result); return STATUS_SUCCESS; }
BOOLEAN KswordARKHvmNoAttachOwned() { return g_KswordNoAttach.Owned != 0; }
void KeStackAttachProcess(void*, void*) {}
void KeUnstackDetachProcess(void*) {}
PMDL IoAllocateMdl(void* address, unsigned long, BOOLEAN, BOOLEAN, void*)
{ return new FixtureMdl{reinterpret_cast<std::uintptr_t>(address), 0, false}; }
void MmProbeAndLockPages(PMDL mdl, int, int)
{
    const auto found = mappings.find(mdl->address & ~0xFFFULL);
    if (found == mappings.end()) RaiseException(static_cast<DWORD>(STATUS_ACCESS_VIOLATION), 0, 0, nullptr);
    mdl->pfn = found->second >> 12; mdl->locked = true; ++probes;
}
unsigned long long* MmGetMdlPfnArray(PMDL mdl) { return &mdl->pfn; }
void MmUnlockPages(PMDL mdl) { check(mdl->locked, "no double/unowned unlock"); mdl->locked = false; ++unlocks; }
void IoFreeMdl(PMDL mdl) { check(!mdl->locked, "no release of locked MDL"); delete mdl; }

static unsigned long long leaf(unsigned long long eptp, unsigned long long physical)
{
    auto* table = NaTable(&runtime, eptp);
    for (int level = 3; level >= 0; --level)
    {
        const auto entry = table[(physical >> (12 + 9 * level)) & 511];
        if (level == 0 || (entry & 0x80)) return entry;
        table = NaTable(&runtime, entry);
        check(table != nullptr, "all child tables are ledgered");
    }
    throw std::runtime_error("EPT walk failed");
}
static KSW_HVM_GPR_FRAME frame{};
static void exitAt(unsigned long reason, unsigned long long qualification = 4)
{
    ULONG action = 0;
    (void)KswordARKHvmNoAttachHandleExit(&cpus[cpu], &frame, reason, qualification, &action);
    check(action == KSW_HVM_EXIT_ACTION_RESUME, "normal scenario never devirtualizes");
}
static void at(unsigned long long rip, unsigned long long physical, unsigned long long root)
{
    vmcs[cpu][0x681E] = rip; vmcs[cpu][0x2400] = physical; vmcs[cpu][0x201A] = root;
}
static auto request(unsigned long operation)
{
    KSWORD_ARK_HVM_NOATTACH_REQUEST value{};
    value.operation = operation; value.stopId = g_KswordNoAttach.Snapshot.stopId;
    return value;
}
static void pause()
{
    g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING;
    vmcs[cpu][0x201A] = g_KswordNoAttach.UserGateEptp;
    exitAt(48);
    check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED, "actual fetch publishes stop");
}
int main()
{
    try
    {
        check(sizeof(KSWORD_ARK_HVM_NOATTACH_REQUEST) == 232, "request ABI");
        check(sizeof(KSWORD_ARK_HVM_NOATTACH_RESPONSE) == 480, "response ABI");
        PHYSICAL_ADDRESS a{}, b{}, c{};
        auto* pml4 = static_cast<unsigned long long*>(KswordARKHvmAllocateEptPageLocked(&runtime, &a));
        auto* pdpt = static_cast<unsigned long long*>(KswordARKHvmAllocateEptPageLocked(&runtime, &b));
        auto* pd = static_cast<unsigned long long*>(KswordARKHvmAllocateEptPageLocked(&runtime, &c));
        pml4[0] = static_cast<unsigned long long>(b.QuadPart) | 7;
        pdpt[0] = static_cast<unsigned long long>(c.QuadPart) | 7;
        for (unsigned long long i = 0; i < 512; ++i) pd[i] = (i << 21) | 0xB7ULL; // WB, R/W/X, 2 MiB
        runtime.EptPml4 = pml4; runtime.EptPointer = static_cast<unsigned long long>(a.QuadPart) | 0x1E;
        runtime.HighestMappedPhysicalAddress = 1ULL << 30;
        runtime.FeatureFlags = KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG | KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
        g_KswordNoAttach.Owned = g_KswordNoAttach.Enabled = 1;
        g_KswordNoAttach.Thread = reinterpret_cast<void*>(1); g_KswordNoAttach.Teb = 0x12340000;
        g_KswordNoAttach.StepProcessor = -1;
        g_KswordNoAttach.Snapshot.sessionId = 1;
        check(NT_SUCCESS(KswordARKHvmNoAttachBuildRootsLocked(&runtime)), "all immutable roots prepare");
        for (unsigned int i = 0; i < 2; ++i)
        {
            cpus[i].Runtime = &runtime; cpus[i].ProcessorIndex = i;
            vmcs[i][0x0802] = 3; vmcs[i][0x6810] = g_KswordNoAttach.Teb;
            vmcs[i][0x681C] = 0x70000000; vmcs[i][0x6820] = 0x202; vmcs[i][0x6802] = 0x4000;
        }
        constexpr unsigned long long address = 0x100000010ULL, physical = 0x2010ULL;
        mappings[address & ~0xFFFULL] = physical & ~0xFFFULL;
        at(address, physical, g_KswordNoAttach.UserGateEptp);
        pause();
        const auto firstStop = g_KswordNoAttach.Snapshot.stopId;
        auto add = request(KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT); add.address = address;
        add.stopId = firstStop + 1;
        check(KswordARKHvmNoAttachEditStopped(&add) == STATUS_REVISION_MISMATCH, "stale stop cannot install breakpoint");
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED, "stale edit preserves original stop");
        add.stopId = firstStop;
        check(NT_SUCCESS(KswordARKHvmNoAttachEditStopped(&add)), "install exact execution breakpoint");
        auto* bank = &g_KswordNoAttach.Banks[g_KswordNoAttach.ActiveBank];
        check(bank->Count == 1 && bank->Rows[0].physicalPage == 0x2000, "pin binds exact backing");
        check((leaf(bank->Eptp, 0x2000) & KSW_NOATTACH_USER_EXECUTE) == 0, "watch denies user execution only");
        check((leaf(bank->Eptp, 0x2000) & 7) == 7, "watch preserves read/write/supervisor permissions");
        check((leaf(runtime.EptPointer, 0x2000) & KSW_NOATTACH_USER_EXECUTE) != 0, "normal EPT remains executable");
        check((leaf(bank->Eptp, 0x3000) & KSW_NOATTACH_USER_EXECUTE) != 0, "adjacent 4 KiB page retains permissions");
        const auto generation = bank->Generation;
        check(KswordARKHvmNoAttachEditStopped(&add) == STATUS_OBJECT_NAME_COLLISION, "duplicate address cannot replace semantics");
        check(bank->Generation == generation, "failed edit never publishes partial bank");

        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_RUNNING;
        at(address, physical, bank->Eptp); exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED, "matching EPT hit really stops selected thread");
        check(g_KswordNoAttach.Snapshot.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT &&
              g_KswordNoAttach.Snapshot.breakpointId == bank->Rows[0].id, "hit identity accompanies snapshot");
        check(g_KswordNoAttach.Snapshot.rip == address && vmcs[0][0x6820] == 0x202, "breakpoint preserves original RIP/TF");
        const auto hitStop = g_KswordNoAttach.Snapshot.stopId;
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING;
        exitAt(48);
        check(cpus[0].NoAttachBypass && vmcs[0][0x201A] == runtime.EptPointer, "continue grants only current CPU one instruction");
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_RUNNING, "continue is confirmed at original stop");
        cpu = 1; targetThread = false;
        at(address + 1, physical + 1, bank->Eptp); exitAt(48);
        check(cpus[1].NoAttachBypass && g_KswordNoAttach.Snapshot.stopId == hitStop, "other thread/page offset is never a target stop");
        check(vmcs[0][0x201A] == runtime.EptPointer, "other CPU cannot overwrite first CPU EPTP");
        vmcs[1][0x681E] += 1; exitAt(37);
        check(!cpus[1].NoAttachBypass && g_KswordNoAttach.Snapshot.stopId == hitStop, "bypass MTF never reports a user step");
        cpu = 0; targetThread = true; vmcs[0][0x681E] += 1; exitAt(37);
        pause();
        const auto beforeStep = g_KswordNoAttach.Snapshot.stopId;
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_STEP_PENDING; exitAt(48);
        check(g_KswordNoAttach.StepProcessor == 0 && (vmcs[0][0x4002] & KSW_NA_MTF), "MTF belongs to one processor");
        vmcs[0][0x681E] += 1; frame.Rax = 0xABC; exitAt(37);
        check(g_KswordNoAttach.Snapshot.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_STEP &&
              g_KswordNoAttach.Snapshot.stopId == beforeStep + 1 && g_KswordNoAttach.Snapshot.rax == 0xABC,
              "matching MTF publishes new integer context");
        check(vmcs[0][0x6820] == 0x202 && !(vmcs[0][0x4002] & KSW_NA_MTF), "step restores MTF and never changes TF");
        auto edit = request(KSWORD_ARK_HVM_NOATTACH_SET_GPR);
        edit.registerMask = 1; edit.registers.rax = 0x12345678;
        check(NT_SUCCESS(KswordARKHvmNoAttachEditStopped(&edit)), "integer edit accepted pending fetch");
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING, "acceptance is not completion");
        at(g_KswordNoAttach.Snapshot.rip, physical, g_KswordNoAttach.UserGateEptp); exitAt(48);
        check(frame.Rax == 0x12345678 && g_KswordNoAttach.Snapshot.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT,
              "register edit commits in exact stopped context");
        edit = request(KSWORD_ARK_HVM_NOATTACH_SET_GPR); edit.registerMask = 1ULL << 17;
        check(KswordARKHvmNoAttachEditStopped(&edit) == STATUS_INVALID_PARAMETER, "flags/DR/XSTATE edits are rejected");

        const auto oldContext = g_KswordNoAttach.Snapshot.stopId;
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING; frame.Rcx = 99; exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED &&
              g_KswordNoAttach.Snapshot.stopId == oldContext + 1 && g_KswordNoAttach.Snapshot.stopReason == 1,
              "external context changes invalidate old continue authorization");
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_STEP_PENDING; exitAt(48);
        const auto beforeInterrupt = g_KswordNoAttach.Snapshot.stopId;
        exitAt(10); // CPUID/other exit is deliberately not claimed as MTF completion.
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_INTERRUPTED &&
              g_KswordNoAttach.Snapshot.stopId == beforeInterrupt && g_KswordNoAttach.StepProcessor == -1,
              "interrupted instruction does not fabricate completion");
        pause();

        KSWORD_ARK_HVM_NOATTACH_RESPONSE query{};
        mappings[address & ~0xFFFULL] = 0x9000;
        KswordARKHvmNoAttachQueryBreakpoints(&query);
        check((query.breakpoints[0].flags & KSWORD_ARK_HVM_NOATTACH_BP_STALE) != 0, "remapping explicitly invalidates breakpoint");
        check(query.breakpoints[0].physicalPage == 0x2000 && (bank->Disabled & 1), "remapping never silently rebinds backing");
        auto run = request(KSWORD_ARK_HVM_NOATTACH_RUN_TO); run.address = address + 0x1000;
        mappings[run.address & ~0xFFFULL] = 0xA000;
        check(NT_SUCCESS(KswordARKHvmNoAttachEditStopped(&run)), "run-to installs before consuming stop");
        bank = &g_KswordNoAttach.Banks[g_KswordNoAttach.ActiveBank];
        check(bank->Count == 1 && (bank->Rows[0].flags & KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT), "run-to is always one-shot");
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING, "run-to does not claim a hit in its ACK");
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_RUNNING;
        at(run.address, 0xA010, bank->Eptp); exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED && (bank->Disabled & 1), "one-shot consumes its own match only");
        check(invepts >= 4 && rendezvous >= 3, "bank reuse requires per-CPU invalidation and barriers");
        // Exercise the actual VMX TF code, with no VMX or privileged instruction.
        tfAvailable = true;
        check(KswordARKHvmNoAttachTfAvailable(), "TF availability requires real pin/exit capabilities");
        g_KswordNoAttach.UseTf = TRUE;
        check(NT_SUCCESS(KswordARKHvmNoAttachPinStepCode(run.address)), "TF code pin has an ordinary-mode mapping");
        const auto pinnedCount = g_KswordNoAttach.PinCount;
        check(NT_SUCCESS(KswordARKHvmNoAttachPinStepCode(run.address)) && g_KswordNoAttach.PinCount == pinnedCount,
              "repeated TF steps reuse the same revalidated backing");
        cpu = 0;
        tfCode.fill(0x90); tfCode[0] = 0x48; tfCode[1] = 0xFF; tfCode[2] = 0xC0;
        vmcs[0][0x2400] = 0xA000; vmcs[0][0x4000] = 8; vmcs[0][0x4004] = 0;
        vmcs[0][0x6820] = 0x202; vmcs[0][0x6822] = 0; vmcs[0][0x400C] = 0;
        vmcs[0][0x4016] = 0; vmcs[0][0x4408] = 0; vmcs[0][0x4824] = 0;
        vmcs[0][0x681A] = 0; vmcs[0][0x2802] = 0;
        check(KswordARKHvmNoAttachTfEnable(&cpus[0], TRUE), "real VMX TF boundary arms at a checked INC");
        check(vmcs[0][0x6820] == 0x302 && vmcs[0][0x4000] == 9 && vmcs[0][0x4004] == 0xFFFFFFFF,
              "TF arm intercepts asynchronous and synchronous delivery without changing IF");
        check(!cpus[1].NoAttachTfArmed, "TF arm remains processor local");
        vmcs[0][0x6820] = 0x346; vmcs[0][0x4404] = 0x80000301;
        ULONG boundaryReason = 0; BOOLEAN forwarded = FALSE;
        check(KswordARKHvmNoAttachTfRetire(&cpus[0], &boundaryReason, 0x4000, &forwarded) && boundaryReason == 37 && !forwarded,
              "only an actual pure owned BS becomes execution completion");
        check(vmcs[0][0x6820] == 0x246 && vmcs[0][0x4000] == 8 && vmcs[0][0x4004] == 0 && !cpus[0].NoAttachTfArmed,
              "retirement restores controls and keeps the instruction's arithmetic flags");
        check(KswordARKHvmNoAttachTfEnable(&cpus[0], TRUE), "TF rearms for a fault experiment");
        vmcs[0][0x4404] = 0x80000B0E; vmcs[0][0x4406] = 5; boundaryReason = 0;
        check(KswordARKHvmNoAttachTfRetire(&cpus[0], &boundaryReason, 0x12345000, &forwarded) && forwarded && boundaryReason == 0,
              "a real page fault is forwarded and never reported as a step");
        check(mockCr2 == 0x12345000 && vmcs[0][0x4016] == 0x80000B0E && vmcs[0][0x4018] == 5 && !(vmcs[0][0x6820] & 0x100),
              "page-fault address/error survive and TF is removed before delivery");
        vmcs[0][0x4016] = 0;
        check(KswordARKHvmNoAttachTfEnable(&cpus[0], TRUE), "TF rearms before an unacknowledged interrupt");
        boundaryReason = 1;
        check(KswordARKHvmNoAttachTfRetire(&cpus[0], &boundaryReason, 0, &forwarded) && forwarded && boundaryReason == 1 && vmcs[0][0x4016] == 0,
              "unacknowledged interrupt is left for normal guest delivery without a fabricated vector");
        at(run.address & ~0xFFFULL, 0xA000, g_KswordNoAttach.UserGateEptp);
        frame.Rax = 0x100; vmcs[0][0x6820] = 0x10202;
        pause();
        const auto beforeIrqStep = g_KswordNoAttach.Snapshot.stopId;
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_STEP_PENDING;
        exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STEPPING && cpus[0].NoAttachTfArmed,
              "real exit state machine arms TF before testing IRQ retry");
        exitAt(1, 0);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STEP_PENDING && !cpus[0].NoAttachTfArmed &&
              g_KswordNoAttach.TfRetryCount == 1 && g_KswordNoAttach.Snapshot.stopId == beforeIrqStep,
              "IRQ before instruction retirement preserves the same consumed STEP request");
        vmcs[0][0x6820] = 0x202;
        exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STEPPING && cpus[0].NoAttachTfArmed,
              "interrupt-return RF change alone does not discard the frozen instruction");
        vmcs[0][0x681E] += 3; frame.Rax = 0x101; vmcs[0][0x6820] = 0x306; vmcs[0][0x4404] = 0x80000301;
        exitAt(0, 0x4000);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_STOPPED && g_KswordNoAttach.Snapshot.stopReason == 2 &&
              g_KswordNoAttach.Snapshot.stopId == beforeIrqStep + 1 && g_KswordNoAttach.Snapshot.rax == 0x101 &&
              !g_KswordNoAttach.TfRetryAfterInterrupt,
              "only the later real BS publishes completion after an IRQ retry");
        const auto actualStepStop = g_KswordNoAttach.Snapshot.stopId;
        vmcs[0][0x6820] |= 0x10000;
        vmcs[0][0x201A] = g_KswordNoAttach.UserGateEptp;
        exitAt(48);
        check(g_KswordNoAttach.Snapshot.stopId == actualStepStop && g_KswordNoAttach.Snapshot.stopReason == 2,
              "CPU-owned EPT resume-flag change never overwrites a completed STEP with a spurious FETCH");
        vmcs[0][0x6820] ^= 1;
        exitAt(48);
        check(g_KswordNoAttach.Snapshot.stopId == actualStepStop + 1 && g_KswordNoAttach.Snapshot.stopReason == 1,
              "ordinary flag changes still invalidate the previous stop identity");
        mockProtection = PAGE_EXECUTE_READWRITE;
        const auto beforeWritablePin = g_KswordNoAttach.PinCount;
        check(KswordARKHvmNoAttachPinStepCode(run.address) == STATUS_NOT_SUPPORTED && g_KswordNoAttach.PinCount == beforeWritablePin,
              "writable executable code is rejected before a TF pin is retained");
        mockProtection = PAGE_EXECUTE_READ;
        const std::array<std::array<unsigned char, 3>, 6> unsafe{{{{0x0F,0x05,0}},{{0xCD,0x2E,0}},{{0x8E,0xD0,0}},{{0x9D,0,0}},{{0xCF,0,0}},{{0xFF,0x18,0}}}};
        for (const auto& instruction : unsafe)
        { check(!NaTfOpcode(instruction.data(), static_cast<ULONG>(instruction.size())), "privilege/flags/SS/interrupt boundary is rejected before TF arm"); }
        tfCode[0] = 0x0F; tfCode[1] = 0x05;
        check(!KswordARKHvmNoAttachTfEnable(&cpus[0], TRUE) && !cpus[0].NoAttachTfArmed && !(vmcs[0][0x6820] & 0x100),
              "rejected syscall never changes TF or retains temporary controls");
        at(address + 0x4000, 0xB000, g_KswordNoAttach.UserGateEptp);
        pause();
        g_KswordNoAttach.State = KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING;
        exitAt(48);
        check(g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_RUNNING && !cpus[0].NoAttachBypass &&
              !cpus[0].NoAttachTfArmed && vmcs[0][0x201A] == bank->Eptp,
              "continue outside the watch page never arms a pointless TF boundary");
        ULONG recoveryAction = KSW_HVM_EXIT_ACTION_FATAL;
        check(NaFail(&cpus[0], &recoveryAction) && recoveryAction == KSW_HVM_EXIT_ACTION_RESUME && devirtualizations == 0,
              "user-mode recovery never switches a kernel continuation onto a user stack");
        check(g_KswordNoAttach.Owned && !g_KswordNoAttach.Enabled &&
              g_KswordNoAttach.State == KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED && vmcs[0][0x201A] == g_KswordNoAttach.NormalEptp,
              "recovery releases execution restrictions but retains resources for kernel-mode close");
        KswordARKHvmNoAttachReleasePins();
        check(probes == unlocks && g_KswordNoAttach.PinCount == 0, "all temporary and lifetime page locks are balanced");
        for (unsigned long i = 0; i < runtime.EptPageCount; ++i) VirtualFree(runtime.EptPages[i].VirtualAddress, 0, MEM_RELEASE);
        std::cout << "NOATTACH_CORE_PASS checks=" << checks << " (production code; simulated VMCS, no VMX)\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "NOATTACH_CORE_FAIL " << error.what() << '\n'; return 1; }
}
