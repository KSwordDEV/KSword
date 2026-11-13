// Included after the unmodified production function bodies by the generator.
KSW_HVM_NOATTACH g_KswordNoAttach{};
static KSW_HVM_RUNTIME runtime;
static std::array<std::array<SIZE_T, 0x7000>, 2> vmcs{};
static std::array<KSW_HVM_RESIDENT_VCPU, 2> cpus{};
static unsigned int cpu = 0, checks = 0, probes = 0, unlocks = 0, invepts = 0, rendezvous = 0;
static bool targetThread = true;
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
BOOLEAN KswordARKHvmResidentDeactivateCurrent(KSW_HVM_RESIDENT_VCPU*, unsigned long, BOOLEAN) { return TRUE; }
void* KeGetCurrentThread() { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(targetThread ? 1 : 2)); }
unsigned long long fixtureReadMsr(unsigned long) { return static_cast<unsigned long long>(KSW_NOATTACH_MBEC_CONTROL) << 32; }
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
        KswordARKHvmNoAttachReleasePins();
        check(probes == unlocks && g_KswordNoAttach.PinCount == 0, "all temporary and lifetime page locks are balanced");
        for (unsigned long i = 0; i < runtime.EptPageCount; ++i) VirtualFree(runtime.EptPages[i].VirtualAddress, 0, MEM_RELEASE);
        std::cout << "NOATTACH_CORE_PASS checks=" << checks << " (production code; simulated VMCS, no VMX)\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "NOATTACH_CORE_FAIL " << error.what() << '\n'; return 1; }
}
