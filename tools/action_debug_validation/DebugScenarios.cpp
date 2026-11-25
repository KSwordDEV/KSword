#include "DebugSession.h"
#include "FixtureCode.h"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>

namespace {
using namespace validation;
void VerifyReturnStop(const Stop& stop, std::uintptr_t afterCall, DWORD64 callerRsp) {
    Require(stop.reason == Reason::TemporaryBreakpoint && stop.code == EXCEPTION_BREAKPOINT,
        "completion_is_real_owned_temporary_breakpoint_event");
    Require(stop.context.Rip == afterCall && stop.context.Rsp == callerRsp,
        "return_boundary_matches_known_call_address_and_caller_stack");
    Require(stop.context.Rax == 42, "known_callee_result_observed_in_actual_rax");
}
void VerifyCall(DebugSession& session, std::uintptr_t call, std::uintptr_t afterCall) {
    Require(session.ReadByte(call) == 0xe8 && afterCall == call + 5,
        "fixed_masm_near_call_is_five_bytes_not_optimized_cpp");
    std::int32_t displacement = 0;
    auto* bytes = reinterpret_cast<unsigned char*>(&displacement);
    for (std::size_t index = 0; index < sizeof(displacement); ++index) {
        bytes[index] = session.ReadByte(call + 1 + index);
    }
    const auto target = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(afterCall) + displacement);
    const auto entry = session.Address(&FixtureCalleeEntry);
    std::printf("CALL_LAYOUT call=0x%llx afterCall=0x%llx decodedTarget=0x%llx label=0x%llx\n",
        static_cast<unsigned long long>(call), static_cast<unsigned long long>(afterCall),
        static_cast<unsigned long long>(target), static_cast<unsigned long long>(entry));
    Require(target == entry, "decoded_call_target_matches_nonprocedure_entry_label");
}
void InstructionAndReturn() {
    DebugSession session("instruction_into_and_known_frame_return", false);
    const auto start = session.Address(&FixtureStart);
    const auto call = session.Address(&FixtureCall);
    const auto callee = session.Address(&FixtureCalleeEntry);
    const auto afterCall = session.Address(&FixtureAfterCall);
    VerifyCall(session, call, afterCall);
    session.Arm(start, Reason::UserBreakpoint);
    const auto entry = session.WaitStop();
    Require(entry.reason == Reason::UserBreakpoint && entry.context.Rip == start,
        "held_real_start_breakpoint_rewound_to_nop");
    session.Step();
    const auto instruction = session.WaitStop();
    Require(instruction.reason == Reason::SingleStep && instruction.code == EXCEPTION_SINGLE_STEP &&
        instruction.context.Rip == call && call == start + 1 && instruction.context.Rsp == entry.context.Rsp,
        "machine_instruction_step_executed_exactly_one_nop");
    session.Step();
    const auto into = session.WaitStop();
    Require(into.reason == Reason::SingleStep && into.context.Rip == callee &&
        into.context.Rsp + 8 == instruction.context.Rsp,
        "call_step_into_stops_at_actual_leaf_entry_with_pushed_stack");
    Require(session.ReadPointer(into.context.Rsp) == afterCall,
        "known_leaf_current_frame_return_address_read_from_actual_stack");
    session.Arm(afterCall, Reason::TemporaryBreakpoint);
    VerifyReturnStop(session.WaitStop(), afterCall, instruction.context.Rsp);
    session.Finish();
}
void CallOver(const char* scenario, bool userBreakpoint, bool fault) {
    DebugSession session(scenario, fault);
    const auto call = session.Address(&FixtureCall);
    const auto afterCall = session.Address(&FixtureAfterCall);
    const auto early = session.Address(&FixtureEarly);
    const auto faultAddress = session.Address(&FixtureFault);
    VerifyCall(session, call, afterCall);
    session.Arm(call, Reason::UserBreakpoint);
    const auto entry = session.WaitStop();
    Require(entry.reason == Reason::UserBreakpoint && entry.context.Rip == call,
        "step_over_begins_at_actual_known_call");
    if (userBreakpoint) { session.Arm(early, Reason::UserBreakpoint); }
    session.Arm(afterCall, Reason::TemporaryBreakpoint);
    auto stop = session.WaitStop();
    if (userBreakpoint || fault) {
        Require(stop.reason == (userBreakpoint ? Reason::UserBreakpoint : Reason::Exception),
            "interruption_reports_actual_reason_not_step_completion");
        Require(stop.context.Rip == (userBreakpoint ? early : faultAddress) &&
            stop.context.Rsp + 8 == entry.context.Rsp && session.ReadPointer(stop.context.Rsp) == afterCall,
            "interruption_preserves_actual_known_leaf_frame_and_return_identity");
        if (fault) {
            Require(stop.code == EXCEPTION_ILLEGAL_INSTRUCTION && stop.firstChance == 1 &&
                session.ReadByte(faultAddress) == 0x0f && session.ReadByte(faultAddress + 1) == 0x0b,
                "controlled_ud2_is_real_first_chance_illegal_instruction");
        } else {
            Require(stop.code == EXCEPTION_BREAKPOINT && session.IsOriginal(early),
                "earlier_user_breakpoint_restored_and_rewound_without_overwrite");
        }
        session.CancelTemporary();
        Require(session.IsOriginal(afterCall), "interrupted_operation_cancels_and_reads_back_temporary_byte");
        if (fault) {
            // Explicit fixture recovery only: skip the known two-byte UD2.
            auto recovered = stop.context;
            recovered.Rip += 2;
            session.SetContext(recovered);
        } else {
            session.Step();
            stop = session.WaitStop();
            Require(stop.reason == Reason::SingleStep && stop.context.Rip == early + 1,
                "resume_after_user_stop_executes_original_nop_once");
        }
        session.Arm(afterCall, Reason::TemporaryBreakpoint);
        stop = session.WaitStop();
        std::printf("RECOVERY scenario=%s temporaryRearmed=1 priorReason=%s\n", scenario,
            userBreakpoint ? "user_breakpoint" : "first_chance_illegal_instruction");
    }
    VerifyReturnStop(stop, afterCall, entry.context.Rsp);
    session.Finish();
}
void AbortCleanup() {
    DebugSession session("controlled_abort_with_owned_patch_and_tf", false);
    const auto call = session.Address(&FixtureCall);
    session.Arm(call, Reason::UserBreakpoint);
    auto stop = session.WaitStop();
    Require(stop.context.Rip == call, "abort_fixture_has_real_held_stop");
    session.Arm(session.Address(&FixtureAfterCall), Reason::TemporaryBreakpoint);
    stop.context.EFlags |= 0x100UL;
    session.SetContext(stop.context);
    session.AbortForCleanupTest();
}
}
int RunDebugScenarios() {
    using namespace validation;
    int errors = 0;
    const auto run = [&errors](auto body) {
        try { body(); }
        catch (const std::exception& error) { ++errors; std::printf("SCENARIO_ERROR detail=%s\n", error.what()); }
        try { Require(Handle::Count() == 0, "all_explicit_owned_handles_closed_after_scenario"); }
        catch (const std::exception&) { ++errors; }
    };
    run([] { InstructionAndReturn(); });
    run([] { CallOver("call_step_over", false, false); });
    run([] { CallOver("step_over_interrupted_by_user", true, false); });
    run([] { CallOver("step_over_interrupted_by_exception", false, true); });
    run([] { AbortCleanup(); });
    const bool passed = errors == 0 && FailureCount() == 0;
    std::printf("RESULT=%s scenarioErrors=%d assertionFailures=%d ownedHandles=%d\n",
        passed ? "PASS" : "FAIL", errors, FailureCount(), Handle::Count());
    return passed ? 0 : 1;
}
int wmain(int argc, wchar_t** argv) {
    // No general target PID, attach, injection or arbitrary instruction input.
    if (argc == 3 && std::wcscmp(argv[1], L"--child") == 0) {
        const bool fault = std::wcscmp(argv[2], L"fault") == 0;
        if (!fault && std::wcscmp(argv[2], L"normal") != 0) { return 2; }
        if (!IsDebuggerPresent()) { return 3; }
        return FixtureRun(fault ? 1 : 0) == 42 ? 0 : 4;
    }
    if (argc != 1) { return 2; }
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    return RunDebugScenarios();
}
