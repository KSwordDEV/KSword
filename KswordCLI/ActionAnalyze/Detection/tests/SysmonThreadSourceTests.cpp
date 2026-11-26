#include "../SysmonThreadSource.h"
#include "../../Cli/SysmonThreadCommand.h"
#include "../../../CommandRegistry.h"

#include <cstdio>
#include <utility>

using namespace Ksword::ActionAnalyze::Detection;

namespace {

constexpr wchar_t kSource[] = L"a23eae89-8e6d-5917-0000-0010dfaf5004";
constexpr wchar_t kTarget[] = L"a23eae89-8e5a-5917-0000-00100e3e4d04";
constexpr wchar_t kOther[] = L"3381f800-8085-635a-2701-000000008a02";
int assertions = 0;
int failures = 0;

void Check(bool passed, const char* name)
{
    ++assertions;
    if (!passed) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", name);
    }
}

// 合成字段只测试规范投影，不创建远程线程、不修改事件通道或服务。
SysmonThreadFields Event()
{
    SysmonThreadFields fields;
    fields.channel = kSysmonChannel;
    fields.provider = kSysmonProvider;
    fields.providerGuid = L"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}";
    fields.computer = L"fixture.invalid";
    fields.eventId = 8;
    fields.version = 2;
    fields.recordId = 123456789123456789ULL;
    fields.timeCreatedFileTime = 133775291110000000ULL;
    fields.sourceGuid = L"{A23EAE89-8E6D-5917-0000-0010DFAF5004}";
    fields.targetGuid = L"{a23eae89-8e5a-5917-0000-00100e3e4d04}";
    fields.sourcePid = 3210;
    fields.targetPid = 4012;
    fields.newThreadId = 6540;
    fields.startAddress = L"0x123456789aBcDEF0";
    fields.startModule = L"";
    return fields;
}

int TestFixtures()
{
    auto decoded = DecodeSysmonThreadEvent(kTarget, Event());
    Check(decoded.state == SysmonThreadDecode::Observed && decoded.observation.has_value(), "verified-observation");
    if (decoded.observation) {
        const auto& observation = *decoded.observation;
        Check(observation.fields.sourceGuid == kSource && observation.fields.targetGuid == kTarget, "independent-provider-identities");
        Check(observation.fields.recordId == 123456789123456789ULL, "lossless-native-record-id");
        Check(observation.reportedStartAddress == 0x123456789abcdef0ULL, "lossless-reported-address");
        Check(observation.fields.startModule == L"" && !observation.fields.startFunction, "empty-not-missing");
    }

    Check(DecodeSysmonThreadEvent(kOther, Event()).state == SysmonThreadDecode::OtherTarget, "no-output-for-other-target");
    Check(!NormalizeSysmonGuid(L"00000000-0000-0000-0000-000000000000"), "nil-guid");
    Check(!NormalizeSysmonGuid(L"{' or EventID=8}"), "invalid-query-guid");
    Check(NormalizeSysmonGuid(L"{A23EAE89-8E5A-5917-0000-00100E3E4D04}") == kTarget, "normalize-guid");
    auto fields = Event();
    fields.providerGuid = kOther;
    Check(DecodeSysmonThreadEvent(kTarget, fields).state == SysmonThreadDecode::WrongSource, "provider-name-is-not-enough");
    fields = Event();
    fields.channel = L"System";
    Check(DecodeSysmonThreadEvent(kTarget, fields).state == SysmonThreadDecode::WrongSource, "wrong-channel");
    fields = Event();
    fields.eventId = 10;
    Check(DecodeSysmonThreadEvent(kTarget, fields).state == SysmonThreadDecode::WrongSource, "wrong-event-id");
    fields = Event();
    fields.version = 3;
    Check(DecodeSysmonThreadEvent(kTarget, fields).state == SysmonThreadDecode::UnsupportedVersion, "unknown-version");
    fields.version.reset();
    Check(DecodeSysmonThreadEvent(kTarget, fields).state == SysmonThreadDecode::UnsupportedVersion, "missing-version");
    fields = Event();
    fields.sourceGuid.clear();
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "source-guid-required-even-with-pid");
    fields = Event();
    fields.sourceGuid = fields.targetGuid;
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "not-cross-process-guid");
    fields = Event();
    fields.sourcePid = fields.targetPid;
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "conflicting-reported-pid");
    fields = Event();
    fields.newThreadId = 0;
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "new-thread-id-required");
    fields = Event();
    fields.startAddress = L"0x10000000000000000";
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "start-address-overflow");
    fields = Event();
    fields.recordId = 0;
    Check(!DecodeSysmonThreadEvent(kTarget, fields).observation, "record-id-required");
    Check(ReadLocalSysmonThreadEvents({L"invalid", 1, {}}).state == SysmonReadState::InvalidRequest, "invalid-plan-no-query");
    std::printf("SysmonThreadSource: %d assertions, %d failures\n", assertions, failures);
    return failures ? 1 : 0;
}

} // namespace

// 有命令行参数时用真实注册表路由和渲染；不替换生产命令或 Win32 读取器。
int wmain(int argc, wchar_t* argv[])
{
    if (argc == 1) { return TestFixtures(); }
    ks::cli::action_analyze::RegisterSysmonThreadCommand();
    if (std::wstring_view(argv[1]) == L"help") {
        return ks::cli::printHelp(L"analyze sysmon-thread-create") ? 0 : 1;
    }
    return ks::cli::dispatchR3(argc, argv).value_or(1);
}
