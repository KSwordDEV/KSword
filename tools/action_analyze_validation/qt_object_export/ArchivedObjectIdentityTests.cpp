#include "ArchivedObjectIdentity.h"

#include <cstdio>

using namespace ks::action_analyze;

// 读取 A0 身份形状的固定合成字节，不依赖机器、真实进程、项目目录或 GUI。
int main()
{
    const ObjectSampleRef sample{QUuid("11111111-1111-4111-8111-111111111111"),
        QUuid("22222222-2222-4222-8222-222222222222")}; // 独立测试项目及采样。
    const QByteArray sharedBasis = R"("basis":{"sourceId":"fixture","sourceEpoch":"33333333-3333-4333-8333-333333333333","verification":"verified","receiveClockId":"rx","firstReceiveQpc":"0","lastReceiveQpc":"17"})"; // 合成归档身份来源。
    const QByteArray process = R"({"kind":"process","ref":{"sampleId":"22222222-2222-4222-8222-222222222222","objectId":"13"},"strength":"strong","machineId":"test-pc","bootId":"test-boot","pid":321,"createTime100ns":"1234",)" + sharedBasis + '}'; // 合成进程值。
    const QByteArray thread = R"({"kind":"thread","ref":{"sampleId":"22222222-2222-4222-8222-222222222222","objectId":"21"},"strength":"strong","owner":{"sampleId":"22222222-2222-4222-8222-222222222222","objectId":"13"},"tid":654,"createTime100ns":"999",)" + sharedBasis + '}'; // 关联到确定的进程对象。
    int checks = 0; // 已执行的断言数。
    int failures = 0; // 失败的断言数。
    const auto check = [&](bool passed, const char* name) {
        // 独立显示每个失败，不短路后续用例。
        ++checks;
        if (!passed)
        {
            ++failures;
            std::printf("FAIL %s\n", name);
        }
    };

    const auto resolveProcess = [&](const QByteArray& bytes) {
        // 每次验证同一明确的采样内进程引用。
        return ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Process, 13, QByteArrayView(bytes));
    };
    const auto resolvedProcess = resolveProcess(process); // 可供导出比对的冻结进程。
    const auto resolvedThread = ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Thread, 21,
        QByteArrayView(thread), QByteArrayView(process)); // 线程与已解析进程。
    check(resolvedProcess.state == ArchivedIdentityState::Ready && resolvedProcess.subject
        && resolvedProcess.subject->process.pid == 321 && resolvedProcess.subject->process.createTime100ns == 1234,
        "process native identity");
    check(resolvedThread.state == ArchivedIdentityState::Ready && resolvedThread.subject && resolvedThread.subject->thread
        && resolvedThread.subject->thread->tid == 654 && resolvedThread.subject->thread->ownerObjectId == 13,
        "thread native identity and owner");
    check(ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Process, 13, std::nullopt).state
        == ArchivedIdentityState::Missing, "missing observation");
    check(ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Thread, 21, QByteArrayView(thread)).state
        == ArchivedIdentityState::Unresolved, "owner not read");
    check(ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Thread, 21, QByteArrayView(thread), QByteArrayView(thread)).state
        == ArchivedIdentityState::IdentityMismatch, "owner type mismatch");

    QByteArray changes = process; // 各反例单独替换一个字段。
    changes.replace(R"("pid":321)", R"("pid":321,"p\u0069d":321)");
    check(resolveProcess(changes).state == ArchivedIdentityState::Invalid, "duplicate decoded key");
    changes = process;
    changes.replace("22222222-2222-4222-8222-222222222222", "22222222-2222-4222-8222-222222222224");
    check(resolveProcess(changes).state == ArchivedIdentityState::IdentityMismatch, "foreign sample");
    changes = process;
    changes.replace(R"("objectId":"13")", R"("objectId":"14")");
    check(ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Thread, 21, QByteArrayView(thread), QByteArrayView(changes)).state
        == ArchivedIdentityState::IdentityMismatch, "wrong owner with same native pid");
    changes = process;
    changes.replace(R"("strength":"strong")", R"("strength":"weak")");
    check(resolveProcess(changes).state == ArchivedIdentityState::Unresolved, "weak process");
    check(ResolveArchivedObjectIdentity(sample, ArchivedObjectKind::Thread, 21, QByteArrayView(thread), QByteArrayView(changes)).state
        == ArchivedIdentityState::Unresolved, "weak owner");

    changes = process;
    changes.replace("verified", "unverified");
    check(resolveProcess(changes).state == ArchivedIdentityState::Invalid, "strong claim without verified source");
    changes = process;
    changes.replace(R"("createTime100ns":"1234")", R"("createTime100ns":"01234")");
    check(resolveProcess(changes).state == ArchivedIdentityState::Invalid, "noncanonical filetime");
    changes = process;
    changes.replace(R"("createTime100ns":"1234")", R"("createTime100ns":"0")");
    check(resolveProcess(changes).state == ArchivedIdentityState::Unresolved, "A0 zero valid but unavailable to menu");
    changes = process;
    changes.replace("test-pc", "\xc0\x80");
    check(resolveProcess(changes).state == ArchivedIdentityState::Invalid, "invalid UTF-8");
    check(resolveProcess(QByteArray("\xef\xbb\xbf") + process).state == ArchivedIdentityState::Invalid, "unexpected BOM");
    changes = process;
    changes.replace(R"("lastReceiveQpc":"17")", R"("lastReceiveQpc":"17","other":1)");
    check(resolveProcess(changes).state == ArchivedIdentityState::Invalid, "unknown source basis field");

    std::printf("Archived identity: %d/%d passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
