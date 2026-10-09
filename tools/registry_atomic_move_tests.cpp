// 直接运行正式 Win32 KTM 后端：沿用树事务的内存 resource manager，禁止真实注册表调用。
#define main RegistryTreeTransactionRegressionMain
#include "registry_document_transaction_tests.cpp"
#undef main

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    RegistryValueRenameResult result;
    const RegistryApplyValueState expected{true, REG_BINARY, QByteArray(1, '\x42')};
    const QString name = QStringLiteral("Old");
    const QString newName = QStringLiteral(" B ");
    for (const int view : {0, 32, 64})
    {
        const REGSAM flag = view == 32 ? KEY_WOW64_32KEY : view == 64 ? KEY_WOW64_64KEY : 0;
        mock::reset();
        check(RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
            expected, view, result), "native/32/64 value rename uses a real transaction and permanent readback");
        check(result.committed && result.state == RegistryValueRenameResult::State::Renamed && !result.actualOriginal.exists
            && result.actualDestination.data == expected.data, "successful move has correct actual two-end state");
        check(mock::commits == 1 && mock::rollbacks == 0 && mock::ordinaryValueWrites == 0,
            "value writes and delete use bound transaction handles only");
        for (const auto actual : mock::moveViews) check(actual == flag, "all no-follow and transaction handles preserve view");

        mock::reset(); mock::live[mock::root][newName] = {REG_BINARY, QByteArray("B-original")};
        check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
            expected, view, result), "existing destination is rejected before staging");
        check(mock::valueWrites == 0 && mock::valueDeletes == 0 && mock::commits == 0
            && mock::live.value(mock::root).value(newName).bytes == "B-original", "existing B retained with zero writes");

        mock::reset(); mock::lateDestinationValue = true;
        check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
            expected, view, result), "late B inserted after final check aborts commit");
        check(mock::commits == 0 && mock::rollbacks == 1 && original()
            && mock::live.value(mock::root).value(newName).bytes == "external-B",
            "commit conflict retains outside B and original A, never false success");
        check(result.state == RegistryValueRenameResult::State::Conflict && result.originalVerified
            && result.destinationVerified && result.actualDestination.data == "external-B",
            "conflict receipt records actual external B");

        mock::reset(); mock::failValueDelete = true;
        check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
            expected, view, result), "original deletion error prevents commit");
        check(result.state == RegistryValueRenameResult::State::Restored && original()
            && !mock::live.value(mock::root).contains(newName), "failed delete atomically rolls back destination");

        mock::reset(); mock::rejectCommit = true;
        check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
            expected, view, result) && mock::commits == 0 && mock::rollbacks == 1,
            "commit failure rolls back both value operations");

        mock::reset();
        const QString destination = mock::root + QStringLiteral("\\Missing\\Target");
        check(RegistryDocumentApplyService::moveValueWin32(mock::root, name, destination, QString(),
            expected, view, result), "missing destination parent chain created inside the value transaction");
        check(mock::live.value(destination).value(QString()).bytes == expected.data
            && !mock::live.value(mock::root).contains(name), "cross-key default value preserves exact raw bytes");

        mock::reset(); mock::lateDestinationValue = true;
        check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, destination, QString(),
            expected, view, result), "new destination key creation also conflicts atomically");
        check(mock::live.value(destination).value(QString()).bytes == "external-B" && original()
            && mock::commits == 0 && mock::ordinaryValueWrites == 0, "late value in new target is retained");
        check(result.destinationVerified && result.actualDestination.data == "external-B",
            "new destination conflict receipt reports the actual outside value");
    }
    mock::reset(); mock::unavailable = true;
    check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
        expected, 0, result) && mock::valueWrites == 0 && mock::ordinaryValueWrites == 0,
        "missing KTM API has zero ordinary-write fallback");
    mock::reset(); mock::unsupported = true;
    check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
        expected, 0, result) && mock::valueWrites == 0 && mock::ordinaryValueWrites == 0,
        "unsupported registry resource manager refuses before writing");
    mock::reset(); mock::failMoveFinalRead = true;
    check(!RegistryDocumentApplyService::moveValueWin32(mock::root, name, mock::root, newName,
        expected, 0, result) && result.committed && result.state == RegistryValueRenameResult::State::Unverified,
        "permanent commit with failed final read is explicit and cannot be called success or rollback");
    std::cout << "REGISTRY_ATOMIC_MOVE_CHECKS=" << checks << " FAILURES=" << failures << " REAL_REGISTRY_CALLS=0\n";
    return failures ? 1 : 0;
}
