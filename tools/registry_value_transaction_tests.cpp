// 生产值事务的能力门禁：普通后端和 R0 不得进入旧 read/set/delete 补写路径。
#include <QCoreApplication>
#include <cstdio>
#include <cstdlib>
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryValueTransactions.h"

namespace fixture
{
unsigned checks = 0;
unsigned ordinaryCalls = 0;
unsigned nativeCalls = 0;
int nativeView = -1;
void require(const bool ok, const char* text)
{
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", text); std::abort(); }
}
// 普通后端只提供旧读写能力；任何意外调用都被计数，绝不连接真实注册表。
class OrdinaryBackend final : public RegistryApplyBackend
{
public:
    bool keyExists(const QString&, bool&, QString&) override { ++ordinaryCalls; return false; }
    bool readValue(const QString&, const QString&, RegistryApplyValueState&, QString&) override { ++ordinaryCalls; return false; }
    bool captureTree(const QString&, RegistryDocument&, QString&) override { ++ordinaryCalls; return false; }
    bool createKey(const QString&, QString&) override { ++ordinaryCalls; return false; }
    bool setValue(const QString&, const QString&, quint32, const QByteArray&, QString&) override { ++ordinaryCalls; return false; }
    bool deleteValue(const QString&, const QString&, QString&) override { ++ordinaryCalls; return false; }
    bool deleteTree(const QString&, const RegistryDocument&, QString&) override { ++ordinaryCalls; return false; }
};
}
// 非原子源不能触发这个 Win32 入口；显式 Win32 来源只用于验证冻结视图的分派。
bool RegistryDocumentApplyService::moveValueWin32(const QString&, const QString&, const QString&, const QString&,
    const RegistryApplyValueState&, const int view, RegistryValueRenameResult& result)
{
    ++fixture::nativeCalls;
    fixture::nativeView = view;
    result = {};
    result.error = QStringLiteral("fixture requires the separate real KTM backend test");
    return false;
}
bool RegistryDocumentApplyService::applyAccess(const RegistryApplyPlan&, RegistryApplyResult&, const std::atomic_bool*) { std::abort(); }
bool RegistryApplyBackend::captureTreeBounded(const QString& path, qint64, RegistryDocument& tree, QString& error)
{ return captureTree(path, tree, error); }

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    using namespace fixture;
    const QString path = QStringLiteral("HKEY_LOCAL_MACHINE\\Fixture");
    const RegistryApplyValueState expected{true, 3, QByteArray::fromHex("004180ff")};
    RegistryValueRenameResult result;
    OrdinaryBackend backend;
    require(!RegistryValueTransactions::renameWithBackend(path, QStringLiteral("A"), QStringLiteral("B"),
        expected, backend, result), "ordinary backend cannot rename");
    require(ordinaryCalls == 0 && result.state == RegistryValueRenameResult::State::Rejected,
        "atomic capability rejection has zero reads/writes");
    for (const int view : {0, 32, 64})
    {
        const auto before = nativeCalls;
        require(!RegistryValueTransactions::rename(path, QStringLiteral("A"), QStringLiteral("B"),
            expected, {view, true}, result), "R0 rename refuses before any native fallback");
        require(nativeCalls == before && ordinaryCalls == 0 && !result.error.isEmpty(), "R0 zero writes and explicit explanation");
    }
    for (const int view : {0, 32, 64})
    {
        require(!RegistryValueTransactions::rename(path, QStringLiteral("A"), QStringLiteral("B"),
            expected, {view, false}, result), "Win32 uses only the KTM entry");
        require(nativeView == view, "Win32 KTM receives original view");
    }
    for (const QString& target : {QString(), QStringLiteral("a"), QString(QChar(0))})
    {
        require(!RegistryValueTransactions::renameWithBackend(path, QStringLiteral("A"), target,
            expected, backend, result), "invalid/default/samecase request rejected");
        require(ordinaryCalls == 0, "invalid request does not call ordinary backend");
    }
    std::printf("REGISTRY_VALUE_TRANSACTION_GATES checks=%u failures=0 real_registry_calls=0\n", checks);
}
