#include "MetricAreaCanvas.h"
#include <QCoreApplication>
#include <QFileInfo>
#include <QMap>
#include <QStringList>
#include <QVariant>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <stdexcept>

namespace ks::i18n {
QString sourceText(const QString& value) { return value; }
struct LanguageManager {
    static LanguageManager& instance() { static LanguageManager manager; return manager; }
    QString displayText(const QString& value) { return value; }
};
}
namespace ks::ui {
struct MetricAreaWindow {
    QString metric, state, identityLabel;
    QStringList modes;
    int selected = -1;
    std::vector<MetricAreaNode> nodes;
    void setSubject(QString, QString, QString identity, QString) { identityLabel = std::move(identity); }
    void setModes(QStringList values, int mode) { modes = std::move(values); selected = mode; }
    void setPresentation(QString value, QString status, std::vector<MetricAreaNode> values) {
        metric = std::move(value); state = std::move(status); nodes = std::move(values);
    }
};
}
enum class ModuleColumn { Size = 1 };
int toModuleColumnIndex(ModuleColumn value) { return static_cast<int>(value); }
struct ModuleRow { QString key, sizeText; QMap<int, QVariant> roles; };
struct CommittedModuleTable {
    std::vector<ModuleRow> rows;
    int rowCount() const { return static_cast<int>(rows.size()); }
    QString rowKey(int row) const { return rows.at(row).key; }
    QVariant cell(int row, int column, int role = Qt::DisplayRole) const {
        const auto& value = rows.at(row);
        return column == 1 && role == Qt::DisplayRole ? QVariant(value.sizeText) : value.roles.value(role);
    }
};
struct ProcessDetailWindow {
    CommittedModuleTable* m_moduleTable = nullptr;
    ks::ui::MetricAreaWindow* m_moduleAreaWindow = nullptr;
    void refreshModuleAreaWindow();
};
struct DiskMonitorStoragePanel {
    struct AreaRow { QString key, drive, label; double readRate = 0, writeRate = 0; bool known = false; };
    std::vector<AreaRow> m_areaRows;
    ks::ui::MetricAreaWindow* m_areaWindow = nullptr;
    int m_areaMode = 2;
    QString m_summaryText;
    static QString formatBytes(double);
    static QString formatRate(double);
    void refreshAreaWindow();
};
__MODULE_PROJECTION__
__VOLUME_PROJECTION__
__FORMAT_BYTES__
__FORMAT_RATE__
int checks = 0;
void check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        ks::ui::MetricAreaWindow chart;
        CommittedModuleTable table;
        ModuleRow first{QStringLiteral("4096|C:\\visible.dll"), QStringLiteral("formatted size, not a number"), {}};
        first.roles.insert(Qt::UserRole, QStringLiteral("C:\\visible.dll"));
        first.roles.insert(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(4096));
        first.roles.insert(Qt::UserRole + 3, QVariant::fromValue<qulonglong>(123456));
        ModuleRow unknown{QStringLiteral("8192|C:\\unknown.dll"), QStringLiteral("N/A"), {}};
        unknown.roles.insert(Qt::UserRole, QStringLiteral("C:\\unknown.dll"));
        table.rows = {first, unknown};
        ProcessDetailWindow modules{&table, &chart}; modules.refreshModuleAreaWindow();
        check(chart.nodes.size() == 2, "visible committed module rows lost");
        check(chart.nodes[0].weight == 123456 && chart.nodes[0].known, "module area parsed display text instead of raw size");
        check(chart.nodes[0].key == first.key && chart.nodes[0].name == QStringLiteral("visible.dll"), "module stable identity/path projection lost");
        check(chart.nodes[0].value == first.sizeText, "module formatted value not preserved");
        check(!chart.nodes[1].known, "missing module size was treated as a real zero");
        table.rows.erase(table.rows.begin()); modules.refreshModuleAreaWindow();
        check(chart.nodes.size() == 1 && chart.nodes[0].key == unknown.key, "filtered-out module remained in chart");
        table.rows.clear(); modules.refreshModuleAreaWindow();
        check(chart.nodes.empty(), "empty committed module view retained old nodes");

        DiskMonitorStoragePanel storage;
        storage.m_areaWindow = &chart;
        storage.m_summaryText = QStringLiteral("partial volume snapshot");
        storage.m_areaRows = {{QStringLiteral("volume-a|epoch-1"), QStringLiteral("T:\\"), QStringLiteral("Data"), 10, 25, true},
            {QStringLiteral("volume-b|epoch-2"), QStringLiteral("U:\\"), {}, 0, 0, false},
            {QStringLiteral("volume-c|epoch-3"), QStringLiteral("V:\\"), {}, 0, 0, true}};
        for (int mode = 0; mode < 3; ++mode) {
            storage.m_areaMode = mode; storage.refreshAreaWindow();
            check(chart.selected == mode && chart.modes.size() == 3, "volume rate selector mode not preserved");
            check(chart.nodes.size() == 3 && chart.nodes[0].weight == (mode == 0 ? 10 : mode == 1 ? 25 : 35), "volume read/write/combined projection incorrect");
            check(chart.nodes[0].key == storage.m_areaRows[0].key, "volume/provider identity changed");
            check(!chart.nodes[1].known && chart.nodes[1].value == QStringLiteral("N/A"), "pending baseline incorrectly became idle volume");
            check(chart.nodes[2].known && chart.nodes[2].weight == 0, "real idle volume became unavailable");
            check(chart.state.contains(storage.m_summaryText), "partial/enumeration source state disappeared");
        }
        storage.m_areaRows.clear(); storage.refreshAreaWindow();
        check(chart.nodes.empty() && chart.identityLabel.isEmpty(), "empty volume snapshot or generic identity-column policy incorrect");
        std::printf("METRIC_AREA_ADAPTERS=PASS CHECKS=%d REAL_PROJECTION_METHODS=1 NATIVE_SAMPLING=0\n", checks);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "METRIC_AREA_ADAPTERS=FAIL %s\n", error.what()); return 1;
    }
}
