// Actual CIM record adapter and native field renderer. No CIM/driver/target queries.
#include "../../Ksword5.1/Ksword5.1/HardwareDock/HardwareFieldDocuments.h"
#include "../../Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"

#include <QApplication>
#include <QTreeWidget>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace
{
    int checks = 0;
    void expect(const bool ok, const char* label)
    {
        ++checks;
        if (!ok) { std::fprintf(stderr, "HARDWARE_FIELD_FAILURE=%s\n", label); std::exit(1); }
    }
    void drain()
    {
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }
}

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    using hardware_field_documents::FromCimJson;
    const QString serial = QStringLiteral("literal SerialNumber: x|y\\nName Manufacturer long text");
    const QString source = QStringLiteral("{\"主板\":[{\"Manufacturer\":\"Maker\",\"Product\":\"board:literal\",\"SerialNumber\":\"%1\"}],"
        "\"显卡设备\":[{\"Name\":\"GPU 0\",\"AdapterRAM\":18446744073709551615},{\"Name\":\"GPU 1\",\"AdapterRAM\":0}],\"USB连接\":[]}").arg(serial);
    const auto parsed = FromCimJson(source);
    expect(parsed.has_value(), "ordered record object is accepted");
    expect(parsed->nodes.size() == 3 && parsed->nodes[0].name == QStringLiteral("主板")
        && parsed->nodes[1].name == QStringLiteral("显卡设备"), "collector section order retained");
    expect(parsed->nodes[0].kind == ks::ui::FieldNode::Kind::Section && parsed->nodes[0].translateName,
        "collector owns section labels");
    const auto& board = parsed->nodes[0].children.front();
    expect(board.name == QStringLiteral("board:literal") && !board.translateName, "record caption comes from actual Product value");
    expect(board.children.size() == 3 && board.children[0].name == QStringLiteral("Manufacturer")
        && board.children[2].name == QStringLiteral("SerialNumber"), "CIM properties retain order and membership");
    expect(board.children[2].value == QStringLiteral("literal SerialNumber: x|y\nName Manufacturer long text"),
        "embedded colons bars newlines and header words are data rather than report syntax");
    expect(!board.children[2].translateName && !board.children[2].translateValue, "CIM key and value stay literal");
    expect(parsed->nodes[1].children.size() == 2 && parsed->nodes[1].children[0].name == QStringLiteral("GPU 0")
        && parsed->nodes[1].children[1].name == QStringLiteral("GPU 1"), "multiple records remain separate");
    expect(parsed->nodes[1].children[0].children[1].value == QStringLiteral("18446744073709551615"), "64 bit record integer retains exact lexical value");
    expect(parsed->nodes[2].children.size() == 1 && parsed->nodes[2].children[0].kind == ks::ui::FieldNode::Kind::Note,
        "empty collection has a typed no-device note");
    for (const QString& invalid : {QStringLiteral("[主板]\nManufacturer Product\nMaker Device\n"),
        QStringLiteral("[]"), QStringLiteral("{\"rows\":\"[]\"}"), QStringLiteral("{\"rows\":[\"{}\"]}"),
        QStringLiteral("{\"rows\":[1]}"), QStringLiteral("{\"rows\":{}}"), QStringLiteral("{\"rows\":[{},]}")})
        expect(!FromCimJson(invalid), "schema and JSON syntax failure returns no partial model");

    // Original collector maxima across device/HID/PCI/signed-driver scopes exceed 4096 nodes.
    // Verify every property survives one combined typed snapshot rather than lowering limits.
    QString maximumScope = QStringLiteral("{");
    int recordTotal = 0;
    int fieldTotal = 0;
    for (const auto [records, fields] : {std::pair{120, 7}, std::pair{160, 7}, std::pair{180, 7}, std::pair{220, 9}})
    {
        if (recordTotal) maximumScope += QLatin1Char(',');
        maximumScope += QStringLiteral("\"scope%1\":[").arg(recordTotal);
        for (int row = 0; row < records; ++row)
        {
            if (row) maximumScope += QLatin1Char(',');
            maximumScope += QLatin1Char('{');
            for (int field = 0; field < fields; ++field)
            {
                if (field) maximumScope += QLatin1Char(',');
                maximumScope += QStringLiteral("\"field%1\":\"value%2\"").arg(field).arg(row);
            }
            maximumScope += QLatin1Char('}');
            fieldTotal += fields;
        }
        maximumScope += QLatin1Char(']');
        recordTotal += records;
    }
    maximumScope += QLatin1Char('}');
    const auto maximum = FromCimJson(maximumScope);
    expect(maximum && maximum->nodes.size() == 4, "original maximum collector scopes remain accepted");
    int actualRecords = 0;
    int actualFields = 0;
    for (const auto& group : maximum->nodes)
        for (const auto& record : group.children) { ++actualRecords; actualFields += record.children.size(); }
    expect(actualRecords == recordTotal && actualFields == fieldTotal && actualFields > 4096,
        "maximum scopes retain every record and all 5200 fields");

    KSWORD_ARK_DEVICE_AUDIT_ENTRY entry{};
    // Populate misleading old key/value text. No flag means no metadata regardless of that text.
    const wchar_t oldDetail[] = L"OwnerDriver=0xBAD status=9 rows=10/20 modules=30 statusFlags=0xBAD";
    std::copy(std::begin(oldDetail), std::end(oldDetail), entry.detail);
    const auto unavailable = hardware_field_documents::FromDeviceAuditEntry(entry);
    expect(unavailable.ownerDriver == QStringLiteral("<不可用>") && unavailable.integrityStatus == QStringLiteral("<不可用>")
        && unavailable.integrityRows == QStringLiteral("<不可用>") && unavailable.modules == QStringLiteral("<不可用>")
        && unavailable.integrityFlags == QStringLiteral("<不可用>"), "missing v2 flags explicitly mark all five columns unavailable");
    entry.fieldFlags = KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT | KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT;
    const auto zero = hardware_field_documents::FromDeviceAuditEntry(entry);
    expect(zero.ownerDriver == QStringLiteral("0X0000000000000000") && zero.integrityStatus == QStringLiteral("0")
        && zero.integrityRows == QStringLiteral("0/0") && zero.modules == QStringLiteral("0") && zero.integrityFlags == QStringLiteral("0X00000000"),
        "valid zero metadata renders actual zeros rather than unavailable or legacy text");
    entry.ownerDriverObjectAddress = 0xFFFFA12345678900ULL;
    entry.integrityStatus = 7; entry.integrityReturnedCount = 11; entry.integrityTotalCount = 17;
    entry.integrityModuleCount = 23; entry.integrityStatusFlags = 0x81234567UL;
    const auto typed = hardware_field_documents::FromDeviceAuditEntry(entry);
    expect(typed.ownerDriver == QStringLiteral("0XFFFFA12345678900") && typed.integrityStatus == QStringLiteral("7")
        && typed.integrityRows == QStringLiteral("11/17") && typed.modules == QStringLiteral("23") && typed.integrityFlags == QStringLiteral("0X81234567"),
        "five displayed columns derive only from all six typed payload fields");

    ks::ui::StructuredFieldView view;
    view.setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
    view.setDocument(*parsed); view.resize(700, 500); view.show(); drain();
    auto* tree = view.tree();
    expect(tree->topLevelItemCount() == 3 && tree->topLevelItem(1)->childCount() == 2, "native renderer displays each transported record");
    const auto* serialItem = tree->topLevelItem(0)->child(0)->child(2);
    expect(serialItem->text(1) == board.children[2].value, "native renderer preserves untruncated multiline serial value");
    expect(tree->editTriggers() == QAbstractItemView::NoEditTriggers, "hardware fields remain readonly");
    view.setSearchText(QStringLiteral("GPU 1")); drain();
    expect(!tree->topLevelItem(1)->isHidden() && !tree->topLevelItem(1)->child(1)->isHidden(), "record caption participates in native search");
    view.setSearchText({});
    std::printf("HARDWARE_FIELD_DOCUMENT_CHECKS=%d\nHARDWARE_FIELD_DOCUMENT_FAILURES=0\n", checks);
    return 0;
}
