#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexFindSearch.h"

#include <QCoreApplication>

#include <iostream>

namespace
{
    namespace hf = ks::ui::hexfind;
    namespace ms = ksword::memwb;
    int checks = 0;
    int failures = 0;

    void Check(bool value, int line)
    {
        ++checks;
        if (!value)
        {
            ++failures;
            std::cerr << "FAIL line " << line << '\n';
        }
    }
#define CHECK(...) Check((__VA_ARGS__), __LINE__)

    void TestCodePages()
    {
        ms::SearchPattern pattern;
        ms::ParseError error;
        CHECK(hf::ParseAnsiPattern(QStringLiteral("中文a"), 936, false, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0xD6, 0xD0, 0xCE, 0xC4, 0x41}));
        CHECK(pattern.mask == std::vector<std::uint8_t>({0xFF, 0xFF, 0xFF, 0xFF, 0xDF}));
        CHECK(error.code == ms::ParseErrorCode::None);
        CHECK(hf::ParseAnsiPattern(QStringLiteral("中A"), 950, true, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0xA4, 0xA4, 0x41}));
        CHECK(hf::ParseAnsiPattern(QStringLiteral("日本a"), 932, true, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x93, 0xFA, 0x96, 0x7B, 0x61}));
        CHECK(hf::ParseAnsiPattern(QStringLiteral("café"), 1252, false, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x43, 0x41, 0x46, 0xE9}));
        CHECK(pattern.mask == std::vector<std::uint8_t>({0xDF, 0xDF, 0xDF, 0xFF}));
        CHECK(hf::ParseAnsiPattern(QStringLiteral("😀a"), 65001, false, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0xF0, 0x9F, 0x98, 0x80, 0x41}));
        CHECK(pattern.mask == std::vector<std::uint8_t>({0xFF, 0xFF, 0xFF, 0xFF, 0xDF}));
        CHECK(hf::ParseAnsiPattern(QStringLiteral("😀a"), 54936, false, pattern, error));
        CHECK(pattern.bytes.size() == 5 && pattern.mask.back() == 0xDF);
        CHECK(hf::ParseAnsiPattern(QString::fromUtf8("A\0b", 3), 936, true, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x41, 0x00, 0x62}));

        CHECK(hf::SystemAnsiCodePage() > 0);
        CHECK(hf::ParsePattern(hf::Mode::TextAnsi, QStringLiteral("Hello"), true, pattern, error, nullptr));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x48, 0x65, 0x6C, 0x6C, 0x6F}));
        ms::SearchPattern explicitPattern;
        CHECK(hf::ParseAnsiPattern(QStringLiteral("Hello"), hf::SystemAnsiCodePage(), true, explicitPattern, error));
        CHECK(pattern.bytes == explicitPattern.bytes && pattern.mask == explicitPattern.mask);
        CHECK(hf::ParsePattern(hf::Mode::TextUtf8, QStringLiteral("中文"), true, pattern, error, nullptr));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87}));
        CHECK(hf::ParsePattern(hf::Mode::TextUtf16Le, QStringLiteral("中文"), true, pattern, error, nullptr));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x2D, 0x4E, 0x87, 0x65}));
        CHECK(hf::ParsePattern(hf::Mode::Hex, QStringLiteral("D6 ??"), true, pattern, error, nullptr));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0xD6, 0x00}));
    }

    void TestLosslessErrors()
    {
        ms::SearchPattern pattern;
        ms::ParseError error;
        CHECK(hf::ParseAnsiPattern(QStringLiteral("OK"), 1252, true, pattern, error));
        const QString text = QStringLiteral("A中文");
        CHECK(!hf::ParseAnsiPattern(text, 1252, true, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::UnrepresentableText && error.position == 1);
        CHECK(pattern.bytes.empty() && pattern.mask.empty() && pattern.description.empty());
        CHECK(hf::DescribeParseError(error, text.toUtf8()) == QStringLiteral("第 2 个字符无法用所选 ANSI 代码页无损表示"));
        CHECK(!hf::ParseAnsiPattern(QStringLiteral("中😀"), 936, false, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::UnrepresentableText && error.position == 3);
        CHECK(hf::DescribeParseError(error, QStringLiteral("中😀").toUtf8()).startsWith(QStringLiteral("第 2 个字符")));
        // Windows 的 best-fit 可将无穷大近似成 8；搜索必须拒绝这种转换。
        CHECK(!hf::ParseAnsiPattern(QStringLiteral("∞"), 1252, false, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::UnrepresentableText);
        CHECK(!hf::ParseAnsiPattern(QString(), 936, false, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::Empty && pattern.bytes.empty());
        CHECK(!hf::ParseAnsiPattern(QStringLiteral("a") + QChar(0xD800), 936, true, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::BadPattern && error.position == 1);
        CHECK(!hf::ParseAnsiPattern(QString(QChar(0xDC00)), 65001, true, pattern, error));
        CHECK(error.code == ms::ParseErrorCode::BadPattern && pattern.bytes.empty());
    }

    void TestMultibyteSearch()
    {
        ms::SearchPattern pattern;
        ms::ParseError error;
        CHECK(hf::ParseAnsiPattern(QStringLiteral("丄a"), 936, false, pattern, error));
        CHECK(pattern.bytes == std::vector<std::uint8_t>({0x81, 0x41, 0x41}));
        CHECK(pattern.mask == std::vector<std::uint8_t>({0xFF, 0xFF, 0xDF}));
        const QByteArray data = QByteArray::fromHex("816141814141814161");
        constexpr std::uint64_t base = 0x1000;
        auto found = hf::RunSearch(data, base, pattern, base, ms::SearchDirection::Forward, true, nullptr);
        CHECK(found.found && found.address == base + 3 && !found.wrapped);
        found = hf::RunSearch(data, base, pattern, base + 4, ms::SearchDirection::Forward, true, nullptr);
        CHECK(found.found && found.address == base + 6);
        found = hf::RunSearch(data, base, pattern, base + 7, ms::SearchDirection::Forward, true, nullptr);
        CHECK(found.found && found.address == base + 3 && found.wrapped);
        found = hf::RunSearch(data, base, pattern, base + 5, ms::SearchDirection::Backward, true, nullptr);
        CHECK(found.found && found.address == base + 3);
        const auto hits = hf::HitsInRange(data, base, pattern, base, base + 8, hf::kMaxVisibleHits);
        CHECK(hits.size() == 2 && hits[0].first == base + 3 && hits[0].last == base + 5);
        QByteArray valid(data.size(), '\1');
        valid[4] = 0; // 未读取字节不能成为真实命中。
        valid[7] = 2; // 加载中字节也不能成为真实命中。
        found = hf::RunSearch(data, base, pattern, base, ms::SearchDirection::Forward, true, nullptr, valid);
        CHECK(!found.found);
        CHECK(hf::ParseAnsiPattern(QStringLiteral("丄a"), 936, true, pattern, error));
        found = hf::RunSearch(data, base, pattern, base, ms::SearchDirection::Forward, true, nullptr);
        CHECK(found.found && found.address == base + 6);
        CHECK(hf::RunSearch(QByteArray::fromHex("816161"), base, pattern, base, ms::SearchDirection::Forward, true, nullptr).found == false);
    }
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    TestCodePages();
    TestLosslessErrors();
    TestMultibyteSearch();
    std::cout << "ANSI_FIND_TESTS checks=" << checks << " failures=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
