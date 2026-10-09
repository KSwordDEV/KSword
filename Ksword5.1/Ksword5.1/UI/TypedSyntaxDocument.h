#pragma once

#include "StructuredFieldView.h"
#include <optional>

namespace ks::ui
{
    struct TypedSyntaxLimits
    {
        qsizetype maximumCharacters = 2 * 1024 * 1024;
        int maximumNodes = 4096;
        int maximumDepth = 64;
    };
    // An explicit adapter for actual JSON/XML documents, never generated reports.
    // It returns a complete typed snapshot only. Invalid/ambiguous/oversized input
    // stays in the host's original byte/text view, with no partial field tree.
    struct TypedSyntaxDocument
    {
        enum class Kind { Json, Xml };
        Kind kind = Kind::Json;
        FieldDocument fields;
    };

    std::optional<TypedSyntaxDocument> ParseTypedSyntaxDocument(
        const QString& source, const TypedSyntaxLimits& limits = TypedSyntaxLimits{});
}
