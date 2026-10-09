"""Extract the current production manifest/promotion logic for isolated Qt tests.

The caller may point at a staged-tree export; no source is taken from another
checkout. Only the UI/network shell is omitted from the generated translation
unit, while the production parser and directory transaction remain unchanged.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re


def definition(source: str, kind: str, name: str) -> str:
    signature = re.search(r"^    " + kind + r"\s+" + re.escape(name) + r"\b", source, re.M)
    if signature is None:
        raise ValueError(f"Production helper missing: {name}")
    start = signature.start()
    opening = source.index("{", signature.end())
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    for token in tokens.finditer(source, opening):
        value = token.group()
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if not depth:
                return source[start:token.end()] + (";" if kind == "struct" else "")
    raise ValueError(f"Unterminated production helper: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    source = (arguments.repository_root / "Ksword5.1/Ksword5.1/PluginHost.cpp").read_text(encoding="utf-8-sig")
    constants = []
    for name in ("kMaxManifestBytes", "kMaxVisualizationColumns", "kMaxVisualizationSummaryItems"):
        match = re.search(r"^    constexpr[^;]+\b" + name + r"\b[^;]+;", source, re.M)
        if match is None:
            raise ValueError(f"Production constant missing: {name}")
        constants.append(match.group())
    units = [definition(source, "struct", name) for name in (
        "VisualizationValueStyle", "VisualizationField", "PluginVisualization",
        "PluginTabPresentation", "PluginDescriptor", "MarketplacePlugin",
    )]
    units += [definition(source, "bool", name) for name in (
        "isValidPluginId", "isSafeRelativePath", "isSafeCommandToken", "readRequiredString",
        "isValidProtocolName", "isAllowedVisualizationFormat", "isAllowedVisualizationTone",
        "parseVisualizationField", "parseVisualization", "parseTabPresentation",
        "isApprovedMarketplaceUrl", "parseMarketplacePlugin",
        "loadPluginManifestDirectory", "loadPluginManifest", "promoteExtractedPlugin",
    )]
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        "// Generated verbatim from the calling source tree; do not edit.\n"
        + "\n\n".join(constants + units) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
