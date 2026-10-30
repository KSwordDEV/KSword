"""Replay the actual hardware field-page factory with production Qt/MSVC objects.

Requires a successful current Release build. No production main, CIM, driver,
GPU sampling or system clipboard access. This component regression does not
replace real MainWindow/ADS GUI acceptance.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from msvc_qt_production_fixture import run_msvc_fixture


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    tokens = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/|[{}]', re.S)
    for token in tokens.finditer(source, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if not depth:
                return source[start:token.end()]
    raise ValueError(f"Unclosed production function: {signature}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".codex-build-logs/hardware-field-page"))
    parser.add_argument("--qt-root", type=Path)
    parser.add_argument("--source-ref", help="Replay factory/status helpers from this revision for an A/B check")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source_path = "Ksword5.1/Ksword5.1/HardwareDock/HardwareDock.cpp"
    if args.source_ref:
        import subprocess
        source = subprocess.check_output(["git", "show", f"{args.source_ref}:{source_path}"], cwd=repo).decode("utf-8-sig")
    else:
        source = (repo / source_path).read_text(encoding="utf-8-sig")
    helpers = "\n".join(function(source, signature) for signature in (
        "QWidget* createReadOnlyFieldPage(",
        "ks::ui::FieldDocument queryPowerShellFieldsSync("))
    (output / "hardware_field_page_actual.inc").write_text(helpers, encoding="utf-8")
    # The include resolves beside this generated TU. All renderer, value model,
    # language, theme and layout objects are the real successful build's inputs.
    harness = (repo / "tools/tests/hardware_field_page_tests.cpp").read_text(encoding="utf-8")
    generated = output / "hardware_field_page_tests.cpp"
    generated.write_text(harness, encoding="utf-8")
    run_msvc_fixture(repo, generated, output, "hardware_field_page_tests", qt_root=args.qt_root)


if __name__ == "__main__":
    main()
