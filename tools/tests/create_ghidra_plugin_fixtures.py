"""Create offline ZIP data for the real Ghidra plugin install transaction tests."""
from __future__ import annotations

import argparse
from pathlib import Path
import warnings
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", default="valid")
    arguments = parser.parse_args()
    wrapper = arguments.source.name
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(arguments.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in sorted(arguments.source.rglob("*")):
            if item.is_file():
                name = wrapper + "/" + item.relative_to(arguments.source).as_posix()
                if arguments.mode == "missing-source" and name.endswith("/lib/src.zip"):
                    continue
                archive.write(item, name)
        if arguments.mode == "traversal":
            archive.writestr(wrapper + "/../outside-marker.txt", "invalid traversal fixture")
        elif arguments.mode == "device":
            archive.writestr(wrapper + "/legal/CON.txt", "invalid Windows alias fixture")
        elif arguments.mode == "link":
            info = zipfile.ZipInfo(wrapper + "/fixture-link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "outside-marker.txt")
        elif arguments.mode == "duplicate":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(wrapper + "/LICENSE", "duplicate ZIP path fixture")
        elif arguments.mode == "wrong-wrapper":
            archive.writestr("unexpected-wrapper/LICENSE", "invalid wrapper fixture")


if __name__ == "__main__":
    main()
