"""Check the actual CLI parser without mutating a driver.

2026-09-19：这里原先还断言每条命令的文案在 GUI 语言包里有对应词条。那条断言
的前提是命令目录被主程序消费，而主程序对 hvm_ctl 的依赖已经整条摘掉——目录
和引擎现在只属于这个探针，它的文案不该再出现在发布物的语言包里。保留下来的
是 CLI 解析器本身的回归：进制、参数位置、位宽与页对齐。
"""
import argparse
import json
from pathlib import Path
import subprocess


def invoke(exe, *args):
    return subprocess.run([str(exe), *args], capture_output=True, encoding="utf-8", timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, default=Path("tools/hvm_ctl/hvm_ctl.exe"))
    args = parser.parse_args()
    result = invoke(args.cli, "--json", "commands")
    assert result.returncode == 0, result.stderr
    catalog = json.loads(result.stdout)["commands"]
    by_name = {c["name"]: c for c in catalog}
    assert len(by_name) == len(catalog), "Duplicate command name"
    for command in catalog:
        # 目录文案只需自洽：非空即可，不再与任何语言包比对。
        for source in [command["title"], command["group"], command["description"],
                       *(a["name"] for a in command["arguments"])]:
            assert source, command["name"]

    # Contract regressions: --json must not shift CPU/MSR arguments; hex values
    # must not become decimal, and 64-bit addresses must not be truncated.
    cases = [
        (["gdt-dump", "1"], [1]),
        (["msr-log", "1b"], [0x1B]),
        (["msr-log"], [0x10]),
        (["ept-leaf", "123456789ABC"], [0x123456789ABC]),
        (["events", "18446744073709551615"], [2**64 - 1, 64]),
        (["events", "123", "7"], [123, 7]),
        (["resident-vmreadbench"], [512]),
        (["resident-nested-fullsnapshot"], []),
        (["prepare-svm-general"], []),
        (["resident-svm-general"], []),
        (["soak"], [1000]),
        (["nested-page-map", "1234501e", "7000000", "d1"], [0x1234501E, 0x7000000, 0xD1, 0]),
        (["nested-page-map", "1234501e", "7000000", "d1", "1234"], [0x1234501E, 0x7000000, 0xD1, 1234]),
        (["nested-page-map-test", "1234501e", "7000000", "d1", "4"], [0x1234501E, 0x7000000, 0xD1, 4]),
        (["inject-test", "42", "10000", "20000"], [42, 0x10000, 0x20000, 0x4B535744]),
        (["inject-dll", "42", "10000", "0", "C:/HVM test/中文 测试.dll"], [42, 0x10000, 0, 0]),
    ]
    for command, expected in cases:
        parsed = []
        for prefix in (["--validate"], ["--json", "--validate"]):
            result = invoke(args.cli, *prefix, *command)
            assert result.returncode == 0, (command, result.stderr)
            value = json.loads(result.stdout)
            assert [int(v, 16) for v in value["values"]] == expected, value
            if command[0] == "inject-dll":
                assert value["arguments"][3] == command[4], value
            if "controlRequest" in value:
                wire = value["controlRequest"]
                assert wire["command"] == value["operation"] and wire["flags"] == value["flags"]
                assert wire["expectedGeneration"] == 0
                assert wire["soakMilliseconds"] == (expected[0] if command[0] == "soak" else 0)
                assert wire["vmreadBenchIterations"] == (expected[0] if command[0] == "resident-vmreadbench" else 0)
                if command[0] in ("prepare-svm-general", "resident-svm-general"):
                    assert wire["flags"] & 0x10000, "General nesting must be explicit"
                    assert not (wire["flags"] & 0x8000), "General and bounded probe profiles are exclusive"
            parsed.append(value)
        assert parsed[0] == parsed[1], command

    # The reference mode differs only in CPUID diagnostic snapshot collection.
    fast = json.loads(invoke(args.cli, "--json", "--validate", "resident-nested-hidehv").stdout)
    reference = json.loads(invoke(args.cli, "--json", "--validate", "resident-nested-fullsnapshot").stdout)
    assert reference["operation"] == fast["operation"]
    assert reference["controlRequest"]["flags"] == (fast["controlRequest"]["flags"] | 0x4000)

    invalid = [
        ["gdt-dump", "-1"], ["gdt-dump", "4294967295"], ["gdt-dump", "1junk"], ["status", "1"],
        ["msr-log", "100000000"], ["msr-log", "-1"], ["msr-log", " 1b"],
        ["events", "18446744073709551616"], ["soak", "4294967296"],
        ["prepare-svm-general", "1"], ["resident-svm-general", "1"],
        ["nested-page-map", "1234501e", "7000001", "d1"],
        ["nested-page-map", "1234501e", "7000000", "100"],
        ["nested-page-map", "10000000000000000", "7000000", "00"],
        ["nested-page-map", "0x", "7000000", "00"],
        ["nested-page-map", "1234501e", "7000000"],
        ["nested-page-map-test", "1234501e", "7000000", "d1", "0"],
        ["nested-page-map-test", "1234501e", "7000000", "d1", "5"],
        ["inject-dll", "42", "10000", "0"],
        ["proc-freeze", "42"], ["proc-terminate", "4294967296", "10000"],
        ["unknown-command"],
    ]
    for command in invalid:
        result = invoke(args.cli, "--json", "--validate", *command)
        assert result.returncode == 2, (command, result.returncode, result.stdout, result.stderr)
        assert "device-open-failed" not in result.stdout, command

    print(f"CATALOG_TEXTS=PASS ({len(catalog)} commands)")
    print(f"ARGUMENT_CONTRACTS=PASS ({len(cases) * 2} valid, {len(invalid)} refused)")


if __name__ == "__main__":
    main()
