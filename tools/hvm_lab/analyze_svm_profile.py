"""Turn KSword AMD metrics snapshots into an exit-profile flame graph input.

The collapsed stacks are weighted by observed exits. They identify the hot
architecture paths (L1/L2 and exit code); they are not instruction-retired
cycle samples. Use ETW/WPA or a PMU sampler for guest instruction-level time.
"""
import argparse
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.loads(f.readline())


def code(v):
    return str(v).lower().replace("0x", "0x")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="metrics JSONL files or glob patterns")
    ap.add_argument("--out", required=True, help="profile JSON destination")
    ns = ap.parse_args()
    files = []
    for item in ns.inputs:
        matches = glob.glob(item, recursive=True)
        files.extend(matches or [item])
    counts = Counter()
    cpu_totals = defaultdict(int)
    npf = Counter()
    samples = 0
    for name in sorted(set(files)):
        data = load(name)
        samples += 1
        for row in data.get("svmProcessors", []):
            cpu = f"g{row.get('group', 0)}p{row.get('number', 0)}"
            levels = row.get("hotspots", {}).get("levels", [])
            for level, hot in enumerate(levels, 1):
                total = int(hot.get("total", 0))
                cpu_totals[cpu] += total
                npf[(cpu, level)] += int(hot.get("npf", 0))
                for raw, count in hot.get("codes", {}).items():
                    n = int(count)
                    if n:
                        counts[f"svm;{cpu};L{level};exit_{raw}"] += n
            general = row.get("general", {})
            if general.get("valid"):
                for name2, value in (("prepared", general.get("preparedEntries", 0)),
                                     ("hardware_exit", general.get("hardwareExits", 0))):
                    counts[f"svm;{cpu};general;{name2}"] += int(value)
    total = sum(counts.values())
    collapsed = "\n".join(f"{stack} {count}" for stack, count in sorted(counts.items())) + ("\n" if counts else "")
    result = {
        "kind": "ksword-amd-exit-profile",
        "samples": samples,
        "weight": "observed exits and lifecycle counters",
        "instructionCycleSampling": False,
        "totalWeight": total,
        "npfByCpuLevel": {f"{cpu}/L{level}": count for (cpu, level), count in sorted(npf.items())},
        "cpuExitTotals": dict(sorted(cpu_totals.items())),
        "collapsedPath": str(Path(ns.out).with_suffix(".collapsed")),
    }
    out = Path(ns.out)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(result["collapsedPath"]).write_text(collapsed, encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
