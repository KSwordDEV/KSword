#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KswordARK 驱动功能矩阵计划的静态门禁。

输入是仓库根目录与 ``driver_test_plan.json``。处理过程复用
``tools/ioctl_audit/ksword_ioctl_audit.py`` 的解析器读取 ``shared/driver`` 协议头和
中央注册表，再逐条核对计划：每个已注册 IOCTL 必须被“执行”或“排除”恰好一次；
危险模式命中的 IOCTL 必须落在排除清单里；每条用例引用的 KswordCLI 子命令和变量
占位符都必须真实存在。返回值是进程退出码，0 表示计划与驱动现状一致。

这个门禁不需要驱动测试机，可以在普通 Windows/Linux runner 上运行；它保证
``DriverFunctionalMatrix.ps1`` 真正跑到的那份计划不会随驱动演进而悄悄失真。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

TIERS = {"probe", "guarded"}
EXPECTATIONS = {"success", "graceful", "timeout"}
REASON_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_.]+)\}")
GAP_REASON = "no-cli-path"


def load_auditor(root: Path):
    """载入既有 IOCTL 审计脚本，复用它的头文件/注册表解析实现。

    输入是仓库根目录。处理过程按路径加载模块，不修改被载入模块的任何状态。
    返回值是模块对象，供调用方读取 IOCTL 定义与注册表行。
    """

    path = root / "tools" / "ioctl_audit" / "ksword_ioctl_audit.py"
    spec = importlib.util.spec_from_file_location("ksword_ioctl_audit", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法载入 IOCTL 审计模块：{path}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses(slots=True) 会回查 sys.modules，动态载入前必须先登记模块名。
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def registered_ioctls(root: Path, prefix: str) -> set[str]:
    """返回中央注册表里真实登记的 IOCTL 短名集合。

    输入是仓库根目录与协议前缀。处理过程解析共享协议头，再与
    ``ioctl_registry.c`` 的表行求交，只保留两边都存在的条目。
    返回值是去掉前缀的短名集合。
    """

    auditor = load_auditor(root)
    rules = auditor.load_rules(root)
    headers = auditor.discover_headers(root, rules)
    definitions, _ = auditor.parse_ioctl_defs(headers, root)
    table = {entry.name for entry in auditor.parse_registry(root)}
    return {d.name[len(prefix):] for d in definitions if d.name in table}


def cli_commands(root: Path) -> tuple[set[tuple[str, str]], dict[str, set[str]]]:
    """解析 KswordCLI 内置 help 元数据，得到命令表与「Backed by」映射。

    输入是仓库根目录。处理过程只做正则提取，不编译也不执行 CLI。
    返回值是 (family, subcommand) 集合，以及短名 IOCTL 到命令族的反向映射。
    """

    source = (root / "KswordCLI" / "KswordCLI.cpp").read_text(encoding="utf-8", errors="replace")
    row_re = re.compile(
        r'\{\s*L"([a-z0-9]+)",\s*L"([a-z0-9-]*)",\s*L"[^"]*",\s*L"[^"]*",\s*L"[^"]*",\s*L"([^"]*)"\s*\}'
    )
    commands: set[tuple[str, str]] = set()
    backed: dict[str, set[str]] = {}
    for family, sub, notes in row_re.findall(source):
        commands.add((family, sub))
        for name in re.findall(r"IOCTL_KSWORD_ARK_[A-Z0-9_]+", notes):
            backed.setdefault(name[len("IOCTL_KSWORD_ARK_"):], set()).add(family)
    # 原生 CommandRegistry 已支持多级路径，不能只识别旧主文件的六列 help 表。
    # 仅扫描已登记编译且注册函数在主入口实际调用的文件，拒绝把闲置字符串当命令。
    project = (root / "KswordCLI" / "KswordCLI.vcxproj").read_text(encoding="utf-8")
    compiled = set(re.findall(r'<ClCompile\s+Include="([^"\\/]+\.cpp)"', project))
    native_path = re.compile(r'(?:\.path\s*=\s*|\badd\(\s*)L"([a-z][a-z0-9 -]*)"')
    for filename in sorted(compiled):
        path = root / "KswordCLI" / filename
        if not path.is_file():
            continue
        native = path.read_text(encoding="utf-8", errors="replace")
        registrations = re.findall(r'void\s+(register\w+)\s*\(', native)
        if "addCommand(" not in native or not any(re.search(rf'\b{re.escape(name)}\s*\(', source)
                                                       for name in registrations):
            continue
        for value in native_path.findall(native):
            parts = value.split()
            commands.add((parts[0], parts[1] if len(parts) > 1 else ""))
    return commands, backed


def fail(errors: list[str], message: str) -> None:
    """记录一条门禁失败原因。

    输入是错误列表与描述文本。处理过程只追加，不做去重或排序。
    返回值为空；调用方在全部检查结束后统一输出。
    """

    errors.append(message)


def check_structure(plan: dict[str, Any], errors: list[str]) -> None:
    """校验计划文件本身的结构约束。

    输入是已解析的计划与错误累加列表。处理过程检查 id 唯一性、tier/expect 枚举、
    步骤形状、cleanup 形状以及排除项的原因码格式。返回值为空。
    """

    seen: set[str] = set()
    for case in plan["cases"]:
        cid = case.get("id", "")
        if not cid:
            fail(errors, "存在缺少 id 的用例。")
            continue
        if cid in seen:
            fail(errors, f"用例 id 重复：{cid}")
        seen.add(cid)
        if case.get("tier") not in TIERS:
            fail(errors, f"{cid}: tier 必须是 {sorted(TIERS)} 之一。")
        if case.get("expect") not in EXPECTATIONS:
            fail(errors, f"{cid}: expect 必须是 {sorted(EXPECTATIONS)} 之一。")
        timeout = case.get("timeoutSeconds")
        if not isinstance(timeout, int) or timeout <= 0:
            fail(errors, f"{cid}: timeoutSeconds 必须是正整数。")
        steps = case.get("steps")
        if not isinstance(steps, list) or not steps:
            fail(errors, f"{cid}: steps 必须是非空数组。")
            continue
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                if not isinstance(step, list) or not step or not all(isinstance(x, str) for x in step):
                    fail(errors, f"{cid}: {group} 中存在非法步骤 {step!r}。")

    for row in plan["excluded"]:
        name = row.get("ioctl", "")
        reason = row.get("reason", "")
        if not REASON_RE.match(reason or ""):
            fail(errors, f"{name}: 排除原因码 {reason!r} 必须是 kebab-case。")
        if not row.get("detail"):
            fail(errors, f"{name}: 排除项必须写明 detail，说明为什么 CI 不能执行它。")


def check_coverage(plan: dict[str, Any], registered: set[str], errors: list[str]) -> dict[str, Any]:
    """核对计划对已注册 IOCTL 的覆盖是否完整且互斥。

    输入是计划、注册表短名集合与错误列表。处理过程分别汇总执行集合与排除集合，
    检查缺口、越界名称与重复归类。返回值是供报告使用的统计字典。
    """

    covered: dict[str, list[str]] = {}
    for case in plan["cases"]:
        for name in case["ioctls"]:
            covered.setdefault(name, []).append(case["id"])
    excluded = {row["ioctl"]: row for row in plan["excluded"]}

    for name in sorted(set(covered) & set(excluded)):
        fail(errors, f"{name}: 同时出现在用例和排除清单里，归类必须唯一。")

    unknown = sorted((set(covered) | set(excluded)) - registered)
    for name in unknown:
        fail(errors, f"{name}: 计划引用了未注册的 IOCTL，可能是改名或删除后的残留。")

    missing = sorted(registered - set(covered) - set(excluded))
    for name in missing:
        fail(errors, f"{name}: 新增 IOCTL 未进入功能矩阵计划，请补一条用例或写明排除原因。")

    return {
        "registered": len(registered),
        "covered": len(set(covered) & registered),
        "excluded": len(set(excluded) & registered),
        "missing": missing,
        "unknown": unknown,
        "coveredMap": covered,
        "excludedMap": excluded,
    }


def check_danger_policy(plan: dict[str, Any], registered: set[str], stats: dict[str, Any],
                        errors: list[str]) -> list[str]:
    """执行「不许手贱」的静态防线。

    输入是计划、注册表集合、覆盖统计与错误列表。处理过程用 mustExcludePatterns
    逐个匹配已注册 IOCTL，命中者必须落在排除清单中；确需放行的必须在
    patternWaivers 里写明理由。返回值是命中危险模式的 IOCTL 列表。
    """

    policy = plan["policy"]
    patterns = [re.compile(p) for p in policy["mustExcludePatterns"]]
    waivers = policy.get("patternWaivers", {})
    dangerous: list[str] = []
    for name in sorted(registered):
        if not any(p.search(name) for p in patterns):
            continue
        dangerous.append(name)
        if name in stats["excludedMap"]:
            continue
        reason = waivers.get(name)
        if not reason:
            fail(
                errors,
                f"{name}: 命中危险操作模式却被排进了执行计划。"
                f"这类 IOCTL 的崩溃会归因于测试输入而不是驱动缺陷，必须排除，"
                f"或在 policy.patternWaivers 写明豁免理由。",
            )
        else:
            cases = ", ".join(stats["coveredMap"].get(name, []))
            print(f"  [waiver] {name}: {reason} (用例: {cases})")
    return dangerous


def check_gap_budget(plan: dict[str, Any], stats: dict[str, Any], errors: list[str]) -> dict[str, int]:
    """检查覆盖缺口没有超出既定预算。

    输入是计划、覆盖统计与错误列表。处理过程按原因码统计排除数量，并把
    ``no-cli-path`` 这类“缺口而非安全排除”与 policy.gapBudget 比较。
    返回值是原因码到数量的映射。
    """

    counts: dict[str, int] = {}
    for row in stats["excludedMap"].values():
        counts[row["reason"]] = counts.get(row["reason"], 0) + 1
    for reason, budget in plan["policy"].get("gapBudget", {}).items():
        actual = counts.get(reason, 0)
        if actual > budget:
            fail(
                errors,
                f"排除原因 {reason} 有 {actual} 项，超过预算 {budget}。"
                f"新增缺口必须先补 CLI 入口，或显式上调预算并说明原因。",
            )
    return counts


def check_commands(plan: dict[str, Any], root: Path, errors: list[str]) -> None:
    """核对每条步骤都对应真实存在的 KswordCLI 子命令。

    输入是计划、仓库根目录与错误列表。处理过程比对 CLI 内置 help 元数据，
    并对声明为 no-cli-path 的排除项做反向验证。返回值为空。
    """

    commands, backed = cli_commands(root)
    families = {family for family, _ in commands}
    for case in plan["cases"]:
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                family = step[0]
                sub = step[1] if len(step) > 1 and not step[1].startswith("--") else ""
                if family not in families:
                    fail(errors, f"{case['id']}: 命令族 {family!r} 不在 KswordCLI help 元数据里。")
                elif (family, sub) not in commands:
                    fail(errors, f"{case['id']}: KswordCLI 没有子命令 {family} {sub!r}。")

    for name, row in ((r["ioctl"], r) for r in plan["excluded"]):
        if row["reason"] != GAP_REASON:
            continue
        if name in backed:
            fail(
                errors,
                f"{name}: 被标成 {GAP_REASON}，但 KswordCLI help 元数据声明 "
                f"{sorted(backed[name])} 命令族由它支撑，应改为可执行用例。",
            )


def check_variables(plan: dict[str, Any], errors: list[str]) -> None:
    """核对占位符与 requires 都在 variables 里有定义。

    输入是计划与错误列表。处理过程扫描全部步骤文本里的 ``{var}`` 占位符，
    以及 requires 声明，逐一与 variables 字典比对，并要求 requires 覆盖所有
    非常量占位符。返回值为空。
    """

    declared = set(plan["variables"])
    for case in plan["cases"]:
        used: set[str] = set()
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                for token in step:
                    used.update(PLACEHOLDER_RE.findall(token))
        for name in sorted(used - declared):
            fail(errors, f"{case['id']}: 使用了未声明的变量 {{{name}}}。")
        for name in case.get("requires", []):
            if name not in declared:
                fail(errors, f"{case['id']}: requires 引用了未声明的变量 {name}。")
            if name not in used:
                fail(errors, f"{case['id']}: requires 声明了 {name}，但步骤里没有用到它。")

    guards = set(plan["policy"]["targetGuards"])
    for case in plan["cases"]:
        guard = case.get("targetGuard")
        if guard is None:
            continue
        if guard not in guards:
            fail(errors, f"{case['id']}: targetGuard {guard!r} 未在 policy.targetGuards 中定义。")


def render_report(plan: dict[str, Any], stats: dict[str, Any], counts: dict[str, int],
                  dangerous: list[str]) -> str:
    """生成人可读的覆盖报告。

    输入是计划、覆盖统计、原因码计数与危险模式命中列表。处理过程只做文本拼装。
    返回值是 Markdown 文本，供 CI 作为构件上传。
    """

    probe = [c for c in plan["cases"] if c["tier"] == "probe"]
    guarded = [c for c in plan["cases"] if c["tier"] == "guarded"]
    lines = [
        "# KswordARK 驱动功能矩阵覆盖报告",
        "",
        f"- 已注册 IOCTL：{stats['registered']}",
        f"- 计划执行：{stats['covered']}",
        f"- 计划排除：{stats['excluded']}",
        f"- 用例总数：{len(plan['cases'])}（probe {len(probe)} / guarded {len(guarded)}）",
        f"- 命中危险操作模式并被强制排除：{len(dangerous)}",
        "",
        "## 排除原因分布",
        "",
        "| 原因 | 数量 |",
        "| --- | ---: |",
    ]
    for reason in sorted(counts):
        lines.append(f"| {reason} | {counts[reason]} |")
    lines += ["", "## 排除明细", "", "| IOCTL | 原因 | 说明 |", "| --- | --- | --- |"]
    for row in sorted(plan["excluded"], key=lambda r: (r["reason"], r["ioctl"])):
        lines.append(f"| {row['ioctl']} | {row['reason']} | {row['detail']} |")
    lines.append("")
    return "\n".join(lines)


def force_utf8_output() -> None:
    """把标准输出/错误切到 UTF-8。

    输入无。处理过程在流支持 reconfigure 时改写编码，失败时静默跳过。
    返回值为空。GitHub 的 Windows runner 默认给 Python 的是 cp1252，
    直接打印中文诊断会抛 UnicodeEncodeError，把通过的门禁误判成失败。
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """解析命令行参数。

    输入是参数列表或 None。处理过程只声明选项，不做文件访问。
    返回值是 argparse 命名空间。
    """

    parser = argparse.ArgumentParser(description="KswordARK 驱动功能矩阵计划门禁")
    parser.add_argument("--repo-root", default=".", help="仓库根目录")
    parser.add_argument("--plan", default=None, help="计划文件路径，默认使用仓库内置计划")
    parser.add_argument("--out", default=None, help="可选的 Markdown 覆盖报告输出路径")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """门禁入口。

    输入是命令行参数。处理过程依次执行结构、覆盖、危险策略、缺口预算、命令与变量
    检查，并按需写出报告。返回值是退出码，非零表示计划需要修正。
    """

    force_utf8_output()
    args = parse_args(argv)
    root = Path(args.repo_root).resolve()
    plan_path = Path(args.plan) if args.plan else root / "tools" / "driver_functional_ci" / "driver_test_plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))

    errors: list[str] = []
    registered = registered_ioctls(root, plan["ioctlPrefix"])

    check_structure(plan, errors)
    stats = check_coverage(plan, registered, errors)
    dangerous = check_danger_policy(plan, registered, stats, errors)
    counts = check_gap_budget(plan, stats, errors)
    check_commands(plan, root, errors)
    check_variables(plan, errors)

    report = render_report(plan, stats, counts, dangerous)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8", newline="\n")

    print(f"registered={stats['registered']} covered={stats['covered']} excluded={stats['excluded']} "
          f"cases={len(plan['cases'])} dangerous={len(dangerous)}")
    if errors:
        print("")
        print("驱动功能矩阵计划门禁失败：")
        for message in errors:
            print(f"  - {message}")
        return 1
    print("驱动功能矩阵计划与当前 IOCTL 注册表一致。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
