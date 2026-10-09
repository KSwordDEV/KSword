"""离线规范化已有 compact v4 包，不解析 PDB、不新增身份或偏移。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any

from . import ksword_profile_release_sync as schema


# 这两个协议号码已保留而无消费者；只移除它们，不忽略其它未知 item。
RETIRED_TIMER_IDS = frozenset({1004, 1006})
ITEM_KEYS = (
    "itemId", "itemKind", "flags", "capabilityGroupId", "valueLow",
    "valueHigh", "aux0", "aux1", "aux2", "aux3",
)
IDENTITY_KEYS = ("moduleClassId", "machine", "timeDateStamp", "sizeOfImage")


def uint32(value: Any, context: str) -> int:
    """输入已有数字及字段名，输出 uint32；拒绝布尔值、缺失和越界值。"""
    if isinstance(value, bool):
        raise ValueError(f"invalid uint32: {context}")
    result = schema.parse_uint32(value)
    if result is None:
        raise ValueError(f"invalid uint32: {context}")
    return result


def field_id_max() -> int:
    """只读唯一共享协议头，输出当前 core ID 上限，避免复制协议常量。"""
    # parents[2] 是仓库根；不依赖调用方当前目录，也不查询语料库或符号缓存。
    header = Path(__file__).resolve().parents[2] / "shared/driver/KswordArkDynDataIoctl.h"
    definitions = dict(re.findall(
        r"^#define\s+(KSW_DYN_FIELD_ID_\w+)\s+(\w+)",
        header.read_text(encoding="utf-8-sig"), re.MULTILINE,
    ))
    value = definitions["KSW_DYN_FIELD_ID_MAX"]
    while value in definitions:
        value = definitions[value]
    return int(value.rstrip("ULul"), 0)


def normalize_profile(profile: Any, index: int, core_max: int) -> dict[str, Any]:
    """输入一个已有 profile，输出单份 v4 items；身份和值原样保留。"""
    context = f"profiles[{index}]"
    if not isinstance(profile, dict):
        raise ValueError(f"profile must be an object: {context}")
    for key in IDENTITY_KEYS:
        uint32(profile.get(key), f"{context}.{key}")
    items = profile.get("items")
    groups = profile.get("capabilityGroups")
    if not isinstance(items, list) or not 1 <= len(items) <= 512:
        raise ValueError(f"invalid v4 items: {context}")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 16:
        raise ValueError(f"invalid v4 capabilityGroups: {context}")

    # 校验原包的组定义与原计数，不能用重算掩盖输入的重复或缺项错误。
    expected: dict[int, tuple[int, int]] = {}
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError(f"invalid capability group: {context}")
        group_id = uint32(group.get("groupId"), context + ".groupId")
        if group_id not in {schema.V4_CORE_GROUP_ID, *schema.V4_FIXED_CAPABILITY_GROUP_COUNTS}:
            raise ValueError(f"unknown capability group {group_id}: {context}")
        if group_id in expected or uint32(group.get("flags"), context + ".group.flags") != 0:
            raise ValueError(f"duplicate/unsupported capability group: {context}")
        expected[group_id] = (
            uint32(group.get("requiredItemCount"), context + ".requiredItemCount"),
            uint32(group.get("optionalItemCount"), context + ".optionalItemCount"),
        )

    actual: Counter[tuple[int, int]] = Counter()
    seen: set[int] = set()
    retained: list[dict[str, Any]] = []
    special_ids = set(schema.V4_SPECIAL_ITEM_IDS.values())
    for source_item in items:
        if not isinstance(source_item, dict):
            raise ValueError(f"invalid v4 item: {context}")
        item = {key: uint32(source_item.get(key), context + "." + key) for key in ITEM_KEYS}
        item_id, group_id = item["itemId"], item["capabilityGroupId"]
        if item_id in seen or item_id == 0 or item_id >= 2048:
            raise ValueError(f"duplicate/invalid item {item_id}: {context}")
        if item_id > core_max and item_id not in special_ids and item_id not in RETIRED_TIMER_IDS:
            raise ValueError(f"unknown item {item_id}: {context}")
        if item["itemKind"] not in schema.V4_ITEM_KIND_IDS.values() or item["flags"] not in (1, 2):
            raise ValueError(f"invalid kind/flags for item {item_id}: {context}")
        if group_id not in expected or item["valueHigh"] != 0:
            raise ValueError(f"invalid group/value for item {item_id}: {context}")
        seen.add(item_id)
        actual[(group_id, item["flags"])] += 1
        if item_id in RETIRED_TIMER_IDS:
            if group_id != schema.V4_TIMER_GROUP_ID:
                raise ValueError(f"retired timer item has wrong group: {context}")
            continue
        if "name" in source_item:
            item["name"] = source_item["name"]
        retained.append(item)
    for group_id, counts in expected.items():
        if counts != (actual[(group_id, 1)], actual[(group_id, 2)]):
            raise ValueError(f"capability group count mismatch {group_id}: {context}")

    # 复用发布生成器的完整组契约；不完整特殊组整体省略，不拼凑缺失偏移。
    current_counts: Counter[tuple[int, int]] = Counter(
        (item["capabilityGroupId"], item["flags"]) for item in retained
    )
    complete_groups = {
        group_id for group_id in expected
        if group_id == schema.V4_CORE_GROUP_ID or
        (current_counts[(group_id, 1)], current_counts[(group_id, 2)]) ==
        schema.V4_FIXED_CAPABILITY_GROUP_COUNTS[group_id]
    }
    retained = [item for item in retained if item["capabilityGroupId"] in complete_groups]
    if not retained:
        raise ValueError(f"no complete v4 items remain: {context}")
    result = dict(profile)
    for key in ("fields", "legacyItems", "typedItems", "callbackItems", "v4Items"):
        result.pop(key, None)
    result["items"] = sorted(retained, key=lambda item: item["itemId"])
    result["capabilityGroups"] = schema.build_pack_v4_capability_groups(result["items"])
    return result


def normalize_pack(pack: Any) -> dict[str, Any]:
    """输入已解析的 v4 包，输出规范包；不写文件，不读取或下载符号。"""
    if not isinstance(pack, dict):
        raise ValueError("DynData pack must be an object")
    if uint32(pack.get("schemaVersion"), "schemaVersion") != 1 or \
            uint32(pack.get("packVersion"), "packVersion") != 4:
        raise ValueError("only schemaVersion=1 packVersion=4 is supported")
    profiles = pack.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("DynData profiles must be nonempty")
    core_max = field_id_max()
    return {
        "schemaVersion": 1,
        "packVersion": 4,
        "profiles": [normalize_profile(profile, index, core_max) for index, profile in enumerate(profiles)],
    }
