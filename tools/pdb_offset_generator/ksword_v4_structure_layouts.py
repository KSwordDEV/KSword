"""把完整结构布局、精确身份与版本索引合入同一 v4；源 TSV 仅作为可审计输入。"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any


KINDS = {"thread_layouts": "KSWTHREAD1", "process_layouts": "KSWPROCESS1"}
HEX_KEY = re.compile(r"[0-9A-F]{33,40}")  # 只允许规范 RSDS 键，不允许路径。


def catalog_entries(text: str) -> dict[str, tuple[str, ...]]:
    """输入 LF 索引文本，返回文件名到完整身份的映射；缺行、重复或非法版本整体拒绝。"""
    if not text.endswith("\n") or "\r" in text or len(text) > 512 * 1024:
        raise ValueError("Invalid structure version catalog encoding or size")
    lines = text.splitlines()  # 第一行是格式标记，其后每行只提供版本元数据。
    if not lines or lines[0] != "KSWLAYOUTVERSIONS1":
        raise ValueError("Invalid structure version catalog marker")
    entries = {}  # 输出映射不携带任意路径或运行时地址。
    for line in lines[1:]:
        columns = tuple(line.split("\t"))  # Machine、时间戳、映像大小、RSDS、版本。
        if len(columns) != 5 or not HEX_KEY.fullmatch(columns[3]):
            raise ValueError("Invalid structure catalog identity")
        identity = tuple(map(int, columns[:3]))
        version = tuple(map(int, columns[4].split(".")))
        if identity[0] != 0x8664 or not 0 < identity[2] <= 0xFFFFFFFF or \
                any(value < 0 or value > 0xFFFFFFFF for value in identity) or \
                len(version) != 4 or any(value < 0 or value > 65535 for value in version) or \
                not version[0] or not version[2]:
            raise ValueError("Invalid structure catalog version or PE identity")
        name = "-".join(map(str, identity)) + ".tsv"  # 包内逻辑键，不是运行时外置文件。
        if name in entries:
            raise ValueError(f"Duplicate structure identity: {name}")
        entries[name] = columns
    if not entries or len(entries) > 8192:
        raise ValueError("Empty or oversized structure catalog")
    return entries


def validate_fields(body: str, root_size: int) -> None:
    """输入字段正文和根大小，检查父子、偏移和位域；输出仅为成功或异常。"""
    if not body.endswith("\n") or "\r" in body or len(body.encode("utf-8")) > 512 * 1024:
        raise ValueError("Invalid complete structure field text")
    absolute = [0]  # 与生产解析器相同的一基父行和相对根偏移规则。
    for line in body.splitlines():
        row = line.split("\t")  # 七列保留非位域的空格位，不丢弃 union 别名。
        if len(row) != 7 or len(absolute) > 4096:
            raise ValueError("Invalid structure field column or row count")
        parent, offset = map(int, row[:2])
        if not 0 <= parent < len(absolute) or not 0 <= offset < root_size - absolute[parent]:
            raise ValueError("Invalid structure parent or offset")
        if any(not value or len(value.encode("utf-8")) > 1024 or
               any(ord(ch) < 32 or ord(ch) == 127 for ch in value) for value in row[2:4]):
            raise ValueError("Invalid structure field name or type")
        if row[4] or row[5]:
            bit, width = map(int, row[4:6])  # 位域严格保持原始位置和宽度。
            if not 0 <= bit < 64 or not 0 < width <= 64 - bit:
                raise ValueError("Invalid structure bitfield")
        if row[6] not in ("member", "union"):
            raise ValueError("Invalid structure union marker")
        absolute.append(absolute[parent] + offset)
    if len(absolute) == 1:
        raise ValueError("Empty structure fields")


def build_structure_layouts(profiles_root: Path) -> dict[str, Any]:
    """输入源码 profiles 根目录，返回可内嵌 v4 的去重数据；任何缺失都阻止发布。"""
    result: dict[str, Any] = {"formatVersion": 1, "fieldSets": {}}
    field_sets = result["fieldSets"]  # 全包共享的完整字段正文，身份与版本分别保留。
    validated = set()  # 相同正文和根大小只需重复校验一次。
    for directory, marker in KINDS.items():
        root = profiles_root / directory  # 只读源码目录，不扫描语料盘或网络。
        catalog = (root / "_versions.index").read_bytes().decode("ascii")
        entries = catalog_entries(catalog)
        files = {path.name: path for path in root.glob("*.tsv")}
        if set(files) != set(entries):
            raise ValueError(f"Structure catalog/shard coverage mismatch: {root}")
        if any(root.glob("*.neighbors")):
            raise ValueError(f"Migrate unexpected legacy reference sidecars before publishing: {root}")
        records = {}  # 每个精确 PE/RSDS 身份保留独立根大小及字段集引用。
        for name, identity in entries.items():
            text = files[name].read_bytes().decode("utf-8")
            if len(text.encode("utf-8")) > 512 * 1024:
                raise ValueError(f"Structure header and fields exceed production parser budget: {name}")
            header, body = text.split("\n", 1)
            columns = header.split("\t")  # 类型标记、完整身份及根大小。
            if len(columns) != 6 or columns[0] != marker or tuple(columns[1:5]) != identity[:4]:
                raise ValueError(f"Structure PE/RSDS/header mismatch: {files[name]}")
            size = int(columns[5])
            if not 0 < size <= 65536:
                raise ValueError(f"Invalid structure root size: {name}")
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            if (digest, size) not in validated:
                validate_fields(body, size)
                validated.add((digest, size))
            field_sets[digest] = body  # 逐字保存全部层级、类型及位域，不裁剪行。
            records[name] = [size, digest]
        result[directory] = {"catalog": catalog, "profiles": records}
    return result


def validate_structure_layouts(layouts: Any) -> None:
    """输入已有 v4 扩展，验证所有引用及正文；不允许规范化时静默丢弃完整布局。"""
    if not isinstance(layouts, dict) or layouts.get("formatVersion") != 1:
        raise ValueError("Invalid v4 structure layout format")
    sets = layouts.get("fieldSets")  # 哈希仅用于去重，不代表采样授权。
    if not isinstance(sets, dict) or not sets or len(sets) > 16384:
        raise ValueError("Invalid structure field sets")
    validated = set()
    used = set()
    for kind in KINDS:
        group = layouts.get(kind, {})
        entries = catalog_entries(group.get("catalog", ""))
        records = group.get("profiles")
        if not isinstance(records, dict) or set(records) != set(entries):
            raise ValueError(f"Missing or extra v4 structure identities: {kind}")
        for name, record in records.items():
            if not isinstance(record, list) or len(record) != 2 or type(record[0]) is not int or \
                    not 0 < record[0] <= 65536 or not isinstance(record[1], str):
                raise ValueError(f"Invalid structure record: {name}")
            size, digest = record  # 根大小与字段正文一起决定边界校验。
            body = sets.get(digest)
            if not isinstance(body, str) or hashlib.sha256(body.encode("utf-8")).hexdigest() != digest:
                raise ValueError(f"Missing or modified structure fields: {name}")
            if (digest, size) not in validated:
                validate_fields(body, size)
                validated.add((digest, size))
            used.add(digest)
    if used != set(sets):
        raise ValueError("Unreferenced structure fields in v4")
