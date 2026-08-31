#!/usr/bin/env python3
"""Validate the data-driven Kernel Knowledge catalog and language articles."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = (
    ROOT
    / "Ksword5.1"
    / "Ksword5.1"
    / "KernelDock"
    / "KernelKnowledgeCatalog.cpp"
)
KERNEL_DOCK_PATH = (
    ROOT / "Ksword5.1" / "Ksword5.1" / "KernelDock" / "KernelDock.cpp"
)
KNOWLEDGE_TAB_PATH = (
    ROOT
    / "Ksword5.1"
    / "Ksword5.1"
    / "KernelDock"
    / "KernelKnowledgeTab.cpp"
)
RESEARCH_PROTOCOL_PATH = ROOT / "shared" / "driver" / "KswordArkResearchIoctl.h"
RESEARCH_DRIVER_PATH = (
    ROOT
    / "KswordARKDriver"
    / "src"
    / "features"
    / "research"
    / "research_topic_ioctl.c"
)
RESEARCH_CLIENT_PATH = (
    ROOT
    / "Ksword5.1"
    / "Ksword5.1"
    / "ArkDriverClient"
    / "ArkDriverResearch.cpp"
)
DRIVER_REGISTRY_PATH = (
    ROOT / "KswordARKDriver" / "src" / "dispatch" / "ioctl_registry.c"
)
DRIVER_PROJECT_PATH = ROOT / "KswordARKDriver" / "KswordARKDriver.vcxproj"
DRIVER_FILTERS_PATH = ROOT / "KswordARKDriver" / "KswordARKDriver.vcxproj.filters"
DRIVER_IOCTL_INCLUDE_PATH = ROOT / "KswordARKDriver" / "include" / "ark" / "ark_ioctl.h"
GUI_PROJECT_PATH = ROOT / "Ksword5.1" / "Ksword5.1" / "Ksword5.1.vcxproj"
GUI_FILTERS_PATH = (
    ROOT / "Ksword5.1" / "Ksword5.1" / "Ksword5.1.vcxproj.filters"
)
GUI_TYPES_PATH = (
    ROOT / "Ksword5.1" / "Ksword5.1" / "ArkDriverClient" / "ArkDriverTypes.h"
)
PLAN_PATH = ROOT / "第二规划.md"
LANGUAGE_PATHS = {
    "zh-CN": ROOT / "Ksword5.1" / "Ksword5.1" / "languages" / "zh-CN.json",
    "en-US": ROOT / "Ksword5.1" / "Ksword5.1" / "languages" / "en-US.json",
}

CATEGORY_RE = re.compile(
    r'\{\s*"([a-z0-9_]+)",\s*"(https://learn\.microsoft\.com/[^"]+)"\s*\}'
)
TOPIC_RE = re.compile(
    r'\{\s*"([a-z0-9_]+)",\s*"([a-z0-9_]+)",\s*'
    r'Coverage::([A-Za-z]+),\s*"([a-z0-9_]*)"\s*\}'
)
ROUTE_RE = re.compile(r'routeId\s*==\s*QStringLiteral\("([a-z0-9_]+)"\)')

EXPECTED_CATEGORY_COUNT = 12
EXPECTED_TOPIC_COUNT = 71
EXPECTED_COVERAGE = {
    "Available",
    "AvailableNeedsExplanation",
    "Partial",
    "Planned",
}
EXPECTED_ROUTES = {
    "",
    "cid",
    "hvm",
    "io_management",
    "ipc",
    "kernel_audit",
    "object_namespace",
    "slat_iommu",
    "text_integrity",
    "timer_dpc",
    "vbs",
    "work_queue_threads",
}
EXPECTED_UI_KEYS = {
    "kernel.knowledge.tab.title",
    "kernel.knowledge.tab.tooltip",
    "kernel.knowledge.ui.search.placeholder",
    "kernel.knowledge.ui.search.tooltip",
    "kernel.knowledge.ui.coverage.tooltip",
    "kernel.knowledge.ui.coverage.all",
    "kernel.knowledge.ui.action.previous.tooltip",
    "kernel.knowledge.ui.action.next.tooltip",
    "kernel.knowledge.ui.action.copy.tooltip",
    "kernel.knowledge.ui.action.evidence.tooltip",
    "kernel.knowledge.ui.action.route.tooltip",
    "kernel.knowledge.ui.action.reference.tooltip",
    "kernel.knowledge.ui.tree.header.topic",
    "kernel.knowledge.ui.tree.header.coverage",
    "kernel.knowledge.ui.result_count",
    "kernel.knowledge.ui.badge.coverage",
    "kernel.knowledge.ui.badge.knowledge_complete",
    "kernel.knowledge.ui.reference.microsoft",
    "kernel.knowledge.ui.evidence.collecting",
    "kernel.knowledge.ui.evidence.dialog.title",
    "kernel.knowledge.ui.evidence.unavailable",
    "kernel.knowledge.ui.evidence.summary",
    "kernel.knowledge.ui.evidence.context",
    "kernel.knowledge.ui.evidence.state.available",
    "kernel.knowledge.ui.evidence.state.unavailable",
    "kernel.knowledge.ui.evidence.row",
    "kernel.knowledge.ui.evidence.boundary",
    "kernel.knowledge.ui.empty.title",
    "kernel.knowledge.ui.empty.summary",
    "kernel.knowledge.coverage.available",
    "kernel.knowledge.coverage.needs_explanation",
    "kernel.knowledge.coverage.partial",
    "kernel.knowledge.coverage.planned",
}
EXPECTED_HEADINGS = {
    "zh-CN": (
        "### 对象关系图",
        "### 生命周期",
        "### 公开与私有边界",
        "### 只读观察路径",
        "### 版本、权限与 IRQL",
        "### 正确与错误处理",
        "### Ksword 字段解释",
        "### 证据不能证明什么",
    ),
    "en-US": (
        "### Object relationship",
        "### Lifecycle",
        "### Public and private boundary",
        "### Read-only observation path",
        "### Version, privilege, and IRQL limits",
        "### Correct and incorrect handling",
        "### Ksword field interpretation",
        "### What the evidence cannot prove",
    ),
}


def duplicate_values(values: list[str]) -> list[str]:
    """Return sorted values that occur more than once."""
    return sorted({value for value in values if values.count(value) > 1})


def load_context_translations(path: Path) -> dict[str, str]:
    """Load one language pack's semantic context translation mapping."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    translations = payload.get("context_translations")
    if not isinstance(translations, dict):
        raise ValueError(f"{path}: context_translations is missing or not an object")
    return translations


def validate() -> list[str]:
    """Return every catalog or article integrity error."""
    errors: list[str] = []
    source = CATALOG_PATH.read_text(encoding="utf-8")
    tab_source = KNOWLEDGE_TAB_PATH.read_text(encoding="utf-8")
    for source_path, semantic_source in (
        (CATALOG_PATH, source),
        (KNOWLEDGE_TAB_PATH, tab_source),
    ):
        if "ks::i18n::text(key, key)" in semantic_source:
            errors.append(
                f"{source_path}: dynamic semantic keys must not use key as the zh-CN fallback"
            )
    if "m_articleView->setMarkdown(" in tab_source:
        errors.append(
            "KernelKnowledgeTab must pass MarkdownFeatures through "
            "QTextDocument::setMarkdown, not QTextEdit::setMarkdown"
        )
    if "m_articleView->document()->setMarkdown(" not in tab_source:
        errors.append("KernelKnowledgeTab Markdown document rendering call is missing")
    if (
        "QTextDocument::MarkdownFeatures(QTextDocument::MarkdownDialectGitHub)"
        not in tab_source
    ):
        errors.append(
            "KernelKnowledgeTab must construct MarkdownFeatures before combining flags"
        )
    categories = CATEGORY_RE.findall(source)
    topics = TOPIC_RE.findall(source)

    category_ids = [category_id for category_id, _ in categories]
    topic_ids = [topic_id for topic_id, _, _, _ in topics]
    if len(categories) != EXPECTED_CATEGORY_COUNT:
        errors.append(
            f"catalog category count: expected {EXPECTED_CATEGORY_COUNT}, got {len(categories)}"
        )
    if len(topics) != EXPECTED_TOPIC_COUNT:
        errors.append(
            f"catalog topic count: expected {EXPECTED_TOPIC_COUNT}, got {len(topics)}"
        )
    if duplicates := duplicate_values(category_ids):
        errors.append(f"duplicate category ids: {', '.join(duplicates)}")
    if duplicates := duplicate_values(topic_ids):
        errors.append(f"duplicate topic ids: {', '.join(duplicates)}")

    category_id_set = set(category_ids)
    for topic_id, category_id, coverage, route_id in topics:
        if category_id not in category_id_set:
            errors.append(f"{topic_id}: unknown category {category_id}")
        if coverage not in EXPECTED_COVERAGE:
            errors.append(f"{topic_id}: unknown coverage {coverage}")
        if route_id not in EXPECTED_ROUTES:
            errors.append(f"{topic_id}: unknown read-only route {route_id}")
        if coverage != "Available":
            errors.append(f"{topic_id}: research implementation is not marked Available")
        if not route_id:
            errors.append(f"{topic_id}: implemented topic has no business evidence route")

    # 共享 topic ID、R0 映射表和 Qt 目录必须严格同序，防止 UI 采集到错专题。
    try:
        protocol_source = RESEARCH_PROTOCOL_PATH.read_text(encoding="utf-8")
        driver_source = RESEARCH_DRIVER_PATH.read_text(encoding="utf-8")
        client_source = RESEARCH_CLIENT_PATH.read_text(encoding="utf-8")
        registry_source = DRIVER_REGISTRY_PATH.read_text(encoding="utf-8")
        driver_project = DRIVER_PROJECT_PATH.read_text(encoding="utf-8")
        driver_filters = DRIVER_FILTERS_PATH.read_text(encoding="utf-8")
        driver_ioctl_include = DRIVER_IOCTL_INCLUDE_PATH.read_text(encoding="utf-8")
        gui_project = GUI_PROJECT_PATH.read_text(encoding="utf-8")
        gui_filters = GUI_FILTERS_PATH.read_text(encoding="utf-8")
        gui_types = GUI_TYPES_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append(str(error))
    else:
        protocol_topics = [
            (name, int(number))
            for name, number in re.findall(
                r"#define\s+(KSWORD_ARK_RESEARCH_TOPIC_[A-Z0-9_]+)\s+(\d+)UL",
                protocol_source,
            )
            if name != "KSWORD_ARK_RESEARCH_TOPIC_COUNT"
        ]
        expected_protocol_names = [
            f"KSWORD_ARK_RESEARCH_TOPIC_{topic_id.upper()}"
            for topic_id in topic_ids
        ]
        if [name for name, _ in protocol_topics] != expected_protocol_names:
            errors.append("research protocol topic names/order do not match catalog")
        if [number for _, number in protocol_topics] != list(
            range(1, EXPECTED_TOPIC_COUNT + 1)
        ):
            errors.append("research protocol topic numbers are not contiguous 1..71")
        if not re.search(
            rf"#define\s+KSWORD_ARK_RESEARCH_TOPIC_COUNT\s+"
            rf"{EXPECTED_TOPIC_COUNT}UL\b",
            protocol_source,
        ):
            errors.append("research protocol topic count is missing or stale")

        mapping_table_match = re.search(
            r"g_KswResearchTopics\[\]\s*=\s*\{(?P<body>.*?)\n\};",
            driver_source,
            re.DOTALL,
        )
        mapping_table = (
            mapping_table_match.group("body") if mapping_table_match else ""
        )
        if not mapping_table_match:
            errors.append("R0 research topic mapping table is missing")
        mapped_topics = re.findall(
            r"KSW_TOPIC[1-4]\(\s*(KSWORD_ARK_RESEARCH_TOPIC_[A-Z0-9_]+)\s*,",
            mapping_table,
        )
        if mapped_topics != expected_protocol_names:
            errors.append("R0 research topic mapping names/order do not match protocol")
        mapping_rows = re.findall(
            r"KSW_TOPIC[1-4]\([^\n]+\)",
            mapping_table,
        )
        if len(mapping_rows) != EXPECTED_TOPIC_COUNT:
            errors.append(
                "R0 research mapping row count: "
                f"expected {EXPECTED_TOPIC_COUNT}, got {len(mapping_rows)}"
            )
        registered_ioctls = set(
            re.findall(r"\{\s*(IOCTL_KSWORD_ARK_[A-Z0-9_]+)\s*,", registry_source)
        )
        for topic_name, mapping_row in zip(mapped_topics, mapping_rows):
            macro_match = re.match(r"KSW_TOPIC([1-4])\(", mapping_row)
            business_ioctls = re.findall(
                r"IOCTL_KSWORD_ARK_[A-Z0-9_]+", mapping_row
            )
            if not business_ioctls:
                errors.append(f"{topic_name}: no mapped business IOCTL")
                continue
            expected_ioctl_count = int(macro_match.group(1)) if macro_match else 0
            if len(business_ioctls) != expected_ioctl_count:
                errors.append(
                    f"{topic_name}: KSW_TOPIC{expected_ioctl_count} contains "
                    f"{len(business_ioctls)} business IOCTLs"
                )
            if len(set(business_ioctls)) != len(business_ioctls):
                errors.append(f"{topic_name}: duplicate business IOCTL mapping")
            for ioctl_name in business_ioctls:
                if ioctl_name not in registered_ioctls:
                    errors.append(
                        f"{topic_name}: business IOCTL is not centrally registered: "
                        f"{ioctl_name}"
                    )

        required_source_markers = {
            "protocol IOCTL": "IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC",
            "METHOD_BUFFERED transport": "METHOD_BUFFERED",
            "address evidence access gate": "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
            "R0 handler": "KswordARKResearchIoctlQueryTopic",
            "R0 ABI guard": "KSWORD_ARK_RESEARCH_RESPONSE_HEADER_SIZE == 168UL",
            "authoritative WDF requestor mode": "WdfRequestGetRequestorMode(Request)",
            "bounded output length": "effectiveOutputLength = min(",
            "R3 wrapper": "DriverClient::queryResearchTopic",
            "R3 ABI guard": "research_response_abi_drift",
            "strict response parser": "row byte count mismatch",
            "cross-field response parser": "commonValuesMatch",
            "requestor-mode mirror parser": (
                "requestorModeMirror != response->requestorMode"
            ),
        }
        source_by_marker = {
            "protocol IOCTL": protocol_source,
            "METHOD_BUFFERED transport": protocol_source,
            "address evidence access gate": protocol_source,
            "R0 handler": driver_source,
            "R0 ABI guard": driver_source,
            "authoritative WDF requestor mode": driver_source,
            "bounded output length": driver_source,
            "R3 wrapper": client_source,
            "R3 ABI guard": client_source,
            "strict response parser": client_source,
            "cross-field response parser": client_source,
            "requestor-mode mirror parser": client_source,
        }
        for label, marker in required_source_markers.items():
            if marker not in source_by_marker[label]:
                errors.append(f"research {label} marker is missing: {marker}")
        input_snapshot_position = driver_source.find(
            "RtlCopyMemory(&requestSnapshot"
        )
        output_retrieval_position = driver_source.find(
            "WdfRequestRetrieveOutputBuffer"
        )
        output_zero_position = driver_source.find(
            "RtlZeroMemory(outputBuffer"
        )
        if not (
            0 <= input_snapshot_position < output_retrieval_position < output_zero_position
        ):
            errors.append(
                "research METHOD_BUFFERED input is not snapshotted before output reset"
            )
        if re.search(r"registryEntry->Handler\s*\(", driver_source):
            errors.append("research R0 handler invokes a mapped business handler")
        if "ExGetPreviousMode" in driver_source:
            errors.append(
                "research R0 handler must use the KMDF requestor mode instead of "
                "ExGetPreviousMode"
            )
        if "ObDereferenceObject(topDeviceObject)" not in driver_source:
            errors.append("research R0 WDM top-device reference is not released")
        if not re.search(
            r"IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC\s*,\s*"
            r"KswordARKResearchIoctlQueryTopic",
            registry_source,
        ):
            errors.append("research IOCTL is not registered in the central table")
        if "src\\features\\research\\research_topic_ioctl.c" not in driver_project:
            errors.append("research R0 source is absent from driver vcxproj")
        if "src\\features\\research\\research_topic_ioctl.c" not in driver_filters:
            errors.append("research R0 source is absent from driver vcxproj.filters")
        if "KswordArkResearchIoctl.h" not in driver_ioctl_include:
            errors.append("research shared protocol is absent from ark_ioctl.h")
        if "ArkDriverClient\\ArkDriverResearch.cpp" not in gui_project:
            errors.append("research R3 source is absent from GUI vcxproj")
        if "ArkDriverClient\\ArkDriverResearch.cpp" not in gui_filters:
            errors.append("research R3 source is absent from GUI vcxproj.filters")
        if "KswordArkResearchIoctl.h" not in gui_types:
            errors.append("research shared protocol is absent from ArkDriverTypes.h")
        if "queryResearchTopic" not in tab_source or "m_evidenceGeneration" not in tab_source:
            errors.append("knowledge UI does not expose stale-safe live evidence collection")
        if "DeviceIoControl" in tab_source:
            errors.append("knowledge UI bypasses ArkDriverClient with direct DeviceIoControl")

    try:
        plan_source = PLAN_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append(str(error))
    else:
        for stale_marker in ("[部分]", "[待补]"):
            if stale_marker in plan_source:
                errors.append(f"第二规划 still contains stale marker {stale_marker}")

    kernel_dock_source = KERNEL_DOCK_PATH.read_text(encoding="utf-8")
    route_function_start = kernel_dock_source.find(
        "void KernelDock::openKnowledgeRoute"
    )
    route_function_end = kernel_dock_source.find(
        "void KernelDock::ensureTabInitialized",
        route_function_start,
    )
    if route_function_start < 0 or route_function_end < 0:
        errors.append("KernelDock::openKnowledgeRoute function is missing")
    else:
        routed_ids = ROUTE_RE.findall(
            kernel_dock_source[route_function_start:route_function_end]
        )
        if duplicates := duplicate_values(routed_ids):
            errors.append(f"duplicate KernelDock routes: {', '.join(duplicates)}")
        if set(routed_ids) != EXPECTED_ROUTES - {""}:
            missing_routes = (EXPECTED_ROUTES - {""}) - set(routed_ids)
            extra_routes = set(routed_ids) - EXPECTED_ROUTES
            if missing_routes:
                errors.append(
                    f"KernelDock routes missing: {', '.join(sorted(missing_routes))}"
                )
            if extra_routes:
                errors.append(
                    f"KernelDock routes not whitelisted: {', '.join(sorted(extra_routes))}"
                )

    for language_id, path in LANGUAGE_PATHS.items():
        try:
            language_source = path.read_text(encoding="utf-8")
            translations = load_context_translations(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            errors.append(str(error))
            continue

        required_keys = set(EXPECTED_UI_KEYS)
        required_keys.update(
            f"kernel.knowledge.category.{category_id}.title"
            for category_id in category_ids
        )
        for topic_id in topic_ids:
            required_keys.update(
                {
                    f"kernel.knowledge.topic.{topic_id}.title",
                    f"kernel.knowledge.topic.{topic_id}.summary",
                    f"kernel.knowledge.topic.{topic_id}.body",
                }
            )

        for key in sorted(required_keys):
            value = translations.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{language_id}: missing or empty {key}")
            key_occurrences = len(
                re.findall(
                    rf'^\s*"{re.escape(key)}"\s*:',
                    language_source,
                    re.MULTILINE,
                )
            )
            if key_occurrences != 1:
                errors.append(
                    f"{language_id}: expected exactly one JSON key {key}, "
                    f"got {key_occurrences}"
                )

        topic_key_re = re.compile(
            r"kernel\.knowledge\.topic\.([a-z0-9_]+)\.(title|summary|body)"
        )
        translated_topic_ids = {
            match.group(1)
            for key in translations
            if (match := topic_key_re.fullmatch(key)) is not None
        }
        extra_topic_ids = translated_topic_ids - set(topic_ids)
        if extra_topic_ids:
            errors.append(
                f"{language_id}: topics absent from catalog: "
                f"{', '.join(sorted(extra_topic_ids))}"
            )

        headings = EXPECTED_HEADINGS[language_id]
        for topic_id in topic_ids:
            body_key = f"kernel.knowledge.topic.{topic_id}.body"
            body = translations.get(body_key)
            if not isinstance(body, str):
                continue
            positions = [body.find(heading) for heading in headings]
            if any(position < 0 for position in positions):
                missing = [
                    heading for heading, position in zip(headings, positions) if position < 0
                ]
                errors.append(
                    f"{language_id}:{topic_id}: missing headings: {', '.join(missing)}"
                )
            elif positions != sorted(positions):
                errors.append(f"{language_id}:{topic_id}: headings are out of order")
            if body.count("### ") != len(headings):
                errors.append(
                    f"{language_id}:{topic_id}: expected {len(headings)} level-3 headings, "
                    f"got {body.count('### ')}"
                )
            if "```text" not in body:
                errors.append(f"{language_id}:{topic_id}: relationship diagram is missing")
            if body.count("```") != 2:
                errors.append(
                    f"{language_id}:{topic_id}: expected one closed relationship diagram, "
                    f"got {body.count('```')} code fences"
                )

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("KERNEL_KNOWLEDGE_VALIDATION=FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "KERNEL_KNOWLEDGE_VALIDATION=SUCCESS "
        f"topics={EXPECTED_TOPIC_COUNT} categories={EXPECTED_CATEGORY_COUNT} languages=2"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
