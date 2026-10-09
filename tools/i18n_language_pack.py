#!/usr/bin/env python3
"""Extract and audit location-aware KSword language-pack entries."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


HAN_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
LATIN_RE = re.compile(r"[A-Za-z]")
PLACEHOLDER_RE = re.compile(r"%(?:L?\d+|n)|\{\d+\}")
SOURCE_SUFFIXES = {".cpp", ".h", ".hpp", ".cc", ".cxx", ".ui"}
# x64 is a generated build-output tree.  It can contain bundled third-party
# plugin payloads whose implementation strings are not application UI text.
SKIPPED_SOURCE_DIRS = {"backup", "x64"}
SKIPPED_SOURCE_LINE_MARKERS = {
    "RELEASE_META_BUILD_TIME_MARKER",
    "RELEASE_META_VERSION_MARKER",
}
# QSS 选择器和 palette 角色不是用户可见文本；样式模板拆行后仍必须从审计源中排除。
QSS_SELECTOR_RE = re.compile(
    r"^(?:Q[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\r\n]+\])?(?:::[A-Za-z_-][A-Za-z0-9_-]*)?)"
    r"(?:\s+Q[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\r\n]+\])?(?:::[A-Za-z_-][A-Za-z0-9_-]*)?)*,?$"
)
QSS_PALETTE_TOKEN_RE = re.compile(r"^palette\([A-Za-z_][A-Za-z0-9_]*\)$")


@dataclass
class Occurrence:
    path: str
    line: int


@dataclass
class ExtractedString:
    text: str
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def stable_key(self) -> str:
        digest = hashlib.sha1(self.text.encode("utf-8")).hexdigest()[:16]
        return f"source.{digest}"


@dataclass(frozen=True)
class CppStringToken:
    text: str
    start: int
    end: int
    line: int


def is_extractable_literal(text: str) -> bool:
    """Keep UI-like source text while excluding paths, styles, and code tokens."""
    if text.lstrip().startswith(("$sections.Add((New-Section", "$ErrorActionPreference=", "$doc[", "$includeHardwareDetails =", "if($includeHardwareDetails)")):
        return False
    if HAN_RE.search(text):
        return True
    value = text.strip()
    if not value or not LATIN_RE.search(value):
        return False
    if QSS_SELECTOR_RE.fullmatch(value) or QSS_PALETTE_TOKEN_RE.fullmatch(value):
        return False
    if any(marker in value for marker in ("\\", "://", "::", "{", "}", ";", "#")):
        return False
    if value.startswith((":/", "--", "-", "<", "$")):
        return False
    if "/" in value or "\\" in value:
        return False
    if re.fullmatch(r"[A-Za-z0-9_+=.?&*|<>:-]+", value) and not re.search(r"[A-Z][a-z]", value):
        return False
    return True


def decode_cpp_string_body(body: str) -> str:
    result: list[str] = []
    index = 0
    simple_escapes = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        '"': '"',
        "'": "'",
        "?": "?",
    }
    while index < len(body):
        character = body[index]
        if character != "\\" or index + 1 >= len(body):
            result.append(character)
            index += 1
            continue

        escape = body[index + 1]
        if escape in simple_escapes:
            result.append(simple_escapes[escape])
            index += 2
            continue
        if escape == "\n":
            index += 2
            continue
        if escape == "\r":
            index += 2
            if index < len(body) and body[index] == "\n":
                index += 1
            continue
        if escape in "xuU":
            if escape == "x":
                match = re.match(r"[0-9A-Fa-f]+", body[index + 2 :])
                width = len(match.group(0)) if match else 0
            else:
                width = 4 if escape == "u" else 8
            digits = body[index + 2 : index + 2 + width]
            if digits and all(value in "0123456789abcdefABCDEF" for value in digits):
                try:
                    result.append(chr(int(digits, 16)))
                    index += 2 + width
                    continue
                except ValueError:
                    pass
        if escape in "01234567":
            match = re.match(r"[0-7]{1,3}", body[index + 1 :])
            digits = match.group(0) if match else escape
            result.append(chr(int(digits, 8)))
            index += 1 + len(digits)
            continue

        result.append("\\")
        result.append(escape)
        index += 2
    return "".join(result)


def scan_cpp_string_tokens(source_text: str) -> Iterable[CppStringToken]:
    index = 0
    line = 1
    length = len(source_text)
    while index < length:
        character = source_text[index]
        if character == "\n":
            line += 1
            index += 1
            continue
        if source_text.startswith("//", index):
            newline_index = source_text.find("\n", index + 2)
            if newline_index < 0:
                return
            index = newline_index
            continue
        if source_text.startswith("/*", index):
            close_index = source_text.find("*/", index + 2)
            if close_index < 0:
                return
            line += source_text.count("\n", index, close_index + 2)
            index = close_index + 2
            continue
        if character == "'":
            index += 1
            while index < length:
                if source_text[index] == "\\":
                    index += 2
                elif source_text[index] == "'":
                    index += 1
                    break
                else:
                    if source_text[index] == "\n":
                        line += 1
                    index += 1
            continue

        prefix = next(
            (
                candidate
                for candidate in (
                    'u8R"',
                    'uR"',
                    'UR"',
                    'LR"',
                    'R"',
                    'u8"',
                    'u"',
                    'U"',
                    'L"',
                    '"',
                )
                if source_text.startswith(candidate, index)
            ),
            None,
        )
        if prefix is None:
            index += 1
            continue

        token_start = index
        token_line = line
        index += len(prefix)
        if "R" in prefix:
            delimiter_end = source_text.find("(", index)
            if delimiter_end < 0:
                index = token_start + 1
                continue
            delimiter = source_text[index:delimiter_end]
            terminator = ")" + delimiter + '"'
            body_start = delimiter_end + 1
            body_end = source_text.find(terminator, body_start)
            if body_end < 0:
                index = token_start + 1
                continue
            body = source_text[body_start:body_end]
            line += source_text.count("\n", token_start, body_end + len(terminator))
            index = body_end + len(terminator)
            yield CppStringToken(body, token_start, index, token_line)
            continue

        body_characters: list[str] = []
        while index < length:
            current = source_text[index]
            if current == "\\" and index + 1 < length:
                body_characters.append(current)
                body_characters.append(source_text[index + 1])
                if source_text[index + 1] == "\n":
                    line += 1
                index += 2
                continue
            if current == '"':
                index += 1
                break
            body_characters.append(current)
            if current == "\n":
                line += 1
            index += 1
        decoded_text = decode_cpp_string_body("".join(body_characters))
        yield CppStringToken(decoded_text, token_start, index, token_line)


def extract_cpp_literals(
    source_text: str,
    tokens: Iterable[CppStringToken] | None = None,
) -> Iterable[tuple[str, int]]:
    for token in tokens if tokens is not None else scan_cpp_string_tokens(source_text):
        decoded_text = token.text
        if is_extractable_literal(decoded_text):
            yield decoded_text, token.line


def cpp_literal_gap_is_ignorable(gap: str) -> bool:
    """Return whether C++ concatenates string tokens separated by this gap."""
    index = 0
    while index < len(gap):
        if gap[index].isspace():
            index += 1
            continue
        if gap.startswith("//", index):
            newline_index = gap.find("\n", index + 2)
            if newline_index < 0:
                return True
            index = newline_index + 1
            continue
        if gap.startswith("/*", index):
            close_index = gap.find("*/", index + 2)
            if close_index < 0:
                return False
            index = close_index + 2
            continue
        return False
    return True


def extract_cpp_concatenated_literals(
    source_text: str,
    tokens: Iterable[CppStringToken] | None = None,
) -> Iterable[tuple[str, int]]:
    """Extract the complete value produced by adjacent C++ string tokens."""
    tokens = list(tokens) if tokens is not None else list(scan_cpp_string_tokens(source_text))
    index = 0
    while index < len(tokens):
        first = tokens[index]
        combined = first.text
        next_index = index + 1
        while next_index < len(tokens):
            previous = tokens[next_index - 1]
            current = tokens[next_index]
            if not cpp_literal_gap_is_ignorable(source_text[previous.end : current.start]):
                break
            combined += current.text
            next_index += 1
        if next_index > index + 1 and is_extractable_literal(combined):
            yield combined, first.line
        index = next_index


SEMANTIC_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+$")
SEMANTIC_CALL_RE = re.compile(
    r"(?:\bks::i18n::(?:text|contextText)|\btranslated|\blocalizedStartupText|"
    r"\bbindText|\bbindToolTip|\bbindStatusTip|\bbindWindowTitle|\bbindPlaceholder|"
    r"\bbindSuffix|\bbindTab|\bbindTabToolTip|\bbindComboItem)\s*\("
)


def find_cpp_call_end(
    source_text: str,
    opening_parenthesis: int,
    token_by_start: dict[int, CppStringToken] | None = None,
) -> int:
    """Find a call's matching parenthesis while ignoring strings and comments."""
    if token_by_start is None:
        token_by_start = {token.start: token for token in scan_cpp_string_tokens(source_text)}
    index = opening_parenthesis
    depth = 0
    while index < len(source_text):
        token = token_by_start.get(index)
        if token is not None:
            index = token.end
            continue
        if source_text.startswith("//", index):
            newline_index = source_text.find("\n", index + 2)
            if newline_index < 0:
                return len(source_text)
            index = newline_index + 1
            continue
        if source_text.startswith("/*", index):
            close_index = source_text.find("*/", index + 2)
            if close_index < 0:
                return len(source_text)
            index = close_index + 2
            continue
        if source_text[index] == "'":
            index += 1
            while index < len(source_text):
                if source_text[index] == "\\":
                    index += 2
                elif source_text[index] == "'":
                    index += 1
                    break
                else:
                    index += 1
            continue
        if source_text[index] == "(":
            depth += 1
        elif source_text[index] == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(source_text)


def extract_semantic_key_references(
    source_text: str,
    tokens: Iterable[CppStringToken] | None = None,
) -> Iterable[tuple[str, int]]:
    """Extract the first dotted string argument from known i18n entry points."""
    all_tokens = list(tokens) if tokens is not None else list(scan_cpp_string_tokens(source_text))
    token_by_start = {token.start: token for token in all_tokens}
    for call_match in SEMANTIC_CALL_RE.finditer(source_text):
        opening_parenthesis = call_match.end() - 1
        call_end = find_cpp_call_end(source_text, opening_parenthesis, token_by_start)
        for token in all_tokens:
            if token.start <= opening_parenthesis:
                continue
            if token.start >= call_end:
                break
            if SEMANTIC_KEY_RE.fullmatch(token.text):
                yield token.text, token.line
                break


def extract_ui_strings(source_text: str) -> Iterable[tuple[str, int]]:
    string_re = re.compile(r"<string(?:\s+[^>]*)?>(.*?)</string>", re.DOTALL)
    for match in string_re.finditer(source_text):
        text = (
            match.group(1)
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&amp;", "&")
        )
        if is_extractable_literal(text):
            yield text, source_text.count("\n", 0, match.start()) + 1


def extract_collector_section_labels(tokens: Iterable[CppStringToken]) -> Iterable[tuple[str, int]]:
    """Collector-owned section labels are UI text; executable PowerShell is not."""
    label_re = re.compile(r"(?:\$doc\['([^']+)'\]\s*=|New-Section\s+'([^']+)')")
    for token in tokens:
        for match in label_re.finditer(token.text):
            label = match.group(1) or match.group(2)
            if is_extractable_literal(label):
                yield label, token.line


def extract_source_strings(
    source_root: Path,
    semantic_references_out: dict[str, list[Occurrence]] | None = None,
) -> dict[str, ExtractedString]:
    extracted: dict[str, ExtractedString] = {}
    for source_path in sorted(source_root.rglob("*")):
        relative_parts = source_path.relative_to(source_root).parts[:-1]
        if any(part.lower() in SKIPPED_SOURCE_DIRS for part in relative_parts):
            continue
        if not source_path.is_file() or source_path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            source_text = source_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            source_text = source_path.read_text(encoding="gb18030")
        cpp_tokens: list[CppStringToken] = []
        if source_path.suffix.lower() == ".ui":
            iterator = extract_ui_strings(source_text)
        else:
            cpp_tokens = list(scan_cpp_string_tokens(source_text))
            iterator = itertools.chain(
                extract_cpp_literals(source_text, cpp_tokens),
                extract_cpp_concatenated_literals(source_text, cpp_tokens),
                extract_collector_section_labels(cpp_tokens),
            )
        source_lines = source_text.splitlines()
        relative_path = source_path.relative_to(source_root).as_posix()
        for text, line in iterator:
            line_text = source_lines[line - 1] if 0 < line <= len(source_lines) else ""
            if any(marker in line_text for marker in SKIPPED_SOURCE_LINE_MARKERS):
                continue
            entry = extracted.setdefault(text, ExtractedString(text=text))
            entry.occurrences.append(Occurrence(relative_path, line))
        if semantic_references_out is not None and cpp_tokens:
            for key, line in extract_semantic_key_references(source_text, cpp_tokens):
                semantic_references_out.setdefault(key, []).append(Occurrence(relative_path, line))
    return extracted


def extract_semantic_references(source_root: Path) -> dict[str, list[Occurrence]]:
    references: dict[str, list[Occurrence]] = {}
    for source_path in sorted(source_root.rglob("*")):
        relative_parts = source_path.relative_to(source_root).parts[:-1]
        if any(part.lower() in SKIPPED_SOURCE_DIRS for part in relative_parts):
            continue
        if not source_path.is_file() or source_path.suffix.lower() not in SOURCE_SUFFIXES - {".ui"}:
            continue
        try:
            source_text = source_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            source_text = source_path.read_text(encoding="gb18030")
        relative_path = source_path.relative_to(source_root).as_posix()
        for key, line in extract_semantic_key_references(source_text):
            references.setdefault(key, []).append(Occurrence(relative_path, line))
    return references


def load_pack(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"Language pack root must be an object: {path}")
    document.setdefault("context_translations", {})
    if not isinstance(document["context_translations"], dict):
        raise ValueError(f"context_translations must be an object: {path}")
    return document


def placeholders(text: str) -> list[str]:
    return sorted(PLACEHOLDER_RE.findall(text))


def allows_han_in_english_source(source_text: str) -> bool:
    """Allow identity data or embedded matching rules that intentionally keep Han text."""
    return (
        source_text
        == "Mapleleaf,存钱买油条（云舟API）,Estrella_Explore,NtKrnl64,一花一树叶,hzh"
        or source_text in {"ACH@流星", "嗯呢呗"}
        # 开发者自述是展示身份的一部分，英文界面也按本人要求保留中文原文。
        or source_text == "一个臭写C++的"
        or "$verdict = if($lower -match 'audit|审计|" in source_text
    )


def build_report(extracted: dict[str, ExtractedString]) -> dict:
    return {
        "schema": "ksword-i18n-source-report",
        "format_version": 1,
        "string_count": len(extracted),
        "strings": [
            {
                "key": entry.stable_key,
                "source": entry.text,
                "occurrences": [occurrence.__dict__ for occurrence in entry.occurrences],
            }
            for entry in sorted(extracted.values(), key=lambda value: value.stable_key)
        ],
    }


def audit(
    extracted: dict[str, ExtractedString],
    zh_pack: dict,
    en_pack: dict,
    semantic_references: dict[str, list[Occurrence]] | None = None,
) -> list[str]:
    errors: list[str] = []
    zh_semantic = zh_pack.get("translations", {})
    en_semantic = en_pack.get("translations", {})
    for semantic_key in sorted(set(zh_semantic) | set(en_semantic)):
        if semantic_key not in zh_semantic:
            errors.append(f"missing zh-CN semantic translation: {semantic_key!r}")
        if semantic_key not in en_semantic:
            errors.append(f"missing en-US semantic translation: {semantic_key!r}")
        elif isinstance(en_semantic[semantic_key], str) and HAN_RE.search(en_semantic[semantic_key]):
            errors.append(f"en-US semantic translation still contains Han text: {semantic_key!r}")
    zh_context = zh_pack.get("context_translations", {})
    en_context = en_pack.get("context_translations", {})
    for context_key in sorted(set(zh_context) | set(en_context)):
        if context_key not in zh_context:
            errors.append(f"missing zh-CN context translation: {context_key!r}")
        if context_key not in en_context:
            errors.append(f"missing en-US context translation: {context_key!r}")
        if context_key in zh_context and not isinstance(zh_context[context_key], str):
            errors.append(f"non-string zh-CN context translation: {context_key!r}")
        if context_key in en_context and not isinstance(en_context[context_key], str):
            errors.append(f"non-string en-US context translation: {context_key!r}")
        if context_key in zh_context and context_key in en_context:
            zh_value = zh_context[context_key]
            en_value = en_context[context_key]
            if placeholders(zh_value) != placeholders(en_value):
                errors.append(f"context placeholder mismatch: {context_key!r}")
            if zh_value.count("\n") != en_value.count("\n"):
                errors.append(f"context newline mismatch: {context_key!r}")
            if HAN_RE.search(en_value):
                errors.append(f"en-US context translation still contains Han text: {context_key!r}")

    for referenced_key, occurrences in sorted((semantic_references or {}).items()):
        location = occurrences[0]
        location_text = f"{location.path}:{location.line}"
        if referenced_key not in zh_semantic and referenced_key not in zh_context:
            errors.append(
                f"missing zh-CN referenced semantic translation: {referenced_key!r} ({location_text})"
            )
        if referenced_key not in en_semantic and referenced_key not in en_context:
            errors.append(
                f"missing en-US referenced semantic translation: {referenced_key!r} ({location_text})"
            )

    # Runtime UI translation uses source_translations only as a controlled
    # fallback for otherwise-unbound widget properties and model headers. Every
    # extractable source string must therefore exist in both packs with matching
    # placeholders/newlines; explicit context keys remain the preferred contract.
    zh_source = zh_pack.get("source_translations", {})
    en_source = en_pack.get("source_translations", {})
    if not isinstance(zh_source, dict):
        errors.append("zh-CN source_translations must be an object")
        zh_source = {}
    if not isinstance(en_source, dict):
        errors.append("en-US source_translations must be an object")
        en_source = {}

    for source_text in sorted(extracted):
        if source_text not in zh_source:
            errors.append(f"missing zh-CN source translation: {source_text!r}")
        if source_text not in en_source:
            errors.append(f"missing en-US source translation: {source_text!r}")
        if source_text not in zh_source or source_text not in en_source:
            continue

        zh_value = zh_source[source_text]
        en_value = en_source[source_text]
        if not isinstance(zh_value, str):
            errors.append(f"non-string zh-CN source translation: {source_text!r}")
            continue
        if not isinstance(en_value, str):
            errors.append(f"non-string en-US source translation: {source_text!r}")
            continue
        source_placeholders = placeholders(source_text)
        if placeholders(zh_value) != source_placeholders:
            errors.append(f"zh-CN source placeholder mismatch: {source_text!r}")
        if placeholders(en_value) != source_placeholders:
            errors.append(f"en-US source placeholder mismatch: {source_text!r}")
        if zh_value.count("\n") != source_text.count("\n"):
            errors.append(f"zh-CN source newline mismatch: {source_text!r}")
        if en_value.count("\n") != source_text.count("\n"):
            errors.append(f"en-US source newline mismatch: {source_text!r}")
        if (
            HAN_RE.search(source_text)
            and HAN_RE.search(en_value)
            and not allows_han_in_english_source(source_text)
        ):
            errors.append(f"en-US source translation still contains Han text: {source_text!r}")
    return errors


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("report", "sync", "translate", "audit"))
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--zh-pack", type=Path, required=True)
    parser.add_argument("--en-pack", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    semantic_references: dict[str, list[Occurrence]] = {}
    extracted = extract_source_strings(arguments.source_root, semantic_references)
    zh_pack = load_pack(arguments.zh_pack)
    en_pack = load_pack(arguments.en_pack)
    if arguments.report is not None:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(
            json.dumps(build_report(extracted), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    if arguments.command == "report":
        print(f"extracted {len(extracted)} unique source strings")
        return 0

    if arguments.command == "translate":
        raise RuntimeError(
            "Automatic source-string translation is disabled. Add a stable "
            "context_translations key at the original UI call site and translate "
            "that key in both language packs."
        )

    if arguments.command == "sync":
        print(
            f"source report contains {len(extracted)} strings; "
            "language packs were not modified"
        )
        return 0

    errors = audit(extracted, zh_pack, en_pack, semantic_references)
    if errors:
        print(f"i18n audit failed with {len(errors)} issue(s):", file=sys.stderr)
        for error in errors[:500]:
            print(f"- {error}", file=sys.stderr)
        if len(errors) > 500:
            print(f"- ... {len(errors) - 500} additional issue(s)", file=sys.stderr)
        return 1
    print(f"i18n audit passed: {len(extracted)} source strings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
