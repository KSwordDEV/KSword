"""Publish a clearly failed automatic prerelease with current-run diagnostics."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile


COMPONENTS = {
    "KswordUserMode-unsigned-Release": "User-mode Release build",
    "KswordSetup-unsigned-Release": "KswordSetup Release build",
    "KswordARKLight-unsigned-Release": "KswordARKLight Release build",
    "KswordCheatEnginePlugin-x64-Release": "KswordCheatEnginePlugin Release build (x64)",
    "KswordCheatEngineLauncher-Release": "KswordCheatEngineLauncher Release build",
    "KswordX96dbg-x64-Release": "TitanEngine and x96dbg Release build (x64)",
    "KswordARKDriver-unsigned-Release": "Driver Release build",
}
DIAGNOSTIC_COMPONENTS = {
    "KswordUserMode-unsigned-Release": "KswordUserMode-diagnostic-Release",
    "KswordSetup-unsigned-Release": "KswordSetup-diagnostic-Release",
    "KswordARKLight-unsigned-Release": "KswordARKLight-diagnostic-Release",
    "KswordCheatEnginePlugin-x64-Release": "KswordCheatEnginePlugin-x64-diagnostic-Release",
    "KswordCheatEngineLauncher-Release": "KswordCheatEngineLauncher-diagnostic-Release",
    "KswordX96dbg-x64-Release": "KswordX96dbg-x64-diagnostic-Release",
    "KswordARKDriver-unsigned-Release": "KswordARKDriver-diagnostic-Release",
}
ALLOWED_COMPONENTS = set(COMPONENTS) | set(DIAGNOSTIC_COMPONENTS.values())
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ERROR = re.compile(r"error\s+(?:C|LNK|MSB)\d+|fatal error|##\[error\]|Exception:|FAILED|Error:", re.I)


class Gh:
    def call(self, *args: str) -> bytes:
        result = subprocess.run(["gh", *args], capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
        return result.stdout

    def api_read(self, *args: str) -> bytes:
        # Only GET requests are retried; release creation/upload/deletion are
        # separate calls and may already have mutated GitHub on an API error.
        for attempt in range(3):
            try:
                return self.call("api", "--method", "GET", *args)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                if attempt == 2:
                    raise
                print(f"GitHub API read attempt {attempt + 1}/3 failed: {error}", flush=True)
                time.sleep(5 * (attempt + 1))
        raise AssertionError("unreachable")

    def json(self, endpoint: str):
        return json.loads(self.api_read(endpoint))

    def pages(self, endpoint: str, key: str | None = None) -> list:
        pages = json.loads(self.api_read("--paginate", "--slurp", endpoint))
        return [item for page in pages for item in (page[key] if key else page)]

    def download(self, endpoint: str) -> bytes:
        return self.api_read("--allow-escape-sequences", endpoint)


def clean(text: str) -> str:
    return ANSI.sub("", text).replace("\x00", "")


def markdown(text: str) -> str:
    return clean(text).replace("\r", "").replace("\n", " ").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def error_excerpt(log: str) -> str:
    lines = clean(log).splitlines()
    errors = list(dict.fromkeys(line for line in lines if ERROR.search(line)))
    selected = errors[:12] or lines[-12:]
    return "\n".join(line[:700] for line in selected)[:6000].replace("```", "''' ")


def automatic_releases(releases: list[dict]) -> list[dict]:
    return sorted((r for r in releases if not r.get("draft") and r.get("prerelease")
                   and r.get("tag_name", "").startswith("ci-build-")
                   and r.get("name", "").startswith("[CI Build] ")),
                  key=lambda r: (r.get("created_at", ""), r["tag_name"]), reverse=True)


def publish(gh: Gh, repo: str, sha: str, run_id: str, attempt: str, root: Path,
            needs: dict, driver_id: str | None = None, publication_log: Path | None = None) -> str:
    root.mkdir(parents=True, exist_ok=True)
    prefix = f"repos/{repo}"
    warnings: list[str] = []
    jobs: list[dict] = []
    runs = [run_id]
    diagnostics: dict[str, bytes] = {}

    if not driver_id:
        try:
            matches = [r for r in gh.json(f"{prefix}/actions/workflows/driver-ci.yml/runs?branch=main&event=push&per_page=100")["workflow_runs"]
                       if r["head_sha"] == sha]
            driver_id = str(matches[0]["id"]) if matches else None
        except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            warnings.append(f"Driver CI 查询失败：{error}")
    if driver_id and driver_id != "0":
        try:
            driver = gh.json(f"{prefix}/actions/runs/{driver_id}")
            if driver["head_sha"] != sha or driver.get("head_branch") != "main" or driver.get("event") != "push":
                raise ValueError("Driver CI 提交或分支不匹配")
            runs.append(driver_id)
            if driver["status"] != "completed" or driver["conclusion"] != "success":
                warnings.append(f"Driver CI：{driver['status']} / {driver.get('conclusion') or '未完成'}")
        except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            warnings.append(f"Driver CI 不可用：{error}")
    else:
        warnings.append("没有找到本次提交的 Driver CI。")

    assets: list[Path] = []
    provenance: list[dict] = []
    for current_run in runs:
        try:
            # The current attempt excludes failed jobs left over from a rerun.
            if current_run == run_id:
                job_endpoint = f"{prefix}/actions/runs/{current_run}/attempts/{attempt}/jobs?per_page=100"
            else:
                job_endpoint = f"{prefix}/actions/runs/{current_run}/jobs?per_page=100"
            run_jobs = gh.pages(job_endpoint, "jobs")
            run_jobs = [j for j in run_jobs if j["name"] != "Publish automatic prerelease"]
            jobs.extend(run_jobs)
        except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            warnings.append(f"CI {current_run} 步骤查询失败：{error}")
            run_jobs = []
        for job in run_jobs:
            if job.get("conclusion") in ("success", "skipped"):
                continue
            try:
                log = clean(gh.download(f"{prefix}/actions/jobs/{job['id']}/logs").decode("utf-8", errors="replace"))
                diagnostics[f"job-{job['id']}.log"] = log.encode("utf-8")
                job["error_excerpt"] = error_excerpt(log)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                warnings.append(f"{job['name']} 日志不可用：{error}；请查看该步骤的 Actions 链接。")
        try:
            artifacts = gh.pages(f"{prefix}/actions/runs/{current_run}/artifacts?per_page=100", "artifacts")
        except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            warnings.append(f"CI {current_run} 产物查询失败：{error}")
            continue
        for artifact in artifacts:
            name = artifact["name"]
            if name not in ALLOWED_COMPONENTS or artifact.get("expired"):
                continue
            source = artifact.get("workflow_run", {})
            if source.get("head_sha") != sha or str(source.get("id")) != current_run or source.get("head_branch") != "main":
                warnings.append(f"{name} 未提供匹配当前提交的来源，已省略。")
                continue
            try:
                data = gh.download(f"{prefix}/actions/artifacts/{artifact['id']}/zip")
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    if not archive.namelist() or archive.testzip():
                        raise ValueError("ZIP 内容为空或校验失败")
                destination = root / f"{name}.zip"
                destination.write_bytes(data)
                assets.append(destination)
                provenance.append({"artifact": name, "run": current_run, "sha": sha, "id": artifact["id"]})
            except (RuntimeError, subprocess.TimeoutExpired, ValueError, zipfile.BadZipFile) as error:
                warnings.append(f"{name} 下载失败，已省略：{error}")

    short_sha = sha[:8]
    tag = f"ci-build-{short_sha}-{run_id}-{attempt}"
    notes = ["> [!CAUTION]", "> **CI FAILED：本次 CI 或发布打包失败。此 Release 的产物不完整，尚未通过完整验证。**",
             "> 使用未经完全测试的版本可能导致程序崩溃、系统死锁、系统崩溃、文件丢失或硬件损坏。", "",
             f"- 提交：`{sha}`", f"- CI：https://github.com/{repo}/actions/runs/{run_id}", ""]
    if len(runs) > 1:
        notes.extend([f"- Driver CI：https://github.com/{repo}/actions/runs/{runs[1]}", ""])
    notes.extend(["## 构建结果", "", "| 项目 | 结果 | 失败步骤 / 日志 |", "| --- | --- | --- |"])
    for job in jobs:
        failures = ", ".join(step["name"] for step in job.get("steps", [])
                             if step.get("conclusion") not in (None, "success", "skipped"))
        notes.append(f"| {markdown(job['name'])} | {markdown(job.get('conclusion') or job.get('status', 'unknown'))} | "
                     f"{markdown(failures)} [Actions]({job.get('html_url', '')}) |")
    if not jobs:
        notes.append("| CI | 状态查询失败 | 请查看上方 CI 链接和诊断包 |")
    # needs also reports failures when the jobs API cannot be read.
    for name, state in needs.items():
        if state.get("result") not in ("success", "skipped"):
            notes.append(f"| {markdown(name)} | {markdown(state.get('result', 'unknown'))} | CI 依赖结果 |")
    for job in jobs:
        if job.get("error_excerpt"):
            notes.extend(["", f"### {markdown(job['name'])} 错误摘要", "", "```text", job["error_excerpt"], "```"])
    if publication_log and publication_log.is_file():
        text = clean(publication_log.read_text(encoding="utf-8", errors="replace"))
        diagnostics["release-publication.log"] = text.encode("utf-8")
        notes.extend(["", "### 发布 / 打包错误", "", "```text", error_excerpt(text), "```"])
    if warnings:
        notes.extend(["", "## 诊断信息", ""] + [f"- {markdown(w)}" for w in warnings])
    available = {p["artifact"] for p in provenance}
    notes.extend(["", "## 下载", "", "下列模块来自本次提交已上传且 ZIP 校验通过的产物；完整构建未通过。"
                  "模块可能不完整、未通过测试，或来自严格编译失败后的诊断构建。", ""])
    for name in COMPONENTS:
        if name in available:
            notes.append(f"- [{name}.zip](https://github.com/{repo}/releases/download/{tag}/{name}.zip)")
        if DIAGNOSTIC_COMPONENTS[name] in available:
            diagnostic_name = DIAGNOSTIC_COMPONENTS[name]
            notes.append(f"- [{diagnostic_name}.zip](https://github.com/{repo}/releases/download/{tag}/{diagnostic_name}.zip)：该模块构建或检查失败，文件仅供诊断。")
        if name not in available and DIAGNOSTIC_COMPONENTS[name] not in available:
            notes.append(f"- `{name}`：本次产物不可用 / 未构建。")
    diagnostic_name = f"KswordCI-Diagnostics-{short_sha}.zip"
    notes.extend([f"- [{diagnostic_name}](https://github.com/{repo}/releases/download/{tag}/{diagnostic_name})：构建状态、错误与完整失败日志。", ""])
    body = "\n".join(notes)
    # GitHub release bodies are bounded; retain full evidence in the ZIP.
    if len(body) > 50000:
        body = body[:48000].rsplit("\n", 1)[0] + f"\n\n其余诊断见 `{diagnostic_name}`。\n"
    notes_path = root / "CI_ERRORS.md"
    notes_path.write_text(body, encoding="utf-8")
    diagnostics["CI_ERRORS.md"] = "\n".join(notes).encode("utf-8")
    diagnostics["CI_STATUS.json"] = json.dumps({"sha": sha, "run": run_id, "jobs": jobs,
                                                 "needs": needs, "warnings": warnings,
                                                 "artifacts": provenance}, ensure_ascii=False, indent=2).encode("utf-8")
    diagnostic_path = root / diagnostic_name
    with zipfile.ZipFile(diagnostic_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in diagnostics.items():
            archive.writestr(name, data)
    assets.append(diagnostic_path)
    try:
        commit_title = gh.json(f"{prefix}/commits/{sha}")["commit"]["message"].splitlines()[0]
    except (RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError):
        commit_title = "CI diagnostics"
    title = f"[CI Build] [FAILED] {short_sha} {clean(commit_title)}"[:250]
    # Reuse the deterministic tag on retries, including a partial create/upload.
    existing = next((r for r in gh.pages(f"{prefix}/releases?per_page=100") if r["tag_name"] == tag), None)
    if existing:
        if not existing.get("prerelease") or not existing.get("name", "").startswith("[CI Build] ") or existing.get("target_commitish") != sha:
            raise RuntimeError("Existing release does not match this automatic CI release")
        gh.call("release", "upload", tag, *(str(p) for p in assets), "--repo", repo, "--clobber")
        gh.call("release", "edit", tag, "--repo", repo, "--title", title, "--notes-file", str(notes_path),
                "--prerelease", "--draft=false", "--latest=false")
        url = existing["html_url"]
    else:
        url = gh.call("release", "create", tag, *(str(p) for p in assets), "--repo", repo,
                      "--target", sha, "--title", title, "--notes-file", str(notes_path), "--prerelease", "--latest=false").decode().strip()
    # Retention failures must not hide an already-published diagnostic release.
    try:
        releases = automatic_releases(gh.pages(f"{prefix}/releases?per_page=100"))
        for stale in releases[3:]:
            gh.call("release", "delete", stale["tag_name"], "--repo", repo, "--cleanup-tag", "--yes")
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"Release published; retention cleanup failed: {error}")
    return url


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver-run-id")
    parser.add_argument("--publication-error-log", type=Path)
    args = parser.parse_args()
    url = publish(Gh(), os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"],
                  os.environ.get("GITHUB_RUN_ATTEMPT", "1"), Path(os.environ["RUNNER_TEMP"]) / "ksword-ci-failed-release",
                  json.loads(os.environ.get("CI_JOB_RESULTS", "{}")), args.driver_run_id, args.publication_error_log)
    print(f"Published failed CI prerelease: {url}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(f"\n### Failed CI prerelease\n\n- Release: {url}\n- Contains current-run artifacts and CI error diagnostics.\n")


if __name__ == "__main__":
    main()
