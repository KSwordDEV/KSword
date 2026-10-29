"""Offline regression tests; all GitHub calls and release mutations are mocked."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zipfile

import ci_failure_release as release
from test_ci_driver_package import bash_path


SHA = "a" * 40
MODULE = "KswordARKLight-unsigned-Release"


def archive_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("Release/KswordARKLight.exe", b"fixture")
    return output.getvalue()


class FakeGh:
    def __init__(self):
        self.calls = []
        self.downloads = []
        self.driver_status = "completed"
        self.driver_conclusion = "success"
        self.driver_sha = SHA
        self.job_failure = True
        self.job_api_error = False
        self.driver_api_error = False
        self.artifact_error = False
        self.corrupt_artifact = False
        self.artifact_sha = SHA
        self.artifact_run = 10
        self.artifact_name = MODULE
        self.releases = []

    def json(self, endpoint):
        if "/workflows/driver-ci.yml/runs" in endpoint:
            if self.driver_api_error:
                raise RuntimeError("Driver status unavailable")
            return {"workflow_runs": [{"id": 20, "head_sha": SHA}]}
        if endpoint.endswith("/actions/runs/20"):
            return {"head_sha": self.driver_sha, "head_branch": "main", "event": "push",
                    "status": self.driver_status, "conclusion": self.driver_conclusion}
        if "/commits/" in endpoint:
            return {"commit": {"message": "fixture title\nsecond line"}}
        raise AssertionError(endpoint)

    def pages(self, endpoint, key=None):
        if key == "jobs":
            if self.job_api_error:
                raise RuntimeError("Jobs unavailable")
            if "/runs/20/" in endpoint:
                return [{"id": 200, "name": "Driver Release build", "status": self.driver_status,
                         "conclusion": self.driver_conclusion, "html_url": "https://github.com/driver", "steps": []}]
            assert "/attempts/2/jobs" in endpoint
            return [{"id": 100, "name": "User-mode Release build", "status": "completed",
                     "conclusion": "failure" if self.job_failure else "success", "html_url": "https://github.com/job",
                     "steps": [{"name": "Compile C++", "conclusion": "failure" if self.job_failure else "success"}]},
                    {"id": 101, "name": "KswordSetup Release build", "conclusion": "skipped", "steps": []},
                    {"id": 102, "name": "Publish automatic prerelease", "conclusion": None, "status": "in_progress"}]
        if key == "artifacts":
            if "/runs/20/" in endpoint:
                return []
            return [{"id": 300, "name": self.artifact_name, "expired": False,
                     "workflow_run": {"head_sha": self.artifact_sha, "id": self.artifact_run, "head_branch": "main"}},
                    {"id": 301, "name": "ioctl-audit", "expired": False},
                    {"id": 302, "name": "KswordSetup-unsigned-Release", "expired": True}]
        if "/releases?" in endpoint:
            return self.releases
        raise AssertionError(endpoint)

    def download(self, endpoint):
        self.downloads.append(endpoint)
        if endpoint.endswith("/logs"):
            return b"noise\n\x1b[31mfile.cpp(4): error C4996: deprecated Qt overload\x1b[0m\n##[error]Build failed\n"
        if self.artifact_error:
            raise RuntimeError("Artifact download unavailable")
        return b"not a ZIP" if self.corrupt_artifact else archive_bytes()

    def call(self, *args):
        self.calls.append(args)
        return b"https://github.com/test/repo/releases/tag/fixture\n"


class FailureReleaseTests(unittest.TestCase):
    def publish(self, gh, root, needs=None, **kwargs):
        return release.publish(gh, "test/repo", SHA, "10", "2", root,
                               needs if needs is not None else {"usermode-release": {"result": "failure"}}, **kwargs)

    def test_failed_build_publishes_errors_and_available_current_modules(self):
        gh = FakeGh()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            url = self.publish(gh, root)
            self.assertIn("github.com", url)
            notes = (root / "CI_ERRORS.md").read_text(encoding="utf-8")
            for expected in ("CI FAILED", "error C4996", "Compile C++", "skipped", MODULE, "未构建", "完整构建未通过", "模块可能不完整"):
                self.assertIn(expected, notes)
            self.assertNotIn("\x1b", notes)
            self.assertNotIn("Publish automatic prerelease", notes)
            with zipfile.ZipFile(root / f"KswordCI-Diagnostics-{SHA[:8]}.zip") as archive:
                self.assertIn("job-100.log", archive.namelist())
                self.assertNotIn("job-101.log", archive.namelist())
                status = json.loads(archive.read("CI_STATUS.json"))
                self.assertEqual(status["artifacts"][0]["sha"], SHA)
            create = next(c for c in gh.calls if c[:2] == ("release", "create"))
            self.assertIn(str(root / f"{MODULE}.zip"), create)
            self.assertIn("--latest=false", create)
            self.assertIn("[FAILED]", create[create.index("--title") + 1])

    def test_driver_failure_alone_generates_failed_release(self):
        gh = FakeGh()
        gh.job_failure = False
        gh.driver_conclusion = "failure"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.publish(gh, root, {"usermode-release": {"result": "success"}}, driver_id="20")
            notes = (root / "CI_ERRORS.md").read_text(encoding="utf-8")
            self.assertIn("Driver CI：completed / failure", notes)
            self.assertIn("Driver Release build 错误摘要", notes)

    def test_failed_usermode_job_keeps_its_current_run_artifact(self):
        gh = FakeGh()
        gh.artifact_name = "KswordUserMode-diagnostic-Release"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.publish(gh, root)
            notes = (root / "CI_ERRORS.md").read_text(encoding="utf-8")
            self.assertIn("CI FAILED", notes)
            self.assertIn("模块可能不完整", notes)
            self.assertIn("该模块构建或检查失败", notes)
            self.assertTrue((root / f"{gh.artifact_name}.zip").is_file())
            create = next(c for c in gh.calls if c[:2] == ("release", "create"))
            self.assertIn(str(root / f"{gh.artifact_name}.zip"), create)

    def test_driver_missing_and_timeout_do_not_block_diagnostic_release(self):
        for kind in ("missing", "timeout", "wrong-sha"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                gh = FakeGh()
                gh.driver_api_error = kind == "missing"
                gh.driver_status = "in_progress" if kind == "timeout" else "completed"
                gh.driver_sha = "b" * 40 if kind == "wrong-sha" else SHA
                root = Path(directory)
                self.publish(gh, root)
                self.assertIn("Driver CI", (root / "CI_ERRORS.md").read_text(encoding="utf-8"))
                self.assertTrue(any(c[:2] == ("release", "create") for c in gh.calls))

    def test_unavailable_job_logs_still_preserve_failure_status(self):
        gh = FakeGh()
        gh.job_api_error = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.publish(gh, root)
            notes = (root / "CI_ERRORS.md").read_text(encoding="utf-8")
            self.assertIn("状态查询失败", notes)
            self.assertIn("usermode-release | failure", notes)

    def test_corrupt_or_unavailable_downloads_still_publish_diagnostics(self):
        for kind in ("corrupt", "unavailable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                gh = FakeGh()
                gh.corrupt_artifact = kind == "corrupt"
                gh.artifact_error = kind == "unavailable"
                root = Path(directory)
                self.publish(gh, root)
                self.assertFalse((root / f"{MODULE}.zip").exists())
                self.assertIn("下载失败", (root / "CI_ERRORS.md").read_text(encoding="utf-8"))
                self.assertTrue(any(c[:2] == ("release", "create") for c in gh.calls))

    def test_foreign_artifact_is_never_downloaded_or_published(self):
        for kind in ("sha", "run"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                gh = FakeGh()
                gh.artifact_sha = "b" * 40 if kind == "sha" else SHA
                gh.artifact_run = 99 if kind == "run" else 10
                root = Path(directory)
                self.publish(gh, root)
                self.assertFalse((root / f"{MODULE}.zip").exists())
                self.assertFalse(any("artifacts/300/zip" in d for d in gh.downloads))

    def test_packaging_failure_is_in_release_body_and_diagnostic_archive(self):
        gh = FakeGh()
        gh.job_failure = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "publish.log"
            log.write_text("Required automatic release artifact is unavailable: Setup\n", encoding="utf-8")
            self.publish(gh, root, {}, publication_log=log)
            self.assertIn("Required automatic release artifact", (root / "CI_ERRORS.md").read_text(encoding="utf-8"))
            with zipfile.ZipFile(root / f"KswordCI-Diagnostics-{SHA[:8]}.zip") as archive:
                self.assertIn("release-publication.log", archive.namelist())

    def test_retention_and_retry_never_mutate_manual_releases(self):
        gh = FakeGh()
        tag = f"ci-build-{SHA[:8]}-10-2"
        def automatic(index):
            return {"tag_name": tag if index == 5 else f"ci-build-old-{index}", "name": "[CI Build] fixture",
                    "created_at": f"2026-10-0{index}", "prerelease": True, "draft": False,
                    "target_commitish": SHA, "html_url": "https://github.com/existing"}
        gh.releases = [automatic(i) for i in range(1, 6)] + [
            {"tag_name": "manual", "name": "Manual", "created_at": "2026-10-09", "prerelease": True},
            {"tag_name": "ci-build-manual", "name": "Manual", "prerelease": True},
            {"tag_name": "regular", "name": "[CI Build] regular", "prerelease": False}]
        with tempfile.TemporaryDirectory() as directory:
            self.publish(gh, Path(directory))
        self.assertTrue(any(c[:2] == ("release", "edit") for c in gh.calls))
        self.assertTrue(any(c[:2] == ("release", "upload") for c in gh.calls))
        self.assertFalse(any(c[:2] == ("release", "create") for c in gh.calls))
        deleted = [c[2] for c in gh.calls if c[:2] == ("release", "delete")]
        self.assertEqual(deleted, ["ci-build-old-2", "ci-build-old-1"])

    def test_unrelated_existing_release_blocks_update(self):
        gh = FakeGh()
        gh.releases = [{"tag_name": f"ci-build-{SHA[:8]}-10-2", "name": "Manual", "prerelease": True}]
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(RuntimeError):
            self.publish(gh, Path(directory))
        self.assertFalse(gh.calls)

    def test_interrupted_upload_draft_is_published_after_retry_upload(self):
        gh = FakeGh()
        gh.releases = [{"tag_name": f"ci-build-{SHA[:8]}-10-2", "name": "[CI Build] fixture",
                        "prerelease": True, "draft": True, "target_commitish": SHA,
                        "html_url": "https://github.com/existing-draft"}]
        with tempfile.TemporaryDirectory() as directory:
            self.publish(gh, Path(directory))
        upload_index = next(i for i, c in enumerate(gh.calls) if c[:2] == ("release", "upload"))
        edit_index = next(i for i, c in enumerate(gh.calls) if c[:2] == ("release", "edit"))
        self.assertLess(upload_index, edit_index)
        self.assertIn("--draft=false", gh.calls[edit_index])
        self.assertIn("--latest=false", gh.calls[edit_index])
        self.assertFalse(any(c[:2] == ("release", "delete") for c in gh.calls))

    def test_error_excerpt_bounds_and_escapes_fences(self):
        text = "\n".join("error C4996: ```" + "a" * 2000 for _ in range(30))
        excerpt = release.error_excerpt(text)
        self.assertLessEqual(len(excerpt), 6000)
        self.assertNotIn("```", excerpt)

    def test_diagnostic_api_reads_retry_without_retrying_release_writes(self):
        gh = release.Gh()
        with patch.object(gh, "call", side_effect=[RuntimeError("HTTP 502"), b'{"status":"ok"}']) as call, \
             patch.object(release.time, "sleep") as sleep:
            self.assertEqual(gh.json("repos/test/repo"), {"status": "ok"})
        self.assertEqual(call.call_count, 2)
        self.assertEqual(call.call_args.args[:3], ("api", "--method", "GET"))
        sleep.assert_called_once_with(5)

        with patch("ci_failure_release.subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = b"HTTP 403"
            with self.assertRaises(RuntimeError):
                gh.call("release", "create", "tag")
            self.assertEqual(run.call_count, 1)

    def test_workflow_routes_failures_without_weakening_build_gates(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        publication = workflow.split("  auto-prerelease:", 1)[1]
        condition = publication.split("    if: >-", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("always()", condition)
        self.assertIn("github.event_name == 'push'", condition)
        self.assertIn("github.ref == 'refs/heads/main'", condition)
        self.assertNotIn("needs.", condition)
        self.assertIn("CI_JOB_RESULTS: ${{ toJSON(needs) }}", publication)
        self.assertIn("publish_status=${PIPESTATUS[0]}", publication)
        self.assertIn("--publication-error-log", publication)
        self.assertIn('exit "$publish_status"', publication)
        self.assertIn('if [[ -f "$RUNNER_TEMP/ksword-ci-build-failure" ]]', publication)
        self.assertNotIn("continue-on-error:", workflow)
        self.assertIn("!cancelled() && needs.changes.outputs.usermode == 'true'", workflow)
        self.assertIn("!cancelled() && needs.changes.outputs.x96dbg == 'true'", workflow)
        for job in ("usermode-release", "ksword-x96dbg"):
            header = workflow.split(f"  {job}:\n", 1)[1].split("    runs-on:", 1)[0]
            self.assertNotIn("needs.source-integrity.result == 'success'", header)

    def test_publication_shell_keeps_build_failure_red_without_republishing(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        section = workflow.split("      - name: Publish prerelease and retain the latest three\n", 1)[1]
        production = textwrap.dedent(section.split("        run: |\n", 1)[1])
        script = (root / ".github/workflows/scripts/publish-ci-prerelease.sh").read_text(encoding="utf-8")
        failure_branch = script.split('if [[ "$ci_failed" ==', 1)[1].split("\nfi", 1)[0]
        self.assertIn('"$RUNNER_TEMP/ksword-ci-build-failure"', failure_branch)
        mock = r'''
bash() {
  case "$KSWORD_TEST_PUBLICATION" in
    diagnostic) : > "$RUNNER_TEMP/ksword-ci-build-failure"; echo PUBLISHED_DIAGNOSTICS ;;
    error) echo PUBLICATION_ERROR; return 1 ;;
    normal) echo PUBLISHED_NORMAL ;;
  esac
}
python3() { echo PUBLICATION_ERROR_FALLBACK; }
'''
        for kind, expected_status in (("diagnostic", 1), ("error", 1), ("normal", 0)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                env = os.environ.copy()
                env["RUNNER_TEMP"] = Path(directory).as_posix()
                env["KSWORD_TEST_PUBLICATION"] = kind
                result = subprocess.run([bash_path(), "--noprofile", "--norc", "-c", mock + production],
                                        env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                if kind == "error":
                    self.assertIn("PUBLICATION_ERROR_FALLBACK", result.stdout)
                else:
                    self.assertNotIn("PUBLICATION_ERROR_FALLBACK", result.stdout)

    def test_failure_does_not_skip_artifact_uploads(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        driver = (root / ".github/workflows/driver-ci.yml").read_text(encoding="utf-8")
        for name, step_id in (
            ("Upload user-mode artifacts", "usermode_build"),
            ("Upload KswordSetup artifacts", "setup_build"),
            ("Upload KswordARKLight artifacts", "arklight_build"),
            ("Upload KswordCheatEnginePlugin artifacts", "ce_plugin_build"),
            ("Upload KswordCheatEngineLauncher artifacts", "ce_launcher_build"),
            ("Upload TitanEngine and x96dbg artifacts", "x96dbg_build"),
        ):
            with self.subTest(name=name):
                block = workflow.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
                self.assertIn(f"!cancelled() && steps.{step_id}.outcome != 'skipped'", block)
                self.assertIn("actions/upload-artifact@", block)
                self.assertIn("job.status == 'success'", block)
                self.assertIn("diagnostic-Release", block)
        driver_upload = driver.split("      - name: Upload driver artifacts\n", 1)[1]
        self.assertIn("!cancelled() && steps.driver_build.outcome != 'skipped'", driver_upload)
        self.assertIn("job.status == 'success'", driver_upload)
        self.assertIn("KswordARKDriver-diagnostic-Release", driver_upload)

        publication = (root / ".github/workflows/scripts/publish-ci-prerelease.sh").read_text(encoding="utf-8")
        expected = publication.split("readonly -a expected_artifacts=(", 1)[1].split(")", 1)[0]
        self.assertNotIn("diagnostic-Release", expected)

    def test_usermode_checks_cannot_suppress_the_product_build(self):
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        usermode = workflow.split("  usermode-release:", 1)[1].split("  ksword-setup:", 1)[0]
        for name in ("Check native NTFS indexing on an isolated scratch volume",
                     "Check shared UI defaults and first-paint behavior", "Build supported user-mode Release targets"):
            with self.subTest(name=name):
                block = usermode.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
                self.assertIn("!cancelled() && steps.qt_install.outcome == 'success'", block)
                self.assertIn("steps.qt_msbuild.outcome == 'success'", block)
        self.assertIn("$buildFailures +=", usermode)
        self.assertIn("if ($buildFailures.Count -gt 0)", usermode)


if __name__ == "__main__":
    unittest.main()
