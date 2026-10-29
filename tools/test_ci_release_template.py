"""离线执行生产模板选择函数；不下载资产、不修改发行版、不运行程序。"""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from test_ci_driver_package import bash_path


SCRIPT = Path(__file__).resolve().parent.parent / ".github/workflows/scripts/publish-ci-prerelease.sh"


def production_selector():
    """抽取生产函数原文，避免测试另写一套筛选逻辑。"""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    start = source.index("# BEGIN manual template selector:")
    end = source.index("# END manual template selector.", start)
    return source[start:end]


class ArtifactSourceVerdictTests(unittest.TestCase):
    def test_failed_source_run_is_uploaded_but_cannot_be_reused_as_verified(self):
        source = SCRIPT.read_text(encoding="utf-8-sig")
        start = source.index("# BEGIN artifact source verdict:")
        end = source.index("# END artifact source verdict.", start)
        function = source[start:end]
        for state, expected in (("completed\tsuccess", 0), ("completed\tfailure", 1),
                                ("in_progress\tnone", 1), ("completed\tcancelled", 1)):
            with self.subTest(state=state):
                env = os.environ.copy()
                env.update({"GITHUB_REPOSITORY": "test/repo", "KSWORD_TEST_SOURCE_STATE": state})
                mock = 'gh_api_read_with_retry() { printf "%s" "$KSWORD_TEST_SOURCE_STATE"; }\n'
                result = subprocess.run([bash_path(), "--noprofile", "--norc", "-c",
                                         "set -euo pipefail\n" + mock + function
                                         + "\nartifact_run_completed_successfully 123\n"],
                                        env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


def production_retry():
    """Run the same retry helper that the publication script uses."""
    source = SCRIPT.read_text(encoding="utf-8-sig")
    start = source.index("# BEGIN GitHub API read retry:")
    end = source.index("# END GitHub API read retry.", start)
    return source[start:end]


MOCK_API = r'''
mock_calls=0
gh() {
    if [[ "$1" != api || "$2" != --method || "$3" != GET ]]; then
        echo "expected an explicit read-only gh api GET" >&2
        return 9
    fi
    if [[ "${KSWORD_TEST_REQUIRE_PAGINATION:-0}" == 1 ]]; then
        if [[ "$4" != --paginate || "$5" != /repos/test/repo || "$6" != --jq || "$7" != '.items[] | .name' ]]; then
            echo "API arguments were not preserved" >&2
            return 9
        fi
    fi
    (( mock_calls += 1 ))
    if (( mock_calls <= KSWORD_TEST_FAILURES )); then
        printf 'partial page from attempt %s\n' "$mock_calls"
        echo 'gh: Server Error (HTTP 502)' >&2
        return 22
    fi
    printf '456\tcompleted\t%s\n' "$KSWORD_TEST_CONCLUSION"
}
sleep() { printf 'mock sleep %s\n' "$1" >&2; }
'''


class ApiReadRetryTests(unittest.TestCase):
    def execute(self, command, failures=0, conclusion="success", pagination=False, ci_failed=False):
        environment = os.environ.copy()
        environment.update({
            "KSWORD_TEST_FAILURES": str(failures),
            "KSWORD_TEST_CONCLUSION": conclusion,
            "KSWORD_TEST_CI_FAILED": "True" if ci_failed else "False",
            "KSWORD_TEST_REQUIRE_PAGINATION": "1" if pagination else "0",
            "GH_TOKEN": "fixture",
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "10",
            "GITHUB_REF_NAME": "main",
        })
        with tempfile.TemporaryDirectory() as directory:
            environment["RUNNER_TEMP"] = Path(directory).as_posix()
            result = subprocess.run(
                [bash_path(), "--noprofile", "--norc", "-c", "set -euo pipefail\n" + MOCK_API + command],
                env=environment, capture_output=True, text=True, timeout=30,
            )
            result.failure_marker = (Path(directory) / "ksword-ci-build-failure").is_file()
            return result

    def test_retries_502_and_discards_partial_paginated_responses(self):
        command = (
            "readonly api_read_attempt_limit=4\n" + production_retry()
            + "\ngh_api_read_with_retry 'mock pagination' --paginate /repos/test/repo --jq '.items[] | .name'\n"
        )
        result = self.execute(command, failures=2, pagination=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "456\tcompleted\tsuccess\n")
        self.assertEqual(result.stderr.count("HTTP 502"), 2)
        self.assertIn("mock sleep 5", result.stderr)
        self.assertIn("mock sleep 10", result.stderr)
        self.assertNotIn("partial page", result.stdout)

    def test_exhausted_retries_fail_with_context_and_no_partial_output(self):
        command = (
            "readonly api_read_attempt_limit=4\n" + production_retry()
            + "\ngh_api_read_with_retry 'Driver CI for fixture' /repos/test/repo\n"
        )
        result = self.execute(command, failures=4)
        self.assertEqual(result.returncode, 22)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.count("HTTP 502"), 4)
        self.assertIn("Unable to query Driver CI for fixture after 4 attempts", result.stderr)
        self.assertIn("mock sleep 20", result.stderr)

    def test_driver_query_recovers_without_weakening_failure_gate(self):
        # Exercise the production driver poll and the real failure-routing branch.
        prefix = SCRIPT.read_text(encoding="utf-8-sig").split("artifact_download_root=", 1)[0]
        python_mock = r'''
python3() {
    if [[ "$1" == -c ]]; then
        echo "$KSWORD_TEST_CI_FAILED"
    elif [[ "$1" == tools/ci_failure_release.py && "$2" == --driver-run-id && "$3" == 456 ]]; then
        echo DIAGNOSTIC_RELEASE
    else
        echo "unexpected python invocation" >&2
        return 9
    fi
}
'''
        for conclusion, ci_failed in (("success", False), ("failure", False), ("success", True)):
            with self.subTest(conclusion=conclusion, ci_failed=ci_failed):
                result = self.execute(python_mock + prefix + "\necho CONTINUE_PACKAGING\n",
                                      failures=1, conclusion=conclusion, ci_failed=ci_failed)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("HTTP 502", result.stderr)
                self.assertIn(f"id=456 status=completed conclusion={conclusion}", result.stdout)
                self.assertNotIn("partial page", result.stdout)
                if conclusion == "success" and not ci_failed:
                    self.assertIn("CONTINUE_PACKAGING", result.stdout)
                    self.assertNotIn("DIAGNOSTIC_RELEASE", result.stdout)
                    self.assertFalse(result.failure_marker)
                else:
                    self.assertIn("DIAGNOSTIC_RELEASE", result.stdout)
                    self.assertNotIn("CONTINUE_PACKAGING", result.stdout)
                    self.assertTrue(result.failure_marker)

    def test_unavailable_driver_query_stops_before_packaging(self):
        prefix = SCRIPT.read_text(encoding="utf-8-sig").split("artifact_download_root=", 1)[0]
        result = self.execute(prefix + "\necho CONTINUE_PACKAGING\n", failures=4)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to query Driver CI", result.stderr)
        self.assertNotIn("CONTINUE_PACKAGING", result.stdout)


class ReleaseTemplateTests(unittest.TestCase):
    def select(self, records):
        """只把候选数据送入 stdin；Bash 代码来自生产文件，不拼接资产名称。"""
        command = production_selector() + "\nselect_manual_release_template_record\n"
        completed = subprocess.run(
            [bash_path(), "-c", "set -euo pipefail\n" + command],
            input="\n".join(records) + "\n", encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        return completed.stdout.strip()

    def test_newer_pdb_asset_does_not_replace_full_package(self):
        """实际故障：同一手工发行的 PDB asset id 比完整包大。"""
        full = "2026-10-13T02:11:57Z\tmcp-preview-20261012\t635598205\tKswordARK-MCP-Preview-261012.7z"
        pdb = "2026-10-13T02:11:57Z\tmcp-preview-20261012\t635598210\tKswordARK-MCP-Preview-261012-PDB.7z"
        self.assertEqual(self.select([full, pdb]), full)

    def test_symbols_only_returns_no_template(self):
        """符号包不能充当运行时模板，名称判断须大小写无关。"""
        records = [
            "2026-10-13T00:00:00Z\tpreview\t9\tKSword.PdB.7z",
            "2026-10-13T00:00:00Z\tpreview\t8\tKSword-SYMBOLS.7z",
        ]
        self.assertEqual(self.select(records), "")

    def test_newest_full_package_preserves_record(self):
        """跳过最新符号附件后，完整保留最新完整包的时间/tag/id/中文名称。"""
        newest = "2026-10-12T00:00:00Z\tpreview\t8\tKsword评估版本.7z"
        older = "2026-10-11T00:00:00Z\tstable\t7\tKsword.7z"
        symbol = "2026-10-13T00:00:00Z\tdebug\t9\tKsword-symbol.7z"
        self.assertEqual(self.select([older, newest, symbol]), newest)

    def test_pdb_feature_in_full_package_name_is_retained(self):
        """完整包的功能描述含 PDB 时仍可选，只有符号附件后缀被排除。"""
        full = "2026-10-13T00:00:00Z\tpreview\t10\tKsword-PDB-增强.7z"
        self.assertEqual(self.select([full]), full)

    def test_large_candidate_list_is_consumed_without_pipe_failure(self):
        """提前停止读取会使 pipefail 下的 sort 被 SIGPIPE 中断。"""
        full = "2026-10-13T00:00:00Z\tpreview\t9\tKsword.7z"
        records = [full] + [f"2026-10-12T00:00:00Z\told\t{number}\tKsword-PDB.7z" for number in range(5000)]
        self.assertEqual(self.select(records), full)


if __name__ == "__main__":
    unittest.main()
