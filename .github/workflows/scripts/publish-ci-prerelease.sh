#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

readonly automatic_tag_prefix='ci-build-'
readonly retained_release_count=3
readonly driver_wait_timeout_seconds=3000
readonly warning_text='使用未经完全测试的版本可能导致：程序崩溃，系统死锁，系统崩溃，文件丢失，硬件损坏等严重后果。'

readonly -a expected_artifacts=(
  'KswordUserMode-unsigned-Release'
  'KswordSetup-unsigned-Release'
  'KswordARKLight-unsigned-Release'
  'KswordCheatEnginePlugin-x64-Release'
  'KswordCheatEnginePlugin-Win32-Release'
  'KswordCheatEngineLauncher-Release'
  'KswordARKDriver-unsigned-Release'
)

# Wait for the independently triggered driver workflow for this exact push.
# A user-mode CI success must not publish an automatic release while the R0
# build is still running or after it has failed.
driver_run_id=''
driver_deadline=$((SECONDS + driver_wait_timeout_seconds))
while (( SECONDS < driver_deadline )); do
  driver_run="$({
    gh api --method GET \
      -H 'Accept: application/vnd.github+json' \
      "/repos/$GITHUB_REPOSITORY/actions/workflows/driver-ci.yml/runs" \
      -f branch="$GITHUB_REF_NAME" \
      -f event=push \
      -f per_page=100 \
      --jq "[.workflow_runs[] | select(.head_sha == \"$GITHUB_SHA\")][0] // {} | [(.id // 0), (.status // \"missing\"), (.conclusion // \"none\")] | @tsv"
  } 2>&1)" || {
    echo "Unable to query Driver CI for $GITHUB_SHA: $driver_run" >&2
    exit 1
  }

  IFS=$'\t' read -r driver_run_id driver_status driver_conclusion <<< "$driver_run"
  echo "Driver CI for $GITHUB_SHA: id=$driver_run_id status=$driver_status conclusion=$driver_conclusion"

  if [[ "$driver_status" == 'completed' ]]; then
    if [[ "$driver_conclusion" != 'success' ]]; then
      echo "Driver CI did not succeed; automatic release is blocked." >&2
      exit 1
    fi
    break
  fi

  sleep 15
done

if [[ -z "$driver_run_id" || "$driver_run_id" == '0' || "$driver_status" != 'completed' ]]; then
  echo "Timed out waiting for Driver CI to complete for $GITHUB_SHA." >&2
  exit 1
fi

artifact_download_root="$RUNNER_TEMP/ksword-ci-artifacts"
release_stage_root="$RUNNER_TEMP/ksword-ci-release-stage"
release_output_root="$RUNNER_TEMP/ksword-ci-release-output"
release_notes="$RUNNER_TEMP/ksword-ci-release-notes.md"
short_sha="${GITHUB_SHA:0:8}"
mkdir -p "$artifact_download_root" "$release_stage_root" "$release_output_root"

declare -A artifact_directories=()
declare -A artifact_run_ids=()
declare -A artifact_source_shas=()
declare -A artifact_created_times=()
declare -a module_archives=()

# Range-based CI may skip unchanged projects. For each named component, select
# the current run's artifact when that project was affected. Only unchanged,
# skipped projects may reuse a non-expired artifact whose source commit is the
# release commit itself or one of its ancestors.
for artifact_name in "${expected_artifacts[@]}"; do
  preferred_run_id="$GITHUB_RUN_ID"
  require_preferred_artifact='false'
  case "$artifact_name" in
    'KswordUserMode-unsigned-Release')
      require_preferred_artifact="${CURRENT_USERMODE_REQUIRED:-false}"
      ;;
    'KswordSetup-unsigned-Release')
      require_preferred_artifact="${CURRENT_SETUP_REQUIRED:-false}"
      ;;
    'KswordARKLight-unsigned-Release')
      require_preferred_artifact="${CURRENT_ARKLIGHT_REQUIRED:-false}"
      ;;
    'KswordCheatEnginePlugin-x64-Release'|'KswordCheatEnginePlugin-Win32-Release')
      require_preferred_artifact="${CURRENT_CE_PLUGIN_REQUIRED:-false}"
      ;;
    'KswordCheatEngineLauncher-Release')
      require_preferred_artifact="${CURRENT_CE_LAUNCHER_REQUIRED:-false}"
      ;;
    'KswordARKDriver-unsigned-Release')
      preferred_run_id="$driver_run_id"
      ;;
  esac

  artifact_record="$({
    gh api --method GET \
      -H 'Accept: application/vnd.github+json' \
      "/repos/$GITHUB_REPOSITORY/actions/runs/$preferred_run_id/artifacts" \
      -f per_page=100 \
      --jq "[.artifacts[] | select(.expired == false and .name == \"$artifact_name\")][0] // {} | [(.id // 0), (.workflow_run.id // 0), (.workflow_run.head_sha // \"missing\"), (.created_at // \"missing\")] | @tsv"
  } 2>&1)" || {
    echo "Unable to query run $preferred_run_id for artifact $artifact_name: $artifact_record" >&2
    exit 1
  }

  IFS=$'\t' read -r artifact_id artifact_run_id artifact_sha artifact_created_at <<< "$artifact_record"
  if [[ -z "$artifact_id" || "$artifact_id" == '0' ]]; then
    if [[ "$require_preferred_artifact" == 'true' ]]; then
      echo "Current affected project did not upload its required artifact: $artifact_name" >&2
      exit 1
    fi

    artifact_candidates="$({
      gh api --method GET \
        -H 'Accept: application/vnd.github+json' \
        "/repos/$GITHUB_REPOSITORY/actions/artifacts" \
        -f name="$artifact_name" \
        -f per_page=100 \
        --jq ".artifacts[] | select(.expired == false and .workflow_run.head_branch == \"$GITHUB_REF_NAME\") | [.id, .workflow_run.id, .workflow_run.head_sha, .created_at] | @tsv"
    } 2>&1)" || {
      echo "Unable to query artifact $artifact_name: $artifact_candidates" >&2
      exit 1
    }

    artifact_id=0
    while IFS=$'\t' read -r candidate_id candidate_run_id candidate_sha candidate_created_at; do
      [[ -n "$candidate_id" && -n "$candidate_sha" ]] || continue
      comparison_status="$({
        gh api \
          -H 'Accept: application/vnd.github+json' \
          "/repos/$GITHUB_REPOSITORY/compare/$candidate_sha...$GITHUB_SHA" \
          --jq '.status'
      } 2>&1)" || {
        echo "Unable to compare artifact commit $candidate_sha with $GITHUB_SHA: $comparison_status" >&2
        exit 1
      }

      if [[ "$comparison_status" == 'identical' || "$comparison_status" == 'ahead' ]]; then
        artifact_id="$candidate_id"
        artifact_run_id="$candidate_run_id"
        artifact_sha="$candidate_sha"
        artifact_created_at="$candidate_created_at"
        break
      fi
      echo "Ignoring $artifact_name from non-ancestor commit $candidate_sha ($comparison_status)."
    done <<< "$artifact_candidates"
  fi
  if [[ -z "$artifact_id" || "$artifact_id" == '0' ]]; then
    echo "Required automatic release artifact is unavailable: $artifact_name" >&2
    exit 1
  fi

  artifact_archive="$artifact_download_root/$artifact_name.zip"
  gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" \
    > "$artifact_archive"
  if [[ ! -s "$artifact_archive" ]]; then
    echo "Downloaded artifact is empty: $artifact_name" >&2
    exit 1
  fi

  artifact_directory="$artifact_download_root/$artifact_name"
  mkdir -p "$artifact_directory"
  python3 -m zipfile -e "$artifact_archive" "$artifact_directory"
  artifact_directories["$artifact_name"]="$artifact_directory"
  artifact_run_ids["$artifact_name"]="$artifact_run_id"
  artifact_source_shas["$artifact_name"]="$artifact_sha"
  artifact_created_times["$artifact_name"]="$artifact_created_at"
  module_archives+=("$artifact_archive")
done

# Use the newest non-automatic manual 7z release as the dependency/profile
# template. CI then overlays every current core binary and unsigned driver while
# preserving the same single Release/ directory layout users already receive.
manual_release_candidates="$({
  gh api --paginate \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq '.[] | select(.draft == false and ((.tag_name | startswith("ci-build-")) | not) and (((.name // "") | startswith("[CI Build] ")) | not)) as $release | $release.assets[] | select(.name | endswith(".7z")) | [$release.published_at, $release.tag_name, .id, .name] | @tsv'
} 2>&1)" || {
  echo "Unable to query the manual release template: $manual_release_candidates" >&2
  exit 1
}
manual_release_record="$(printf '%s\n' "$manual_release_candidates" | sort -r | sed -n '1p')"
IFS=$'\t' read -r manual_published_at manual_tag manual_asset_id manual_asset_name <<< "$manual_release_record"
if [[ -z "$manual_asset_id" || -z "$manual_asset_name" ]]; then
  echo 'No non-automatic manual .7z release is available as a packaging template.' >&2
  exit 1
fi

manual_archive="$RUNNER_TEMP/manual-release-template.7z"
gh api \
  -H 'Accept: application/octet-stream' \
  "/repos/$GITHUB_REPOSITORY/releases/assets/$manual_asset_id" \
  > "$manual_archive"
if [[ ! -s "$manual_archive" ]]; then
  echo "Downloaded manual release template is empty: $manual_asset_name" >&2
  exit 1
fi

seven_zip="$(command -v 7z || command -v 7zz || true)"
if [[ -z "$seven_zip" ]]; then
  sudo apt-get update
  sudo apt-get install -y p7zip-full || sudo apt-get install -y 7zip
  seven_zip="$(command -v 7z || command -v 7zz || true)"
fi
if [[ -z "$seven_zip" ]]; then
  echo '7-Zip is unavailable on the runner.' >&2
  exit 1
fi

"$seven_zip" x -y "-o$release_stage_root" "$manual_archive"
release_root="$release_stage_root/Release"
if [[ ! -d "$release_root" ]]; then
  echo "Manual release template does not contain the required Release/ root: $manual_asset_name" >&2
  exit 1
fi
if [[ -n "$(find "$release_root" -type l -print -quit)" ]]; then
  echo "Manual release template contains a symbolic link and cannot be overlaid safely: $manual_asset_name" >&2
  exit 1
fi
if [[ -n "$(find "$artifact_download_root" -type l -print -quit)" ]]; then
  echo 'A downloaded module artifact contains a symbolic link and cannot be overlaid safely.' >&2
  exit 1
fi

usermode_main="$(find "${artifact_directories[KswordUserMode-unsigned-Release]}" -type f -name 'Ksword5.1.exe' -print -quit)"
if [[ -z "$usermode_main" ]]; then
  echo 'User-mode artifact does not contain Ksword5.1.exe.' >&2
  exit 1
fi
usermode_root="$(dirname "$usermode_main")"
cp -a "$usermode_root/." "$release_root/"

arklight_exe="$(find "${artifact_directories[KswordARKLight-unsigned-Release]}" -type f -name 'KswordARKLight.exe' -print -quit)"
if [[ -z "$arklight_exe" ]]; then
  echo 'ARKLight artifact does not contain KswordARKLight.exe.' >&2
  exit 1
fi
cp -f "$arklight_exe" "$release_root/KswordARKLight.exe"

declare -a driver_release_roots=()
while IFS= read -r -d '' driver_root_sys; do
  driver_release_root="$(dirname "$driver_root_sys")"
  if [[ -f "$driver_release_root/KswordARKDriver.inf" ]]; then
    driver_release_roots+=("$driver_release_root")
  fi
done < <(find "${artifact_directories[KswordARKDriver-unsigned-Release]}" -type f -name 'KswordARK.sys' -print0)
if (( ${#driver_release_roots[@]} != 1 )); then
  echo "Driver artifact must contain exactly one KswordARK.sys/KswordARKDriver.inf pair; found ${#driver_release_roots[@]}." >&2
  exit 1
fi
driver_release_root="${driver_release_roots[0]}"
for driver_file in KswordARK.sys KswordARKDriver.inf; do
  if [[ ! -f "$driver_release_root/$driver_file" ]]; then
    echo "Driver artifact is missing $driver_file." >&2
    exit 1
  fi
done
cp -f "$driver_release_root/KswordARK.sys" "$release_root/KswordARK.sys"
cp -f "$driver_release_root/KswordARKDriver.inf" "$release_root/KswordARKDriver.inf"
mkdir -p "$release_root/KswordARKDriver"
cp -f "$driver_release_root/KswordARK.sys" "$release_root/KswordARKDriver/KswordARK.sys"
cp -f "$driver_release_root/KswordARKDriver.inf" "$release_root/KswordARKDriver/KswordARKDriver.inf"

# Module ZIPs retain PDBs for debugging, while the manual-style aggregate is a
# runtime package. Remove symbols only from the validated temporary Release/.
while IFS= read -r -d '' symbol_file; do
  rm -f "$symbol_file"
done < <(find "$release_root" -type f -iname '*.pdb' -print0)

# The automatic driver is unsigned, so a catalog inherited from the signed
# manual template would be stale and misleading. Remove only those exact files.
rm -f \
  "$release_root/KswordARKDriver/kswordarkdriver.cat" \
  "$release_root/KswordARKDriver/KswordARKDriver.cat"

# Current runtime accepts the v4 profile pack only. Keep the reviewed v4 pack
# and related assets from the manual template, but do not carry legacy packs.
for legacy_version in 1 2 3; do
  rm -f \
    "$release_root/profiles/ark_dyndata_pack_v${legacy_version}.json" \
    "$release_root/profiles/ark_dyndata_pack_v${legacy_version}.json.qz"
done

provenance_file="$release_root/CI_ARTIFACT_PROVENANCE.md"
{
  echo '# Automatic CI release artifact provenance'
  echo
  echo "Release commit: \`$GITHUB_SHA\`"
  echo "Manual template: \`$manual_tag\` / \`$manual_asset_name\` / $manual_published_at"
  echo
  echo '| Artifact | Source commit | Actions run | Created at |'
  echo '| --- | --- | ---: | --- |'
  for artifact_name in "${expected_artifacts[@]}"; do
    printf '| `%s` | `%s` | `%s` | %s |\n' \
      "$artifact_name" \
      "${artifact_source_shas[$artifact_name]}" \
      "${artifact_run_ids[$artifact_name]}" \
      "${artifact_created_times[$artifact_name]}"
  done
} > "$provenance_file"

readonly -a required_release_paths=(
  'Ksword5.1.exe'
  'Launcher.exe'
  'Taskbar.exe'
  'KswordHUD.exe'
  'KswordCLI.exe'
  'APIMonitor_x64.dll'
  'KswordARKLight.exe'
  'KswordARK.sys'
  'KswordARKDriver.inf'
  'KswordARKDriver/KswordARK.sys'
  'KswordARKDriver/KswordARKDriver.inf'
  'LICENSE'
  'COMMUNITY_COVENANT.md'
  'languages/zh-CN.json'
  'languages/en-US.json'
  'platforms/qwindows.dll'
  'profiles/ark_dyndata_pack_v4.json.qz'
  'profiles/launcher_support_manifest.json'
)
for required_path in "${required_release_paths[@]}"; do
  if [[ ! -f "$release_root/$required_path" ]]; then
    echo "Aggregated Release/ package is missing $required_path." >&2
    exit 1
  fi
done

aggregate_archive="$release_output_root/KswordARK-CI-$short_sha.7z"
(
  cd "$release_stage_root"
  "$seven_zip" a -t7z -mx=9 -mmt=on "$aggregate_archive" Release
)
"$seven_zip" t "$aggregate_archive"
if [[ ! -s "$aggregate_archive" ]]; then
  echo 'Aggregated automatic release archive is empty.' >&2
  exit 1
fi

push_text="$({
  gh api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA" \
    --jq '.commit.message | split("\n")[0]'
} 2>&1)" || {
  echo "Unable to read commit text for $GITHUB_SHA: $push_text" >&2
  exit 1
}
if [[ -z "$push_text" ]]; then
  push_text='(no commit text)'
fi

release_title="[CI Build] $short_sha $push_text"
release_tag="${automatic_tag_prefix}${short_sha}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}"
aggregate_asset_name="$(basename "$aggregate_archive")"
setup_asset_name='KswordSetup-unsigned-Release.zip'
aggregate_download_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$release_tag/$aggregate_asset_name"
setup_download_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$release_tag/$setup_asset_name"
aggregate_badge_url='https://img.shields.io/badge/Download-Full%207z-2ea44f?style=for-the-badge&logo=github'
setup_badge_url='https://img.shields.io/badge/Download-Setup%20ZIP-0969da?style=for-the-badge&logo=github'

{
  echo '> [!CAUTION]'
  echo "> $warning_text"
  echo
  echo '> [!IMPORTANT]'
  echo '> 此预发行版由 GitHub Actions 自动生成，其中包含未经签名的 CI 构建产物。'
  echo
  echo '## 下载说明'
  echo
  echo '> [!TIP]'
  echo '> 普通使用请下载完整 7z 整包；仅需要安装器时可单独下载 Setup ZIP。'
  echo
  echo "[![下载完整 7z 整包]($aggregate_badge_url)]($aggregate_download_url) [![下载 Setup ZIP]($setup_badge_url)]($setup_download_url)"
  echo
  echo '> [!NOTE]'
  echo "> \`$aggregate_asset_name\` 是以 \`Release/\` 为根目录的完整聚合包，布局与手工发行版一致。"
  echo '> 其余 `.zip` 是主程序、Setup、ARKLight、Cheat Engine 插件/Launcher 和 Driver 模块分别构建的原始 CI 产物。'
  echo
  echo "- 提交：\`$GITHUB_SHA\`"
  echo "- CI：https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  echo "- Driver CI：https://github.com/$GITHUB_REPOSITORY/actions/runs/$driver_run_id"
  echo "- 手工发行模板：\`$manual_tag\` / \`$manual_asset_name\`"
  echo
  echo '> [!IMPORTANT]'
  echo '> 各资产的提交与工作流来源详见压缩包内的 `Release/CI_ARTIFACT_PROVENANCE.md`。'
} > "$release_notes"

release_url="$({
  gh release create "$release_tag" "$aggregate_archive" "${module_archives[@]}" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" \
    --title "$release_title" \
    --notes-file "$release_notes" \
    --prerelease
} 2>&1)" || {
  echo "Unable to create automatic prerelease: $release_url" >&2
  exit 1
}
echo "Created automatic prerelease: $release_url"

# Delete only releases carrying both of our automatic markers. Sort explicitly
# by creation timestamp so exactly the newest three automatic releases remain;
# manual prereleases and all normal releases are outside this cleanup scope.
mapfile -t automatic_releases < <(
  gh api --paginate \
    -H 'Accept: application/vnd.github+json' \
    "/repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq '.[] | select(.draft == false and .prerelease == true and (.tag_name | startswith("ci-build-")) and ((.name // "") | startswith("[CI Build] "))) | [.created_at, .tag_name] | @tsv' \
    | sort -r
)

for stale_release in "${automatic_releases[@]:retained_release_count}"; do
  stale_tag="${stale_release#*$'\t'}"
  echo "Deleting stale automatic prerelease: $stale_tag"
  gh release delete "$stale_tag" \
    --repo "$GITHUB_REPOSITORY" \
    --cleanup-tag \
    --yes
done

{
  echo '### Automatic prerelease'
  echo
  echo "- Release: $release_url"
  echo "- Title: $release_title"
  echo "- Aggregate asset: $(basename "$aggregate_archive")"
  echo "- Module ZIP assets: ${#module_archives[@]}"
  echo "- Retention: newest $retained_release_count automatic prereleases"
} >> "$GITHUB_STEP_SUMMARY"
