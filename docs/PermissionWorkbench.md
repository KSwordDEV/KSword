# Permission workbench

The Permissions tab brings local accounts, group membership, account policy and process tokens into one workspace. Use it to trace permission sources, compare execution identities and investigate access failures. New pages load on demand and perform their Windows queries in background workers.

| Page | Purpose |
| --- | --- |
| Accounts → Account management | Local accounts, enable/disable, memberships and navigation to related pages |
| Accounts → Create and reset | Existing local-user creation and password-reset tools |
| Permissions | Existing overview of accounts, groups and KSword's own token privileges |
| Local groups | Group members, account memberships and member changes |
| Rights assignment | Bidirectional queries and edits of direct local LSA assignments |
| Token comparison | Compare two actual process tokens |
| Access diagnostics | Inspect an object's security descriptor and evaluate requested access |
| Logon sessions | Logon identities and processes associated by logon LUID |
| Launch as identity | Ordinary user, administrator, SYSTEM and TrustedInstaller launch with actual token comparison |
| Permission snapshots | Manual collection, save/load and comparison of permission evidence |

## 1. Account and group management

Refresh local accounts under **Accounts → Account management**. Search account names, SIDs, state or descriptions. Selecting an account shows its direct and indirect local memberships. The group, rights and logon-session navigation buttons pass the selected account's SID to the destination instead of associating identities by display name alone.

Enable/disable previews show the account, SID and before/after state. After confirmation, the worker changes the disabled bit, preserves other account flags and reads the state back. A submitted change with failed or inconsistent readback is reported explicitly. Refresh to inspect the current result. User creation and password reset remain in the nested **Create and reset** page, with their existing elevation and confirmation flow.

On **Local groups**, refresh the groups and select a group to inspect its members. Enumeration follows Windows pagination through the remaining pages. Enter an account name or SID to add a member, or select an existing member to remove it. Confirmation identifies both group and member by SID, followed by application and membership readback.

The lower panel queries an account's local groups. It distinguishes direct membership from membership through a global group. If the direct query is incomplete, the source is marked unknown. Double-click a membership to locate the corresponding group. Account, group and member tables support searching, copying a SID and copying a row.

## 2. Account rights assignment

This page separates account queries on the left from right-to-account lookup on the right and supports three queries against local LSA policy:

- Query an account name/SID to list rights assigned directly to that user, group or service identity.
- Choose **Account → Own and group rights** on the left to collect assignments from the account and resolvable local groups. A right is retained separately for each source SID. View A shows rights, descriptions and sources; view B shows rights, source SIDs and one membership path.
- Select a right to list its directly assigned accounts. Double-click an account to query that SID's rights.

The two account query buttons share one row on the left. Lookup, assign and remove share one row on the right. Each side has its own search and query status. Changing an input clears that side's previous results. Local-group traversal deduplicates recursive relationships; domain groups, dynamic logon groups and failed relationship queries may be incomplete, with scope diagnostics shown on the page.

The catalog includes interactive, network, batch, service and Remote Desktop logon rights, their deny-logon counterparts, and privileges such as debugging, driver loading, backup and restore. Logon rights have descriptions; privilege descriptions come from Windows.

**Assign this right** and **Remove this right** are in the fixed action area below the right selector. The target preview identifies the left-hand account and the right-hand right. Edits affect only that account's direct assignment, never a source group in the aggregate results. Before assigning or removing a right, the page resolves the SID, reads its current direct assignment and presents a concrete preview. Confirmation applies the LSA change and reads policy back. An assignment already matching the requested state needs no change.

Direct policy assignment and actual token privileges are separate evidence. Group inheritance, logon type, deny-logon policy, UAC and restrictions can affect the actual token. Policy edits do not immediately rewrite existing process tokens. Obtain a new logon/token and inspect it in **Token comparison**. An empty direct assignment does not mean the account has no effective rights.

## 3. Token comparison

Choose process A and process B, or enter PIDs, then refresh their tokens. PID and process creation time are checked to avoid associating a reused PID with the old process. Filter text or show differences only.

Fields include user, owner, primary group, group attributes, enabled and deny-only groups, restricted SIDs, privilege attributes and enablement, integrity, elevation type, UIAccess, AppContainer, session ID and logon AuthenticationId. Linked-token fields are displayed when readable.

Read, absent and unreadable evidence remain distinct. Access denial or process exit produces collection diagnostics; an empty result does not establish token equality. Related pages can open process details with identity revalidation.

## 4. Access diagnostics

Select the target process token, object type and target, then choose the requested operation or access mask. File, registry-key and service targets are supported. Registry paths identify the root key; service targets use service names. The page shows the requested and mapped access masks, the descriptor and ACE evidence, with integrity-related restrictions.

| Evidence | Interpretation |
| --- | --- |
| Descriptor check | Evaluates requested access against the obtained descriptor and token, preserving ACE order, attributes and SIDs |
| Integrity hint | Uses object labels, token integrity and mandatory policy to indicate possible upward-access restrictions; unavailable evidence is reported |
| Actual open probe | When enabled on the page, attempts to open an object handle with the requested rights and closes it, reporting the real call result |

A descriptor allowance does not guarantee an operation will succeed. File sharing, path traversal, object state and other Windows checks can affect an actual open. Failure to retrieve a descriptor also does not by itself prove the requested operation is denied. A successful handle probe proves that particular open request succeeded; it does not establish that a later read, write, execution or service operation occurred. Diagnostics do not change ACLs, file contents, registry values or service configuration.

## 5. Logon sessions and related processes

Refresh to view account, SID, logon LUID, logon type, time, authentication package, terminal-session ID and related-process count. Search accounts, SIDs or logon LUIDs.

Select a logon session to filter its processes. Show all related processes restores the overview; the process panel has its own name/PID/error filter. Double-click a process or use its details button to open details after rechecking its identity. Navigation from account management locates the exact account SID and reports when no readable matching session exists.

Association uses the process token's `AuthenticationId` and the LSA logon LUID. The WTS/terminal-session ID is a displayed field: a terminal session can contain different logon identities, so it cannot replace the LUID. Unreadable process tokens, identities absent from the LSA enumeration and exited processes retain explicit error or unmatched states.

## 6. Launch as identity

Choose an existing `.exe`, provide arguments and select ordinary user, administrator, SYSTEM or TrustedInstaller. The working directory is the executable's directory. Availability is checked first; unavailable identities are disabled and can be checked again.

Administrator launch uses Windows UAC. SYSTEM/TrustedInstaller require an elevated KSword, and TrustedInstaller mode may start its service. Confirmation identifies the requested identity, executable and arguments. The executable starts immediately, so the user must interactively confirm the intended program.

After launch, the page reads the actual child PID, account, SID, elevation, integrity and token fields. Requested identity is an input; the child token is the result. A quick exit, unreadable token or failed identity recheck is reported as incomplete verification. Launching an ordinary-user comparison instance runs a second instance and retains both tokens. Refresh checks the original PID and creation time again.

## 7. Permission snapshots

Snapshots are collected manually, without periodic monitoring. They contain account state, group memberships and direct LSA assignments, optionally including a selected PID's token.

1. Choose the token option/PID and capture a baseline.
2. Perform the operation to observe, then capture the current state and compare.
3. Save either JSON snapshot, reload later, filter entries/old/new values and copy the selected difference.

Differences distinguish added, removed, modified, enabled, disabled and uncertain evidence. JSON types are preserved: string `"1"` differs from number `1`. SID-based keys preserve account and membership identity across display-name changes.

Collection errors are stored in the snapshot. Missing evidence from an incomplete collection is uncertain, and unreadable fields are not asserted as permission changes. Both snapshots must identify the same computer and use the same token-collection option. Unsupported versions, duplicate keys, non-scalar values, invalid states and exceeded limits are rejected; JSON import is limited to 64 MiB. Import compares evidence without restoring or applying its permissions.

## Reproducing checks

Run from the repository root. Portable checks require Windows MinGW Qt 6.9.3 and `g++`. Set `$qtDir` to the actual `mingw_64` directory; MSVC Qt is not interchangeable with it. Outputs go to a separate directory.

```powershell
$qtDir = 'C:\path\to\Qt\6.9.3\mingw_64'
$testOutput = '.codex-build-logs\privilege-workbench'
python tools\privilege_workbench_test.py --qt-dir $qtDir --output-dir $testOutput
```

The runner strictly compiles actual pages, collectors, the snapshot model and language/theme code, runs read-only collection, differences and page-lifetime checks, and produces offscreen screenshots. It performs no account/group/policy writes and launches no administrator, SYSTEM or TrustedInstaller test executable.

Compile the account-pagination and SID-navigation fixture separately:

```powershell
New-Item -ItemType Directory -Force -Path $testOutput | Out-Null
$qtIncludeArgs = @()
foreach ($part in @('include', 'include\QtCore', 'include\QtGui', 'include\QtWidgets')) {
    $qtIncludeArgs += @('-isystem', (Join-Path $qtDir $part))
}
$testCompileArgs = @('-std=c++23', '-Wall', '-Wextra', '-Werror', '-Wno-unknown-pragmas', '-DNOMINMAX', '-DUNICODE', '-D_UNICODE') + $qtIncludeArgs
g++ @testCompileArgs tools\privilege_accounts_tests.cpp Ksword5.1\Ksword5.1\Internationalization\LanguageManager.cpp Ksword5.1\Ksword5.1\UI\ThemeStatusRole.cpp -L "$qtDir\lib" -lQt6Widgets -lQt6Gui -lQt6Core -lnetapi32 -ladvapi32 -o "$testOutput\privilege_accounts_tests.exe"
$env:PATH = "$qtDir\bin;$env:PATH"
$env:QT_QPA_PLATFORM = 'offscreen'
$env:QT_PLUGIN_PATH = "$qtDir\plugins"
& "$testOutput\privilege_accounts_tests.exe"
```

The access fixture uses in-memory descriptors and isolated test tokens, without changing actual objects:

```powershell
g++ -std=c++23 -Wall -Wextra -Werror -Wno-unknown-pragmas -DNOMINMAX -DUNICODE -D_UNICODE tools\privilege_access_tests.cpp -ladvapi32 -lauthz -o "$testOutput\privilege_access_tests.exe"
& "$testOutput\privilege_access_tests.exe"
```

The account fixture passed 229 read-only checks on this host, covering 7 accounts, 22 groups and asynchronous page destruction. Global LSA assignment enumeration returned `Access is denied (code=5)`, retained in the snapshot. A restricted execution token can also cause `NetUserEnum` error 5; record the actual permission environment instead of claiming complete collection. Use each run's output as its evidence.

Standalone checks do not replace the prescribed production MSVC/Qt build. Continue to use `tools\Invoke-KSwordBuildCheck.ps1` and the x64 toolchain specified in `AGENTS.md`. Actual account/group/LSA writes, UAC interaction and elevated identity startup require interactive use and acceptance on the target Windows system. Read-only and isolated fixtures do not establish that those operations have passed live acceptance.

Chinese guide: [权限工作台.md](权限工作台.md).
