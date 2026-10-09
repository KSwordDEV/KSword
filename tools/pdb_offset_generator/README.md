# Ksword PDB Offset Generator

## Launcher report intake

Use `launcher_report_intake.py` for an extracted Launcher collection directory.
The default command validates `report.json`, `SHA256SUMS.txt`, every PE identity,
and RSDS metadata without modifying the corpus:

```powershell
$reportDir='<extracted-report-directory>'
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py `
  $reportDir
```

After reviewing the result, add `--commit` to stage all inputs, download and
validate exact public PDBs, generate compatibility-required NTOS/NTKRLA57
profiles, and atomically import them into `E:\KswordPDB\PDB`. Collection-only
modules are retained as PE/PDB research corpus and do not produce fake NTOS
profiles.

```powershell
$corpusRoot='<private-corpus-root>'
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py `
  $reportDir `
  --corpus-root $corpusRoot `
  --commit
```

Each committed report writes provenance to
`scratch\launcher-report-intake\<report-id>\intake.json` and
`logs\launcher_report_intake\<report-id>.json`.

Corpus intake and repository publishing are separate operations. After review,
publish the validated corpus into the repository data files and regenerate the
Launcher identity list explicitly:

```powershell
py -3.12 tools\pdb_offset_generator\ksword_profile_release_sync.py `
  --source "$corpusRoot\profiles\ark_dyndata" `
  --release-root "Ksword5.1\x64\Release" `
  --pack-only --emit-pack --pack-version 4 `
  --pack-output "Ksword5.1\Ksword5.1\profiles\ark_dyndata_pack_v4.json" `
  --manifest "Ksword5.1\Ksword5.1\profiles\ark_dyndata_manifest.json" `
  --report "$corpusRoot\logs\ark_dyndata_publish_report.launcher-intake.json"

py -3.12 Launcher\tools\generate_support_manifest.py `
  --source Launcher\support_manifest_source.json `
  --pack Ksword5.1\Ksword5.1\profiles\ark_dyndata_pack_v4.json `
  --output Launcher\launcher_support_manifest.json
```

The offline generator builds KswordARK dynamic-offset JSON profiles from Microsoft public symbols.
It uses the same public symbol-server PE key format used by debugger symbol tools:
`/<file>/<TimeDateStamp><SizeOfImage>/<file>`.

The offline corpus workflow intentionally runs outside the driver and outside the released product:

- It may download PE/PDB files into a local corpus/cache.
- It emits small JSON profiles under `profiles/ark_dyndata`.
- KswordARK user mode parses JSON and sends a packed, validated offset packet to the driver.

## Runtime exact-PDB fallback

The checked-in/release pack remains the primary and reproducible profile source.
If no valid pack entry matches the loaded image, the main application and
KswordARKLight can build an in-memory fallback profile from the exact public PDB:

- R0 supplies the loaded module `Machine + TimeDateStamp + SizeOfImage + ImageBase`.
- R3 first verifies the local PE against that identity, then loads symbols with
  DbgHelp using `SYMOPT_EXACT_SYMBOLS`.
- The fallback is accepted only when DbgHelp reports a loaded PDB with a nonzero
  GUID/Age and no PDB mismatch.
- NTOS/NTKRLA57 entries produce the same legacy, EX, and v4 catalog consumed by
  the offline generator. The layers are applied in `Legacy -> EX -> V4` order.
- FLTMGR and CI companion entries produce their existing v4 capability groups.
- A mismatch or unresolved item remains unavailable; the resolver never reuses
  a neighboring-build offset.

`KSWORD_SYMBOL_PATH` and `_NT_SYMBOL_PATH` are honored. The default symbol cache
is `%LOCALAPPDATA%\KSword\symbols`. Because stock Windows can provide DbgHelp
without the separate SymSrv component, R3 also parses the PE's RSDS record and
can download the exact `<pdb>/<GUID+Age>/<pdb>` object with WinHTTP. The default
upstream is the Microsoft public symbol server; `KSWORD_SYMBOL_SERVER` can
override its base URL. DbgHelp still revalidates the downloaded PDB GUID/Age
before any offset is accepted.

Keep the compiled runtime catalog synchronized with the Python generator:

```powershell
python tools\pdb_offset_generator\verify_runtime_dyndata_catalog.py
```

R0 also has a final read-only fallback inspired by bounded accessor decoding:
it decodes only a small allowlist of exported one-argument accessors, validates
each candidate against the live current process/thread object, and fills only
fields still unavailable after System Informer data and exact PDB application.
It does not pattern-scan arbitrary kernel text, invent global addresses, or
enable a mutation path from an unvalidated candidate.

## Minimal example

```powershell
python tools\pdb_offset_generator\ksword_pdb_profile_generator.py `
  --kphdyn third_party\systeminformer_dyn\kphdyn.xml `
  --version 10.0.26100 `
  --arch amd64 `
  --symbol-root D:\KswordKernelCorpus `
  --llvm-pdbutil D:\Software\VS\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe `
  --limit 1
```

Output profiles are written to:

```text
D:\KswordKernelCorpus\profiles\ark_dyndata\*.json
```

## Callback item dry-run

Use `--dry-run` with one local PE/PDB pair to validate callback item parsing without
running the full corpus generator, building KswordARK, writing `Release`, or
refreshing pack files:

```powershell
python tools\pdb_offset_generator\ksword_pdb_profile_generator.py `
  --dry-run `
  --local-pe D:\PDB\pe-store\amd64\ntoskrnl.exe.10.0.26100.961\<sha256>\ntoskrnl.exe `
  --local-pdb D:\PDB\pdb-cache\amd64\ntkrnlmp.pdb\<pdb-guid+age>\ntkrnlmp.pdb `
  --llvm-pdbutil D:\Software\VS\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe `
  --output D:\PDB\scratch\callback_profile_dryrun.json
```

The generated JSON uses one `v4Items` matrix. Each item has a stable numeric
`itemId`, string `kind`, capability group, value, and optional auxiliary values.
The historical `fields`, `typeSizes`, `callbackItems`, and `typedItems` mirrors
are not serialized. Missing candidates remain diagnostic-only under
`v4MissingItems` and `diagnostics`.

## v4-only release policy

`ark_dyndata_pack_v4.json` is the sole supported release artifact. The release
sync rejects `--pack-version` values other than 4, omits the old field dictionary
and legacy item arrays, and publishes only complete capability groups. Runtime
R3/Light loaders look up v4 only. Core v4 items are projected in memory to the
existing EX apply request so process, thread, callback, module, and token
consumers retain their behavior without duplicate offsets on disk.

The main-program build compresses an existing compact source pack with
`compress_qt_profile_json.py --normalize-dyndata-v4`. This offline step verifies
the original item/group counts, removes legacy mirrors and the retired timer
IDs 1004/1006, and omits incomplete special groups using the release generator's
existing contract. It preserves every retained offset and module identity and
does not read or download PDBs. Unknown items and malformed inputs fail the
build instead of publishing a silently repaired profile. Runtime loaders still
require canonical v4 and exact PE identity; normalization cannot fill a missing
kernel profile.

Use:

```powershell
python tools\pdb_offset_generator\ksword_profile_release_sync.py `
  --source D:\KswordKernelCorpus\profiles\ark_dyndata `
  --release-root Ksword5.1\x64\Release `
  --pack-only --emit-pack --pack-version 4 `
  --pack-output Ksword5.1\x64\Release\profiles\ark_dyndata_pack_v4.json `
  --clean-target
```

The two timer IDs `1004` and `1006` remain reserved protocol numbers and are
not generated because no runtime consumer reads them. Incomplete CI and work
queue groups are omitted as a whole. This prevents a profile from advertising
a capability that R0 would reject immediately.

## v4 pack schema

The pack has no top-level field dictionary and no per-profile legacy mirrors.
Every usable offset, RVA, type size, bit field, or enum value appears exactly
once in `profile.items`:

```json
{
  "schemaVersion": 1,
  "packVersion": 4,
  "profiles": [
    {
      "moduleClassId": 0,
      "machine": 34404,
      "timeDateStamp": 305419896,
      "sizeOfImage": 21299200,
      "profileName": "example",
      "pdbName": "ntkrnlmp.pdb",
      "pdbGuid": "",
      "pdbAge": 1,
      "items": [
        {
          "itemId": 58,
          "name": "EpUniqueProcessId",
          "itemKind": 1,
          "flags": 1,
          "capabilityGroupId": 1,
          "valueLow": 1088,
          "valueHigh": 0,
          "aux0": 0,
          "aux1": 0,
          "aux2": 0,
          "aux3": 0
        }
      ],
      "capabilityGroups": [
        {
          "groupId": 1,
          "flags": 0,
          "requiredItemCount": 1,
          "optionalItemCount": 0,
          "groupName": "ntos.core"
        }
      ],
      "missingFields": [],
      "missingGlobals": ["PiDDBCacheTable"],
      "coveragePercent": 96.3
    }
  ]
}
```

Release reports include per-profile `missingFields`, `missingGlobals`, and
`coveragePercent`. Source corpus files use `v4Items`; release sync validates and
converts those entries to the numeric wire shape above. The source compatibility
parser may read an older corpus while it is being regenerated, but it never
publishes legacy keys.

## ActiveProcessLinks audit helper

Use `ksword_active_process_links_audit.py` to verify that the current
`ark_dyndata_pack_v4.json` contains `_EPROCESS.ActiveProcessLinks` for the
local `ntoskrnl.exe` identity:

```powershell
python tools\pdb_offset_generator\ksword_active_process_links_audit.py `
  --pack Ksword5.1\x64\Release\profiles\ark_dyndata_pack_v4.json `
  --kernel C:\Windows\System32\ntoskrnl.exe
```

The script prints the matching profile name and v4 item offset list, and exits
non-zero if the offset is missing.

## v4 item validation

Source `v4Items` must use the stable IDs and kinds declared in
`shared/driver/KswordArkDynDataIoctl.h`. Values must fit the corresponding
offset/RVA/type-size limits. Duplicate IDs, unknown IDs, invalid auxiliary bit
field metadata, and incomplete fixed capability groups are rejected or omitted
before publication. Timer IDs `1004` and `1006` are reserved and must not appear
in generated source or release packs.

## ntoskrnl deep runtime offset catalog

`ksword_ntos_pdb_deep_offsets.py` is the read-only deep catalog generator for
runtime detail work. It parses one local `ntkrnlmp.pdb` with `llvm-pdbutil` and
writes a large JSON/CSV field inventory for process, thread, handle/object,
driver/module, memory/section, ALPC/IPC, callback/registry/security, and common
kernel primitive types.

Current repository deep library:

```text
Ksword5.1\Ksword5.1\profiles\pdb_deep_offsets\ntkrnlmp_f923da2d238e7c7ce180b962b19a3781_age5_deep_offsets.json
```

Important identity note: `llvm-pdbutil dump -summary` may report a PDB internal
`Age` that differs from the Microsoft symbol-cache GUID+Age folder. Runtime
profile matching must use the RSDS/symbol-cache identity used by the loaded PE.
For the current checked-in library the PDB summary age is `5`, but the
symbol-cache key is `F923DA2D238E7C7CE180B962B19A37811`, so the runtime
`pdbAge` stored in JSON/manifest is `1` and `pdbSummaryAge` is retained only as
diagnostic provenance.

Regenerate the current library without re-dumping TPI when the raw type cache is
already present:

```powershell
python tools\pdb_offset_generator\ksword_ntos_pdb_deep_offsets.py `
  --pdb E:\KswordPDB\PDB\pdb-cache\amd64\ntkrnlmp.pdb\F923DA2D238E7C7CE180B962B19A37811\ntkrnlmp.pdb `
  --llvm-pdbutil D:\Software\VS\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe `
  --output-dir D:\Temp\ksword_pdb_deep_offsets `
  --json-name ntkrnlmp_f923da2d238e7c7ce180b962b19a3781_age5_deep_offsets.json `
  --csv-name ntkrnlmp_f923da2d238e7c7ce180b962b19a3781_age5_deep_offsets.csv `
  --repo-json Ksword5.1\Ksword5.1\profiles\pdb_deep_offsets\ntkrnlmp_f923da2d238e7c7ce180b962b19a3781_age5_deep_offsets.json `
  --dump-types-cache D:\Temp\ksword_pdb_deep_offsets\ntkrnlmp_f923da2d238e7c7ce180b962b19a3781_age5_types.txt
```

The JSON contains:

- `flatFields`: all extracted fields, each with `runtimeItemId`,
  `runtimeItemIdHex`, type name, byte offset, and bitfield metadata when present.
- `kswordAliasFields`: fields already mapped to existing Ksword/DynData item
  names such as `EpUniqueProcessId`, `EtCid`, `KldrDllBase`, and
  `DoMajorFunction`.
- `runtimeDetailCatalog`: domain/type grouping for future process/thread/handle
  detail pages and future paged detail IOCTLs.

The generated `runtimeItemId` values are deterministic CRC32-derived IDs in the
high-bit namespace so they do not collide with existing small
`KSW_DYN_FIELD_ID_*` values. They are catalog identifiers only; the current R0
detail IOCTLs still consume a fixed, validated whitelist of applied DynData
aliases. Do not add an arbitrary “R3 passes offset, R0 reads memory” interface.
The safe next step for exposing all 2682 fields is a paged, identity-checked
profile/catalog protocol that only reads fields from a driver-validated applied
catalog.

Validate pack coverage against checked-in deep libraries:

```powershell
python tools\pdb_offset_generator\ksword_dyndata_pack_deep_audit.py
```

The audit writes:

```text
D:\Temp\ksword_pdb_deep_offsets\ksword_dyndata_pack_deep_audit.json
```

For the current `F923...` ntoskrnl profile the audit should report strict
identity match, `47/47` deep aliases present, and process/thread/module detail
required fields ready. This proves the release JSON carries the required
offsets; it does not prove a running driver has already consumed the pack.

## Driver unload research report

`ksword_driver_unload_research.py` is a read-only research helper for the
current unload investigation. It does not build R3, does not modify release
artifacts, and does not execute any unload path.

It summarizes:

- existing scattered profile coverage for unload-relevant fields;
- per-version readiness for `DriverObject` / `KLDR` / callback / kernel-global
  evidence;
- a static risk model for the current unload paths;
- an optional PDB deep-dive mode for selected local PE/PDB pairs.

Basic offline summary:

```powershell
python tools\pdb_offset_generator\ksword_driver_unload_research.py `
  --output D:\PDB\scratch\driver_unload_research_report.json `
  --markdown D:\PDB\scratch\driver_unload_research_report.md
```

Optional direct PDB deep dive on a filtered sample set:

```powershell
python tools\pdb_offset_generator\ksword_driver_unload_research.py `
  --parse-pdb `
  --module-class ntoskrnl `
  --version-filter 10.0.26100 `
  --max-pdb 8 `
  --output D:\PDB\scratch\driver_unload_research_report.json
```

The deep-dive mode uses the local corpus paths already stored in the profile
metadata and resolves additional `llvm-pdbutil` type/global evidence when the
matching PE/PDB files are present.
