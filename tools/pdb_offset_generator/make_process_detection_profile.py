"""Build only the read-only process-detection group from one locally matched PE/PDB."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid

import pefile


FIELDS = {
    57: ("EpUniqueProcessId", "_EPROCESS!UniqueProcessId"),
    58: ("EpActiveProcessLinks", "_EPROCESS!ActiveProcessLinks"),
    59: ("EpThreadListHead", "_EPROCESS!ThreadListHead"),
    62: ("EtCid", "_ETHREAD!Cid"),
    63: ("EtThreadListEntry", "_ETHREAD!ThreadListEntry"),
    64: ("EtStartAddress", "_ETHREAD!StartAddress"),
    66: ("KtProcess", "_KTHREAD!Process"),
    122: ("EpVadRoot", "_EPROCESS!VadRoot"),
    123: ("EpVadHint", "_EPROCESS!VadHint"),
    166: ("EpVadCount", "_EPROCESS!VadCount"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("pe", "pdb", "extractor", "out-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    image = args.pe.resolve().read_bytes()
    with pefile.PE(data=image) as pe:
        records = [debug.struct for debug in pe.DIRECTORY_ENTRY_DEBUG if debug.struct.Type == 2]
        rsds = [image[r.PointerToRawData:r.PointerToRawData + r.SizeOfData] for r in records]
        rsds = [v for v in rsds if len(v) > 24 and v.startswith(b"RSDS")]
        if len(rsds) != 1 or pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("Expected one RSDS record in an x64 kernel image")
        guid = uuid.UUID(bytes_le=rsds[0][4:20]).hex.upper()
        age = int.from_bytes(rsds[0][20:24], "little")
        pdb_name = rsds[0][24:].split(b"\0")[0].decode("ascii").replace("\\", "/").split("/")[-1]
        timestamp, size = pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage
    pdb = args.pdb.resolve()
    if pdb_name.lower() != "ntkrnlmp.pdb" or pdb_name.lower() != pdb.name.lower():
        raise ValueError("PE CodeView does not reference the selected kernel PDB")
    extracted = json.loads(subprocess.check_output([str(args.extractor.resolve()), str(args.pe.resolve()),
        str(pdb.parent), *(name for _, name in FIELDS.values())], text=True, encoding="utf-8"))
    if (Path(extracted["pdb"]).resolve() != pdb or extracted["pdbGuid"].upper() != guid or extracted["pdbAge"] != age
            or int(extracted["timeDateStamp"], 0) != timestamp or int(extracted["sizeOfImage"], 0) != size
            or extracted["missing"]):
        raise ValueError("DbgHelp exact-symbol identity or field verification failed")
    items = []
    for key, (name, typemember) in FIELDS.items():
        offset = extracted["fields"][typemember]["offset"]
        if not 0 < offset < 0x10000 or offset % 8:
            raise ValueError("Unexpected x64 field alignment or offset for " + name)
        items.append(dict(itemId=key, itemKind=1, flags=1, capabilityGroupId=0x5052, valueLow=offset,
                          valueHigh=0, aux0=0, aux1=0, aux2=0, aux3=0, name=name))
    values = "".join(f"{item['itemId']}:{item['valueLow']}\n" for item in items).encode("ascii")
    profile = dict(profileName=f"process-detection-{guid}-{age}", moduleClassId=0, machine=0x8664,
                   sizeOfImage=size, timeDateStamp=timestamp, pdbName=pdb_name, pdbGuid=guid, pdbAge=age,
                   capabilityGroups=[dict(groupId=0x5052, groupName="process.enumeration.readonly",
                                          flags=0, requiredItemCount=len(items), optionalItemCount=0)], items=items)
    artifact = dict(packVersion=4, schemaVersion=4, profiles=[profile], imageSha256=sha(image),
                    pdbSha256=sha(pdb.read_bytes()), fieldsSha256=sha(values))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / f"{guid}-{age}.json"
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{path} GUID={guid} age={age} fields={len(items)} fields_sha256={artifact['fieldsSha256']}")


if __name__ == "__main__":
    main()
