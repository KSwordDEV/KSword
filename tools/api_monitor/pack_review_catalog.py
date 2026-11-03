"""Pack a review catalog as deterministic gzip JSON; verify exact round-trip.

The packed file remains review-only and is not loaded by the application.
"""
import argparse
import gzip
import json
from pathlib import Path
import time


def pack(source: Path, output: Path):
    if output.exists() or source.resolve() == output.resolve():
        raise ValueError('output must be a new file')
    start = time.perf_counter()
    source_bytes = source.read_bytes()
    original = json.loads(source_bytes)
    if original.get('external_review', {}).get('status') != 'unverified_not_runtime':
        raise ValueError('expected an unverified review catalog')
    compact = json.dumps(original, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    compressed = gzip.compress(compact, compresslevel=9, mtime=0)
    if json.loads(gzip.decompress(compressed)) != original:
        raise ValueError('round-trip verification failed')
    # Write only after full conversion and verification; never overwrite.
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(compressed)
    start_read = time.perf_counter()
    restored = json.loads(gzip.decompress(output.read_bytes()))
    load_seconds = time.perf_counter() - start_read
    if restored != original:
        raise ValueError('written file verification failed')
    return {'source_bytes': len(source_bytes), 'compact_json_bytes': len(compact),
            'gzip_bytes': len(compressed), 'round_trip_equal': True,
            'load_parse_seconds': round(load_seconds, 3),
            'total_seconds': round(time.perf_counter() - start, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(pack(args.source, args.output), ensure_ascii=False))


if __name__ == '__main__':
    main()
