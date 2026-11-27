"""Verify the one VM capture from saved formal network-read results; no traffic."""
import hashlib
import json
from pathlib import Path
import socket
import struct

ROOT = Path(__file__).resolve().parents[3]
LOG = ROOT / '.codex-build-logs/action-analyze-wfp-vm'


def load(name):
    return json.loads((LOG / name).read_text(encoding='utf-8-sig'))


def main():
    capture = load('capture.stdout.json')['data']
    state = load('state.json')
    assert load('capture.exit.json')['exitCode'] == 0
    assert capture['source'] == 'existing-wfp' and capture['sourceReady']
    assert capture['reason'] == 'duration-elapsed' and capture['cleanupConfirmed']
    assert int(capture['packetCount']) == 3 and int(capture['capturedLength']) == 191
    window = capture['targetWindows'][0]
    assert window['pid'] == state['listenerPid']
    assert str(window['creationFileTime']) == state['listenerCreationFileTime']
    marker = (state['marker'] + '\n').encode('ascii')
    rows = load('network-read-1.stdout.json')['data']['records']
    proof = []
    marker_hits = 0
    for row in rows:
        selected = load(f"record-1-{row['recordSequence']}.stdout.json")['data']
        assert selected['checkpointVerified'] and selected['sourceId'] == 'ksword-r0-wfp-existing'
        full = selected['records'][0]
        packet = bytes.fromhex(full['bytes'])
        assert packet[0] >> 4 == 4 and packet[9] == 6
        ihl = (packet[0] & 15) * 4
        total = struct.unpack_from('!H', packet, 2)[0]
        assert total == len(packet) == full['capturedLength']
        assert total == int(full['originalLength']) and not full['sourceTruncated']
        assert socket.inet_ntoa(packet[12:16]) == '127.0.0.1'
        assert socket.inet_ntoa(packet[16:20]) == '127.0.0.1'
        source, destination = struct.unpack_from('!HH', packet, ihl)
        assert source == full['sourceEndpoint']['port']
        assert destination == full['destinationEndpoint']['port']
        tcp_header = (packet[ihl + 12] >> 4) * 4
        payload = packet[ihl + tcp_header:]
        marker_hits += payload == marker
        assert full['processAttribution'] == 'endpoint-table-hint'
        assert full['creationFileTime'] is None
        assert int(window['startUtc']) <= int(full['sourceFileTime']) <= int(window['endUtc'])
        proof.append({'ordinal': 1, 'recordSequence': full['recordSequence'],
                      'recordOffset': full['recordOffset'], 'producerSequence': full['producerSequence'],
                      'ipLength': total, 'payloadLength': len(payload),
                      'payloadSha256': hashlib.sha256(payload).hexdigest(), 'marker': payload == marker})
    assert len(rows) == 3 and marker_hits == 1
    assert load('listener-result.json')['receivedMarker']
    assert load('fixture-cleanup.json')['cleanupConfirmed']
    cleanup = load('cleanup.json')
    assert cleanup['trafficStopExit'] == cleanup['serviceStopExit'] == cleanup['serviceDeleteExit'] == 0
    assert not cleanup['remainingService'] and not cleanup['remainingOwned']
    summary = {'verdict': 'PASS: narrow IPv4 inbound loopback archive/readback',
               'captureCoverage': capture['captureCoverage'], 'sourceLossUnquantified': True,
               'sample': capture['sampleId'], 'marker': state['marker'], 'packets': proof,
               'fixtureClientExit': load('fixture-cleanup.json')['clientExitCode'],
               'cleanup': cleanup}
    (LOG / 'verification.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
