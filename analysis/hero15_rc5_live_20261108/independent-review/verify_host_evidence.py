"""Offline independent validation of the already captured .15 Linux evidence.

No imports from the collector/controller and no network or device access.
"""
from pathlib import Path
import base64
import hashlib
import json
import struct
import uuid

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent
ROOT = SOURCE.parents[1]
EXPECTED_HOST = '26a6c61793e820e053044d9673297e2a0f1cf3643aaff81e8aafe5da5316dced'


def digest(p):
    b = p.read_bytes()
    return {'path': p.relative_to(ROOT).as_posix(), 'bytes': len(b),
            'sha256': hashlib.sha256(b).hexdigest()}


def require(condition, text):
    if not condition:
        raise ValueError(text)


def main():
    host = SOURCE / 'host-read-01.json'
    require(digest(host)['sha256'] == EXPECTED_HOST, 'source evidence hash')
    data = json.loads(host.read_text())
    table = (SOURCE / 'host-DMI.bin').read_bytes()
    ep = (SOURCE / 'host-smbios_entry_point.bin').read_bytes()
    require(table == base64.b64decode(data['smbios']['DMI'], validate=True), 'DMI copy')
    require(ep == base64.b64decode(data['smbios']['smbios_entry_point'], validate=True), 'entry copy')
    require(len(ep) == 24 and ep[:5] == b'_SM3_' and ep[6] == 24, 'SMBIOS3 entry shape')
    require(sum(ep) % 256 == 0, 'entry checksum')
    maximum, address = struct.unpack_from('<IQ', ep, 12)
    require(0 < len(table) <= maximum <= 262144 and address != 0, 'table range metadata')
    records = []
    seen_handles = set()
    pos = 0
    while pos < len(table):
        require(len(table)-pos >= 4, 'short structure header')
        kind, length, handle = struct.unpack_from('<BBH', table, pos)
        require(length >= 4 and length <= len(table)-pos, 'formatted bounds')
        require(handle not in seen_handles, 'duplicate SMBIOS handle')
        seen_handles.add(handle)
        end = table.find(b'\0\0', pos+length)
        require(end >= 0, 'unterminated string area')
        raw_strings = table[pos+length:end]
        strings = raw_strings.split(b'\0') if raw_strings else []
        records.append({'type': kind, 'handle': handle, 'offset': pos,
                        'formatted': table[pos:pos+length], 'strings': strings,
                        'end': end+2})
        pos = end+2
        if kind == 127:
            require(length == 4, 'invalid end-of-table record')
            break
    require(records and records[-1]['type'] == 127 and pos == len(table), 'complete exact Type127 stream')

    def unique(kind):
        items = [r for r in records if r['type'] == kind]
        require(len(items) == 1, 'unique identity type '+str(kind))
        return items[0]

    def field(record, offset):
        require(offset < len(record['formatted']), 'field offset')
        index = record['formatted'][offset]
        require(1 <= index <= len(record['strings']), 'referenced string index')
        value = record['strings'][index-1]
        require(0 < len(value) <= 255 and all(32 <= c < 127 for c in value), 'identity ASCII string')
        return value.decode('ascii')

    bios, system, board = unique(0), unique(1), unique(2)
    require(len(system['formatted']) >= 24, 'Type1 UUID field')
    raw_uuid = system['formatted'][8:24]
    require(raw_uuid not in (bytes(16), bytes([255])*16), 'real UUID')
    canonical = str(uuid.UUID(bytes_le=raw_uuid))
    identity = {
        'board': field(board, 5), 'board_vendor': field(board, 4),
        'bios_version': field(bios, 5), 'bios_date': field(bios, 8),
        'uuid_raw_hex': raw_uuid.hex(), 'uuid_canonical': canonical,
        'smbios_version': f'{ep[7]}.{ep[8]}.{ep[9]}',
        'table_bytes': len(table), 'table_maximum_bytes': maximum,
        'record_count': len(records), 'exact_type127_end': True,
    }
    require(identity['board'] == data['dmi']['board_name'] == 'ROG MAXIMUS Z790 HERO', 'HERO board')
    require(identity['board_vendor'] == data['dmi']['board_vendor'], 'board vendor cross-check')
    require(identity['bios_version'] == data['dmi']['bios_version'] == '3107', 'BIOS3107')
    require(identity['bios_date'] == data['dmi']['bios_date'] == '11/28/2025', 'BIOS date')
    require(canonical == data['dmi']['product_uuid'] == 'b222f546-dbb3-9ac8-bbfb-581122d8be9f', 'UUID endian/cross-check')
    management = [p for p in data['aspeed_pci']
                  if int(p['vendor'], 16) == 0x1a03 and int(p['device'], 16) == 0x2402]
    require(len(management) == 1, 'one Linux enumerated ASPEED management function')
    p = management[0]
    c = bytes.fromhex(p['config64'])
    require(len(c) == 64 and struct.unpack_from('<HH', c) == (0x1a03, 0x2402), 'config vendor/device')
    require(struct.unpack_from('<HH', c, 44) == (0x1a03, 0x2402), 'subsystem')
    require(c[8:12] == bytes.fromhex('0101070c') and c[14] == 0, 'revision/class/type0')
    bars = struct.unpack_from('<II', c, 16)
    require(bars == (0x78000000, 0x78100000), 'current BAR metadata')
    resources = [tuple(int(v, 16) for v in line.split()) for line in p['resource'].splitlines()]
    require(resources[0][:2] == (bars[0], bars[0]+0x100000-1), 'BAR0 resource')
    require(resources[1][:2] == (bars[1], bars[1]+0x40000-1), 'BAR1 resource')
    require(all(r[2] & 0x200 and not r[2] & 0x100 for r in resources[:2]), 'memory resources')
    pci = {
        'linux_address': p['address'], 'uefi_address_confirmed': False,
        'vendor_device': '1a03:2402', 'subsystem': '1a03:2402',
        'class': '0c0701', 'revision': c[8], 'header_type': c[14],
        'command': struct.unpack_from('<H', c, 4)[0],
        'bar0_base': bars[0], 'bar0_bytes': 0x100000,
        'bar1_base': bars[1], 'bar1_bytes': 0x40000,
        'kcs_last_offset': 0xe8c,
        'config64_sha256': hashlib.sha256(c).hexdigest(),
        'linux_aspeed_functions': len(data['aspeed_pci']),
        'linux_management_functions': len(management),
    }
    require(pci['linux_address'] == '0000:74:01.0', 'observed Linux location')
    old_sources = [ROOT/'analysis/hero_sensor_r4_20261108/source/engine.c',
                   ROOT/'analysis/hero_p6_settings21s_20261108/source/transport.c']
    require(all('bus!=4' in x.read_text() for x in old_sources), 'fixed-bus source evidence')
    result = {
        'scope': 'Independent offline reconciliation of already captured Linux identity; no target access',
        'passed': True, 'sources': [digest(host), digest(SOURCE/'host-DMI.bin'),
                                   digest(SOURCE/'host-smbios_entry_point.bin')],
        'identity': identity, 'pci': pci, 'old_fixed_bus_sources': [digest(x) for x in old_sources],
        'conclusions': [
            'HERO3107 identity and exact Type1 UUID now verified from raw SMBIOS plus sysfs fields.',
            'The Linux management BDF conflicts with both old R4/S21S fixed-bus4 selectors. UEFI must rediscover independently.',
            'New portable R5/S22 must be identified by new hashes; their success cannot be described as validation of the original exact C03 payloads.',
            'Linux empty Hero variable listing does not establish missing/non-runtime UEFI variables; fresh UEFI checks remain required.',
        ],
        'still_gated': ['UEFI unique candidate selection and resource bounds',
                        'UEFI settings/state/attempt locks and same-boot source identity',
                        'exact P6 native form resource availability',
                        'new core and loader actual-PE negative tests',
                        'whole new CAP FlashBack/native boot/F10/recovery validation'],
        'frozen_artifacts_modified': False,
    }
    (HERE/'host-evidence-addendum.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'passed': True, 'identity': identity, 'pci': pci,
                      'report': digest(HERE/'host-evidence-addendum.json')}, indent=2))


if __name__ == '__main__':
    main()
