"""Convert a validated HERO SMBIOS-I1 capture to pending AMI inventory JSON.

This tool is offline. It never uploads, contacts a BMC, or changes firmware.
The donor envelope/schema is confirmed by REA; empty GroupCrcList acceptance
must still be tested against the target BMC. No donor identity is reused.
"""
from pathlib import Path
import argparse
import collections
import hashlib
import json
import re
import struct
import uuid
import zlib

MAX_TABLE = 256 * 1024
PLACEHOLDERS = {'default string', 'to be filled by o.e.m.', 'to be filled by oem',
                'system product name', 'system manufacturer', 'system serial number',
                'system version', 'not specified', 'not applicable', 'unknown', 'none', 'sku'}


class CaptureError(ValueError):
    pass


def field(text, name):
    hits = re.findall(r'^' + re.escape(name) + r'=([0-9A-Fa-f]+)\s*$', text, re.M)
    if len(hits) != 1:
        raise CaptureError(f'{name}: require one hexadecimal value')
    return int(hits[0], 16)


def block(text, name):
    matches = re.findall(r'^' + re.escape(name) + r'_HEX_BEGIN\r?\n(.*?)^' +
                         re.escape(name) + r'_HEX_END\s*$', text, re.M | re.S)
    if len(matches) != 1:
        raise CaptureError(f'{name}: require one complete hexadecimal block')
    value = ''.join(matches[0].split())
    if len(value) % 2 or not re.fullmatch(r'[0-9A-Fa-f]*', value):
        raise CaptureError(f'{name}: invalid hexadecimal payload')
    return bytes.fromhex(value)


def structures(table):
    pos = 0
    result = []
    handles = set()
    while pos < len(table):
        if len(table) - pos < 6:
            raise CaptureError('truncated structure header or string terminator')
        typ, size, handle = struct.unpack_from('<BBH', table, pos)
        if size < 4 or pos + size + 2 > len(table):
            raise CaptureError('invalid formatted structure length')
        end = table.find(b'\0\0', pos + size)
        if end < 0:
            raise CaptureError('unterminated structure string set')
        if handle in handles:
            raise CaptureError('duplicate SMBIOS handle')
        handles.add(handle)
        raw_strings = table[pos + size:end]
        try:
            strings = raw_strings.decode('utf8').split('\0') if raw_strings else []
        except UnicodeDecodeError as error:
            raise CaptureError('non-UTF8 SMBIOS string requires explicit review') from error
        result.append({'type': typ, 'handle': handle, 'offset': pos,
                       'data': table[pos:pos + size], 'strings': strings})
        pos = end + 2
        if typ == 127:
            if pos != len(table):
                raise CaptureError('unexpected bytes after end-of-table')
            return result
    raise CaptureError('missing end-of-table structure')


def parse_capture(text):
    if text.count('HERO-SMBIOS-I1') != 1 or field(text, 'CAPTURE_VALID') != 1:
        raise CaptureError('capture is not a single valid HERO SMBIOS-I1 snapshot')
    table = block(text, 'TABLE')
    used, bound = field(text, 'TABLE_USED'), field(text, 'TABLE_BOUND')
    if not (6 <= used == len(table) <= bound <= MAX_TABLE):
        raise CaptureError('table size or bound mismatch')
    if zlib.crc32(table) != field(text, 'TABLE_CRC32'):
        raise CaptureError('table CRC32 mismatch')
    kind = field(text, 'SOURCE_KIND')
    major, minor = field(text, 'MAJOR'), field(text, 'MINOR')
    ep = block(text, f'ENTRY{kind}')
    if kind == 3:
        if not (24 <= len(ep) <= 64 and ep[:5] == b'_SM3_' and ep[6] == len(ep)):
            raise CaptureError('invalid SMBIOS3 entry point')
        if sum(ep) & 255 or ep[7:9] != bytes((major, minor)):
            raise CaptureError('SMBIOS3 entry checksum/version mismatch')
        if struct.unpack_from('<I', ep, 12)[0] != bound:
            raise CaptureError('SMBIOS3 declared table bound mismatch')
        address = struct.unpack_from('<Q', ep, 16)[0]
    elif kind == 2:
        if not (31 <= len(ep) <= 64 and ep[:4] == b'_SM_' and ep[5] == len(ep)):
            raise CaptureError('invalid SMBIOS2 entry point')
        if sum(ep) & 255 or ep[6:8] != bytes((major, minor)):
            raise CaptureError('SMBIOS2 entry checksum/version mismatch')
        if ep[16:21] != b'_DMI_' or sum(ep[16:31]) & 255:
            raise CaptureError('SMBIOS2 intermediate checksum mismatch')
        if struct.unpack_from('<H', ep, 22)[0] != bound:
            raise CaptureError('SMBIOS2 table bound mismatch')
        address = struct.unpack_from('<I', ep, 24)[0]
    else:
        raise CaptureError('unsupported entry point kind')
    if address != field(text, 'TABLE_ADDRESS'):
        raise CaptureError('entry point/table address mismatch')
    records = structures(table)
    if len(records) != field(text, 'STRUCTURES') or records[-1]['offset'] != field(text, 'TYPE127_OFFSET'):
        raise CaptureError('structure count/end-of-table offset mismatch')
    counts = collections.Counter(r['type'] for r in records)
    for typ in (0, 1, 2, 3, 4, 9, 16, 17, 41, 127):
        if field(text, f'TYPE_{typ:02X}_COUNT') != counts[typ]:
            raise CaptureError(f'Type{typ} count mismatch')
    return records, {'major': major, 'minor': minor, 'source_kind': kind,
                     'table_bytes': used, 'table_crc32': f'{zlib.crc32(table):08X}',
                     'table_sha256': hashlib.sha256(table).hexdigest()}


def string(record, offset):
    data = record['data']
    if offset >= len(data) or data[offset] == 0:
        return None
    index = data[offset] - 1
    if index >= len(record['strings']):
        raise CaptureError(f'invalid string index: Type{record["type"]} handle {record["handle"]:04x}')
    value = record['strings'][index].strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CaptureError('control character in SMBIOS string')
    return value if value and value.casefold() not in PLACEHOLDERS else None


def number(record, offset, width=2):
    data = record['data']
    if offset + width > len(data):
        return None
    return int.from_bytes(data[offset:offset + width], 'little')


def set_if(obj, name, value):
    if value is not None:
        obj[name] = value


def singleton(records, typ, required=False):
    values = [r for r in records if r['type'] == typ]
    if len(values) > 1 or (required and not values):
        raise CaptureError(f'Type{typ}: missing or ambiguous singleton')
    return values[0] if values else None


def cpu_count(record, short, extended):
    value = number(record, short, 1)
    if value == 255:
        value = number(record, extended)
    return value if value not in (None, 0, 65535) else None


def compose(records, meta, include_smbios_max_speed=False):
    board = singleton(records, 2, True)
    board_model = string(board, 5)
    if board_model != 'ROG MAXIMUS Z790 HERO':
        raise CaptureError('this uploader preparation is restricted to ROG MAXIMUS Z790 HERO')
    bios = singleton(records, 0, True)
    bios_version = string(bios, 5)
    if not bios_version:
        raise CaptureError('missing actual BIOS version')
    sy = singleton(records, 1)
    system = {'Id': 'Self', 'Name': 'System'}
    model = string(sy, 5) if sy else None
    manufacturer = string(sy, 4) if sy else None
    set_if(system, 'Model', model or board_model)
    set_if(system, 'Manufacturer', manufacturer or string(board, 4))
    system['BiosVersion'] = bios_version
    if sy:
        set_if(system, 'SerialNumber', string(sy, 7))
        set_if(system, 'SKU', string(sy, 25))
        if len(sy['data']) >= 24:
            raw_uuid = sy['data'][8:24]
            if raw_uuid not in (bytes(16), b'\xff' * 16):
                if (meta['major'], meta['minor']) >= (2, 6):
                    system['UUID'] = str(uuid.UUID(bytes_le=raw_uuid))
                else:
                    system['UUID'] = str(uuid.UUID(bytes=raw_uuid))
    cpus = []
    for index, rec in enumerate(r for r in records if r['type'] == 4):
        cpu = {'Id': f'DevType1_CPU{index}', 'Name': f'DevType1_CPU{index}'}
        for key, offset in [('Socket', 4), ('Manufacturer', 7), ('Model', 16),
                            ('SerialNumber', 32), ('PartNumber', 34)]:
            set_if(cpu, key, string(rec, offset))
        processor_type = number(rec, 5, 1)
        if processor_type == 3:
            cpu['ProcessorType'] = 'CPU'
            cpu['ProcessorArchitecture'] = 'x86'
        speed = number(rec, 20)
        if include_smbios_max_speed and speed not in (None, 0, 65535):
            cpu['MaxSpeedMHz'] = speed
        for key, short, extended in [('TotalCores', 35, 42), ('TotalEnabledCores', 36, 44), ('TotalThreads', 37, 46)]:
            set_if(cpu, key, cpu_count(rec, short, extended))
        state = number(rec, 24, 1)
        if state is not None:
            if not state & 64:
                cpu['Status'] = {'State': 'Absent'}
            elif state & 7 == 1:
                cpu['Status'] = {'State': 'Enabled'}
            elif state & 7 in (2, 3):
                cpu['Status'] = {'State': 'Disabled'}
        cpus.append(cpu)
    dimms = []
    device_types = {0x0f: 'SDRAM', 0x12: 'DDR', 0x13: 'DDR2', 0x18: 'DDR3', 0x1a: 'DDR4', 0x22: 'DDR5'}
    for index, rec in enumerate(r for r in records if r['type'] == 17):
        dimm = {'Id': f'DevType2_DIMM{index}', 'Name': f'DevType2_DIMM{index}'}
        for key, offset in [('DeviceLocator', 16), ('Manufacturer', 23), ('SerialNumber', 24), ('PartNumber', 26)]:
            set_if(dimm, key, string(rec, offset))
        size = number(rec, 12)
        capacity = None
        if size == 0:
            capacity = 0
            dimm['Status'] = {'State': 'Absent'}
        elif size not in (None, 65535):
            if size == 32767:
                value = number(rec, 28, 4)
                capacity = None if value is None else value & 0x7fffffff
            elif size & 32768:
                kib = size & 32767
                if kib % 1024 == 0:
                    capacity = kib // 1024
            else:
                capacity = size
            dimm['Status'] = {'State': 'Enabled'}
        set_if(dimm, 'CapacityMiB', capacity)
        set_if(dimm, 'MemoryDeviceType', device_types.get(number(rec, 18, 1)))
        if number(rec, 40, 1) == 3:
            dimm['MemoryType'] = 'DRAM'
        for key, offset in [('BusWidthBits', 8), ('DataWidthBits', 10)]:
            value = number(rec, offset)
            if value not in (None, 0, 65535):
                dimm[key] = value
        speed = number(rec, 21)
        if speed == 65535:
            speed = number(rec, 84, 4)
        if speed not in (None, 0, 65535, 0xffffffff):
            dimm['AllowedSpeedsMHz'] = [speed]
        configured = number(rec, 32)
        if configured == 65535:
            configured = number(rec, 88, 4)
        if configured not in (None, 0, 65535, 0xffffffff):
            dimm['OperatingSpeedMhz'] = configured
        dimms.append(dimm)
    system['Processors'] = cpus
    system['Memory'] = dimms
    chassis = {'Id': 'Self', 'Name': 'Chassis'}
    ch = singleton(records, 3)
    if ch:
        for key, offset in [('Manufacturer', 4), ('SerialNumber', 7), ('AssetTag', 8)]:
            set_if(chassis, key, string(ch, offset))
    return {'GroupCrcList': {}, 'RedfishVersion': '1.8.0', 'RtpVersion': '1.8.a',
            'Systems': [system], 'Chassis': [chassis]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--include-smbios-max-speed', action='store_true',
                        help='Include the firmware reported Type4 maximum; not an observed or rated CPU clock.')
    args = parser.parse_args()
    text = args.capture.read_text('utf-8-sig')
    records, meta = parse_capture(text)
    payload = compose(records, meta, args.include_smbios_max_speed)
    content = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'inventory.pending.json').write_bytes(content)
    manifest = {'state': 'offline-generated-not-yet-accepted-by-bmc', 'source_capture': str(args.capture.resolve()),
                'source_capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
                'smbios': meta, 'json_bytes': len(content), 'json_sha256': hashlib.sha256(content).hexdigest(),
                'identity': 'Actual HERO records only; system model/manufacturer fall back to actual Type2 if absent/placeholder.',
                'group_crc': 'Empty per donor nonzero-key omission behavior; no invented donor-structure CRCs.',
                'cpu_raw_type4_maximum_mhz': [number(r, 20) for r in records if r['type'] == 4],
                'cpu_maximum_published': args.include_smbios_max_speed,
                'limitations': ['BMC acceptance untested', 'PCIe/storage not included',
                                'CPU MaxSpeedMHz is the SMBIOS reported maximum, not a measured clock',
                                'OperatingSpeedMhz uses donor legacy spelling; source memory speed is MT/s',
                                'No synthesized health, slot topology, frequencies, serial number, or UUID'],
                'processors': len(payload['Systems'][0]['Processors']), 'memory_slots': len(payload['Systems'][0]['Memory'])}
    (args.out / 'inventory-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'json_bytes': len(content), 'processors': manifest['processors'], 'memory_slots': manifest['memory_slots'],
                      'output': str((args.out / 'inventory.pending.json').resolve())}))


if __name__ == '__main__':
    main()
