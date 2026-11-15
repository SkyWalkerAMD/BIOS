"""Decode a retained I4 snapshot. No network, firmware or device access.

An observation catalogue is not a ready-to-publish payload. In particular,
NVMe DiskInfo bytes are not assumed to be an Identify Controller structure.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
import uuid
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('bounded_pci', ROOT / 'analysis/hero_inventory_20261108/pcie_storage_analysis/decode_readonly.py')
pci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pci)
MAX_BYTES = 2 * 1024 * 1024
LIMITS = {'PCI': 128, 'BLOCK': 128, 'DISK': 64}
ATA = {'9e498932-4abc-45af-a34d-0247787be7c6', '5e948fe3-26d3-42b5-af17-610287188dec'}
NVME = '3ab14680-5d3f-4a4d-bcdc-cc380018c7f7'


class InvalidCapture(ValueError):
    pass


def num(d, key, default=None):
    value = d.get(key)
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not re.fullmatch('[0-9A-F]{1,16}', value):
        raise InvalidCapture('Missing or invalid numeric field: ' + key)
    return int(value, 16)


def parse_catalog(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise InvalidCapture('Snapshot size out of bounds')
    text = raw.decode('ascii', errors='strict')
    lines = text.splitlines()
    if lines.count('I4_CATALOG_BEGIN') != 1 or lines.count('I4_CATALOG_END') != 1:
        raise InvalidCapture('Require one complete I4 catalogue')
    begin, end = lines.index('I4_CATALOG_BEGIN'), lines.index('I4_CATALOG_END')
    if end <= begin:
        raise InvalidCapture('Invalid catalogue order')
    groups, global_fields = {}, {}
    group = record = blob_name = None
    blob_lines = []
    for line in lines[begin + 1:end]:
        if blob_name is not None:
            if line == blob_name + '_HEX_END':
                record[blob_name + '_HEX'] = ''.join(blob_lines)
                blob_name = None
            elif not re.fullmatch('[0-9A-F]{2,64}', line) or len(line) % 2:
                raise InvalidCapture('Invalid raw hex line')
            else:
                blob_lines.append(line)
                if sum(map(len, blob_lines)) > 8192:
                    raise InvalidCapture('Raw field too large')
            continue
        if line.startswith('ENUM_BEGIN='):
            kind = line.split('=', 1)[1]
            if group is not None or record is not None or kind not in LIMITS or kind in groups:
                raise InvalidCapture('Invalid or duplicate enumeration')
            group = {'kind': kind, 'records': []}
            groups[kind] = group
        elif line.startswith('ENUM_END='):
            if group is None or record is not None or line != 'ENUM_END=' + group['kind']:
                raise InvalidCapture('Unbalanced enumeration')
            group = None
        elif line in tuple(k + '_BEGIN' for k in LIMITS):
            if group is None or record is not None or line != group['kind'] + '_BEGIN':
                raise InvalidCapture('Unbalanced record')
            record = {}
            group['records'].append(record)
            if len(group['records']) > LIMITS[group['kind']]:
                raise InvalidCapture('Record bound exceeded')
        elif line in tuple(k + '_END' for k in LIMITS):
            if group is None or record is None or line != group['kind'] + '_END':
                raise InvalidCapture('Unbalanced record end')
            record = None
        elif line.endswith('_HEX_BEGIN'):
            blob_name = line[:-10]
            if record is None or blob_name + '_HEX' in record:
                raise InvalidCapture('Unexpected or duplicate raw block')
            blob_lines = []
        elif '=' in line:
            key, value = line.split('=', 1)
            if not re.fullmatch('[A-Z][A-Z0-9_]{0,79}', key) or len(value) > 160:
                raise InvalidCapture('Invalid field')
            target = record if record is not None else group if group is not None else global_fields
            if key in target:
                raise InvalidCapture('Duplicate field: ' + key)
            target[key] = value
        else:
            raise InvalidCapture('Unknown catalogue line')
    if group is not None or record is not None or blob_name is not None or set(groups) != set(LIMITS):
        raise InvalidCapture('Truncated catalogue')
    if global_fields.get('SCHEMA') != 'I4-READONLY-1' or global_fields.get('PUBLICATION_ALLOWED') != '0':
        raise InvalidCapture('Unexpected schema')
    tail = {}
    for line in lines[end + 1:]:
        if '=' in line:
            key, value = line.split('=', 1)
            if key in tail:
                raise InvalidCapture('Duplicate terminal field')
            tail[key] = value
    if num(tail, 'CAPTURE_COMPLETE') != 1 or num(tail, 'COLLECT_RETURN') != 0 or num(tail, 'LOG_OVERFLOW') != 0:
        raise InvalidCapture('Capture did not complete successfully')
    for kind, g in groups.items():
        count = num(g, 'ENUM_COUNT')
        if num(g, 'ENUM_STATUS') == 0:
            if count:
                if num(g, 'ENUM_CAPTURED') != len(g['records']) or len(g['records']) != min(count, LIMITS[kind]):
                    raise InvalidCapture('Enumeration count mismatch')
            elif g['records']:
                raise InvalidCapture('Unexpected records in empty enumeration')
        elif g['records']:
            raise InvalidCapture('Records after failed enumeration')
        if [num(r, 'INDEX') for r in g['records']] != list(range(len(g['records']))):
            raise InvalidCapture('Nonsequential record indices')
        handles = [num(r, 'HANDLE') for r in g['records']]
        if len(set(handles)) != len(handles) or 0 in handles:
            raise InvalidCapture('Duplicate or null handle')
    return groups, global_fields


def raw_bytes(record, key, size=None, crc=False):
    raw = bytes.fromhex(record[key + '_HEX'])
    if size is not None and len(raw) != size:
        raise InvalidCapture('Unexpected ' + key + ' size')
    if crc and zlib.crc32(raw) != num(record, key + '_CRC32'):
        raise InvalidCapture('Raw field CRC mismatch')
    return raw


def device_path(record):
    if num(record, 'PATH_PROTOCOL_STATUS') or num(record, 'PATH_FIRST_STATUS') or num(record, 'PATH_SECOND_STATUS') or num(record, 'PATH_STABLE') != 1:
        raise InvalidCapture('Unstable or unavailable device path')
    raw = raw_bytes(record, 'PATH_FIRST', num(record, 'PATH_FIRST_BYTES'))
    if len(raw) != num(record, 'PATH_SECOND_BYTES'):
        raise InvalidCapture('Device path length changed')
    return raw, pci.decode_path(raw)


def media_fields(raw):
    if len(raw) not in (32, 44, 48):
        raise InvalidCapture('Unexpected BlockIo media size')
    if any(x not in (0, 1) for x in raw[4:9]):
        raise InvalidCapture('Invalid BlockIo boolean')
    return dict(media_id=struct.unpack_from('<I', raw)[0], removable=bool(raw[4]),
                media_present=bool(raw[5]), logical_partition=bool(raw[6]), read_only=bool(raw[7]),
                write_caching=bool(raw[8]), block_size=struct.unpack_from('<I', raw, 12)[0],
                io_align=struct.unpack_from('<I', raw, 16)[0], last_block=struct.unpack_from('<Q', raw, 24)[0])


def ata_identity(raw):
    if len(raw) != 512 or not any(raw) or raw == b'\xff' * 512:
        raise InvalidCapture('Invalid ATA Identify bytes')
    if raw[510] == 0xa5 and sum(raw) & 255:
        raise InvalidCapture('ATA Identify checksum failed')
    result = {'format': 'ATA/ATAPI Identify', 'atapi': bool(raw[1] & 0x80)}
    for key, start, count in [('serial_number', 20, 20), ('firmware_revision', 46, 8), ('model', 54, 40)]:
        b = raw[start:start + count]
        b = b''.join(bytes([b[i + 1], b[i]]) for i in range(0, len(b), 2))
        if any(x < 32 or x > 126 for x in b):
            result[key] = None
        else:
            result[key] = b.decode('ascii').strip() or None
    result['physical_drive_proven'] = False
    return result


def decode(raw):
    groups, global_fields = parse_catalog(raw)
    out = dict(schema='hero-i4-observations-1', source_sha256=hashlib.sha256(raw).hexdigest(),
               source_bytes=len(raw), collection_partial=bool(num(global_fields, 'COLLECTION_PARTIAL')),
               cleanup_status=global_fields.get('CLEANUP_STATUS'),
               pci=[], block=[], disk=[], publication_allowed=False)
    all_bdf = set()
    for kind in ('PCI', 'BLOCK', 'DISK'):
        for r in groups[kind]['records']:
            item = dict(index=num(r, 'INDEX'), handle=r['HANDLE'], valid=False)
            try:
                if num(r, 'PROTOCOL_STATUS'):
                    raise InvalidCapture('Protocol unavailable')
                path, path_info = device_path(r)
                item.update(path_hex=path.hex(), path=path_info)
                if kind == 'PCI':
                    if num(r, 'LOCATION_STATUS') or num(r, 'LOCATION_VALID') != 1 or num(r, 'CONFIG_STATUS'):
                        raise InvalidCapture('PCI location or config unavailable')
                    config = raw_bytes(r, 'CONFIG', 256, crc=True)
                    data = pci.decode_pci(config, *(num(r, k) for k in ('SEGMENT', 'BUS', 'DEVICE', 'FUNCTION')))
                    if data['bdf'] in all_bdf:
                        raise InvalidCapture('Duplicate BDF')
                    all_bdf.add(data['bdf'])
                    item.update(data, config_hex=config.hex())
                elif kind == 'BLOCK':
                    revision = num(r, 'REVISION')
                    size = 48 if revision >= 0x2001f else 44 if revision >= 0x20001 else 32
                    if revision < 0x10000 or num(r, 'MEDIA_READABLE') != 1 or num(r, 'MEDIA_FIELDS_STABLE') != 1:
                        raise InvalidCapture('Block metadata unavailable or changed')
                    a, b = raw_bytes(r, 'MEDIA_FIRST', size), raw_bytes(r, 'MEDIA_SECOND', size)
                    if a[:9] != b[:9] or a[12:20] != b[12:20] or a[24:] != b[24:]:
                        raise InvalidCapture('Block metadata bytes changed')
                    if num(r, 'MEDIA_REVISION_AFTER') != revision or r['MEDIA_POINTER'] != r['MEDIA_POINTER_AFTER']:
                        raise InvalidCapture('Block metadata identity changed')
                    item.update(pci.block_observation(media_fields(a), path))
                else:
                    interface = str(uuid.UUID(bytes_le=raw_bytes(r, 'INTERFACE_GUID_LE', 16)))
                    item['interface_guid'] = interface
                    if interface not in ATA | {NVME}:
                        item['identify_not_collected'] = r.get('IDENTIFY_SKIPPED', 'unsupported interface')
                    else:
                        size = 4096 if interface == NVME else 512
                        if num(r, 'IDENTIFY_STATUS') or num(r, 'IDENTIFY_RETURNED_BYTES') != size or num(r, 'IDENTIFY_BUFFER_GUARDS_OK') != 1 or num(r, 'IDENTIFY_FORMAT_SIZE_MATCH') != 1:
                            raise InvalidCapture('Identify getter failed or returned an unexpected size')
                        identity = raw_bytes(r, 'IDENTIFY', size, crc=True)
                        item.update(identify_sha256=hashlib.sha256(identity).hexdigest(), identify_hex=identity.hex())
                        if interface in ATA:
                            item['identity'] = ata_identity(identity)
                        else:
                            item['identity'] = {'format': 'NVMe DiskInfo raw; AMI layout unproven',
                                                'note': 'EDK2 returns Identify Namespace. Do not decode these bytes as Controller identity.'}
                item['valid'] = True
            except (InvalidCapture, pci.CaptureError, KeyError, ValueError) as e:
                item['error'] = str(e)
            out[kind.lower()].append(item)
    for kind in ('block', 'disk'):
        for item in out[kind]:
            if not item.get('valid'):
                continue
            path = bytes.fromhex(item['path_hex'])
            candidates = [p for p in out['pci'] if p.get('valid') and path.startswith(bytes.fromhex(p['path_hex'])[:-4])]
            if candidates:
                longest = max(len(p['path_hex']) for p in candidates)
                parents = [p for p in candidates if len(p['path_hex']) == longest]
                if len(parents) == 1:
                    item['pci_parent_bdf'] = parents[0]['bdf']
    out['counts'] = {kind: dict(total=len(out[kind]), decoded=sum(x['valid'] for x in out[kind])) for kind in ('pci', 'block', 'disk')}
    return out


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('snapshot', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = decode(a.snapshot.read_bytes())
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('source_sha256', 'counts', 'collection_partial', 'publication_allowed')}, indent=2))
