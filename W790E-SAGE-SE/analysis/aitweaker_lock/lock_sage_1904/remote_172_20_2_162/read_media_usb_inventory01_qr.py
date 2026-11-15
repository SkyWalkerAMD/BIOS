"""Decode USB metadata captures as data; never execute captured content."""
from pathlib import Path
import hashlib, importlib.util, json, sys
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / 'review/flash_readiness/remote_only/media_usb_inventory01'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj)
    return obj

decoder = module('p3_decoder', HERE.parents[1] / 'probe_p3_kvm/decode_captures.py')
parser_path = ROOT / 'decode_inventory_log.py'

def parse_log(raw):
    manifest = json.loads((ROOT / 'candidate_manifest.json').read_text())
    bound = [x for x in manifest['artifacts'] if Path(x['path']) == parser_path]
    if len(bound) != 1 or hashlib.sha256(parser_path.read_bytes()).hexdigest() != bound[0]['sha256']:
        raise ValueError('Inventory parser binding changed')
    result = module('usb_inventory_parser', parser_path).parse(raw)
    safe = b'FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0\r\n'
    if raw.count(safe) != 1 or not raw.endswith(safe + b'PROBE_COMPLETE\r\n'):
        raise ValueError('Diagnostic operation footer changed')
    result['status'] = 'METADATA_INVENTORY_COMPLETE' if result['complete'] else 'METADATA_INVENTORY_PARTIAL'
    result['physical_file_writeback_pass'] = False
    result['complete_spi_backup'] = False
    result['permanent_password_lock_test'] = False
    return result

def main():
    if sys.argv[1] == 'frame':
        screenshot = Path(sys.argv[2]); raw = decoder.read_image(screenshot)
        info = decoder.parse_frame(raw)
        screenshot.with_suffix('.frame').write_bytes(raw)
        print(json.dumps({k:v for k,v in info.items() if k != 'data'}))
    elif sys.argv[1] == 'assemble':
        folder = Path(sys.argv[2])
        raw, meta = decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))], require_inventory=False)
        result = parse_log(raw); target = folder / 'hardware-log.txt'
        if target.exists() and target.read_bytes() != raw: raise FileExistsError(target)
        target.write_bytes(raw); meta['capture'] = result
        meta['scope'] = 'Existing USB/BlockIO/SFS metadata only. No controller connect, storage data or file calls.'
        meta['files'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*')) if p.is_file() and p.name != 'manifest.json'}
        (folder / 'manifest.json').write_text(json.dumps(meta, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(meta))
    else: raise ValueError('Unsupported action')

if __name__ == '__main__': main()
