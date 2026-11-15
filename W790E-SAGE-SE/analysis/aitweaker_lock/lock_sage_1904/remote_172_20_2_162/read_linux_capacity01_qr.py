"""Capture a complete production LC01 single-page QR as data, never commands."""
from pathlib import Path
import hashlib, importlib.util, json, sys
HERE = Path(__file__).resolve().parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def module(name, path, digest):
    if sha(path) != digest: raise ValueError('Decoder binding changed: '+name)
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); sys.modules[name] = m
    spec.loader.exec_module(m); return m
p3 = module('linux_capacity_p3', HERE.parents[1]/'probe_p3_kvm/decode_captures.py',
            'f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283')
semantic = module('linux_capacity_semantic', HERE.parent/'review/flash_readiness/remote_only/linux_capacity_candidate01/decode_linux_log.py',
                  '96538b8d7722711b018bd18aafd35f3d35d4e7b98c5160c3baf9762f4aa6935a')
def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'capture': raise ValueError('Expected capture screenshot')
    shot = Path(sys.argv[2]); frame = p3.read_image(shot); fields = p3.parse_frame(frame)
    if fields['page'] != 1 or fields['pages'] != 1 or not 0 < fields['total'] <= 768:
        raise ValueError('Unexpected LC01 single-page bounds')
    log, transport = p3.assemble([frame], require_inventory=False)
    meaning = semantic.decode(log)
    if not meaning['complete']: raise ValueError('Incomplete probe')
    folder = shot.parent
    for name, data in [('page-01.frame', frame), ('hardware-log.txt', log)]:
        target = folder/name
        if target.exists() and target.read_bytes() != data: raise FileExistsError(target)
        target.write_bytes(data)
    result = {**transport, 'semantic':meaning,
              'scope':'Production Linux capacity observation only; no block backup, firmware writes or release acceptance.'}
    result['files'] = {p.name:sha(p) for p in sorted(folder.iterdir())
                       if p.is_file() and p.name != 'manifest.json'}
    (folder/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result))
if __name__ == '__main__': main()
