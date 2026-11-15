"""Offline, pinned official BMC geometry provenance; never executes target code."""
from pathlib import Path
import hashlib, json, re, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p/'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0, str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage
SOURCE = BASE/'official_bmc/W7901157.ima'
PIN = '0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
NEEDLES = [b'/dev/nbd', b'mass_storage.usb', b'268436480', b'268435456', b'262144',
           b'nbds_max', b'nbd-client', b'block_size', b'blocksize', b'hdredir', b'HDRedir']
EXPLICIT={'/usr/local/lib/libsafesystem.so.13.1.1','/usr/local/bin/safe_system_exe',
          '/usr/local/bin/execdaemon','/etc/init.d/execdaemon_init'}
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
    assert sha(SOURCE.read_bytes()) == PIN
    offsets = sorted(set(x['filesystem_offset'] for x in json.loads((BASE/'bmc_backend_inventory.json').read_text())['files']))
    rows=[]; scanned=0
    for offset in offsets:
        with SquashFsImage.from_file(str(SOURCE), offset=offset) as fs:
            for item in fs:
                if not item.is_file: continue
                data=item.read_bytes(); scanned+=1
                hits=[]
                for needle in NEEDLES:
                    pos=[m.start() for m in re.finditer(re.escape(needle),data)]
                    if pos: hits.append({'needle':needle.decode(),'offsets':pos})
                if not hits and item.path not in EXPLICIT: continue
                # Preserve relevant native libs/startup scripts; generic language
                # assets are inventoried only and cannot influence ELF replay.
                relevant = (item.path.startswith('/etc/') or item.path.startswith('/usr/local/'))
                output=None
                if relevant:
                    dest=(HERE/'official_inputs'/str(offset)/item.path.lstrip('/')).resolve()
                    assert dest.is_relative_to((HERE/'official_inputs').resolve())
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    if dest.exists(): assert dest.read_bytes()==data
                    else: dest.write_bytes(data)
                    output=str(dest.relative_to(HERE))
                strings=[{'offset':hex(m.start()),'text':m.group().decode('ascii')} for m in re.finditer(rb'[\x20-\x7e]{5,}',data)
                         if any(n in m.group() for n in NEEDLES)]
                rows.append({'path':item.path,'filesystem_offset':offset,'bytes':len(data),'sha256':sha(data),'hits':hits,'output':output,'matching_strings':strings})
    out={'source':str(SOURCE),'sha256':PIN,'regular_files_scanned':scanned,'filesystems':offsets,'files':rows,
         'limits':'Static shipped regular-file bytes. Does not observe live processes, runtime configfs/sysfs/tmpfs, network packets or running BMC backend identity.'}
    (HERE/'official_scan.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
    print(json.dumps({'scanned':scanned,'matched':len(rows),'files':[{'path':r['path'],'needles':[h['needle'] for h in r['hits']]} for r in rows]},indent=2))
if __name__=='__main__': main()
