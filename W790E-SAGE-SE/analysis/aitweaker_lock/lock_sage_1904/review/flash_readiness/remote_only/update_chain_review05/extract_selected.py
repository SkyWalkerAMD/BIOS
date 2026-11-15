"""Scan pinned official image for feature configuration provenance; no devices."""
from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage
SOURCE=BASE/'official_bmc/W7901157.ima'
PIN='0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
NEEDLES=[b'/var/tmp/libfeature',b'CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT',b'core_features',b'IniLoadFile']
EXPLICIT={'/etc/init.d/compmngr','/usr/local/bin/compmanager','/usr/local/bin/featuredef',
          '/etc/core_features','/etc/init.d/mountall.sh','/etc/init.d/mountall_dual.sh',
          '/etc/init.d/bootmisc.sh','/etc/init.d/mountkernfs.sh','/etc/init.d/mountdevsubfs.sh'}
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    assert sha(SOURCE.read_bytes())==PIN
    inventory=json.loads((BASE/'bmc_backend_inventory.json').read_text())
    offsets=sorted(set(x['filesystem_offset'] for x in inventory['files']))
    rows=[];count=0
    for offset in offsets:
        with SquashFsImage.from_file(str(SOURCE),offset=offset) as fs:
            for item in fs:
                if not item.is_file: continue
                # All regular members are scanned locally, with only matching
                # files/explicit startup artifacts materialized in this new dir.
                data=item.read_bytes(); count+=1
                hits=[]
                for needle in NEEDLES:
                    pos=[m.start() for m in re.finditer(re.escape(needle),data)]
                    if pos:hits.append({'needle':needle.decode(),'offsets':pos})
                if hits or item.path in EXPLICIT or ('ini' in item.path.lower() and item.path.startswith('/usr/local/lib/lib')):
                    dest=(HERE/'official_inputs'/str(offset)/item.path.lstrip('/')).resolve()
                    assert dest.is_relative_to((HERE/'official_inputs').resolve())
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    if dest.exists():assert dest.read_bytes()==data
                    else:dest.write_bytes(data)
                    rows.append({'path':item.path,'filesystem_offset':offset,'bytes':len(data),'sha256':sha(data),'hits':hits,'output':str(dest.relative_to(HERE))})
    report={'source':str(SOURCE),'sha256':PIN,'scanned_regular_files':count,'filesystems':offsets,'selected':rows,
            'scope':'Static official regular-file contents only; does not inventory runtime tmpfs or running processes.'}
    (HERE/'official_input_manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'scanned':count,'selected':len(rows),'matches':[{'path':x['path'],'hits':[h['needle'] for h in x['hits']]} for x in rows if x['hits']]},indent=2))
if __name__=='__main__':main()
