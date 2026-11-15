"""Read pinned official BMC boot override source; no device access."""
from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage
SOURCE=BASE/'official_bmc/W7901157.ima'
PIN='0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
sha=lambda b:hashlib.sha256(b).hexdigest()
NEEDLES=[b'BootSourceOverride',b'BootFlags',b'SetSystemBootOptions',b'SystemBootOptions',b'BootOrderPropertySelection']
def main():
    assert sha(SOURCE.read_bytes())==PIN
    inv=json.loads((BASE/'bmc_backend_inventory.json').read_text())
    rows=[];count=0
    for offset in sorted(set(x['filesystem_offset'] for x in inv['files'])):
        with SquashFsImage.from_file(str(SOURCE),offset=offset) as fs:
            for item in fs:
                if not item.is_file or not item.path.endswith(('.lua','.rcmd','.json')):continue
                count+=1;data=item.read_bytes();hits=[n.decode() for n in NEEDLES if n in data]
                if not hits:continue
                p=(HERE/'official_inputs'/str(offset)/item.path.lstrip('/')).resolve()
                assert p.is_relative_to((HERE/'official_inputs').resolve())
                p.parent.mkdir(parents=True,exist_ok=True)
                if p.exists():assert p.read_bytes()==data
                else:p.write_bytes(data)
                rows.append({'path':item.path,'filesystem_offset':offset,'bytes':len(data),'sha256':sha(data),'hits':hits,'output':str(p.relative_to(HERE))})
    out={'source':str(SOURCE),'sha256':PIN,'regular_lua_rcmd_json_scanned':count,'files':rows}
    (HERE/'official_scan.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'selected':len(rows),'files':[{k:x[k] for k in ('path','bytes','hits')} for x in rows]},indent=2))
if __name__=='__main__':main()
