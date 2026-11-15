"""Read pinned official BMC files for supported manager-only reset paths."""
from pathlib import Path
import hashlib,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage
SOURCE=BASE/'official_bmc/W7901157.ima'
PIN='0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
NEEDLES=[b'Manager.Reset',b'ForceRestart',b'GracefulRestart',b'ResetType',b'BMCReset',b'BmcReset',
         b'bmc_reset',b'reset_bmc',b'ColdReset',b'WarmReset',b'BMCReboot',b'bmc-reboot']
EXPLICIT={'/usr/local/redfish/redfish/manager.lua','/usr/local/redfish/redfish/manager/manager_utils.lua',
          '/usr/local/redfish/db_init/managers.rcmd'}
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
    assert sha(SOURCE.read_bytes())==PIN
    offsets=sorted(set(x['filesystem_offset'] for x in json.loads((BASE/'bmc_backend_inventory.json').read_text())['files']))
    rows=[];count=0
    for offset in offsets:
        with SquashFsImage.from_file(str(SOURCE),offset=offset) as fs:
            for item in fs:
                if not item.is_file:continue
                count+=1;data=item.read_bytes();hits=[]
                for needle in NEEDLES:
                    pos=[m.start() for m in re.finditer(re.escape(needle),data)]
                    if pos:hits.append({'needle':needle.decode(),'offsets':pos})
                if not hits and item.path not in EXPLICIT:continue
                output=None
                if item.path.startswith(('/usr/local/','/etc/')):
                    dest=(HERE/'official_inputs'/str(offset)/item.path.lstrip('/')).resolve()
                    assert dest.is_relative_to((HERE/'official_inputs').resolve())
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    if dest.exists():assert dest.read_bytes()==data
                    else:dest.write_bytes(data)
                    output=str(dest.relative_to(HERE))
                rows.append({'path':item.path,'filesystem_offset':offset,'bytes':len(data),'sha256':sha(data),'hits':hits,'output':output})
    result={'source':str(SOURCE),'sha256':PIN,'regular_files_scanned':count,'filesystems':offsets,'files':rows,
            'scope':'Pinned official files only. No connection, live configuration read or reset request.'}
    (HERE/'official_scan.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({'scanned':count,'selected':len(rows),'files':[{'path':x['path'],'hits':[h['needle'] for h in x['hits']]} for x in rows]},indent=2))
if __name__=='__main__':main()
