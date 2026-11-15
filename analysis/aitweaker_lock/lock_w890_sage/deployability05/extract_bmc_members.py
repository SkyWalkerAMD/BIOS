"""Extract only named regular members for offline update-policy inspection."""
from pathlib import Path
import hashlib,json,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SEVEN=ROOT/'tools/7zip-26.04/7z.exe'
MEMBERS={
 'squashfs_00510000.bin':[
  'usr/local/lib/libcompamibios.so.13.3.0',
  'usr/local/lib/libipmihpm.so.13.36.0',
  'usr/local/lib/libflash.so.13.37.0',
  'usr/local/lib/libspx_restservice.so.13.22.0',
  'usr/local/lib/libipmipdk.so.13.39.0',
  'usr/local/lib/libipmipdkapi.so.13.4.0',
  'usr/local/lib/libpdkapp.so.13.19.0',
  'usr/local/lib/libhosthelper.so.13.7.0',
  'usr/local/lib/libcomponent_manager.so.13.23.0',
  'etc/core_features',
  'usr/local/bin/spx_restservice',
  'usr/local/bin/flasher',
  'usr/local/lib/hpm.conf',
  'usr/local/lib/HPM_Conf.h',
 ],
 'squashfs_02cb0000.bin':['source.min.js']}

def main():
    out=HERE/'backend_inputs';out.mkdir(exist_ok=True)
    report=[]
    for carrier,names in MEMBERS.items():
        for name in names:
            listing=(HERE/carrier).with_suffix('.listing.txt').read_text(encoding='utf-8-sig')
            windows=name.replace('/','\\')
            block=next((b for b in listing.split('\n\n') if '\nPath = '+windows+'\n' in '\n'+b+'\n'),None)
            if block is None or 'Symbolic Link =' in block: raise ValueError('Missing/non-regular selected member '+name)
            r=subprocess.run([str(SEVEN),'e','-so',str(HERE/carrier),windows],capture_output=True,timeout=60)
            if r.returncode: raise ValueError(r.stderr.decode('utf-8','replace'))
            target=out/Path(name).name
            if target.exists():
                if target.read_bytes()!=r.stdout: raise ValueError('Existing extraction differs '+str(target))
            else: target.write_bytes(r.stdout)
            report.append({'carrier':carrier,'member':name,'path':str(target.resolve()),'bytes':len(r.stdout),'sha256':hashlib.sha256(r.stdout).hexdigest()})
    (HERE/'backend_inputs.json').write_text(json.dumps({'extractions':report,'execution':False,'hardware_access':False},indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))

if __name__=='__main__': main()
