"""Fetch one public vendor BMC artifact for OFFLINE analysis only.

No connection to the user's BMC; no downloaded code is executed.
Version and SHA256 are taken from the already captured vendor support page.
"""
from pathlib import Path
import hashlib, json, re, urllib.request, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SNAPSHOT = ROOT / 'analysis/workstation_20261008/asus_w890_bios.html'
URL = 'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4710/Pro_WS_W890E-SAGE_SE/W890-ASUS-2.1.11.zip'
DEST = HERE / 'W890-ASUS-2.1.11.zip'

def bind(p):
    b=p.read_bytes()
    return {'path':str(p.resolve()),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    text=SNAPSHOT.read_text(encoding='utf-8')
    path='/pub/ASUS/mb/LGA4710/Pro_WS_W890E-SAGE_SE/W890-ASUS-2.1.11.zip'
    start=text.index('"'+path+'"')
    match=re.search(r'"([A-Fa-f0-9]{64})"',text[start+len(path):start+len(path)+400])
    if match is None: raise ValueError('No vendor SHA256 adjacent to the selected exact download')
    expected=match[1].lower()
    if not DEST.exists():
        temp=DEST.with_suffix('.zip.part')
        req=urllib.request.Request(URL,headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req,timeout=45) as source, temp.open('wb') as target:
            total=0
            while chunk:=source.read(1024*1024):
                total+=len(chunk)
                if total>80*1024*1024: raise ValueError('Download exceeds 80 MiB bound')
                target.write(chunk)
        if bind(temp)['sha256']!=expected: raise ValueError('Download SHA256 does not match vendor snapshot')
        temp.rename(DEST)
    actual=bind(DEST)
    if actual['sha256']!=expected: raise ValueError('Existing download does not match vendor SHA256')
    with zipfile.ZipFile(DEST) as z:
        if z.testzip() is not None: raise ValueError('ZIP CRC failed')
        members=[{'name':i.filename,'bytes':i.file_size,'compressed':i.compress_size} for i in z.infolist()]
    report={'purpose':'offline BMC update-policy analysis; no hardware access or target execution',
            'url':URL,'vendor_snapshot':bind(SNAPSHOT),'expected_sha256':expected,'download':actual,
            'members':members,'version_attribution':'package 2.1.11; not a dump of installed BMC 2.01.11',
            'hardware_actions':0}
    (HERE/'bmc_download.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'download':actual,'members':members},ensure_ascii=False))

if __name__=='__main__': main()
