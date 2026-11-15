"""Package the tested R6f artifacts and selected evidence; no sessions/secrets."""
from pathlib import Path
import hashlib, json, zipfile

BASE=Path(__file__).resolve().parent
LIVE=BASE.parent/'hero_remote_bios_r6_live_20261103'
build=json.loads((BASE/'build.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert build['version']=='R6f'
assert sha(BASE/'HERO-REMOTE-BIOS-R6.iso')==build['iso_sha256']
for name,record in build['artifacts'].items():
    assert sha(BASE/'USB/EFI/BOOT'/name)==record['sha256']
for name,digest in build['sources'].items():
    assert sha(BASE/'source'/name)==digest, name
for name in ['network-tests.json','tcp-tests.json','rndis-gate-tests.json','vm/result.json','vm-usb/result.json']:
    assert json.loads((BASE/name).read_text())['passed']
live=json.loads((LIVE/'live-verification.json').read_text())
assert live['internal_usb_network']['tcp443_connect_success']
assert live['final']['virtual_cd_unmounted'] and live['final']['bmc_logout_confirmed']

files={}
def add(path,dest):
    assert path.is_file() and dest not in files
    files[dest]=path
def folder(path,dest):
    for p in sorted(path.rglob('*')):
        if p.is_file():add(p,dest+'/'+p.relative_to(path).as_posix())

for name in ['HERO-REMOTE-BIOS-R6.iso','操作说明-R6f.txt','远程BIOS配置R6实机结果-20261103.txt','build.json']:
    add(BASE/name,name)
folder(BASE/'USB','USB')
folder(BASE/'source','source')
folder(BASE/'staged-drivers','staged-drivers')
for name in ['build.py','prepare_usb_drivers.py','test_network.py','test_network.c','test_tcp.py','test_tcp.c','test_rndis_gate.py','run_vm.py','decode_captures.py','package.py']:
    add(BASE/name,name)
for name in ['network-tests.json','tcp-tests.json','rndis-gate-tests.json','vm/result.json','vm-usb/result.json']:
    add(BASE/name,'verification/'+name)
for name in ['live-verification.json','R6-inventory.TXT','R6b-usb.TXT','R6c-drivers.TXT','R6d-http.TXT','R6e-https.TXT','R6f-tcp.TXT']:
    add(LIVE/name,'hardware/'+name)
folder(LIVE/'captures/R6f-tcp','hardware/R6f-tcp-captures')
for name in ['106-key-Enter.png','150-key-H.png','190-key-H.png','226-key-Enter.png','229-key-D.png','230-key-T.png','258-key-Q.png','263-capture.png','266-key-Enter.png']:
    add(LIVE/'screens'/name,'hardware/screens/'+name)
for name in ['usb-driver-origin.json','hero-tls-origin.json','hero-bmc-public-cert.json','sources.json']:
    add(BASE/'reference'/name,'reference/'+name)
for name in ['Http.h','HttpImpl.c','HttpsSupport.c','Ip4Config2.h','ServiceBinding.h','SimpleNetwork.h','Tcp4.h','Tls.h','TlsAuthentication.h','UsbIo.h']:
    add(BASE/'reference'/name,'reference/'+name)
for name in ['11E32C34-60B5-4991-8DEA-63D3E8C876DE.efi','CA6EB4F4-F1D6-4375-97D6-18856871E1BF.efi']:
    add(BASE/'reference'/name,'reference/'+name)
for name in ['003-entry-body.c','009-ca-path.c','010-ca-caller.c']:
    add(BASE/'rea-https/responses'/name,'reference/rea/'+name)

manifest={name:{'bytes':p.stat().st_size,'sha256':sha(p)} for name,p in sorted(files.items())}
dest=BASE.parent/'HERO-3107-REMOTE-BIOS-R6f.zip'
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for name,p in sorted(files.items()):z.write(p,name)
    z.writestr('SHA256.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
with zipfile.ZipFile(dest) as z:
    assert z.testzip() is None
    for name,row in manifest.items():assert hashlib.sha256(z.read(name)).hexdigest()==row['sha256']
result={'zip':str(dest),'bytes':dest.stat().st_size,'sha256':sha(dest),'files':len(files)+1,'iso_sha256':build['iso_sha256'],'revision':'R6f','hardware_verified':'RAM USB network and TCP443 only; HTTPS and native remote BIOS apply incomplete'}
(BASE/'delivery.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
