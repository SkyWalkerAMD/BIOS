"""Prepare an isolated optical packager for the browser baseline, locally only."""
from pathlib import Path
import hashlib, json
HERE=Path(__file__).resolve().parent
D04=HERE.parents[1]/'native13_split_candidate/installer_design04'
SOURCE=D04/'ram_test05_delivery/package_app.py'
OUT=D04/'browser_baseline06_delivery'
raw=SOURCE.read_bytes()
if hashlib.sha256(raw).hexdigest()!='7cbce850c3c85fdf996508f3748b9a60fe7367e16efa7651596aa894f5c58ddd':
    raise ValueError('Original packager changed')
text=raw.decode()
for old,new in [
    ('RAM_TEST05','BROWSER_BASELINE06'),
    ('ram_transaction05/app_build','readonly_browser_baseline06/build'),
    ('SageNative13RamTest05.efi','SageNative13BrowserBaseline06.efi'),
    ('SAGERAM05','SAGEBR06'),
    ('SAGE-N13-RAMTEST05-NOFLASH.iso','SAGE-N13-BROWSER06-NOFLASH.iso'),
    ('SAGE_N13_RAM05','SAGE_N13_BR06'),
]:
    if old not in text: raise ValueError(f'Missing source marker {old}')
    text=text.replace(old,new)
OUT.mkdir(exist_ok=True)
target=OUT/'package_app.py'
data=text.encode()
if target.exists():
    if target.read_bytes()!=data:raise FileExistsError('New packager already changed')
else:
    with target.open('xb') as f:f.write(data)
report={'scope':'Local packager preparation only; no EFI built or device touched',
        'source':str(SOURCE),'source_sha256':hashlib.sha256(raw).hexdigest(),
        'packager':str(target),'packager_sha256':hashlib.sha256(data).hexdigest()}
report['transport_test_derivation']=[]
for name in ['build_transport_boundary.py','transport_boundary_support.c','verify_transport_boundary.py','smoke_iso.py']:
    oldfile=SOURCE.parent/name
    original=oldfile.read_bytes()
    text=original.decode().replace('ram_transaction05/source/transport','readonly_browser_baseline06/source/transport').replace('SAGE_NATIVE13_RAM_TEST05','SAGE_NATIVE13_BROWSER_BASELINE06')
    if name=='smoke_iso.py':
        for old,new in [
            ('RAM_TEST05','BROWSER_BASELINE06'),
            ('read_native13_ram_test05_qr.py','read_native13_browser_baseline06_qr.py'),
            ('ram05_actual_decoder','browser06_actual_decoder'),
            ('MODE=0000000000000000','BROWSER_ATTEMPTED=0000000000000000'),
            ('OPERATION_ID=0000000000000000','BASELINE_RETURN_ACCEPTED=0000000000000000'),
            ("qmp.key('1');qmp.key('2')", "qmp.key('b');qmp.key('m')"),
            ('Keys 1 and 2 ignored on unsupported platform; operation ID and journal unchanged',
             'Browser B and unsupported M ignored on unsupported platform; attempt flag and journal unchanged'),
            ('Refused transaction keys changed the journal','Refused browser keys changed the journal'),
            ('No ASUS modules, native installation, password UI, physical disks, NIC or BMC attached.',
             'No ASUS modules, native SendForm, password UI, physical disks, NIC or BMC attached.'),
        ]:
            if old not in text:raise ValueError(f'Missing smoke marker {old}')
            text=text.replace(old,new)
    data=text.encode()
    newfile=OUT/name
    if newfile.exists():
        if newfile.read_bytes()!=data:raise FileExistsError(f'Changed existing test: {newfile.name}')
    else:
        with newfile.open('xb') as f:f.write(data)
    report['transport_test_derivation'].append({'source':str(oldfile),'source_sha256':hashlib.sha256(original).hexdigest(),'output':str(newfile),'output_sha256':hashlib.sha256(data).hexdigest()})
(OUT/'packager_derivation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
