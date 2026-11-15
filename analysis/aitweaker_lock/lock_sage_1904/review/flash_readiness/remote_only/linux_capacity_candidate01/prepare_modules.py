"""Extract only a fixed module whitelist from an already acquired local SquashFS."""
from pathlib import Path
import hashlib,json,struct,subprocess
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OFF=HERE/'official';DEST=HERE/'modules';DEST.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
acq=json.loads((OFF/'acquisition.json').read_text())
assert acq['checksum_matched'] and acq['sha256']=='5d45d36ad44ebbea5fd97123b409b7b4227afa5f89d25be5c5366a572555aac2'
expected={x['name']:x['sha256'] for x in acq['selected_regular_files']}
assert sha(OFF/'modloop-lts')==expected['modloop-lts']
seven=ROOT/'tools/7zip-26.04/7z.exe'
listing=subprocess.run([str(seven),'l','-slt',str(OFF/'modloop-lts')],capture_output=True,text=True,encoding='utf8',check=True).stdout
selected=['usb-common.ko','usbcore.ko','xhci-hcd.ko','xhci-pci.ko','scsi_common.ko','scsi_mod.ko','sg.ko','usb-storage.ko']
rows=[];matches={}
for block in listing.split('\n\n'):
    row=dict(line.split(' = ',1) for line in block.splitlines() if ' = ' in line);path=row.get('Path','');name=path.rsplit('\\',1)[-1]
    if name in selected:
        assert name not in matches and row['Folder']=='-' and 0<int(row['Size'])<5*1024*1024
        matches[name]=row
assert set(matches)==set(selected)
for name in selected:
    row=matches[name];data=subprocess.run([str(seven),'e','-so','-bd','-y',str(OFF/'modloop-lts'),row['Path']],capture_output=True,check=True).stdout
    assert len(data)==int(row['Size']) and data[:6]==b'\x7fELF\x02\x01'
    shoff=struct.unpack_from('<Q',data,40)[0];ents,num,ss=struct.unpack_from('<HHH',data,58)
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*ents) for i in range(num)]
    shstr=data[headers[ss][4]:headers[ss][4]+headers[ss][5]]
    sec=[h for h in headers if shstr[h[0]:].split(b'\0',1)[0]==b'.modinfo'];assert len(sec)==1;h=sec[0]
    fields=[x.decode('ascii') for x in data[h[4]:h[4]+h[5]].split(b'\0') if x]
    def one(key):
        values=[x.split('=',1)[1] for x in fields if x.startswith(key+'=')];assert len(values)==1;return values[0]
    info={'name':one('name'),'filename':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'archive_path':row['Path'],
      'vermagic':one('vermagic'),'depends':[x.replace('-','_') for x in one('depends').split(',')] if one('depends') else [],'softdep':[x for x in fields if x.startswith('softdep=')]}
    assert info['vermagic'].startswith('6.12.114-0-lts ')
    (DEST/name).write_bytes(data);rows.append(info)
names={r['name'] for r in rows}
assert all(set(r['depends'])<=names for r in rows),'Unreviewed module dependency: '+repr({r['name']:sorted(set(r['depends'])-names) for r in rows if set(r['depends'])-names})
for n in ['modules.dep','modules.builtin']:
    path='modules\\6.12.114-0-lts\\'+n
    data=subprocess.run([str(seven),'e','-so','-bd','-y',str(OFF/'modloop-lts'),path],capture_output=True,check=True).stdout
    (HERE/'review/reference'/n).write_bytes(data)
report={'status':'FIXED_LOCAL_MODULE_WHITELIST_EXTRACTED','modloop_sha256':sha(OFF/'modloop-lts'),'seven_zip_sha256':sha(seven),'modules':rows,
  'scope':'Only eight exact ELF module files selected. No module loaded/executed, no full module tree or stock init copied. A previously inspected optional Renesas module may exist in the local staging directory but is excluded from the initramfs manifest.',
  'excluded':['xhci_pci_renesas','sd_mod','sr_mod','uas','ata/ahci','nvme','network','hid','mtd/spi controllers','efivarfs','storage filesystems','stock init/udev/mdev/modprobe']}
(HERE/'modules.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps({'modules':[{'name':r['name'],'depends':r['depends'],'bytes':r['bytes']} for r in rows],'total_bytes':sum(r['bytes'] for r in rows)},indent=2))
