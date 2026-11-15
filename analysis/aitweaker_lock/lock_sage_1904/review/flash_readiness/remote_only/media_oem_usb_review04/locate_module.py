"""Select original ASUS USB storage modules by embedded protocol GUIDs/strings."""
from pathlib import Path
import hashlib,json,re,sys,uuid
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
CAP=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
EXPECTED='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
USB=uuid.UUID('2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75').bytes_le
BLOCK=uuid.UUID('964e5b21-6459-11d2-8e39-00a0c969723b').bytes_le

def main():
    assert hashlib.sha256(CAP.read_bytes()).hexdigest()==EXPECTED
    dump=Path(str(CAP)+'.dump')/'0 Intel image/3 BIOS region'
    images=sorted(dump.rglob('*PE32 image section/body.bin'));assert len(images)<2048
    candidates=[]
    for p in images:
        raw=p.read_bytes();usb=USB in raw;block=BLOCK in raw
        selected=(usb and block) or any(g in str(p).upper() for g in ['171F43DC-C4D9-47A6-9641-65DDCDD5AA30','04EAAAA1-29A1-11D7-8838-00500473D4EB'])
        ascii_strings=[m.group().decode('ascii') for m in re.finditer(rb'[\x20-\x7e]{6,}',raw)]
        names=[s for s in ascii_strings if re.search(r'usb.*(mass|storage)|amiusb|usb.*\.pdb',s,re.I)]
        if not selected and not names:continue
        pe=pefile.PE(data=raw);owner=p.parent.parent
        info=(owner/'info.txt').read_text()
        match=re.search(r'File GUID: ([0-9A-F-]+)',info);guid=match.group(1) if match else 'unknown'
        target=HERE/(guid+'.efi');target.write_bytes(raw)
        ex=[{'begin':hex(e.struct.BeginAddress),'end':hex(e.struct.EndAddress),'unwind':hex(e.struct.UnwindData)} for e in getattr(pe,'DIRECTORY_ENTRY_EXCEPTION',[])]
        candidates.append({'source':str(p.relative_to(ROOT)),'owner_info':info,'target':target.name,'sha256':hashlib.sha256(raw).hexdigest(),
                           'bytes':len(raw),'USB_IO_GUID':usb,'BLOCK_IO_GUID':block,'matched_strings':names,
                           'entry':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'image_base':hex(pe.OPTIONAL_HEADER.ImageBase),
                           'exception_functions':ex})
    out={'source_CAP':str(CAP.relative_to(ROOT)),'source_CAP_sha256':EXPECTED,'PE_images_checked':len(images),'candidates':candidates}
    (HERE/'module_candidates.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({'PE_images_checked':len(images),'candidates':[{k:v for k,v in x.items() if k not in ['owner_info','exception_functions']} for x in candidates]},indent=2))
if __name__=='__main__':main()
