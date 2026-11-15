"""Read-only independent ElTorito/FAT, exact EFI and raw OVMF QR verification."""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;DEL=D04/'ram_test09_delivery'
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
sys.path[:0]=[str(ROOT/'tools/kvm-pydeps'),str(ROOT/'tools/pydeps')]
from PIL import Image
import zxingcpp,pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
FINAL='3a1def1697c50d1a61b20fc205539fca24107d12891d62b2e971dd6ccde7d1b9'
ISO='05dccec80c7ae1c831abc39dd5e0633a0d411584dd020a646cd2642195686d3d'
bindings={}
def bind(p):
 p=Path(p).resolve();assert p.is_relative_to(ROOT);rel=str(p.relative_to(ROOT)).replace('\\','/')
 bindings[rel]={'path':rel,'bytes':p.stat().st_size,'sha256':sha(p)};return p
def qr(png,frame=None):
 code=zxingcpp.read_barcodes(Image.open(png));assert len(code)==1
 raw=bytes(code[0].bytes);head,payload=raw.split(b'\n\n',1)
 m=re.fullmatch(rb'AITWK-P3-KVM\nT=(\d+);C=([0-9A-F]{8});P=(\d+)/(\d+);O=(\d+);N=(\d+);D=([0-9A-F]{8})',head);assert m
 total,crc,page,pages,offset,length,pcrc=m.groups();total,page,pages,offset,length=map(int,[total,page,pages,offset,length])
 assert page==pages==1 and offset==0 and total==length==len(payload)
 actual=f'{zlib.crc32(payload)&0xffffffff:08X}'.encode();assert crc==pcrc==actual
 if frame:assert raw==frame.read_bytes()
 assert payload.startswith(b'AITWK-P3-KVM\r\nSAGE_NATIVE13_RAM_TEST09\r\n')
 assert payload.count(b'SAGE_NATIVE13_RAM_TEST09_END\r\n')==1 and payload.endswith(b'SAGE_NATIVE13_RAM_TEST09_END\r\n')
 for text in [b'MODE=0000000000000000\r\n',b'OPERATION_ID=0000000000000000\r\n',b'FAIL exact SAGE SE 1904 SMBIOS\r\n',b'FAIL complete initial original identity and boot context\r\n',b'LOG_OVERFLOW=NO\r\n',b'LOG_COMPLETE=YES\r\n']:
  assert payload.count(text)==1
 assert b'ACTION='not in payload
 ids=re.findall(rb'SNAPSHOT_ID=([0-9A-F]{16})\r\n',payload);assert len(ids)==1
 return payload,{'pages':pages,'bytes':total,'crc32':actual.decode(),'sha256':hashlib.sha256(payload).hexdigest(),'snapshot_id':ids[0].decode()}
def main():
 # The two pure raw parsers are reused unmodified from the frozen independent
 # TX05 audit. Import has no main execution and does not inspect its old inputs.
 parser_source=D04/'ram_test05_delivery_review/verify_delivery.py';parser_copy=HERE/'iso_parser_snapshot.py'
 parser_copy.write_bytes(parser_source.read_bytes());bind(parser_source);bind(parser_copy)
 spec=importlib.util.spec_from_file_location('frozen_raw_iso_parser',parser_copy);parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
 package=DEL/'packages'/FINAL[:16]/'package.json';info=json.loads(package.read_text());run=DEL/'ovmf/20261104_001716';result=json.loads((run/'result.json').read_text())
 for base in [package.parent,run]:
  for p in base.rglob('*'):
   if p.is_file():bind(p)
 efi=Path(info['efi']);iso=Path(info['iso']);fat=Path(info['boot_image']);raw=efi.read_bytes()
 assert sha(efi)==info['efi_sha256']==result['efi_sha256']==FINAL
 assert sha(iso)==info['iso_sha256']==result['iso_sha256']==ISO
 assert sha(fat)==info['boot_image_sha256']=='5ccb06b7ddce9a0685502ee6b6bf706ec610ab3dece358adb090abcdd6f3df8a'
 assert sha(package)==result['package_sha256'] and len(raw)==info['efi_bytes']==187904 and iso.stat().st_size==16842752
 assert Path(info['source_efi']).read_bytes()==raw
 assert info['hardware_execution']is False and info['firmware_release_ready']is False
 assert result['status']=='PASS_EXACT_ISO_OVMF_REFUSAL_AND_QR_TRANSPORT' and result['error']is None and result['qemu_exit_code']==0 and result['input_images_unchanged']is True
 pe=pefile.PE(data=raw);assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
 for i in [1,4,13]:assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].VirtualAddress
 assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0 and pe.verify_checksum()
 assert all((s.Characteristics&0xa0000000)!=0xa0000000 for s in pe.sections)
 argv=json.loads((run/'command.json').read_text());assert argv.count('-nic')==1 and argv[argv.index('-nic')+1]=='none'
 assert not any(x in argv for x in ['-net','-netdev','-hda','-hdb','-hdd','-device','-kernel','-initrd'])
 drives=[argv[i+1]for i,x in enumerate(argv)if x=='-drive'];share=ROOT/'tools/qemu-11.1.0/share'
 assert drives==['if=pflash,format=raw,unit=0,readonly=on,file='+str(share/'edk2-x86_64-code.fd'),'if=pflash,format=raw,unit=1,file='+str(run/'vars.fd'),'media=cdrom,readonly=on,file='+str(iso)]
 assert argv[argv.index('-qmp')+1]=='stdio'and argv[argv.index('-monitor')+1]=='none'
 pairs=[]
 for p in run.rglob('*.png'):
  ppm=p.with_suffix('.ppm');assert ppm.is_file();a,b=Image.open(p),Image.open(ppm)
  assert a.size==b.size and a.convert('RGB').tobytes()==b.convert('RGB').tobytes();pairs.append(str(p.relative_to(run)))
 snapshots=[];payloads=[]
 for label in ['snapshot1','snapshot2']:
  sub=run/label;payload,record=qr(sub/'page-01.png',sub/'page-01.frame');assert payload==(sub/'hardware-log.txt').read_bytes()
  saved=next(x for x in result['snapshots']if x['label']==label)
  for k,v in record.items():assert saved[k]==v,(k,saved[k],v)
  snapshots.append(record);payloads.append(payload)
 assert snapshots[0]['snapshot_id']!=snapshots[1]['snapshot_id']
 assert re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',payloads[0])==re.sub(rb'SNAPSHOT_ID=[0-9A-F]{16}',b'SNAPSHOT_ID=ID',payloads[1])
 assert qr(run/'qr-return.png')[0]==payloads[0] and qr(run/'refusal-after-keys.png')[0]==payloads[1]
 for p in run.glob('probe-qr-*.png'):assert qr(p)[0]==payloads[0]
 for snapshot,live,key,obj in [(package.parent/'packager-snapshot.py',DEL/'package_app.py','packager_sha256',info),(run/'runner-snapshot.py',DEL/'smoke_iso.py','runner_sha256',result),(run/'decoder-snapshot.py',ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/read_native13_ram_test09_qr.py','decoder_sha256',result)]:
  assert sha(bind(snapshot))==sha(bind(live))==obj[key]
 for p in [ROOT/'tools/qemu-11.1.0/qemu-system-x86_64.exe',share/'edk2-x86_64-code.fd',share/'edk2-i386-vars.fd',Path(__file__)]:bind(p)
 output={'status':'PASS_INDEPENDENT_RAW_ISO_FAT_PE_AND_OVMF_QR_BINDING','efi_sha256':FINAL,'iso_sha256':ISO,'package_sha256':sha(package),'smoke_result_sha256':sha(run/'result.json'),'fat':parser.fat_audit(fat.read_bytes(),raw),'eltorito':parser.iso_audit(iso.read_bytes(),fat.read_bytes()),'pe_checksum_valid':True,'no_import_delayimport_security_directory':True,'no_pe_rwx_sections':True,'png_ppm_pairs':len(pairs),'snapshots':snapshots,'qemu_exit_code':0,'bindings':list(bindings.values()),'limitations':['Uses two unmodified raw filesystem parsers from a preserved earlier audit; no pycdlib/pyfatfs parsing is used in this independent pass.','OVMF log bytes were recovered again directly from PNG pixels; no ASUS identity or SendForm positive case is inferred.','Only the per-run OVMF VAR file was writable; NIC and host disks were absent in the recorded command.','PE section flags do not establish runtime page W^X.','No device action, firmware flash or release acceptance.']}
 out=HERE/'delivery_review.json';out.write_text(json.dumps(output,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':output['status'],'png_ppm_pairs':len(pairs),'bindings':len(bindings),'sha256':sha(out)}))
if __name__=='__main__':main()
