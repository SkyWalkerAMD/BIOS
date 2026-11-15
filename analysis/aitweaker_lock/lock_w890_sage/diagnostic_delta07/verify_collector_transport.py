"""Replay actual new collector logs through frozen native QR encoder+decoder."""
from pathlib import Path
import ctypes as C,hashlib,json,re,struct,zlib
from verify_transport import dll,Image,read_image,assemble
from decode_log import decode_log
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';checks=[]
def check(name):checks.append({'case':name,'passed':True})
def main():
 cases=[('lab_complete',OUT/'lab/efi_cases/spf_complete.txt',OUT/'lab/SYNTHETIC-selection.json'),('lab_budget',OUT/'lab_huge/efi_cases/huge_socket.txt',OUT/'lab_huge/SYNTHETIC-selection.json'),('fixed_refusal',OUT/'efi_cases/shipping_refuses_synthetic.txt',HERE/'selection_hardware02.json')];reports=[]
 for name,path,selection_path in cases:
  log=path.read_bytes();selection=json.loads(selection_path.read_text());decoded=decode_log(log,selection);folder=OUT/'collector_qr'/name;folder.mkdir(parents=True,exist_ok=True);frames=[]
  for page in range((len(log)+767)//768):
   q=C.create_string_buffer(4096);temp=C.create_string_buffer(4096);assert dll.kvm_encode_frame(log,len(log),page,q,temp)==1
   modules=dll.qrcodegen_getSize(q);im=Image.new('1',((modules+8)*4,)*2,1);pixels=im.load()
   for y in range(modules):
    for x in range(modules):
     if dll.qrcodegen_getModule(q,x,y):
      for dy in range(4):
       for dx in range(4):pixels[(x+4)*4+dx,(y+4)*4+dy]=0
   image=folder/f'qr-{page+1:03}.png';im.save(image);frames.append(read_image(image))
  restored,meta=assemble(frames);assert restored==log;again=decode_log(restored,selection)
  assert again['spf']==decoded['spf'] and again['omitted']==decoded['omitted'] and again['refused']==decoded['refused']
  for i,obj in again['objects'].items():assert obj['forms']==decoded['objects'][i]['forms']
  (folder/'RESTORED-LOG.TXT').write_bytes(restored);reports.append({'name':name,'bytes':len(log),'pages':len(frames),'crc32':f'{zlib.crc32(log):08X}','sha256':hashlib.sha256(log).hexdigest(),'qr':meta});check(name+'_actual_QR_full_roundtrip')
  try:assemble(frames[:-1])
  except ValueError:check(name+'_missing_page_rejected')
  else:raise AssertionError('missing page accepted')
 full=cases[0][1].read_bytes();selection=json.loads(cases[0][2].read_text())
 def reject(name,data):
  try:decode_log(data,selection)
  except ValueError:check(name);return
  raise AssertionError('accepted '+name)
 reject('map_refused_with_complete_spf',full.replace(b'MAP=READY',b'MAP=REFUSED'))
 reject('duplicate_tse_with_complete_spf',full.replace(b'TSE_COUNT=1',b'TSE_COUNT=2'))
 reject('false_incomplete_spf',full.replace(b'E=COMPLETE_OBSERVATION',b'E=INCOMPLETE_OBSERVATION'))
 reject('unavailable_spf_with_valid_fields',full.replace(b'E=COMPLETE_OBSERVATION',b'E=MODULE_UNAVAILABLE'))
 match=re.search(rb'D7 SPF A=([0-9A-F]{140}) B=([0-9A-F]{140}) CRC=([0-9A-F]{8}) SHA=([0-9a-f]{64})',full);assert match
 pair=bytearray.fromhex((match[1]+match[2]).decode())
 for off in (66,136):struct.pack_into('<I',pair,off,struct.unpack_from('<I',pair,off)[0]|(1<<20))
 replacement=b'D7 SPF A='+pair[:70].hex().upper().encode()+b' B='+pair[70:].hex().upper().encode()+b' CRC='+f'{zlib.crc32(pair):08X}'.encode()+b' SHA='+hashlib.sha256(pair).hexdigest().encode()
 reject('complete_spf_with_profile_error',full[:match.start()]+replacement+full[match.end():])
 corrupt=bytearray(full);corrupt[match.start(1)]^=1;reject('spf_pair_CRC_or_encoding_error',bytes(corrupt))
 reject('wrong_observed_code_sha',re.sub(rb' N=[0-9a-f]{64}',b' N='+b'0'*64,full,count=1))
 reject('changed_selection',full.replace(selection['selection_sha256'].encode(),b'0'*64,1))
 reject('false_transport_partial',full.replace(b'STATUS=COMPLETE',b'STATUS=PARTIAL'))
 report={'passed':True,'count':len(checks),'checks':checks,'roundtrips':reports,'shipping_efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest()};(OUT/'collector_transport_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(checks),'roundtrips':reports},indent=2))
if __name__=='__main__':main()
