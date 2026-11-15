"""Actual frozen C QR encoder -> screenshots -> CRC -> delta reconstruction."""
from pathlib import Path
import ctypes as C,hashlib,json,sys
from transport import render,parse
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';P3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
sys.path.insert(0,str(P3));from decode_captures import assemble,read_image
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'));from PIL import Image
BASE=(HERE.parent/'foreign_hii05/blobs/GetCpuInfo_0.forms.bin').read_bytes()
dll=C.CDLL(str(P3/'capture_test.dll'));dll.kvm_make_frame.argtypes=[C.c_void_p,C.c_size_t,C.c_uint,C.c_void_p,C.c_size_t];dll.kvm_make_frame.restype=C.c_size_t;dll.kvm_encode_frame.argtypes=[C.c_void_p,C.c_size_t,C.c_uint,C.c_void_p,C.c_void_p];dll.kvm_encode_frame.restype=C.c_int;dll.qrcodegen_getSize.argtypes=[C.c_void_p];dll.qrcodegen_getSize.restype=C.c_int;dll.qrcodegen_getModule.argtypes=[C.c_void_p,C.c_int,C.c_int];dll.qrcodegen_getModule.restype=C.c_bool
tests=[]
def record(name):tests.append({'case':name,'passed':True})
def main():
 r=json.loads((OUT/'core_tests.json').read_text());source=bytes.fromhex(r['source_log_sha']);selection=bytes.fromhex(r['selection_sha'])
 names=['cpu_7','unknown_0','unknown_1'];packets=[(OUT/'synthetic'/f'{n}.bin').read_bytes() for n in names];targets=[json.loads((OUT/'synthetic'/f'{n}.target.json').read_text()) for n in names[:2]]
 observations=[]
 for budget in (1024,1536,2048,4096):
  log,meta=render(packets,targets,source,selection,budget,BASE);result=parse(log,targets,source,selection,BASE,budget);assert result['complete']==meta['complete'];record('budget_'+str(budget));observations.append(meta)
  assert len(log)<=budget
  if not result['complete']:assert result['omitted'] and b'PARTIAL' in log
  out=OUT/'qr'/str(budget);out.mkdir(parents=True,exist_ok=True);frames=[];screens=[]
  for page in range((len(log)+767)//768):
   buf=C.create_string_buffer(1024);n=dll.kvm_make_frame(log,len(log),page,buf,1024);assert n;frame=buf.raw[:n];frames.append(frame)
   q=C.create_string_buffer(4096);temp=C.create_string_buffer(4096);assert dll.kvm_encode_frame(log,len(log),page,q,temp)==1
   modules=dll.qrcodegen_getSize(q);image=Image.new('1',((modules+8)*4,)*2,1);pixels=image.load()
   for y in range(modules):
    for x in range(modules):
     if dll.qrcodegen_getModule(q,x,y):
      for dy in range(4):
       for dx in range(4):pixels[(x+4)*4+dx,(y+4)*4+dy]=0
   path=out/f'qr-{page+1:03}.png';image.save(path);screens.append(read_image(path));assert screens[-1]==frame
  restored,qrmeta=assemble(screens);assert restored==log;assert assemble(list(reversed(frames)))[0]==log;decoded=parse(restored,targets,source,selection,BASE,budget)
  for key,obj in decoded['objects'].items():
   assert hashlib.sha256(obj['forms']).hexdigest()==obj['metadata']['sha256'];(out/f'object-{key:02}.forms.bin').write_bytes(obj['forms'])
  (out/'RESTORED-LOG.TXT').write_bytes(restored);(out/'result.json').write_text(json.dumps({**meta,'qr':qrmeta},indent=2)+'\n');record('actual_native_QR_CRC_and_reconstruction_'+str(budget))
  def reject_frame(name,broken):
   try:assemble(broken)
   except ValueError:record(name);return
   raise AssertionError(name)
  bad=bytearray(frames[0]);bad[-1]^=1;reject_frame('page_crc_'+str(budget),[bytes(bad)]+frames[1:])
  reject_frame('missing_page_'+str(budget),frames[:-1])
 def reject_log(name,raw):
  try:parse(raw,targets,source,selection,BASE,4096)
  except ValueError:record(name);return
  raise AssertionError(name)
 full,_=render(packets,targets,source,selection,4096,BASE)
 reject_log('wrong_selection',full.replace(selection.hex().encode(),b'0'*64,1))
 reject_log('false_complete',render(packets,targets,source,selection,1024,BASE)[0].replace(b'STATUS=PARTIAL',b'STATUS=COMPLETE'))
 reject_log('missing_footer',full[:-2])
 reject_log('bad_base64',full.replace(b'D7+ ',b'D7+ !',1))
 altered=bytearray(packets[0]);altered[225]^=1
 try:render([bytes(altered)]+packets[1:],targets,source,selection,4096,BASE)
 except ValueError:record('body_crc_reject_before_render')
 else:raise AssertionError('bad packet rendered')
 try:render(packets,targets,source,selection,64,BASE)
 except ValueError:record('budget_below_omission_manifest_no_output')
 else:raise AssertionError('tiny budget accepted')
 report={'status':'SYNTHETIC_TRANSPORT_ONLY_NO_DEPLOYMENT_BUDGET','passed':True,'count':len(tests),'tests':tests,'budget_examples':observations,'native_qr_encoder_sha256':hashlib.sha256((P3/'capture_test.dll').read_bytes()).hexdigest(),'core_dll_sha256':hashlib.sha256((OUT/'delta_core_test.dll').read_bytes()).hexdigest(),'original_tools_unchanged':True};(OUT/'transport_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(tests),'examples':observations},indent=2))
if __name__=='__main__':main()
