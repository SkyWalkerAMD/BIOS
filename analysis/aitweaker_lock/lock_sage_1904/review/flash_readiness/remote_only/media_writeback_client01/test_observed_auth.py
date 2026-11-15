from pathlib import Path
import hashlib,json,struct
from observed_auth_adapter import ObservedAuthEngine
from hdmedia_offline import TunnelGate,Reject
HERE=Path(__file__).resolve().parent
cases=[]
def frame():
    b=bytearray(108);b[:8]=b'IUSB    ';struct.pack_into('<I',b,12,76);b[41]=0xf1;b[62]=1;return b
def run(name,b,accepted,twice=False):
    opened=[]
    class Dummy:
        closed=False
        def close(self):self.closed=True
    image=Dummy()
    def factory():opened.append(1);return image
    gate=TunnelGate(b'SYNTHETIC');gate.accept(b'SYNTHETIC')
    e=ObservedAuthEngine(factory);e.start(gate,'synthetic_token')
    try:e.handle(bytes(b));result=True
    except Reject:result=False
    assert result==accepted and bool(opened)==accepted,name
    if twice:
        try:e.handle(bytes(b))
        except Reject:pass
        else:raise AssertionError('Legacy F1 accepted after authentication')
        assert image.closed and e.state=='STOPPED'
    e.stop();cases.append({'name':name,'passed':True})
run('observed_legacy_shape',frame(),True)
run('legacy_shape_only_before_auth',frame(),True,True)
for offset,value in [(0,0),(8,1),(9,1),(10,32),(12,75),(17,5),(18,1),(19,128),(41,0xf2),(62,0)]:
    b=frame();b[offset]=value;run(f'metadata_change_{offset}',b,False)
run('truncated',frame()[:-1],False)
run('extended',frame()+b'\0',False)
b=frame();b[8:11]=b'\x01\x00\x20';b[17:20]=b'\x05\x01\x00';run('original_standard_auth_still_supported',b,True)
out={'status':'PASS_SYNTHETIC_AUTH_ADAPTER_ONLY','cases':cases,'case_count':len(cases),
     'adapter_sha256':hashlib.sha256((HERE/'observed_auth_adapter.py').read_bytes()).hexdigest(),
     'engine_sha256':hashlib.sha256((HERE/'hdmedia_offline.py').read_bytes()).hexdigest(),
     'physical_image_opened':False,'network_access':False}
(HERE/'observed_auth_regression.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':out['status'],'cases':len(cases),'adapter_sha256':out['adapter_sha256']}))
