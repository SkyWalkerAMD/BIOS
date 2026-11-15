"""Native parser reads response buffers ending at a NOACCESS guard page.
Only source-matched read-only inspections execute; there are no BMC requests.
"""
import ctypes as c
import json
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_cache_refresh import Tests, Peer, Catalog, Ops, EXCHANGE

Tests.setUpClass()
kernel = c.WinDLL('kernel32',use_last_error=True)
kernel.VirtualAlloc.argtypes = [c.c_void_p,c.c_size_t,c.c_uint32,c.c_uint32]
kernel.VirtualAlloc.restype = c.c_void_p
kernel.VirtualProtect.argtypes = [c.c_void_p,c.c_size_t,c.c_uint32,c.POINTER(c.c_uint32)]
kernel.VirtualFree.argtypes = [c.c_void_p,c.c_size_t,c.c_uint32]
raw = json.dumps(Tests.cpu_empty,separators=(',',':')).encode()
cases = [(raw,0),(raw[:-1],16),(b'{"x":"\\u',16),(b'{"x":"\\ud800\\u',16),
         (b'{"x":"\xf0\x9f\x98',16),(b'{"x":"\xe4\xb8',16),(b'{"x":1e+',16),
         (b'{"x":-',16),(b'{"x":true',16),(b'{"x":'+b'['*14+b'0'+b']'*14+b'}',16),
         (b' '*32768,16),(b'{"x":['+b'0,'*2050+b'0]}',16)]
report=[]
for data,wanted in cases:
    case=Tests();case.setUp()
    pages=(len(data)+4095)//4096;total=(pages+1)*4096
    address=kernel.VirtualAlloc(None,total,0x3000,4)
    if not address:raise OSError(c.get_last_error())
    try:
        source=address+pages*4096-len(data)
        c.memmove(source,data,len(data));previous=c.c_uint32()
        if not kernel.VirtualProtect(address,pages*4096,2,c.byref(previous)):raise OSError(c.get_last_error())
        if not kernel.VirtualProtect(address+pages*4096,4096,1,c.byref(previous)):raise OSError(c.get_last_error())
        def exchange(user,method,resource,index,body,size,tag,tag_size,out):
            if not method and resource==2:
                case.peer.calls.append((method,resource,index,b'',b''))
                out.contents.status=200;out.contents.body=source;out.contents.bytes=len(data)
                return 0
            return case.peer.exchange(user,method,resource,index,body,size,tag,tag_size,out)
        callback=EXCHANGE(exchange)
        ops=Ops(None,case.peer.source_cb,case.peer.reserve_cb,callback)
        result=case.lib.HeroInventoryCacheInspect(case.ctx,1,c.byref(case.cat),c.byref(ops))
        assert result==wanted,(result,wanted)
        assert not case.peer.writes
        case.tearDown()
        report.append({'bytes':len(data),'result':result,'response':'READONLY','next_page':'NOACCESS','passed':True})
    finally:
        if not kernel.VirtualFree(address,0,0x8000):raise OSError(c.get_last_error())
(HERE/'build/response-bounds.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'{len(report)} readonly response/NOACCESS boundary cases passed.')
