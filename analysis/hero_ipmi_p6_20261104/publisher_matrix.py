"""Fault-inject real compiled publisher through mocked UEFI protocols."""
from pathlib import Path
import ctypes as C,json,hashlib
P=Path(__file__).resolve().parent
D=C.CDLL(str(P/'publisher_test.dll'))
U=C.c_uint64;V=C.c_void_p;PU=C.POINTER(U);PV=C.POINTER(V)
ERR=lambda n:0x8000000000000000|n
meta=json.loads((P/'native/native-payload.json').read_text())
package=(P/'native/Setup-HII-P6.bin').read_bytes()
langs=[x['language'] for x in json.loads((P.parent/'hero_ipmi_p5/native-payload.json').read_text())['languages']];ids=list(meta['value_ids'].values())
D.p5_package_matches.argtypes=[V,U];D.p5_package_matches.restype=C.c_int
D.p5_bind.restype=D.p5_publish.restype=U
buffers={}; callbacks=[];tests=[]
state={};strings={};sets=[]
def cb(sig,fn):
    callback=C.CFUNCTYPE(*sig)(fn);callbacks.append(callback);return C.cast(callback,V).value
def allocate(kind,size,out):
    if state.get('allocation_fail'):return ERR(9)
    b=C.create_string_buffer(size);p=C.addressof(b);buffers[p]=b;out[0]=p;return 0
def free(p):
    assert p in buffers;p0=buffers.pop(p);return 0
def locate(g,registration,out):
    key=C.string_at(g,4).hex()
    out[0]=C.addressof(db) if key=='72c19fef' else C.addressof(st)
    return 0
def listing(this,kind,guid,size,out):
    count=state.get('count',1);required=count*8
    if not out:size[0]=state.get('list_size',required);return ERR(5)
    if state.get('list_growth'):size[0]+=8;return 0
    for i in range(count):C.cast(out,PU)[i]=100+i
    size[0]=required;return 0
def export(this,handle,size,out):
    content=state.get('package',package)
    if not out:size[0]=len(content);return ERR(5)
    if state.get('export_growth'):size[0]+=8;return 0
    C.memmove(out,content,len(content));size[0]=len(content);return 0
def get(this,language,handle,id,out,size,font):
    if state.get('get_fail'):return ERR(14)
    key=(language.decode(),id);assert key in strings
    value=strings[key]
    if state.get('wrong_readback') and sets:value='Corrupted'
    raw=(value+'\0').encode('utf-16le')
    if size[0]<len(raw):size[0]=len(raw);return ERR(5)
    C.memmove(out,raw,len(raw));size[0]=len(raw);return 0
def set_string(this,handle,id,language,content,font):
    if state.get('set_fail'):return ERR(7)
    key=(language.decode(),id);assert key in strings
    b=bytearray();p=C.cast(content,C.POINTER(C.c_uint16))
    for i in range(160):
        if p[i]==0:break
        b.extend(p[i].to_bytes(2,'little'))
    else:raise AssertionError('unterminated')
    strings[key]=b.decode('utf-16le');sets.append(key);return 0
db=(V*5)(0,0,0,cb([U,V,C.c_uint8,V,PU,V],listing),cb([U,V,V,PU,V],export))
st=(V*3)(0,cb([U,V,C.c_char_p,V,C.c_uint16,V,PU,PV],get),cb([U,V,V,C.c_uint16,C.c_char_p,V,V],set_string))
bs=(V*48)();bs[0x40//8]=cb([U,C.c_uint32,U,PV],allocate);bs[0x48//8]=cb([U,V],free);bs[0x140//8]=cb([U,V,V,PV],locate)
system=(V*16)();system[0x60//8]=C.addressof(bs);V.in_dll(D,'gST').value=C.addressof(system)
values=((C.c_char*160)*41).in_dll(D,'values')
for i in range(41):values[i].value=f'TEST-{i:02d}'.encode()
def reset(**kw):
    D.p5_release();assert not buffers
    state.clear();state.update(kw);sets.clear();strings.clear()
    strings.update({(l,id):'Not queried' for l in langs for id in ids})
def checked(name,actual,expected):
    assert actual==expected,(name,hex(actual),hex(expected));assert not buffers;tests.append(name)
checked('exact form resource accepted',D.p5_package_matches(package,len(package)),1)
checked('null resource rejected',D.p5_package_matches(None,0),0)
for name,mut in [('truncation',package[:-1]),('IFR mutation',package[:60]+bytes([package[60]^1])+package[61:]),('bad package-list length',package[:16]+b'\0'*4+package[20:]),('absent END',package[:-4]+b'\x04\0\0\x04')]:
    checked(name,D.p5_package_matches(mut,len(mut)),0)
reset();checked('bind one exact resource',D.p5_bind(),0)
checked('publish with exact readback',D.p5_publish(),0)
assert len(sets)==410 and set(sets)=={(l,id) for l in langs for id in ids}
assert all(strings[(l,id)]==f'TEST-{i:02d}' for l in langs for i,id in enumerate(ids))
tests.append('all 410 writes confined to new IDs and languages')
for name,kw,expected in [('ambiguous packages',dict(count=2),ERR(15)),('missing value strings',dict(get_fail=True),ERR(33)),('oversized list',dict(list_size=32776),ERR(14)),('misaligned list',dict(list_size=7),ERR(14)),('growing list',dict(list_growth=True),ERR(7)),('growing export',dict(export_growth=True),ERR(14)),('allocation failure',dict(allocation_fail=True),ERR(9)),('different IFR',dict(package=package[:60]+bytes([package[60]^1])+package[61:]),ERR(14))]:
    reset(**kw);checked(name,D.p5_bind(),expected);assert not sets
for name,kw,expected in [('resource replaced after bind',dict(package=package[:60]+bytes([package[60]^1])+package[61:]),ERR(33)),('set failure propagated',dict(set_fail=True),ERR(7)),('incorrect readback',dict(wrong_readback=True),ERR(7)),('oversized export after bind',dict(export_growth=True),ERR(7))]:
    reset();checked(name+' initial bind',D.p5_bind(),0);state.update(kw);checked(name,D.p5_publish(),expected)
reset();checked('publish without bind',D.p5_publish(),ERR(6))
report=dict(passed=True,cases=len(tests),checks=tests,scope='compiled C publisher with mock UEFI protocols; not native AMITSE rendering',dll_sha256=hashlib.sha256((P/'publisher_test.dll').read_bytes()).hexdigest())
(P/'publisher-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
